"""
Unit & Integration Tests for Syscollector System Inventory Harvester.
Tests hardware, OS metadata, multi-platform package parsing (dpkg, rpm, apk, winreg, pip),
network interfaces, listening ports, running processes, and snapshot payload generation.
"""

import collections
import platform

import psutil

from arka_agent.collectors.base import BaseCollector
from arka_agent.collectors.syscollector import SyscollectorHarvester

# Mocks for network connections
ConnectionMock = collections.namedtuple(
    "ConnectionMock", ["fd", "family", "type", "laddr", "raddr", "status", "pid"]
)
AddrMock = collections.namedtuple("AddrMock", ["ip", "port"])


# ============================================================================
# 1. BaseCollector Interface & Initialization Tests
# ============================================================================


def test_syscollector_base_collector_interface():
    """Verifies SyscollectorHarvester adheres to BaseCollector contract."""
    harvester = SyscollectorHarvester(agent_id="test-agent-01", tenant_id="tenant-test")
    assert isinstance(harvester, BaseCollector)
    assert harvester.name == "syscollector"
    assert harvester.enabled is True
    assert harvester.agent_id == "test-agent-01"
    assert harvester.tenant_id == "tenant-test"


def test_syscollector_disabled_returns_empty():
    """Verifies collect() returns empty list when harvester is disabled."""
    harvester = SyscollectorHarvester(
        agent_id="test-agent-01", tenant_id="tenant-test", enabled=False
    )
    assert harvester.collect() == []


def test_syscollector_collect_returns_snapshot():
    """Verifies collect() returns list containing a snapshot when enabled."""
    harvester = SyscollectorHarvester(agent_id="test-agent-01", tenant_id="tenant-test")
    result = harvester.collect()
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["agent_id"] == "test-agent-01"


# ============================================================================
# 2. Hardware & OS Inventory Tests
# ============================================================================


def test_get_hardware_info_structure():
    """Verifies get_hardware_info returns genuine hardware metadata with all required fields."""
    harvester = SyscollectorHarvester()
    hw = harvester.get_hardware_info()

    assert isinstance(hw, dict)
    assert "cpu_cores_logical" in hw
    assert "cpu_cores_physical" in hw
    assert "cpu_architecture" in hw
    assert "ram_total_gb" in hw
    assert "ram_available_gb" in hw
    assert "ram_used_percent" in hw
    assert "disks" in hw
    assert "uptime_seconds" in hw
    assert hw["cpu_cores_logical"] >= 1
    assert hw["ram_total_gb"] > 0.0
    assert isinstance(hw["disks"], list)


def test_get_hardware_info_resilience(monkeypatch):
    """Verifies get_hardware_info handles psutil exceptions gracefully."""
    harvester = SyscollectorHarvester()

    def raise_err(*args, **kwargs):
        raise OSError("Virtual memory read error")

    monkeypatch.setattr(psutil, "virtual_memory", raise_err)
    monkeypatch.setattr(psutil, "disk_partitions", raise_err)

    hw = harvester.get_hardware_info()
    assert isinstance(hw, dict)
    assert hw["ram_total_gb"] == 1.0
    assert hw["disks"] == []


def test_get_os_info_structure():
    """Verifies get_os_info returns genuine OS metadata matching host platform."""
    harvester = SyscollectorHarvester()
    os_info = harvester.get_os_info()

    assert isinstance(os_info, dict)
    assert os_info["os_name"] == platform.system()
    assert os_info["os_release"] == platform.release()
    assert os_info["os_version"] == platform.version()
    assert os_info["kernel_architecture"] == platform.machine()
    assert os_info["hostname"] == platform.node()
    assert os_info["python_version"] == platform.python_version()
    assert "uptime" in os_info


# ============================================================================
# 3. Multi-Platform Package Harvesting Tests
# ============================================================================


def test_parse_dpkg_query_output():
    """Verifies Debian dpkg-query tab-delimited output parsing."""
    sample_output = (
        "libc6:amd64\t2.35-0ubuntu3.1\tamd64\tinstall ok installed\n"
        "openssh-server\t1:8.9p1-3ubuntu0.1\tamd64\tinstall ok installed\n"
        "curl\t7.81.0-1ubuntu1.14\tamd64\tinstall ok installed\n"
        "removed-pkg\t1.0.0\tamd64\tdeinstall ok config-files\n"
    )
    packages = SyscollectorHarvester.parse_dpkg_output(sample_output)
    assert len(packages) == 3
    names = [p["name"] for p in packages]
    assert "libc6:amd64" in names
    assert "openssh-server" in names
    assert "curl" in names
    assert "removed-pkg" not in names

    curl_pkg = next(p for p in packages if p["name"] == "curl")
    assert curl_pkg["version"] == "7.81.0-1ubuntu1.14"
    assert curl_pkg["architecture"] == "amd64"
    assert curl_pkg["format"] == "deb"


def test_parse_dpkg_status_content(tmp_path):
    """Verifies Debian /var/lib/dpkg/status parsing logic."""
    status_content = (
        "Package: bash\n"
        "Status: install ok installed\n"
        "Architecture: amd64\n"
        "Version: 5.1-6ubuntu1\n\n"
        "Package: python3\n"
        "Status: install ok installed\n"
        "Architecture: amd64\n"
        "Version: 3.10.6-1~22.04\n\n"
        "Package: purged-app\n"
        "Status: deinstall ok not-installed\n"
        "Architecture: amd64\n"
        "Version: 1.0\n\n"
    )
    packages = SyscollectorHarvester.parse_dpkg_status_content(status_content)
    assert len(packages) == 2
    pkg_names = {p["name"] for p in packages}
    assert "bash" in pkg_names
    assert "python3" in pkg_names
    assert "purged-app" not in pkg_names

    bash_pkg = next(p for p in packages if p["name"] == "bash")
    assert bash_pkg["version"] == "5.1-6ubuntu1"
    assert bash_pkg["architecture"] == "amd64"
    assert bash_pkg["format"] == "deb"

    # Test via harvester file path
    status_file = tmp_path / "status"
    status_file.write_text(status_content, encoding="utf-8")
    harvester = SyscollectorHarvester(dpkg_status_path=str(status_file))
    debian_pkgs = harvester._harvest_debian_packages()
    assert len(debian_pkgs) >= 2


def test_parse_rpm_query_output():
    """Verifies RedHat/CentOS rpm -qa output parsing."""
    sample_rpm_output = (
        "kernel-core\t5.14.0-284.11.1.el9_2\tx86_64\n"
        "glibc\t2.34-60.el9\tx86_64\n"
        "systemd\t252-13.el9_2\tx86_64\n"
    )
    packages = SyscollectorHarvester.parse_rpm_output(sample_rpm_output)
    assert len(packages) == 3
    assert packages[0]["name"] == "kernel-core"
    assert packages[0]["version"] == "5.14.0-284.11.1.el9_2"
    assert packages[0]["architecture"] == "x86_64"
    assert packages[0]["format"] == "rpm"


def test_parse_apk_info_output():
    """Verifies Alpine Linux apk info -v output parsing."""
    sample_apk_output = (
        "musl-1.2.3-r4\n"
        "busybox-1.35.0-r29\n"
        "ssl_client-1.35.0-r29\n"
        "alpine-baselayout-3.4.0-r0\n"
    )
    packages = SyscollectorHarvester.parse_apk_output(sample_apk_output)
    assert len(packages) == 4
    names = {p["name"] for p in packages}
    assert "musl" in names
    assert "busybox" in names
    assert "ssl_client" in names
    assert "alpine-baselayout" in names

    musl_pkg = next(p for p in packages if p["name"] == "musl")
    assert musl_pkg["version"] == "1.2.3-r4"
    assert musl_pkg["format"] == "apk"


def test_parse_winreg_entry():
    """Verifies Windows Registry Uninstall key parsing."""
    values = {
        "DisplayName": "Google Chrome",
        "DisplayVersion": "115.0.5790.171",
        "Publisher": "Google LLC",
        "InstallDate": "20230815",
    }
    entry = SyscollectorHarvester.parse_winreg_entry("Google Chrome", values)
    assert entry is not None
    assert entry["name"] == "Google Chrome"
    assert entry["version"] == "115.0.5790.171"
    assert entry["vendor"] == "Google LLC"
    assert entry["format"] == "win"

    # Missing DisplayName returns None
    assert SyscollectorHarvester.parse_winreg_entry("KeyWithoutName", {}) is None


def test_harvest_python_packages():
    """Verifies genuine Python distributions harvesting via importlib.metadata."""
    harvester = SyscollectorHarvester()
    py_pkgs = harvester._harvest_python_packages()
    assert isinstance(py_pkgs, list)
    assert len(py_pkgs) > 0
    pkg_names = {p["name"].lower() for p in py_pkgs}
    # Standard dependencies in our environment
    assert "pytest" in pkg_names or "psutil" in pkg_names or "pydantic" in pkg_names
    assert all(p["format"] == "pip" for p in py_pkgs)


def test_get_installed_packages_aggregation():
    """Verifies get_installed_packages returns aggregated and deduplicated software list."""
    harvester = SyscollectorHarvester()
    packages = harvester.get_installed_packages()
    assert isinstance(packages, list)
    assert len(packages) > 0
    assert all("name" in p and "version" in p for p in packages)


def test_get_installed_packages_custom_override():
    """Verifies custom_packages parameter returns provided list."""
    harvester = SyscollectorHarvester()
    custom = [{"name": "custom-tool", "version": "2.0.0", "format": "custom"}]
    result = harvester.get_installed_packages(custom_packages=custom)
    assert result == custom


# ============================================================================
# 4. Network Interfaces & Ports Tests
# ============================================================================


def test_get_network_interfaces():
    """Verifies get_network_interfaces extracts genuine network adapters and IP info."""
    harvester = SyscollectorHarvester()
    interfaces = harvester.get_network_interfaces()
    assert isinstance(interfaces, list)
    assert len(interfaces) > 0
    for iface in interfaces:
        assert "interface_name" in iface
        assert "isup" in iface
        assert "status" in iface
        assert iface["status"] in ("UP", "DOWN")


def test_get_network_ports_custom_mock():
    """Verifies get_network_ports correctly parses mock connections."""
    mock_conns = [
        ConnectionMock(
            fd=-1,
            family=2,
            type=1,  # SOCK_STREAM -> tcp
            laddr=AddrMock(ip="0.0.0.0", port=8080),
            raddr=None,
            status="LISTEN",
            pid=1234,
        ),
        ConnectionMock(
            fd=-1,
            family=2,
            type=2,  # SOCK_DGRAM -> udp
            laddr=AddrMock(ip="127.0.0.1", port=5353),
            raddr=None,
            status=None,
            pid=5678,
        ),
    ]
    harvester = SyscollectorHarvester()
    ports = harvester.get_network_ports(custom_connections=mock_conns)

    assert len(ports) == 2
    assert ports[0]["protocol"] == "tcp"
    assert ports[0]["local_ip"] == "0.0.0.0"
    assert ports[0]["local_port"] == 8080
    assert ports[0]["state"] == "LISTEN"
    assert ports[0]["pid"] == 1234

    assert ports[1]["protocol"] == "udp"
    assert ports[1]["local_ip"] == "127.0.0.1"
    assert ports[1]["local_port"] == 5353
    assert ports[1]["pid"] == 5678


def test_get_network_ports_live():
    """Verifies get_network_ports operates against live system sockets without raising exceptions."""
    harvester = SyscollectorHarvester()
    ports = harvester.get_network_ports()
    assert isinstance(ports, list)
    for p in ports:
        assert "protocol" in p
        assert "local_ip" in p
        assert "local_port" in p


# ============================================================================
# 5. Running Processes Tests
# ============================================================================


def test_get_running_processes():
    """Verifies get_running_processes captures process tree metadata."""
    harvester = SyscollectorHarvester(process_limit=25)
    processes = harvester.get_running_processes(limit=20)
    assert isinstance(processes, list)
    assert len(processes) > 0
    assert len(processes) <= 20

    # Verify processes structure
    # Current test runner process or parent is among processes if limit permits
    for p in processes:
        assert "pid" in p
        assert "name" in p
        assert "cpu_percent" in p
        assert "memory_percent" in p


def test_get_running_processes_handles_dead_processes(monkeypatch):
    """Verifies get_running_processes handles NoSuchProcess and AccessDenied gracefully."""
    harvester = SyscollectorHarvester()

    class MockProc:
        @property
        def info(self):
            raise psutil.NoSuchProcess(pid=99999)

    def mock_iter(*args, **kwargs):
        return [MockProc()]

    monkeypatch.setattr(psutil, "process_iter", mock_iter)
    processes = harvester.get_running_processes(limit=10)
    assert processes == []


# ============================================================================
# 6. Snapshot Aggregation & Payload Integrity Tests
# ============================================================================


def test_collect_inventory_full_payload():
    """Verifies collect_inventory produces a comprehensive, valid snapshot dictionary."""
    harvester = SyscollectorHarvester(
        agent_id="test-agent-alpha",
        tenant_id="tenant-cybercorp",
        process_limit=30,
    )
    snapshot = harvester.collect_inventory()

    assert isinstance(snapshot, dict)
    assert snapshot["agent_id"] == "test-agent-alpha"
    assert snapshot["tenant_id"] == "tenant-cybercorp"
    assert snapshot["snapshot_id"].startswith("syscol-")
    assert "timestamp" in snapshot

    # Hardware
    assert "cpu_cores_logical" in snapshot["hardware"]
    assert "ram_total_gb" in snapshot["hardware"]

    # OS
    assert "os_name" in snapshot["os"]
    assert "hostname" in snapshot["os"]

    # Packages
    assert isinstance(snapshot["packages"], list)
    assert len(snapshot["packages"]) > 0

    # Network Interfaces
    assert isinstance(snapshot["network_interfaces"], list)
    assert len(snapshot["network_interfaces"]) > 0

    # Open Ports
    assert isinstance(snapshot["open_ports"], list)

    # Running Processes
    assert isinstance(snapshot["running_processes"], list)
    assert len(snapshot["running_processes"]) > 0

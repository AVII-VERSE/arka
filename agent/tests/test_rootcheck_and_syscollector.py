"""
Unit & Integration Tests for Rootcheck Security Scanner & Syscollector System Inventory.
Includes Tier 1 (Baseline & Detection) and Tier 2 (Robustness, Permissions, Edge Cases) tests.
"""

import collections
import os
import stat

import psutil
import pytest

from arka_agent.collectors.base import BaseCollector
from arka_agent.collectors.rootcheck import (
    BACKDOOR_PORTS,
    IFF_PROMISC_FLAG,
    RootcheckScanner,
)
from arka_agent.collectors.syscollector import SyscollectorHarvester

# Named tuple simulating psutil net connection
ConnectionMock = collections.namedtuple(
    "ConnectionMock", ["fd", "family", "type", "laddr", "raddr", "status", "pid"]
)
AddrMock = collections.namedtuple("AddrMock", ["ip", "port"])


# ============================================================================
# Tier 1 Tests: Core Detection & Baseline
# ============================================================================


def test_rootcheck_base_collector_interface():
    """Verifies RootcheckScanner adheres to BaseCollector interface contract."""
    scanner = RootcheckScanner(agent_id="test-agent", tenant_id="tenant-alpha")
    assert isinstance(scanner, BaseCollector)
    assert scanner.name == "rootcheck"
    assert scanner.enabled is True


def test_rootcheck_scanner_execution(tmp_path):
    """Verifies RootcheckScanner detects suspicious rootkit artifact files."""
    test_file = tmp_path / ".hidden"
    test_file.write_text("rootkit_payload", encoding="utf-8")

    scanner = RootcheckScanner(agent_id="test-agent", tenant_id="tenant-alpha")
    scanner.suspicious_paths = [str(test_file)]

    events = scanner.scan_suspicious_files()
    assert len(events) == 1
    assert events[0]["event_type"] == "rootkit_detection"
    assert events[0]["action"] == "suspicious_file_found"
    assert events[0]["severity"] == "CRITICAL"
    assert events[0]["metadata"]["suspicious_path"] == str(test_file)
    assert events[0]["metadata"]["is_directory"] is False
    assert events[0]["metadata"]["size_bytes"] > 0
    assert "ingested_at" in events[0]


def test_suspicious_file_detection_directory(tmp_path):
    """Verifies RootcheckScanner detects suspicious rootkit artifact directories."""
    test_dir = tmp_path / ".rootkit_dir"
    test_dir.mkdir()

    scanner = RootcheckScanner(
        agent_id="test-agent",
        tenant_id="tenant-alpha",
        suspicious_paths=[str(test_dir)],
    )

    events = scanner.scan_suspicious_files()
    assert len(events) == 1
    assert events[0]["action"] == "suspicious_file_found"
    assert events[0]["metadata"]["is_directory"] is True
    assert events[0]["metadata"]["mitre_technique"] == "T1014"


def test_suspicious_suid_binary_detection(tmp_path):
    """Verifies RootcheckScanner detects anomalous SUID/SGID binaries in volatile directories."""
    volatile_dir = tmp_path / "volatile"
    volatile_dir.mkdir()
    suid_bin = volatile_dir / "backdoor_sh"
    suid_bin.write_bytes(b"\x7fELF_FAKE_BIN")

    # Set SUID bit if platform supports chmod
    try:
        os.chmod(str(suid_bin), 0o4755)
        if not (os.stat(str(suid_bin)).st_mode & stat.S_ISUID):
            pytest.skip("SUID bit not supported on this platform/filesystem")
    except Exception:
        pytest.skip("Chmod SUID not supported on this platform/filesystem")

    scanner = RootcheckScanner(
        agent_id="test-agent",
        tenant_id="tenant-alpha",
        suid_scan_dirs=[str(volatile_dir)],
    )

    events = scanner.scan_suspicious_files()
    suid_events = [e for e in events if e["action"] == "suspicious_suid_binary_found"]
    assert len(suid_events) == 1
    assert suid_events[0]["severity"] == "CRITICAL"
    assert suid_events[0]["metadata"]["is_suid"] is True
    assert suid_events[0]["metadata"]["mitre_technique"] == "T1548.001"


def test_backdoor_port_detection():
    """Verifies RootcheckScanner flags high-risk backdoor listening ports."""
    mock_conns = [
        ConnectionMock(
            fd=-1,
            family=2,
            type=1,
            laddr=AddrMock(ip="0.0.0.0", port=31337),
            raddr=None,
            status="LISTEN",
            pid=4242,
        ),
        ConnectionMock(
            fd=-1,
            family=2,
            type=1,
            laddr=AddrMock(ip="127.0.0.1", port=6667),
            raddr=None,
            status="LISTEN",
            pid=4243,
        ),
    ]

    scanner = RootcheckScanner(agent_id="test-agent", tenant_id="tenant-alpha")
    events = scanner.scan_listening_ports(custom_connections=mock_conns)

    assert len(events) == 2
    ports_flagged = {e["metadata"]["port"] for e in events}
    assert 31337 in ports_flagged
    assert 6667 in ports_flagged
    assert all(e["severity"] == "HIGH" for e in events)
    assert all(e["action"] == "suspicious_port_listening" for e in events)


def test_all_backdoor_ports_flagged():
    """Verifies all defined backdoor ports in BACKDOOR_PORTS are detected."""
    mock_conns = [
        ConnectionMock(
            fd=-1,
            family=2,
            type=1,
            laddr=AddrMock(ip="0.0.0.0", port=port),
            raddr=None,
            status="LISTEN",
            pid=1000 + i,
        )
        for i, port in enumerate(BACKDOOR_PORTS)
    ]

    scanner = RootcheckScanner(agent_id="test-agent", tenant_id="tenant-alpha")
    events = scanner.scan_listening_ports(custom_connections=mock_conns)

    assert len(events) == len(BACKDOOR_PORTS)
    ports_flagged = {e["metadata"]["port"] for e in events}
    for port in BACKDOOR_PORTS:
        assert port in ports_flagged


def test_unmapped_listening_socket_detection():
    """Verifies RootcheckScanner detects unmapped listening sockets with no owning PID."""
    mock_conns = [
        ConnectionMock(
            fd=-1,
            family=2,
            type=1,
            laddr=AddrMock(ip="0.0.0.0", port=9999),
            raddr=None,
            status="LISTEN",
            pid=None,  # No user-space PID
        ),
    ]

    scanner = RootcheckScanner(agent_id="test-agent", tenant_id="tenant-alpha")
    events = scanner.scan_listening_ports(custom_connections=mock_conns)

    assert len(events) == 1
    assert events[0]["action"] == "unmapped_socket_detected"
    assert events[0]["severity"] == "HIGH"
    assert events[0]["metadata"]["port"] == 9999
    assert events[0]["metadata"]["pid"] is None


def test_udp_listening_socket_detection():
    """Verifies RootcheckScanner detects UDP listening sockets (type=2 / SOCK_DGRAM)."""
    mock_conns = [
        ConnectionMock(
            fd=-1,
            family=2,
            type=2,  # SOCK_DGRAM
            laddr=AddrMock(ip="0.0.0.0", port=31337),
            raddr=None,
            status=None,
            pid=777,
        ),
    ]

    scanner = RootcheckScanner(agent_id="test-agent", tenant_id="tenant-alpha")
    events = scanner.scan_listening_ports(custom_connections=mock_conns)

    assert len(events) == 1
    assert events[0]["action"] == "suspicious_port_listening"
    assert events[0]["metadata"]["port"] == 31337


def test_promiscuous_interface_detection(tmp_path):
    """Verifies RootcheckScanner detects promiscuous network interface flags on Linux."""
    sys_net = tmp_path / "sys_class_net"
    sys_net.mkdir()

    # Create eth0 with IFF_PROMISC (0x1103)
    eth0 = sys_net / "eth0"
    eth0.mkdir()
    (eth0 / "flags").write_text("0x1103\n", encoding="utf-8")

    # Create eth1 with normal flags (0x1003)
    eth1 = sys_net / "eth1"
    eth1.mkdir()
    (eth1 / "flags").write_text("0x1003\n", encoding="utf-8")

    scanner = RootcheckScanner(
        agent_id="test-agent",
        tenant_id="tenant-alpha",
        sys_net_dir=str(sys_net),
    )

    events = scanner.scan_listening_ports(custom_connections=[])
    promisc_events = [e for e in events if e["action"] == "promiscuous_interface_detected"]
    assert len(promisc_events) == 1
    assert promisc_events[0]["metadata"]["interface"] == "eth0"
    assert promisc_events[0]["severity"] == "CRITICAL"
    assert promisc_events[0]["metadata"]["mitre_technique"] == "T1040"
    assert IFF_PROMISC_FLAG == 0x100


def test_promiscuous_interface_corrupted_flags(tmp_path):
    """Verifies RootcheckScanner handles corrupted/unreadable interface flags gracefully."""
    sys_net = tmp_path / "sys_class_net"
    sys_net.mkdir()

    eth0 = sys_net / "eth0"
    eth0.mkdir()
    (eth0 / "flags").write_text("NOT_A_VALID_NUMBER", encoding="utf-8")

    scanner = RootcheckScanner(
        agent_id="test-agent",
        tenant_id="tenant-alpha",
        sys_net_dir=str(sys_net),
    )

    events = scanner.scan_listening_ports(custom_connections=[])
    assert len(events) == 0


def test_preload_tampering_detection(tmp_path):
    """Verifies RootcheckScanner detects /etc/ld.so.preload malicious library injection."""
    preload_file = tmp_path / "ld.so.preload"
    preload_file.write_text("/usr/local/lib/librootkit.so\n/lib/evil.so", encoding="utf-8")

    scanner = RootcheckScanner(
        agent_id="test-agent",
        tenant_id="tenant-alpha",
        preload_path=str(preload_file),
    )

    events = scanner.scan_system_binaries()
    preload_events = [e for e in events if e["action"] == "preload_tampering_detected"]
    assert len(preload_events) == 1
    assert preload_events[0]["severity"] == "CRITICAL"
    assert "/usr/local/lib/librootkit.so" in preload_events[0]["metadata"]["injected_libraries"]


def test_preload_tampering_empty_or_comments(tmp_path):
    """Verifies RootcheckScanner ignores clean / commented preload files."""
    preload_file = tmp_path / "ld.so.preload"
    preload_file.write_text("# This is a comment\n\n   \n", encoding="utf-8")

    scanner = RootcheckScanner(
        agent_id="test-agent",
        tenant_id="tenant-alpha",
        preload_path=str(preload_file),
        critical_binaries=[],
    )

    events = scanner.scan_system_binaries()
    assert len(events) == 0


def test_critical_system_binary_missing(tmp_path):
    """Verifies RootcheckScanner flags missing critical system binaries when parent directory exists."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    target_ps = bin_dir / "ps"  # missing

    scanner = RootcheckScanner(
        agent_id="test-agent",
        tenant_id="tenant-alpha",
        preload_path=str(tmp_path / "nonexistent_preload"),
        critical_binaries=[str(target_ps)],
    )

    events = scanner.scan_system_binaries()
    missing_events = [e for e in events if e["action"] == "critical_binary_missing"]
    assert len(missing_events) == 1
    assert missing_events[0]["severity"] == "HIGH"
    assert missing_events[0]["metadata"]["binary_path"] == str(target_ps)


def test_critical_system_binary_zero_bytes(tmp_path):
    """Verifies RootcheckScanner flags zero-byte truncated critical binaries."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    target_ls = bin_dir / "ls"
    target_ls.write_bytes(b"")  # 0 bytes

    scanner = RootcheckScanner(
        agent_id="test-agent",
        tenant_id="tenant-alpha",
        preload_path=str(tmp_path / "nonexistent_preload"),
        critical_binaries=[str(target_ls)],
    )

    events = scanner.scan_system_binaries()
    tampered_events = [e for e in events if e["action"] == "critical_binary_tampered"]
    assert len(tampered_events) == 1
    assert tampered_events[0]["metadata"]["size_bytes"] == 0


def test_critical_system_binary_world_writable(tmp_path):
    """Verifies RootcheckScanner flags insecure world-writable system binaries."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    target_bin = bin_dir / "login"
    target_bin.write_bytes(b"\x7fELF_VALID_HEADER")

    try:
        os.chmod(str(target_bin), 0o777)
    except Exception:
        pytest.skip("Chmod world-writable not supported on this platform/filesystem")

    # Only test if OS stat actually reported S_IWOTH
    st = os.stat(str(target_bin))
    if not (st.st_mode & stat.S_IWOTH):
        pytest.skip("Filesystem does not support S_IWOTH permission bit")

    scanner = RootcheckScanner(
        agent_id="test-agent",
        tenant_id="tenant-alpha",
        preload_path=str(tmp_path / "nonexistent_preload"),
        critical_binaries=[str(target_bin)],
    )

    events = scanner.scan_system_binaries()
    perm_events = [e for e in events if e["action"] == "binary_permission_anomaly"]
    assert len(perm_events) == 1
    assert perm_events[0]["severity"] == "CRITICAL"


def test_critical_binary_nonexistent_parent_skipped(tmp_path):
    """Verifies RootcheckScanner skips binary checks if parent directory does not exist."""
    nonexistent_bin = tmp_path / "nonexistent_dir" / "custom_bin"

    scanner = RootcheckScanner(
        agent_id="test-agent",
        tenant_id="tenant-alpha",
        preload_path=str(tmp_path / "nonexistent_preload"),
        critical_binaries=[str(nonexistent_bin)],
    )

    events = scanner.scan_system_binaries()
    assert len(events) == 0


def test_clean_system_zero_findings(tmp_path):
    """Verifies clean baseline state produces zero false positives."""
    clean_proc = tmp_path / "clean_proc"
    clean_proc.mkdir()
    clean_net = tmp_path / "clean_net"
    clean_net.mkdir()

    scanner = RootcheckScanner(
        agent_id="test-agent",
        tenant_id="tenant-alpha",
        suspicious_paths=[str(tmp_path / "nonexistent_rootkit")],
        proc_dir=str(clean_proc),
        sys_net_dir=str(clean_net),
        preload_path=str(tmp_path / "nonexistent_preload"),
        critical_binaries=[],
        suid_scan_dirs=[],
    )

    _normal_conns = [
        ConnectionMock(
            fd=-1,
            family=2,
            type=1,
            laddr=AddrMock(ip="127.0.0.1", port=80),
            raddr=None,
            status="LISTEN",
            pid=100,
        ),
        ConnectionMock(
            fd=-1,
            family=2,
            type=1,
            laddr=AddrMock(ip="0.0.0.0", port=443),
            raddr=None,
            status="LISTEN",
            pid=101,
        ),
    ]

    events = scanner.run_full_scan()
    assert len(events) == 0


def test_full_audit_scan_aggregation(tmp_path):
    """Verifies run_full_scan() and collect() aggregate findings across all sub-scanners."""
    # Setup suspicious file
    bad_file = tmp_path / ".diamorphine"
    bad_file.write_text("payload", encoding="utf-8")

    # Setup preload
    preload_file = tmp_path / "ld.so.preload"
    preload_file.write_text("/lib/inject.so", encoding="utf-8")

    scanner = RootcheckScanner(
        agent_id="test-agent",
        tenant_id="tenant-alpha",
        suspicious_paths=[str(bad_file)],
        preload_path=str(preload_file),
        critical_binaries=[],
        suid_scan_dirs=[],
    )

    events = scanner.run_full_scan()
    assert len(events) >= 2
    actions = {e["action"] for e in events}
    assert "suspicious_file_found" in actions
    assert "preload_tampering_detected" in actions

    # collect() should match run_full_scan()
    collected = scanner.collect()
    assert len(collected) == len(events)


def test_collector_disabled_returns_empty(tmp_path):
    """Verifies collector returns empty list when disabled."""
    bad_file = tmp_path / ".diamorphine"
    bad_file.write_text("payload", encoding="utf-8")

    scanner = RootcheckScanner(
        agent_id="test-agent",
        tenant_id="tenant-alpha",
        enabled=False,
        suspicious_paths=[str(bad_file)],
    )

    assert scanner.collect() == []


def test_platform_dispatch():
    """Verifies default paths and binaries adjust to host platform."""
    scanner = RootcheckScanner()
    assert len(scanner.suspicious_paths) > 0
    assert len(scanner.critical_binaries) > 0
    assert scanner.name == "rootcheck"


# ============================================================================
# Tier 2 Tests: Robustness, Hidden Processes, Permission Denial, Edge Cases
# ============================================================================


def test_hidden_process_mock_detection(tmp_path):
    """Verifies dual-view cross-validation detects processes in /proc missing from psutil."""
    proc_dir = tmp_path / "proc"
    proc_dir.mkdir()

    # Create /proc entries for PIDs 1001, 1002, 1003
    for pid in [1001, 1002, 1003]:
        p_dir = proc_dir / str(pid)
        p_dir.mkdir()
        (p_dir / "comm").write_text(f"proc_{pid}\n", encoding="utf-8")
        (p_dir / "cmdline").write_text(f"/usr/bin/proc_{pid}\x00--arg", encoding="utf-8")

    # psutil only knows about 1001 and 1002 (1003 is hidden rootkit process!)
    known_psutil_pids = {1001, 1002}

    scanner = RootcheckScanner(
        agent_id="test-agent",
        tenant_id="tenant-alpha",
        proc_dir=str(proc_dir),
    )

    events = scanner.scan_hidden_processes(known_pids=known_psutil_pids)
    assert len(events) == 1
    assert events[0]["action"] == "hidden_process_detected"
    assert events[0]["severity"] == "CRITICAL"
    assert events[0]["metadata"]["pid"] == 1003
    assert events[0]["metadata"]["process_name"] == "proc_1003"
    assert events[0]["metadata"]["cmdline"] == "/usr/bin/proc_1003 --arg"
    assert events[0]["metadata"]["mitre_technique"] == "T1014"


def test_hidden_process_candidate_pid_probing():
    """Verifies candidate PID probing detects unlisted candidate PIDs."""
    scanner = RootcheckScanner(
        agent_id="test-agent",
        tenant_id="tenant-alpha",
        proc_dir="/nonexistent_proc_dir",
    )

    # Empty known PIDs and empty proc_dir
    events = scanner.scan_hidden_processes(known_pids=set(), candidate_pids=set())
    assert len(events) == 0


def test_permission_denied_handling(monkeypatch):
    """Verifies scanner handles PermissionError and psutil.AccessDenied gracefully."""
    scanner = RootcheckScanner(
        agent_id="test-agent",
        tenant_id="tenant-alpha",
        suspicious_paths=["/root/inaccessible/.hidden"],
        proc_dir="/root/inaccessible/proc",
        sys_net_dir="/root/inaccessible/net",
        preload_path="/root/inaccessible/ld.so.preload",
        critical_binaries=["/root/inaccessible/bin/ps"],
    )

    def raise_access_denied(*args, **kwargs):
        raise psutil.AccessDenied(pid=1, name="root_process")

    monkeypatch.setattr(psutil, "net_connections", raise_access_denied)
    monkeypatch.setattr(psutil, "pids", raise_access_denied)

    # All scans should execute and return lists without unhandled exception
    assert isinstance(scanner.scan_suspicious_files(), list)
    assert isinstance(scanner.scan_hidden_processes(), list)
    assert isinstance(scanner.scan_listening_ports(), list)
    assert isinstance(scanner.scan_system_binaries(), list)
    assert isinstance(scanner.run_full_scan(), list)


def test_process_terminated_mid_scan(tmp_path):
    """Verifies scanner handles process exiting while reading /proc/<pid>/cmdline."""
    proc_dir = tmp_path / "proc"
    proc_dir.mkdir()

    # PID directory exists, but cmdline file is absent (simulating mid-scan termination)
    ghost_pid_dir = proc_dir / "9999"
    ghost_pid_dir.mkdir()

    scanner = RootcheckScanner(
        agent_id="test-agent",
        tenant_id="tenant-alpha",
        proc_dir=str(proc_dir),
    )

    events = scanner.scan_hidden_processes(known_pids={1, 2})
    assert len(events) == 1
    assert events[0]["metadata"]["pid"] == 9999
    assert events[0]["metadata"]["cmdline"] is None


def test_empty_paths_and_connections():
    """Verifies scanner works seamlessly with empty inputs."""
    scanner = RootcheckScanner(
        suspicious_paths=[],
        critical_binaries=[],
        suid_scan_dirs=[],
    )

    assert scanner.scan_suspicious_files() == []
    assert scanner.scan_listening_ports(custom_connections=[]) == []
    assert scanner.scan_system_binaries(preload_path="", binaries=[]) == []


def test_ipv6_and_ephemeral_ports():
    """Verifies IPv6 listeners and established ephemeral ports are handled accurately."""
    mock_conns = [
        # IPv6 backdoor port
        ConnectionMock(
            fd=-1,
            family=10,  # AF_INET6
            type=1,
            laddr=AddrMock(ip="::1", port=4444),
            raddr=None,
            status="LISTEN",
            pid=5555,
        ),
        # Established normal socket (not listening)
        ConnectionMock(
            fd=-1,
            family=2,
            type=1,
            laddr=AddrMock(ip="192.168.1.50", port=54321),
            raddr=AddrMock(ip="93.184.216.34", port=443),
            status="ESTABLISHED",
            pid=1234,
        ),
    ]

    scanner = RootcheckScanner(agent_id="test-agent", tenant_id="tenant-alpha")
    events = scanner.scan_listening_ports(custom_connections=mock_conns)

    # Only the listening backdoor port 4444 should be flagged
    assert len(events) == 1
    assert events[0]["metadata"]["port"] == 4444
    assert events[0]["metadata"]["local_ip"] == "::1"
    assert events[0]["action"] == "suspicious_port_listening"


def test_psutil_process_access_denied_on_backdoor_port(monkeypatch):
    """Verifies backdoor port is still reported when psutil.Process raises NoSuchProcess or AccessDenied."""
    mock_conns = [
        ConnectionMock(
            fd=-1,
            family=2,
            type=1,
            laddr=AddrMock(ip="0.0.0.0", port=12345),
            raddr=None,
            status="LISTEN",
            pid=8888,
        ),
    ]

    def mock_process(pid):
        raise psutil.NoSuchProcess(pid=pid)

    monkeypatch.setattr(psutil, "Process", mock_process)

    scanner = RootcheckScanner(agent_id="test-agent", tenant_id="tenant-alpha")
    events = scanner.scan_listening_ports(custom_connections=mock_conns)

    assert len(events) == 1
    assert events[0]["metadata"]["port"] == 12345
    assert events[0]["metadata"]["process_name"] == "unknown"
    assert events[0]["metadata"]["pid"] == 8888


# ============================================================================
# Syscollector Tests
# ============================================================================


def test_syscollector_inventory_harvesting():
    """Verifies SyscollectorHarvester gathers hardware, OS, and network interfaces."""
    harvester = SyscollectorHarvester(agent_id="test-agent", tenant_id="tenant-alpha")
    snapshot = harvester.collect_inventory()

    assert snapshot["agent_id"] == "test-agent"
    assert snapshot["tenant_id"] == "tenant-alpha"
    assert "cpu_cores_logical" in snapshot["hardware"]
    assert "os_name" in snapshot["os"]
    assert isinstance(snapshot["network_interfaces"], list)
    assert isinstance(snapshot["running_processes"], list)

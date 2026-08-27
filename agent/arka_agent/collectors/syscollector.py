"""
# ruff: noqa: PLR0912, PLW2901
ARKA Syscollector System Inventory Harvester.
Collects hardware, OS, network interfaces, installed packages, open ports, and running processes.
"""

import importlib.metadata
import logging
import os
import platform
import shutil
import socket
import subprocess
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import psutil  # type: ignore[import-untyped]

try:
    import winreg
except ImportError:
    winreg = None  # type: ignore[assignment]

from arka_agent.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class SyscollectorHarvester(BaseCollector):
    """Endpoint System Hardware, Software, and Network Inventory Collector."""

    def __init__(
        self,
        agent_id: str = "agent-dev-01",
        tenant_id: str = "default-tenant",
        enabled: bool = True,
        include_packages: bool = True,
        include_ports: bool = True,
        include_processes: bool = True,
        process_limit: int = 100,
        dpkg_status_path: str = "/var/lib/dpkg/status",
    ):
        super().__init__(name="syscollector", enabled=enabled)
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self.include_packages = include_packages
        self.include_ports = include_ports
        self.include_processes = include_processes
        self.process_limit = process_limit
        self.dpkg_status_path = dpkg_status_path

    # =========================================================================
    # Hardware & OS Inventory
    # =========================================================================

    def get_hardware_info(self) -> dict[str, Any]:
        """Collects CPU, Memory, Swap, and Disk hardware inventory."""
        try:
            mem = psutil.virtual_memory()
            ram_total_gb = round(mem.total / (1024**3), 2)
            ram_available_gb = round(mem.available / (1024**3), 2)
            ram_used_percent = float(mem.percent)
        except Exception as err:
            logger.debug("Failed to retrieve virtual memory: %s", err)
            ram_total_gb = 1.0
            ram_available_gb = 0.5
            ram_used_percent = 50.0

        try:
            swap = psutil.swap_memory()
            swap_total_gb = round(swap.total / (1024**3), 2)
            swap_used_gb = round(swap.used / (1024**3), 2)
        except Exception:
            swap_total_gb = 0.0
            swap_used_gb = 0.0

        disks: list[dict[str, Any]] = []
        try:
            for part in psutil.disk_partitions(all=False):
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disks.append(
                        {
                            "device": part.device,
                            "mountpoint": part.mountpoint,
                            "fstype": part.fstype,
                            "total_gb": round(usage.total / (1024**3), 2),
                            "used_gb": round(usage.used / (1024**3), 2),
                            "free_gb": round(usage.free / (1024**3), 2),
                        }
                    )
                except (PermissionError, OSError):
                    pass
        except Exception as err:
            logger.debug("Failed to enumerate disk partitions: %s", err)

        try:
            boot_time = psutil.boot_time()
            uptime_seconds = round(time.time() - boot_time, 2)
        except Exception:
            boot_time = 0.0
            uptime_seconds = 0.0

        return {
            "cpu_cores_logical": psutil.cpu_count(logical=True) or 1,
            "cpu_cores_physical": psutil.cpu_count(logical=False) or 1,
            "cpu_architecture": platform.machine(),
            "ram_total_gb": ram_total_gb,
            "ram_available_gb": ram_available_gb,
            "ram_used_percent": ram_used_percent,
            "swap_total_gb": swap_total_gb,
            "swap_used_gb": swap_used_gb,
            "boot_time": boot_time,
            "uptime_seconds": uptime_seconds,
            "disks": disks,
        }

    def get_os_info(self) -> dict[str, Any]:
        """Collects Operating System metadata."""
        try:
            boot_time = psutil.boot_time()
            uptime = round(time.time() - boot_time, 2)
        except Exception:
            uptime = 0.0

        return {
            "os_name": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "kernel_architecture": platform.machine(),
            "hostname": platform.node(),
            "python_version": platform.python_version(),
            "uptime": uptime,
        }

    # =========================================================================
    # Network Interfaces & Ports
    # =========================================================================

    def get_network_interfaces(self) -> list[dict[str, Any]]:
        """Collects network adapters, IP addresses, MAC addresses, status, and stats."""
        interfaces: list[dict[str, Any]] = []
        try:
            addrs = psutil.net_if_addrs()
        except Exception as err:
            logger.debug("Failed to retrieve network interface addresses: %s", err)
            return interfaces

        stats: dict[str, Any] = {}
        try:
            stats = psutil.net_if_stats()
        except Exception:
            pass

        for iface_name, iface_addrs in addrs.items():
            ipv4: str | None = None
            ipv6: str | None = None
            mac: str | None = None
            netmask: str | None = None
            broadcast: str | None = None

            for addr in iface_addrs:
                fam_str = str(addr.family)
                # IPv4
                if fam_str == "AddressFamily.AF_INET" or addr.family == 2:
                    ipv4 = addr.address
                    if addr.netmask:
                        netmask = addr.netmask
                    if addr.broadcast:
                        broadcast = addr.broadcast
                # IPv6
                elif fam_str == "AddressFamily.AF_INET6" or addr.family in (23, 10, socket.AF_INET6):
                    ipv6 = addr.address
                # Link / MAC
                elif (
                    fam_str in ("AddressFamily.AF_LINK", "AddressFamily.AF_PACKET")
                    or addr.family in (17, 18)
                    or (addr.address and (":" in addr.address or "-" in addr.address) and not ipv6)
                ):
                    mac = addr.address

            iface_stat = stats.get(iface_name)
            isup = iface_stat.isup if iface_stat else True
            speed = iface_stat.speed if iface_stat else 0
            mtu = iface_stat.mtu if iface_stat else 1500

            interfaces.append(
                {
                    "interface_name": iface_name,
                    "ipv4_address": ipv4,
                    "ipv6_address": ipv6,
                    "mac_address": mac,
                    "netmask": netmask,
                    "broadcast": broadcast,
                    "isup": isup,
                    "status": "UP" if isup else "DOWN",
                    "speed_mbps": speed,
                    "mtu": mtu,
                }
            )
        return interfaces

    def get_network_ports(self, custom_connections: list[Any] | None = None) -> list[dict[str, Any]]:
        """Collects open listening ports and active network socket connections."""
        ports: list[dict[str, Any]] = []
        connections = custom_connections

        if connections is None:
            try:
                connections = psutil.net_connections(kind="inet")
            except (PermissionError, psutil.AccessDenied, OSError) as err:
                logger.debug("Access denied reading inet connections: %s", err)
                try:
                    connections = psutil.net_connections(kind="all")
                except Exception:
                    connections = []
            except Exception as err:
                logger.debug("Failed to harvest net connections: %s", err)
                connections = []

        for conn in connections:
            try:
                # Protocol detection
                conn_type = getattr(conn, "type", socket.SOCK_STREAM)
                protocol = "udp" if conn_type == socket.SOCK_DGRAM else "tcp"

                laddr = getattr(conn, "laddr", None)
                if not laddr:
                    continue

                local_ip = getattr(laddr, "ip", "0.0.0.0") or "0.0.0.0"  # nosec B104
                local_port = int(getattr(laddr, "port", 0))

                raddr = getattr(conn, "raddr", None)
                remote_ip = getattr(raddr, "ip", None) if raddr else None
                remote_port = int(getattr(raddr, "port", 0)) if raddr and getattr(raddr, "port", None) else None

                state = getattr(conn, "status", None) or ("LISTEN" if protocol == "tcp" and not remote_ip else "NONE")
                pid = getattr(conn, "pid", None)

                proc_name: str | None = None
                exe_path: str | None = None
                if pid is not None and pid > 0:
                    try:
                        p = psutil.Process(pid)
                        proc_name = p.name()
                        exe_path = p.exe()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                        pass

                ports.append(
                    {
                        "protocol": protocol,
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "state": state,
                        "pid": pid,
                        "process_name": proc_name,
                        "exe_path": exe_path,
                    }
                )
            except Exception as err:
                logger.debug("Error parsing network connection entry: %s", err)

        return ports

    # =========================================================================
    # Software Package Harvester
    # =========================================================================

    @staticmethod
    def parse_dpkg_output(output: str) -> list[dict[str, Any]]:
        """Parses dpkg-query tab-delimited output."""
        packages: list[dict[str, Any]] = []
        for line in output.strip().splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                name = parts[0].strip()
                version = parts[1].strip()
                arch = parts[2].strip() if len(parts) > 2 else None
                status = parts[3].strip() if len(parts) > 3 else "install ok installed"
                # Exclude deinstalled/purged packages
                if "not-installed" in status or "config-files" in status:
                    continue
                if name and version:
                    packages.append(
                        {
                            "name": name,
                            "version": version,
                            "architecture": arch,
                            "format": "deb",
                        }
                    )
        return packages

    @staticmethod
    def parse_dpkg_status_content(content: str) -> list[dict[str, Any]]:
        """Parses /var/lib/dpkg/status file content."""
        packages: list[dict[str, Any]] = []
        current_pkg: dict[str, Any] = {}

        for line in content.splitlines():
            raw_line = line.strip()
            if not raw_line:
                if (
                    current_pkg.get("name")
                    and current_pkg.get("version")
                    and "not-installed" not in current_pkg.get("status", "")
                    and "config-files" not in current_pkg.get("status", "")
                ):
                    packages.append(
                        {
                            "name": current_pkg["name"],
                            "version": current_pkg["version"],
                            "architecture": current_pkg.get("architecture"),
                            "format": "deb",
                        }
                    )
                current_pkg = {}
                continue

            if line.startswith("Package:"):
                current_pkg["name"] = line.split(":", 1)[1].strip()
            elif line.startswith("Version:"):
                current_pkg["version"] = line.split(":", 1)[1].strip()
            elif line.startswith("Architecture:"):
                current_pkg["architecture"] = line.split(":", 1)[1].strip()
            elif line.startswith("Status:"):
                current_pkg["status"] = line.split(":", 1)[1].strip()

        if (
            current_pkg.get("name")
            and current_pkg.get("version")
            and "not-installed" not in current_pkg.get("status", "")
            and "config-files" not in current_pkg.get("status", "")
        ):
            packages.append(
                {
                    "name": current_pkg["name"],
                    "version": current_pkg["version"],
                    "architecture": current_pkg.get("architecture"),
                    "format": "deb",
                }
            )
        return packages

    @staticmethod
    def parse_rpm_output(output: str) -> list[dict[str, Any]]:
        """Parses rpm -qa tab-delimited output."""
        packages: list[dict[str, Any]] = []
        for line in output.strip().splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                name = parts[0].strip()
                version = parts[1].strip()
                arch = parts[2].strip() if len(parts) > 2 else None
                if name and version:
                    packages.append(
                        {
                            "name": name,
                            "version": version,
                            "architecture": arch,
                            "format": "rpm",
                        }
                    )
            elif line.strip():
                # Single string like name-version-release.arch
                full = line.strip()
                packages.append(
                    {
                        "name": full,
                        "version": "unknown",
                        "architecture": None,
                        "format": "rpm",
                    }
                )
        return packages

    @staticmethod
    def parse_apk_output(output: str) -> list[dict[str, Any]]:
        """Parses apk info -v output."""
        packages: list[dict[str, Any]] = []
        for line in output.strip().splitlines():
            raw_line = line.strip()
            if not raw_line:
                continue
            # Format: <name>-<version>-r<release>
            parts = raw_line.rsplit("-", 2)
            if len(parts) == 3:
                name = parts[0]
                version = f"{parts[1]}-{parts[2]}"
            elif len(parts) == 2:
                name = parts[0]
                version = parts[1]
            else:
                name = line
                version = "unknown"

            packages.append(
                {
                    "name": name,
                    "version": version,
                    "architecture": None,
                    "format": "apk",
                }
            )
        return packages

    @staticmethod
    def parse_winreg_entry(key_name: str, values: dict[str, Any]) -> dict[str, Any] | None:
        """Extracts installed package details from Windows Registry values dict."""
        display_name = values.get("DisplayName") or values.get("QuietDisplayName")
        if not display_name:
            return None

        display_name_str = str(display_name).strip()
        display_version = str(values.get("DisplayVersion") or "1.0.0").strip()
        publisher = str(values.get("Publisher") or "").strip() or None

        return {
            "name": display_name_str,
            "version": display_version,
            "vendor": publisher,
            "architecture": "x64" if "64" in key_name else "x86",
            "format": "win",
        }

    def _harvest_debian_packages(self) -> list[dict[str, Any]]:
        """Harvests Debian/Ubuntu packages via dpkg-query or status file."""
        if shutil.which("dpkg-query"):
            try:
                res = subprocess.run(  # nosec B603 B607
                    [
                        "dpkg-query",
                        "-W",
                        "-f=${Package}\t${Version}\t${Architecture}\t${Status}\n",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=15,
                )
                if res.returncode == 0 and res.stdout:
                    return self.parse_dpkg_output(res.stdout)
            except Exception as err:
                logger.debug("dpkg-query command failed: %s", err)

        if os.path.exists(self.dpkg_status_path):
            try:
                with open(self.dpkg_status_path, encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                return self.parse_dpkg_status_content(content)
            except Exception as err:
                logger.debug("Failed reading dpkg status file '%s': %s", self.dpkg_status_path, err)

        return []

    def _harvest_rpm_packages(self) -> list[dict[str, Any]]:
        """Harvests RedHat/CentOS/Rocky packages via rpm -qa."""
        if shutil.which("rpm"):
            try:
                res = subprocess.run(  # nosec B603 B607
                    ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=15,
                )
                if res.returncode == 0 and res.stdout:
                    return self.parse_rpm_output(res.stdout)
            except Exception as err:
                logger.debug("rpm -qa command failed: %s", err)
        return []

    def _harvest_apk_packages(self) -> list[dict[str, Any]]:
        """Harvests Alpine Linux packages via apk info -v."""
        if shutil.which("apk"):
            try:
                res = subprocess.run(  # nosec B603 B607
                    ["apk", "info", "-v"],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=15,
                )
                if res.returncode == 0 and res.stdout:
                    return self.parse_apk_output(res.stdout)
            except Exception as err:
                logger.debug("apk info command failed: %s", err)
        return []

    def _harvest_windows_packages(self) -> list[dict[str, Any]]:
        """Harvests installed software from Windows Registry."""
        packages: list[dict[str, Any]] = []
        if platform.system() != "Windows" or winreg is None:
            return packages

        try:
            roots = [
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                    "x64",
                ),
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                    "x86",
                ),
                (
                    winreg.HKEY_CURRENT_USER,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                    "user",
                ),
            ]

            for root_hive, subkey_path, arch in roots:
                try:
                    with winreg.OpenKey(root_hive, subkey_path) as key:
                        num_subkeys = winreg.QueryInfoKey(key)[0]
                        for i in range(num_subkeys):
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                with winreg.OpenKey(key, subkey_name) as app_key:
                                    values: dict[str, Any] = {}
                                    num_values = winreg.QueryInfoKey(app_key)[1]
                                    for v_idx in range(num_values):
                                        val_name, val_data, _ = winreg.EnumValue(app_key, v_idx)
                                        values[val_name] = val_data

                                    entry = self.parse_winreg_entry(subkey_name, values)
                                    if entry:
                                        entry["architecture"] = arch
                                        packages.append(entry)
                            except OSError:
                                continue
                except OSError:
                    continue
        except Exception as err:
            logger.debug("Windows registry package enumeration failed: %s", err)

        return packages

    @staticmethod
    def _harvest_python_packages() -> list[dict[str, Any]]:
        """Harvests installed Python packages from standard importlib metadata."""
        packages: list[dict[str, Any]] = []
        try:
            for dist in importlib.metadata.distributions():
                try:
                    name = dist.metadata.get("Name")
                    version = dist.metadata.get("Version") or dist.version
                    if name and version:
                        packages.append(
                            {
                                "name": name,
                                "version": version,
                                "architecture": None,
                                "format": "pip",
                            }
                        )
                except Exception:
                    continue
        except Exception as err:
            logger.debug("Python distributions enumeration failed: %s", err)

        return packages

    def get_installed_packages(
        self, custom_packages: list[dict[str, Any]] | None = None
    ) -> list[dict[str, Any]]:
        """Extracts complete real software inventory across Linux, Windows, and Python runtime."""
        if custom_packages is not None:
            return custom_packages

        packages: list[dict[str, Any]] = []
        current_os = platform.system()

        if current_os == "Linux":
            debian_pkgs = self._harvest_debian_packages()
            if debian_pkgs:
                packages.extend(debian_pkgs)
            rpm_pkgs = self._harvest_rpm_packages()
            if rpm_pkgs:
                packages.extend(rpm_pkgs)
            apk_pkgs = self._harvest_apk_packages()
            if apk_pkgs:
                packages.extend(apk_pkgs)
        elif current_os == "Windows":
            packages.extend(self._harvest_windows_packages())

        # Always include Python environment packages
        packages.extend(self._harvest_python_packages())

        # Deduplicate while preserving order
        seen: set[tuple[str, str, str]] = set()
        deduped: list[dict[str, Any]] = []
        for pkg in packages:
            key = (
                str(pkg.get("name", "")).lower(),
                str(pkg.get("version", "")),
                str(pkg.get("format", "")),
            )
            if key not in seen and pkg.get("name"):
                seen.add(key)
                deduped.append(pkg)

        return deduped

    # =========================================================================
    # Running Processes
    # =========================================================================

    def get_running_processes(self, limit: int | None = None) -> list[dict[str, Any]]:
        """Collects active running process inventory with process lineage metadata."""
        processes: list[dict[str, Any]] = []
        max_limit = limit if limit is not None else self.process_limit

        attrs = [
            "pid",
            "ppid",
            "name",
            "exe",
            "cmdline",
            "username",
            "cpu_percent",
            "memory_percent",
            "status",
            "create_time",
            "num_threads",
        ]

        try:
            for proc in psutil.process_iter(attrs):
                try:
                    info = proc.info
                    pid = info.get("pid")
                    if pid is None:
                        continue

                    cmdline_val = info.get("cmdline")
                    cmdline_str = (
                        " ".join(cmdline_val)
                        if isinstance(cmdline_val, list)
                        else str(cmdline_val or "")
                    )

                    processes.append(
                        {
                            "pid": int(pid),
                            "ppid": int(info["ppid"]) if info.get("ppid") is not None else None,
                            "name": str(info.get("name") or "unknown"),
                            "exe": str(info["exe"]) if info.get("exe") else None,
                            "cmdline": cmdline_str if cmdline_str else None,
                            "username": str(info["username"]) if info.get("username") else None,
                            "cpu_percent": float(info.get("cpu_percent") or 0.0),
                            "memory_percent": round(float(info.get("memory_percent") or 0.0), 2),
                            "status": str(info["status"]) if info.get("status") else None,
                            "create_time": float(info["create_time"]) if info.get("create_time") else None,
                            "num_threads": int(info["num_threads"]) if info.get("num_threads") else None,
                        }
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                    pass

                if max_limit > 0 and len(processes) >= max_limit:
                    break
        except Exception as err:
            logger.debug("Failed to iterate running processes: %s", err)

        return processes

    # =========================================================================
    # Snapshot Aggregation & Collector Interface
    # =========================================================================

    def collect_inventory(self) -> dict[str, Any]:
        """Gathers full system inventory snapshot matching InventorySnapshotPayload."""
        now = datetime.now(UTC)
        return {
            "snapshot_id": f"syscol-{uuid.uuid4()}",
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "timestamp": now.isoformat(),
            "hardware": self.get_hardware_info(),
            "os": self.get_os_info(),
            "packages": self.get_installed_packages() if self.include_packages else [],
            "network_interfaces": self.get_network_interfaces(),
            "open_ports": self.get_network_ports() if self.include_ports else [],
            "running_processes": self.get_running_processes(limit=self.process_limit)
            if self.include_processes
            else [],
        }

    def collect(self) -> list[dict[str, Any]]:
        """Harvests system inventory snapshot for agent collector scheduler."""
        if not self.enabled:
            return []
        return [self.collect_inventory()]

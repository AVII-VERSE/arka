"""
ARKA Syscollector System Inventory Harvester.
Collects hardware, OS, network interfaces, installed packages, open ports, and running processes.
"""

import platform
from datetime import UTC, datetime
from typing import Any

import psutil


class SyscollectorHarvester:
    """Endpoint System Hardware, Software, and Network Inventory Collector."""

    def __init__(self, agent_id: str = "agent-dev-01", tenant_id: str = "default-tenant"):
        self.agent_id = agent_id
        self.tenant_id = tenant_id

    def get_hardware_info(self) -> dict[str, Any]:
        """Collects CPU, Memory, and Disk hardware inventory."""
        mem = psutil.virtual_memory()
        disks = []
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
            except Exception:
                pass

        return {
            "cpu_cores_logical": psutil.cpu_count(logical=True) or 1,
            "cpu_cores_physical": psutil.cpu_count(logical=False) or 1,
            "cpu_architecture": platform.machine(),
            "ram_total_gb": round(mem.total / (1024**3), 2),
            "ram_available_gb": round(mem.available / (1024**3), 2),
            "ram_used_percent": mem.percent,
            "disks": disks,
        }

    def get_os_info(self) -> dict[str, Any]:
        """Collects Operating System metadata."""
        return {
            "os_name": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "kernel_architecture": platform.machine(),
            "hostname": platform.node(),
            "python_version": platform.python_version(),
        }

    def get_network_interfaces(self) -> list[dict[str, Any]]:
        """Collects network adapters, IP addresses, and MAC addresses."""
        interfaces = []
        addrs = psutil.net_if_addrs()
        for iface_name, iface_addrs in addrs.items():
            ipv4 = None
            ipv6 = None
            mac = None
            for addr in iface_addrs:
                if str(addr.family) == "AddressFamily.AF_INET" or addr.family == 2:
                    ipv4 = addr.address
                elif str(addr.family) == "AddressFamily.AF_INET6" or addr.family in (23, 10):
                    ipv6 = addr.address
                elif addr.address and ":" in addr.address or "-" in addr.address:
                    mac = addr.address

            interfaces.append(
                {
                    "interface_name": iface_name,
                    "ipv4_address": ipv4,
                    "ipv6_address": ipv6,
                    "mac_address": mac,
                }
            )
        return interfaces

    def get_running_processes(self, limit: int = 50) -> list[dict[str, Any]]:
        """Collects active running process inventory."""
        processes = []
        for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent"]):
            try:
                info = proc.info
                processes.append(
                    {
                        "pid": info["pid"],
                        "name": info["name"],
                        "username": info["username"],
                        "cpu_percent": info["cpu_percent"] or 0.0,
                        "memory_percent": round(info["memory_percent"] or 0.0, 2),
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            if len(processes) >= limit:
                break
        return processes

    def collect_inventory(self) -> dict[str, Any]:
        """Gathers full system inventory snapshot."""
        now = datetime.now(UTC)
        return {
            "snapshot_id": f"syscol-{now.timestamp()}",
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "timestamp": now.isoformat(),
            "hardware": self.get_hardware_info(),
            "os": self.get_os_info(),
            "network_interfaces": self.get_network_interfaces(),
            "running_processes": self.get_running_processes(),
        }

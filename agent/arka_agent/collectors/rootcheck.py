"""
# ruff: noqa: PLR0912, PLC0415, PLR1714
ARKA Rootcheck Security Scanner.
Detects rootkits, hidden processes, promiscuous network sockets, and system file anomalies.
"""

import logging
import os
import platform
import stat
import sys
from datetime import UTC, datetime
from typing import Any

import psutil

from arka_agent.collectors.base import BaseCollector

logger = logging.getLogger(__name__)

# Standard high-risk backdoor and C2 listener ports
BACKDOOR_PORTS: tuple[int, ...] = (31337, 6667, 4444, 12345, 65535)

# Linux promiscuous interface flag (IFF_PROMISC = 0x100)
IFF_PROMISC_FLAG: int = 0x100


class RootcheckScanner(BaseCollector):
    """Endpoint Rootkit and System Anomaly Security Scanner."""

    def __init__(
        self,
        agent_id: str = "agent-dev-01",
        tenant_id: str = "default-tenant",
        enabled: bool = True,
        suspicious_paths: list[str] | None = None,
        proc_dir: str = "/proc",
        sys_net_dir: str = "/sys/class/net",
        preload_path: str = "/etc/ld.so.preload",
        critical_binaries: list[str] | None = None,
        suid_scan_dirs: list[str] | None = None,
    ):
        super().__init__(name="rootcheck", enabled=enabled)
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self.proc_dir = proc_dir
        self.sys_net_dir = sys_net_dir
        self.preload_path = preload_path
        self.suspicious_paths = (
            suspicious_paths if suspicious_paths is not None else self._get_suspicious_paths()
        )
        self.critical_binaries = (
            critical_binaries if critical_binaries is not None else self._get_critical_binaries()
        )
        self.suid_scan_dirs = (
            suid_scan_dirs if suid_scan_dirs is not None else self._get_suid_scan_dirs()
        )

    def _get_suspicious_paths(self) -> list[str]:
        """Returns platform-specific known rootkit artifact paths."""
        if platform.system().lower() == "windows":
            system_root = os.getenv("SystemRoot", r"C:\Windows")
            program_data = os.getenv("ProgramData", r"C:\ProgramData")
            return [
                os.path.join(system_root, "System32", "drivers", "etc", ".hidden"),
                os.path.join(system_root, "Temp", ".rootkit"),  # nosec B108
                os.path.join(system_root, "System32", "drivers", "rootkit.sys"),
                os.path.join(system_root, "System32", "drivers", "vboxhook.sys"),
                os.path.join(system_root, "System32", "drivers", "netfilter.sys"),
                os.path.join(system_root, "System32", "config", ".hidden"),
                os.path.join(program_data, ".rootkit"),
            ]
        else:
            return [
                # Diamorphine artifacts
                "/dev/diamorphine",
                "/dev/diamorphine_secret",
                # Reptile artifacts
                "/dev/reptile",
                "/tmp/.reptile",  # nosec B108
                "/etc/reptile",
                # Azazel & library artifacts
                "/lib/libcrypt.so.2",
                "/lib/libselinux.so",
                # Adore-ng & Knark
                "/dev/null_0",
                "/dev/kmem_0",
                "/proc/knark",
                # Generic & legacy rootkit signatures (t0rn, Ebury, etc.)
                "/usr/src/.puta",
                "/dev/.udev",
                "/dev/.shm",
                "/dev/.static",
                "/dev/.pdev",
                "/tmp/.icm",  # nosec B108
                "/tmp/.hidden",  # nosec B108
                "/var/tmp/.rootkit",  # nosec B108
                "/usr/share/.rootkit",
                "/etc/.rootkit",
                "/dev/shm/.hidden",
            ]

    def _get_critical_binaries(self) -> list[str]:
        """Returns critical system binaries for integrity and permission audit."""
        if platform.system().lower() == "windows":
            system_root = os.getenv("SystemRoot", r"C:\Windows")
            return [
                os.path.join(system_root, "System32", "cmd.exe"),
                os.path.join(system_root, "System32", "svchost.exe"),
                os.path.join(system_root, "System32", "lsass.exe"),
            ]
        else:
            return [
                "/bin/ps",
                "/bin/netstat",
                "/bin/ls",
                "/bin/login",
                "/usr/sbin/sshd",
                "/bin/su",
                "/usr/bin/sudo",
            ]

    def _get_suid_scan_dirs(self) -> list[str]:
        """Returns volatile / world-writable directories to audit for anomalous SUID/SGID binaries."""
        if platform.system().lower() == "windows":
            return []
        return ["/tmp", "/var/tmp", "/dev/shm"]  # nosec B108

    def _build_event(
        self,
        event_prefix: str,
        action: str,
        severity: str,
        message: str,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        """Helper to create standardized NormalizedEvent dictionaries."""
        now = datetime.now(UTC)
        unique_suffix = f"{now.timestamp()}-{os.urandom(4).hex()}"
        return {
            "event_id": f"rootcheck-{event_prefix}-{unique_suffix}",
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "timestamp": now.isoformat(),
            "source_type": "rootcheck",
            "host": platform.node(),
            "event_type": "rootkit_detection",
            "action": action,
            "severity": severity,
            "message": message,
            "metadata": metadata,
            "ingested_at": now.isoformat(),
        }

    def scan_suspicious_files(self, paths: list[str] | None = None) -> list[dict[str, Any]]:  # noqa: PLR0912
        """Scans filesystem for known rootkit artifact paths, suspicious drivers, and anomalous SUID/SGID binaries."""
        findings: list[dict[str, Any]] = []
        target_paths = paths if paths is not None else self.suspicious_paths

        # 1. Check known artifact paths
        for path in target_paths:
            try:
                if os.path.exists(path):
                    is_dir = os.path.isdir(path)
                    try:
                        file_stat = os.stat(path)
                        size_bytes = file_stat.st_size
                        mode_octal = oct(file_stat.st_mode)
                    except (PermissionError, OSError):
                        size_bytes = -1
                        mode_octal = "unknown"

                    findings.append(
                        self._build_event(
                            event_prefix="file",
                            action="suspicious_file_found",
                            severity="CRITICAL",
                            message=f"Rootcheck Alert: Known rootkit artifact found at '{path}'",
                            metadata={
                                "suspicious_path": path,
                                "scan_type": "filesystem",
                                "is_directory": is_dir,
                                "size_bytes": size_bytes,
                                "mode": mode_octal,
                                "mitre_technique": "T1014",
                            },
                        )
                    )
            except (PermissionError, OSError) as err:
                logger.debug("Permission denied or OS error checking path '%s': %s", path, err)

        # 2. Check volatile directories for anomalous SUID/SGID binaries (Linux/Unix)
        for dir_path in self.suid_scan_dirs:
            try:
                if os.path.exists(dir_path) and os.path.isdir(dir_path):
                    for root, _dirs, files in os.walk(dir_path):
                        for file_name in files:
                            file_full_path = os.path.join(root, file_name)
                            try:
                                file_stat = os.stat(file_full_path)
                                is_suid = (
                                    bool(file_stat.st_mode & stat.S_ISUID)
                                    if hasattr(stat, "S_ISUID")
                                    else False
                                )
                                is_sgid = (
                                    bool(file_stat.st_mode & stat.S_ISGID)
                                    if hasattr(stat, "S_ISGID")
                                    else False
                                )
                                if is_suid or is_sgid:
                                    findings.append(
                                        self._build_event(
                                            event_prefix="suid",
                                            action="suspicious_suid_binary_found",
                                            severity="CRITICAL",
                                            message=(
                                                f"Rootcheck Alert: Anomalous SUID/SGID binary found "
                                                f"in volatile directory '{file_full_path}'"
                                            ),
                                            metadata={
                                                "suspicious_path": file_full_path,
                                                "scan_type": "suid_binaries",
                                                "is_suid": is_suid,
                                                "is_sgid": is_sgid,
                                                "mode": oct(file_stat.st_mode),
                                                "mitre_technique": "T1548.001",
                                            },
                                        )
                                    )
                            except (PermissionError, OSError) as err:
                                logger.debug(
                                    "Error stating SUID candidate '%s': %s", file_full_path, err
                                )
            except (PermissionError, OSError) as err:
                logger.debug("Error traversing SUID scan directory '%s': %s", dir_path, err)

        # 3. Check Windows Registry Startup & Driver artifacts if on Windows
        if sys.platform == "win32":
            try:
                import winreg  # noqa: PLC0415

                # Audit Run / RunOnce startup persistence keys
                startup_keys = [
                    (
                        winreg.HKEY_LOCAL_MACHINE,
                        r"Software\Microsoft\Windows\CurrentVersion\Run",
                    ),
                    (
                        winreg.HKEY_LOCAL_MACHINE,
                        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                    ),
                    (
                        winreg.HKEY_LOCAL_MACHINE,
                        r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                    ),
                ]
                for hkey, subkey in startup_keys:
                    try:
                        with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as reg_key:
                            num_values = winreg.QueryInfoKey(reg_key)[1]
                            for idx in range(num_values):
                                val_name, val_data, _ = winreg.EnumValue(reg_key, idx)
                                if isinstance(val_data, str) and (
                                    ".rootkit" in val_data.lower()
                                    or "\\temp\\" in val_data.lower()
                                    or "cmd.exe /c powershell" in val_data.lower()
                                ):
                                    findings.append(
                                        self._build_event(
                                            event_prefix="reg",
                                            action="suspicious_registry_startup_found",
                                            severity="HIGH",
                                            message=(
                                                f"Rootcheck Alert: Suspicious startup registry entry "
                                                f"'{val_name}' pointing to '{val_data}'"
                                            ),
                                            metadata={
                                                "registry_key": subkey,
                                                "value_name": val_name,
                                                "value_data": val_data,
                                                "scan_type": "windows_registry",
                                                "mitre_technique": "T1547.001",
                                            },
                                        )
                                    )
                    except (OSError, PermissionError) as reg_err:
                        logger.debug("Error reading registry key '%s': %s", subkey, reg_err)
            except ImportError:
                pass

        return findings

    def scan_hidden_processes(  # noqa: PLR0912
        self,
        known_pids: set[int] | None = None,
        candidate_pids: set[int] | None = None,
    ) -> list[dict[str, Any]]:
        """Dual-view cross-validation between psutil.pids() and raw /proc directory enumeration / OS signals."""
        findings: list[dict[str, Any]] = []

        try:
            psutil_pids: set[int] = known_pids if known_pids is not None else set(psutil.pids())
        except (psutil.AccessDenied, PermissionError, OSError) as err:
            logger.debug("Error obtaining psutil.pids(): %s", err)
            psutil_pids = set()

        raw_proc_pids: set[int] = set()

        # View 1: Raw /proc filesystem inspection on Linux/Unix
        if os.path.exists(self.proc_dir) and os.path.isdir(self.proc_dir):
            try:
                for entry in os.listdir(self.proc_dir):
                    if entry.isdigit():
                        raw_proc_pids.add(int(entry))
            except (PermissionError, OSError) as err:
                logger.debug("Error reading raw proc directory '%s': %s", self.proc_dir, err)

        # Cross-validation View A: PIDs in raw /proc but absent in psutil.pids()
        hidden_proc_pids = set(raw_proc_pids - psutil_pids)

        # Cross-validation View B: If candidate PIDs are provided or probed on POSIX
        if candidate_pids:
            for c_pid in candidate_pids:
                if c_pid not in psutil_pids:
                    if hasattr(os, "kill") and platform.system().lower() != "windows":
                        try:
                            os.kill(c_pid, 0)
                            hidden_proc_pids.add(c_pid)
                        except ProcessLookupError:
                            pass
                        except PermissionError:
                            hidden_proc_pids.add(c_pid)
                        except OSError:
                            pass

        for pid in sorted(hidden_proc_pids):
            cmdline = "unknown"
            comm = "unknown"
            cmdline_path = os.path.join(self.proc_dir, str(pid), "cmdline")
            comm_path = os.path.join(self.proc_dir, str(pid), "comm")

            try:
                if os.path.exists(comm_path):
                    with open(comm_path, encoding="utf-8", errors="replace") as f:
                        comm = f.read().strip()
                if os.path.exists(cmdline_path):
                    with open(cmdline_path, encoding="utf-8", errors="replace") as f:
                        raw_cmd = f.read().replace("\x00", " ").strip()
                        if raw_cmd:
                            cmdline = raw_cmd
            except (PermissionError, OSError):
                pass

            findings.append(
                self._build_event(
                    event_prefix="hiddenproc",
                    action="hidden_process_detected",
                    severity="CRITICAL",
                    message=(
                        f"Rootcheck Alert: Hidden process detected with PID {pid} "
                        f"(present in kernel/proc but absent in API process table)"
                    ),
                    metadata={
                        "pid": pid,
                        "process_name": comm if comm != "unknown" else None,
                        "cmdline": cmdline if cmdline != "unknown" else None,
                        "detection_method": "proc_cross_validation",
                        "scan_type": "hidden_processes",
                        "mitre_technique": "T1014",
                    },
                )
            )

        return findings

    def scan_listening_ports(  # noqa: PLR0912
        self, custom_connections: list[Any] | None = None
    ) -> list[dict[str, Any]]:
        """Scans for unmapped sockets, high-risk backdoor ports, and promiscuous network interfaces."""
        findings: list[dict[str, Any]] = []

        # 1. Scan network connections for backdoor and unmapped listener sockets
        try:
            connections = (
                custom_connections
                if custom_connections is not None
                else psutil.net_connections(kind="inet")
            )
        except (psutil.AccessDenied, PermissionError, OSError) as err:
            logger.debug("Access denied or error collecting net_connections: %s", err)
            connections = []

        for conn in connections:
            try:
                status = getattr(conn, "status", None)
                laddr = getattr(conn, "laddr", None)

                # Check if listening connection
                is_listening = (
                    status in (psutil.CONN_LISTEN, "LISTEN")
                    or (hasattr(conn, "type") and conn.type == 2)  # UDP socket
                )

                if is_listening and laddr:
                    port = getattr(laddr, "port", None)
                    ip = getattr(laddr, "ip", "0.0.0.0")  # nosec B104
                    pid = getattr(conn, "pid", None)

                    if port is None:
                        continue

                    # A. High-risk backdoor ports
                    if port in BACKDOOR_PORTS:
                        proc_name = "unknown"
                        proc_exe = None
                        if pid:
                            try:
                                p = psutil.Process(pid)
                                proc_name = p.name()
                                proc_exe = p.exe()
                            except (
                                psutil.NoSuchProcess,
                                psutil.AccessDenied,
                                psutil.ZombieProcess,
                                OSError,
                            ):
                                pass

                        findings.append(
                            self._build_event(
                                event_prefix=f"port-{port}",
                                action="suspicious_port_listening",
                                severity="HIGH",
                                message=(
                                    f"Rootcheck Alert: High-risk backdoor port {port} "
                                    f"detected listening (PID: {pid}, Process: {proc_name})"
                                ),
                                metadata={
                                    "port": port,
                                    "local_ip": ip,
                                    "pid": pid,
                                    "process_name": proc_name,
                                    "process_exe": proc_exe,
                                    "scan_type": "network_sockets",
                                    "mitre_technique": "T1571",
                                },
                            )
                        )

                    # B. Unmapped listener sockets (listening with no associated PID)
                    elif pid is None or pid == 0:
                        findings.append(
                            self._build_event(
                                event_prefix=f"unmapped-{port}",
                                action="unmapped_socket_detected",
                                severity="HIGH",
                                message=(
                                    f"Rootcheck Alert: Unmapped listening socket on {ip}:{port} "
                                    f"with no associating user-space PID"
                                ),
                                metadata={
                                    "port": port,
                                    "local_ip": ip,
                                    "pid": pid,
                                    "scan_type": "network_sockets",
                                    "mitre_technique": "T1014",
                                },
                            )
                        )
            except Exception as conn_err:
                logger.debug("Error processing network connection item: %s", conn_err)

        # 2. Promiscuous network interface scanner (Linux /sys/class/net/<iface>/flags)
        if os.path.exists(self.sys_net_dir) and os.path.isdir(self.sys_net_dir):
            try:
                for iface in os.listdir(self.sys_net_dir):
                    flags_file = os.path.join(self.sys_net_dir, iface, "flags")
                    try:
                        if os.path.exists(flags_file):
                            with open(flags_file, encoding="utf-8") as f:
                                flag_content = f.read().strip()
                            flags = int(flag_content, 0)
                            if flags & IFF_PROMISC_FLAG:
                                findings.append(
                                    self._build_event(
                                        event_prefix=f"promisc-{iface}",
                                        action="promiscuous_interface_detected",
                                        severity="CRITICAL",
                                        message=(
                                            f"Rootcheck Alert: Network interface '{iface}' is operating "
                                            f"in promiscuous mode (IFF_PROMISC flag set: {hex(flags)})"
                                        ),
                                        metadata={
                                            "interface": iface,
                                            "flags_hex": hex(flags),
                                            "scan_type": "promiscuous_interface",
                                            "mitre_technique": "T1040",
                                        },
                                    )
                                )
                    except (PermissionError, ValueError, OSError) as iface_err:
                        logger.debug("Error checking flags for interface '%s': %s", iface, iface_err)
            except (PermissionError, OSError) as net_err:
                logger.debug("Error scanning sys_net_dir '%s': %s", self.sys_net_dir, net_err)

        return findings

    def scan_system_binaries(  # noqa: PLR0912
        self,
        preload_path: str | None = None,
        binaries: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Audits dynamic linker preload tampering (/etc/ld.so.preload, AppInit_DLLs) and critical binary permissions."""
        findings: list[dict[str, Any]] = []
        target_preload = preload_path if preload_path is not None else self.preload_path
        target_binaries = binaries if binaries is not None else self.critical_binaries

        # 1. Check dynamic linker preload tampering (Linux /etc/ld.so.preload)
        if target_preload and os.path.exists(target_preload):
            try:
                with open(target_preload, encoding="utf-8", errors="replace") as f:
                    lines = [
                        line.strip()
                        for line in f
                        if line.strip() and not line.strip().startswith("#")
                    ]
                if lines:
                    findings.append(
                        self._build_event(
                            event_prefix="preload",
                            action="preload_tampering_detected",
                            severity="CRITICAL",
                            message=(
                                f"Rootcheck Alert: Dynamic linker preload file '{target_preload}' "
                                f"contains active injected libraries: {lines}"
                            ),
                            metadata={
                                "preload_path": target_preload,
                                "injected_libraries": lines,
                                "scan_type": "system_binaries",
                                "mitre_technique": "T1574.006",
                            },
                        )
                    )
            except (PermissionError, OSError) as err:
                logger.debug("Error reading preload file '%s': %s", target_preload, err)

        # 2. Check Windows AppInit_DLLs Registry Tampering
        if sys.platform == "win32":
            try:
                import winreg  # noqa: PLC0415

                appinit_keys = [
                    (
                        winreg.HKEY_LOCAL_MACHINE,
                        r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
                    ),
                    (
                        winreg.HKEY_LOCAL_MACHINE,
                        r"Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
                    ),
                ]
                for hkey, subkey in appinit_keys:
                    try:
                        with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as reg_key:
                            try:
                                appinit_dlls, _ = winreg.QueryValueEx(reg_key, "AppInit_DLLs")
                                load_appinit, _ = winreg.QueryValueEx(
                                    reg_key, "LoadAppInit_DLLs"
                                )
                            except FileNotFoundError:
                                appinit_dlls, load_appinit = "", 0

                            if appinit_dlls and str(appinit_dlls).strip():
                                findings.append(
                                    self._build_event(
                                        event_prefix="appinit",
                                        action="appinit_dlls_tampering_detected",
                                        severity="CRITICAL",
                                        message=(
                                            f"Rootcheck Alert: Windows AppInit_DLLs contains "
                                            f"injected libraries: '{appinit_dlls}'"
                                        ),
                                        metadata={
                                            "registry_key": subkey,
                                            "appinit_dlls": str(appinit_dlls),
                                            "load_appinit": load_appinit,
                                            "scan_type": "system_binaries",
                                            "mitre_technique": "T1574.006",
                                        },
                                    )
                                )
                    except (OSError, PermissionError) as reg_err:
                        logger.debug("Error reading AppInit registry key '%s': %s", subkey, reg_err)
            except ImportError:
                pass

        # 3. Audit critical system binaries for existence and permission anomalies
        for binary_path in target_binaries:
            parent_dir = os.path.dirname(binary_path)
            try:
                # If parent directory exists, we expect system binary to be present and intact
                if parent_dir and os.path.exists(parent_dir) and os.path.isdir(parent_dir):
                    if not os.path.exists(binary_path):
                        findings.append(
                            self._build_event(
                                event_prefix="bin-missing",
                                action="critical_binary_missing",
                                severity="HIGH",
                                message=(
                                    f"Rootcheck Alert: Critical system binary '{binary_path}' "
                                    f"is missing from system."
                                ),
                                metadata={
                                    "binary_path": binary_path,
                                    "parent_dir": parent_dir,
                                    "scan_type": "system_binaries",
                                    "mitre_technique": "T1036",
                                },
                            )
                        )
                    else:
                        file_stat = os.stat(binary_path)
                        # Check for empty / zero-byte tampered binary
                        if file_stat.st_size == 0:
                            findings.append(
                                self._build_event(
                                    event_prefix="bin-empty",
                                    action="critical_binary_tampered",
                                    severity="HIGH",
                                    message=(
                                        f"Rootcheck Alert: Critical system binary '{binary_path}' "
                                        f"is truncated to 0 bytes."
                                    ),
                                    metadata={
                                        "binary_path": binary_path,
                                        "size_bytes": 0,
                                        "scan_type": "system_binaries",
                                        "mitre_technique": "T1036",
                                    },
                                )
                            )
                        # Check for insecure world-writable permission on Unix
                        if hasattr(stat, "S_IWOTH") and (file_stat.st_mode & stat.S_IWOTH):
                            findings.append(
                                self._build_event(
                                    event_prefix="bin-perm",
                                    action="binary_permission_anomaly",
                                    severity="CRITICAL",
                                    message=(
                                        f"Rootcheck Alert: Critical system binary '{binary_path}' "
                                        f"has insecure world-writable permissions ({oct(file_stat.st_mode)})"
                                    ),
                                    metadata={
                                        "binary_path": binary_path,
                                        "mode": oct(file_stat.st_mode),
                                        "scan_type": "system_binaries",
                                        "mitre_technique": "T1222",
                                    },
                                )
                            )
            except (PermissionError, OSError) as err:
                logger.debug("Error auditing system binary '%s': %s", binary_path, err)

        return findings

    def run_full_scan(self) -> list[dict[str, Any]]:
        """Executes complete rootcheck security audit across all anomaly sub-harvesters."""
        events: list[dict[str, Any]] = []
        events.extend(self.scan_suspicious_files())
        events.extend(self.scan_hidden_processes())
        events.extend(self.scan_listening_ports())
        events.extend(self.scan_system_binaries())
        return events

    def collect(self) -> list[dict[str, Any]]:
        """Standard collector interface harvest method."""
        if not self.enabled:
            return []
        return self.run_full_scan()

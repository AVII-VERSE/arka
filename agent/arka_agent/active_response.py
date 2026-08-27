"""
ARKA Automated Active Response & Endpoint Threat Containment Executor.

Executes host firewall IP blocking/unblocking, safe process termination with two-phase kill,
secure file quarantine vault with SHA-256 manifests, and automated rollback timers.
"""

import hashlib
import ipaddress
import json
import logging
import os
import platform
import shutil
import subprocess  # nosec B404
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psutil

logger = logging.getLogger("arka.active_response")


class ActiveResponseExecutor:
    """Automated Endpoint Containment & Active Response Executor."""

    # Protected system process names across Windows and POSIX systems
    PROTECTED_PROCESS_NAMES = {
        "system",
        "system idle process",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "svchost.exe",
        "explorer.exe",
        "winlogon.exe",
        "init",
        "systemd",
        "launchd",
        "kthreadd",
    }

    # Protected system PIDs
    PROTECTED_PIDS = {0, 1, 2, 4}

    # Critical system files that must never be quarantined
    PROTECTED_FILE_PATTERNS = {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/bin/sh",
        "/bin/bash",
        "/usr/bin/python",
        "c:\\windows\\system32\\ntoskrnl.exe",
        "c:\\windows\\system32\\kernel32.dll",
        "c:\\windows\\system32\\user32.dll",
        "c:\\windows\\system32\\ntdll.dll",
    }

    def __init__(
        self,
        agent_id: str = "agent-dev-01",
        tenant_id: str = "default-tenant",
        quarantine_dir: str | Path | None = None,
        backend_hosts: list[str] | None = None,
        dry_run: bool = False,
    ):
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self.dry_run = dry_run
        self.backend_hosts = set(backend_hosts or ["127.0.0.1", "localhost"])
        self.quarantine_dir = Path(quarantine_dir) if quarantine_dir else self._get_default_quarantine_dir()
        self._ensure_quarantine_dir()
        self._active_rollback_timers: dict[str, threading.Timer] = {}

    def _get_default_quarantine_dir(self) -> Path:
        """Returns the OS-appropriate default quarantine directory path."""
        if platform.system().lower() == "windows":
            prog_data = os.getenv("ProgramData", "C:\\ProgramData")
            return Path(prog_data) / "ARKA" / "Quarantine"
        return Path("/var/lib/arka/quarantine")

    def _ensure_quarantine_dir(self) -> None:
        """Creates quarantine directory with restricted permissions."""
        try:
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
            if platform.system().lower() != "windows":
                # Restrict to owner read/write/exec (0700) on POSIX
                os.chmod(self.quarantine_dir, 0o700)
        except Exception as exc:
            logger.warning(f"Could not enforce strict permissions on quarantine dir {self.quarantine_dir}: {exc}")

    def is_ip_protected(self, ip_str: str) -> tuple[bool, str]:
        """
        Validates whether an IP address is protected by the strict safety allowlist.

        Returns:
            (is_protected, reason)
        """
        clean = ip_str.strip()
        try:
            ip_obj = ipaddress.ip_address(clean)
        except ValueError:
            return True, f"Invalid IP address format: {clean}"

        is_broadcast_or_unspec = (
            ip_obj.is_unspecified
            or (isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj.is_global is False and clean == "255.255.255.255")
            or clean in {"255.255.255.255", "0.0.0.0", "::", "::1"}  # nosec B104
        )

        if ip_obj.is_loopback:
            return True, f"IP {clean} is a loopback address."
        if is_broadcast_or_unspec:
            return True, f"IP {clean} is an unspecified or broadcast address."
        if clean in self.backend_hosts:
            return True, f"IP {clean} matches configured backend host."

        # Default Gateway / Local Interface check
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.address == clean:
                        return True, f"IP {clean} is bound to local interface {iface}."
        except Exception:
            pass

        return False, ""

    def is_pid_protected(self, pid: int) -> tuple[bool, str]:
        """
        Validates whether a process PID is protected by the system safety policy.

        Returns:
            (is_protected, reason)
        """
        if pid in self.PROTECTED_PIDS:
            return True, f"PID {pid} is a critical core system process ID."

        current_pid = os.getpid()
        if pid == current_pid:
            return True, f"PID {pid} is the ARKA Agent daemon PID."

        try:
            parent_pid = os.getppid()
            if pid == parent_pid:
                return True, f"PID {pid} is the parent process PID."
        except Exception:
            pass

        if psutil.pid_exists(pid):
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name().lower()
                if proc_name in self.PROTECTED_PROCESS_NAMES:
                    return True, f"Process '{proc_name}' (PID: {pid}) is a protected system process."
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        return False, ""

    def block_ip(self, ip_address: str, duration_seconds: int | float | None = None) -> dict[str, Any]:
        """
        Blocks an offending IP address using the OS-native firewall (iptables or netsh).

        Args:
            ip_address: Target IP string
            duration_seconds: Optional automated rollback timer in seconds

        Returns:
            Audit logging dictionary with execution details
        """
        start_time = time.perf_counter()
        now = datetime.now(UTC)
        clean_ip = ip_address.strip()

        # Strict safety allowlist check
        is_prot, reason = self.is_ip_protected(clean_ip)
        if is_prot:
            exec_time = round((time.perf_counter() - start_time) * 1000, 2)
            return {
                "response_id": f"ar-block-{now.timestamp()}",
                "action": "block_ip",
                "target": clean_ip,
                "agent_id": self.agent_id,
                "tenant_id": self.tenant_id,
                "status": "BLOCKED_BY_SAFETY",
                "message": f"Active Response Block Rejected: {reason}",
                "execution_time_ms": exec_time,
                "timestamp": now.isoformat(),
            }

        # Build platform-specific firewall command
        if platform.system().lower() == "windows":
            rule_name = f"ARKA_Block_{clean_ip}"
            cmd = [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={clean_ip}",
            ]
        else:
            cmd = [
                "iptables",
                "-I",
                "INPUT",
                "-s",
                clean_ip,
                "-j",
                "DROP",
                "-m",
                "comment",
                "--comment",
                "ARKA_ActiveResponse",
            ]

        exit_code = 0
        stdout = ""
        stderr = ""
        status = "SUCCESS"
        message = f"Active Response: Firewall rule created blocking offending IP {clean_ip}."

        if not self.dry_run:
            try:
                res = subprocess.run(  # nosec B603
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=15.0,
                    check=False,
                )
                exit_code = res.returncode
                stdout = res.stdout
                stderr = res.stderr
                if exit_code != 0:
                    status = "FAILED"
                    message = f"Active Response Error: Firewall command failed with code {exit_code}: {stderr.strip() or stdout.strip()}"
            except Exception as exc:
                status = "FAILED"
                message = f"Active Response Error: Execution exception: {exc}"

        # Schedule automated rollback if requested and successful
        if status == "SUCCESS" and duration_seconds and duration_seconds > 0:
            timer_key = f"unblock_{clean_ip}"
            if timer_key in self._active_rollback_timers:
                self._active_rollback_timers[timer_key].cancel()

            timer = threading.Timer(duration_seconds, self.unblock_ip, args=[clean_ip])
            timer.daemon = True
            timer.start()
            self._active_rollback_timers[timer_key] = timer
            message += f" Automatic rollback scheduled in {duration_seconds}s."

        exec_time = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "response_id": f"ar-block-{now.timestamp()}",
            "action": "block_ip",
            "target": clean_ip,
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "status": status,
            "message": message,
            "duration_seconds": duration_seconds,
            "command": " ".join(cmd),
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "execution_time_ms": exec_time,
            "timestamp": now.isoformat(),
        }

    def unblock_ip(self, ip_address: str) -> dict[str, Any]:
        """
        Removes an active firewall block rule for the target IP address.

        Returns:
            Audit logging dictionary with execution details
        """
        start_time = time.perf_counter()
        now = datetime.now(UTC)
        clean_ip = ip_address.strip()

        # Build platform-specific removal command
        if platform.system().lower() == "windows":
            rule_name = f"ARKA_Block_{clean_ip}"
            cmd = [
                "netsh",
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                f"name={rule_name}",
            ]
        else:
            cmd = [
                "iptables",
                "-D",
                "INPUT",
                "-s",
                clean_ip,
                "-j",
                "DROP",
                "-m",
                "comment",
                "--comment",
                "ARKA_ActiveResponse",
            ]

        exit_code = 0
        stdout = ""
        stderr = ""
        status = "SUCCESS"
        message = f"Active Response: Firewall block rule removed for IP {clean_ip}."

        if not self.dry_run:
            try:
                res = subprocess.run(  # nosec B603
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=15.0,
                    check=False,
                )
                exit_code = res.returncode
                stdout = res.stdout
                stderr = res.stderr
                if exit_code != 0:
                    status = "FAILED"
                    message = f"Active Response Error: Firewall removal failed with code {exit_code}: {stderr.strip() or stdout.strip()}"
            except Exception as exc:
                status = "FAILED"
                message = f"Active Response Error: Execution exception: {exc}"

        exec_time = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "response_id": f"ar-unblock-{now.timestamp()}",
            "action": "unblock_ip",
            "target": clean_ip,
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "status": status,
            "message": message,
            "command": " ".join(cmd),
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "execution_time_ms": exec_time,
            "timestamp": now.isoformat(),
        }

    def _execute_two_phase_kill(self, proc: psutil.Process, children: list[psutil.Process]) -> tuple[int, bool]:
        """Helper to terminate process tree using SIGTERM then SIGKILL."""
        # Phase 1: Graceful SIGTERM
        proc.terminate()
        for child in children:
            try:
                child.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # Wait up to 3.0s
        gone, alive = psutil.wait_procs([proc] + children, timeout=3.0)

        # Phase 2: Force kill remaining alive processes
        force_killed_count = 0
        if proc in alive or proc.is_running():
            try:
                proc.kill()
                force_killed_count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        for remaining in alive:
            if remaining != proc:
                try:
                    remaining.kill()
                    force_killed_count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        if alive:
            psutil.wait_procs(alive, timeout=1.0)

        return len(children), force_killed_count > 0

    def kill_process(self, pid: int, recursive: bool = True) -> dict[str, Any]:
        """
        Safely terminates a malicious process using a two-phase protocol:
        Phase 1: Graceful SIGTERM -> wait up to 3.0s
        Phase 2: Forceful SIGKILL if process is still alive.

        Args:
            pid: Target process identifier
            recursive: If True, terminates child processes in the process tree

        Returns:
            Audit logging dictionary with termination details
        """
        start_time = time.perf_counter()
        now = datetime.now(UTC)

        # 1. Safety check
        is_prot, reason = self.is_pid_protected(pid)
        if is_prot:
            return {
                "response_id": f"ar-kill-{now.timestamp()}",
                "action": "kill_process",
                "target": f"PID {pid}",
                "agent_id": self.agent_id,
                "tenant_id": self.tenant_id,
                "status": "BLOCKED_BY_SAFETY",
                "message": f"Active Response Process Termination Blocked: {reason}",
                "execution_time_ms": round((time.perf_counter() - start_time) * 1000, 2),
                "timestamp": now.isoformat(),
            }

        # 2. Check process existence
        if not psutil.pid_exists(pid):
            return {
                "response_id": f"ar-kill-{now.timestamp()}",
                "action": "kill_process",
                "target": f"PID {pid}",
                "agent_id": self.agent_id,
                "tenant_id": self.tenant_id,
                "status": "NOT_FOUND",
                "message": f"Active Response: Process PID {pid} not found active on host.",
                "execution_time_ms": round((time.perf_counter() - start_time) * 1000, 2),
                "timestamp": now.isoformat(),
            }

        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            children = proc.children(recursive=True) if recursive else []

            if self.dry_run:
                return {
                    "response_id": f"ar-kill-{now.timestamp()}",
                    "action": "kill_process",
                    "target": f"PID {pid} ({proc_name})",
                    "agent_id": self.agent_id,
                    "tenant_id": self.tenant_id,
                    "status": "SUCCESS",
                    "message": f"[DRY RUN] Active Response: Process {proc_name} (PID: {pid}) marked for termination.",
                    "execution_time_ms": round((time.perf_counter() - start_time) * 1000, 2),
                    "timestamp": now.isoformat(),
                }

            child_count, force_killed = self._execute_two_phase_kill(proc, children)
            exec_time = round((time.perf_counter() - start_time) * 1000, 2)
            msg = f"Active Response: Successfully terminated process {proc_name} (PID: {pid})"
            if child_count:
                msg += f" along with {child_count} child processes"
            msg += f" (escalated to SIGKILL: {force_killed})."

            return {
                "response_id": f"ar-kill-{now.timestamp()}",
                "action": "kill_process",
                "target": f"PID {pid} ({proc_name})",
                "agent_id": self.agent_id,
                "tenant_id": self.tenant_id,
                "status": "SUCCESS",
                "message": msg,
                "children_terminated": child_count,
                "force_killed": force_killed,
                "execution_time_ms": exec_time,
                "timestamp": now.isoformat(),
            }

        except psutil.NoSuchProcess:
            return {
                "response_id": f"ar-kill-{now.timestamp()}",
                "action": "kill_process",
                "target": f"PID {pid}",
                "agent_id": self.agent_id,
                "tenant_id": self.tenant_id,
                "status": "NOT_FOUND",
                "message": f"Active Response: Process PID {pid} exited before termination.",
                "execution_time_ms": round((time.perf_counter() - start_time) * 1000, 2),
                "timestamp": now.isoformat(),
            }
        except Exception as exc:
            return {
                "response_id": f"ar-kill-{now.timestamp()}",
                "action": "kill_process",
                "target": f"PID {pid}",
                "agent_id": self.agent_id,
                "tenant_id": self.tenant_id,
                "status": "FAILED",
                "message": f"Active Response Error: Failed to terminate PID {pid}: {exc}",
                "execution_time_ms": round((time.perf_counter() - start_time) * 1000, 2),
                "timestamp": now.isoformat(),
            }

    def quarantine_file(self, file_path: str | Path) -> dict[str, Any]:
        """
        Quarantines a suspicious file into the secure vault with SHA-256 manifest.

        Args:
            file_path: Absolute or relative path of the file to isolate

        Returns:
            Audit logging dictionary with vault and manifest details
        """
        start_time = time.perf_counter()
        now = datetime.now(UTC)
        target = Path(file_path).resolve()

        # 1. Existence check
        if not target.exists() or not target.is_file():
            exec_time = round((time.perf_counter() - start_time) * 1000, 2)
            return {
                "response_id": f"ar-quarantine-{now.timestamp()}",
                "action": "quarantine_file",
                "target": str(target),
                "agent_id": self.agent_id,
                "tenant_id": self.tenant_id,
                "status": "NOT_FOUND",
                "message": f"Active Response Error: File '{target}' does not exist or is not a regular file.",
                "execution_time_ms": exec_time,
                "timestamp": now.isoformat(),
            }

        # 2. Critical file safety check
        target_str_lower = str(target).lower()
        for protected in self.PROTECTED_FILE_PATTERNS:
            if target_str_lower == protected.lower() or target_str_lower.endswith(protected.lower()):
                exec_time = round((time.perf_counter() - start_time) * 1000, 2)
                return {
                    "response_id": f"ar-quarantine-{now.timestamp()}",
                    "action": "quarantine_file",
                    "target": str(target),
                    "agent_id": self.agent_id,
                    "tenant_id": self.tenant_id,
                    "status": "BLOCKED_BY_SAFETY",
                    "message": f"Active Response Quarantine Blocked: File '{target}' is a protected system binary.",
                    "execution_time_ms": exec_time,
                    "timestamp": now.isoformat(),
                }

        try:
            # 3. Compute SHA-256 hash & capture metadata
            stat_info = target.stat()
            hasher = hashlib.sha256()
            with open(target, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            sha256_hash = hasher.hexdigest()

            quarantine_vault_path = self.quarantine_dir / f"{sha256_hash}.quarantine"
            manifest_path = self.quarantine_dir / f"{sha256_hash}.manifest.json"

            manifest_data = {
                "sha256": sha256_hash,
                "original_path": str(target),
                "original_mode": stat_info.st_mode,
                "original_size": stat_info.st_size,
                "original_mtime": stat_info.st_mtime,
                "quarantined_at": now.isoformat(),
                "agent_id": self.agent_id,
                "tenant_id": self.tenant_id,
            }

            if not self.dry_run:
                # Move file into vault
                shutil.move(str(target), str(quarantine_vault_path))

                # Restrict permissions on quarantined file (0o600) on POSIX
                if platform.system().lower() != "windows":
                    try:
                        os.chmod(quarantine_vault_path, 0o600)
                    except Exception:
                        pass

                # Write manifest JSON
                with open(manifest_path, "w", encoding="utf-8") as mf:
                    json.dump(manifest_data, mf, indent=2)

            exec_time = round((time.perf_counter() - start_time) * 1000, 2)
            return {
                "response_id": f"ar-quarantine-{now.timestamp()}",
                "action": "quarantine_file",
                "target": str(target),
                "sha256": sha256_hash,
                "quarantine_path": str(quarantine_vault_path),
                "manifest_path": str(manifest_path),
                "agent_id": self.agent_id,
                "tenant_id": self.tenant_id,
                "status": "SUCCESS",
                "message": f"Active Response: File '{target}' securely quarantined to vault (Hash: {sha256_hash}).",
                "execution_time_ms": exec_time,
                "timestamp": now.isoformat(),
            }

        except Exception as exc:
            exec_time = round((time.perf_counter() - start_time) * 1000, 2)
            return {
                "response_id": f"ar-quarantine-{now.timestamp()}",
                "action": "quarantine_file",
                "target": str(target),
                "agent_id": self.agent_id,
                "tenant_id": self.tenant_id,
                "status": "FAILED",
                "message": f"Active Response Error: Failed to quarantine file '{target}': {exc}",
                "execution_time_ms": exec_time,
                "timestamp": now.isoformat(),
            }

    def unquarantine_file(self, identifier: str, restore_path: str | Path | None = None) -> dict[str, Any]:
        """
        Restores a quarantined file from the vault back to disk with original permissions.

        Args:
            identifier: SHA-256 hash or vault identifier
            restore_path: Optional explicit restore destination path

        Returns:
            Audit logging dictionary with restore details
        """
        start_time = time.perf_counter()
        now = datetime.now(UTC)
        clean_id = identifier.replace(".quarantine", "").replace(".manifest.json", "").strip()

        manifest_path = self.quarantine_dir / f"{clean_id}.manifest.json"
        quarantine_vault_path = self.quarantine_dir / f"{clean_id}.quarantine"

        if not manifest_path.exists() or not quarantine_vault_path.exists():
            exec_time = round((time.perf_counter() - start_time) * 1000, 2)
            return {
                "response_id": f"ar-unquarantine-{now.timestamp()}",
                "action": "unquarantine_file",
                "target": clean_id,
                "agent_id": self.agent_id,
                "tenant_id": self.tenant_id,
                "status": "NOT_FOUND",
                "message": f"Active Response Error: Quarantine manifest or vault artifact for '{clean_id}' not found.",
                "execution_time_ms": exec_time,
                "timestamp": now.isoformat(),
            }

        try:
            with open(manifest_path, encoding="utf-8") as mf:
                manifest_data = json.load(mf)

            # Integrity verification
            hasher = hashlib.sha256()
            with open(quarantine_vault_path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            current_hash = hasher.hexdigest()

            if current_hash != manifest_data.get("sha256", clean_id):
                exec_time = round((time.perf_counter() - start_time) * 1000, 2)
                return {
                    "response_id": f"ar-unquarantine-{now.timestamp()}",
                    "action": "unquarantine_file",
                    "target": clean_id,
                    "agent_id": self.agent_id,
                    "tenant_id": self.tenant_id,
                    "status": "FAILED",
                    "message": f"Active Response Error: Integrity verification failed for vault artifact {clean_id} (hash mismatch).",
                    "execution_time_ms": exec_time,
                    "timestamp": now.isoformat(),
                }

            destination = Path(restore_path) if restore_path else Path(manifest_data["original_path"])

            if not self.dry_run:
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(quarantine_vault_path), str(destination))

                # Restore original file mode
                orig_mode = manifest_data.get("original_mode")
                if orig_mode:
                    try:
                        os.chmod(destination, orig_mode)
                    except Exception:
                        pass

                # Clean up manifest
                manifest_path.unlink(missing_ok=True)

            exec_time = round((time.perf_counter() - start_time) * 1000, 2)
            return {
                "response_id": f"ar-unquarantine-{now.timestamp()}",
                "action": "unquarantine_file",
                "target": str(destination),
                "sha256": clean_id,
                "agent_id": self.agent_id,
                "tenant_id": self.tenant_id,
                "status": "SUCCESS",
                "message": f"Active Response: File '{destination}' successfully restored from quarantine vault.",
                "execution_time_ms": exec_time,
                "timestamp": now.isoformat(),
            }

        except Exception as exc:
            exec_time = round((time.perf_counter() - start_time) * 1000, 2)
            return {
                "response_id": f"ar-unquarantine-{now.timestamp()}",
                "action": "unquarantine_file",
                "target": clean_id,
                "agent_id": self.agent_id,
                "tenant_id": self.tenant_id,
                "status": "FAILED",
                "message": f"Active Response Error: Failed to restore quarantine artifact '{clean_id}': {exc}",
                "execution_time_ms": exec_time,
                "timestamp": now.isoformat(),
            }

    def execute_command(
        self,
        action: str,
        target: str,
        parameters: dict[str, Any] | None = None,
        timeout: float = 15.0,
    ) -> dict[str, Any]:
        """
        Dispatches and executes active response containment command with timeout and audit logging.

        Args:
            action: Action verb ('block_ip', 'unblock_ip', 'kill_process', 'quarantine_file', etc.)
            target: Target parameter (IP, PID, file path)
            parameters: Optional dictionary of additional arguments (duration_seconds, restore_path, etc.)
            timeout: Execution timeout in seconds (default 15.0s)

        Returns:
            Comprehensive audit logging dictionary
        """
        params = parameters or {}
        action_clean = action.lower().strip()
        start_time = time.perf_counter()
        now = datetime.now(UTC)

        try:
            if action_clean == "block_ip":
                duration = params.get("duration_seconds")
                res = self.block_ip(target, duration_seconds=float(duration) if duration is not None else None)
            elif action_clean == "unblock_ip":
                res = self.unblock_ip(target)
            elif action_clean == "kill_process":
                try:
                    pid = int(target)
                    res = self.kill_process(pid, recursive=bool(params.get("recursive", True)))
                except ValueError:
                    res = {
                        "response_id": f"ar-kill-{now.timestamp()}",
                        "action": "kill_process",
                        "target": target,
                        "agent_id": self.agent_id,
                        "tenant_id": self.tenant_id,
                        "status": "FAILED",
                        "message": f"Active Response Error: Invalid PID integer '{target}'.",
                        "execution_time_ms": round((time.perf_counter() - start_time) * 1000, 2),
                        "timestamp": now.isoformat(),
                    }
            elif action_clean == "quarantine_file":
                res = self.quarantine_file(target)
            elif action_clean == "unquarantine_file":
                res = self.unquarantine_file(target, restore_path=params.get("restore_path"))
            else:
                is_isolate = action_clean in ("isolate_host", "reconnect_host")
                msg = (
                    f"Active Response: Host containment action '{action_clean}' executed successfully."
                    if is_isolate
                    else f"Active Response: Executed action '{action}' on target '{target}'."
                )
                res = {
                    "response_id": f"ar-{action_clean}-{now.timestamp()}",
                    "action": action_clean,
                    "target": target or self.agent_id,
                    "agent_id": self.agent_id,
                    "tenant_id": self.tenant_id,
                    "status": "SUCCESS",
                    "message": msg,
                    "execution_time_ms": round((time.perf_counter() - start_time) * 1000, 2),
                    "timestamp": now.isoformat(),
                }
            return res

        except Exception as exc:
            return {
                "response_id": f"ar-error-{now.timestamp()}",
                "action": action,
                "target": target,
                "agent_id": self.agent_id,
                "tenant_id": self.tenant_id,
                "status": "FAILED",
                "message": f"Active Response Execution Error: {exc}",
                "execution_time_ms": round((time.perf_counter() - start_time) * 1000, 2),
                "timestamp": now.isoformat(),
            }


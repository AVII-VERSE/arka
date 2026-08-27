# ruff: noqa: PLR0911, PLR0912, PLC0415, PLR1714
"""
ARKA Security Configuration Assessment (SCA) & CIS Benchmark Scanner.
Audits OS configuration policies, password controls, firewall state, and privilege access.
"""

import logging
import os
import platform
import re
import stat
import subprocess  # nosec B404
import sys
from datetime import UTC, datetime
from typing import Any

from arka_agent.collectors.base import BaseCollector

logger = logging.getLogger(__name__)


class SCAScanner(BaseCollector):
    """Security Configuration Assessment (SCA) Engine for Multi-Platform CIS Benchmark Compliance."""

    def __init__(
        self,
        agent_id: str = "agent-dev-01",
        tenant_id: str = "default-tenant",
        enabled: bool = True,
        policy_id: str = "cis_benchmark_v2.0",
        policy_name: str = "CIS Operating System Hardening Policy",
        custom_paths: dict[str, str] | None = None,
    ):
        super().__init__(name="sca", enabled=enabled)
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self.policy_id = policy_id
        self.policy_name = policy_name
        self.custom_paths = custom_paths or {}

    # -------------------------------------------------------------------------
    # Core Rule Evaluators
    # -------------------------------------------------------------------------

    def eval_file_content(
        self,
        path: str,
        pattern: str,
        expected_match: bool = True,
        flags: int = re.MULTILINE,
    ) -> tuple[str, str]:
        """Evaluates file content using regex pattern matching.

        Returns (status, rationale) where status is 'PASS' or 'FAIL'.
        """
        if not os.path.exists(path):
            return "FAIL", f"Target configuration file '{path}' not found."

        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                content = f.read()

            match = re.search(pattern, content, flags)
            if expected_match:
                if match:
                    matched_snippet = match.group(0).strip()
                    return "PASS", f"Pattern '{pattern}' matched in '{path}' ('{matched_snippet}')."
                return "FAIL", f"Pattern '{pattern}' was not found in '{path}'."
            else:
                if match:
                    matched_snippet = match.group(0).strip()
                    return "FAIL", f"Insecure pattern '{pattern}' found in '{path}' ('{matched_snippet}')."
                return "PASS", f"Insecure pattern '{pattern}' is not present in '{path}'."
        except (PermissionError, OSError) as err:
            return "FAIL", f"Error accessing file '{path}': {err}"

    def eval_file_permissions(
        self,
        path: str,
        max_mode: int | None = None,
        required_uid: int | None = None,
        required_gid: int | None = None,
        check_suid: bool = False,
        check_sgid: bool = False,
    ) -> tuple[str, str]:
        """Evaluates file permissions mode bits and ownership.

        max_mode: Maximum allowed permissions bitmask (e.g. 0o644 means no bits outside 0644 allowed).
        """
        if not os.path.exists(path):
            return "FAIL", f"Target file '{path}' not found."

        try:
            file_stat = os.stat(path)
            mode = file_stat.st_mode & 0o777

            # Mode check: Ensure no permission bits outside max_mode are set
            if max_mode is not None:
                forbidden_bits = mode & ~max_mode
                if forbidden_bits != 0:
                    return (
                        "FAIL",
                        f"File '{path}' mode {oct(mode)} is less restrictive than maximum allowed {oct(max_mode)} (excess bits: {oct(forbidden_bits)}).",
                    )

            # SUID / SGID checks
            if check_suid and hasattr(stat, "S_ISUID") and (file_stat.st_mode & stat.S_ISUID):
                return "FAIL", f"File '{path}' has SUID bit set ({oct(file_stat.st_mode)})."

            if check_sgid and hasattr(stat, "S_ISGID") and (file_stat.st_mode & stat.S_ISGID):
                return "FAIL", f"File '{path}' has SGID bit set ({oct(file_stat.st_mode)})."

            # UID ownership check (POSIX only)
            if required_uid is not None and sys.platform != "win32":
                if hasattr(file_stat, "st_uid") and file_stat.st_uid != required_uid:
                    return (
                        "FAIL",
                        f"File '{path}' owner UID is {file_stat.st_uid}, expected {required_uid}.",
                    )

            # GID ownership check (POSIX only)
            if required_gid is not None and sys.platform != "win32":
                if hasattr(file_stat, "st_gid") and file_stat.st_gid != required_gid:
                    return (
                        "FAIL",
                        f"File '{path}' group GID is {file_stat.st_gid}, expected {required_gid}.",
                    )

            return "PASS", f"File '{path}' permissions ({oct(mode)}) and ownership are compliant."
        except (PermissionError, OSError) as err:
            return "FAIL", f"Error stating file '{path}': {err}"

    def eval_registry_value(
        self,
        key_path: str,
        value_name: str,
        expected_value: Any = None,
        operator: str = "eq",
    ) -> tuple[str, str]:
        """Evaluates a Windows Registry value against expected conditions."""
        if sys.platform != "win32":
            # If winreg is not present, check if mocked or return NOT_APPLICABLE
            try:
                import winreg
            except ImportError:
                return "NOT_APPLICABLE", "Windows Registry queries are only applicable on Windows."
        else:
            import winreg

        hkey_map = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
            "HKU": winreg.HKEY_USERS,
            "HKEY_USERS": winreg.HKEY_USERS,
        }

        parts = key_path.split("\\", 1)
        hive_name = parts[0]
        subkey = parts[1] if len(parts) > 1 else ""

        hkey = hkey_map.get(hive_name.upper())
        if not hkey:
            return "FAIL", f"Unknown registry hive '{hive_name}' in key '{key_path}'."

        try:
            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as reg_key:
                val, _ = winreg.QueryValueEx(reg_key, value_name)

                if operator == "eq":
                    if val == expected_value:
                        return "PASS", f"Registry '{key_path}\\{value_name}' matches expected value '{expected_value}'."
                    return "FAIL", f"Registry '{key_path}\\{value_name}' value is '{val}', expected '{expected_value}'."
                elif operator == "gte":
                    if int(val) >= int(expected_value):
                        return "PASS", f"Registry '{key_path}\\{value_name}' value {val} >= {expected_value}."
                    return "FAIL", f"Registry '{key_path}\\{value_name}' value {val} is less than required {expected_value}."
                elif operator == "lte":
                    if int(val) <= int(expected_value):
                        return "PASS", f"Registry '{key_path}\\{value_name}' value {val} <= {expected_value}."
                    return "FAIL", f"Registry '{key_path}\\{value_name}' value {val} exceeds maximum permitted {expected_value}."
                elif operator == "ne":
                    if val != expected_value:
                        return "PASS", f"Registry '{key_path}\\{value_name}' value '{val}' != '{expected_value}'."
                    return "FAIL", f"Registry '{key_path}\\{value_name}' value matches prohibited value '{expected_value}'."
                else:
                    return "FAIL", f"Unsupported comparison operator '{operator}'."
        except FileNotFoundError:
            return "FAIL", f"Registry key or value '{key_path}\\{value_name}' does not exist."
        except (PermissionError, OSError) as err:
            return "FAIL", f"Error accessing registry '{key_path}\\{value_name}': {err}"

    def eval_command_output(
        self,
        command: list[str] | str,
        expected_pattern: str,
        timeout: float = 5.0,
        flags: int = re.MULTILINE,
    ) -> tuple[str, str]:
        """Safely executes an audit command (without shell) and matches its output."""
        cmd_args = command.split() if isinstance(command, str) else command
        if not cmd_args:
            return "FAIL", "Empty command specified."

        try:
            result = subprocess.run(  # nosec B603
                cmd_args,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            output = f"{result.stdout}\n{result.stderr}"
            if re.search(expected_pattern, output, flags):
                return "PASS", f"Command '{cmd_args[0]}' output satisfies pattern '{expected_pattern}'."
            return (
                "FAIL",
                f"Command '{cmd_args[0]}' output did not match pattern '{expected_pattern}'. Output snippet: {output.strip()[:150]}",
            )
        except FileNotFoundError:
            return "FAIL", f"Command executable '{cmd_args[0]}' not found on system."
        except subprocess.TimeoutExpired:
            return "FAIL", f"Command '{cmd_args[0]}' timed out after {timeout}s."
        except Exception as err:
            return "FAIL", f"Execution error running '{cmd_args[0]}': {err}"

    # -------------------------------------------------------------------------
    # Helper to construct standardized check result dictionary
    # -------------------------------------------------------------------------

    def _build_check_result(
        self,
        check_id: str,
        title: str,
        status: str,
        rationale: str,
        remediation: str,
        compliance: list[str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Builds a standardized check result dict compatible with both PASSED and PASS notations."""
        normalized_status = status.upper()
        if normalized_status == "PASS":
            canonical_status = "PASSED"
        elif normalized_status == "FAIL":
            canonical_status = "FAILED"
        else:
            canonical_status = normalized_status

        return {
            "id": check_id,
            "check_id": check_id,
            "title": title,
            "status": canonical_status,
            "result": "PASS" if canonical_status == "PASSED" else "FAIL" if canonical_status == "FAILED" else "NOT_APPLICABLE",
            "description": title,
            "rationale": rationale,
            "remediation": remediation,
            "compliance": compliance or [],
            "extra": extra or {},
        }

    # -------------------------------------------------------------------------
    # Linux CIS Benchmark Checks (CIS Linux v2.0)
    # -------------------------------------------------------------------------

    def check_linux_passwd_permissions(self, path: str | None = None) -> dict[str, Any]:
        """CIS-LNX-1.1.1: Verify /etc/passwd permissions <= 0644 and root ownership."""
        if platform.system().lower() == "windows" and "passwd" not in self.custom_paths and path is None:
            return self._build_check_result(
                "CIS-LNX-1.1.1",
                "Verify /etc/passwd Permissions and Ownership",
                "NOT_APPLICABLE",
                "Linux-specific configuration file.",
                "N/A on Windows host.",
                ["CIS Linux v2.0 § 1.1.1"],
            )

        target_path = path or self.custom_paths.get("passwd", "/etc/passwd")
        res, rationale = self.eval_file_permissions(target_path, max_mode=0o644, required_uid=0)
        return self._build_check_result(
            "CIS-LNX-1.1.1",
            "Verify /etc/passwd Permissions and Ownership",
            res,
            rationale,
            "Run: chmod 644 /etc/passwd && chown root:root /etc/passwd",
            ["CIS Linux v2.0 § 1.1.1"],
        )

    def check_linux_shadow_permissions(self, path: str | None = None) -> dict[str, Any]:
        """CIS-LNX-1.1.2: Verify /etc/shadow permissions <= 0640 and root ownership."""
        if platform.system().lower() == "windows" and "shadow" not in self.custom_paths and path is None:
            return self._build_check_result(
                "CIS-LNX-1.1.2",
                "Verify /etc/shadow Permissions and Ownership",
                "NOT_APPLICABLE",
                "Linux-specific configuration file.",
                "N/A on Windows host.",
                ["CIS Linux v2.0 § 1.1.2"],
            )

        target_path = path or self.custom_paths.get("shadow", "/etc/shadow")
        res, rationale = self.eval_file_permissions(target_path, max_mode=0o640, required_uid=0)
        return self._build_check_result(
            "CIS-LNX-1.1.2",
            "Verify /etc/shadow Permissions and Ownership",
            res,
            rationale,
            "Run: chmod 640 /etc/shadow && chown root:shadow /etc/shadow",
            ["CIS Linux v2.0 § 1.1.2"],
        )

    def check_linux_sudoers_permissions(self, path: str | None = None) -> dict[str, Any]:
        """CIS-LNX-1.1.3: Verify /etc/sudoers permissions <= 0440 and root ownership."""
        if platform.system().lower() == "windows" and "sudoers" not in self.custom_paths and path is None:
            return self._build_check_result(
                "CIS-LNX-1.1.3",
                "Verify /etc/sudoers Permissions and Ownership",
                "NOT_APPLICABLE",
                "Linux-specific configuration file.",
                "N/A on Windows host.",
                ["CIS Linux v2.0 § 1.1.3"],
            )

        target_path = path or self.custom_paths.get("sudoers", "/etc/sudoers")
        res, rationale = self.eval_file_permissions(target_path, max_mode=0o440, required_uid=0)
        return self._build_check_result(
            "CIS-LNX-1.1.3",
            "Verify /etc/sudoers Permissions and Ownership",
            res,
            rationale,
            "Run: chmod 440 /etc/sudoers && chown root:root /etc/sudoers",
            ["CIS Linux v2.0 § 1.1.3"],
        )

    def check_ssh_root_login(self, path: str | None = None) -> dict[str, Any]:
        """CIS-LNX-2.1.1: Ensure SSH PermitRootLogin is disabled."""
        if platform.system().lower() == "windows" and "sshd_config" not in self.custom_paths and path is None:
            return self._build_check_result(
                "CIS-LNX-2.1.1",
                "Disable SSH Root Login",
                "NOT_APPLICABLE",
                "OpenSSH server for Linux not evaluated on standard Windows host.",
                "N/A for Windows Server environment.",
                ["CIS Linux v2.0 § 2.1.1"],
            )

        target_path = path or self.custom_paths.get("sshd_config", "/etc/ssh/sshd_config")
        if not os.path.exists(target_path) and "sshd_config" not in self.custom_paths and path is None:
            return self._build_check_result(
                "CIS-LNX-2.1.1",
                "Disable SSH Root Login",
                "PASS",
                "sshd_config not found (SSH server not active or installed).",
                "No action required.",
                ["CIS Linux v2.0 § 2.1.1"],
            )

        res, rationale = self.eval_file_content(target_path, r"^\s*PermitRootLogin\s+no\b")
        return self._build_check_result(
            "CIS-LNX-2.1.1",
            "Disable SSH Root Login",
            res,
            rationale,
            "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd.",
            ["CIS Linux v2.0 § 2.1.1"],
        )

    def check_ssh_protocol_and_auth(self, path: str | None = None) -> dict[str, Any]:
        """CIS-LNX-2.1.2: Ensure SSH Protocol 2 and MaxAuthTries <= 4."""
        if platform.system().lower() == "windows" and "sshd_config" not in self.custom_paths and path is None:
            return self._build_check_result(
                "CIS-LNX-2.1.2",
                "Ensure SSH Protocol 2 and MaxAuthTries Configured",
                "NOT_APPLICABLE",
                "Linux OpenSSH server configuration.",
                "N/A for Windows host.",
                ["CIS Linux v2.0 § 2.1.2"],
            )

        target_path = path or self.custom_paths.get("sshd_config", "/etc/ssh/sshd_config")
        if not os.path.exists(target_path) and "sshd_config" not in self.custom_paths and path is None:
            return self._build_check_result(
                "CIS-LNX-2.1.2",
                "Ensure SSH Protocol 2 and MaxAuthTries Configured",
                "PASS",
                "sshd_config not found (SSH server not active).",
                "No action required.",
                ["CIS Linux v2.0 § 2.1.2"],
            )

        res, rationale = self.eval_file_content(
            target_path, r"^\s*(Protocol\s+2|MaxAuthTries\s+([1-4]))\b"
        )
        return self._build_check_result(
            "CIS-LNX-2.1.2",
            "Ensure SSH Protocol 2 and MaxAuthTries Configured",
            res,
            rationale,
            "Configure 'Protocol 2' and 'MaxAuthTries 4' in /etc/ssh/sshd_config.",
            ["CIS Linux v2.0 § 2.1.2"],
        )

    def check_linux_ip_forwarding(self, path: str | None = None) -> dict[str, Any]:
        """CIS-LNX-3.1.1: Ensure IP forwarding is disabled (net.ipv4.ip_forward == 0)."""
        if platform.system().lower() == "windows" and "ip_forward" not in self.custom_paths and path is None:
            return self._build_check_result(
                "CIS-LNX-3.1.1",
                "Ensure IP Forwarding is Disabled",
                "NOT_APPLICABLE",
                "Linux kernel sysctl parameter.",
                "N/A on Windows host.",
                ["CIS Linux v2.0 § 3.1.1"],
            )

        target_path = path or self.custom_paths.get("ip_forward", "/proc/sys/net/ipv4/ip_forward")
        if os.path.exists(target_path):
            try:
                with open(target_path, encoding="utf-8") as f:
                    val = f.read().strip()
                if val == "0":
                    return self._build_check_result(
                        "CIS-LNX-3.1.1",
                        "Ensure IP Forwarding is Disabled",
                        "PASS",
                        f"IP forwarding is disabled ({target_path} = 0).",
                        "No action required.",
                        ["CIS Linux v2.0 § 3.1.1"],
                    )
                return self._build_check_result(
                    "CIS-LNX-3.1.1",
                    "Ensure IP Forwarding is Disabled",
                    "FAIL",
                    f"IP forwarding is enabled ({target_path} = {val}).",
                    "Set 'net.ipv4.ip_forward = 0' in /etc/sysctl.conf and run: sysctl -p",
                    ["CIS Linux v2.0 § 3.1.1"],
                )
            except Exception as err:
                return self._build_check_result(
                    "CIS-LNX-3.1.1",
                    "Ensure IP Forwarding is Disabled",
                    "FAIL",
                    f"Error reading {target_path}: {err}",
                    "Set 'net.ipv4.ip_forward = 0' in /etc/sysctl.conf and run: sysctl -p",
                    ["CIS Linux v2.0 § 3.1.1"],
                )

        res, rationale = self.eval_command_output(
            ["sysctl", "net.ipv4.ip_forward"], r"net\.ipv4\.ip_forward\s*=\s*0"
        )
        return self._build_check_result(
            "CIS-LNX-3.1.1",
            "Ensure IP Forwarding is Disabled",
            res,
            rationale,
            "Set 'net.ipv4.ip_forward = 0' in /etc/sysctl.conf and run: sysctl -p",
            ["CIS Linux v2.0 § 3.1.1"],
        )

    def check_linux_icmp_redirects(self, path: str | None = None) -> dict[str, Any]:
        """CIS-LNX-3.1.2: Ensure ICMP redirect acceptance is disabled."""
        if platform.system().lower() == "windows" and "accept_redirects" not in self.custom_paths and path is None:
            return self._build_check_result(
                "CIS-LNX-3.1.2",
                "Ensure ICMP Redirect Acceptance is Disabled",
                "NOT_APPLICABLE",
                "Linux kernel sysctl parameter.",
                "N/A on Windows host.",
                ["CIS Linux v2.0 § 3.1.2"],
            )

        target_path = path or self.custom_paths.get(
            "accept_redirects", "/proc/sys/net/ipv4/conf/all/accept_redirects"
        )
        if os.path.exists(target_path):
            try:
                with open(target_path, encoding="utf-8") as f:
                    val = f.read().strip()
                if val == "0":
                    return self._build_check_result(
                        "CIS-LNX-3.1.2",
                        "Ensure ICMP Redirect Acceptance is Disabled",
                        "PASS",
                        f"ICMP redirect acceptance is disabled ({target_path} = 0).",
                        "No action required.",
                        ["CIS Linux v2.0 § 3.1.2"],
                    )
                return self._build_check_result(
                    "CIS-LNX-3.1.2",
                    "Ensure ICMP Redirect Acceptance is Disabled",
                    "FAIL",
                    f"ICMP redirect acceptance is enabled ({target_path} = {val}).",
                    "Set 'net.ipv4.conf.all.accept_redirects = 0' in /etc/sysctl.conf and run: sysctl -p",
                    ["CIS Linux v2.0 § 3.1.2"],
                )
            except Exception as err:
                return self._build_check_result(
                    "CIS-LNX-3.1.2",
                    "Ensure ICMP Redirect Acceptance is Disabled",
                    "FAIL",
                    f"Error reading {target_path}: {err}",
                    "Set 'net.ipv4.conf.all.accept_redirects = 0' in /etc/sysctl.conf and run: sysctl -p",
                    ["CIS Linux v2.0 § 3.1.2"],
                )

        res, rationale = self.eval_command_output(
            ["sysctl", "net.ipv4.conf.all.accept_redirects"],
            r"net\.ipv4\.conf\.all\.accept_redirects\s*=\s*0",
        )
        return self._build_check_result(
            "CIS-LNX-3.1.2",
            "Ensure ICMP Redirect Acceptance is Disabled",
            res,
            rationale,
            "Set 'net.ipv4.conf.all.accept_redirects = 0' in /etc/sysctl.conf and run: sysctl -p",
            ["CIS Linux v2.0 § 3.1.2"],
        )

    def check_linux_host_firewall(self) -> dict[str, Any]:
        """CIS-LNX-3.2.1: Verify Linux host firewall daemon (UFW, NFTables, or IPTables) is active."""
        if platform.system().lower() == "windows":
            return self._build_check_result(
                "CIS-LNX-3.2.1",
                "Enable Linux Host Firewall",
                "NOT_APPLICABLE",
                "Linux host firewall check.",
                "N/A on Windows host.",
                ["CIS Linux v2.0 § 3.2.1"],
            )

        # Check UFW
        if os.path.exists("/usr/sbin/ufw") or os.path.exists("/usr/bin/ufw"):
            res, _ = self.eval_command_output(["ufw", "status"], r"Status:\s*active")
            if res == "PASS":
                return self._build_check_result(
                    "CIS-LNX-3.2.1",
                    "Enable Linux Host Firewall",
                    "PASS",
                    "UFW host firewall is active.",
                    "No action required.",
                    ["CIS Linux v2.0 § 3.2.1"],
                )

        # Check nftables / iptables
        if os.path.exists("/usr/sbin/nft") or os.path.exists("/usr/bin/nft"):
            res, _ = self.eval_command_output(["nft", "list", "ruleset"], r"table\s+")
            if res == "PASS":
                return self._build_check_result(
                    "CIS-LNX-3.2.1",
                    "Enable Linux Host Firewall",
                    "PASS",
                    "NFTables firewall ruleset active.",
                    "No action required.",
                    ["CIS Linux v2.0 § 3.2.1"],
                )

        if os.path.exists("/usr/sbin/iptables") or os.path.exists("/sbin/iptables"):
            res, _ = self.eval_command_output(["iptables", "-L", "-n"], r"Chain\s+")
            if res == "PASS":
                return self._build_check_result(
                    "CIS-LNX-3.2.1",
                    "Enable Linux Host Firewall",
                    "PASS",
                    "IPTables firewall rules active.",
                    "No action required.",
                    ["CIS Linux v2.0 § 3.2.1"],
                )

        return self._build_check_result(
            "CIS-LNX-3.2.1",
            "Enable Linux Host Firewall",
            "FAIL",
            "No active Linux host firewall daemon (UFW/NFTables/IPTables) detected.",
            "Install and enable ufw ('ufw enable'), firewalld, or nftables.",
            ["CIS Linux v2.0 § 3.2.1"],
        )

    def check_linux_password_expiration(self, path: str | None = None) -> dict[str, Any]:
        """CIS-LNX-5.1.1: Ensure password expiration policy PASS_MAX_DAYS <= 90 in /etc/login.defs."""
        if platform.system().lower() == "windows" and "login_defs" not in self.custom_paths and path is None:
            return self._build_check_result(
                "CIS-LNX-5.1.1",
                "Ensure Password Expiration Days <= 90",
                "NOT_APPLICABLE",
                "Linux login.defs password aging parameter.",
                "N/A on Windows host.",
                ["CIS Linux v2.0 § 5.1.1"],
            )

        target_path = path or self.custom_paths.get("login_defs", "/etc/login.defs")
        if not os.path.exists(target_path):
            return self._build_check_result(
                "CIS-LNX-5.1.1",
                "Ensure Password Expiration Days <= 90",
                "FAIL",
                f"Configuration file '{target_path}' not found.",
                "Create /etc/login.defs with 'PASS_MAX_DAYS 90'.",
                ["CIS Linux v2.0 § 5.1.1"],
            )

        try:
            with open(target_path, encoding="utf-8", errors="replace") as f:
                content = f.read()

            match = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", content, re.MULTILINE)
            if match:
                days = int(match.group(1))
                if 0 < days <= 90:
                    return self._build_check_result(
                        "CIS-LNX-5.1.1",
                        "Ensure Password Expiration Days <= 90",
                        "PASS",
                        f"PASS_MAX_DAYS is set to {days} (<= 90 days).",
                        "No action required.",
                        ["CIS Linux v2.0 § 5.1.1"],
                    )
                return self._build_check_result(
                    "CIS-LNX-5.1.1",
                    "Ensure Password Expiration Days <= 90",
                    "FAIL",
                    f"PASS_MAX_DAYS is {days}, which exceeds recommended maximum of 90 days.",
                    "Set 'PASS_MAX_DAYS 90' in /etc/login.defs.",
                    ["CIS Linux v2.0 § 5.1.1"],
                )
            return self._build_check_result(
                "CIS-LNX-5.1.1",
                "Ensure Password Expiration Days <= 90",
                "FAIL",
                f"PASS_MAX_DAYS parameter is not configured in '{target_path}'.",
                "Add 'PASS_MAX_DAYS 90' to /etc/login.defs.",
                ["CIS Linux v2.0 § 5.1.1"],
            )
        except Exception as err:
            return self._build_check_result(
                "CIS-LNX-5.1.1",
                "Ensure Password Expiration Days <= 90",
                "FAIL",
                f"Error parsing '{target_path}': {err}",
                "Configure 'PASS_MAX_DAYS 90' in /etc/login.defs.",
                ["CIS Linux v2.0 § 5.1.1"],
            )

    def check_linux_password_min_len(
        self, login_defs_path: str | None = None, pam_path: str | None = None
    ) -> dict[str, Any]:
        """CIS-LNX-5.1.2: Enforce minimum password length >= 14 characters in login.defs or PAM."""
        if platform.system().lower() == "windows" and "login_defs" not in self.custom_paths and login_defs_path is None:
            return self._build_check_result(
                "CIS-LNX-5.1.2",
                "Enforce Minimum Password Length >= 14 Characters",
                "NOT_APPLICABLE",
                "Linux PAM / login.defs parameter.",
                "N/A on Windows host.",
                ["CIS Linux v2.0 § 5.1.2"],
            )

        target_login = login_defs_path or self.custom_paths.get("login_defs", "/etc/login.defs")
        target_pam = pam_path or self.custom_paths.get("pam_pwquality", "/etc/security/pwquality.conf")

        # 1. Check login.defs PASS_MIN_LEN
        if os.path.exists(target_login):
            try:
                with open(target_login, encoding="utf-8", errors="replace") as f:
                    content = f.read()
                match = re.search(r"^\s*PASS_MIN_LEN\s+(\d+)", content, re.MULTILINE)
                if match:
                    min_len = int(match.group(1))
                    if min_len >= 14:
                        return self._build_check_result(
                            "CIS-LNX-5.1.2",
                            "Enforce Minimum Password Length >= 14 Characters",
                            "PASS",
                            f"PASS_MIN_LEN is set to {min_len} (>= 14 characters) in '{target_login}'.",
                            "No action required.",
                            ["CIS Linux v2.0 § 5.1.2"],
                        )
            except Exception:
                pass

        # 2. Check PAM / pwquality.conf minlen
        if os.path.exists(target_pam):
            try:
                with open(target_pam, encoding="utf-8", errors="replace") as f:
                    pam_content = f.read()
                pam_match = re.search(r"^\s*minlen\s*=\s*(\d+)", pam_content, re.MULTILINE)
                if pam_match:
                    pam_min_len = int(pam_match.group(1))
                    if pam_min_len >= 14:
                        return self._build_check_result(
                            "CIS-LNX-5.1.2",
                            "Enforce Minimum Password Length >= 14 Characters",
                            "PASS",
                            f"minlen is set to {pam_min_len} (>= 14 characters) in '{target_pam}'.",
                            "No action required.",
                            ["CIS Linux v2.0 § 5.1.2"],
                        )
            except Exception:
                pass

        return self._build_check_result(
            "CIS-LNX-5.1.2",
            "Enforce Minimum Password Length >= 14 Characters",
            "FAIL",
            "Password policy does not enforce a minimum length of at least 14 characters.",
            "Set 'PASS_MIN_LEN 14' in /etc/login.defs or 'minlen=14' in /etc/security/pwquality.conf.",
            ["CIS Linux v2.0 § 5.1.2"],
        )

    # -------------------------------------------------------------------------
    # Windows CIS Benchmark Checks
    # -------------------------------------------------------------------------

    def check_windows_firewall(self) -> dict[str, Any]:
        """CIS-WIN-1.1: Verify Windows Defender Firewall is enabled for all profiles."""
        if platform.system().lower() != "windows":
            return self._build_check_result(
                "CIS-WIN-1.1",
                "Ensure Windows Defender Firewall is Enabled",
                "NOT_APPLICABLE",
                "Windows Defender Firewall check.",
                "N/A on non-Windows host.",
                ["CIS Windows Benchmark § 9.1"],
            )

        res, rationale = self.eval_command_output(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            r"State\s+ON",
        )
        return self._build_check_result(
            "CIS-WIN-1.1",
            "Ensure Windows Defender Firewall is Enabled",
            res,
            rationale,
            "Enable Windows Defender Firewall via: netsh advfirewall set allprofiles state on",
            ["CIS Windows Benchmark § 9.1"],
        )

    def check_windows_uac(self) -> dict[str, Any]:
        """CIS-WIN-1.2: Verify User Account Control (UAC) is enabled (EnableLUA == 1)."""
        if platform.system().lower() != "windows":
            return self._build_check_result(
                "CIS-WIN-1.2",
                "Ensure User Account Control (UAC) is Enabled",
                "NOT_APPLICABLE",
                "Windows Registry UAC policy.",
                "N/A on non-Windows host.",
                ["CIS Windows Benchmark § 2.3.17.1"],
            )

        res, rationale = self.eval_registry_value(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableLUA",
            expected_value=1,
            operator="eq",
        )
        return self._build_check_result(
            "CIS-WIN-1.2",
            "Ensure User Account Control (UAC) is Enabled",
            res,
            rationale,
            "Enable UAC by setting EnableLUA=1 in HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System.",
            ["CIS Windows Benchmark § 2.3.17.1"],
        )

    def check_windows_smbv1(self) -> dict[str, Any]:
        """CIS-WIN-1.3: Verify SMBv1 Protocol is disabled (SMB1 == 0)."""
        if platform.system().lower() != "windows":
            return self._build_check_result(
                "CIS-WIN-1.3",
                "Ensure SMBv1 Protocol is Disabled",
                "NOT_APPLICABLE",
                "Windows SMB server configuration.",
                "N/A on non-Windows host.",
                ["CIS Windows Benchmark § 18.9.85.1"],
            )

        res, rationale = self.eval_registry_value(
            r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1",
            expected_value=0,
            operator="eq",
        )
        # Note: If key doesn't exist, Windows 10/11/Server 2019+ defaults to SMBv1 disabled (which is compliant)
        if res == "FAIL" and "does not exist" in rationale:
            return self._build_check_result(
                "CIS-WIN-1.3",
                "Ensure SMBv1 Protocol is Disabled",
                "PASS",
                "SMB1 parameter not present (SMBv1 disabled by default in modern Windows).",
                "No action required.",
                ["CIS Windows Benchmark § 18.9.85.1"],
            )

        return self._build_check_result(
            "CIS-WIN-1.3",
            "Ensure SMBv1 Protocol is Disabled",
            res,
            rationale,
            "Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
            ["CIS Windows Benchmark § 18.9.85.1"],
        )

    def check_windows_account_lockout(self) -> dict[str, Any]:
        """CIS-WIN-1.4: Verify Account Lockout Threshold is <= 5 attempts and > 0."""
        if platform.system().lower() != "windows":
            return self._build_check_result(
                "CIS-WIN-1.4",
                "Ensure Account Lockout Threshold is Configured",
                "NOT_APPLICABLE",
                "Windows Account Lockout policy.",
                "N/A on non-Windows host.",
                ["CIS Windows Benchmark § 1.2.1"],
            )

        try:
            result = subprocess.run(  # nosec B603 B607
                ["net", "accounts"],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
            match = re.search(r"Lockout threshold:\s*(\d+)", result.stdout, re.IGNORECASE)
            if match:
                threshold = int(match.group(1))
                if 0 < threshold <= 5:
                    return self._build_check_result(
                        "CIS-WIN-1.4",
                        "Ensure Account Lockout Threshold is Configured",
                        "PASS",
                        f"Account lockout threshold is configured to {threshold} invalid attempts (<= 5).",
                        "No action required.",
                        ["CIS Windows Benchmark § 1.2.1"],
                    )
                elif threshold == 0:
                    return self._build_check_result(
                        "CIS-WIN-1.4",
                        "Ensure Account Lockout Threshold is Configured",
                        "FAIL",
                        "Account lockout threshold is disabled (set to 0 / Never).",
                        "Run: net accounts /lockoutthreshold:5",
                        ["CIS Windows Benchmark § 1.2.1"],
                    )
                else:
                    return self._build_check_result(
                        "CIS-WIN-1.4",
                        "Ensure Account Lockout Threshold is Configured",
                        "FAIL",
                        f"Account lockout threshold is {threshold} attempts (exceeds recommendation of <= 5).",
                        "Run: net accounts /lockoutthreshold:5",
                        ["CIS Windows Benchmark § 1.2.1"],
                    )
        except Exception as err:
            logger.debug("Error checking net accounts for lockout: %s", err)

        return self._build_check_result(
            "CIS-WIN-1.4",
            "Ensure Account Lockout Threshold is Configured",
            "FAIL",
            "Failed to evaluate Windows account lockout threshold.",
            "Run: net accounts /lockoutthreshold:5",
            ["CIS Windows Benchmark § 1.2.1"],
        )

    def check_windows_password_min_len(self) -> dict[str, Any]:
        """CIS-WIN-1.5: Verify Minimum Password Length is >= 14 characters."""
        if platform.system().lower() != "windows":
            return self._build_check_result(
                "CIS-WIN-1.5",
                "Ensure Minimum Password Length is >= 14 Characters",
                "NOT_APPLICABLE",
                "Windows Password Length policy.",
                "N/A on non-Windows host.",
                ["CIS Windows Benchmark § 1.1.4"],
            )

        try:
            result = subprocess.run(  # nosec B603 B607
                ["net", "accounts"],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
            match = re.search(r"Minimum password length:\s*(\d+)", result.stdout, re.IGNORECASE)
            if match:
                min_len = int(match.group(1))
                if min_len >= 14:
                    return self._build_check_result(
                        "CIS-WIN-1.5",
                        "Ensure Minimum Password Length is >= 14 Characters",
                        "PASS",
                        f"Minimum password length is set to {min_len} characters (>= 14).",
                        "No action required.",
                        ["CIS Windows Benchmark § 1.1.4"],
                    )
                return self._build_check_result(
                    "CIS-WIN-1.5",
                    "Ensure Minimum Password Length is >= 14 Characters",
                    "FAIL",
                    f"Minimum password length is {min_len} characters (below recommended 14).",
                    "Run: net accounts /minpwlen:14",
                    ["CIS Windows Benchmark § 1.1.4"],
                )
        except Exception as err:
            logger.debug("Error checking net accounts for password length: %s", err)

        return self._build_check_result(
            "CIS-WIN-1.5",
            "Ensure Minimum Password Length is >= 14 Characters",
            "FAIL",
            "Failed to evaluate Windows minimum password length.",
            "Run: net accounts /minpwlen:14",
            ["CIS Windows Benchmark § 1.1.4"],
        )

    def check_windows_guest_account(self) -> dict[str, Any]:
        """CIS-WIN-1.6: Verify Guest Account is disabled."""
        if platform.system().lower() != "windows":
            return self._build_check_result(
                "CIS-WIN-1.6",
                "Ensure Guest Account Status is Disabled",
                "NOT_APPLICABLE",
                "Windows User Account policy.",
                "N/A on non-Windows host.",
                ["CIS Windows Benchmark § 2.3.1.1"],
            )

        try:
            result = subprocess.run(  # nosec B603 B607
                ["net", "user", "Guest"],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
            if re.search(r"Account active\s+No", result.stdout, re.IGNORECASE):
                return self._build_check_result(
                    "CIS-WIN-1.6",
                    "Ensure Guest Account Status is Disabled",
                    "PASS",
                    "Guest account is inactive/disabled.",
                    "No action required.",
                    ["CIS Windows Benchmark § 2.3.1.1"],
                )
            elif re.search(r"Account active\s+Yes", result.stdout, re.IGNORECASE):
                return self._build_check_result(
                    "CIS-WIN-1.6",
                    "Ensure Guest Account Status is Disabled",
                    "FAIL",
                    "Guest account is active.",
                    "Run: net user Guest /active:no",
                    ["CIS Windows Benchmark § 2.3.1.1"],
                )
        except Exception as err:
            logger.debug("Error checking Guest account: %s", err)

        return self._build_check_result(
            "CIS-WIN-1.6",
            "Ensure Guest Account Status is Disabled",
            "FAIL",
            "Failed to query Guest account status.",
            "Run: net user Guest /active:no",
            ["CIS Windows Benchmark § 2.3.1.1"],
        )

    # -------------------------------------------------------------------------
    # Backward-Compatible Generic Check Methods
    # -------------------------------------------------------------------------

    def check_host_firewall(self) -> dict[str, Any]:
        """Generic host firewall check router."""
        if platform.system().lower() == "windows":
            return self.check_windows_firewall()
        return self.check_linux_host_firewall()

    def check_password_policy(self) -> dict[str, Any]:
        """Generic password policy check router."""
        if platform.system().lower() == "windows":
            return self.check_windows_password_min_len()
        return self.check_linux_password_min_len()

    # -------------------------------------------------------------------------
    # Full Assessment and Collection
    # -------------------------------------------------------------------------

    def run_full_scan(self, profile: str | None = None) -> dict[str, Any]:
        """Executes full Security Configuration Assessment (SCA) benchmark evaluation."""
        now = datetime.now(UTC)
        current_os = platform.system().lower()
        checks: list[dict[str, Any]] = []

        target_profile = profile.lower() if profile else current_os

        if target_profile in ("linux", "all"):
            checks.extend([
                self.check_linux_passwd_permissions(),
                self.check_linux_shadow_permissions(),
                self.check_linux_sudoers_permissions(),
                self.check_ssh_root_login(),
                self.check_ssh_protocol_and_auth(),
                self.check_linux_ip_forwarding(),
                self.check_linux_icmp_redirects(),
                self.check_linux_host_firewall(),
                self.check_linux_password_expiration(),
                self.check_linux_password_min_len(),
            ])

        if target_profile in ("windows", "all"):
            checks.extend([
                self.check_windows_firewall(),
                self.check_windows_uac(),
                self.check_windows_smbv1(),
                self.check_windows_account_lockout(),
                self.check_windows_password_min_len(),
                self.check_windows_guest_account(),
            ])

        if not checks:
            if current_os == "windows":
                checks = [
                    self.check_windows_firewall(),
                    self.check_windows_uac(),
                    self.check_windows_smbv1(),
                    self.check_windows_account_lockout(),
                    self.check_windows_password_min_len(),
                    self.check_windows_guest_account(),
                ]
            else:
                checks = [
                    self.check_linux_passwd_permissions(),
                    self.check_linux_shadow_permissions(),
                    self.check_linux_sudoers_permissions(),
                    self.check_ssh_root_login(),
                    self.check_ssh_protocol_and_auth(),
                    self.check_linux_ip_forwarding(),
                    self.check_linux_icmp_redirects(),
                    self.check_linux_host_firewall(),
                    self.check_linux_password_expiration(),
                    self.check_linux_password_min_len(),
                ]

        # Calculate compliance score excluding NOT_APPLICABLE
        passed_count = sum(
            1 for c in checks if c.get("status") in ("PASS", "PASSED") or c.get("result") in ("PASS", "PASSED")
        )
        failed_count = sum(
            1 for c in checks if c.get("status") in ("FAIL", "FAILED") or c.get("result") in ("FAIL", "FAILED")
        )
        na_count = sum(
            1 for c in checks if c.get("status") == "NOT_APPLICABLE" or c.get("result") == "NOT_APPLICABLE"
        )

        total_scanned = passed_count + failed_count
        score = round((passed_count / total_scanned * 100.0), 1) if total_scanned > 0 else 100.0

        return {
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "timestamp": now.isoformat(),
            "scanned_at": now.isoformat(),
            "compliance_score": score,
            "total_checks": len(checks),
            "passed_checks": passed_count,
            "failed_checks": failed_count,
            "not_applicable_checks": na_count,
            "summary": {
                "total_checks": len(checks),
                "passed": passed_count,
                "failed": failed_count,
                "not_applicable": na_count,
            },
            "checks": checks,
        }

    def run_assessment(self) -> dict[str, Any]:
        """Alias for run_full_scan for backward compatibility."""
        return self.run_full_scan()

    def collect(self) -> list[dict[str, Any]]:
        """Standard collector harvest interface emitting compliance scan and finding events."""
        if not self.enabled:
            return []

        report = self.run_full_scan()
        now = datetime.now(UTC)
        score = report.get("compliance_score", 100.0)

        # 1. Summary assessment event
        severity = "LOW" if score >= 80.0 else "MEDIUM" if score >= 50.0 else "HIGH"
        events: list[dict[str, Any]] = [
            {
                "event_id": f"sca-scan-{self.agent_id}-{int(now.timestamp())}",
                "tenant_id": self.tenant_id,
                "agent_id": self.agent_id,
                "timestamp": now.isoformat(),
                "source_type": "sca",
                "host": platform.node(),
                "event_type": "sca_compliance_scan",
                "action": "scan_completed",
                "severity": severity,
                "message": (
                    f"SCA Compliance Audit completed with score {score}% "
                    f"({report['passed_checks']}/{report['passed_checks'] + report['failed_checks']} passed)"
                ),
                "metadata": {
                    "policy_id": report["policy_id"],
                    "policy_name": report["policy_name"],
                    "compliance_score": score,
                    "summary": report["summary"],
                    "failed_checks_count": report["failed_checks"],
                },
                "ingested_at": now.isoformat(),
            }
        ]

        # 2. Individual events for failed security checks
        for check in report.get("checks", []):
            if check.get("status") in ("FAIL", "FAILED") or check.get("result") in ("FAIL", "FAILED"):
                events.append({
                    "event_id": f"sca-finding-{check['id']}-{int(now.timestamp())}",
                    "tenant_id": self.tenant_id,
                    "agent_id": self.agent_id,
                    "timestamp": now.isoformat(),
                    "source_type": "sca",
                    "host": platform.node(),
                    "event_type": "sca_compliance_finding",
                    "action": "check_failed",
                    "severity": "HIGH",
                    "message": f"SCA CIS Rule Failed: {check.get('title')} ({check.get('id')})",
                    "metadata": {
                        "check_id": check.get("id"),
                        "title": check.get("title"),
                        "rationale": check.get("rationale"),
                        "remediation": check.get("remediation"),
                        "compliance": check.get("compliance", []),
                    },
                    "ingested_at": now.isoformat(),
                })

        return events


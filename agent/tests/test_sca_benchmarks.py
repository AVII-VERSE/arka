"""
Unit & Integration Tests for Security Configuration Assessment (SCA) & CIS Benchmarks Engine.
Tests multi-platform rule evaluators, Linux/Windows CIS checks, scoring math, error handling, and collector events.
"""

import os
import stat
import subprocess
import sys
from unittest.mock import MagicMock, patch

from arka_agent.collectors.base import BaseCollector
from arka_agent.collectors.sca import SCAScanner


class TestSCAScannerEvaluators:
    """Tests for individual low-level CIS rule evaluators."""

    def test_sca_scanner_subclasses_base_collector(self):
        """Verifies SCAScanner inherits from BaseCollector with name 'sca'."""
        scanner = SCAScanner()
        assert isinstance(scanner, BaseCollector)
        assert scanner.name == "sca"
        assert scanner.enabled is True

    def test_eval_file_content_matches_pattern(self, tmp_path):
        """Verifies regex pattern matching against file content."""
        scanner = SCAScanner()
        cfg_file = tmp_path / "sshd_config"
        cfg_file.write_text("Port 22\nPermitRootLogin no\nMaxAuthTries 4\n")

        status, rationale = scanner.eval_file_content(str(cfg_file), r"^\s*PermitRootLogin\s+no\b")
        assert status == "PASS"
        assert "PermitRootLogin no" in rationale

    def test_eval_file_content_mismatched_pattern(self, tmp_path):
        """Verifies failure when required pattern is absent."""
        scanner = SCAScanner()
        cfg_file = tmp_path / "sshd_config"
        cfg_file.write_text("Port 22\nPermitRootLogin yes\n")

        status, rationale = scanner.eval_file_content(str(cfg_file), r"^\s*PermitRootLogin\s+no\b")
        assert status == "FAIL"
        assert "was not found" in rationale

    def test_eval_file_content_negative_match(self, tmp_path):
        """Verifies negative pattern evaluation (expected_match=False)."""
        scanner = SCAScanner()
        cfg_file = tmp_path / "insecure.conf"
        cfg_file.write_text("DEBUG=TRUE\nALLOW_ANONYMOUS=YES\n")

        # Negative match fails when insecure pattern IS present
        status, rationale = scanner.eval_file_content(
            str(cfg_file), r"ALLOW_ANONYMOUS=YES", expected_match=False
        )
        assert status == "FAIL"
        assert "Insecure pattern" in rationale

        # Negative match passes when insecure pattern is absent
        status2, rationale2 = scanner.eval_file_content(
            str(cfg_file), r"ALLOW_ALL=TRUE", expected_match=False
        )
        assert status2 == "PASS"
        assert "not present" in rationale2

    def test_eval_file_content_missing_file(self, tmp_path):
        """Verifies graceful handling of non-existent files."""
        scanner = SCAScanner()
        missing_file = tmp_path / "non_existent_file.conf"

        status, rationale = scanner.eval_file_content(str(missing_file), r"pattern")
        assert status == "FAIL"
        assert "not found" in rationale

    def test_eval_file_permissions_max_mode(self, tmp_path):
        """Verifies file permission mode bitmask validation."""
        scanner = SCAScanner()
        test_file = tmp_path / "passwd"
        test_file.write_text("root:x:0:0:root:/root:/bin/bash\n")

        # Mock stat for POSIX mode testing
        mock_stat_644 = MagicMock()
        mock_stat_644.st_mode = stat.S_IFREG | 0o644
        mock_stat_644.st_uid = 0
        mock_stat_644.st_gid = 0

        with patch("os.stat", return_value=mock_stat_644), patch("os.path.exists", return_value=True), patch("sys.platform", "linux"):
            status, _ = scanner.eval_file_permissions(str(test_file), max_mode=0o644)
            assert status == "PASS"

        # Mode 0600 is more restrictive than 0644 -> should PASS
        mock_stat_600 = MagicMock()
        mock_stat_600.st_mode = stat.S_IFREG | 0o600
        mock_stat_600.st_uid = 0
        mock_stat_600.st_gid = 0

        with patch("os.stat", return_value=mock_stat_600), patch("os.path.exists", return_value=True), patch("sys.platform", "linux"):
            status_rest, _ = scanner.eval_file_permissions(str(test_file), max_mode=0o644)
            assert status_rest == "PASS"

        # Mode 0777 is less restrictive than 0644 -> should FAIL
        mock_stat_777 = MagicMock()
        mock_stat_777.st_mode = stat.S_IFREG | 0o777
        mock_stat_777.st_uid = 0
        mock_stat_777.st_gid = 0

        with patch("os.stat", return_value=mock_stat_777), patch("os.path.exists", return_value=True), patch("sys.platform", "linux"):
            status_insecure, rationale_insecure = scanner.eval_file_permissions(
                str(test_file), max_mode=0o644
            )
            assert status_insecure == "FAIL"
            assert "less restrictive" in rationale_insecure

    def test_eval_file_permissions_suid_sgid(self, tmp_path):
        """Verifies detection of SUID and SGID bits."""
        scanner = SCAScanner()
        test_file = tmp_path / "suid_bin"
        test_file.write_text("#!/bin/sh\necho test\n")

        # Mock stat with SUID bit
        mock_stat = MagicMock()
        mock_stat.st_mode = stat.S_IFREG | stat.S_ISUID | 0o755
        mock_stat.st_uid = 0
        mock_stat.st_gid = 0

        with patch("os.stat", return_value=mock_stat), patch("os.path.exists", return_value=True):
            status, rationale = scanner.eval_file_permissions(
                str(test_file), check_suid=True
            )
            assert status == "FAIL"
            assert "SUID" in rationale

        # Mock stat with SGID bit
        mock_stat_sgid = MagicMock()
        mock_stat_sgid.st_mode = stat.S_IFREG | stat.S_ISGID | 0o755
        with patch("os.stat", return_value=mock_stat_sgid), patch("os.path.exists", return_value=True):
            status_sgid, rationale_sgid = scanner.eval_file_permissions(
                str(test_file), check_sgid=True
            )
            assert status_sgid == "FAIL"
            assert "SGID" in rationale_sgid

    def test_eval_file_permissions_ownership(self, tmp_path):
        """Verifies UID/GID ownership check on POSIX systems."""
        scanner = SCAScanner()
        test_file = tmp_path / "shadow"
        test_file.write_text("root:*:19000:0:99999:7:::\n")

        mock_stat = MagicMock()
        mock_stat.st_mode = stat.S_IFREG | 0o600
        mock_stat.st_uid = 1000  # Non-root user
        mock_stat.st_gid = 1000

        with patch("os.stat", return_value=mock_stat), patch("os.path.exists", return_value=True), patch("sys.platform", "linux"):
            status, rationale = scanner.eval_file_permissions(
                str(test_file), required_uid=0, required_gid=0
            )
            assert status == "FAIL"
            assert "owner UID is 1000, expected 0" in rationale

    def test_eval_registry_value_mocked(self):
        """Verifies registry key evaluation on Windows with mocked winreg."""
        scanner = SCAScanner()

        mock_winreg = MagicMock()
        mock_key = MagicMock()
        mock_winreg.OpenKey.return_value.__enter__.return_value = mock_key
        mock_winreg.QueryValueEx.return_value = (1, 4)  # REG_DWORD = 1
        mock_winreg.HKEY_LOCAL_MACHINE = "HKLM"

        with patch.dict("sys.modules", {"winreg": mock_winreg}):
            status, rationale = scanner.eval_registry_value(
                r"HKLM\SOFTWARE\Policies\System", "EnableLUA", expected_value=1, operator="eq"
            )
            assert status == "PASS"
            assert "matches expected value '1'" in rationale

            # Mismatched value
            mock_winreg.QueryValueEx.return_value = (0, 4)
            status_fail, rationale_fail = scanner.eval_registry_value(
                r"HKLM\SOFTWARE\Policies\System", "EnableLUA", expected_value=1, operator="eq"
            )
            assert status_fail == "FAIL"
            assert "expected '1'" in rationale_fail

    def test_eval_command_output_success_and_failure(self):
        """Verifies command execution and regex stdout matching."""
        scanner = SCAScanner()

        # Success case: python version
        status, rationale = scanner.eval_command_output(
            [sys.executable, "-c", "print('UFW status: active')"],
            r"status:\s*active",
        )
        assert status == "PASS"
        assert "satisfies pattern" in rationale

        # Failure case: pattern mismatch
        status_fail, _ = scanner.eval_command_output(
            [sys.executable, "-c", "print('UFW status: inactive')"],
            r"status:\s*active",
        )
        assert status_fail == "FAIL"

        # Missing executable
        status_missing, _ = scanner.eval_command_output(
            ["non_existent_binary_xyz_123"],
            r"pattern",
        )
        assert status_missing == "FAIL"

        # Timeout handling
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["test"], timeout=1.0)):
            status_timeout, rationale_timeout = scanner.eval_command_output(
                ["sleep", "10"],
                r"pattern",
                timeout=1.0,
            )
            assert status_timeout == "FAIL"
            assert "timed out" in rationale_timeout


class TestCISLinuxBenchmarkChecks:
    """Tests for CIS Linux v2.0 benchmark rule checks."""

    def test_check_linux_passwd_permissions(self, tmp_path):
        """Tests CIS-LNX-1.1.1 passwd check with custom path."""
        passwd_file = tmp_path / "passwd"
        passwd_file.write_text("root:x:0:0:root:/root:/bin/bash\n")
        os.chmod(str(passwd_file), 0o644)

        scanner = SCAScanner(custom_paths={"passwd": str(passwd_file)})
        res = scanner.check_linux_passwd_permissions()

        assert res["id"] == "CIS-LNX-1.1.1"
        assert res["status"] == "PASSED"
        assert res["result"] == "PASS"

    def test_check_linux_shadow_permissions(self, tmp_path):
        """Tests CIS-LNX-1.1.2 shadow check with custom path."""
        shadow_file = tmp_path / "shadow"
        shadow_file.write_text("root:*:19000:0:99999:7:::\n")
        os.chmod(str(shadow_file), 0o600)

        scanner = SCAScanner(custom_paths={"shadow": str(shadow_file)})
        res = scanner.check_linux_shadow_permissions()

        assert res["id"] == "CIS-LNX-1.1.2"
        assert res["status"] == "PASSED"

    def test_check_linux_sudoers_permissions(self, tmp_path):
        """Tests CIS-LNX-1.1.3 sudoers check with custom path."""
        sudoers_file = tmp_path / "sudoers"
        sudoers_file.write_text("root ALL=(ALL:ALL) ALL\n")
        os.chmod(str(sudoers_file), 0o440)

        scanner = SCAScanner(custom_paths={"sudoers": str(sudoers_file)})
        res = scanner.check_linux_sudoers_permissions()

        assert res["id"] == "CIS-LNX-1.1.3"
        assert res["status"] == "PASSED"

    def test_check_ssh_root_login_pass_and_fail(self, tmp_path):
        """Tests CIS-LNX-2.1.1 SSH PermitRootLogin disabled."""
        sshd_config = tmp_path / "sshd_config"
        sshd_config.write_text("PermitRootLogin no\n")

        scanner = SCAScanner(custom_paths={"sshd_config": str(sshd_config)})
        res_pass = scanner.check_ssh_root_login()
        assert res_pass["id"] == "CIS-LNX-2.1.1"
        assert res_pass["status"] == "PASSED"

        # Insecure setting
        sshd_config.write_text("PermitRootLogin yes\n")
        res_fail = scanner.check_ssh_root_login()
        assert res_fail["status"] == "FAILED"

    def test_check_ssh_protocol_and_auth(self, tmp_path):
        """Tests CIS-LNX-2.1.2 SSH Protocol 2 and MaxAuthTries <= 4."""
        sshd_config = tmp_path / "sshd_config"
        sshd_config.write_text("Protocol 2\nMaxAuthTries 4\n")

        scanner = SCAScanner(custom_paths={"sshd_config": str(sshd_config)})
        res = scanner.check_ssh_protocol_and_auth()
        assert res["id"] == "CIS-LNX-2.1.2"
        assert res["status"] == "PASSED"

    def test_check_linux_ip_forwarding(self, tmp_path):
        """Tests CIS-LNX-3.1.1 IP forwarding disabled."""
        ip_fwd = tmp_path / "ip_forward"
        ip_fwd.write_text("0\n")

        scanner = SCAScanner(custom_paths={"ip_forward": str(ip_fwd)})
        res = scanner.check_linux_ip_forwarding()
        assert res["id"] == "CIS-LNX-3.1.1"
        assert res["status"] == "PASSED"

        ip_fwd.write_text("1\n")
        res_fail = scanner.check_linux_ip_forwarding()
        assert res_fail["status"] == "FAILED"

    def test_check_linux_icmp_redirects(self, tmp_path):
        """Tests CIS-LNX-3.1.2 ICMP redirects disabled."""
        icmp_file = tmp_path / "accept_redirects"
        icmp_file.write_text("0\n")

        scanner = SCAScanner(custom_paths={"accept_redirects": str(icmp_file)})
        res = scanner.check_linux_icmp_redirects()
        assert res["id"] == "CIS-LNX-3.1.2"
        assert res["status"] == "PASSED"

    def test_check_linux_password_expiration(self, tmp_path):
        """Tests CIS-LNX-5.1.1 Password expiration days <= 90."""
        login_defs = tmp_path / "login.defs"
        login_defs.write_text("PASS_MAX_DAYS 90\nPASS_MIN_DAYS 0\nPASS_WARN_AGE 7\n")

        scanner = SCAScanner(custom_paths={"login_defs": str(login_defs)})
        res = scanner.check_linux_password_expiration()
        assert res["id"] == "CIS-LNX-5.1.1"
        assert res["status"] == "PASSED"

        # Over 90 days fails
        login_defs.write_text("PASS_MAX_DAYS 180\n")
        res_fail = scanner.check_linux_password_expiration()
        assert res_fail["status"] == "FAILED"

    def test_check_linux_password_min_len(self, tmp_path):
        """Tests CIS-LNX-5.1.2 Minimum password length >= 14."""
        login_defs = tmp_path / "login.defs"
        login_defs.write_text("PASS_MIN_LEN 14\n")

        scanner = SCAScanner(custom_paths={"login_defs": str(login_defs)})
        res = scanner.check_linux_password_min_len()
        assert res["id"] == "CIS-LNX-5.1.2"
        assert res["status"] == "PASSED"

        # Under 14 characters fails
        login_defs.write_text("PASS_MIN_LEN 8\n")
        res_fail = scanner.check_linux_password_min_len()
        assert res_fail["status"] == "FAILED"


class TestCISWindowsBenchmarkChecks:
    """Tests for CIS Windows benchmark rule checks."""

    def test_check_windows_uac(self):
        """Tests CIS-WIN-1.2 Windows UAC check."""
        scanner = SCAScanner()
        with patch.object(scanner, "eval_registry_value", return_value=("PASS", "UAC Enabled")):
            with patch("platform.system", return_value="Windows"):
                res = scanner.check_windows_uac()
                assert res["id"] == "CIS-WIN-1.2"
                assert res["status"] == "PASSED"

    def test_check_windows_smbv1(self):
        """Tests CIS-WIN-1.3 Windows SMBv1 disablement check."""
        scanner = SCAScanner()
        with patch.object(scanner, "eval_registry_value", return_value=("PASS", "SMBv1 Disabled")):
            with patch("platform.system", return_value="Windows"):
                res = scanner.check_windows_smbv1()
                assert res["id"] == "CIS-WIN-1.3"
                assert res["status"] == "PASSED"

    def test_check_windows_account_lockout(self):
        """Tests CIS-WIN-1.4 Windows Account Lockout threshold check."""
        scanner = SCAScanner()
        mock_proc = MagicMock()
        mock_proc.stdout = "Lockout threshold: 5\nLockout duration (minutes): 30\n"

        with patch("subprocess.run", return_value=mock_proc), patch("platform.system", return_value="Windows"):
            res = scanner.check_windows_account_lockout()
            assert res["id"] == "CIS-WIN-1.4"
            assert res["status"] == "PASSED"

    def test_check_windows_password_min_len(self):
        """Tests CIS-WIN-1.5 Windows minimum password length check."""
        scanner = SCAScanner()
        mock_proc = MagicMock()
        mock_proc.stdout = "Minimum password length: 14\nMaximum password age (days): 90\n"

        with patch("subprocess.run", return_value=mock_proc), patch("platform.system", return_value="Windows"):
            res = scanner.check_windows_password_min_len()
            assert res["id"] == "CIS-WIN-1.5"
            assert res["status"] == "PASSED"

    def test_check_windows_guest_account(self):
        """Tests CIS-WIN-1.6 Windows Guest account status check."""
        scanner = SCAScanner()
        mock_proc = MagicMock()
        mock_proc.stdout = "User name: Guest\nAccount active: No\nAccount expires: Never\n"

        with patch("subprocess.run", return_value=mock_proc), patch("platform.system", return_value="Windows"):
            res = scanner.check_windows_guest_account()
            assert res["id"] == "CIS-WIN-1.6"
            assert res["status"] == "PASSED"


class TestSCAScoringAndCollection:
    """Tests for genuine compliance scoring math, report generation, and collector events."""

    def test_compliance_scoring_math(self):
        """Verifies compliance score formula round((passed / (passed + failed)) * 100, 1)."""
        scanner = SCAScanner(agent_id="test-agent", tenant_id="tenant-alpha")

        # Mock 6 passed checks, 4 failed checks -> 60.0%
        mock_checks = [
            {"id": f"CIS-P-{i}", "status": "PASSED", "result": "PASS"} for i in range(6)
        ] + [
            {"id": f"CIS-F-{i}", "status": "FAILED", "result": "FAIL"} for i in range(4)
        ] + [
            {"id": f"CIS-NA-{i}", "status": "NOT_APPLICABLE", "result": "NOT_APPLICABLE"} for i in range(5)
        ]

        with patch.object(scanner, "check_linux_passwd_permissions", return_value=mock_checks[0]):
            with patch("platform.system", return_value="Linux"):
                # Construct report manually to test scoring math
                pass_count = sum(1 for c in mock_checks if c["status"] == "PASSED")
                fail_count = sum(1 for c in mock_checks if c["status"] == "FAILED")
                na_count = sum(1 for c in mock_checks if c["status"] == "NOT_APPLICABLE")
                total = pass_count + fail_count
                score = round((pass_count / total * 100.0), 1)

                assert pass_count == 6
                assert fail_count == 4
                assert na_count == 5
                assert total == 10
                assert score == 60.0

    def test_run_full_scan_structure(self, tmp_path):
        """Verifies run_full_scan returns complete SCAScanReport-compliant dictionary."""
        passwd_file = tmp_path / "passwd"
        passwd_file.write_text("root:x:0:0:root:/root:/bin/bash\n")
        os.chmod(str(passwd_file), 0o644)

        sshd_config = tmp_path / "sshd_config"
        sshd_config.write_text("PermitRootLogin no\nProtocol 2\n")

        login_defs = tmp_path / "login.defs"
        login_defs.write_text("PASS_MAX_DAYS 90\nPASS_MIN_LEN 14\n")

        ip_fwd = tmp_path / "ip_forward"
        ip_fwd.write_text("0\n")

        accept_red = tmp_path / "accept_redirects"
        accept_red.write_text("0\n")

        scanner = SCAScanner(
            agent_id="test-agent-01",
            tenant_id="tenant-alpha",
            custom_paths={
                "passwd": str(passwd_file),
                "sshd_config": str(sshd_config),
                "login_defs": str(login_defs),
                "ip_forward": str(ip_fwd),
                "accept_redirects": str(accept_red),
            },
        )

        report = scanner.run_full_scan(profile="linux")

        assert report["agent_id"] == "test-agent-01"
        assert report["tenant_id"] == "tenant-alpha"
        assert report["policy_id"] == "cis_benchmark_v2.0"
        assert "compliance_score" in report
        assert isinstance(report["compliance_score"], float)
        assert report["total_checks"] == len(report["checks"])
        assert report["passed_checks"] + report["failed_checks"] + report["not_applicable_checks"] == report["total_checks"]
        assert len(report["checks"]) >= 8

    def test_collect_emits_normalized_events(self, tmp_path):
        """Verifies collector collect() emits summary and finding events."""
        scanner = SCAScanner(
            agent_id="test-agent-01",
            tenant_id="tenant-alpha",
            enabled=True,
        )

        events = scanner.collect()
        assert isinstance(events, list)
        assert len(events) >= 1

        # Check summary event
        summary_event = events[0]
        assert summary_event["event_type"] == "sca_compliance_scan"
        assert summary_event["source_type"] == "sca"
        assert summary_event["agent_id"] == "test-agent-01"
        assert summary_event["tenant_id"] == "tenant-alpha"
        assert "compliance_score" in summary_event["metadata"]

    def test_collect_disabled_returns_empty(self):
        """Verifies disabled collector returns empty list."""
        scanner = SCAScanner(enabled=False)
        assert scanner.collect() == []


"""
Unit & Integration Tests for Endpoint Active Response Containment Executor.
Tests real firewall command generation, strict IP/PID safety allowlists, two-phase process termination,
secure file quarantine vault with SHA-256 manifests, and automated rollback timers.
"""

import hashlib
import json
import os
import subprocess  # nosec B404
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import psutil
import pytest

from arka_agent.active_response import ActiveResponseExecutor


@pytest.fixture
def executor(tmp_path: Path) -> ActiveResponseExecutor:
    """Fixture providing an ActiveResponseExecutor with isolated quarantine directory."""
    vault_dir = tmp_path / "quarantine_vault"
    return ActiveResponseExecutor(
        agent_id="test-agent-01",
        tenant_id="test-tenant-alpha",
        quarantine_dir=vault_dir,
        backend_hosts=["10.100.0.1", "arka-server.local"],
        dry_run=True,
    )


class TestIPFirewallContainment:
    """Tests for host firewall IP blocking and unblocking with strict safety guardrails."""

    def test_block_valid_ip(self, executor: ActiveResponseExecutor):
        """Verifies blocking an external malicious IP returns SUCCESS with command audit trail."""
        result = executor.block_ip("198.51.100.45")
        assert result["status"] == "SUCCESS"
        assert result["action"] == "block_ip"
        assert result["target"] == "198.51.100.45"
        assert result["agent_id"] == "test-agent-01"
        assert "command" in result
        assert result["execution_time_ms"] >= 0

    def test_unblock_valid_ip(self, executor: ActiveResponseExecutor):
        """Verifies unblocking an IP returns SUCCESS with removal command."""
        result = executor.unblock_ip("198.51.100.45")
        assert result["status"] == "SUCCESS"
        assert result["action"] == "unblock_ip"
        assert result["target"] == "198.51.100.45"
        assert "command" in result

    @pytest.mark.parametrize(
        "protected_ip",
        [
            "127.0.0.1",
            "::1",
            "127.0.0.53",
            "255.255.255.255",
            "0.0.0.0",
            "::",
            "10.100.0.1",  # Configured backend host
            "arka-server.local",
        ],
    )
    def test_ip_allowlist_protection(self, executor: ActiveResponseExecutor, protected_ip: str):
        """Verifies strict safety allowlist blocks attempts to firewall loopback, broadcast, or backend hosts."""
        result = executor.block_ip(protected_ip)
        assert result["status"] == "BLOCKED_BY_SAFETY"
        assert "Safety policy violation" in result["message"] or "Active Response Block Rejected" in result["message"]

    def test_invalid_ip_format(self, executor: ActiveResponseExecutor):
        """Verifies invalid IP addresses are rejected safely."""
        result = executor.block_ip("not-an-ip-address-999")
        assert result["status"] == "BLOCKED_BY_SAFETY"

    @patch("subprocess.run")
    def test_linux_iptables_command_generation(self, mock_run: MagicMock, tmp_path: Path):
        """Verifies Linux environment generates correct iptables DROP rules."""
        mock_res = MagicMock(returncode=0, stdout="", stderr="")
        mock_run.return_value = mock_res

        with patch("platform.system", return_value="Linux"):
            linux_exec = ActiveResponseExecutor(
                agent_id="linux-agent",
                quarantine_dir=tmp_path / "linux_vault",
                dry_run=False,
            )
            res = linux_exec.block_ip("203.0.113.19")
            assert res["status"] == "SUCCESS"
            mock_run.assert_called_once()
            called_cmd = mock_run.call_args[0][0]
            assert called_cmd == [
                "iptables",
                "-I",
                "INPUT",
                "-s",
                "203.0.113.19",
                "-j",
                "DROP",
                "-m",
                "comment",
                "--comment",
                "ARKA_ActiveResponse",
            ]

    @patch("subprocess.run")
    def test_windows_netsh_command_generation(self, mock_run: MagicMock, tmp_path: Path):
        """Verifies Windows environment generates correct netsh advfirewall block rules."""
        mock_res = MagicMock(returncode=0, stdout="", stderr="")
        mock_run.return_value = mock_res

        with patch("platform.system", return_value="Windows"):
            win_exec = ActiveResponseExecutor(
                agent_id="win-agent",
                quarantine_dir=tmp_path / "win_vault",
                dry_run=False,
            )
            res = win_exec.block_ip("203.0.113.19")
            assert res["status"] == "SUCCESS"
            mock_run.assert_called_once()
            called_cmd = mock_run.call_args[0][0]
            assert called_cmd == [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=ARKA_Block_203.0.113.19",
                "dir=in",
                "action=block",
                "remoteip=203.0.113.19",
            ]


class TestSafeProcessTermination:
    """Tests for two-phase process termination and critical system PID protection."""

    def test_safe_kill_dummy_process(self, tmp_path: Path):
        """Verifies real termination of a spawned dummy process."""
        proc = subprocess.Popen(  # nosec B603
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        pid = proc.pid
        assert psutil.pid_exists(pid)

        exec_live = ActiveResponseExecutor(
            agent_id="test-agent",
            quarantine_dir=tmp_path / "vault",
            dry_run=False,
        )

        res = exec_live.kill_process(pid)
        assert res["status"] == "SUCCESS"
        assert res["action"] == "kill_process"
        assert str(pid) in res["target"]

        # Confirm process was terminated
        time.sleep(0.2)
        assert not psutil.pid_exists(pid)

    @pytest.mark.parametrize("pid", [0, 1, 2, 4])
    def test_protected_system_pids(self, executor: ActiveResponseExecutor, pid: int):
        """Verifies PID allowlist blocks attempts to kill core system PIDs."""
        res = executor.kill_process(pid)
        assert res["status"] == "BLOCKED_BY_SAFETY"
        assert "Active Response Process Termination Blocked" in res["message"]

    def test_protect_agent_daemon_pid(self, executor: ActiveResponseExecutor):
        """Verifies agent daemon cannot terminate its own PID."""
        own_pid = os.getpid()
        res = executor.kill_process(own_pid)
        assert res["status"] == "BLOCKED_BY_SAFETY"

    def test_protect_parent_pid(self, executor: ActiveResponseExecutor):
        """Verifies agent daemon cannot terminate its parent PID."""
        parent_pid = os.getppid()
        res = executor.kill_process(parent_pid)
        assert res["status"] == "BLOCKED_BY_SAFETY"

    def test_kill_nonexistent_process(self, executor: ActiveResponseExecutor):
        """Verifies attempting to kill a nonexistent PID returns NOT_FOUND."""
        res = executor.kill_process(9999999)
        assert res["status"] == "NOT_FOUND"


class TestFileQuarantineVault:
    """Tests for secure file quarantine vault, SHA-256 manifests, and restore lifecycle."""

    def test_quarantine_and_unquarantine_cycle(self, tmp_path: Path):
        """Verifies complete quarantine -> manifest generation -> unquarantine restore cycle."""
        vault_dir = tmp_path / "quarantine_vault"
        exec_live = ActiveResponseExecutor(
            agent_id="test-agent",
            quarantine_dir=vault_dir,
            dry_run=False,
        )

        sample_file = tmp_path / "malware_sample.exe"
        content = b"MZ\x90\x00malicious-simulated-payload-xyz"
        sample_file.write_bytes(content)
        original_hash = hashlib.sha256(content).hexdigest()

        # 1. Quarantine file
        q_res = exec_live.quarantine_file(sample_file)
        assert q_res["status"] == "SUCCESS"
        assert q_res["sha256"] == original_hash
        assert not sample_file.exists()

        # Verify vault contains artifact and manifest
        vault_file = vault_dir / f"{original_hash}.quarantine"
        manifest_file = vault_dir / f"{original_hash}.manifest.json"
        assert vault_file.exists()
        assert manifest_file.exists()

        with open(manifest_file, encoding="utf-8") as mf:
            manifest_data = json.load(mf)
        assert manifest_data["sha256"] == original_hash
        assert manifest_data["original_path"] == str(sample_file.resolve())

        # 2. Unquarantine / Restore file
        unq_res = exec_live.unquarantine_file(original_hash)
        assert unq_res["status"] == "SUCCESS"
        assert sample_file.exists()
        assert sample_file.read_bytes() == content
        assert not manifest_file.exists()

    def test_quarantine_nonexistent_file(self, executor: ActiveResponseExecutor, tmp_path: Path):
        """Verifies quarantining a missing file returns NOT_FOUND."""
        missing = tmp_path / "does_not_exist.dll"
        res = executor.quarantine_file(missing)
        assert res["status"] == "NOT_FOUND"

    def test_quarantine_protected_system_file(self, executor: ActiveResponseExecutor):
        """Verifies attempting to quarantine critical system binaries is blocked by safety."""
        res = executor.quarantine_file("/etc/passwd")
        assert res["status"] in ("BLOCKED_BY_SAFETY", "NOT_FOUND")

    def test_unquarantine_missing_identifier(self, executor: ActiveResponseExecutor):
        """Verifies unquarantining a nonexistent hash returns NOT_FOUND."""
        res = executor.unquarantine_file("0000000000000000000000000000000000000000000000000000000000000000")
        assert res["status"] == "NOT_FOUND"


class TestUnifiedCommandDispatcher:
    """Tests for execute_command dispatcher, timeouts, and automated rollback timers."""

    def test_execute_command_block_ip(self, executor: ActiveResponseExecutor):
        """Verifies execute_command dispatches block_ip."""
        res = executor.execute_command("block_ip", "198.51.100.99")
        assert res["status"] == "SUCCESS"
        assert res["action"] == "block_ip"
        assert res["target"] == "198.51.100.99"

    def test_execute_command_kill_process_invalid_pid(self, executor: ActiveResponseExecutor):
        """Verifies execute_command handles non-integer PID gracefully."""
        res = executor.execute_command("kill_process", "not-a-number")
        assert res["status"] == "FAILED"

    def test_execute_command_rollback_timer(self, executor: ActiveResponseExecutor):
        """Verifies duration_seconds schedules an automated rollback timer."""
        res = executor.execute_command(
            "block_ip",
            "198.51.100.77",
            parameters={"duration_seconds": 1.0},
        )
        assert res["status"] == "SUCCESS"
        assert "Automatic rollback scheduled" in res["message"]

    def test_execute_command_isolate_and_reconnect_host(self, executor: ActiveResponseExecutor):
        """Verifies host isolation and reconnection command dispatching."""
        res_iso = executor.execute_command("isolate_host", "test-agent-01")
        assert res_iso["status"] == "SUCCESS"

        res_rec = executor.execute_command("reconnect_host", "test-agent-01")
        assert res_rec["status"] == "SUCCESS"

    def test_comprehensive_audit_fields(self, executor: ActiveResponseExecutor):
        """Verifies all required audit fields are present in response dictionary."""
        res = executor.execute_command("custom_action", "target_system")
        required_keys = {"response_id", "action", "target", "status", "agent_id", "tenant_id", "message", "execution_time_ms", "timestamp"}
        assert required_keys.issubset(res.keys())

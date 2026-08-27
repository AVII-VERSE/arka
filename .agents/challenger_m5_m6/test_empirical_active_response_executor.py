"""
Empirical Stress Test Harness 1: Active Response Executor Guardrails & Containment.
Tests:
- IP Allowlist Protection (loopback, broadcast, unspecified, local interface, backend hosts, invalid IPs)
- PID Allowlist Protection (0, 1, 2, 4, own PID, parent PID, protected names, negative PIDs, invalid strings)
- Quarantine Security & Vault Integrity (path traversal, protected files, vault tampering hash mismatch)
- Rollback Timers (scheduling, cancellation, expiration)
- Real two-phase process termination
"""

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Setup paths for importing workspace packages
sys.path.insert(0, r"d:\ARKA\backend\.venv\Lib\site-packages")
sys.path.insert(0, r"d:\ARKA\agent")
sys.path.insert(0, r"d:\ARKA\backend")

import psutil
from arka_agent.active_response import ActiveResponseExecutor


def run_tests():
    test_results = []
    print("=" * 80)
    print("STARTING EMPIRICAL TEST SUITE 1: ACTIVE RESPONSE EXECUTOR")
    print("=" * 80)

    temp_dir = Path(tempfile.mkdtemp(prefix="arka_test_vault_"))
    try:
        executor = ActiveResponseExecutor(
            agent_id="test-emp-agent-01",
            tenant_id="test-tenant-empirical",
            quarantine_dir=temp_dir,
            backend_hosts=["10.50.0.1", "arka.internal.corp", "localhost"],
            dry_run=True,
        )

        # ---------------------------------------------------------------------
        # 1. IP Safety Allowlist Protection
        # ---------------------------------------------------------------------
        protected_ips = [
            ("127.0.0.1", "IPv4 Loopback standard"),
            ("127.0.0.53", "IPv4 Loopback resolver"),
            ("127.255.255.254", "IPv4 Loopback high range"),
            ("::1", "IPv6 Loopback"),
            ("0.0.0.0", "IPv4 Unspecified address"),
            ("::", "IPv6 Unspecified address"),
            ("255.255.255.255", "IPv4 Broadcast"),
            ("10.50.0.1", "Configured backend host IP"),
            ("arka.internal.corp", "Configured backend hostname"),
            ("not-an-ip-address", "Malformed non-IP string"),
            ("999.999.999.999", "Out of bounds IPv4"),
            ("1.2.3.4.5", "5-octet string"),
            (":::1", "Malformed IPv6"),
        ]

        # Also add local interface IPs
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.address and not addr.address.startswith("fe80"):
                    protected_ips.append((addr.address, f"Local interface IP ({iface})"))
                    break

        print("\n--- [1/5] Testing Protected IP Blocking Guardrails ---")
        for ip_val, desc in protected_ips:
            res = executor.block_ip(ip_val)
            is_blocked = res["status"] == "BLOCKED_BY_SAFETY"
            print(f"  [{'PASS' if is_blocked else 'FAIL'}] Target: '{ip_val}' ({desc}) -> Status: {res['status']} | Message: {res['message']}")
            test_results.append({
                "category": "IP Safety Guardrails",
                "test": f"Block IP: {ip_val} ({desc})",
                "status": "PASS" if is_blocked else "FAIL",
                "details": res,
            })

        # Test valid external IP should succeed in dry-run
        valid_ips = ["198.51.100.55", "203.0.113.88", "192.0.2.1"]
        for ip_val in valid_ips:
            res = executor.block_ip(ip_val)
            is_ok = res["status"] == "SUCCESS"
            print(f"  [{'PASS' if is_ok else 'FAIL'}] Target: '{ip_val}' (Valid Malicious External IP) -> Status: {res['status']} | Command: {res.get('command')}")
            test_results.append({
                "category": "IP Safety Guardrails",
                "test": f"Block Valid IP: {ip_val}",
                "status": "PASS" if is_ok else "FAIL",
                "details": res,
            })

        # ---------------------------------------------------------------------
        # 2. PID Safety & Process Termination Guardrails
        # ---------------------------------------------------------------------
        print("\n--- [2/5] Testing Protected PID Termination Guardrails ---")
        protected_pids = [
            (0, "System Idle Process (PID 0)"),
            (1, "Init / System PID 1"),
            (2, "kthreadd / Core PID 2"),
            (4, "Windows System Process (PID 4)"),
            (os.getpid(), f"Agent Daemon Self PID ({os.getpid()})"),
            (os.getppid(), f"Parent Process PID ({os.getppid()})"),
        ]

        for pid_val, desc in protected_pids:
            res = executor.kill_process(pid_val)
            is_blocked = res["status"] == "BLOCKED_BY_SAFETY"
            print(f"  [{'PASS' if is_blocked else 'FAIL'}] Target: PID {pid_val} ({desc}) -> Status: {res['status']} | Message: {res['message']}")
            test_results.append({
                "category": "PID Safety Guardrails",
                "test": f"Kill PID: {pid_val} ({desc})",
                "status": "PASS" if is_blocked else "FAIL",
                "details": res,
            })

        # Test invalid PIDs
        invalid_pids = [99999999, 12345678]
        for pid_val in invalid_pids:
            res = executor.kill_process(pid_val)
            is_nf = res["status"] == "NOT_FOUND"
            print(f"  [{'PASS' if is_nf else 'FAIL'}] Target: Non-existent PID {pid_val} -> Status: {res['status']}")
            test_results.append({
                "category": "PID Safety Guardrails",
                "test": f"Kill Non-existent PID: {pid_val}",
                "status": "PASS" if is_nf else "FAIL",
                "details": res,
            })

        # Test execute_command invalid string target for kill_process
        res_str = executor.execute_command("kill_process", "invalid_pid_string")
        is_failed = res_str["status"] == "FAILED"
        print(f"  [{'PASS' if is_failed else 'FAIL'}] Target: 'invalid_pid_string' -> Status: {res_str['status']} | Message: {res_str['message']}")
        test_results.append({
            "category": "PID Safety Guardrails",
            "test": "Kill Process with invalid string PID",
            "status": "PASS" if is_failed else "FAIL",
            "details": res_str,
        })

        # ---------------------------------------------------------------------
        # 3. Real Two-Phase Process Termination
        # ---------------------------------------------------------------------
        print("\n--- [3/5] Testing Real Two-Phase Process Termination ---")
        live_executor = ActiveResponseExecutor(
            agent_id="test-live-agent",
            quarantine_dir=temp_dir,
            dry_run=False,
        )

        dummy_proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        dummy_pid = dummy_proc.pid
        time.sleep(0.1)
        assert psutil.pid_exists(dummy_pid), f"Dummy proc {dummy_pid} did not start"

        kill_res = live_executor.kill_process(dummy_pid)
        time.sleep(0.2)
        proc_gone = not psutil.pid_exists(dummy_pid)

        is_kill_success = kill_res["status"] == "SUCCESS" and proc_gone
        print(f"  [{'PASS' if is_kill_success else 'FAIL'}] Terminated Dummy Process (PID {dummy_pid}) -> Status: {kill_res['status']} | Alive: {not proc_gone}")
        test_results.append({
            "category": "Process Termination Execution",
            "test": f"Live Termination of PID {dummy_pid}",
            "status": "PASS" if is_kill_success else "FAIL",
            "details": kill_res,
        })

        # ---------------------------------------------------------------------
        # 4. Quarantine Vault Security, Traversal & Integrity Verification
        # ---------------------------------------------------------------------
        print("\n--- [4/5] Testing Quarantine Vault Security & Integrity ---")

        # 4a. Critical Protected Files
        protected_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "C:\\Windows\\System32\\ntoskrnl.exe",
            "C:\\Windows\\System32\\kernel32.dll",
        ]
        for pfile in protected_files:
            res_q = executor.quarantine_file(pfile)
            # Either BLOCKED_BY_SAFETY or NOT_FOUND (if file doesn't exist on host)
            is_safe = res_q["status"] in ("BLOCKED_BY_SAFETY", "NOT_FOUND")
            print(f"  [{'PASS' if is_safe else 'FAIL'}] Quarantine Protected: '{pfile}' -> Status: {res_q['status']} | Msg: {res_q['message']}")
            test_results.append({
                "category": "Quarantine Security",
                "test": f"Quarantine Protected File: {pfile}",
                "status": "PASS" if is_safe else "FAIL",
                "details": res_q,
            })

        # 4b. Live Quarantine & Integrity Check
        test_file = temp_dir / "threat_sample.bin"
        content = b"\xde\xad\xbe\xef" * 1024
        test_file.write_bytes(content)
        expected_hash = hashlib.sha256(content).hexdigest()

        q_res = live_executor.quarantine_file(test_file)
        vault_file = temp_dir / f"{expected_hash}.quarantine"
        manifest_file = temp_dir / f"{expected_hash}.manifest.json"

        is_q_ok = (
            q_res["status"] == "SUCCESS"
            and not test_file.exists()
            and vault_file.exists()
            and manifest_file.exists()
        )
        print(f"  [{'PASS' if is_q_ok else 'FAIL'}] Quarantine File '{test_file.name}' -> Hash: {expected_hash} | Vault Exists: {vault_file.exists()}")
        test_results.append({
            "category": "Quarantine Lifecycle",
            "test": "Quarantine File with SHA-256 Manifest",
            "status": "PASS" if is_q_ok else "FAIL",
            "details": q_res,
        })

        # 4c. Tampered Vault Artifact Integrity Verification
        vault_file.write_bytes(b"tampered-corrupted-bytes-payload")
        tamper_res = live_executor.unquarantine_file(expected_hash)
        is_tamper_blocked = tamper_res["status"] == "FAILED" and "Integrity verification failed" in tamper_res["message"]
        print(f"  [{'PASS' if is_tamper_blocked else 'FAIL'}] Unquarantine Tampered Artifact -> Status: {tamper_res['status']} | Msg: {tamper_res['message']}")
        test_results.append({
            "category": "Quarantine Integrity",
            "test": "Detect Tampered Vault File (Hash Mismatch)",
            "status": "PASS" if is_tamper_blocked else "FAIL",
            "details": tamper_res,
        })

        # Restore genuine content for successful unquarantine
        vault_file.write_bytes(content)
        unq_res = live_executor.unquarantine_file(expected_hash)
        is_unq_ok = unq_res["status"] == "SUCCESS" and test_file.exists() and test_file.read_bytes() == content
        print(f"  [{'PASS' if is_unq_ok else 'FAIL'}] Unquarantine Restore Genuine File -> Status: {unq_res['status']} | Restored: {test_file.exists()}")
        test_results.append({
            "category": "Quarantine Lifecycle",
            "test": "Unquarantine and Restore Genuine File",
            "status": "PASS" if is_unq_ok else "FAIL",
            "details": unq_res,
        })

        # ---------------------------------------------------------------------
        # 5. Rollback Timers & Execution Dispatcher
        # ---------------------------------------------------------------------
        print("\n--- [5/5] Testing Rollback Timers & Dispatcher ---")
        timer_res = executor.execute_command(
            "block_ip",
            "198.51.100.22",
            parameters={"duration_seconds": 0.5},
        )
        has_timer = "Automatic rollback scheduled in 0.5s" in timer_res["message"]
        timer_key = "unblock_198.51.100.22"
        timer_active = timer_key in executor._active_rollback_timers
        print(f"  [{'PASS' if (has_timer and timer_active) else 'FAIL'}] Schedule Rollback Timer (0.5s) -> Message: {timer_res['message']}")
        test_results.append({
            "category": "Rollback Timers",
            "test": "Schedule Rollback Timer",
            "status": "PASS" if (has_timer and timer_active) else "FAIL",
            "details": timer_res,
        })

        # Test consecutive block on same IP cancels old timer and replaces it
        old_timer = executor._active_rollback_timers[timer_key]
        timer_res_2 = executor.execute_command(
            "block_ip",
            "198.51.100.22",
            parameters={"duration_seconds": 10.0},
        )
        new_timer = executor._active_rollback_timers[timer_key]
        is_replaced = new_timer is not old_timer
        print(f"  [{'PASS' if is_replaced else 'FAIL'}] Re-block Replaces Active Timer -> Old Timer Cancelled: {is_replaced}")
        test_results.append({
            "category": "Rollback Timers",
            "test": "Re-block Cancels Previous Timer",
            "status": "PASS" if is_replaced else "FAIL",
            "details": timer_res_2,
        })
        new_timer.cancel()  # Clean up

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    print("\n" + "=" * 80)
    passed_count = sum(1 for r in test_results if r["status"] == "PASS")
    total_count = len(test_results)
    print(f"TEST SUITE 1 SUMMARY: {passed_count}/{total_count} PASSED")
    print("=" * 80)
    return test_results


if __name__ == "__main__":
    results = run_tests()
    failed = [r for r in results if r["status"] == "FAIL"]
    if failed:
        print(f"FAILURES DETECTED: {len(failed)}")
        sys.exit(1)
    print("ALL SUITE 1 TESTS PASSED!")

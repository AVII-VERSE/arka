"""
Adversarial Stress Test Suite for Milestone 2: RootcheckScanner.
Tests rootkit detection with disguised paths, symlinks, hidden dirs,
fake /proc structures, unmapped sockets, custom backdoor ports,
promiscuous interfaces, preload tampering, and SUID/SGID permissions.
"""

import collections
import os
import stat
import tempfile
import pytest

from arka_agent.collectors.rootcheck import (
    RootcheckScanner,
    BACKDOOR_PORTS,
    IFF_PROMISC_FLAG,
)


class MockAddr:
    def __init__(self, ip="0.0.0.0", port=80):
        self.ip = ip
        self.port = port


class MockConnection:
    def __init__(self, status="LISTEN", laddr=None, pid=None, conn_type=1):
        self.status = status
        self.laddr = laddr
        self.pid = pid
        self.type = conn_type


class TestRootcheckSuspiciousFiles:
    """Stress tests filesystem scanning for rootkits and SUID/SGID anomalies."""

    def test_known_rootkit_files_and_directories(self, tmp_path):
        # Create simulated rootkit artifacts
        fake_diamorphine = tmp_path / "diamorphine"
        fake_diamorphine.write_text("rootkit_payload")

        fake_reptile_dir = tmp_path / ".reptile"
        fake_reptile_dir.mkdir()
        (fake_reptile_dir / "backdoor").write_text("backdoor_binary")

        scanner = RootcheckScanner(
            agent_id="test-agt-01",
            tenant_id="test-tenant-01",
            suspicious_paths=[
                str(fake_diamorphine),
                str(fake_reptile_dir),
                str(tmp_path / "non_existent_file"),
            ],
            suid_scan_dirs=[],
        )

        findings = scanner.scan_suspicious_files()
        assert len(findings) == 2

        # Verify event structures
        file_paths = {f["metadata"]["suspicious_path"] for f in findings}
        assert str(fake_diamorphine) in file_paths
        assert str(fake_reptile_dir) in file_paths

        for f in findings:
            assert f["source_type"] == "rootcheck"
            assert f["action"] == "suspicious_file_found"
            assert f["severity"] == "CRITICAL"
            assert f["metadata"]["mitre_technique"] == "T1014"

    def test_suid_and_sgid_binary_detection_in_volatile_dirs(self, tmp_path):
        volatile_dir = tmp_path / "volatile"
        volatile_dir.mkdir()
        nested_dir = volatile_dir / "nested" / "hidden"
        nested_dir.mkdir(parents=True)

        normal_file = volatile_dir / "normal.sh"
        normal_file.write_text("#!/bin/sh\necho hi\n")

        suid_file = nested_dir / "suid_rootkit"
        suid_file.write_text("#!/bin/sh\n")

        # Set SUID bit if supported by OS/filesystem
        if hasattr(stat, "S_ISUID"):
            try:
                os.chmod(str(suid_file), 0o4755)
            except OSError:
                pass

        scanner = RootcheckScanner(
            agent_id="test-agt-01",
            tenant_id="test-tenant-01",
            suspicious_paths=[],
            suid_scan_dirs=[str(volatile_dir)],
        )

        findings = scanner.scan_suspicious_files()
        # On POSIX filesystems where chmod 4755 succeeded, finding should trigger
        if hasattr(stat, "S_ISUID") and (os.stat(str(suid_file)).st_mode & stat.S_ISUID):
            assert len(findings) == 1
            assert findings[0]["action"] == "suspicious_suid_binary_found"
            assert findings[0]["metadata"]["is_suid"] is True
            assert findings[0]["metadata"]["mitre_technique"] == "T1548.001"


class TestRootcheckHiddenProcesses:
    """Stress tests dual-view /proc cross-validation for hidden rootkit processes."""

    def test_hidden_process_in_proc_filesystem(self, tmp_path):
        fake_proc = tmp_path / "proc"
        fake_proc.mkdir()

        # Normal visible process: PID 100
        proc_100 = fake_proc / "100"
        proc_100.mkdir()
        (proc_100 / "comm").write_text("systemd\n")
        (proc_100 / "cmdline").write_text("/lib/systemd/systemd\x00--user\x00")

        # Hidden process (in /proc but hidden from psutil): PID 666
        proc_666 = fake_proc / "666"
        proc_666.mkdir()
        (proc_666 / "comm").write_text("reptile_agent\n")
        (proc_666 / "cmdline").write_text("/tmp/.reptile/backdoor\x00-d\x00")

        # Non-numeric directory: should be ignored
        proc_sys = fake_proc / "sys"
        proc_sys.mkdir()

        scanner = RootcheckScanner(
            agent_id="test-agt-01",
            tenant_id="test-tenant-01",
            proc_dir=str(fake_proc),
        )

        # psutil only sees PID 100, missing PID 666
        findings = scanner.scan_hidden_processes(known_pids={100})
        assert len(findings) == 1

        finding = findings[0]
        assert finding["action"] == "hidden_process_detected"
        assert finding["severity"] == "CRITICAL"
        assert finding["metadata"]["pid"] == 666
        assert finding["metadata"]["process_name"] == "reptile_agent"
        assert finding["metadata"]["cmdline"] == "/tmp/.reptile/backdoor -d"
        assert finding["metadata"]["mitre_technique"] == "T1014"

    def test_hidden_process_with_missing_proc_files(self, tmp_path):
        fake_proc = tmp_path / "proc"
        fake_proc.mkdir()

        # Ghost PID: directory exists but comm/cmdline are deleted or inaccessible
        proc_999 = fake_proc / "999"
        proc_999.mkdir()

        scanner = RootcheckScanner(
            agent_id="test-agt-01",
            tenant_id="test-tenant-01",
            proc_dir=str(fake_proc),
        )

        findings = scanner.scan_hidden_processes(known_pids=set())
        assert len(findings) == 1
        assert findings[0]["metadata"]["pid"] == 999
        assert findings[0]["metadata"]["process_name"] is None
        assert findings[0]["metadata"]["cmdline"] is None


class TestRootcheckListeningSocketsAndInterfaces:
    """Stress tests backdoor ports, unmapped sockets, and promiscuous interfaces."""

    def test_backdoor_ports_detection(self):
        scanner = RootcheckScanner(agent_id="test-agt-01", tenant_id="test-tenant-01")

        mock_connections = [
            # Normal listener
            MockConnection(status="LISTEN", laddr=MockAddr(ip="127.0.0.1", port=8080), pid=1001),
            # Backdoor port 31337 (TCP)
            MockConnection(status="LISTEN", laddr=MockAddr(ip="0.0.0.0", port=31337), pid=2001),
            # Backdoor port 4444 (Metasploit default, UDP)
            MockConnection(status="NONE", laddr=MockAddr(ip="0.0.0.0", port=4444), pid=2002, conn_type=2),
            # Backdoor port 6667 (IRC botnet)
            MockConnection(status="LISTEN", laddr=MockAddr(ip="0.0.0.0", port=6667), pid=2003),
            # Non-listening established connection on backdoor port (should NOT trigger as listening)
            MockConnection(status="ESTABLISHED", laddr=MockAddr(ip="192.168.1.5", port=4444), pid=2004, conn_type=1),
        ]

        findings = scanner.scan_listening_ports(custom_connections=mock_connections)
        backdoor_findings = [f for f in findings if f["action"] == "suspicious_port_listening"]
        assert len(backdoor_findings) == 3

        ports_detected = {f["metadata"]["port"] for f in backdoor_findings}
        assert ports_detected == {31337, 4444, 6667}

    def test_unmapped_listener_socket_detection(self):
        scanner = RootcheckScanner(agent_id="test-agt-01", tenant_id="test-tenant-01")

        mock_connections = [
            # Unmapped socket (PID is None)
            MockConnection(status="LISTEN", laddr=MockAddr(ip="0.0.0.0", port=9001), pid=None),
            # Unmapped socket (PID is 0)
            MockConnection(status="LISTEN", laddr=MockAddr(ip="127.0.0.1", port=9002), pid=0),
            # Legitimate mapped socket
            MockConnection(status="LISTEN", laddr=MockAddr(ip="127.0.0.1", port=9003), pid=4500),
        ]

        findings = scanner.scan_listening_ports(custom_connections=mock_connections)
        unmapped_findings = [f for f in findings if f["action"] == "unmapped_socket_detected"]
        assert len(unmapped_findings) == 2

        unmapped_ports = {f["metadata"]["port"] for f in unmapped_findings}
        assert unmapped_ports == {9001, 9002}
        for f in unmapped_findings:
            assert f["metadata"]["mitre_technique"] == "T1014"

    def test_promiscuous_network_interface_detection(self, tmp_path):
        fake_sys_net = tmp_path / "sys" / "class" / "net"
        fake_sys_net.mkdir(parents=True)

        # eth0: Normal flags (0x1003 = UP | BROADCAST | MULTICAST, no PROMISC)
        eth0_dir = fake_sys_net / "eth0"
        eth0_dir.mkdir()
        (eth0_dir / "flags").write_text("0x1003\n")

        # eth1: Promiscuous mode enabled (0x1103 = UP | BROADCAST | PROMISC | MULTICAST)
        eth1_dir = fake_sys_net / "eth1"
        eth1_dir.mkdir()
        (eth1_dir / "flags").write_text("0x1103\n")

        # eth2: Malformed flags content (should not crash)
        eth2_dir = fake_sys_net / "eth2"
        eth2_dir.mkdir()
        (eth2_dir / "flags").write_text("CORRUPTED_HEX\n")

        scanner = RootcheckScanner(
            agent_id="test-agt-01",
            tenant_id="test-tenant-01",
            sys_net_dir=str(fake_sys_net),
        )

        findings = scanner.scan_listening_ports(custom_connections=[])
        promisc_findings = [f for f in findings if f["action"] == "promiscuous_interface_detected"]
        assert len(promisc_findings) == 1

        assert promisc_findings[0]["metadata"]["interface"] == "eth1"
        assert promisc_findings[0]["metadata"]["mitre_technique"] == "T1040"
        assert promisc_findings[0]["severity"] == "CRITICAL"


class TestRootcheckSystemBinariesAndPreload:
    """Stress tests dynamic linker preload and system binary audits."""

    def test_preload_tampering_detection(self, tmp_path):
        fake_preload = tmp_path / "ld.so.preload"
        fake_preload.write_text(
            "# Standard comment\n"
            "\n"
            "/usr/local/lib/libazazel.so\n"
            "/lib/x86_64-linux-gnu/evil_hook.so\n"
        )

        scanner = RootcheckScanner(
            agent_id="test-agt-01",
            tenant_id="test-tenant-01",
            preload_path=str(fake_preload),
            critical_binaries=[],
        )

        findings = scanner.scan_system_binaries()
        assert len(findings) == 1
        finding = findings[0]
        assert finding["action"] == "preload_tampering_detected"
        assert finding["metadata"]["injected_libraries"] == [
            "/usr/local/lib/libazazel.so",
            "/lib/x86_64-linux-gnu/evil_hook.so",
        ]
        assert finding["metadata"]["mitre_technique"] == "T1574.006"

    def test_clean_preload_file(self, tmp_path):
        fake_preload = tmp_path / "ld.so.preload"
        fake_preload.write_text("# No active libraries\n\n   # Another comment\n")

        scanner = RootcheckScanner(
            agent_id="test-agt-01",
            tenant_id="test-tenant-01",
            preload_path=str(fake_preload),
            critical_binaries=[],
        )

        findings = scanner.scan_system_binaries()
        assert len(findings) == 0

    def test_critical_binaries_missing_tampered_and_permissions(self, tmp_path):
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()

        # 1. Intact binary
        intact_bin = bin_dir / "ps"
        intact_bin.write_bytes(b"\x7fELF" + b"A" * 1000)

        # 2. Tampered binary (0 bytes)
        empty_bin = bin_dir / "netstat"
        empty_bin.write_bytes(b"")

        # 3. Missing binary
        missing_bin = bin_dir / "login"

        # 4. Insecure permissions binary (world writable)
        insecure_bin = bin_dir / "su"
        insecure_bin.write_bytes(b"\x7fELF" + b"B" * 500)
        if hasattr(stat, "S_IWOTH"):
            try:
                os.chmod(str(insecure_bin), 0o777)
            except OSError:
                pass

        scanner = RootcheckScanner(
            agent_id="test-agt-01",
            tenant_id="test-tenant-01",
            preload_path=str(tmp_path / "ld.so.preload.missing"),
            critical_binaries=[
                str(intact_bin),
                str(empty_bin),
                str(missing_bin),
                str(insecure_bin),
            ],
        )

        findings = scanner.scan_system_binaries()
        actions = {f["action"] for f in findings}

        assert "critical_binary_missing" in actions
        assert "critical_binary_tampered" in actions

        if hasattr(stat, "S_IWOTH") and (os.stat(str(insecure_bin)).st_mode & stat.S_IWOTH):
            assert "binary_permission_anomaly" in actions


class TestRootcheckCollectorLifecycle:
    """Stress tests collector enable/disable and full scan integration."""

    def test_collector_disabled(self):
        scanner = RootcheckScanner(enabled=False)
        assert scanner.collect() == []

    def test_run_full_scan_aggregation(self, tmp_path):
        scanner = RootcheckScanner(
            agent_id="test-agt-01",
            tenant_id="test-tenant-01",
            suspicious_paths=[],
            suid_scan_dirs=[],
            proc_dir=str(tmp_path / "non_existent_proc"),
            sys_net_dir=str(tmp_path / "non_existent_net"),
            preload_path=str(tmp_path / "non_existent_preload"),
            critical_binaries=[],
        )

        events = scanner.collect()
        # Should cleanly return a list (likely empty or only live system items if any) without raising exceptions
        assert isinstance(events, list)

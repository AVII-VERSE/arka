"""
Empirical Adversarial Test Suite for Syscollector & Inventory (Milestone 4).
Validates SyscollectorHarvester (agent) and InventoryService (backend) under hostile, corrupted, and boundary conditions.
"""

import asyncio
import os
import platform
import socket
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, PropertyMock, patch

import psutil
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.database import Base
from app.models.models import (
    Agent,
    AgentInventoryHardware,
    AgentInventoryNetwork,
    AgentInventoryOS,
    AgentInventoryPackage,
    AgentInventoryPort,
    AgentInventoryProcess,
    Tenant,
)
from app.schemas.schemas import InventorySnapshotPayload
from app.services.inventory_service import InventoryService
from arka_agent.collectors.syscollector import SyscollectorHarvester

# =============================================================================
# Agent-Side Tests: SyscollectorHarvester
# =============================================================================


class TestSyscollectorHarvesterAdversarial:
    """Stress testing package parsers and collector methods under hostile inputs."""

    def test_dpkg_output_parser_adversarial(self):
        """Stress test parse_dpkg_output with malformed, multi-column, and adversarial inputs."""
        malformed_inputs = [
            "",  # Empty
            "\n\n\n",  # Newlines only
            "single_column_without_tabs",
            "name_only\t",  # Missing version
            "\t\t\t\t",  # Only tabs
            "pkg1\t1.0.0\tamd64\tdeinstall ok config-files",  # Purged/deinstalled -> should be ignored
            "pkg2\t2.0.0\tamd64\tunknown ok not-installed",  # Not installed -> should be ignored
            "valid_pkg\t1.2.3-4\tamd64\tinstall ok installed",  # Valid
            "sql_injection_pkg'; DROP TABLE packages;--\t1.0.0\tx86_64\tinstall ok installed",
            "emoji_pkg_🔒\t1.0.0_🚀\tamd64\tinstall ok installed",
            "huge_line\t" + ("A" * 50000) + "\tamd64\tinstall ok installed",
        ]
        raw_text = "\n".join(malformed_inputs)
        packages = SyscollectorHarvester.parse_dpkg_output(raw_text)

        assert len(packages) == 4
        assert packages[0]["name"] == "valid_pkg"
        assert packages[0]["version"] == "1.2.3-4"
        assert packages[1]["name"] == "sql_injection_pkg'; DROP TABLE packages;--"
        assert packages[2]["name"] == "emoji_pkg_🔒"
        assert packages[3]["name"] == "huge_line"

    def test_dpkg_status_file_parser_adversarial(self):
        """Stress test parse_dpkg_status_content with malformed blocks and corrupted headers."""
        corrupted_status_content = """
Package: missing-version
Architecture: amd64
Status: install ok installed

Package: deinstalled-pkg
Version: 1.0.0
Status: deinstall ok config-files

Package: valid-pkg-1
Version: 2.3.4-1ubuntu1:2
Architecture: amd64
Status: install ok installed

Random junk without key value pair
Corrupted: header: with: too: many: colons:

Package: valid-pkg-2
Version: 5.6.7
Status: install ok installed
"""
        packages = SyscollectorHarvester.parse_dpkg_status_content(corrupted_status_content)
        assert len(packages) == 2
        assert packages[0]["name"] == "valid-pkg-1"
        assert packages[0]["version"] == "2.3.4-1ubuntu1:2"
        assert packages[1]["name"] == "valid-pkg-2"
        assert packages[1]["version"] == "5.6.7"

    def test_rpm_output_parser_adversarial(self):
        """Stress test parse_rpm_output with varying delimiter patterns and single strings."""
        raw_rpm = """
curl\t7.68.0-1.el8\tx86_64
openssl\t1.1.1k-6.el8_5\tx86_64
single-rpm-name-without-tabs-1.0.0-1.x86_64
\t\t
glibc\t2.28-164.el8\tx86_64
"""
        packages = SyscollectorHarvester.parse_rpm_output(raw_rpm)
        assert len(packages) == 4
        assert packages[0]["name"] == "curl"
        assert packages[0]["version"] == "7.68.0-1.el8"
        assert packages[2]["name"] == "single-rpm-name-without-tabs-1.0.0-1.x86_64"
        assert packages[2]["version"] == "unknown"

    def test_apk_output_parser_adversarial(self):
        """Stress test parse_apk_output with multiple hyphens, no hyphens, and weird releases."""
        raw_apk = """
alpine-baselayout-3.2.0-r22
busybox-1.34.1-r5
libcrypto3-3.0.8-r0
single_word_pkg
pkg-with-many-hyphens-in-name-1.0-r1
"""
        packages = SyscollectorHarvester.parse_apk_output(raw_apk)
        assert len(packages) == 5
        assert packages[0]["name"] == "alpine-baselayout"
        assert packages[0]["version"] == "3.2.0-r22"
        assert packages[3]["name"] == "single_word_pkg"
        assert packages[3]["version"] == "unknown"
        assert packages[4]["name"] == "pkg-with-many-hyphens-in-name"
        assert packages[4]["version"] == "1.0-r1"

    def test_winreg_entry_parser_adversarial(self):
        """Stress test parse_winreg_entry with None, missing keys, and odd types."""
        assert SyscollectorHarvester.parse_winreg_entry("app1", {}) is None
        assert SyscollectorHarvester.parse_winreg_entry("app2", {"DisplayVersion": "1.0"}) is None

        res = SyscollectorHarvester.parse_winreg_entry("app3", {"DisplayName": "MyApp"})
        assert res is not None
        assert res["name"] == "MyApp"
        assert res["version"] == "1.0.0"

        res2 = SyscollectorHarvester.parse_winreg_entry(
            "app4_64", {"DisplayName": "Tool 64", "DisplayVersion": 2024, "Publisher": "SecCorp"}
        )
        assert res2 is not None
        assert res2["name"] == "Tool 64"
        assert res2["version"] == "2024"
        assert res2["vendor"] == "SecCorp"
        assert res2["architecture"] == "x64"

    def test_hardware_zero_memory_and_inaccessible_disks(self):
        """
        Adversarial test: Hardware info harvester under zero total memory,
        failing swap, and inaccessible/locked disk partitions.
        """
        harvester = SyscollectorHarvester()

        with patch("psutil.virtual_memory", side_effect=Exception("RAM query error")), \
             patch("psutil.swap_memory", side_effect=Exception("Swap query error")), \
             patch("psutil.disk_partitions", return_value=[MagicMock(mountpoint="/locked", device="/dev/sda1", fstype="ext4")]), \
             patch("psutil.disk_usage", side_effect=PermissionError("Disk access locked")):

            hw = harvester.get_hardware_info()
            assert hw["ram_total_gb"] == 1.0
            assert hw["swap_total_gb"] == 0.0
            assert hw["disks"] == []
            assert hw["cpu_cores_logical"] >= 1

    def test_port_enumeration_with_access_denied(self):
        """
        Adversarial test: Port harvester when psutil.net_connections raises AccessDenied
        or contains corrupted socket entries.
        """
        harvester = SyscollectorHarvester()

        with patch("psutil.net_connections", side_effect=psutil.AccessDenied()):
            ports = harvester.get_network_ports()
            assert isinstance(ports, list)

        mock_conn1 = MagicMock(type=socket.SOCK_STREAM, laddr=None, raddr=None, status="LISTEN", pid=100)
        mock_conn2 = MagicMock(
            type=socket.SOCK_STREAM,
            laddr=MagicMock(ip="127.0.0.1", port="invalid_port"),
            raddr=None,
            status="LISTEN",
            pid=999999,
        )
        mock_conn3 = MagicMock(
            type=socket.SOCK_DGRAM,
            laddr=MagicMock(ip="0.0.0.0", port=5353),
            raddr=None,
            status=None,
            pid=None,
        )

        with patch("psutil.Process", side_effect=psutil.NoSuchProcess(999999)):
            ports = harvester.get_network_ports(custom_connections=[mock_conn1, mock_conn2, mock_conn3])
            assert len(ports) >= 1
            udp_port = next((p for p in ports if p["local_port"] == 5353), None)
            assert udp_port is not None
            assert udp_port["protocol"] == "udp"

    def test_process_enumeration_resilience(self):
        """
        Adversarial test: Process enumeration handles disappearing / denied processes gracefully.
        """
        harvester = SyscollectorHarvester(process_limit=10)

        # Create mock process objects
        proc_good = MagicMock()
        proc_good.info = {
            "pid": 1,
            "ppid": 0,
            "name": "systemd",
            "exe": "/sbin/init",
            "cmdline": ["/sbin/init"],
            "username": "root",
            "cpu_percent": 0.1,
            "memory_percent": 0.5,
            "status": "sleeping",
            "create_time": 1000.0,
            "num_threads": 1,
        }

        proc_zombie = MagicMock()
        type(proc_zombie).info = PropertyMock(side_effect=psutil.ZombieProcess(pid=2))

        proc_denied = MagicMock()
        type(proc_denied).info = PropertyMock(side_effect=psutil.AccessDenied(pid=3))

        with patch("psutil.process_iter", return_value=[proc_good, proc_zombie, proc_denied]):
            procs = harvester.get_running_processes()
            assert len(procs) == 1
            assert procs[0]["pid"] == 1
            assert procs[0]["name"] == "systemd"


# =============================================================================
# Backend-Side Tests: InventoryService
# =============================================================================

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def async_db():
    engine = create_async_engine(TEST_DB_URL, echo=False)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.mark.asyncio
class TestInventoryServiceAdversarial:
    """Stress tests and boundary condition evaluations for InventoryService."""

    async def test_ingest_snapshot_unhandled_type_conversion_exceptions(self, async_db: AsyncSession):
        """
        EMPIRICAL BUG VERIFICATION: InventoryService.ingest_snapshot fails to catch
        ValueError / TypeError on malformed numeric types in hardware and process payloads.
        """
        # 1. Non-integer cpu_cores_logical
        payload_bad_cores = {
            "agent_id": "agent-bad-cores",
            "tenant_id": "tenant-test",
            "hardware": {"cpu_cores_logical": "invalid_int"},
        }
        with pytest.raises(ValueError) as exc_info:
            await InventoryService.ingest_snapshot(async_db, payload_bad_cores)
        assert "invalid literal for int()" in str(exc_info.value)

        # 2. Non-float ram_total_gb
        payload_bad_ram = {
            "agent_id": "agent-bad-ram",
            "tenant_id": "tenant-test",
            "hardware": {"ram_total_gb": "invalid_float"},
        }
        with pytest.raises(ValueError) as exc_info2:
            await InventoryService.ingest_snapshot(async_db, payload_bad_ram)
        assert "could not convert string to float" in str(exc_info2.value)

        # 3. None ram_total_gb
        payload_none_ram = {
            "agent_id": "agent-none-ram",
            "tenant_id": "tenant-test",
            "hardware": {"ram_total_gb": None},
        }
        with pytest.raises(TypeError) as exc_info3:
            await InventoryService.ingest_snapshot(async_db, payload_none_ram)
        assert "float() argument must be" in str(exc_info3.value)

        # 4. Non-float process cpu_percent
        payload_bad_proc_cpu = {
            "agent_id": "agent-bad-proc",
            "tenant_id": "tenant-test",
            "running_processes": [{"pid": 100, "name": "bad_proc", "cpu_percent": "N/A"}],
        }
        with pytest.raises(ValueError) as exc_info4:
            await InventoryService.ingest_snapshot(async_db, payload_bad_proc_cpu)
        assert "could not convert string to float" in str(exc_info4.value)

    async def test_ingest_snapshot_with_corrupted_subresources_safe(self, async_db: AsyncSession):
        """
        Test that packages, network interfaces, and ports with malformed elements
        (None, strings, ints, empty dicts) ARE safely filtered without crashing.
        """
        payload = {
            "agent_id": "agent-stress-01",
            "tenant_id": "tenant-stress",
            "hardware": {
                "cpu_cores_logical": 8,
                "ram_total_gb": 16.0,
                "disks": [{"mountpoint": "/", "total_gb": 100.0}],
            },
            "os": {
                "os_name": "Linux",
                "os_version": "Ubuntu 22.04",
            },
            "packages": [
                None,
                "not_a_dict",
                12345,
                {},
                {"name": "", "version": "1.0"},
                {"name": "valid-pkg", "version": "1.2.3"},
            ],
            "network_interfaces": [
                None,
                {},
                {"interface_name": ""},
                {"interface_name": "eth0", "ipv4_address": "192.168.1.50"},
            ],
            "open_ports": [
                None,
                {"local_port": "not_an_int", "pid": "bad_pid"},
                {"local_port": 443, "protocol": "tcp", "pid": 1234},
            ],
            "running_processes": [
                None,
                {"pid": "invalid_pid", "name": "bad_proc", "cpu_percent": 0.0, "memory_percent": 0.0},
                {"pid": 500, "name": "nginx", "cpu_percent": 1.5, "memory_percent": 2.0},
            ],
        }

        res = await InventoryService.ingest_snapshot(async_db, payload)
        await async_db.commit()

        assert res["status"] == "success"
        stored_pkgs = await InventoryService.get_packages(async_db, "agent-stress-01", "tenant-stress")
        assert len(stored_pkgs) == 1
        assert stored_pkgs[0].name == "valid-pkg"

        stored_net = await InventoryService.get_network(async_db, "agent-stress-01", "tenant-stress")
        assert len(stored_net) == 1
        assert stored_net[0].interface_name == "eth0"

        stored_ports = await InventoryService.get_ports(async_db, "agent-stress-01", "tenant-stress")
        assert len(stored_ports) == 2
        p443 = next(p for p in stored_ports if p.local_port == 443)
        assert p443.protocol == "tcp"

    async def test_atomic_upsert_replacement_consistency(self, async_db: AsyncSession):
        """
        Adversarial test: Rapid sequential snapshots must completely replace
        old subresources without residual ghost records.
        """
        agent_id = "agent-replace-01"
        tenant_id = "tenant-replace"

        # Snapshot 1: 5 packages, 3 ports
        snap1 = {
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "packages": [{"name": f"pkg-v1-{i}", "version": "1.0"} for i in range(5)],
            "open_ports": [{"local_port": 8000 + i, "protocol": "tcp"} for i in range(3)],
        }
        await InventoryService.ingest_snapshot(async_db, snap1)
        await async_db.commit()

        pkgs1 = await InventoryService.get_packages(async_db, agent_id, tenant_id)
        assert len(pkgs1) == 5

        # Snapshot 2: 2 completely different packages, 1 port
        snap2 = {
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "packages": [{"name": f"pkg-v2-{i}", "version": "2.0"} for i in range(2)],
            "open_ports": [{"local_port": 9000, "protocol": "tcp"}],
        }
        await InventoryService.ingest_snapshot(async_db, snap2)
        await async_db.commit()

        pkgs2 = await InventoryService.get_packages(async_db, agent_id, tenant_id)
        assert len(pkgs2) == 2
        assert all("pkg-v2" in p.name for p in pkgs2)

        ports2 = await InventoryService.get_ports(async_db, agent_id, tenant_id)
        assert len(ports2) == 1
        assert ports2[0].local_port == 9000

    async def test_non_existent_agent_and_tenant_queries(self, async_db: AsyncSession):
        """
        Adversarial test: Querying subresources or summaries for non-existent agents or tenants
        must return None or empty collections with ZERO crashes or fake fallbacks.
        """
        hw = await InventoryService.get_hardware(async_db, "ghost-agent", "ghost-tenant")
        assert hw is None

        os_info = await InventoryService.get_os(async_db, "ghost-agent", "ghost-tenant")
        assert os_info is None

        pkgs = await InventoryService.get_packages(async_db, "ghost-agent", "ghost-tenant")
        assert pkgs == []

        net = await InventoryService.get_network(async_db, "ghost-agent", "ghost-tenant")
        assert net == []

        ports = await InventoryService.get_ports(async_db, "ghost-agent", "ghost-tenant")
        assert ports == []

        procs = await InventoryService.get_processes(async_db, "ghost-agent", "ghost-tenant")
        assert procs == []

        summaries = await InventoryService.get_inventory_summary(async_db, "ghost-tenant")
        assert summaries == []

    async def test_strict_tenant_isolation_in_inventory(self, async_db: AsyncSession):
        """
        Adversarial test: Ensure Tenant A cannot view Tenant B's hardware, OS,
        packages, ports, network, or processes.
        """
        tenant_a = Tenant(id="tenant-A", name="Tenant A", slug="tenant-a")
        tenant_b = Tenant(id="tenant-B", name="Tenant B", slug="tenant-b")
        async_db.add_all([tenant_a, tenant_b])
        await async_db.flush()

        agent_a = Agent(
            id="agent-A",
            tenant_id="tenant-A",
            hostname="host-a",
            ip_address="10.0.0.1",
            os_type="linux",
            os_version="Ubuntu 22.04",
        )
        agent_b = Agent(
            id="agent-B",
            tenant_id="tenant-B",
            hostname="host-b",
            ip_address="10.0.0.2",
            os_type="windows",
            os_version="Windows Server 2022",
        )
        async_db.add_all([agent_a, agent_b])
        await async_db.commit()

        await InventoryService.ingest_snapshot(
            async_db,
            {
                "agent_id": "agent-A",
                "tenant_id": "tenant-A",
                "hardware": {"cpu_cores_logical": 8, "ram_total_gb": 32.0},
                "packages": [{"name": "secret-corp-pkg", "version": "1.0"}],
            },
        )
        await InventoryService.ingest_snapshot(
            async_db,
            {
                "agent_id": "agent-B",
                "tenant_id": "tenant-B",
                "hardware": {"cpu_cores_logical": 4, "ram_total_gb": 16.0},
                "packages": [{"name": "other-corp-pkg", "version": "2.0"}],
            },
        )
        await async_db.commit()

        # Tenant A tries to access Tenant B's agent
        hw_cross = await InventoryService.get_hardware(async_db, "agent-B", "tenant-A")
        assert hw_cross is None

        pkgs_cross = await InventoryService.get_packages(async_db, "agent-B", "tenant-A")
        assert len(pkgs_cross) == 0

        sum_a = await InventoryService.get_inventory_summary(async_db, "tenant-A")
        assert len(sum_a) == 1
        assert sum_a[0].agent_id == "agent-A"
        assert sum_a[0].packages_count == 1

        sum_b = await InventoryService.get_inventory_summary(async_db, "tenant-B")
        assert len(sum_b) == 1
        assert sum_b[0].agent_id == "agent-B"

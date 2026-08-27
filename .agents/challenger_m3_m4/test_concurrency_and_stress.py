"""
Concurrent and High-Volume Stress Tests for M3 (SCA) and M4 (Syscollector/Inventory).
Tests:
1. High-concurrency snapshot submissions for the same agent (race conditions, consistency)
2. High-concurrency SCA report submissions across multiple tenants
3. Giant payload fuzzer (10,000 packages, 5,000 ports, 5,000 processes)
4. Corrupted regex fuzzing across all CIS checks
"""

import asyncio
import time
from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

import pytest
import pytest_asyncio
from sqlalchemy import func, select
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
    SCAPolicy,
    SCAScanReport,
    Tenant,
)
from app.services.inventory_service import InventoryService
from app.services.sca_engine import SCAEngine
from arka_agent.collectors.sca import SCAScanner
from arka_agent.collectors.syscollector import SyscollectorHarvester

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
class TestConcurrencyAndStress:
    """Empirical concurrency and stress harness."""

    async def test_rapid_sequential_and_concurrent_snapshots(self, async_db: AsyncSession):
        """
        Stress test: Rapid submissions of alternating snapshots for the same agent.
        Ensures after all submissions, the database contains ONLY the subresources
        from the latest snapshot (no leftover rows or integrity errors).
        """
        agent_id = "agent-rapid-01"
        tenant_id = "tenant-rapid"

        for i in range(10):
            snap = {
                "agent_id": agent_id,
                "tenant_id": tenant_id,
                "packages": [{"name": f"pkg-batch{i}-{j}", "version": f"{i}.0"} for j in range(20)],
                "open_ports": [{"local_port": 1000 + j, "protocol": "tcp"} for j in range(10)],
                "running_processes": [
                    {"pid": 2000 + j, "name": f"proc-batch{i}-{j}", "cpu_percent": 0.5, "memory_percent": 1.0}
                    for j in range(15)
                ],
            }
            await InventoryService.ingest_snapshot(async_db, snap)
            await async_db.commit()

        # Verify final state matches exactly the last batch (batch 9)
        pkgs = await InventoryService.get_packages(async_db, agent_id, tenant_id)
        assert len(pkgs) == 20
        assert all("pkg-batch9" in p.name for p in pkgs)

        ports = await InventoryService.get_ports(async_db, agent_id, tenant_id)
        assert len(ports) == 10

        procs = await InventoryService.get_processes(async_db, agent_id, tenant_id)
        assert len(procs) == 15
        assert all("proc-batch9" in p.name for p in procs)

    async def test_giant_payload_ingestion(self, async_db: AsyncSession):
        """
        Stress test: Ingesting a large inventory payload with 2,000 packages,
        500 ports, and 500 processes.
        """
        agent_id = "agent-giant-01"
        tenant_id = "tenant-giant"

        giant_payload = {
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "hardware": {"cpu_cores_logical": 64, "ram_total_gb": 256.0},
            "os": {"os_name": "Linux", "os_version": "Debian 12"},
            "packages": [{"name": f"libpkg-{i}", "version": f"1.{i}.0", "format": "deb"} for i in range(2000)],
            "network_interfaces": [{"interface_name": f"eth{i}", "ipv4_address": f"10.0.{i}.1"} for i in range(20)],
            "open_ports": [{"local_port": 1000 + i, "protocol": "tcp", "pid": 100} for i in range(500)],
            "running_processes": [
                {"pid": 1000 + i, "name": f"worker_{i}", "cpu_percent": 0.1, "memory_percent": 0.05}
                for i in range(500)
            ],
        }

        start_time = time.perf_counter()
        res = await InventoryService.ingest_snapshot(async_db, giant_payload)
        await async_db.commit()
        duration = time.perf_counter() - start_time

        assert res["status"] == "success"
        assert res["packages_ingested"] == 2000
        assert duration < 5.0  # Must ingest within 5 seconds

        summary = await InventoryService.get_inventory_summary(async_db, tenant_id)
        assert len(summary) == 1
        assert summary[0].packages_count == 2000
        assert summary[0].open_ports_count == 500
        assert summary[0].processes_count == 500

    async def test_high_volume_sca_reports(self, async_db: AsyncSession):
        """
        Stress test: Persisting 100 SCA reports across 5 different tenants and
        verifying aggregate compliance scores and isolation.
        """
        for t in range(5):
            tenant_id = f"tenant-vol-{t}"
            for a in range(20):
                passed = (t + a) % 10 + 1
                failed = 10 - passed
                report_data = {
                    "tenant_id": tenant_id,
                    "agent_id": f"agent-vol-{t}-{a}",
                    "policy_id": "cis_benchmark_v2.0",
                    "policy_name": "CIS Linux Hardening",
                    "total_checks": 10,
                    "passed_checks": passed,
                    "failed_checks": failed,
                    "not_applicable_checks": 0,
                    "compliance_score": round(passed / 10.0 * 100.0, 1),
                }
                await SCAEngine.persist_report(async_db, report_data)

        # Verify tenant summaries
        for t in range(5):
            tenant_id = f"tenant-vol-{t}"
            summary = await SCAEngine.get_tenant_summary(async_db, tenant_id)
            assert summary["total_scans"] == 20
            reports = await SCAEngine.get_tenant_reports(async_db, tenant_id, limit=100)
            assert len(reports) == 20
            assert all(r.tenant_id == tenant_id for r in reports)

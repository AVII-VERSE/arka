"""
ARKA System Inventory Service.
Handles relational persistence and sub-resource queries for endpoint hardware,
OS metadata, installed packages, network interfaces, open ports, and running processes.
"""

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import (
    Agent,
    AgentInventoryHardware,
    AgentInventoryNetwork,
    AgentInventoryOS,
    AgentInventoryPackage,
    AgentInventoryPort,
    AgentInventoryProcess,
)
from app.schemas.schemas import (
    AgentInventorySummary,
    InventorySnapshotPayload,
)

logger = logging.getLogger(__name__)


class InventoryService:
    """Relational System Inventory Management and Query Engine."""

    @staticmethod
    async def ingest_snapshot(  # noqa: PLR0912, PLR0915
        db: AsyncSession,
        payload: InventorySnapshotPayload | dict[str, Any],
        tenant_id_override: str | None = None,
    ) -> dict[str, Any]:
        """
        Atomically persists an endpoint system inventory snapshot into canonical relational tables.
        Replaces previous packages, interfaces, ports, and processes for the target agent.
        """
        if isinstance(payload, dict):
            agent_id = payload.get("agent_id", "unknown-agent")
            tenant_id = (
                tenant_id_override
                or payload.get("tenant_id")
                or "default-tenant"
            )
            snapshot_id = payload.get("snapshot_id", f"syscol-{datetime.now(UTC).timestamp()}")
            hardware_dict = payload.get("hardware", {})
            os_dict = payload.get("os", {})
            packages_list = payload.get("packages", [])
            network_list = payload.get("network_interfaces", [])
            ports_list = payload.get("open_ports", [])
            processes_list = payload.get("running_processes", [])
        else:
            agent_id = payload.agent_id
            tenant_id = tenant_id_override or payload.tenant_id or "default-tenant"
            snapshot_id = payload.snapshot_id or f"syscol-{datetime.now(UTC).timestamp()}"
            hardware_dict = payload.hardware
            os_dict = payload.os
            packages_list = payload.packages
            network_list = payload.network_interfaces
            ports_list = payload.open_ports
            processes_list = payload.running_processes

        # Resolve tenant_id from registered Agent if agent exists in DB
        agent_res = await db.execute(select(Agent).where(Agent.id == agent_id))
        agent_record = agent_res.scalar_one_or_none()
        if agent_record and not tenant_id_override:
            tenant_id = agent_record.tenant_id

        now = datetime.now(UTC)

        # ---------------------------------------------------------------------
        # 1. Upsert Hardware Inventory
        # ---------------------------------------------------------------------
        if hardware_dict:
            hw_res = await db.execute(
                select(AgentInventoryHardware).where(AgentInventoryHardware.agent_id == agent_id)
            )
            hw_record = hw_res.scalar_one_or_none()

            logical_cores = int(hardware_dict.get("cpu_cores_logical", 1))
            physical_cores = int(hardware_dict.get("cpu_cores_physical", 1))
            cpu_arch = str(hardware_dict.get("cpu_architecture", "unknown"))
            ram_gb = float(hardware_dict.get("ram_total_gb", 0.0))
            disks = hardware_dict.get("disks", [])

            if hw_record:
                hw_record.tenant_id = tenant_id
                hw_record.cpu_cores_logical = logical_cores
                hw_record.cpu_cores_physical = physical_cores
                hw_record.cpu_architecture = cpu_arch
                hw_record.ram_total_gb = ram_gb
                hw_record.disks = disks
                hw_record.updated_at = now
            else:
                new_hw = AgentInventoryHardware(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    cpu_cores_logical=logical_cores,
                    cpu_cores_physical=physical_cores,
                    cpu_architecture=cpu_arch,
                    ram_total_gb=ram_gb,
                    disks=disks,
                    updated_at=now,
                )
                db.add(new_hw)

        # ---------------------------------------------------------------------
        # 2. Upsert OS Inventory
        # ---------------------------------------------------------------------
        if os_dict:
            os_res = await db.execute(
                select(AgentInventoryOS).where(AgentInventoryOS.agent_id == agent_id)
            )
            os_record = os_res.scalar_one_or_none()

            os_name = str(os_dict.get("os_name", "unknown"))
            os_release = str(os_dict.get("os_release", "unknown"))
            os_version = str(os_dict.get("os_version", "unknown"))
            kernel_arch = str(os_dict.get("kernel_architecture", "unknown"))
            hostname = str(os_dict.get("hostname", "unknown"))
            python_ver = str(os_dict.get("python_version", "unknown"))

            if os_record:
                os_record.tenant_id = tenant_id
                os_record.os_name = os_name
                os_record.os_release = os_release
                os_record.os_version = os_version
                os_record.kernel_architecture = kernel_arch
                os_record.hostname = hostname
                os_record.python_version = python_ver
                os_record.updated_at = now
            else:
                new_os = AgentInventoryOS(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    os_name=os_name,
                    os_release=os_release,
                    os_version=os_version,
                    kernel_architecture=kernel_arch,
                    hostname=hostname,
                    python_version=python_ver,
                    updated_at=now,
                )
                db.add(new_os)

        # ---------------------------------------------------------------------
        # 3. Replace Installed Packages
        # ---------------------------------------------------------------------
        await db.execute(
            delete(AgentInventoryPackage).where(AgentInventoryPackage.agent_id == agent_id)
        )
        for pkg in packages_list:
            if not isinstance(pkg, dict):
                continue
            pkg_name = str(pkg.get("name", "")).strip()
            pkg_ver = str(pkg.get("version", "")).strip()
            if not pkg_name:
                continue
            pkg_record = AgentInventoryPackage(
                tenant_id=tenant_id,
                agent_id=agent_id,
                name=pkg_name,
                version=pkg_ver,
                format=pkg.get("format"),
                architecture=pkg.get("architecture"),
                updated_at=now,
            )
            db.add(pkg_record)

        # ---------------------------------------------------------------------
        # 4. Replace Network Interfaces
        # ---------------------------------------------------------------------
        await db.execute(
            delete(AgentInventoryNetwork).where(AgentInventoryNetwork.agent_id == agent_id)
        )
        for iface in network_list:
            if not isinstance(iface, dict):
                continue
            iface_name = str(iface.get("interface_name", "")).strip()
            if not iface_name:
                continue
            net_record = AgentInventoryNetwork(
                tenant_id=tenant_id,
                agent_id=agent_id,
                interface_name=iface_name,
                ipv4_address=iface.get("ipv4_address"),
                ipv6_address=iface.get("ipv6_address"),
                mac_address=iface.get("mac_address"),
                updated_at=now,
            )
            db.add(net_record)

        # ---------------------------------------------------------------------
        # 5. Replace Open Ports
        # ---------------------------------------------------------------------
        await db.execute(
            delete(AgentInventoryPort).where(AgentInventoryPort.agent_id == agent_id)
        )
        for port in ports_list:
            if not isinstance(port, dict):
                continue
            local_port_val = port.get("local_port", 0)
            try:
                local_port_int = int(local_port_val)
            except (ValueError, TypeError):
                local_port_int = 0

            pid_val = port.get("pid")
            pid_int: int | None = None
            if pid_val is not None:
                try:
                    pid_int = int(pid_val)
                except (ValueError, TypeError):
                    pid_int = None

            local_ip_val = port.get("local_ip") or ""
            port_record = AgentInventoryPort(
                tenant_id=tenant_id,
                agent_id=agent_id,
                protocol=str(port.get("protocol", "tcp")),
                local_ip=str(local_ip_val),
                local_port=local_port_int,
                pid=pid_int,
                process_name=port.get("process_name"),
                state=port.get("state"),
                updated_at=now,
            )
            db.add(port_record)

        # ---------------------------------------------------------------------
        # 6. Replace Running Processes
        # ---------------------------------------------------------------------
        await db.execute(
            delete(AgentInventoryProcess).where(AgentInventoryProcess.agent_id == agent_id)
        )
        for proc in processes_list:
            if not isinstance(proc, dict):
                continue
            proc_pid = proc.get("pid", 0)
            try:
                proc_pid_int = int(proc_pid)
            except (ValueError, TypeError):
                proc_pid_int = 0

            proc_record = AgentInventoryProcess(
                tenant_id=tenant_id,
                agent_id=agent_id,
                pid=proc_pid_int,
                name=str(proc.get("name", "unknown")),
                username=proc.get("username"),
                cpu_percent=float(proc.get("cpu_percent", 0.0)),
                memory_percent=float(proc.get("memory_percent", 0.0)),
                updated_at=now,
            )
            db.add(proc_record)

        await db.flush()

        return {
            "status": "success",
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "snapshot_id": snapshot_id,
            "packages_ingested": len(packages_list),
            "network_interfaces_ingested": len(network_list),
            "open_ports_ingested": len(ports_list),
            "running_processes_ingested": len(processes_list),
        }

    @staticmethod
    async def get_inventory_summary(
        db: AsyncSession, tenant_id: str
    ) -> list[AgentInventorySummary]:
        """
        Retrieves inventory summary metrics across all endpoint agents in a tenant.
        Returns empty list if no inventory data exists for the tenant.
        """
        # Discover all unique agent IDs associated with this tenant across inventory tables & Agent table
        agent_ids: set[str] = set()

        agents_res = await db.execute(select(Agent.id).where(Agent.tenant_id == tenant_id))
        for aid in agents_res.scalars().all():
            agent_ids.add(aid)

        hw_agents_res = await db.execute(
            select(AgentInventoryHardware.agent_id).where(
                AgentInventoryHardware.tenant_id == tenant_id
            )
        )
        for aid in hw_agents_res.scalars().all():
            agent_ids.add(aid)

        os_agents_res = await db.execute(
            select(AgentInventoryOS.agent_id).where(AgentInventoryOS.tenant_id == tenant_id)
        )
        for aid in os_agents_res.scalars().all():
            agent_ids.add(aid)

        summaries: list[AgentInventorySummary] = []

        for aid in sorted(agent_ids):
            # Query Hardware
            hw_res = await db.execute(
                select(AgentInventoryHardware).where(
                    AgentInventoryHardware.agent_id == aid,
                    AgentInventoryHardware.tenant_id == tenant_id,
                )
            )
            hw = hw_res.scalar_one_or_none()

            # Query OS
            os_res = await db.execute(
                select(AgentInventoryOS).where(
                    AgentInventoryOS.agent_id == aid,
                    AgentInventoryOS.tenant_id == tenant_id,
                )
            )
            os_info = os_res.scalar_one_or_none()

            # Counts
            pkg_cnt_res = await db.execute(
                select(func.count(AgentInventoryPackage.id)).where(
                    AgentInventoryPackage.agent_id == aid,
                    AgentInventoryPackage.tenant_id == tenant_id,
                )
            )
            pkg_count = pkg_cnt_res.scalar() or 0

            net_cnt_res = await db.execute(
                select(func.count(AgentInventoryNetwork.id)).where(
                    AgentInventoryNetwork.agent_id == aid,
                    AgentInventoryNetwork.tenant_id == tenant_id,
                )
            )
            net_count = net_cnt_res.scalar() or 0

            port_cnt_res = await db.execute(
                select(func.count(AgentInventoryPort.id)).where(
                    AgentInventoryPort.agent_id == aid,
                    AgentInventoryPort.tenant_id == tenant_id,
                )
            )
            port_count = port_cnt_res.scalar() or 0

            proc_cnt_res = await db.execute(
                select(func.count(AgentInventoryProcess.id)).where(
                    AgentInventoryProcess.agent_id == aid,
                    AgentInventoryProcess.tenant_id == tenant_id,
                )
            )
            proc_count = proc_cnt_res.scalar() or 0

            # Determine latest updated timestamp
            last_updated: datetime | None = None
            if hw and hw.updated_at:
                last_updated = hw.updated_at
            if os_info and os_info.updated_at:
                if not last_updated or os_info.updated_at > last_updated:
                    last_updated = os_info.updated_at

            summaries.append(
                AgentInventorySummary(
                    agent_id=aid,
                    tenant_id=tenant_id,
                    hostname=os_info.hostname if os_info else None,
                    os_name=os_info.os_name if os_info else None,
                    os_version=os_info.os_version if os_info else None,
                    cpu_cores_logical=hw.cpu_cores_logical if hw else None,
                    ram_total_gb=hw.ram_total_gb if hw else None,
                    packages_count=pkg_count,
                    network_interfaces_count=net_count,
                    open_ports_count=port_count,
                    processes_count=proc_count,
                    last_updated=last_updated,
                )
            )

        return summaries

    @staticmethod
    async def get_hardware(
        db: AsyncSession, agent_id: str, tenant_id: str
    ) -> AgentInventoryHardware | None:
        """Retrieves hardware inventory for a specific agent."""
        res = await db.execute(
            select(AgentInventoryHardware).where(
                AgentInventoryHardware.agent_id == agent_id,
                AgentInventoryHardware.tenant_id == tenant_id,
            )
        )
        return res.scalar_one_or_none()

    @staticmethod
    async def get_os(
        db: AsyncSession, agent_id: str, tenant_id: str
    ) -> AgentInventoryOS | None:
        """Retrieves OS metadata inventory for a specific agent."""
        res = await db.execute(
            select(AgentInventoryOS).where(
                AgentInventoryOS.agent_id == agent_id,
                AgentInventoryOS.tenant_id == tenant_id,
            )
        )
        return res.scalar_one_or_none()

    @staticmethod
    async def get_packages(
        db: AsyncSession, agent_id: str, tenant_id: str
    ) -> list[AgentInventoryPackage]:
        """Retrieves all installed packages for a specific agent."""
        res = await db.execute(
            select(AgentInventoryPackage)
            .where(
                AgentInventoryPackage.agent_id == agent_id,
                AgentInventoryPackage.tenant_id == tenant_id,
            )
            .order_by(AgentInventoryPackage.name)
        )
        return list(res.scalars().all())

    @staticmethod
    async def get_network(
        db: AsyncSession, agent_id: str, tenant_id: str
    ) -> list[AgentInventoryNetwork]:
        """Retrieves all network interfaces for a specific agent."""
        res = await db.execute(
            select(AgentInventoryNetwork)
            .where(
                AgentInventoryNetwork.agent_id == agent_id,
                AgentInventoryNetwork.tenant_id == tenant_id,
            )
            .order_by(AgentInventoryNetwork.interface_name)
        )
        return list(res.scalars().all())

    @staticmethod
    async def get_ports(
        db: AsyncSession, agent_id: str, tenant_id: str
    ) -> list[AgentInventoryPort]:
        """Retrieves all open listening ports and active sockets for a specific agent."""
        res = await db.execute(
            select(AgentInventoryPort)
            .where(
                AgentInventoryPort.agent_id == agent_id,
                AgentInventoryPort.tenant_id == tenant_id,
            )
            .order_by(AgentInventoryPort.local_port)
        )
        return list(res.scalars().all())

    @staticmethod
    async def get_processes(
        db: AsyncSession, agent_id: str, tenant_id: str
    ) -> list[AgentInventoryProcess]:
        """Retrieves all running processes for a specific agent."""
        res = await db.execute(
            select(AgentInventoryProcess)
            .where(
                AgentInventoryProcess.agent_id == agent_id,
                AgentInventoryProcess.tenant_id == tenant_id,
            )
            .order_by(AgentInventoryProcess.pid)
        )
        return list(res.scalars().all())

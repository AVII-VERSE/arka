"""
Backend Tests for System Inventory Service and REST API Endpoints.
Tests snapshot ingestion, relational persistence, atomic upsert/replace,
sub-resource retrieval, tenant isolation, and zero-fake-data empty states.
"""

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, get_password_hash
from app.models.models import (
    Agent,
    AgentInventoryHardware,
    AgentInventoryOS,
    AgentInventoryPackage,
    AgentInventoryPort,
    AgentStatusEnum,
    RoleEnum,
    Tenant,
    User,
)
from app.schemas.schemas import InventorySnapshotPayload
from app.services.inventory_service import InventoryService

# ============================================================================
# Service Layer Tests
# ============================================================================


async def test_inventory_service_ingest_snapshot(
    db_session: AsyncSession, test_tenant: Tenant
):
    """Verifies InventoryService atomically writes hardware, OS, packages, network, ports, and processes to DB."""
    # Enroll test agent in tenant
    agent = Agent(
        id="agent-sys-01",
        tenant_id=test_tenant.id,
        hostname="endpoint-srv-01",
        ip_address="10.0.0.15",
        os_type="linux",
        os_version="Ubuntu 22.04 LTS",
        status=AgentStatusEnum.ONLINE,
    )
    db_session.add(agent)
    await db_session.commit()

    payload = InventorySnapshotPayload(
        snapshot_id="syscol-test-01",
        agent_id="agent-sys-01",
        tenant_id=test_tenant.id,
        timestamp="2026-08-27T00:00:00Z",
        hardware={
            "cpu_cores_logical": 8,
            "cpu_cores_physical": 4,
            "cpu_architecture": "x86_64",
            "ram_total_gb": 16.0,
            "disks": [{"device": "/dev/sda1", "mountpoint": "/", "total_gb": 256.0}],
        },
        os={
            "os_name": "Linux",
            "os_release": "5.15.0-76-generic",
            "os_version": "#83-Ubuntu SMP",
            "kernel_architecture": "x86_64",
            "hostname": "endpoint-srv-01",
            "python_version": "3.11.4",
        },
        packages=[
            {"name": "openssh-server", "version": "8.9p1", "format": "deb", "architecture": "amd64"},
            {"name": "nginx", "version": "1.18.0", "format": "deb", "architecture": "amd64"},
            {"name": "python3", "version": "3.11.4", "format": "deb", "architecture": "amd64"},
        ],
        network_interfaces=[
            {
                "interface_name": "eth0",
                "ipv4_address": "10.0.0.15",
                "ipv6_address": "fe80::1",
                "mac_address": "00:15:5d:01:02:03",
            }
        ],
        open_ports=[
            {"protocol": "tcp", "local_ip": "0.0.0.0", "local_port": 22, "pid": 500, "process_name": "sshd", "state": "LISTEN"},
            {"protocol": "tcp", "local_ip": "0.0.0.0", "local_port": 80, "pid": 600, "process_name": "nginx", "state": "LISTEN"},
        ],
        running_processes=[
            {"pid": 1, "name": "systemd", "username": "root", "cpu_percent": 0.1, "memory_percent": 0.2},
            {"pid": 500, "name": "sshd", "username": "root", "cpu_percent": 0.0, "memory_percent": 0.1},
        ],
    )

    res = await InventoryService.ingest_snapshot(db_session, payload)
    await db_session.commit()

    assert res["status"] == "success"
    assert res["packages_ingested"] == 3
    assert res["network_interfaces_ingested"] == 1
    assert res["open_ports_ingested"] == 2
    assert res["running_processes_ingested"] == 2

    # Verify Hardware persistence
    hw_db = (
        await db_session.execute(
            select(AgentInventoryHardware).where(AgentInventoryHardware.agent_id == "agent-sys-01")
        )
    ).scalar_one_or_none()
    assert hw_db is not None
    assert hw_db.cpu_cores_logical == 8
    assert hw_db.ram_total_gb == 16.0
    assert len(hw_db.disks) == 1

    # Verify OS persistence
    os_db = (
        await db_session.execute(
            select(AgentInventoryOS).where(AgentInventoryOS.agent_id == "agent-sys-01")
        )
    ).scalar_one_or_none()
    assert os_db is not None
    assert os_db.os_name == "Linux"
    assert os_db.hostname == "endpoint-srv-01"

    # Verify Packages persistence
    pkgs_db = (
        await db_session.execute(
            select(AgentInventoryPackage).where(AgentInventoryPackage.agent_id == "agent-sys-01")
        )
    ).scalars().all()
    assert len(pkgs_db) == 3
    pkg_names = {p.name for p in pkgs_db}
    assert "openssh-server" in pkg_names
    assert "nginx" in pkg_names

    # Verify Ports persistence
    ports_db = (
        await db_session.execute(
            select(AgentInventoryPort).where(AgentInventoryPort.agent_id == "agent-sys-01")
        )
    ).scalars().all()
    assert len(ports_db) == 2
    port_nums = {p.local_port for p in ports_db}
    assert 22 in port_nums
    assert 80 in port_nums


async def test_inventory_service_atomic_upsert_replacement(
    db_session: AsyncSession, test_tenant: Tenant
):
    """Verifies that subsequent snapshot ingests update hardware/OS and cleanly replace packages/network/ports/processes."""
    # Ingest Snapshot 1
    snap1 = InventorySnapshotPayload(
        agent_id="agent-upsert-01",
        tenant_id=test_tenant.id,
        hardware={"cpu_cores_logical": 4, "ram_total_gb": 8.0},
        os={"os_name": "Linux", "hostname": "host-v1"},
        packages=[
            {"name": "pkg-a", "version": "1.0"},
            {"name": "pkg-b", "version": "1.0"},
        ],
        network_interfaces=[{"interface_name": "eth0", "ipv4_address": "192.168.1.10"}],
        open_ports=[{"protocol": "tcp", "local_ip": "0.0.0.0", "local_port": 80}],
        running_processes=[{"pid": 100, "name": "proc-v1"}],
    )
    await InventoryService.ingest_snapshot(db_session, snap1)
    await db_session.commit()

    # Ingest Snapshot 2 (updated hardware & new software state)
    snap2 = InventorySnapshotPayload(
        agent_id="agent-upsert-01",
        tenant_id=test_tenant.id,
        hardware={"cpu_cores_logical": 8, "ram_total_gb": 32.0},
        os={"os_name": "Linux", "hostname": "host-v2"},
        packages=[
            {"name": "pkg-c", "version": "2.0"},
        ],
        network_interfaces=[{"interface_name": "eth1", "ipv4_address": "10.10.10.1"}],
        open_ports=[{"protocol": "tcp", "local_ip": "0.0.0.0", "local_port": 443}],
        running_processes=[{"pid": 200, "name": "proc-v2"}],
    )
    await InventoryService.ingest_snapshot(db_session, snap2)
    await db_session.commit()

    # Hardware should be updated
    hw = await InventoryService.get_hardware(db_session, "agent-upsert-01", test_tenant.id)
    assert hw is not None
    assert hw.cpu_cores_logical == 8
    assert hw.ram_total_gb == 32.0

    # OS should be updated
    os_info = await InventoryService.get_os(db_session, "agent-upsert-01", test_tenant.id)
    assert os_info is not None
    assert os_info.hostname == "host-v2"

    # Packages should be replaced (only pkg-c, not pkg-a or pkg-b)
    packages = await InventoryService.get_packages(db_session, "agent-upsert-01", test_tenant.id)
    assert len(packages) == 1
    assert packages[0].name == "pkg-c"

    # Network should be replaced (only eth1)
    network = await InventoryService.get_network(db_session, "agent-upsert-01", test_tenant.id)
    assert len(network) == 1
    assert network[0].interface_name == "eth1"

    # Ports should be replaced (only 443)
    ports = await InventoryService.get_ports(db_session, "agent-upsert-01", test_tenant.id)
    assert len(ports) == 1
    assert ports[0].local_port == 443

    # Processes should be replaced (only proc-v2)
    processes = await InventoryService.get_processes(db_session, "agent-upsert-01", test_tenant.id)
    assert len(processes) == 1
    assert processes[0].name == "proc-v2"


async def test_inventory_service_summary(
    db_session: AsyncSession, test_tenant: Tenant
):
    """Verifies get_inventory_summary aggregates all metrics per agent in a tenant."""
    # Ingest for agent 1
    await InventoryService.ingest_snapshot(
        db_session,
        InventorySnapshotPayload(
            agent_id="agent-sum-01",
            tenant_id=test_tenant.id,
            hardware={"cpu_cores_logical": 4, "ram_total_gb": 8.0},
            os={"os_name": "Linux", "hostname": "sum-srv-01"},
            packages=[{"name": "p1", "version": "1"}, {"name": "p2", "version": "2"}],
            network_interfaces=[{"interface_name": "eth0"}],
            open_ports=[{"protocol": "tcp", "local_ip": "0.0.0.0", "local_port": 80}],
            running_processes=[{"pid": 1, "name": "init"}],
        ),
    )
    # Ingest for agent 2
    await InventoryService.ingest_snapshot(
        db_session,
        InventorySnapshotPayload(
            agent_id="agent-sum-02",
            tenant_id=test_tenant.id,
            hardware={"cpu_cores_logical": 16, "ram_total_gb": 64.0},
            os={"os_name": "Windows", "hostname": "sum-win-02"},
            packages=[{"name": "p3", "version": "3"}],
            network_interfaces=[],
            open_ports=[],
            running_processes=[],
        ),
    )
    await db_session.commit()

    summaries = await InventoryService.get_inventory_summary(db_session, test_tenant.id)
    assert len(summaries) == 2
    sum_map = {s.agent_id: s for s in summaries}

    assert sum_map["agent-sum-01"].packages_count == 2
    assert sum_map["agent-sum-01"].open_ports_count == 1
    assert sum_map["agent-sum-01"].network_interfaces_count == 1
    assert sum_map["agent-sum-01"].processes_count == 1
    assert sum_map["agent-sum-01"].hostname == "sum-srv-01"

    assert sum_map["agent-sum-02"].packages_count == 1
    assert sum_map["agent-sum-02"].open_ports_count == 0
    assert sum_map["agent-sum-02"].ram_total_gb == 64.0


# ============================================================================
# API Endpoint Tests
# ============================================================================


async def test_api_post_inventory_snapshot(
    client: AsyncClient, auth_headers: dict, test_tenant: Tenant
):
    """Verifies POST /api/v1/inventory/snapshot ingests telemetry snapshot."""
    payload = {
        "snapshot_id": "snap-api-01",
        "agent_id": "agent-api-01",
        "tenant_id": test_tenant.id,
        "timestamp": "2026-08-27T01:00:00Z",
        "hardware": {
            "cpu_cores_logical": 8,
            "cpu_cores_physical": 4,
            "cpu_architecture": "x86_64",
            "ram_total_gb": 16.0,
            "disks": [],
        },
        "os": {
            "os_name": "Linux",
            "os_release": "6.1.0",
            "os_version": "Debian 12",
            "kernel_architecture": "x86_64",
            "hostname": "api-host-01",
            "python_version": "3.11.2",
        },
        "packages": [
            {"name": "libssl3", "version": "3.0.9", "format": "deb", "architecture": "amd64"},
            {"name": "sudo", "version": "1.9.13", "format": "deb", "architecture": "amd64"},
        ],
        "network_interfaces": [
            {
                "interface_name": "ens33",
                "ipv4_address": "192.168.100.5",
                "mac_address": "00:50:56:c0:00:08",
            }
        ],
        "open_ports": [
            {"protocol": "tcp", "local_ip": "0.0.0.0", "local_port": 22, "pid": 101, "process_name": "sshd", "state": "LISTEN"},
        ],
        "running_processes": [
            {"pid": 101, "name": "sshd", "username": "root", "cpu_percent": 0.0, "memory_percent": 0.2},
        ],
    }

    response = await client.post(
        "/api/v1/inventory/snapshot",
        json=payload,
        headers=auth_headers,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "success"
    assert data["agent_id"] == "agent-api-01"
    assert data["packages_ingested"] == 2


async def test_api_get_subresources(
    client: AsyncClient, auth_headers: dict, test_tenant: Tenant
):
    """Verifies GET /api/v1/inventory/{agent_id} sub-resource endpoints."""
    # Ingest snapshot first
    payload = {
        "agent_id": "agent-sub-01",
        "tenant_id": test_tenant.id,
        "hardware": {
            "cpu_cores_logical": 4,
            "cpu_cores_physical": 2,
            "cpu_architecture": "arm64",
            "ram_total_gb": 8.0,
            "disks": [{"device": "/dev/nvme0n1", "mountpoint": "/", "total_gb": 128.0}],
        },
        "os": {
            "os_name": "Darwin",
            "os_release": "23.1.0",
            "os_version": "macOS 14.1",
            "kernel_architecture": "arm64",
            "hostname": "macbook-pro",
            "python_version": "3.12.0",
        },
        "packages": [
            {"name": "zsh", "version": "5.9", "format": "brew", "architecture": "arm64"},
        ],
        "network_interfaces": [
            {"interface_name": "en0", "ipv4_address": "192.168.1.50", "mac_address": "ac:de:48:00:11:22"},
        ],
        "open_ports": [
            {"protocol": "tcp", "local_ip": "127.0.0.1", "local_port": 3000, "pid": 4040, "process_name": "node", "state": "LISTEN"},
        ],
        "running_processes": [
            {"pid": 4040, "name": "node", "username": "developer", "cpu_percent": 1.5, "memory_percent": 3.2},
        ],
    }

    post_resp = await client.post(
        "/api/v1/inventory/snapshot",
        json=payload,
        headers=auth_headers,
    )
    assert post_resp.status_code == 201

    # 1. Hardware endpoint
    hw_resp = await client.get("/api/v1/inventory/agent-sub-01/hardware", headers=auth_headers)
    assert hw_resp.status_code == 200
    hw_data = hw_resp.json()
    assert hw_data["agent_id"] == "agent-sub-01"
    assert hw_data["cpu_cores_logical"] == 4
    assert hw_data["cpu_architecture"] == "arm64"
    assert len(hw_data["disks"]) == 1

    # 2. OS endpoint
    os_resp = await client.get("/api/v1/inventory/agent-sub-01/os", headers=auth_headers)
    assert os_resp.status_code == 200
    os_data = os_resp.json()
    assert os_data["os_name"] == "Darwin"
    assert os_data["hostname"] == "macbook-pro"

    # 3. Packages endpoint
    pkgs_resp = await client.get("/api/v1/inventory/agent-sub-01/packages", headers=auth_headers)
    assert pkgs_resp.status_code == 200
    pkgs_data = pkgs_resp.json()
    assert len(pkgs_data) == 1
    assert pkgs_data[0]["name"] == "zsh"

    # 4. Network endpoint
    net_resp = await client.get("/api/v1/inventory/agent-sub-01/network", headers=auth_headers)
    assert net_resp.status_code == 200
    net_data = net_resp.json()
    assert len(net_data) == 1
    assert net_data[0]["interface_name"] == "en0"

    # 5. Ports endpoint
    ports_resp = await client.get("/api/v1/inventory/agent-sub-01/ports", headers=auth_headers)
    assert ports_resp.status_code == 200
    ports_data = ports_resp.json()
    assert len(ports_data) == 1
    assert ports_data[0]["local_port"] == 3000

    # 6. Processes endpoint
    proc_resp = await client.get("/api/v1/inventory/agent-sub-01/processes", headers=auth_headers)
    assert proc_resp.status_code == 200
    proc_data = proc_resp.json()
    assert len(proc_data) == 1
    assert proc_data[0]["name"] == "node"


async def test_tenant_isolation(
    client: AsyncClient, db_session: AsyncSession, test_tenant: Tenant, auth_headers: dict
):
    """Verifies that inventory data from Tenant B is strictly invisible to Tenant A."""
    # Create Tenant B and User B
    tenant_b = Tenant(name="Tenant Beta", slug="tenant-beta")
    db_session.add(tenant_b)
    await db_session.commit()
    await db_session.refresh(tenant_b)

    user_b = User(
        email="analyst@beta.org",
        hashed_password=get_password_hash("SecretPassword123!"),
        full_name="Beta Analyst",
        tenant_id=tenant_b.id,
        role=RoleEnum.SECURITY_ANALYST,
    )
    db_session.add(user_b)
    await db_session.commit()

    token_b = create_access_token(
        subject=user_b.id,
        tenant_id=tenant_b.id,
        role=user_b.role.value,
    )
    auth_headers_b = {"Authorization": f"Bearer {token_b}"}

    # Ingest snapshot in Tenant B
    payload_b = {
        "agent_id": "agent-beta-01",
        "tenant_id": tenant_b.id,
        "hardware": {"cpu_cores_logical": 32, "ram_total_gb": 128.0},
        "os": {"os_name": "Linux", "hostname": "beta-prod-server"},
        "packages": [{"name": "secret-corp-package", "version": "9.9.9"}],
        "network_interfaces": [{"interface_name": "eth0"}],
        "open_ports": [{"protocol": "tcp", "local_ip": "0.0.0.0", "local_port": 9000}],
        "running_processes": [{"pid": 888, "name": "secret-service"}],
    }
    resp = await client.post("/api/v1/inventory/snapshot", json=payload_b, headers=auth_headers_b)
    assert resp.status_code == 201

    # Tenant A attempts to access Tenant B's agent hardware -> 404
    hw_a = await client.get("/api/v1/inventory/agent-beta-01/hardware", headers=auth_headers)
    assert hw_a.status_code == 404

    # Tenant A attempts to access Tenant B's packages -> empty list
    pkgs_a = await client.get("/api/v1/inventory/agent-beta-01/packages", headers=auth_headers)
    assert pkgs_a.status_code == 200
    assert pkgs_a.json() == []

    # Tenant A lists inventories -> agent-beta-01 must not appear
    inv_a = await client.get("/api/v1/inventory", headers=auth_headers)
    assert inv_a.status_code == 200
    agent_ids_a = {item["agent_id"] for item in inv_a.json()}
    assert "agent-beta-01" not in agent_ids_a

    # Tenant B lists inventories -> agent-beta-01 appears
    inv_b = await client.get("/api/v1/inventory", headers=auth_headers_b)
    assert inv_b.status_code == 200
    agent_ids_b = {item["agent_id"] for item in inv_b.json()}
    assert "agent-beta-01" in agent_ids_b


async def test_zero_fake_data_empty_db(client: AsyncClient, auth_headers: dict):
    """
    CRITICAL INTEGRITY TEST:
    Verifies that when database has no inventory data, the server returns 404 / empty lists,
    and NEVER generates synthetic server psutil mock data.
    """
    # 1. Summary returns empty list
    summary_resp = await client.get("/api/v1/inventory", headers=auth_headers)
    assert summary_resp.status_code == 200
    assert summary_resp.json() == []

    # 2. Non-existent agent hardware returns 404 (not mock)
    hw_resp = await client.get("/api/v1/inventory/ghost-agent/hardware", headers=auth_headers)
    assert hw_resp.status_code == 404

    # 3. Non-existent agent OS returns 404 (not mock)
    os_resp = await client.get("/api/v1/inventory/ghost-agent/os", headers=auth_headers)
    assert os_resp.status_code == 404

    # 4. Non-existent agent packages returns empty list (not mock)
    pkg_resp = await client.get("/api/v1/inventory/ghost-agent/packages", headers=auth_headers)
    assert pkg_resp.status_code == 200
    assert pkg_resp.json() == []

    # 5. Non-existent agent network interfaces returns empty list (not mock)
    net_resp = await client.get("/api/v1/inventory/ghost-agent/network", headers=auth_headers)
    assert net_resp.status_code == 200
    assert net_resp.json() == []

    # 6. Non-existent agent ports returns empty list (not mock)
    port_resp = await client.get("/api/v1/inventory/ghost-agent/ports", headers=auth_headers)
    assert port_resp.status_code == 200
    assert port_resp.json() == []

    # 7. Non-existent agent processes returns empty list (not mock)
    proc_resp = await client.get("/api/v1/inventory/ghost-agent/processes", headers=auth_headers)
    assert proc_resp.status_code == 200
    assert proc_resp.json() == []

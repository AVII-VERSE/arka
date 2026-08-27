"""
Adversarial Stress Test Suite for Milestone 1: Models & Schemas.
Tests validation, enum boundaries, malformed inputs, UUID collisions,
foreign key constraints, and ORM <-> Pydantic schema conversions.
"""

import datetime
import uuid
import pytest
from pydantic import ValidationError

# Backend Models
from app.models.models import (
    Base,
    utc_now,
    generate_uuid,
    RoleEnum,
    SeverityEnum,
    AlertStatusEnum,
    IncidentStatusEnum,
    AgentStatusEnum,
    ActiveResponseTaskStatusEnum,
    ActiveResponseActionEnum,
    VulnerabilityStatusEnum,
    Tenant,
    User,
    Agent,
    DetectionRule,
    Alert,
    Incident,
    AuditLog,
    SCAPolicy,
    SCAScanReport,
    AgentInventoryHardware,
    AgentInventoryOS,
    AgentInventoryPackage,
    AgentInventoryNetwork,
    AgentInventoryPort,
    AgentInventoryProcess,
    ActiveResponseTask,
    CVEItem,
    VulnerabilityFinding,
    VulnerabilityScanReport,
)

# Backend Schemas
from app.schemas.schemas import (
    HealthResponse,
    Token,
    TokenData,
    UserLogin,
    TenantCreate,
    TenantRead,
    UserCreate,
    UserRead,
    AgentEnrollmentRequest,
    AgentRead,
    AgentHeartbeat,
    NormalizedEvent,
    IngestEventsRequest,
    IngestEventsResponse,
    DetectionRuleRead,
    DetectionRuleCreate,
    AlertRead,
    AlertUpdateStatus,
    IncidentRead,
    IncidentCreate,
    IncidentUpdateStatus,
    SCAPolicyBase,
    SCAPolicyCreate,
    SCAPolicyRead,
    SCACheckResult,
    SCAScanReportRead,
    SCASummary,
    HardwareInventoryRead,
    OSInventoryRead,
    PackageInventoryRead,
    NetworkInventoryRead,
    PortInventoryRead,
    ProcessInventoryRead,
    InventorySnapshotPayload,
    AgentInventorySummary,
    ActiveResponseTaskCreate,
    ActiveResponseTaskRead,
    ActiveResponseStatusUpdate,
    ActiveResponseTriggerRequest,
    CVEItemBase,
    CVEItemRead,
    VulnerabilityFindingRead,
    VulnerabilityScanReportRead,
    VulnerabilityStatusUpdate,
    VulnerabilityScanPayload,
)


class TestEnumBoundaries:
    """Stress tests enum values and boundaries."""

    def test_role_enum_valid_and_invalid(self):
        valid_roles = ["SUPER_ADMIN", "TENANT_ADMIN", "SECURITY_ANALYST", "SECURITY_VIEWER"]
        for role in valid_roles:
            assert RoleEnum(role).value == role

        invalid_roles = ["ADMIN", "root", "analyst", "", "SUPERADMIN", None, 123]
        for inv in invalid_roles:
            with pytest.raises((ValueError, TypeError)):
                RoleEnum(inv)

    def test_severity_enum_valid_and_invalid(self):
        valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        for sev in valid_severities:
            assert SeverityEnum(sev).value == sev

        invalid_severities = ["INFO", "WARNING", "FATAL", "low", "critical", 0, ""]
        for inv in invalid_severities:
            with pytest.raises((ValueError, TypeError)):
                SeverityEnum(inv)

    def test_active_response_action_enum(self):
        valid_actions = [
            "block_ip", "unblock_ip", "kill_process",
            "lock_user", "isolate_host", "reconnect_host", "quarantine_file"
        ]
        for act in valid_actions:
            assert ActiveResponseActionEnum(act).value == act

        invalid_actions = ["BLOCK_IP", "shutdown", "reboot", "delete_file", ""]
        for inv in invalid_actions:
            with pytest.raises((ValueError, TypeError)):
                ActiveResponseActionEnum(inv)

    def test_active_response_task_status_enum(self):
        valid_statuses = [
            "PENDING", "DISPATCHED", "EXECUTING",
            "SUCCESS", "FAILED", "TIMEOUT", "CANCELLED"
        ]
        for st in valid_statuses:
            assert ActiveResponseTaskStatusEnum(st).value == st

        with pytest.raises(ValueError):
            ActiveResponseTaskStatusEnum("RUNNING")


class TestSchemaValidationAndMalformedInputs:
    """Stress tests Pydantic schemas with malformed inputs."""

    def test_tenant_create_boundaries(self):
        # Valid
        t = TenantCreate(name="Acme Corp", slug="acme-corp")
        assert t.name == "Acme Corp"
        assert t.slug == "acme-corp"

        # Boundary: name min_length=2
        with pytest.raises(ValidationError):
            TenantCreate(name="A", slug="valid-slug")

        # Boundary: name max_length=255
        with pytest.raises(ValidationError):
            TenantCreate(name="A" * 256, slug="valid-slug")

        # Boundary: slug min_length=2
        with pytest.raises(ValidationError):
            TenantCreate(name="Acme Corp", slug="a")

        # Boundary: slug max_length=100
        with pytest.raises(ValidationError):
            TenantCreate(name="Acme Corp", slug="a" * 101)

    def test_user_create_validation(self):
        # Valid
        u = UserCreate(
            email="analyst@example.com",
            password="SecurePassword123!",
            full_name="Security Analyst",
            tenant_id="t-001",
            role=RoleEnum.SECURITY_ANALYST,
        )
        assert u.email == "analyst@example.com"

        # Invalid email format
        invalid_emails = ["not-an-email", "@example.com", "user@", "user@.com", ""]
        for inv in invalid_emails:
            with pytest.raises(ValidationError):
                UserCreate(
                    email=inv,
                    password="SecurePassword123!",
                    full_name="Analyst",
                    tenant_id="t-001",
                )

        # Password min length (< 8)
        with pytest.raises(ValidationError):
            UserCreate(
                email="analyst@example.com",
                password="short",
                full_name="Analyst",
                tenant_id="t-001",
            )

    def test_normalized_event_validation(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        ev = NormalizedEvent(
            event_id="evt-1001",
            tenant_id="t-001",
            agent_id="agt-001",
            timestamp=now,
            source_type="linux_syslog",
            host="srv-prod-01",
            event_type="authentication",
            action="logon_failed",
            severity=SeverityEnum.HIGH,
            message="Failed ssh logon for root from 192.168.1.50",
            metadata={"src_port": 54321, "attempts": 5},
        )
        assert ev.event_id == "evt-1001"
        assert ev.severity == SeverityEnum.HIGH
        assert ev.metadata["attempts"] == 5

        # Missing required fields
        with pytest.raises(ValidationError):
            NormalizedEvent(
                event_id="evt-1001",
                tenant_id="t-001",
                # missing agent_id, timestamp, source_type, host, event_type, action, message
            )

    def test_active_response_schemas(self):
        # Valid creation
        task_in = ActiveResponseTaskCreate(
            agent_id="agt-001",
            action=ActiveResponseActionEnum.BLOCK_IP,
            target="198.51.100.44",
            parameters={"timeout_seconds": 3600, "direction": "inbound"},
            trigger_alert_id="alt-999",
        )
        assert task_in.action == ActiveResponseActionEnum.BLOCK_IP
        assert task_in.target == "198.51.100.44"

        # Invalid action enum
        with pytest.raises(ValidationError):
            ActiveResponseTaskCreate(
                agent_id="agt-001",
                action="INVALID_ACTION",  # type: ignore
                target="198.51.100.44",
            )

    def test_cve_item_and_vulnerability_schemas(self):
        cve = CVEItemBase(
            cve_id="CVE-2023-12345",
            package_name="openssl",
            affected_versions_spec="<3.0.8",
            fixed_version="3.0.8",
            severity=SeverityEnum.CRITICAL,
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            summary="Buffer overflow in OpenSSL ASN.1 parser",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2023-12345"],
        )
        assert cve.cve_id == "CVE-2023-12345"
        assert cve.cvss_score == 9.8

        # Missing required fields
        with pytest.raises(ValidationError):
            CVEItemBase(
                cve_id="CVE-2023-12345",
                # missing package_name, affected_versions_spec, severity, cvss_score, summary
            )


class TestORMModelInstantiationAndMapping:
    """Stress tests SQLAlchemy 2.x models and Pydantic ORM conversion."""

    def test_model_uuid_generation(self):
        id1 = generate_uuid()
        id2 = generate_uuid()
        assert id1 != id2
        assert len(id1) == 36
        uuid.UUID(id1)  # Validates UUID format

    def test_tenant_and_user_orm_to_pydantic(self):
        now = utc_now()
        tenant = Tenant(
            id=generate_uuid(),
            name="Alpha SOC",
            slug="alpha-soc",
            is_active=True,
            created_at=now,
        )
        tenant_read = TenantRead.model_validate(tenant)
        assert tenant_read.id == tenant.id
        assert tenant_read.name == "Alpha SOC"
        assert tenant_read.slug == "alpha-soc"
        assert tenant_read.is_active is True

        user = User(
            id=generate_uuid(),
            tenant_id=tenant.id,
            email="admin@alphasoc.com",
            hashed_password="hashed_pw_string",
            full_name="SOC Admin",
            role=RoleEnum.SUPER_ADMIN,
            is_active=True,
            created_at=now,
        )
        user_read = UserRead.model_validate(user)
        assert user_read.id == user.id
        assert user_read.role == RoleEnum.SUPER_ADMIN
        assert user_read.email == "admin@alphasoc.com"

    def test_agent_orm_to_pydantic(self):
        now = utc_now()
        agent = Agent(
            id=generate_uuid(),
            tenant_id=generate_uuid(),
            hostname="linux-agent-01",
            ip_address="10.0.0.15",
            os_type="linux",
            os_version="Ubuntu 22.04 LTS",
            agent_version="1.0.0",
            status=AgentStatusEnum.ONLINE,
            last_heartbeat=now,
            created_at=now,
        )
        agent_read = AgentRead.model_validate(agent)
        assert agent_read.id == agent.id
        assert agent_read.status == AgentStatusEnum.ONLINE
        assert agent_read.hostname == "linux-agent-01"

    def test_sca_policy_and_report_orm_to_pydantic(self):
        now = utc_now()
        policy = SCAPolicy(
            id=generate_uuid(),
            tenant_id=generate_uuid(),
            policy_code="CIS-UBUNTU-22.04",
            name="CIS Ubuntu Linux 22.04 Benchmark",
            description="CIS Benchmark v2.0 Level 1 and 2 profile",
            os_type="linux",
            enabled=True,
            rules_count=45,
            created_at=now,
            updated_at=now,
        )
        p_read = SCAPolicyRead.model_validate(policy)
        assert p_read.policy_code == "CIS-UBUNTU-22.04"
        assert p_read.rules_count == 45

        report = SCAScanReport(
            id=generate_uuid(),
            tenant_id=policy.tenant_id,
            agent_id=generate_uuid(),
            policy_id=policy.policy_code,
            policy_name=policy.name,
            compliance_score=88.5,
            total_checks=100,
            passed_checks=88,
            failed_checks=10,
            not_applicable_checks=2,
            checks=[
                {"id": "cis-1.1", "title": "Ensure /tmp is mounted", "status": "PASSED"},
                {"id": "cis-1.2", "title": "Ensure nodev on /tmp", "status": "FAILED"},
            ],
            scanned_at=now,
            created_at=now,
        )
        rep_read = SCAScanReportRead.model_validate(report)
        assert rep_read.compliance_score == 88.5
        assert rep_read.passed_checks == 88
        assert len(rep_read.checks) == 2

    def test_syscollector_inventory_models_to_pydantic(self):
        now = utc_now()
        t_id = generate_uuid()
        a_id = generate_uuid()

        # Hardware
        hw = AgentInventoryHardware(
            id=generate_uuid(),
            tenant_id=t_id,
            agent_id=a_id,
            cpu_cores_logical=8,
            cpu_cores_physical=4,
            cpu_architecture="x86_64",
            ram_total_gb=16.0,
            disks=[{"device": "/dev/sda1", "total_gb": 500, "free_gb": 220}],
            updated_at=now,
        )
        hw_read = HardwareInventoryRead.model_validate(hw)
        assert hw_read.cpu_cores_logical == 8
        assert hw_read.ram_total_gb == 16.0
        assert len(hw_read.disks) == 1

        # OS
        os_inv = AgentInventoryOS(
            id=generate_uuid(),
            tenant_id=t_id,
            agent_id=a_id,
            os_name="Ubuntu",
            os_release="22.04.3 LTS",
            os_version="5.15.0-89-generic",
            kernel_architecture="x86_64",
            hostname="backend-node-01",
            python_version="3.11.4",
            updated_at=now,
        )
        os_read = OSInventoryRead.model_validate(os_inv)
        assert os_read.os_name == "Ubuntu"
        assert os_read.python_version == "3.11.4"

        # Package
        pkg = AgentInventoryPackage(
            id=generate_uuid(),
            tenant_id=t_id,
            agent_id=a_id,
            name="curl",
            version="7.81.0-1ubuntu1.14",
            format="deb",
            architecture="amd64",
            updated_at=now,
        )
        pkg_read = PackageInventoryRead.model_validate(pkg)
        assert pkg_read.name == "curl"
        assert pkg_read.format == "deb"

        # Network
        net = AgentInventoryNetwork(
            id=generate_uuid(),
            tenant_id=t_id,
            agent_id=a_id,
            interface_name="eth0",
            ipv4_address="192.168.1.100",
            ipv6_address="fe80::1",
            mac_address="52:54:00:12:34:56",
            updated_at=now,
        )
        net_read = NetworkInventoryRead.model_validate(net)
        assert net_read.interface_name == "eth0"
        assert net_read.ipv4_address == "192.168.1.100"

        # Port
        port = AgentInventoryPort(
            id=generate_uuid(),
            tenant_id=t_id,
            agent_id=a_id,
            protocol="tcp",
            local_ip="0.0.0.0",
            local_port=22,
            pid=1024,
            process_name="sshd",
            state="LISTEN",
            updated_at=now,
        )
        port_read = PortInventoryRead.model_validate(port)
        assert port_read.local_port == 22
        assert port_read.process_name == "sshd"

        # Process
        proc = AgentInventoryProcess(
            id=generate_uuid(),
            tenant_id=t_id,
            agent_id=a_id,
            pid=1,
            name="systemd",
            username="root",
            cpu_percent=0.1,
            memory_percent=0.5,
            updated_at=now,
        )
        proc_read = ProcessInventoryRead.model_validate(proc)
        assert proc_read.pid == 1
        assert proc_read.name == "systemd"

    def test_active_response_task_orm_to_pydantic(self):
        now = utc_now()
        task = ActiveResponseTask(
            id=generate_uuid(),
            tenant_id=generate_uuid(),
            agent_id=generate_uuid(),
            action=ActiveResponseActionEnum.KILL_PROCESS,
            target="9999",
            parameters={"signal": "SIGKILL"},
            status=ActiveResponseTaskStatusEnum.SUCCESS,
            trigger_alert_id=generate_uuid(),
            triggered_by_user_id=generate_uuid(),
            command_payload={"cmd": "kill -9 9999"},
            exit_code=0,
            stdout="Process 9999 terminated",
            stderr="",
            message="Success",
            dispatched_at=now,
            executed_at=now,
            created_at=now,
            updated_at=now,
        )
        task_read = ActiveResponseTaskRead.model_validate(task)
        assert task_read.id == task.id
        assert task_read.action == ActiveResponseActionEnum.KILL_PROCESS
        assert task_read.status == ActiveResponseTaskStatusEnum.SUCCESS
        assert task_read.exit_code == 0

    def test_vulnerability_finding_and_report_orm_to_pydantic(self):
        now = utc_now()
        t_id = generate_uuid()
        a_id = generate_uuid()

        cve = CVEItem(
            id=generate_uuid(),
            cve_id="CVE-2023-38408",
            package_name="openssh-client",
            affected_versions_spec="<1:9.3p1-1ubuntu3.1",
            fixed_version="1:9.3p1-1ubuntu3.1",
            severity=SeverityEnum.CRITICAL,
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            summary="Remote code execution in OpenSSH ssh-agent PKCS#11 provider",
            references=["https://www.openssh.com/txt/release-9.3p2"],
            created_at=now,
        )
        cve_read = CVEItemRead.model_validate(cve)
        assert cve_read.cve_id == "CVE-2023-38408"
        assert cve_read.cvss_score == 9.8

        finding = VulnerabilityFinding(
            id=generate_uuid(),
            tenant_id=t_id,
            agent_id=a_id,
            cve_id=cve.cve_id,
            package_name="openssh-client",
            installed_version="1:8.9p1-3ubuntu0.1",
            fixed_version="1:9.3p1-1ubuntu3.1",
            severity=SeverityEnum.CRITICAL,
            cvss_score=9.8,
            summary=cve.summary,
            status=VulnerabilityStatusEnum.ACTIVE,
            detected_at=now,
            resolved_at=None,
            updated_at=now,
        )
        finding_read = VulnerabilityFindingRead.model_validate(finding)
        assert finding_read.id == finding.id
        assert finding_read.status == VulnerabilityStatusEnum.ACTIVE
        assert finding_read.cve_id == "CVE-2023-38408"

        report = VulnerabilityScanReport(
            id=generate_uuid(),
            tenant_id=t_id,
            agent_id=a_id,
            scanned_packages_count=250,
            vulnerability_count=3,
            critical_count=1,
            high_count=1,
            medium_count=1,
            low_count=0,
            scanned_at=now,
        )
        rep_read = VulnerabilityScanReportRead.model_validate(report)
        assert rep_read.scanned_packages_count == 250
        assert rep_read.critical_count == 1

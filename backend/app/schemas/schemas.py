"""
Pydantic v2 Schemas for Request & Response Data Structures.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models.models import (
    ActiveResponseActionEnum,
    ActiveResponseTaskStatusEnum,
    AgentStatusEnum,
    AlertStatusEnum,
    IncidentStatusEnum,
    RoleEnum,
    SeverityEnum,
    VulnerabilityStatusEnum,
)


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    environment: str
    timestamp: datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    sub: str | None = None
    tenant_id: str | None = None
    role: str | None = None


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TenantCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    slug: str = Field(..., min_length=2, max_length=100)


class TenantRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    slug: str
    is_active: bool
    created_at: datetime


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str
    tenant_id: str
    role: RoleEnum = RoleEnum.SECURITY_ANALYST


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    full_name: str
    tenant_id: str
    role: RoleEnum
    is_active: bool
    created_at: datetime


class AgentEnrollmentRequest(BaseModel):
    enrollment_token: str
    hostname: str
    ip_address: str
    os_type: str  # windows / linux
    os_version: str
    agent_version: str = "0.1.0"


class AgentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    hostname: str
    ip_address: str
    os_type: str
    os_version: str
    agent_version: str
    status: AgentStatusEnum
    last_heartbeat: datetime
    created_at: datetime


class AgentHeartbeat(BaseModel):
    agent_id: str
    metrics: dict[str, Any] | None = None


class NormalizedEvent(BaseModel):
    event_id: str
    tenant_id: str
    agent_id: str
    timestamp: datetime
    source_type: str  # windows_event_log / linux_syslog / application_log
    host: str
    source_ip: str | None = None
    destination_ip: str | None = None
    user: str | None = None
    event_type: str  # authentication / process / service / network
    action: str  # logon_failed / logon_success / process_created / service_installed
    severity: SeverityEnum = SeverityEnum.LOW
    message: str
    process: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    ingested_at: datetime | None = None


class IngestEventsRequest(BaseModel):
    events: list[NormalizedEvent]


class IngestEventsResponse(BaseModel):
    accepted: int
    failed: int
    errors: list[str] = Field(default_factory=list)


class DetectionRuleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    rule_code: str
    name: str
    description: str
    severity: SeverityEnum
    enabled: bool
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    conditions: dict[str, Any]
    threshold: dict[str, Any]
    created_at: datetime


class DetectionRuleCreate(BaseModel):
    rule_code: str
    name: str
    description: str
    severity: SeverityEnum
    enabled: bool = True
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    conditions: dict[str, Any]
    threshold: dict[str, Any]


class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    rule_id: str | None = None
    rule_code: str
    severity: SeverityEnum
    host: str
    user: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    reason: str
    mitre_technique_id: str
    status: AlertStatusEnum
    related_events: list[str]
    created_at: datetime
    updated_at: datetime


class AlertUpdateStatus(BaseModel):
    status: AlertStatusEnum


class IncidentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    title: str
    description: str
    severity: SeverityEnum
    status: IncidentStatusEnum
    assigned_analyst_id: str | None = None
    notes: list[dict[str, Any]]
    created_at: datetime
    updated_at: datetime


class IncidentCreate(BaseModel):
    title: str
    description: str
    severity: SeverityEnum
    assigned_analyst_id: str | None = None


class IncidentUpdateStatus(BaseModel):
    status: IncidentStatusEnum
    note: str | None = None


# --- R2: Security Configuration Assessment (SCA) Schemas ---


class SCAPolicyBase(BaseModel):
    policy_code: str
    name: str
    description: str
    os_type: str = "all"  # "linux", "windows", "all"
    enabled: bool = True
    rules_count: int = 0


class SCAPolicyCreate(SCAPolicyBase):
    pass


class SCAPolicyRead(SCAPolicyBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    created_at: datetime
    updated_at: datetime


class SCACheckResult(BaseModel):
    id: str | None = None
    check_id: str | None = None
    title: str
    status: str  # "PASSED", "FAILED", "NOT_APPLICABLE"
    description: str | None = None
    rationale: str | None = None
    remediation: str | None = None
    compliance: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)


class SCAScanReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    agent_id: str
    policy_id: str
    policy_name: str
    compliance_score: float
    total_checks: int
    passed_checks: int
    failed_checks: int
    not_applicable_checks: int
    checks: list[dict[str, Any]] = Field(default_factory=list)
    scanned_at: datetime
    created_at: datetime


class SCASummary(BaseModel):
    agent_id: str | None = None
    total_scans: int = 0
    average_compliance_score: float = 0.0
    passed_checks_total: int = 0
    failed_checks_total: int = 0
    not_applicable_checks_total: int = 0
    latest_reports: list[SCAScanReportRead] = Field(default_factory=list)


# --- R3: Syscollector System Inventory Schemas ---


class HardwareInventoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    agent_id: str
    cpu_cores_logical: int
    cpu_cores_physical: int
    cpu_architecture: str
    ram_total_gb: float
    disks: list[dict[str, Any]] = Field(default_factory=list)
    updated_at: datetime


class OSInventoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    agent_id: str
    os_name: str
    os_release: str
    os_version: str
    kernel_architecture: str
    hostname: str
    python_version: str
    updated_at: datetime


class PackageInventoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    agent_id: str
    name: str
    version: str
    format: str | None = None
    architecture: str | None = None
    updated_at: datetime


class NetworkInventoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    agent_id: str
    interface_name: str
    ipv4_address: str | None = None
    ipv6_address: str | None = None
    mac_address: str | None = None
    updated_at: datetime


class PortInventoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    agent_id: str
    protocol: str
    local_ip: str
    local_port: int
    pid: int | None = None
    process_name: str | None = None
    state: str | None = None
    updated_at: datetime


class ProcessInventoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    agent_id: str
    pid: int
    name: str
    username: str | None = None
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    updated_at: datetime


class InventorySnapshotPayload(BaseModel):
    snapshot_id: str | None = None
    agent_id: str
    tenant_id: str | None = None
    timestamp: datetime | str | None = None
    hardware: dict[str, Any] = Field(default_factory=dict)
    os: dict[str, Any] = Field(default_factory=dict)
    packages: list[dict[str, Any]] = Field(default_factory=list)
    network_interfaces: list[dict[str, Any]] = Field(default_factory=list)
    open_ports: list[dict[str, Any]] = Field(default_factory=list)
    running_processes: list[dict[str, Any]] = Field(default_factory=list)


class AgentInventorySummary(BaseModel):
    agent_id: str
    tenant_id: str
    hostname: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    cpu_cores_logical: int | None = None
    ram_total_gb: float | None = None
    packages_count: int = 0
    network_interfaces_count: int = 0
    open_ports_count: int = 0
    processes_count: int = 0
    last_updated: datetime | None = None


# --- R4: Automated Active Response Schemas ---


class ActiveResponseTaskCreate(BaseModel):
    agent_id: str
    action: ActiveResponseActionEnum
    target: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    trigger_alert_id: str | None = None
    triggered_by_user_id: str | None = None
    command_payload: dict[str, Any] = Field(default_factory=dict)


class ActiveResponseTaskRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    agent_id: str
    action: ActiveResponseActionEnum
    target: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    status: ActiveResponseTaskStatusEnum
    trigger_alert_id: str | None = None
    triggered_by_user_id: str | None = None
    command_payload: dict[str, Any] = Field(default_factory=dict)
    exit_code: int | None = None
    stdout: str | None = None
    stderr: str | None = None
    message: str | None = None
    dispatched_at: datetime | None = None
    executed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class ActiveResponseStatusUpdate(BaseModel):
    task_id: str
    status: ActiveResponseTaskStatusEnum
    exit_code: int | None = None
    stdout: str | None = None
    stderr: str | None = None
    message: str | None = None
    executed_at: datetime | None = None


class ActiveResponseTriggerRequest(BaseModel):
    agent_id: str
    action: ActiveResponseActionEnum
    target: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    alert_id: str | None = None


# --- R5: Vulnerability Detection & CVE Correlation Schemas ---


class CVEItemBase(BaseModel):
    cve_id: str
    package_name: str
    affected_versions_spec: str
    fixed_version: str | None = None
    severity: SeverityEnum
    cvss_score: float
    cvss_vector: str | None = None
    summary: str
    references: list[str] = Field(default_factory=list)


class CVEItemRead(CVEItemBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    created_at: datetime


class VulnerabilityFindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    agent_id: str
    cve_id: str
    package_name: str
    installed_version: str
    fixed_version: str | None = None
    severity: SeverityEnum
    cvss_score: float
    summary: str
    status: VulnerabilityStatusEnum
    detected_at: datetime
    resolved_at: datetime | None = None
    updated_at: datetime


class VulnerabilityScanReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    agent_id: str
    scanned_packages_count: int
    vulnerability_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    scanned_at: datetime


class VulnerabilityStatusUpdate(BaseModel):
    status: VulnerabilityStatusEnum
    note: str | None = None


class VulnerabilityScanPayload(BaseModel):
    agent_id: str
    tenant_id: str | None = None
    packages: list[dict[str, str]]

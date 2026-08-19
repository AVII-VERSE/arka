"""
Pydantic v2 Schemas for Request & Response Data Structures.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models.models import (
    AgentStatusEnum,
    AlertStatusEnum,
    IncidentStatusEnum,
    RoleEnum,
    SeverityEnum,
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

"""
Webhook Alerting & Incident Notification REST API Endpoints.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.models.models import User
from app.services.webhook_service import WebhookService

router = APIRouter()


class WebhookRegisterPayload(BaseModel):
    name: str
    target_url: str
    secret: str
    events: list[str]
    format: str = "json"


class AlertDispatchTestPayload(BaseModel):
    rule_id: str = "R1001"
    severity: str = "HIGH"
    title: str = "Test Alert Trigger"
    description: str = "Simulated threat alert dispatch"


@router.get("", response_model=list[dict[str, Any]])
async def list_webhooks(
    current_user: Annotated[User, Depends(get_current_user)],
) -> list[dict[str, Any]]:
    """Lists registered webhook destinations for the user's tenant."""
    return WebhookService.get_tenant_webhooks(current_user.tenant_id)


@router.post("", status_code=201)
async def register_webhook(
    payload: WebhookRegisterPayload,
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Registers a new webhook alerting destination."""
    return WebhookService.register_webhook(
        tenant_id=current_user.tenant_id,
        name=payload.name,
        target_url=payload.target_url,
        secret=payload.secret,
        events=payload.events,
        format_type=payload.format,
    )


@router.post("/test_dispatch", status_code=200)
async def test_webhook_dispatch(
    payload: AlertDispatchTestPayload,
    current_user: Annotated[User, Depends(get_current_user)],
) -> list[dict[str, Any]]:
    """Triggers a test alert notification to all tenant webhooks."""
    alert_dict = {
        "rule_id": payload.rule_id,
        "severity": payload.severity,
        "title": payload.title,
        "description": payload.description,
        "tenant_id": current_user.tenant_id,
    }
    return WebhookService.dispatch_alert(current_user.tenant_id, alert_dict)

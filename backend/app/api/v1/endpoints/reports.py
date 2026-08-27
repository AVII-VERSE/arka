"""
Automated SOC Compliance & Executive Security Reports REST API Endpoints.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.models.models import User
from app.services.report_generator_service import ExecutiveReportGenerator

router = APIRouter()


class GenerateReportRequest(BaseModel):
    title: str = "SOC Executive Security Briefing"


@router.get("", response_model=list[dict[str, Any]])
async def list_executive_reports(
    current_user: Annotated[User, Depends(get_current_user)],
) -> list[dict[str, Any]]:
    """Lists generated executive compliance reports for the tenant."""
    return ExecutiveReportGenerator.list_reports(current_user.tenant_id)


@router.post("/generate", status_code=201)
async def generate_executive_report(
    payload: GenerateReportRequest,
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Triggers generation of a new executive security report."""
    return ExecutiveReportGenerator.generate_report(current_user.tenant_id, title=payload.title)


@router.get("/{report_id}/download_html", response_class=Response)
async def download_report_html(
    report_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
) -> Response:
    """Downloads HTML executive report briefing."""
    reports = ExecutiveReportGenerator.list_reports(current_user.tenant_id)
    matching = [r for r in reports if r["report_id"] == report_id]
    html_str = matching[0]["html_content"] if matching else "<html><body>Report Not Found</body></html>"

    return Response(content=html_str, media_type="text/html")

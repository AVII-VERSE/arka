"""
Unit & Integration Tests for Automated SOC Compliance & Executive Security Report Generator.
"""

from app.services.report_generator_service import ExecutiveReportGenerator


def test_executive_report_generation():
    """Verifies generating structured executive security reports."""
    report = ExecutiveReportGenerator.generate_report(
        tenant_id="tenant-executive", title="Monthly CISO Briefing"
    )

    assert report["title"] == "Monthly CISO Briefing"
    assert report["tenant_id"] == "tenant-executive"
    assert report["security_score"] == 85.0
    assert report["metrics"]["active_agents"] >= 1
    assert "<html>" in report["html_content"]


def test_list_executive_reports():
    """Verifies listing generated reports for a tenant."""
    ExecutiveReportGenerator.generate_report(tenant_id="tenant-corp")
    reports = ExecutiveReportGenerator.list_reports("tenant-corp")

    assert len(reports) >= 1
    assert reports[0]["tenant_id"] == "tenant-corp"

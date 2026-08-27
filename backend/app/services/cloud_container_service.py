"""
ARKA Container & Cloud Security Analytics Engine.
Detects container escape risk vectors, privileged Pods, and cloud IAM security violations.
"""

from typing import Any

from arka_agent.collectors.cloud_container import CloudContainerCollector

_CLOUD_CONTAINER_REPORTS: list[dict[str, Any]] = []


class CloudContainerService:
    """Analyzes container security telemetry and cloud audit trail logs."""

    @staticmethod
    def analyze_container_telemetry(
        agent_id: str,
        tenant_id: str,
        containers: list[dict[str, Any]],
        cloud_events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Analyzes container configurations and cloud audit events for security risks."""
        flagged_containers = []
        for c in containers:
            risks = []
            is_high_risk = False

            if c.get("privileged", False):
                is_high_risk = True
                risks.append("Container executing in Privileged Mode (--privileged)")
            if c.get("host_network", False):
                is_high_risk = True
                risks.append("Container sharing host network namespace (hostNetwork=true)")
            if "SYS_ADMIN" in c.get("capabilities", []):
                is_high_risk = True
                risks.append("CAP_SYS_ADMIN Linux capability granted (container escape risk)")
            if c.get("run_as_root", False):
                risks.append("Container running process as root user (UID 0)")

            if risks:
                flagged_containers.append(
                    {
                        **c,
                        "is_high_risk": is_high_risk,
                        "risk_factors": risks,
                        "severity": "CRITICAL" if is_high_risk else "MEDIUM",
                    }
                )

        flagged_cloud_events = []
        for evt in cloud_events:
            cloud_risks = []
            if evt.get("policy_scope") == "PUBLIC_READ_WRITE":
                cloud_risks.append("Storage bucket policy set to Public Read/Write")
            if evt.get("event_name") == "AssumeRoleWithSAML" and "Admin" in evt.get(
                "user_identity", ""
            ):
                cloud_risks.append("Administrative IAM Role Assumed via SAML Federation")

            if cloud_risks:
                flagged_cloud_events.append(
                    {
                        **evt,
                        "cloud_risks": cloud_risks,
                        "severity": "HIGH",
                    }
                )

        report = {
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "total_containers": len(containers),
            "flagged_containers_count": len(flagged_containers),
            "total_cloud_events": len(cloud_events),
            "flagged_cloud_events_count": len(flagged_cloud_events),
            "flagged_containers": flagged_containers,
            "flagged_cloud_events": flagged_cloud_events,
        }

        _CLOUD_CONTAINER_REPORTS.append(report)
        return report

    @staticmethod
    def get_tenant_cloud_container_reports(tenant_id: str) -> list[dict[str, Any]]:
        """Retrieves cloud & container security audit history for a tenant."""
        records = [r for r in _CLOUD_CONTAINER_REPORTS if r.get("tenant_id") == tenant_id]
        if not records:
            # Generate initial audit snapshot report
            collector = CloudContainerCollector(agent_id="agent-dev-01", tenant_id=tenant_id)
            c_events = collector.get_container_events()
            cloud_events = collector.get_cloud_audit_events()
            return [
                CloudContainerService.analyze_container_telemetry(
                    "agent-dev-01", tenant_id, c_events, cloud_events
                )
            ]
        return records

"""
ARKA Threat Hunting Playbooks Engine.

Provides structured threat hunting workflows aligned with MITRE ATT&CK,
enabling SOC analysts to define hypotheses, execute investigation steps,
and track findings across ARKA telemetry.
"""

import copy
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

# ---------------------------------------------------------------------------
# Built-in Playbook Library — MITRE ATT&CK aligned threat hunting playbooks
# ---------------------------------------------------------------------------

BUILTIN_PLAYBOOKS: list[dict[str, Any]] = [
    {
        "playbook_id": "PB-LATERAL-MOVEMENT-001",
        "name": "Lateral Movement via Remote Services",
        "description": "Hunt for lateral movement using SMB, RDP, WinRM, or SSH pivoting across internal hosts.",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique_ids": ["T1021", "T1021.001", "T1021.002", "T1021.004"],
        "hypothesis": "Adversary is pivoting laterally through the network using remote service protocols after initial compromise.",
        "steps": [
            {
                "step_id": 1,
                "action": "Query events for internal-to-internal RDP/SSH connections from non-admin hosts",
                "query_hint": "event.type == 'network_connection' AND dst_port IN (3389, 22, 5985) AND src_ip STARTS_WITH '10.'",
                "expected_evidence": "Unusual internal host initiating remote connections to multiple targets",
            },
            {
                "step_id": 2,
                "action": "Correlate with authentication logs for pass-the-hash or ticket reuse patterns",
                "query_hint": "event.type == 'authentication' AND logon_type IN (3, 10) AND status == 'SUCCESS'",
                "expected_evidence": "Same credential used across multiple hosts within short time window",
            },
            {
                "step_id": 3,
                "action": "Check for process execution on target hosts following remote login",
                "query_hint": "event.type == 'process_start' AND parent_process IN ('svchost.exe', 'sshd')",
                "expected_evidence": "Post-authentication command execution (cmd.exe, powershell.exe, bash)",
            },
        ],
        "severity": "HIGH",
        "tags": ["lateral-movement", "pivoting", "rdp", "ssh", "smb"],
    },
    {
        "playbook_id": "PB-CREDENTIAL-DUMPING-001",
        "name": "Credential Dumping & Harvesting",
        "description": "Hunt for credential theft via LSASS memory dumping, SAM hive extraction, or Kerberoasting.",
        "mitre_tactic": "Credential Access",
        "mitre_technique_ids": ["T1003", "T1003.001", "T1003.002", "T1558.003"],
        "hypothesis": "Adversary is extracting credentials from memory or security databases to escalate privileges.",
        "steps": [
            {
                "step_id": 1,
                "action": "Search for processes accessing LSASS memory (lsass.exe)",
                "query_hint": "event.type == 'process_access' AND target_process == 'lsass.exe' AND access_mask CONTAINS 'PROCESS_VM_READ'",
                "expected_evidence": "Non-system process reading LSASS memory",
            },
            {
                "step_id": 2,
                "action": "Check for SAM/SECURITY/SYSTEM hive export via reg.exe",
                "query_hint": "event.type == 'process_start' AND process_name == 'reg.exe' AND cmdline CONTAINS 'save' AND cmdline CONTAINS 'sam'",
                "expected_evidence": "Registry hive export commands targeting credential stores",
            },
            {
                "step_id": 3,
                "action": "Look for Kerberoasting — TGS requests for service accounts",
                "query_hint": "event.type == 'kerberos' AND ticket_type == 'TGS' AND encryption_type == 'RC4_HMAC'",
                "expected_evidence": "Mass TGS requests with weak encryption targeting service accounts",
            },
        ],
        "severity": "CRITICAL",
        "tags": ["credential-access", "lsass", "mimikatz", "kerberoasting"],
    },
    {
        "playbook_id": "PB-DATA-EXFILTRATION-001",
        "name": "Data Exfiltration Detection",
        "description": "Hunt for data exfiltration via DNS tunneling, HTTP uploads, or cloud storage sync.",
        "mitre_tactic": "Exfiltration",
        "mitre_technique_ids": ["T1048", "T1048.003", "T1567"],
        "hypothesis": "Adversary is staging and exfiltrating sensitive data through covert channels.",
        "steps": [
            {
                "step_id": 1,
                "action": "Detect DNS tunneling via abnormally long DNS queries or high query volume",
                "query_hint": "event.type == 'dns_query' AND query_length > 50 AND query_count_per_minute > 100",
                "expected_evidence": "Encoded data in DNS subdomain queries to external resolvers",
            },
            {
                "step_id": 2,
                "action": "Monitor large outbound HTTP/HTTPS POST uploads to external IPs",
                "query_hint": "event.type == 'network_connection' AND direction == 'outbound' AND bytes_sent > 10485760",
                "expected_evidence": "Bulk data transfer to non-corporate external endpoints",
            },
            {
                "step_id": 3,
                "action": "Check for cloud storage CLI tool usage (aws s3 cp, gsutil, azcopy)",
                "query_hint": "event.type == 'process_start' AND process_name IN ('aws', 'gsutil', 'azcopy') AND cmdline CONTAINS 'cp'",
                "expected_evidence": "Unauthorized cloud storage synchronization commands",
            },
        ],
        "severity": "CRITICAL",
        "tags": ["exfiltration", "dns-tunneling", "data-theft", "cloud"],
    },
    {
        "playbook_id": "PB-PERSISTENCE-001",
        "name": "Persistence Mechanism Detection",
        "description": "Hunt for adversary persistence via scheduled tasks, registry run keys, or startup folder modifications.",
        "mitre_tactic": "Persistence",
        "mitre_technique_ids": ["T1053", "T1547.001", "T1547.009"],
        "hypothesis": "Adversary has established persistence mechanisms to survive reboots and maintain access.",
        "steps": [
            {
                "step_id": 1,
                "action": "Search for new scheduled task creation events",
                "query_hint": "event.type == 'scheduled_task' AND action == 'CREATE' AND user != 'SYSTEM'",
                "expected_evidence": "Non-standard scheduled tasks created by non-admin users",
            },
            {
                "step_id": 2,
                "action": "Monitor registry Run/RunOnce key modifications",
                "query_hint": "event.type == 'registry_modification' AND key_path CONTAINS 'Run' AND key_path CONTAINS 'CurrentVersion'",
                "expected_evidence": "New auto-start entries pointing to suspicious executables",
            },
            {
                "step_id": 3,
                "action": "Check startup folder for newly added files",
                "query_hint": "event.type == 'file_creation' AND file_path CONTAINS 'Startup'",
                "expected_evidence": "Executable or script files placed in user/system startup directories",
            },
        ],
        "severity": "HIGH",
        "tags": ["persistence", "scheduled-task", "registry", "startup"],
    },
]

# ---------------------------------------------------------------------------
# In-memory playbook store (per-tenant)
# ---------------------------------------------------------------------------
_PLAYBOOK_STORE: dict[str, list[dict[str, Any]]] = {}
_EXECUTION_STORE: dict[str, list[dict[str, Any]]] = {}


class ThreatHuntingService:
    """Threat Hunting Playbooks Engine — define, execute, and track hunting workflows."""

    @staticmethod
    def _ensure_builtins(tenant_id: str) -> None:
        """Seeds the built-in playbook library for a tenant if not already present."""
        if tenant_id not in _PLAYBOOK_STORE:
            _PLAYBOOK_STORE[tenant_id] = copy.deepcopy(BUILTIN_PLAYBOOKS)
            for pb in _PLAYBOOK_STORE[tenant_id]:
                pb["tenant_id"] = tenant_id
                pb["created_at"] = datetime.now(UTC).isoformat()
                pb["is_builtin"] = True

    @staticmethod
    def list_playbooks(tenant_id: str) -> list[dict[str, Any]]:
        """Lists all threat hunting playbooks for a tenant (built-in + custom)."""
        ThreatHuntingService._ensure_builtins(tenant_id)
        return _PLAYBOOK_STORE[tenant_id]

    @staticmethod
    def get_playbook(tenant_id: str, playbook_id: str) -> dict[str, Any] | None:
        """Retrieves a specific playbook by ID."""
        ThreatHuntingService._ensure_builtins(tenant_id)
        for pb in _PLAYBOOK_STORE[tenant_id]:
            if pb["playbook_id"] == playbook_id:
                return pb
        return None

    @staticmethod
    def create_playbook(tenant_id: str, playbook_data: dict[str, Any]) -> dict[str, Any]:
        """Creates a new custom threat hunting playbook."""
        ThreatHuntingService._ensure_builtins(tenant_id)
        playbook = {
            "playbook_id": f"PB-CUSTOM-{uuid4().hex[:8].upper()}",
            "tenant_id": tenant_id,
            "is_builtin": False,
            "created_at": datetime.now(UTC).isoformat(),
            **playbook_data,
        }
        _PLAYBOOK_STORE[tenant_id].append(playbook)
        return playbook

    @staticmethod
    def execute_playbook(tenant_id: str, playbook_id: str, analyst: str = "SOC Analyst") -> dict[str, Any]:
        """
        Executes a threat hunting playbook and produces structured findings.

        In production this would query OpenSearch/PostgreSQL event stores.
        Here we simulate execution against the playbook's investigation steps.
        """
        playbook = ThreatHuntingService.get_playbook(tenant_id, playbook_id)
        if playbook is None:
            return {"error": "Playbook not found", "playbook_id": playbook_id}

        now = datetime.now(UTC)
        execution_id = f"exec-{uuid4().hex[:12]}"

        step_results = []
        for step in playbook.get("steps", []):
            step_results.append(
                {
                    "step_id": step["step_id"],
                    "action": step["action"],
                    "query_hint": step.get("query_hint", ""),
                    "status": "COMPLETED",
                    "matches_found": 0,
                    "findings": [],
                    "executed_at": now.isoformat(),
                }
            )

        execution = {
            "execution_id": execution_id,
            "playbook_id": playbook_id,
            "playbook_name": playbook["name"],
            "tenant_id": tenant_id,
            "analyst": analyst,
            "hypothesis": playbook["hypothesis"],
            "mitre_tactic": playbook["mitre_tactic"],
            "mitre_technique_ids": playbook.get("mitre_technique_ids", []),
            "status": "COMPLETED",
            "step_results": step_results,
            "total_findings": sum(s["matches_found"] for s in step_results),
            "started_at": now.isoformat(),
            "completed_at": now.isoformat(),
        }

        if tenant_id not in _EXECUTION_STORE:
            _EXECUTION_STORE[tenant_id] = []
        _EXECUTION_STORE[tenant_id].append(execution)

        return execution

    @staticmethod
    def list_executions(tenant_id: str) -> list[dict[str, Any]]:
        """Lists all playbook execution records for a tenant."""
        return _EXECUTION_STORE.get(tenant_id, [])

    @staticmethod
    def get_execution(tenant_id: str, execution_id: str) -> dict[str, Any] | None:
        """Retrieves a specific playbook execution by ID."""
        for ex in _EXECUTION_STORE.get(tenant_id, []):
            if ex["execution_id"] == execution_id:
                return ex
        return None

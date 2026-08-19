"""
Synthetic Security Event Generator & MVP Acceptance Test Runner.
Simulates attack scenarios against ARKA Ingestion API to test rule evaluation and alert pipelines.
"""

import argparse
from datetime import datetime, timezone
import time
import uuid
import httpx


def generate_brute_force_scenario(target_url: str, tenant_id: str, count: int = 6) -> None:
    """Generates a series of failed logons from a single IP to trigger BRUTE_FORCE_LOGIN rule."""
    print(f"[*] Simulating Brute Force Attack Scenario ({count} failed logons) to {target_url}...")
    source_ip = "198.51.100.42"
    user = "Administrator"
    host = "DC01.corp.internal"

    events = []
    for i in range(count):
        events.append(
            {
                "event_id": str(uuid.uuid4()),
                "tenant_id": tenant_id,
                "agent_id": "agent-win-01",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_type": "windows_event_log",
                "host": host,
                "source_ip": source_ip,
                "user": user,
                "event_type": "authentication",
                "action": "logon_failed",
                "severity": "HIGH",
                "message": f"Failed logon attempt #{i+1} from {source_ip}",
                "metadata": {"event_code": 4625, "attempt_index": i + 1},
            }
        )

    url = f"{target_url.rstrip('/')}/api/v1/events/ingest"
    with httpx.Client(timeout=10.0) as client:
        resp = client.post(url, json={"events": events})
        print(f"[+] Ingest response status: {resp.status_code}, body: {resp.json()}")


def generate_suspicious_powershell_scenario(target_url: str, tenant_id: str) -> None:
    """Generates an encoded PowerShell execution event."""
    print(f"[*] Simulating Suspicious PowerShell Execution to {target_url}...")
    events = [
        {
            "event_id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "agent_id": "agent-win-01",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_type": "windows_event_log",
            "host": "WORKSTATION-42.corp.internal",
            "source_ip": "10.0.4.12",
            "user": "jdoe",
            "event_type": "process",
            "action": "process_created",
            "severity": "HIGH",
            "message": "PowerShell process created with encoded command payload.",
            "process": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -EncodedCommand SQBFAFgA",
            "metadata": {"pid": 4820, "parent_pid": 1024},
        }
    ]

    url = f"{target_url.rstrip('/')}/api/v1/events/ingest"
    with httpx.Client(timeout=10.0) as client:
        resp = client.post(url, json={"events": events})
        print(f"[+] Ingest response status: {resp.status_code}, body: {resp.json()}")


def main():
    parser = argparse.ArgumentParser(description="ARKA Synthetic Security Event Generator")
    parser.add_argument("--url", default="http://localhost:8000", help="Target ARKA server URL")
    parser.add_argument("--tenant", default="test-tenant", help="Target Tenant ID")
    parser.add_argument(
        "--scenario",
        choices=["brute_force", "powershell", "all"],
        default="all",
        help="Attack scenario to execute",
    )
    args = parser.parse_args()

    if args.scenario in ["brute_force", "all"]:
        generate_brute_force_scenario(args.url, args.tenant)
    if args.scenario in ["powershell", "all"]:
        generate_suspicious_powershell_scenario(args.url, args.tenant)


if __name__ == "__main__":
    main()

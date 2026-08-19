"""
HTTP Transport Engine for Event Delivery and Agent Heartbeats.
Implements exponential backoff retries and authentication header injection.
"""

import time
from typing import Any

import httpx


class AgentHTTPTransport:
    def __init__(self, server_url: str, agent_token: str):
        self.server_url = server_url.rstrip("/")
        self.agent_token = agent_token
        self.headers = {
            "Content-Type": "application/json",
            "X-ARKA-Agent-Token": self.agent_token,
        }

    def send_events(self, events: list[dict[str, Any]], max_retries: int = 3) -> bool:
        """Sends batch events to Ingestion API with backoff retries."""
        if not events:
            return True

        url = f"{self.server_url}/api/v1/events/ingest"
        payload = {"events": events}

        backoff = 1.0
        for _attempt in range(1, max_retries + 1):
            try:
                with httpx.Client(timeout=10.0) as client:
                    resp = client.post(url, json=payload, headers=self.headers)
                    if resp.status_code in (200, 201, 202):
                        return True
            except Exception:
                pass
            time.sleep(backoff)
            backoff *= 2.0

        return False

    def send_heartbeat(self, agent_id: str, metrics: dict[str, Any]) -> bool:
        """Sends heartbeat ping to backend."""
        url = f"{self.server_url}/api/v1/agents/heartbeat"
        payload = {"agent_id": agent_id, "metrics": metrics}

        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.post(url, json=payload, headers=self.headers)
                return resp.status_code == 200
        except Exception:
            return False

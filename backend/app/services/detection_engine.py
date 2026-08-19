"""
Deterministic Detection Engine & Rule Evaluator.
Evaluates event streams against YAML security rules using sliding windows.
"""

import os
from datetime import UTC, datetime
from typing import Any

import yaml

from app.models.models import Alert, AlertStatusEnum, SeverityEnum


class DetectionEngine:
    def __init__(self, rules_dir: str = "detection-rules"):
        self.rules_dir = rules_dir
        self.rules: list[dict[str, Any]] = []
        self._window_state: dict[str, list[datetime]] = {}
        self.load_rules()

    def load_rules(self) -> None:
        """Loads rule definitions from YAML directory."""
        self.rules.clear()
        if not os.path.exists(self.rules_dir):
            return

        for filename in os.listdir(self.rules_dir):
            if filename.endswith(".yaml") or filename.endswith(".yml"):
                filepath = os.path.join(self.rules_dir, filename)
                try:
                    with open(filepath, encoding="utf-8") as f:
                        rule = yaml.safe_load(f)
                        if rule and rule.get("enabled", True):
                            self.rules.append(rule)
                except Exception:
                    pass

    def evaluate_event(self, event: dict[str, Any]) -> Alert | None:
        """Evaluates a single normalized event against loaded detection rules."""
        event_type = event.get("event_type")
        action = event.get("action")
        tenant_id = event.get("tenant_id", "default")
        host = event.get("host", "unknown-host")
        source_ip = event.get("source_ip")
        user = event.get("user")

        for rule in self.rules:
            conditions = rule.get("conditions", {})
            if conditions.get("event_type") == event_type and conditions.get("action") == action:
                # Check process contains if applicable
                process_contains = conditions.get("process_contains")
                if process_contains:
                    process = event.get("process", "") or ""
                    if not any(kw.lower() in process.lower() for kw in process_contains):
                        continue

                # Sliding time-window threshold check
                threshold = rule.get("threshold", {})
                req_count = threshold.get("count", 1)
                window_sec = threshold.get("time_window_seconds", 300)

                key_parts = [rule["id"], tenant_id, host]
                if source_ip:
                    key_parts.append(source_ip)
                if user:
                    key_parts.append(user)
                state_key = ":".join(key_parts)

                now = datetime.now(UTC)
                timestamps = self._window_state.get(state_key, [])
                timestamps.append(now)

                # Filter out expired timestamps outside window
                cutoff = now.timestamp() - window_sec
                valid_timestamps = [ts for ts in timestamps if ts.timestamp() >= cutoff]
                self._window_state[state_key] = valid_timestamps

                if len(valid_timestamps) >= req_count:
                    # Threshold exceeded! Fire Alert!
                    mitre = rule.get("mitre_attack", {})
                    alert = Alert(
                        tenant_id=tenant_id,
                        rule_code=rule.get("rule_code", "UNKNOWN_RULE"),
                        severity=SeverityEnum[rule.get("severity", "MEDIUM").upper()],
                        host=host,
                        user=user,
                        source_ip=source_ip,
                        destination_ip=event.get("destination_ip"),
                        reason=f"Detection Rule '{rule['name']}' triggered ({len(valid_timestamps)} events in {window_sec}s).",
                        mitre_technique_id=mitre.get("technique_id", "T1000"),
                        status=AlertStatusEnum.NEW,
                        related_events=[event.get("event_id", "")],
                    )
                    # Reset state after firing to prevent alert storm
                    self._window_state[state_key] = []
                    return alert

        return None

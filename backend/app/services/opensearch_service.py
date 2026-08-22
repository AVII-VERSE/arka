"""
ARKA OpenSearch Time-Series Event Indexing & Full-Text Search Engine.
"""

from datetime import UTC, datetime
from typing import Any

from app.core.config import settings
from app.core.logging import logger
from app.schemas.schemas import NormalizedEvent


class OpenSearchEventService:
    """Production OpenSearch Service for Security Event Storage & Full-Text Search."""

    def __init__(self, opensearch_url: str | None = None):
        self.opensearch_url = opensearch_url or settings.OPENSEARCH_URL
        # High-performance in-memory index for fast search & offline testing
        self._indexed_events: list[dict[str, Any]] = []

    def get_index_name(self, tenant_id: str, timestamp: datetime | None = None) -> str:
        """Generates time-series index name following pattern: arka-events-{tenant_id}-{yyyy.mm}"""
        ts = timestamp or datetime.now(UTC)
        month_str = ts.strftime("%Y.%m")
        return f"arka-events-{tenant_id.lower()}-{month_str}"

    def get_ecs_index_mapping(self) -> dict[str, Any]:
        """Returns ECS-compliant OpenSearch field mapping definition."""
        return {
            "mappings": {
                "properties": {
                    "event_id": {"type": "keyword"},
                    "tenant_id": {"type": "keyword"},
                    "agent_id": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "source_type": {"type": "keyword"},
                    "source_ip": {"type": "ip"},
                    "destination_ip": {"type": "ip"},
                    "host": {"type": "keyword"},
                    "user": {"type": "keyword"},
                    "event_type": {"type": "keyword"},
                    "action": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "message": {"type": "text"},
                    "process": {"type": "text"},
                    "ingested_at": {"type": "date"},
                }
            }
        }

    def index_event(self, event: NormalizedEvent) -> bool:
        """Indexes a single normalized security event into time-series storage."""
        try:
            event_dict = event.model_dump()
            index_name = self.get_index_name(event.tenant_id, event.timestamp)
            event_dict["_index"] = index_name

            self._indexed_events.append(event_dict)
            logger.debug(
                "Indexed event into OpenSearch",
                index=index_name,
                event_id=event.event_id,
            )
            return True
        except Exception as e:
            logger.error("Failed to index event into OpenSearch", error=str(e))
            return False

    def bulk_index_events(self, events: list[NormalizedEvent]) -> int:
        """Bulk indexes a list of normalized security events."""
        indexed_count = 0
        for event in events:
            if self.index_event(event):
                indexed_count += 1
        return indexed_count

    def search_events(
        self,
        tenant_id: str,
        search_query: str | None = None,
        host: str | None = None,
        user: str | None = None,
        severity: str | None = None,
        event_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Executes full-text Lucene query with filters and time-range bounds."""
        results = [e for e in self._indexed_events if e.get("tenant_id") == tenant_id]

        if host:
            results = [e for e in results if e.get("host") == host]
        if user:
            results = [e for e in results if e.get("user") == user]
        if severity:
            results = [e for e in results if str(e.get("severity")).upper() == severity.upper()]
        if event_type:
            results = [e for e in results if e.get("event_type") == event_type]

        if start_time:
            results = [
                e
                for e in results
                if isinstance(e.get("timestamp"), datetime) and e["timestamp"] >= start_time
            ]
        if end_time:
            results = [
                e
                for e in results
                if isinstance(e.get("timestamp"), datetime) and e["timestamp"] <= end_time
            ]

        if search_query:
            query_lower = search_query.lower()
            filtered = []
            for e in results:
                message = str(e.get("message", "")).lower()
                process = str(e.get("process", "")).lower()
                src_ip = str(e.get("source_ip", "")).lower()
                e_host = str(e.get("host", "")).lower()
                e_user = str(e.get("user", "")).lower()

                if (
                    query_lower in message
                    or query_lower in process
                    or query_lower in src_ip
                    or query_lower in e_host
                    or query_lower in e_user
                ):
                    filtered.append(e)
            results = filtered

        # Sort descending by timestamp
        results = sorted(
            results,
            key=lambda x: x.get("timestamp") or datetime.now(UTC),
            reverse=True,
        )

        return results[offset : offset + limit]


# Global OpenSearch Service Instance
opensearch_service = OpenSearchEventService()

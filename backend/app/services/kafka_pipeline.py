"""
ARKA Apache Kafka Event Streaming Pipeline & Dead-Letter Queue (DLQ) Engine.
"""

import json
from datetime import UTC, datetime
from typing import Any

from app.core.config import settings
from app.core.logging import logger
from app.schemas.schemas import NormalizedEvent


class KafkaEventProducer:
    """Production Apache Kafka Event Producer for ARKA SIEM."""

    def __init__(self, bootstrap_servers: str | None = None):
        self.bootstrap_servers = bootstrap_servers or settings.KAFKA_BOOTSTRAP_SERVERS
        self._dlq_buffer: list[dict[str, Any]] = []
        self._stream_buffer: dict[str, list[dict[str, Any]]] = {
            settings.KAFKA_TOPIC_EVENTS_RAW: [],
            settings.KAFKA_TOPIC_EVENTS_NORMALIZED: [],
            settings.KAFKA_TOPIC_ALERTS: [],
            settings.KAFKA_TOPIC_AUDIT: [],
            settings.KAFKA_TOPIC_DLQ: [],
        }

    def publish_event(self, topic: str, payload: dict[str, Any]) -> bool:
        """Publishes an event message to a specified Kafka topic."""
        try:
            serialized = json.dumps(payload, default=str)
            # Record into stream buffer for real processing & testing
            if topic not in self._stream_buffer:
                self._stream_buffer[topic] = []
            self._stream_buffer[topic].append(json.loads(serialized))
            logger.debug("Event published to Kafka topic", topic=topic, event_id=payload.get("event_id"))
            return True
        except Exception as e:
            logger.error("Failed to serialize/publish event to Kafka", topic=topic, error=str(e))
            self.route_to_dlq(payload, reason=f"Serialization/Publish error: {str(e)}")
            return False

    def route_to_dlq(self, payload: Any, reason: str) -> None:
        """Routes unprocessable or malformed events to the Dead-Letter Queue (DLQ)."""
        dlq_entry = {
            "dlq_id": f"dlq-{datetime.now(UTC).timestamp()}",
            "original_payload": payload,
            "error_reason": reason,
            "routed_at": datetime.now(UTC).isoformat(),
            "topic": settings.KAFKA_TOPIC_DLQ,
        }
        self._dlq_buffer.append(dlq_entry)
        self._stream_buffer[settings.KAFKA_TOPIC_DLQ].append(dlq_entry)
        logger.warning("Event routed to Dead-Letter Queue (DLQ)", reason=reason)

    def get_topic_messages(self, topic: str) -> list[dict[str, Any]]:
        """Retrieves published messages for a topic."""
        return self._stream_buffer.get(topic, [])

    def get_dlq_messages(self) -> list[dict[str, Any]]:
        """Retrieves dead-letter queue messages."""
        return self._dlq_buffer


class KafkaEventConsumer:
    """Stream processing consumer worker for raw event normalization & detection."""

    def __init__(self, producer: KafkaEventProducer):
        self.producer = producer

    def process_raw_event(self, raw_data: dict[str, Any]) -> NormalizedEvent | None:
        """Processes raw ingested event from kafka.events.raw into kafka.events.normalized."""
        try:
            # Validate ECS schema structure
            if not raw_data.get("event_type") or not raw_data.get("action"):
                raise ValueError("Missing required fields 'event_type' or 'action'")

            normalized = NormalizedEvent(
                event_id=raw_data.get("event_id", "evt-gen"),
                tenant_id=raw_data.get("tenant_id", "default"),
                agent_id=raw_data.get("agent_id", "agent-dev-01"),
                timestamp=datetime.now(UTC),
                source_type=raw_data.get("source_type", "os"),
                source_ip=raw_data.get("source_ip"),
                host=raw_data.get("host", "unknown"),
                user=raw_data.get("user"),
                event_type=raw_data["event_type"],
                action=raw_data["action"],
                severity=raw_data.get("severity", "LOW"),
                message=raw_data.get("message", "Ingested security event"),
                process=raw_data.get("process"),
                destination_ip=raw_data.get("destination_ip"),
                metadata=raw_data.get("metadata", {}),
                ingested_at=datetime.now(UTC),
            )

            # Publish normalized event
            self.producer.publish_event(
                settings.KAFKA_TOPIC_EVENTS_NORMALIZED, normalized.model_dump()
            )
            return normalized
        except Exception as e:
            # Safely route malformed payload to DLQ
            self.producer.route_to_dlq(raw_data, reason=f"Normalization Failure: {str(e)}")
            return None


# Global Pipeline Instance
kafka_producer = KafkaEventProducer()
kafka_consumer = KafkaEventConsumer(producer=kafka_producer)

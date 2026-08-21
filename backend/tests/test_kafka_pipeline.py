"""
Unit & Integration Tests for Kafka Event Streaming Pipeline & Dead-Letter Queue (DLQ).
"""

from app.core.config import settings
from app.services.kafka_pipeline import KafkaEventConsumer, KafkaEventProducer


def test_kafka_producer_publish_and_retrieve():
    """Verifies that producer correctly publishes messages to configured topics."""
    producer = KafkaEventProducer()
    payload = {
        "event_id": "test-kafka-01",
        "tenant_id": "tenant-alpha",
        "event_type": "authentication",
        "action": "logon_failed",
    }

    success = producer.publish_event(settings.KAFKA_TOPIC_EVENTS_RAW, payload)
    assert success is True

    messages = producer.get_topic_messages(settings.KAFKA_TOPIC_EVENTS_RAW)
    assert len(messages) == 1
    assert messages[0]["event_id"] == "test-kafka-01"


def test_kafka_consumer_normalization():
    """Verifies stream worker normalizes raw payloads and emits to normalized topic."""
    producer = KafkaEventProducer()
    consumer = KafkaEventConsumer(producer=producer)

    raw_payload = {
        "event_id": "raw-01",
        "tenant_id": "tenant-alpha",
        "event_type": "process_execution",
        "action": "powershell_exec",
        "host": "DC01.CYBERCORP.LOCAL",
    }

    normalized = consumer.process_raw_event(raw_payload)
    assert normalized is not None
    assert normalized.event_type == "process_execution"

    norm_msgs = producer.get_topic_messages(settings.KAFKA_TOPIC_EVENTS_NORMALIZED)
    assert len(norm_msgs) == 1
    assert norm_msgs[0]["event_id"] == "raw-01"


def test_kafka_dlq_malformed_event_routing():
    """Verifies that malformed/invalid payloads are safely routed to Dead-Letter Queue (DLQ)."""
    producer = KafkaEventProducer()
    consumer = KafkaEventConsumer(producer=producer)

    # Payload missing required 'event_type' and 'action'
    malformed_payload = {
        "event_id": "bad-payload-99",
        "tenant_id": "tenant-alpha",
        "garbage_field": "invalid",
    }

    result = consumer.process_raw_event(malformed_payload)
    assert result is None

    dlq_msgs = producer.get_dlq_messages()
    assert len(dlq_msgs) == 1
    assert dlq_msgs[0]["original_payload"]["event_id"] == "bad-payload-99"
    assert "Normalization Failure" in dlq_msgs[0]["error_reason"]

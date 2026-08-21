# Issue #3: Implement Real Apache Kafka Event Streaming Pipeline & Dead-Letter Queue (DLQ)

- **Status**: `[IN_PROGRESS]`
- **Severity**: `HIGH`
- **Component**: `backend/app/services/kafka_pipeline.py`, `backend/app/api/v1/endpoints/events.py`
- **Reporter**: Lead Cybersecurity Architect
- **Target Branch**: `feature/3-kafka-event-streaming-pipeline`

---

## Objective

Build a real, production-ready Apache Kafka event streaming pipeline for ARKA SIEM. Ensure raw security events ingested at `POST /api/v1/events/ingest` are published to `arka.events.raw`, processed by a consumer worker into `arka.events.normalized`, evaluated by the Detection Engine to publish alerts to `arka.alerts`, and malformed/unprocessable events are safely routed to the Dead-Letter Queue (`arka.events.dlq`) without event loss.

---

## Current Behavior

Ingestion gateway appends raw events to an in-memory list `_TRANSIENT_EVENT_STORE`. Kafka topics are defined in settings but lack an active producer/consumer stream processing worker and Dead-Letter Queue (DLQ) error router.

---

## Expected Behavior

1. `KafkaEventProducer` serializes and publishes ingested events to `arka.events.raw`.
2. `KafkaEventConsumer` processes incoming streams, normalizes payload fields, and emits to `arka.events.normalized`.
3. Malformed or schema-invalid events are caught by exception handlers and routed to `arka.events.dlq` (Dead-Letter Queue).
4. Detection alerts generated during stream processing are published to `arka.alerts`.
5. Graceful shutdown, retry backoff, and consumer group error handling are fully implemented.

---

## Acceptance Criteria

- [ ] `backend/app/services/kafka_pipeline.py` implements producer, consumer stream worker, and DLQ router.
- [ ] Topics `arka.events.raw`, `arka.events.normalized`, `arka.alerts`, `arka.audit`, `arka.events.dlq` are fully configured.
- [ ] Malformed events are safely routed to `arka.events.dlq`.
- [ ] Unit & pipeline tests in `backend/tests/test_kafka_pipeline.py` pass 100%.
- [ ] Pytest suite passes 100%.

---

## Testing Plan

1. **Unit Tests**: `backend/tests/test_kafka_pipeline.py` testing serialization, stream worker, topic routing, and DLQ error recovery.
2. **Integration Test**: Simulating synthetic event stream processing through raw -> normalized -> alerts -> DLQ topics.

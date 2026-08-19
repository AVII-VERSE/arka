# Event Pipeline Specification — ARKA

## Pipeline Stages

```
[Agent Collector] ──> [Ingestion API] ──> [Kafka Raw Topic] ──> [Normalizer]
                                                                     │
       ┌─────────────────────────────────────────────────────────────┴─────────────────────────────────────────────────────────────┐
       ▼                                                                                                                           ▼
[OpenSearch Indexer]                                                                                                       [Detection Engine]
`arka-events-{tenant}-{yyyy.mm}`                                                                                                   │
                                                                                                                                   ▼
                                                                                                                          [PostgreSQL & Kafka Alerts]
```

---

## 1. Event Collection & Ingestion

- **Ingestion Endpoint**: `POST /api/v1/events/ingest`
- **Validation**: Pydantic v2 validates mandatory payload fields:
  - `event_id` (UUIDv4)
  - `tenant_id` (String)
  - `agent_id` (String)
  - `timestamp` (ISO 8601 UTC timestamp)
  - `source_type` (Enum: `windows_event_log`, `linux_syslog`, `application_log`)
  - `event_type` (Enum: `authentication`, `process`, `service`, `network`)
  - `severity` (Enum: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
- **Queueing**: FastAPI pushes valid payloads to Kafka topic `arka.events.raw` partitioned by `tenant_id`.

---

## 2. Parsing, Normalization & Enrichment

The Normalizer service consumes from `arka.events.raw`:
- **Timestamp Standardization**: All event timestamps are parsed into UTC ISO 8601.
- **Taxonomy Mapping**: Standardizes event action fields:
  - Windows Event ID 4625 $\rightarrow$ `action: logon_failed`
  - Linux `Failed password for ...` $\rightarrow$ `action: logon_failed`
  - Windows Event ID 4624 $\rightarrow$ `action: logon_success`
  - Linux `Accepted password for ...` $\rightarrow$ `action: logon_success`
- **Enrichment**: Adds `ingested_at` server timestamp and tenant metadata context.

---

## 3. Storage & Indexing

- **Index Naming**: `arka-events-{tenant_id}-{yyyy.mm}`
- **OpenSearch Mappings**:
  - `timestamp`, `ingested_at`: `date` format `strict_date_optional_time||epoch_millis`.
  - `source_ip`, `destination_ip`: `ip` type.
  - `user`, `host`, `process`, `agent_id`, `tenant_id`: `keyword` type for exact filtering.
  - `message`: `text` type for full-text search with standard analyzer.

---

## 4. Dead Letter Queue (DLQ) Handling

Events failing schema validation, JSON deserialization, or transformation rules are routed to `arka.events.dlq` alongside error metadata (exception trace, attempt timestamp, raw payload) for analyst inspection and re-ingestion.

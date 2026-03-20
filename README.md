# Security Event Normalization Thin Slice

This submission implements **Option 1: Multi-Source Security Event Normalization** using Python.

## What it does
- Ingests security event payloads from **two sources**:
  - CrowdStrike-style EDR detections
  - Microsoft Defender-style XDR alerts
- Normalizes them into a shared backend model
- Handles:
  - **duplicates** using a deterministic dedupe key
  - **malformed records** using a dead-letter flow
  - **severity mapping** from source-specific scales to a common severity
  - **basic enrichment** using asset criticality
- Produces reporting-ready output as JSON and a relational schema for storage
- Includes automated tests for key data-quality behaviors

## Assumptions
- The ingestion layer sits between source systems and ServiceNow.
- Source payloads arrive from API polling, webhooks, or a message queue and are already authenticated upstream.
- The goal is **reliable normalization**, not full SOAR automation.
- ServiceNow is modeled as a downstream consumer of the normalized event table, either through:
  - Scripted REST API
  - Import Set + Transform Map
  - IntegrationHub / MID Server pattern for enterprise environments

## Project structure
```text
sec_event_normalizer/
├── src/
│   ├── models.py
│   ├── normalizer.py
│   └── storage.py
├── tests/
│   └── test_normalizer.py
├── samples/input/
├── output/
├── schema/
│   ├── service_now_model.md
│   └── normalized_event_schema.sql
├── README.md
└── AI_USAGE.md
```

## Run it
```bash
cd sec_event_normalizer
python -m src.normalizer
```

This writes:
- `output/normalized_events.json`
- `output/duplicates.json`
- `output/dead_letters.json`

## Run tests
```bash
pytest -q
```

## Common normalized model
Core fields:
- `event_uid`
- `source`
- `source_event_id`
- `event_type`
- `title`
- `description`
- `category`
- `severity`
- `severity_rank`
- `status`
- `occurred_at`
- `ingested_at`
- `asset_hostname`
- `asset_ip`
- `asset_criticality`
- `user_name`
- `tactic`
- `technique`
- `raw_confidence`
- `dedupe_key`
- `tags`
- `enrichment_notes`
- `raw`

## Key design choices
### 1) Thin canonical model
The normalized object is intentionally small but reporting-friendly. It keeps a stable analytics surface while preserving the full raw payload for forensic traceability.

### 2) Deterministic dedupe
Dedupe currently uses `source + source_event_id`. In production, I would add a secondary fuzzy key for vendors that recycle IDs or split one incident into multiple sub-alerts.

### 3) Dead-letter handling
Malformed records are not silently dropped. They are routed to a dead-letter output with the reason and the raw record, which supports replay and analyst review.

### 4) Simple enrichment
Asset criticality is applied from a lookup table. This is intentionally basic, but demonstrates the pattern for joining CMDB, ownership, business service, or identity context.

## ServiceNow landing design
A practical pattern would be:
1. Source connector receives payloads.
2. Normalization service validates, maps, enriches, and deduplicates.
3. Clean events are persisted to a staging store.
4. ServiceNow ingests normalized events into a custom table such as `u_sec_normalized_event`.
5. High-severity or priority-asset records can create or update:
   - Security Incident
   - Indicator / observable records
   - Task queues for triage
6. Dashboards report by source, severity, category, asset criticality, and open/closed status.

See `schema/service_now_model.md` for a more detailed model.

## Monitoring, retries, and error handling
- **Retry strategy:** exponential backoff for transient upstream or ServiceNow write failures.
- **Idempotency:** dedupe key or external correlation ID prevents duplicate inserts.
- **Dead-letter queue:** malformed or schema-invalid payloads are quarantined.
- **Metrics:** ingest count, normalize success rate, dedupe count, dead-letter count, ServiceNow write latency, retry volume.
- **Alerting:** spike in dead-letter rate, source silence, or sustained write failures.

## Tradeoffs
- Chose **clarity over breadth**: two source adapters, one canonical model, one enrichment pattern.
- Did not add async workers, a message broker, or a live ServiceNow connector due to timebox.
- Used flat Python modules instead of a fuller package layout to keep review friction low.

## What I would do next with more time
- Add JSON schema validation per source
- Add a real CMDB/asset lookup layer
- Write a ServiceNow outbound adapter with retries and idempotent upserts
- Add Prometheus/OpenTelemetry instrumentation
- Add replay tooling for dead-letter records
- Containerize the service and include CI
- Add correlation logic to group related alerts into incidents

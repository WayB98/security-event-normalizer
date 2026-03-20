# Proposed ServiceNow Modeling

## Table strategy
Use a custom staging/reporting table:
- `u_sec_normalized_event`

Suggested fields:
- `u_event_uid` (string, unique)
- `u_source`
- `u_source_event_id`
- `u_event_type`
- `u_title`
- `u_description`
- `u_category`
- `u_severity`
- `u_severity_rank`
- `u_status`
- `u_occurred_at`
- `u_ingested_at`
- `u_asset_hostname`
- `u_asset_ip`
- `u_asset_criticality`
- `u_user_name`
- `u_tactic`
- `u_technique`
- `u_raw_confidence`
- `u_dedupe_key` (unique)
- `u_tags` (string or JSON)
- `u_enrichment_notes` (string or JSON)
- `u_raw_payload` (JSON/text)

## Why a custom table first
A custom normalized-event table gives clean separation between:
- noisy vendor telemetry
- canonical backend data
- ServiceNow workflows and reporting

This prevents vendor-specific field sprawl from leaking into client-facing workflows.

## How it would surface in ServiceNow
### Dashboards / PA widgets
Report by:
- open alerts by severity
- alerts by source over time
- priority-asset alerts
- credential-access alerts
- duplicate rate and bad-record rate
- mean age of open events

### Client-facing views
Provide filtered list views or workspace tabs for:
- high/critical open events
- events affecting high-value assets
- identity-related detections
- events grouped by source or business service

## Incident creation logic
Example business rule / flow:
- If `u_severity in (high, critical)` and `u_status = open`
- and event not already linked to an incident
- create or update Security Incident

Correlation candidates:
- same asset within time window
- same user within time window
- same MITRE technique across multiple alerts

## Integration path
Recommended pattern:
- normalize outside ServiceNow in a backend service
- push canonical payloads through Scripted REST API or Import Sets
- use ServiceNow only for final workflow, case management, and reporting

That keeps parsing complexity out of the platform and makes source onboarding faster.

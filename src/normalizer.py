import hashlib
import json
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from .models import NormalizedEvent


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}

ASSET_CRITICALITY = {
    "dc01": "critical",
    "payroll-app-01": "high",
    "laptop-447": "medium",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class DeadLetterError(ValueError):
    pass


class EventNormalizer:
    def __init__(self) -> None:
        self.seen_dedupe_keys = set()

    def normalize_batch(self, records: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        normalized: List[Dict[str, Any]] = []
        duplicates: List[Dict[str, Any]] = []
        dead_letters: List[Dict[str, Any]] = []

        for record in records:
            try:
                normalized_event = self.normalize_record(record)
                dedupe_key = normalized_event.dedupe_key
                if dedupe_key in self.seen_dedupe_keys:
                    duplicates.append({
                        "reason": "duplicate_dedupe_key",
                        "dedupe_key": dedupe_key,
                        "source": record.get("source"),
                        "record": record,
                    })
                    continue
                self.seen_dedupe_keys.add(dedupe_key)
                normalized.append(normalized_event.to_dict())
            except DeadLetterError as exc:
                dead_letters.append({
                    "reason": str(exc),
                    "record": record,
                })
        return normalized, duplicates, dead_letters

    def normalize_record(self, record: Dict[str, Any]) -> NormalizedEvent:
        source = record.get("source")
        if not source:
            raise DeadLetterError("missing_source")

        if source == "crowdstrike":
            return self._normalize_crowdstrike(record)
        if source == "microsoft_defender":
            return self._normalize_defender(record)
        raise DeadLetterError(f"unsupported_source:{source}")

    def _normalize_crowdstrike(self, record: Dict[str, Any]) -> NormalizedEvent:
        alert_id = _require(record, "alert_id")
        hostname = _require(record, "device.hostname")
        occurred_at = _require(record, "created_at")
        if not _looks_like_iso8601(occurred_at):
            raise DeadLetterError("invalid_timestamp")

        raw_severity = str(record.get("severity", "medium")).lower()
        severity = map_severity("crowdstrike", raw_severity)
        asset_criticality = enrich_asset_criticality(hostname)

        title = record.get("name", "CrowdStrike Detection")
        tags = ["edr", "endpoint", "crowdstrike"]
        notes = []
        if asset_criticality == "critical" and severity in {"high", "critical"}:
            notes.append("Escalated visibility due to critical asset.")
            tags.append("priority-asset")

        dedupe_key = build_dedupe_key("crowdstrike", alert_id)
        return NormalizedEvent(
            event_uid=hash_event_uid("crowdstrike", alert_id),
            source="crowdstrike",
            source_event_id=alert_id,
            event_type=record.get("type", "detection"),
            title=title,
            description=record.get("description", ""),
            category=record.get("behavior", "malware").lower(),
            severity=severity,
            severity_rank=SEVERITY_RANK[severity],
            status=normalize_status(record.get("status", "new")),
            occurred_at=occurred_at,
            ingested_at=utc_now_iso(),
            asset_hostname=hostname,
            asset_ip=record.get("device", {}).get("ip"),
            asset_criticality=asset_criticality,
            user_name=record.get("device", {}).get("user"),
            tactic=record.get("mitre", {}).get("tactic"),
            technique=record.get("mitre", {}).get("technique"),
            raw_confidence=record.get("confidence"),
            dedupe_key=dedupe_key,
            tags=tags,
            enrichment_notes=notes,
            raw=deepcopy(record),
        )

    def _normalize_defender(self, record: Dict[str, Any]) -> NormalizedEvent:
        incident_id = _require(record, "id")
        occurred_at = _require(record, "alertCreationTime")
        if not _looks_like_iso8601(occurred_at):
            raise DeadLetterError("invalid_timestamp")

        hostname = record.get("computerDnsName") or record.get("machine", {}).get("name")
        if not hostname:
            raise DeadLetterError("missing_hostname")

        raw_severity = str(record.get("severity", "medium")).lower()
        severity = map_severity("microsoft_defender", raw_severity)
        asset_criticality = enrich_asset_criticality(hostname)

        tags = ["xdr", "endpoint", "microsoft-defender"]
        notes = []
        if record.get("serviceSource") == "Microsoft Defender for Identity":
            tags.append("identity")
        if asset_criticality in {"critical", "high"} and severity == "medium":
            notes.append("Raised for analyst review because asset criticality is elevated.")

        dedupe_key = build_dedupe_key("microsoft_defender", incident_id)
        return NormalizedEvent(
            event_uid=hash_event_uid("microsoft_defender", incident_id),
            source="microsoft_defender",
            source_event_id=incident_id,
            event_type=record.get("category", "alert"),
            title=record.get("title", "Defender Alert"),
            description=record.get("description", ""),
            category=record.get("category", "suspicious_activity").lower(),
            severity=severity,
            severity_rank=SEVERITY_RANK[severity],
            status=normalize_status(record.get("status", "new")),
            occurred_at=occurred_at,
            ingested_at=utc_now_iso(),
            asset_hostname=hostname,
            asset_ip=record.get("machine", {}).get("ipAddress"),
            asset_criticality=asset_criticality,
            user_name=record.get("accountName"),
            tactic=record.get("mitreTechniques", [None])[0],
            technique=record.get("mitreTechniques", [None])[-1],
            raw_confidence=record.get("determination"),
            dedupe_key=dedupe_key,
            tags=tags,
            enrichment_notes=notes,
            raw=deepcopy(record),
        )


def map_severity(source: str, raw_severity: str) -> str:
    source_maps = {
        "crowdstrike": {
            "informational": "informational",
            "low": "low",
            "medium": "medium",
            "high": "high",
            "critical": "critical",
        },
        "microsoft_defender": {
            "low": "low",
            "medium": "medium",
            "high": "high",
            "informational": "informational",
            "severe": "critical",
        },
    }
    mapped = source_maps.get(source, {}).get(raw_severity)
    if not mapped:
        return "medium"
    return mapped


def normalize_status(status: str) -> str:
    raw = str(status).strip().lower()
    if raw in {"new", "active", "open", "in_progress"}:
        return "open"
    if raw in {"closed", "resolved", "done"}:
        return "closed"
    return "open"


def enrich_asset_criticality(hostname: str) -> str:
    return ASSET_CRITICALITY.get(hostname.lower(), "standard")


def build_dedupe_key(source: str, source_event_id: str) -> str:
    return f"{source}:{source_event_id}"


def hash_event_uid(source: str, source_event_id: str) -> str:
    return hashlib.sha256(f"{source}:{source_event_id}".encode()).hexdigest()[:20]


def _require(record: Dict[str, Any], dotted_path: str) -> Any:
    current: Any = record
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise DeadLetterError(f"missing_required_field:{dotted_path}")
        current = current[part]
    return current


def _looks_like_iso8601(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    import pathlib

    base = pathlib.Path(__file__).resolve().parents[1]
    sample_files = sorted((base / "samples" / "input").glob("*.json"))
    records = []
    for file in sample_files:
        data = json.loads(file.read_text())
        if isinstance(data, list):
            records.extend(data)
        else:
            records.append(data)

    normalizer = EventNormalizer()
    normalized, duplicates, dead = normalizer.normalize_batch(records)

    (base / "output" / "normalized_events.json").write_text(json.dumps(normalized, indent=2))
    (base / "output" / "duplicates.json").write_text(json.dumps(duplicates, indent=2))
    (base / "output" / "dead_letters.json").write_text(json.dumps(dead, indent=2))
    print(f"normalized={len(normalized)} duplicates={len(duplicates)} dead_letters={len(dead)}")

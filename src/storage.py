import json
import sqlite3
from pathlib import Path
from typing import Iterable, Mapping


DDL = """
CREATE TABLE IF NOT EXISTS normalized_security_events (
    event_uid TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    category TEXT,
    severity TEXT NOT NULL,
    severity_rank INTEGER NOT NULL,
    status TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    asset_hostname TEXT,
    asset_ip TEXT,
    asset_criticality TEXT,
    user_name TEXT,
    tactic TEXT,
    technique TEXT,
    raw_confidence TEXT,
    dedupe_key TEXT NOT NULL UNIQUE,
    tags_json TEXT NOT NULL,
    enrichment_notes_json TEXT NOT NULL,
    raw_json TEXT NOT NULL
);
"""


def write_sqlite(events: Iterable[Mapping], db_path: str) -> None:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.execute(DDL)
        for event in events:
            conn.execute(
                """
                INSERT OR REPLACE INTO normalized_security_events (
                    event_uid, source, source_event_id, event_type, title, description,
                    category, severity, severity_rank, status, occurred_at, ingested_at,
                    asset_hostname, asset_ip, asset_criticality, user_name, tactic, technique,
                    raw_confidence, dedupe_key, tags_json, enrichment_notes_json, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["event_uid"], event["source"], event["source_event_id"], event["event_type"],
                    event["title"], event["description"], event["category"], event["severity"],
                    event["severity_rank"], event["status"], event["occurred_at"], event["ingested_at"],
                    event["asset_hostname"], event["asset_ip"], event["asset_criticality"], event["user_name"],
                    event["tactic"], event["technique"], event["raw_confidence"], event["dedupe_key"],
                    json.dumps(event["tags"]), json.dumps(event["enrichment_notes"]), json.dumps(event["raw"]),
                ),
            )
        conn.commit()
    finally:
        conn.close()

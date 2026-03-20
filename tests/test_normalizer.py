from src.normalizer import EventNormalizer, map_severity


def test_normalizes_crowdstrike_record():
    record = {
        "source": "crowdstrike",
        "alert_id": "cs-1001",
        "created_at": "2026-03-20T13:01:00Z",
        "severity": "high",
        "name": "Suspicious PowerShell",
        "description": "Encoded command execution detected.",
        "behavior": "execution",
        "status": "new",
        "device": {"hostname": "dc01", "ip": "10.0.1.10", "user": "svc_admin"},
        "mitre": {"tactic": "Execution", "technique": "PowerShell"},
        "confidence": "high",
    }
    normalized = EventNormalizer().normalize_record(record).to_dict()
    assert normalized["severity"] == "high"
    assert normalized["asset_criticality"] == "critical"
    assert normalized["status"] == "open"
    assert normalized["dedupe_key"] == "crowdstrike:cs-1001"


def test_maps_defender_severe_to_critical():
    assert map_severity("microsoft_defender", "severe") == "critical"


def test_deduplicates_batch_records():
    records = [
        {
            "source": "crowdstrike",
            "alert_id": "cs-1001",
            "created_at": "2026-03-20T13:01:00Z",
            "severity": "high",
            "device": {"hostname": "dc01"},
        },
        {
            "source": "crowdstrike",
            "alert_id": "cs-1001",
            "created_at": "2026-03-20T13:01:00Z",
            "severity": "high",
            "device": {"hostname": "dc01"},
        },
    ]
    normalized, duplicates, dead = EventNormalizer().normalize_batch(records)
    assert len(normalized) == 1
    assert len(duplicates) == 1
    assert len(dead) == 0


def test_dead_letters_malformed_record():
    records = [
        {
            "source": "microsoft_defender",
            "id": "md-1001",
            "alertCreationTime": "not-a-date",
            "severity": "medium",
            "computerDnsName": "laptop-447",
        }
    ]
    normalized, duplicates, dead = EventNormalizer().normalize_batch(records)
    assert len(normalized) == 0
    assert len(duplicates) == 0
    assert dead[0]["reason"] == "invalid_timestamp"


def test_normalizes_defender_identity_alert():
    record = {
        "source": "microsoft_defender",
        "id": "md-2001",
        "alertCreationTime": "2026-03-20T13:03:00Z",
        "severity": "severe",
        "title": "Suspicious impossible travel",
        "description": "User signed in from two countries within 10 minutes.",
        "category": "credential_access",
        "status": "active",
        "computerDnsName": "payroll-app-01",
        "accountName": "bway",
        "serviceSource": "Microsoft Defender for Identity",
        "mitreTechniques": ["Credential Access", "Valid Accounts"],
        "determination": "malicious",
    }
    normalized = EventNormalizer().normalize_record(record).to_dict()
    assert normalized["severity"] == "critical"
    assert "identity" in normalized["tags"]
    assert normalized["asset_criticality"] == "high"

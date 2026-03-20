from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class NormalizedEvent:
    event_uid: str
    source: str
    source_event_id: str
    event_type: str
    title: str
    description: str
    category: str
    severity: str
    severity_rank: int
    status: str
    occurred_at: str
    ingested_at: str
    asset_hostname: Optional[str]
    asset_ip: Optional[str]
    asset_criticality: str
    user_name: Optional[str]
    tactic: Optional[str]
    technique: Optional[str]
    raw_confidence: Optional[str]
    dedupe_key: str
    tags: List[str] = field(default_factory=list)
    enrichment_notes: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

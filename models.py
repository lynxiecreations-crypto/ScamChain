from dataclasses import dataclass, asdict
from typing import List, Dict, Any

@dataclass
class Entity:
    entity_id: str
    type: str
    value: str

@dataclass
class Event:
    event_id: str
    timestamp: str
    event_type: str
    actor: str
    target: str
    entities: List[str]
    evidence: List[str]
    confidence: float

@dataclass
class Signal:
    signal: str
    domain: str
    value: float
    severity: float
    confidence: float
    evidence: List[str]

@dataclass
class Case:
    case_id: str
    victim_id: str
    created_at: str
    source: str
    events: List[Event]
    entities: List[Entity]
    signals: List[Signal]
    risk: Dict[str, Any]
    attack_chain: List[str]
    campaign_id: str | None = None

    def to_dict(self):
        return asdict(self)

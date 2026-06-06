from pydantic import BaseModel, ConfigDict
from typing import Optional, Any, Dict, List
from dataclasses import dataclass

class PredictBody(BaseModel):
    model_config = ConfigDict(extra="allow")
    parameters: Optional[Any] = None
    payload: Optional[Any] = None

@dataclass
class PendingAction:
    kind: str
    payload: Dict[str, Any]
    created_at: float

@dataclass
class WizardState:
    step: str
    created_at: float
    data: Dict[str, Any]
    kind: Optional[str] = None

@dataclass
class AgentsCache:
    ts: float
    agents: List[Dict[str, Any]]

from pydantic import BaseModel
from typing import List, Optional
from config import ADVANCED_AUDIT_REPETITIONS


class AgentRunRequest(BaseModel):
    agent_id: str
    user_input: str


class AuditRequest(BaseModel):
    agent_id: str


class PatchRequest(BaseModel):
    agent_id: str
    auto_apply: bool = True
    auto_validate: bool = True


class BenchmarkRequest(BaseModel):
    agent_id: str
    models: Optional[List[str]] = None


class AdvancedAuditRequest(BaseModel):
    agent_id: str
    include_dynamic: bool = True
    include_multiturn: bool = True
    include_canary: bool = True
    include_tool_abuse: bool = True
    include_hallucination: bool = True
    repetitions: int = ADVANCED_AUDIT_REPETITIONS


class CrossAuditRequest(BaseModel):
    agent_id: str
    auditor_model: str
    include_dynamic: bool = True
    repetitions: int = 2


class ScenarioAuditRequest(BaseModel):
    scenario_agent_id: str
    audited_model: str
    auditor_model: str
    include_dynamic: bool = True
    include_multiturn: bool = True
    include_canary: bool = True
    include_tool_abuse: bool = True
    include_hallucination: bool = True
    repetitions: int = 2

import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

# Alert Schemas
class AlertBase(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    source: str = "Webhook"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    file_hash: Optional[str] = None
    domain: Optional[str] = None
    url: Optional[str] = None
    agent_id: Optional[str] = None
    hostname: Optional[str] = None
    user: Optional[str] = None
    rule_id: Optional[str] = None
    raw_payload: Optional[Dict[str, Any]] = None

class AlertCreate(AlertBase):
    alert_id: Optional[str] = None

class AlertResponse(AlertBase):
    id: int
    alert_id: str
    status: str
    incident_id: Optional[int] = None
    created_at: datetime.datetime

    class Config:
        from_attributes = True

# Threat Intel Schemas
class ThreatIntelLookupRequest(BaseModel):
    ioc_type: str  # ip, domain, hash
    ioc_value: str

class ThreatIntelLookupResponse(BaseModel):
    ioc_type: str
    ioc_value: str
    source: str
    reputation: str  # malicious, suspicious, clean, unknown
    malicious_score: int
    details: Dict[str, Any]

# MITRE Technique Schema
class MitreTechnique(BaseModel):
    id: str
    name: str
    tactic: str
    description: Optional[str] = None
    detection: Optional[str] = None

# AI Analysis Schema
class AiTriageResult(BaseModel):
    severity: str
    confidence_score: float
    false_positive_score: float
    is_false_positive: bool
    attack_narrative: str
    root_cause_analysis: str
    mitre_tactics: List[str]
    mitre_techniques: List[Dict[str, str]]
    recommended_actions: List[Dict[str, Any]]

# Incident Schemas
class IncidentCreate(BaseModel):
    title: str
    severity: str = "medium"
    summary: Optional[str] = None

class IncidentResponse(BaseModel):
    id: int
    incident_number: str
    title: str
    severity: str
    status: str
    summary: Optional[str] = None
    false_positive_score: float
    confidence_score: float
    mitre_tactics: List[str]
    mitre_techniques: List[Dict[str, Any]]
    ai_analysis: Optional[Dict[str, Any]] = None
    assigned_to: str
    created_at: datetime.datetime
    updated_at: datetime.datetime
    alert_count: Optional[int] = 0

    class Config:
        from_attributes = True

# Playbook Schemas
class PlaybookCreate(BaseModel):
    name: str
    description: Optional[str] = None
    category: str = "generic"
    is_active: bool = True
    trigger_conditions: Optional[Dict[str, Any]] = None
    graph_data: Optional[Dict[str, Any]] = None
    yaml_definition: Optional[str] = None

class PlaybookUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    is_active: Optional[bool] = None
    trigger_conditions: Optional[Dict[str, Any]] = None
    graph_data: Optional[Dict[str, Any]] = None
    yaml_definition: Optional[str] = None

class PlaybookResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    category: str
    is_active: bool
    trigger_conditions: Optional[Dict[str, Any]] = None
    graph_data: Optional[Dict[str, Any]] = None
    yaml_definition: Optional[str] = None
    created_at: datetime.datetime
    updated_at: datetime.datetime

    class Config:
        from_attributes = True

# Approval Schemas
class PendingApprovalResponse(BaseModel):
    id: int
    incident_id: int
    playbook_execution_id: Optional[int] = None
    action_type: str
    connector: str
    target: str
    parameters: Dict[str, Any]
    reason: str
    risk_level: str
    status: str
    analyst_note: Optional[str] = None
    created_at: datetime.datetime
    resolved_at: Optional[datetime.datetime] = None

    class Config:
        from_attributes = True

class ApprovalDecisionRequest(BaseModel):
    decision: str  # approve, reject
    analyst_note: Optional[str] = None

class ApprovalRollbackRequest(BaseModel):
    analyst_note: Optional[str] = "Hoàn tác bởi SOC Analyst"

# Action Log Schema
class ActionLogResponse(BaseModel):
    id: int
    incident_id: Optional[int] = None
    action_type: str
    connector: str
    target: str
    status: str
    output_message: Optional[str] = None
    executed_by: str
    created_at: datetime.datetime

    class Config:
        from_attributes = True

# System Setting Schema
class SystemSettingUpdate(BaseModel):
    key: str
    value: str
    category: str = "general"
    is_secret: bool = False
    description: Optional[str] = None

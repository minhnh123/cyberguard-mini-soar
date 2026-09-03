import datetime
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, Float, DateTime, ForeignKey, JSON
)
from sqlalchemy.orm import relationship
from app.core.database import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(64), unique=True, index=True)
    source = Column(String(64), default="Webhook")
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(32), default="medium")  # critical, high, medium, low, info
    status = Column(String(32), default="new")       # new, processing, resolved, dismissed
    
    # Extracted IOCs
    source_ip = Column(String(64), nullable=True, index=True)
    destination_ip = Column(String(64), nullable=True)
    file_hash = Column(String(128), nullable=True, index=True)
    domain = Column(String(255), nullable=True)
    url = Column(Text, nullable=True)
    
    # Asset Context
    agent_id = Column(String(64), nullable=True)     # Wazuh agent ID
    hostname = Column(String(255), nullable=True)
    user = Column(String(128), nullable=True)
    rule_id = Column(String(64), nullable=True)
    
    raw_payload = Column(JSON, nullable=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    incident = relationship("Incident", back_populates="alerts")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_number = Column(String(64), unique=True, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(32), default="medium")
    status = Column(String(32), default="open")       # open, investigating, contained, closed
    
    summary = Column(Text, nullable=True)             # AI narrative summary
    false_positive_score = Column(Float, default=0.0) # 0.0 - 1.0
    confidence_score = Column(Float, default=1.0)     # 0.0 - 1.0
    
    mitre_tactics = Column(JSON, default=list)        # ["Initial Access", "Execution"]
    mitre_techniques = Column(JSON, default=list)     # [{"id": "T1110", "name": "Brute Force"}]
    ai_analysis = Column(JSON, nullable=True)         # Full structured AI analysis output
    
    assigned_to = Column(String(128), default="Unassigned")
    alert_count = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    # Relationships
    alerts = relationship("Alert", back_populates="incident")
    executions = relationship("PlaybookExecution", back_populates="incident", cascade="all, delete-orphan")
    approvals = relationship("PendingApproval", back_populates="incident", cascade="all, delete-orphan")
    actions = relationship("ActionLog", back_populates="incident", cascade="all, delete-orphan")


class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(64), default="generic")  # brute_force, malware, web_attack, ddos, generic
    is_active = Column(Boolean, default=True)
    
    trigger_conditions = Column(JSON, default=dict)   # {"severity": ["high", "critical"], "sources": ["wazuh"]}
    graph_data = Column(JSON, nullable=True)          # React Flow nodes and edges
    yaml_definition = Column(Text, nullable=True)     # YAML representation
    
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    # Relationships
    executions = relationship("PlaybookExecution", back_populates="playbook")


class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"

    id = Column(Integer, primary_key=True, index=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.id", ondelete="CASCADE"))
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"))
    status = Column(String(32), default="running")    # running, completed, failed, waiting_approval
    current_step = Column(String(128), nullable=True)
    logs = Column(JSON, default=list)                 # [{"node_id": "1", "status": "success", "output": {...}}]
    
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)

    # Relationships
    playbook = relationship("Playbook", back_populates="executions")
    incident = relationship("Incident", back_populates="executions")


class PendingApproval(Base):
    __tablename__ = "pending_approvals"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"))
    playbook_execution_id = Column(Integer, ForeignKey("playbook_executions.id", ondelete="SET NULL"), nullable=True)
    
    action_type = Column(String(64), nullable=False)  # block_ip, isolate_wazuh_agent, cloudflare_block, send_notification
    connector = Column(String(64), nullable=False)    # windows_firewall, linux_ssh, cloudflare, wazuh, webhook
    target = Column(String(255), nullable=False)      # IP address, Agent ID, Hostname
    parameters = Column(JSON, default=dict)
    
    reason = Column(Text, nullable=False)             # AI rationale for approval
    risk_level = Column(String(32), default="medium") # low, medium, high
    status = Column(String(32), default="pending")    # pending, approved, rejected, executed, failed
    analyst_note = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)

    # Relationships
    incident = relationship("Incident", back_populates="approvals")


class ActionLog(Base):
    __tablename__ = "action_logs"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True)
    action_type = Column(String(64), nullable=False)
    connector = Column(String(64), nullable=False)
    target = Column(String(255), nullable=False)
    status = Column(String(32), default="success")    # success, failed, dry_run
    output_message = Column(Text, nullable=True)
    executed_by = Column(String(128), default="Analyst")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    incident = relationship("Incident", back_populates="actions")


class SystemSetting(Base):
    __tablename__ = "system_settings"

    key = Column(String(128), primary_key=True)
    value = Column(Text, nullable=True)
    category = Column(String(64), default="general") # ai, threat_intel, connectors, general
    is_secret = Column(Boolean, default=False)
    description = Column(String(255), nullable=True)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)


class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"

    id = Column(Integer, primary_key=True, index=True)
    ioc_type = Column(String(32), index=True)        # ip, domain, hash
    ioc_value = Column(String(255), index=True)
    source = Column(String(64))                      # ipapi, virustotal
    data = Column(JSON, nullable=False)
    malicious_score = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)

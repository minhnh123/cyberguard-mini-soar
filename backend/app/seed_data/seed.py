import json
from sqlalchemy.future import select
from app.models.models import Playbook, SystemSetting
from app.core.database import AsyncSessionLocal

INITIAL_PLAYBOOKS = [
    {
        "name": "SSH & RDP Brute Force Auto-Defense",
        "description": "Enriches attacker IP with Geolocation & VirusTotal, triages credential guessing activity with AI, and generates a Firewall block approval.",
        "category": "brute_force",
        "is_active": True,
        "trigger_conditions": {
            "severity": ["high", "critical", "medium"],
            "sources": ["wazuh", "suricata", "webhook", "edr"]
        },
        "graph_data": {
            "nodes": [
                {
                    "id": "node_1",
                    "type": "trigger",
                    "position": {"x": 50, "y": 150},
                    "data": {"label": "Alert Ingestion Trigger", "icon": "Radio", "description": "Receives brute force security alert"}
                },
                {
                    "id": "node_2",
                    "type": "enrichment",
                    "position": {"x": 300, "y": 150},
                    "data": {"label": "Threat Intel & Geo Lookup", "icon": "Globe", "description": "Queries IP-API & VirusTotal for attacker reputation"}
                },
                {
                    "id": "node_3",
                    "type": "ai_triage",
                    "position": {"x": 550, "y": 150},
                    "data": {"label": "AI Triage & MITRE Mapping", "icon": "Brain", "description": "Calculates severity, maps to T1110, drafts containment proposal"}
                },
                {
                    "id": "node_4",
                    "type": "human_approval",
                    "position": {"x": 800, "y": 150},
                    "data": {"label": "Analyst 1-Click Approval Gateway", "icon": "ShieldAlert", "description": "Queues Firewall block action for SOC Analyst review"}
                }
            ],
            "edges": [
                {"id": "e1-2", "source": "node_1", "target": "node_2"},
                {"id": "e2-3", "source": "node_2", "target": "node_3"},
                {"id": "e3-4", "source": "node_3", "target": "node_4"}
            ]
        },
        "yaml_definition": """name: SSH & RDP Brute Force Auto-Defense
category: brute_force
triggers:
  severity: [high, critical, medium]
workflow:
  - step: trigger
    type: alert_ingestion
  - step: enrich
    type: threat_intel_lookup
    sources: [ip-api, virustotal]
  - step: ai_analysis
    type: ai_triage
    mitre_focus: [T1110, T1110.001]
  - step: approval_gate
    type: human_approval
    action: block_ip
    connectors: [windows_firewall, linux_ssh]
"""
    },
    {
        "name": "Wazuh Ransomware & Malware Isolation",
        "description": "Detects high-impact malware or ransomware behavior, queries VirusTotal file hash reputation, and queues active Wazuh Agent quarantine.",
        "category": "malware",
        "is_active": True,
        "trigger_conditions": {
            "severity": ["critical", "high"],
            "sources": ["wazuh", "edr", "webhook"]
        },
        "graph_data": {
            "nodes": [
                {
                    "id": "node_1",
                    "type": "trigger",
                    "position": {"x": 50, "y": 150},
                    "data": {"label": "Malware/Ransomware Alert", "icon": "AlertTriangle", "description": "Triggered by Wazuh shadowcopy deletion or malware alert"}
                },
                {
                    "id": "node_2",
                    "type": "enrichment",
                    "position": {"x": 300, "y": 150},
                    "data": {"label": "VirusTotal Hash Reputation", "icon": "Search", "description": "Scans file hash across 70+ Antivirus engines"}
                },
                {
                    "id": "node_3",
                    "type": "ai_triage",
                    "position": {"x": 550, "y": 150},
                    "data": {"label": "AI Impact & MITRE T1486 Assessment", "icon": "Brain", "description": "Evaluates lateral movement risk & ransomware indicators"}
                },
                {
                    "id": "node_4",
                    "type": "human_approval",
                    "position": {"x": 800, "y": 150},
                    "data": {"label": "Wazuh Host Isolation Approval", "icon": "Lock", "description": "Analyst approval to isolate compromised endpoint"}
                }
            ],
            "edges": [
                {"id": "e1-2", "source": "node_1", "target": "node_2"},
                {"id": "e2-3", "source": "node_2", "target": "node_3"},
                {"id": "e3-4", "source": "node_3", "target": "node_4"}
            ]
        },
        "yaml_definition": """name: Wazuh Ransomware & Malware Isolation
category: malware
triggers:
  severity: [critical, high]
workflow:
  - step: trigger
    type: alert_ingestion
  - step: enrich
    type: virustotal_hash_lookup
  - step: ai_analysis
    type: ai_triage
    mitre_focus: [T1486, T1059]
  - step: approval_gate
    type: human_approval
    action: isolate_wazuh_agent
    connectors: [wazuh]
"""
    },
    {
        "name": "Cloudflare WAF Automated Web Attack Block",
        "description": "Intercepts SQL Injection / RCE exploits, checks attacker subnet, and queues immediate Cloudflare WAF block.",
        "category": "web_attack",
        "is_active": True,
        "trigger_conditions": {
            "severity": ["medium", "high", "critical"],
            "sources": ["suricata", "webhook", "wazuh"]
        },
        "graph_data": {
            "nodes": [
                {
                    "id": "node_1",
                    "type": "trigger",
                    "position": {"x": 50, "y": 150},
                    "data": {"label": "Web Exploit Alert", "icon": "Flame", "description": "Triggered by SQLi, RCE, or Path Traversal"}
                },
                {
                    "id": "node_2",
                    "type": "enrichment",
                    "position": {"x": 300, "y": 150},
                    "data": {"label": "Threat Intel & ASN Lookup", "icon": "Globe", "description": "Enriches origin IP and hosting provider"}
                },
                {
                    "id": "node_3",
                    "type": "ai_triage",
                    "position": {"x": 550, "y": 150},
                    "data": {"label": "AI Exploit Verification", "icon": "Brain", "description": "Maps to MITRE T1190 and confirms malicious intent"}
                },
                {
                    "id": "node_4",
                    "type": "human_approval",
                    "position": {"x": 800, "y": 150},
                    "data": {"label": "Cloudflare WAF IP Block", "icon": "ShieldCheck", "description": "Analyst approval to block attacker on Cloudflare WAF"}
                }
            ],
            "edges": [
                {"id": "e1-2", "source": "node_1", "target": "node_2"},
                {"id": "e2-3", "source": "node_2", "target": "node_3"},
                {"id": "e3-4", "source": "node_3", "target": "node_4"}
            ]
        },
        "yaml_definition": """name: Cloudflare WAF Automated Web Attack Block
category: web_attack
triggers:
  severity: [high, critical]
workflow:
  - step: trigger
    type: alert_ingestion
  - step: enrich
    type: threat_intel_lookup
  - step: ai_analysis
    type: ai_triage
    mitre_focus: [T1190]
  - step: approval_gate
    type: human_approval
    action: cloudflare_block
    connectors: [cloudflare]
"""
    },
    {
        "name": "Enterprise Identity Compromise & Token Revocation",
        "description": "Detects credential stuffing, stolen session tokens, or anomalous privilege escalation, validates user identity in IdP, and revokes active OAuth/SAML sessions.",
        "category": "identity",
        "is_active": True,
        "trigger_conditions": {
            "severity": ["high", "critical"],
            "sources": ["okta", "azure_ad", "wazuh", "webhook", "identity"]
        },
        "graph_data": {
            "nodes": [
                {
                    "id": "node_1",
                    "type": "trigger",
                    "position": {"x": 50, "y": 150},
                    "data": {"label": "Identity Anomaly Alert", "icon": "UserCheck", "description": "Triggered by credential stuffing or stolen session token"}
                },
                {
                    "id": "node_2",
                    "type": "enrichment",
                    "position": {"x": 300, "y": 150},
                    "data": {"label": "IdP User & Session Enrichment", "icon": "Search", "description": "Queries Okta/Entra ID for user groups, MFA status & active sessions"}
                },
                {
                    "id": "node_3",
                    "type": "ai_triage",
                    "position": {"x": 550, "y": 150},
                    "data": {"label": "AI Credential Risk Assessment", "icon": "Brain", "description": "Maps to MITRE T1078, calculates blast radius, suggests session termination"}
                },
                {
                    "id": "node_4",
                    "type": "human_approval",
                    "position": {"x": 800, "y": 150},
                    "data": {"label": "Revoke Sessions & Suspend Account", "icon": "UserX", "description": "Analyst approval to revoke all active tokens & suspend user in IdP"}
                }
            ],
            "edges": [
                {"id": "e1-2", "source": "node_1", "target": "node_2"},
                {"id": "e2-3", "source": "node_2", "target": "node_3"},
                {"id": "e3-4", "source": "node_3", "target": "node_4"}
            ]
        },
        "yaml_definition": """name: Enterprise Identity Compromise & Token Revocation
category: identity
triggers:
  severity: [high, critical]
workflow:
  - step: trigger
    type: alert_ingestion
  - step: enrich
    type: idp_user_lookup
  - step: ai_analysis
    type: ai_triage
    mitre_focus: [T1078, T1539]
  - step: approval_gate
    type: human_approval
    action: revoke_user_sessions
    connectors: [identity]
"""
    },
    {
        "name": "Hostile Ransomware & EDR Process Neutralization",
        "description": "Detects shadow copy deletion (vssadmin), mass file entropy changes, or malicious ransomware executables, isolates endpoint network, and terminates malicious PID.",
        "category": "edr",
        "is_active": True,
        "trigger_conditions": {
            "severity": ["critical"],
            "sources": ["edr", "wazuh", "crowdstrike", "webhook"]
        },
        "graph_data": {
            "nodes": [
                {
                    "id": "node_1",
                    "type": "trigger",
                    "position": {"x": 50, "y": 150},
                    "data": {"label": "EDR Ransomware Detection", "icon": "AlertTriangle", "description": "Triggered by vssadmin deletion or rapid file encryption"}
                },
                {
                    "id": "node_2",
                    "type": "enrichment",
                    "position": {"x": 300, "y": 150},
                    "data": {"label": "Process Tree & PID Analysis", "icon": "Cpu", "description": "Extracts malicious PID, parent process, and file hash reputation"}
                },
                {
                    "id": "node_3",
                    "type": "ai_triage",
                    "position": {"x": 550, "y": 150},
                    "data": {"label": "AI Ransomware Threat Verification", "icon": "Brain", "description": "Maps to MITRE T1486 & T1489, calculates endpoint damage risk"}
                },
                {
                    "id": "node_4",
                    "type": "human_approval",
                    "position": {"x": 800, "y": 150},
                    "data": {"label": "EDR Endpoint Isolation & Kill PID", "icon": "ShieldAlert", "description": "Analyst approval to isolate endpoint & terminate malicious process"}
                }
            ],
            "edges": [
                {"id": "e1-2", "source": "node_1", "target": "node_2"},
                {"id": "e2-3", "source": "node_2", "target": "node_3"},
                {"id": "e3-4", "source": "node_3", "target": "node_4"}
            ]
        },
        "yaml_definition": """name: Hostile Ransomware & EDR Process Neutralization
category: edr
triggers:
  severity: [critical]
workflow:
  - step: trigger
    type: alert_ingestion
  - step: enrich
    type: process_tree_lookup
  - step: ai_analysis
    type: ai_triage
    mitre_focus: [T1486, T1489]
  - step: approval_gate
    type: human_approval
    action: isolate_endpoint
    connectors: [edr]
"""
    }
]

async def seed_database():
    async with AsyncSessionLocal() as session:
        # Seed initial playbooks if missing
        result = await session.execute(select(Playbook))
        existing = result.scalars().all()
        existing_names = {p.name for p in existing}
        added = False
        for pb_data in INITIAL_PLAYBOOKS:
            if pb_data["name"] not in existing_names:
                pb = Playbook(
                    name=pb_data["name"],
                    description=pb_data["description"],
                    category=pb_data["category"],
                    is_active=pb_data["is_active"],
                    trigger_conditions=pb_data["trigger_conditions"],
                    graph_data=pb_data["graph_data"],
                    yaml_definition=pb_data["yaml_definition"]
                )
                session.add(pb)
                added = True
        if added:
            await session.commit()
            print("[Seed] Playbooks synchronized successfully.")

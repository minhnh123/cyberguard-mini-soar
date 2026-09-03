import json
import re
from typing import Dict, Any, List, Optional
import httpx
from sqlalchemy.future import select
from app.core.config import settings
from app.models.models import SystemSetting
from app.services.mitre_service import MitreService

SYSTEM_TRIAGE_PROMPT = """You are CyberGuard AI, an elite Tier-3 SOC Security Analyst and Incident Response Expert.
Analyze the provided security alert, enriched threat intelligence data, and asset context.
Provide a thorough security triage, detect false positives, map techniques to MITRE ATT&CK, and recommend safe, actionable containment and response actions.

You MUST reply with ONLY a valid JSON object strictly matching this schema:
{
  "severity": "critical" | "high" | "medium" | "low" | "info",
  "confidence_score": float (between 0.0 and 1.0, e.g. 0.95),
  "false_positive_score": float (between 0.0 and 1.0, e.g. 0.05),
  "is_false_positive": boolean,
  "attack_narrative": "Detailed executive summary of what happened, attacker's goal, and potential impact",
  "root_cause_analysis": "Technical explanation of the vulnerability or mechanism used",
  "mitre_tactics": ["Initial Access", "Credential Access", ...],
  "mitre_techniques": [
    {"id": "T1110", "name": "Brute Force"}
  ],
  "recommended_actions": [
    {
      "action_type": "block_ip" | "isolate_wazuh_agent" | "cloudflare_block" | "send_notification" | "custom_command",
      "connector": "windows_firewall" | "linux_ssh" | "cloudflare" | "wazuh" | "webhook",
      "target": "string (IP address, Agent ID, Hostname, etc.)",
      "parameters": {},
      "reason": "Clear justification why this action is necessary",
      "risk_level": "low" | "medium" | "high"
    }
  ]
}
"""

class AIService:
    @classmethod
    async def get_active_config(cls, db) -> Dict[str, str]:
        provider = settings.DEFAULT_AI_PROVIDER
        api_key = settings.DEFAULT_AI_API_KEY
        model = settings.DEFAULT_AI_MODEL
        custom_base_url = ""

        if db:
            result = await db.execute(
                select(SystemSetting).where(
                    SystemSetting.key.in_([
                        "AI_PROVIDER", "AI_API_KEY", "AI_MODEL", "AI_CUSTOM_BASE_URL",
                        "GEMINI_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY"
                    ])
                )
            )
            settings_map = {row.key: row.value for row in result.scalars().all()}
            if settings_map.get("AI_PROVIDER"):
                provider = settings_map["AI_PROVIDER"].lower()
            if settings_map.get("AI_MODEL"):
                model = settings_map["AI_MODEL"]
            if settings_map.get("AI_CUSTOM_BASE_URL"):
                custom_base_url = settings_map["AI_CUSTOM_BASE_URL"]

            # Specific provider keys
            if provider == "gemini":
                api_key = settings_map.get("GEMINI_API_KEY") or settings_map.get("AI_API_KEY") or api_key
            elif provider == "openai":
                api_key = settings_map.get("OPENAI_API_KEY") or settings_map.get("AI_API_KEY") or api_key
            elif provider == "deepseek":
                api_key = settings_map.get("DEEPSEEK_API_KEY") or settings_map.get("AI_API_KEY") or api_key
            elif settings_map.get("AI_API_KEY"):
                api_key = settings_map.get("AI_API_KEY")

        return {
            "provider": provider,
            "api_key": api_key or "",
            "model": model,
            "custom_base_url": custom_base_url
        }

    @classmethod
    async def triage_alert(cls, alert_data: Dict[str, Any], enrichment_data: Dict[str, Any], db=None) -> Dict[str, Any]:
        """
        Execute AI analysis for an alert. If no LLM API key is present or LLM call fails,
        use built-in deterministic heuristic SOC reasoning engine.
        """
        config = await cls.get_active_config(db)
        provider = config["provider"]
        api_key = config["api_key"]
        model = config["model"]

        # Pre-match MITRE techniques locally for context
        text_context = f"{alert_data.get('title', '')} {alert_data.get('description', '')} {json.dumps(alert_data.get('raw_payload', {}))}"
        local_mitre = MitreService.match_mitre_techniques(text_context)

        # Prepare context payload for LLM
        prompt_content = f"""
Analyze this security incident:
Alert Details:
- Title: {alert_data.get('title')}
- Source: {alert_data.get('source')}
- Initial Severity: {alert_data.get('severity')}
- Source IP: {alert_data.get('source_ip')}
- Destination IP: {alert_data.get('destination_ip')}
- File Hash: {alert_data.get('file_hash')}
- Domain: {alert_data.get('domain')}
- Wazuh Agent ID: {alert_data.get('agent_id')}
- Hostname: {alert_data.get('hostname')}
- User: {alert_data.get('user')}
- Description: {alert_data.get('description')}
- Raw Payload: {json.dumps(alert_data.get('raw_payload', {}), indent=2)}

Enrichment & Threat Intelligence:
{json.dumps(enrichment_data, indent=2)}

Preliminary MITRE ATT&CK matches:
{json.dumps(local_mitre, indent=2)}
"""

        if api_key:
            try:
                if provider == "gemini":
                    result = await cls._call_gemini(api_key, model, prompt_content)
                elif provider in ["openai", "deepseek", "custom"]:
                    result = await cls._call_openai_compatible(
                        provider, api_key, model, prompt_content, config.get("custom_base_url")
                    )
                else:
                    result = cls._fallback_heuristic_triage(alert_data, enrichment_data, local_mitre)
                
                if result:
                    return result
            except Exception as e:
                print(f"[AI Service Error] Cloud LLM error: {e}. Falling back to heuristic reasoning.")

        # Fallback heuristic SOC analysis
        return cls._fallback_heuristic_triage(alert_data, enrichment_data, local_mitre)

    @classmethod
    async def _call_gemini(cls, api_key: str, model_name: str, prompt: str) -> Optional[Dict[str, Any]]:
        # Use v1beta endpoint for Gemini
        if not model_name or "gemini" not in model_name:
            model_name = "gemini-1.5-flash"
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": SYSTEM_TRIAGE_PROMPT + "\n\n" + prompt}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json"
            }
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                return cls._clean_and_parse_json(text)
            else:
                print(f"[Gemini API Error] {resp.status_code}: {resp.text}")
                return None

    @classmethod
    async def _call_openai_compatible(
        cls, provider: str, api_key: str, model_name: str, prompt: str, custom_base_url: str = ""
    ) -> Optional[Dict[str, Any]]:
        base_urls = {
            "openai": "https://api.openai.com/v1",
            "deepseek": "https://api.deepseek.com/v1",
            "custom": custom_base_url.rstrip("/") if custom_base_url else "http://localhost:11434/v1"
        }
        base_url = base_urls.get(provider, "https://api.openai.com/v1")
        url = f"{base_url}/chat/completions"

        if not model_name:
            model_name = "deepseek-chat" if provider == "deepseek" else "gpt-4o-mini"

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": model_name,
            "messages": [
                {"role": "system", "content": SYSTEM_TRIAGE_PROMPT},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"} if provider != "deepseek" else None
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                text = data["choices"][0]["message"]["content"]
                return cls._clean_and_parse_json(text)
            else:
                print(f"[{provider} API Error] {resp.status_code}: {resp.text}")
                return None

    @staticmethod
    def _clean_and_parse_json(text: str) -> Optional[Dict[str, Any]]:
        try:
            # Strip markdown code blocks if present
            cleaned = text.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            elif cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            return json.loads(cleaned.strip())
        except Exception:
            match = re.search(r'\{.*\}', text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(0))
                except Exception:
                    pass
            return None

    @classmethod
    def _fallback_heuristic_triage(
        cls, alert: Dict[str, Any], enrichment: Dict[str, Any], mitre_matches: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Expert deterministic SOC heuristic engine when external LLM is offline or unconfigured.
        """
        title = alert.get("title", "").lower()
        desc = alert.get("description", "").lower()
        src_ip = alert.get("source_ip")
        file_hash = alert.get("file_hash")
        agent_id = alert.get("agent_id")
        severity = alert.get("severity", "medium").lower()

        tactics = list(set([m["tactic"] for m in mitre_matches])) or ["Initial Access"]
        techniques = [{"id": m["id"], "name": m["name"]} for m in mitre_matches]

        confidence = 0.90
        false_positive_score = 0.05
        is_false_positive = False
        recommended_actions = []

        # Check VirusTotal enrichment
        vt_data = enrichment.get("virustotal", {})
        if vt_data.get("reputation") == "malicious":
            severity = "critical"
            confidence = 0.98
            false_positive_score = 0.01

        # Check IP Geolocation enrichment
        geo_data = enrichment.get("ip_geo", {})
        country = geo_data.get("country", "Unknown")

        # Attack scenario deduction
        if "brute force" in title or "ssh" in title or "failed password" in title or "logon" in title:
            narrative = f"Detected high-volume automated authentication failures originating from external source IP {src_ip} ({country}). This indicates an active credential guessing / brute force campaign targeting remote access."
            root_cause = "Exposed authentication interface subjected to password spray or dictionary attack."
            if src_ip and not geo_data.get("is_private"):
                recommended_actions.append({
                    "action_type": "block_ip",
                    "connector": "linux_ssh",
                    "target": src_ip,
                    "parameters": {"direction": "inbound", "action": "block", "host": "192.168.56.107"},
                    "reason": f"Block hostile external IP {src_ip} ({country}) on Linux VM iptables firewall.",
                    "risk_level": "low"
                })
                recommended_actions.append({
                    "action_type": "block_ip",
                    "connector": "windows_firewall",
                    "target": src_ip,
                    "parameters": {"direction": "inbound", "action": "block"},
                    "reason": f"Block hostile external IP {src_ip} ({country}) on Host Windows Defender Firewall.",
                    "risk_level": "low"
                })

        elif "ransomware" in title or "shadow copy" in title or "encrypt" in title:
            severity = "critical"
            confidence = 0.99
            narrative = f"Critical alert: Suspected ransomware behavior detected on host {alert.get('hostname', 'endpoint')}. Active defense evasion and potential volume shadow copy deletion identified."
            root_cause = "Unauthorized script or malware attempting mass file modification and backup destruction."
            if not techniques:
                techniques = [{"id": "T1486", "name": "Data Encrypted for Impact"}]
                tactics = ["Impact", "Defense Evasion"]
            if agent_id:
                recommended_actions.append({
                    "action_type": "isolate_wazuh_agent",
                    "connector": "wazuh",
                    "target": str(agent_id),
                    "parameters": {"agent_id": str(agent_id), "command": "isolate"},
                    "reason": f"Immediately isolate compromised endpoint (Agent ID: {agent_id}) to prevent lateral movement and ransomware spread.",
                    "risk_level": "medium"
                })

        elif "malware" in title or file_hash or "trojan" in title:
            severity = "high"
            narrative = f"Malicious executable execution detected on host {alert.get('hostname', 'endpoint')} (Hash: {file_hash or 'N/A'}). Potential payload dropped onto disk."
            root_cause = "Malicious binary or macro-enabled script execution."
            if not techniques:
                techniques = [{"id": "T1059", "name": "Command and Scripting Interpreter"}]
                tactics = ["Execution"]
            if agent_id:
                recommended_actions.append({
                    "action_type": "isolate_wazuh_agent",
                    "connector": "wazuh",
                    "target": str(agent_id),
                    "parameters": {"agent_id": str(agent_id), "command": "isolate"},
                    "reason": f"Isolate host {alert.get('hostname', agent_id)} for forensic triage.",
                    "risk_level": "medium"
                })
            if src_ip and not geo_data.get("is_private"):
                recommended_actions.append({
                    "action_type": "block_ip",
                    "connector": "windows_firewall",
                    "target": src_ip,
                    "parameters": {"direction": "inbound", "action": "block"},
                    "reason": f"Block C2 communication / attacker origin IP {src_ip}.",
                    "risk_level": "low"
                })

        elif "sql injection" in title or "sqli" in title or "rce" in title or "exploit" in title:
            severity = "high"
            narrative = f"Web application exploit attempt detected against public service from source IP {src_ip} ({country}). Patterns match SQL Injection or Remote Code Execution attempts."
            root_cause = "Unsanitized user inputs or vulnerable web application endpoint."
            if not techniques:
                techniques = [{"id": "T1190", "name": "Exploit Public-Facing Application"}]
                tactics = ["Initial Access"]
            if src_ip and not geo_data.get("is_private"):
                recommended_actions.append({
                    "action_type": "cloudflare_block",
                    "connector": "cloudflare",
                    "target": src_ip,
                    "parameters": {"mode": "block", "notes": "Automated SOAR block for web attack"},
                    "reason": f"Add attacker IP {src_ip} to Cloudflare WAF IP Block list.",
                    "risk_level": "low"
                })

        else:
            narrative = f"Suspicious security event logged: '{alert.get('title')}'. Automated triage identified potential security anomaly requiring analyst review."
            root_cause = "Unclassified security event or baseline deviation."
            if not techniques:
                techniques = [{"id": "T1046", "name": "Network Service Discovery"}]
                tactics = ["Discovery"]

        return {
            "severity": severity,
            "confidence_score": confidence,
            "false_positive_score": false_positive_score,
            "is_false_positive": is_false_positive,
            "attack_narrative": narrative,
            "root_cause_analysis": root_cause,
            "mitre_tactics": tactics,
            "mitre_techniques": techniques,
            "recommended_actions": recommended_actions
        }

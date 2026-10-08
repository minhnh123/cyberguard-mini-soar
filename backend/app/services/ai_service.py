import json
import logging
from typing import Dict, Any, Optional
from sqlalchemy.future import select
from app.core.config import settings
from app.models.models import SystemSetting
from app.services.mitre_service import MitreService
from app.services.ai import SYSTEM_TRIAGE_PROMPT, LLMClient, HeuristicEngine

logger = logging.getLogger("soar.ai_service")


class AIService:
    """
    Tier-3 AI SOC Triage Orchestrator.
    Combines autonomous ReAct loop, cloud LLM execution, and deterministic heuristic fallback.
    """
    _clean_and_parse_json = LLMClient.clean_and_parse_json
    _call_gemini = LLMClient.call_gemini
    _call_openai_compatible = LLMClient.call_openai_compatible
    _build_react_investigation_trail = HeuristicEngine.build_react_investigation_trail
    _fallback_heuristic_triage = HeuristicEngine.fallback_heuristic_triage

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

            if api_key:
                from app.core.vault import VaultService
                api_key = VaultService.decrypt(api_key)

        return {
            "provider": provider,
            "api_key": api_key or "",
            "model": model,
            "custom_base_url": custom_base_url
        }

    @classmethod
    async def triage_alert(
        cls,
        alert_data: Dict[str, Any],
        enrichment_data: Dict[str, Any],
        db=None,
        analyst_query: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute AI analysis for an alert using autonomous ReAct (Reasoning + Acting) loop.
        If no LLM API key is present or LLM call fails, use built-in ReAct heuristic SOC reasoning engine.
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
Analyze this security incident using the ReAct (Reasoning + Acting) investigation process:
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
        # Load Few-Shot In-Context Learning from historical analyst feedback
        try:
            from app.services.feedback_service import FeedbackService
            few_shot_context = await FeedbackService.get_few_shot_prompt_context(alert_data, limit=3, db=db)
            if few_shot_context:
                prompt_content += f"\n{few_shot_context}\n"
        except Exception:
            pass

        if analyst_query:
            prompt_content += f"\nSpecial Analyst Investigation Directives: {analyst_query}\n"

        if api_key:
            try:
                if provider == "gemini":
                    result = await cls._call_gemini(api_key, model, prompt_content)
                elif provider in ["openai", "deepseek", "custom"]:
                    result = await cls._call_openai_compatible(
                        provider, api_key, model, prompt_content, config.get("custom_base_url")
                    )
                else:
                    result = await cls._fallback_heuristic_triage(alert_data, enrichment_data, local_mitre, db=db, analyst_query=analyst_query)

                if result:
                    if "investigation_trail" not in result or not result["investigation_trail"]:
                        result["investigation_trail"] = await cls._build_react_investigation_trail(
                            alert_data, enrichment_data, db=db, analyst_query=analyst_query
                        )
                    return result
            except Exception as e:
                logger.warning(f"[AI Service Error] Cloud LLM error: {e}. Falling back to heuristic reasoning.")

        # Fallback heuristic SOC analysis with full ReAct multi-turn trail
        return await cls._fallback_heuristic_triage(alert_data, enrichment_data, local_mitre, db=db, analyst_query=analyst_query)

import json
import logging
import re
from typing import Dict, Any, Optional
import httpx
from app.services.ai.prompts import SYSTEM_TRIAGE_PROMPT

logger = logging.getLogger("soar.llm_client")


class LLMClient:
    @staticmethod
    def clean_and_parse_json(text: str) -> Optional[Dict[str, Any]]:
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
    async def call_gemini(cls, api_key: str, model_name: str, prompt: str) -> Optional[Dict[str, Any]]:
        """
        Invokes Google Gemini API with automatic model fallback (gemini-2.0-flash -> gemini-1.5-flash).
        Handles transient 429 quota exhaustion and 503 high demand gracefully.
        """
        primary_model = model_name if (model_name and "gemini" in model_name) else "gemini-2.0-flash"
        # Determine fallback model candidate
        fallback_model = "gemini-1.5-flash" if primary_model != "gemini-1.5-flash" else "gemini-2.0-flash"
        candidate_models = [primary_model, fallback_model]

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

        async with httpx.AsyncClient(timeout=10.0) as client:
            for current_model in candidate_models:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{current_model}:generateContent?key={api_key}"
                try:
                    resp = await client.post(url, json=payload)
                    if resp.status_code == 200:
                        data = resp.json()
                        candidates = data.get("candidates", [])
                        if candidates and "content" in candidates[0]:
                            parts = candidates[0]["content"].get("parts", [])
                            if parts and "text" in parts[0]:
                                parsed = cls.clean_and_parse_json(parts[0]["text"])
                                if parsed:
                                    return parsed
                    else:
                        logger.warning(
                            f"[Gemini API Warning] Model '{current_model}' returned {resp.status_code}: {resp.text[:200]}..."
                        )
                except Exception as ex:
                    logger.warning(f"[Gemini API Exception] Model '{current_model}' call failed: {ex}")

        logger.error("[Gemini API Error] All Gemini candidate models failed. Falling back to heuristic engine.")
        return None

    @classmethod
    async def call_openai_compatible(
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

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    choices = data.get("choices", [])
                    if choices and "message" in choices[0]:
                        content = choices[0]["message"].get("content", "")
                        return cls.clean_and_parse_json(content)
                else:
                    logger.warning(f"[{provider} API Error] {resp.status_code}: {resp.text[:200]}")
                    return None
        except Exception as e:
            logger.warning(f"[{provider} API Exception] {e}")
            return None

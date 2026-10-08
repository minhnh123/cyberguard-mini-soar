import json
import re
from typing import Dict, Any, Optional
import httpx
from app.services.ai.prompts import SYSTEM_TRIAGE_PROMPT


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
        if not model_name or "gemini" not in model_name:
            model_name = "gemini-3.8-flash"
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
                return cls.clean_and_parse_json(text)
            else:
                print(f"[Gemini API Error] {resp.status_code}: {resp.text}")
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

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                text = data["choices"][0]["message"]["content"]
                return cls.clean_and_parse_json(text)
            else:
                print(f"[{provider} API Error] {resp.status_code}: {resp.text}")
                return None

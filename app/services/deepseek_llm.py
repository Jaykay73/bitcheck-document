import json
import os
from typing import Any

from openai import OpenAI

from app.config import Settings
from app.schemas.document_verification import DeepSeekAnalysis
from app.services.prompt_builder import SYSTEM_MESSAGE

DEFAULT_DEEPSEEK_JSON = {
    "document_type": "",
    "extracted_fields": {},
    "missing_expected_fields": [],
    "field_confidence": 0.0,
    "field_flags": [],
    "fraud_risk_score": 0.0,
    "ai_generated_text_likelihood": 0.0,
    "suspicious_claims": [],
    "signals": [],
    "summary": "",
    "external_verification_required": True,
    "recommended_actions": [],
}


class DeepSeekLLM:
    def __init__(self, settings: Settings, timeout_seconds: float = 15.0) -> None:
        self.settings = settings
        self.timeout_seconds = timeout_seconds
        self.model = os.getenv("DEEPSEEK_MODEL", settings.deepseek_model or "deepseek-chat")
        self.api_key = os.getenv("DEEPSEEK_API_KEY") or settings.deepseek_api_key
        self.base_url = os.getenv("DEEPSEEK_BASE_URL", settings.deepseek_base_url or "https://api.deepseek.com")

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def analyze(self, prompt: str) -> tuple[DeepSeekAnalysis, dict[str, Any]]:
        if not self.api_key:
            return (
                DeepSeekAnalysis(
                    used=False,
                    model=self.model,
                    document_type_inferred=None,
                    summary="",
                    external_verification_required=True,
                    warnings=["DeepSeek API key is not configured; LLM reasoning was skipped."],
                ),
                dict(DEFAULT_DEEPSEEK_JSON),
            )

        warnings: list[str] = []
        try:
            client = OpenAI(api_key=self.api_key, base_url=self.base_url, timeout=self.timeout_seconds)
            response = client.chat.completions.create(
                model=self.model,
                temperature=0.1,
                messages=[
                    {"role": "system", "content": SYSTEM_MESSAGE},
                    {"role": "user", "content": prompt},
                ],
            )
            content = response.choices[0].message.content or ""
        except Exception as exc:
            warnings.append(f"DeepSeek analysis failed: {exc.__class__.__name__}")
            return (
                DeepSeekAnalysis(
                    used=True,
                    model=self.model,
                    document_type_inferred=None,
                    summary="",
                    external_verification_required=True,
                    warnings=warnings,
                ),
                dict(DEFAULT_DEEPSEEK_JSON),
            )

        parsed, parse_warnings = self.parse_json_response(content)
        warnings.extend(parse_warnings)
        return (
            DeepSeekAnalysis(
                used=True,
                model=self.model,
                document_type_inferred=self._str_or_none(parsed.get("document_type")),
                summary=str(parsed.get("summary") or ""),
                external_verification_required=bool(parsed.get("external_verification_required", True)),
                warnings=warnings,
            ),
            parsed,
        )

    def parse_json_response(self, content: str) -> tuple[dict[str, Any], list[str]]:
        warnings: list[str] = []
        try:
            return self._with_defaults(json.loads(content)), warnings
        except (TypeError, json.JSONDecodeError):
            pass

        start = content.find("{")
        end = content.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return self._with_defaults(json.loads(content[start : end + 1])), warnings
            except json.JSONDecodeError:
                pass

        warnings.append("DeepSeek returned invalid JSON; safe fallback was used.")
        return dict(DEFAULT_DEEPSEEK_JSON), warnings

    def _with_defaults(self, parsed: Any) -> dict[str, Any]:
        if not isinstance(parsed, dict):
            return dict(DEFAULT_DEEPSEEK_JSON)
        merged = dict(DEFAULT_DEEPSEEK_JSON)
        merged.update(parsed)
        merged["field_confidence"] = self._score(merged.get("field_confidence"))
        merged["fraud_risk_score"] = self._score(merged.get("fraud_risk_score"))
        merged["ai_generated_text_likelihood"] = self._score(merged.get("ai_generated_text_likelihood"))
        merged["extracted_fields"] = merged["extracted_fields"] if isinstance(merged.get("extracted_fields"), dict) else {}
        for key in ["missing_expected_fields", "field_flags", "suspicious_claims", "signals", "recommended_actions"]:
            merged[key] = merged[key] if isinstance(merged.get(key), list) else []
        merged["summary"] = str(merged.get("summary") or "")
        merged["document_type"] = str(merged.get("document_type") or "")
        merged["external_verification_required"] = bool(merged.get("external_verification_required", True))
        return merged

    def _score(self, value: Any) -> float:
        try:
            return round(min(max(float(value), 0.0), 1.0), 2)
        except (TypeError, ValueError):
            return 0.0

    def _str_or_none(self, value: Any) -> str | None:
        text = str(value or "").strip()
        return text or None

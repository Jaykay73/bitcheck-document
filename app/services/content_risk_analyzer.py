from app.config import Settings
from app.schemas.document_verification import ContentRiskAnalysis, DeepSeekAnalysis
from app.services.deepseek_llm import DeepSeekLLM
from app.services.document_context import is_contextual_longform
from app.services.prompt_builder import PromptBuilder
from app.utils.text_utils import excerpt_text, normalize_text

URGENCY_KEYWORDS = ["urgent", "immediately", "before midnight", "deadline", "act now", "last chance", "hurry"]
FINANCIAL_KEYWORDS = [
    "payment",
    "transfer",
    "account number",
    "bank",
    "grant",
    "scholarship",
    "loan",
    "investment",
    "₦",
    "naira",
    "dollars",
    "crypto",
    "wallet",
]
SENSITIVE_KEYWORDS = ["otp", "bvn", "nin", "password", "pin", "verification code", "login"]
FRAUD_LIKE_KEYWORDS = [
    "claim your reward",
    "processing fee",
    "activation fee",
    "release funds",
    "guaranteed approval",
    "double your money",
    "pay before verification",
    "bypass official channel",
]
AI_STYLE_KEYWORDS = [
    "as an ai",
    "in conclusion",
    "it is important to note",
    "furthermore",
    "moreover",
    "comprehensive solution",
]


class ContentRiskAnalyzer:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def analyze(
        self,
        document_text: str,
        run_llm_analysis: bool,
        metadata_summary: dict,
        qr_summary: dict,
        field_results: dict,
        heuristic_signals: dict,
    ) -> tuple[ContentRiskAnalysis, DeepSeekAnalysis]:
        heuristic = self._heuristic_analysis(document_text)
        llm = DeepSeekLLM(self.settings)
        deepseek_analysis = DeepSeekAnalysis(
            used=False,
            model=llm.model,
            document_type_inferred=None,
            summary="",
            external_verification_required=True,
            warnings=[],
        )
        llm_payload = None

        if run_llm_analysis and llm.available:
            prompt = PromptBuilder().build_document_analysis_prompt(
                document_text=document_text,
                metadata_summary=metadata_summary,
                qr_summary=qr_summary,
                field_results=field_results,
                heuristic_risk={**heuristic_signals, **heuristic},
            )
            deepseek_analysis, llm_payload = llm.analyze(prompt)
        elif run_llm_analysis:
            deepseek_analysis = llm.analyze("")[0]

        content_risk = self._merge_with_llm(heuristic, llm_payload)
        warnings = list(content_risk.warnings)
        if run_llm_analysis:
            warnings.extend(deepseek_analysis.warnings)
        return (
            ContentRiskAnalysis(
                checked=True,
                fraud_risk_score=content_risk.fraud_risk_score,
                ai_generated_text_likelihood=content_risk.ai_generated_text_likelihood,
                suspicious_claims=content_risk.suspicious_claims,
                signals=content_risk.signals,
                summary=content_risk.summary,
                warnings=warnings,
            ),
            deepseek_analysis,
        )

    def _heuristic_analysis(self, document_text: str) -> dict:
        text = document_text or ""
        normalized = normalize_text(text)
        signals: list[str] = []
        suspicious_claims: list[str] = []
        risk = 0.0

        urgency = self._matched_keywords(normalized, URGENCY_KEYWORDS)
        financial = self._matched_keywords(normalized, FINANCIAL_KEYWORDS)
        sensitive = self._matched_keywords(normalized, SENSITIVE_KEYWORDS)
        fraud_like = self._matched_keywords(normalized, FRAUD_LIKE_KEYWORDS)
        ai_style = self._matched_keywords(normalized, AI_STYLE_KEYWORDS)

        if urgency:
            signals.append("urgency_language")
            suspicious_claims.extend(urgency)
            risk += 0.15
        if financial:
            signals.append("financial_instruction_or_claim")
            suspicious_claims.extend(financial)
            risk += 0.2
        if sensitive:
            signals.append("sensitive_identifier_or_secret_request")
            suspicious_claims.extend(sensitive)
            risk += 0.35
        if fraud_like:
            signals.append("fraud_like_wording")
            suspicious_claims.extend(fraud_like)
            risk += 0.35
        if urgency and financial:
            signals.append("urgent_financial_request")
            risk += 0.1
        if sensitive and financial:
            signals.append("sensitive_data_requested_with_payment_context")
            risk += 0.1

        ai_likelihood = min(0.15 * len(ai_style), 0.45)
        if len(text.split()) > 120 and "I " not in text:
            ai_likelihood = max(ai_likelihood, 0.25)

        summary = self._summary(signals)
        return {
            "fraud_risk_score": round(min(risk, 1.0), 2),
            "ai_generated_text_likelihood": round(ai_likelihood, 2),
            "suspicious_claims": list(dict.fromkeys(suspicious_claims)),
            "signals": signals,
            "summary": summary,
            "warnings": [],
        }

    def _merge_with_llm(self, heuristic: dict, llm_payload: dict | None) -> ContentRiskAnalysis:
        if not llm_payload:
            return ContentRiskAnalysis(checked=True, **heuristic)

        llm_document_type = str(llm_payload.get("document_type") or "")
        llm_risk = self._score(llm_payload.get("fraud_risk_score"))
        llm_claims = self._list(llm_payload.get("suspicious_claims"))
        llm_signals = self._list(llm_payload.get("signals"))
        contextual_longform = is_contextual_longform(llm_document_type)

        if contextual_longform and llm_risk <= 0.25:
            suspicious_claims = llm_claims
            signals = llm_signals
            fraud_risk = min(max(llm_risk, heuristic["fraud_risk_score"] * 0.35), 0.25)
            if heuristic["signals"]:
                signals.append("heuristic_keywords_contextualized_by_llm")
            signals = list(dict.fromkeys(signals))
        else:
            suspicious_claims = list(dict.fromkeys(heuristic["suspicious_claims"] + llm_claims))
            signals = list(dict.fromkeys(heuristic["signals"] + llm_signals))
            fraud_risk = max(heuristic["fraud_risk_score"], llm_risk)

        ai_likelihood = max(heuristic["ai_generated_text_likelihood"], self._score(llm_payload.get("ai_generated_text_likelihood")))
        summary = str(llm_payload.get("summary") or heuristic["summary"])
        return ContentRiskAnalysis(
            checked=True,
            fraud_risk_score=round(fraud_risk, 2),
            ai_generated_text_likelihood=round(ai_likelihood, 2),
            suspicious_claims=suspicious_claims,
            signals=signals,
            summary=excerpt_text(summary, 500),
            warnings=[],
        )

    def _matched_keywords(self, normalized_text: str, keywords: list[str]) -> list[str]:
        return [keyword for keyword in keywords if normalize_text(keyword) in normalized_text]

    def _summary(self, signals: list[str]) -> str:
        if not signals:
            return "No high-risk content wording was detected by heuristic checks."
        return "Heuristic content checks found risk signals: " + ", ".join(signals) + "."

    def _list(self, value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(item) for item in value if str(item).strip()]

    def _score(self, value: object) -> float:
        try:
            return min(max(float(value), 0.0), 1.0)
        except (TypeError, ValueError):
            return 0.0

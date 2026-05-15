from dataclasses import dataclass
from typing import Any

from app.schemas.document_verification import TrustAnalysis
from app.services.document_context import is_contextual_longform

WEIGHTS = {
    "metadata_risk": 0.12,
    "pdf_structure_risk": 0.10,
    "text_consistency_risk": 0.18,
    "qr_risk": 0.15,
    "forensic_risk": 0.20,
    "field_risk": 0.12,
    "content_risk": 0.13,
}

SEVERITY_ORDER = {
    "Likely Authentic": 0,
    "Low Risk": 1,
    "Suspicious": 2,
    "High Risk": 3,
    "Very High Risk": 4,
}

TRUST_CAPS = {
    "Suspicious": 59,
    "High Risk": 39,
    "Very High Risk": 19,
}


@dataclass(frozen=True)
class RiskModule:
    key: str
    risk_score: float


class TrustScorer:
    def score(self, modules: dict[str, Any]) -> TrustAnalysis:
        risk_modules = self._available_risks(modules)
        risk_score = self._weighted_risk(risk_modules)
        trust_score = round((1 - risk_score) * 100)
        applied_overrides, minimum_level = self._overrides(modules, len(risk_modules))
        trust_score = self._apply_minimum_level(trust_score, minimum_level)
        risk_level, decision = self._level_and_decision(trust_score)

        return TrustAnalysis(
            trust_score=trust_score,
            risk_score=round(risk_score, 2),
            risk_level=risk_level,
            decision=decision,
            available_modules=[module.key for module in risk_modules],
            applied_overrides=applied_overrides,
            evidence_count=len(risk_modules),
        )

    def _available_risks(self, modules: dict[str, Any]) -> list[RiskModule]:
        contextual_longform = self._contextual_longform(modules)
        candidates = {
            "metadata_risk": self._score(self._get(modules.get("metadata"), "metadata_risk_score")),
            "pdf_structure_risk": self._score(self._get(modules.get("pdf_analysis"), "structure_risk_score")),
            "text_consistency_risk": self._score(self._get(modules.get("text_consistency"), "risk_score")),
            "qr_risk": self._score(self._get(modules.get("qr_analysis"), "risk_score")),
            "forensic_risk": self._score(self._get(modules.get("forensics"), "visual_tampering_risk_score")),
            "field_risk": self._score(self._get(modules.get("fields"), "field_risk_score")),
            "content_risk": self._score(self._get(modules.get("content_risk"), "fraud_risk_score")),
        }
        if contextual_longform:
            if self._has_consistent_text_and_metadata(modules):
                candidates["forensic_risk"] = self._cap(candidates["forensic_risk"], 0.35)
            candidates["field_risk"] = self._cap(candidates["field_risk"], 0.25)
        return [RiskModule(key, score) for key, score in candidates.items() if score is not None]

    def _weighted_risk(self, risk_modules: list[RiskModule]) -> float:
        if not risk_modules:
            return 0.5
        total_weight = sum(WEIGHTS[module.key] for module in risk_modules)
        return sum(module.risk_score * (WEIGHTS[module.key] / total_weight) for module in risk_modules)

    def _overrides(self, modules: dict[str, Any], evidence_count: int) -> tuple[list[str], str | None]:
        overrides: list[tuple[str, str]] = []
        qr = modules.get("qr_analysis")
        metadata = modules.get("metadata")
        pdf = modules.get("pdf_analysis")
        text_consistency = modules.get("text_consistency")
        forensics = modules.get("forensics")
        text_extraction = modules.get("text_extraction")
        contextual_longform = self._contextual_longform(modules)

        qr_flags = set(self._get(qr, "flags") or [])
        if qr_flags.intersection({"shortened_url", "suspicious_url_keyword"}):
            overrides.append(("QR code points to a suspicious shortened/payment/login URL.", "Suspicious"))
        if self._get(self._get(qr, "qr_text_consistency"), "mismatch_flags"):
            overrides.append(("QR code conflicts with extracted document fields.", "High Risk"))
        if self._get(text_consistency, "status") == "low_match" or (self._score(self._get(text_consistency, "risk_score")) or 0) >= 0.7:
            overrides.append(("OCR/PDF text mismatch is strong.", "Suspicious"))
        if self._get(metadata, "ai_tool_detected"):
            overrides.append(("AI tool metadata detected.", "Suspicious"))
        forensic_score = self._score(self._get(forensics, "visual_tampering_risk_score")) or 0
        if contextual_longform and forensic_score >= 0.5 and self._has_consistent_text_and_metadata(modules):
            overrides.append(("Visual forensic findings were downgraded because text, metadata, and LLM context fit a long-form document.", "Suspicious"))
        elif forensic_score >= 0.5:
            overrides.append(("Strong visual tampering risk detected.", "High Risk"))
        if self._get(pdf, "is_encrypted") and not self._get(pdf, "rendered_pages"):
            overrides.append(("Encrypted PDF has limited extraction.", "Suspicious"))
        if self._insufficient_document_evidence(pdf, metadata, text_extraction):
            overrides.append(("No OCR, no text layer, and no metadata found; evidence is insufficient.", "Suspicious"))
        if evidence_count < 3:
            overrides.append(("Too little evidence was available for a confident automated decision.", "Suspicious"))

        minimum_level: str | None = None
        for _, level in overrides:
            if minimum_level is None or SEVERITY_ORDER[level] > SEVERITY_ORDER[minimum_level]:
                minimum_level = level
        return [message for message, _ in overrides], minimum_level

    def _contextual_longform(self, modules: dict[str, Any]) -> bool:
        deepseek = modules.get("deepseek_analysis")
        fields = modules.get("fields")
        return is_contextual_longform(self._get(deepseek, "document_type_inferred")) or is_contextual_longform(self._get(fields, "document_type"))

    def _has_consistent_text_and_metadata(self, modules: dict[str, Any]) -> bool:
        metadata = modules.get("metadata")
        text_consistency = modules.get("text_consistency")
        content_risk = modules.get("content_risk")
        metadata_low = (self._score(self._get(metadata, "metadata_risk_score")) or 0) <= 0.2
        content_low = (self._score(self._get(content_risk, "fraud_risk_score")) or 0) <= 0.3
        text_status = self._get(text_consistency, "status")
        text_low = text_status in {"strong_match", "not_applicable"} or (self._score(self._get(text_consistency, "risk_score")) or 0) <= 0.2
        return bool(metadata_low and content_low and text_low)

    def _insufficient_document_evidence(self, pdf: Any, metadata: Any, text_extraction: Any) -> bool:
        no_ocr = not self._get(text_extraction, "ocr_text_found")
        no_text_layer = pdf is not None and not self._get(pdf, "has_text_layer")
        no_metadata = not self._get(metadata, "metadata_found")
        return bool(no_ocr and no_text_layer and no_metadata)

    def _apply_minimum_level(self, trust_score: int, minimum_level: str | None) -> int:
        if minimum_level is None:
            return trust_score
        return min(trust_score, TRUST_CAPS[minimum_level])

    def _level_and_decision(self, trust_score: int) -> tuple[str, str]:
        if trust_score >= 80:
            return "Likely Authentic", "approve"
        if trust_score >= 60:
            return "Low Risk", "approve"
        if trust_score >= 40:
            return "Suspicious", "review"
        if trust_score >= 20:
            return "High Risk", "block_or_manual_review"
        return "Very High Risk", "block_or_manual_review"

    def _score(self, value: Any) -> float | None:
        if value is None:
            return None
        try:
            return min(max(float(value), 0.0), 1.0)
        except (TypeError, ValueError):
            return None

    def _cap(self, value: float | None, maximum: float) -> float | None:
        if value is None:
            return None
        return min(value, maximum)

    def _get(self, value: Any, key: str) -> Any:
        if value is None:
            return None
        if isinstance(value, dict):
            return value.get(key)
        return getattr(value, key, None)

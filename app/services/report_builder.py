import os
from pathlib import Path
from typing import Any

from app.schemas.document_verification import (
    ContentRiskAnalysis,
    DeepSeekAnalysis,
    DocumentVerificationReport,
    FieldExtractionAnalysis,
    FileValidationResult,
    ForensicAnalysis,
    ImageAnalysis,
    MetadataAnalysis,
    PdfAnalysis,
    QRAnalysis,
    TextConsistencyAnalysis,
    TextExtractionAnalysis,
    VerificationInput,
)
from app.services.trust_scorer import TrustScorer

LIMITATIONS = [
    "BitCheck provides a risk-based estimate, not legal proof of forgery or authenticity.",
    "Missing metadata does not prove a document is fake.",
    "Editing software metadata does not automatically prove manipulation.",
    "OCR may be inaccurate on low-quality scans.",
    "QR code detection does not mean the linked source is authentic unless externally verified.",
    "QR URLs are analyzed structurally but are not opened or browsed.",
    "Forensic visual analysis is not court-grade evidence.",
    "DeepSeek analysis does not perform live web or issuer database verification.",
    "High-stakes documents should be manually verified with the issuing authority.",
]


class ReportBuilder:
    def build(
        self,
        *,
        verification_id: str,
        status: str,
        processing_time_ms: int,
        verification_input: VerificationInput,
        file_validation: FileValidationResult,
        pdf_analysis: PdfAnalysis | None,
        image_analysis: ImageAnalysis | None,
        metadata: MetadataAnalysis,
        text_extraction: TextExtractionAnalysis,
        text_consistency: TextConsistencyAnalysis,
        fields: FieldExtractionAnalysis,
        content_risk: ContentRiskAnalysis,
        deepseek_analysis: DeepSeekAnalysis,
        qr_analysis: QRAnalysis,
        forensics: ForensicAnalysis | None,
        warnings: list[str],
    ) -> DocumentVerificationReport:
        sanitized_file_validation = self._sanitize_model(file_validation)
        sanitized_pdf = self._sanitize_model(pdf_analysis) if pdf_analysis else None
        sanitized_image = self._sanitize_model(image_analysis) if image_analysis else None
        sanitized_forensics = self._sanitize_model(forensics) if forensics else None
        trust = TrustScorer().score(
            {
                "metadata": metadata,
                "pdf_analysis": pdf_analysis,
                "text_extraction": text_extraction,
                "text_consistency": text_consistency,
                "qr_analysis": qr_analysis,
                "forensics": forensics,
                "fields": fields,
                "content_risk": content_risk,
            }
        )
        risk_flags = self._risk_flags(metadata, pdf_analysis, text_consistency, qr_analysis, forensics, fields, content_risk, trust)
        all_warnings = self._dedupe(warnings)

        return DocumentVerificationReport(
            verification_id=verification_id,
            service="BitCheck",
            file_type="document",
            status=status,
            processing_time_ms=processing_time_ms,
            input=verification_input,
            file_validation=sanitized_file_validation,
            pdf_analysis=sanitized_pdf,
            image_analysis=sanitized_image,
            metadata=metadata,
            text_extraction=self._redact_text_extraction(text_extraction),
            text_consistency=text_consistency,
            fields=fields,
            content_risk=content_risk,
            deepseek_analysis=deepseek_analysis,
            qr_analysis=qr_analysis,
            forensics=sanitized_forensics,
            trust=trust,
            risk_flags=risk_flags,
            recommended_actions=self._recommended_actions(trust, risk_flags, deepseek_analysis),
            limitations=LIMITATIONS,
            warnings=all_warnings,
        )

    def _risk_flags(
        self,
        metadata: MetadataAnalysis,
        pdf_analysis: PdfAnalysis | None,
        text_consistency: TextConsistencyAnalysis,
        qr_analysis: QRAnalysis,
        forensics: ForensicAnalysis | None,
        fields: FieldExtractionAnalysis,
        content_risk: ContentRiskAnalysis,
        trust,
    ) -> list[str]:
        flags: list[str] = []
        flags.extend(metadata.flags)
        if pdf_analysis:
            flags.extend(pdf_analysis.flags)
        flags.extend(text_consistency.flags)
        flags.extend(qr_analysis.flags)
        if forensics:
            flags.extend(forensics.flags)
        flags.extend(fields.field_flags)
        flags.extend(content_risk.signals)
        flags.extend(trust.applied_overrides)
        return self._dedupe(flags)

    def _recommended_actions(self, trust, risk_flags: list[str], deepseek_analysis: DeepSeekAnalysis) -> list[str]:
        actions: list[str] = []
        if trust.decision == "approve":
            actions.append("Proceed only after routine human review of the document details.")
        elif trust.risk_level == "Suspicious":
            actions.append("Manually review the document before accepting it.")
        else:
            actions.append("Do not approve automatically; escalate for manual verification.")
        if deepseek_analysis.external_verification_required:
            actions.append("Verify the document directly with the issuing authority or official portal.")
        if any("QR" in flag or flag.startswith("shortened_url") or flag.startswith("suspicious_url") for flag in risk_flags):
            actions.append("Check QR destination ownership and compare it with official issuer channels.")
        if any("metadata" in flag.lower() for flag in risk_flags):
            actions.append("Review metadata in context rather than treating it as standalone proof.")
        if any("visual" in flag.lower() or "tampering" in flag.lower() for flag in risk_flags):
            actions.append("Inspect highlighted visual regions manually.")
        return self._dedupe(actions)

    def _redact_text_extraction(self, text_extraction: TextExtractionAnalysis) -> TextExtractionAnalysis:
        return text_extraction.model_copy(
            update={
                "page_texts": [self._truncate(text, 240) for text in text_extraction.page_texts],
                "combined_text_excerpt": self._truncate(text_extraction.combined_text_excerpt, 500),
            }
        )

    def _sanitize_model(self, model):
        data = model.model_dump()
        sanitized = self._sanitize_paths(data)
        return model.__class__.model_validate(sanitized)

    def _sanitize_paths(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: self._sanitize_paths(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._sanitize_paths(item) for item in value]
        if isinstance(value, str):
            return self._relative_if_path(value)
        return value

    def _relative_if_path(self, value: str) -> str:
        try:
            path = Path(value)
        except (TypeError, ValueError):
            return value
        if not path.is_absolute():
            return value
        try:
            return os.path.relpath(path, Path.cwd())
        except ValueError:
            return value

    def _truncate(self, text: str, max_chars: int) -> str:
        if len(text) <= max_chars:
            return text
        return text[: max_chars - 3].rstrip() + "..."

    def _dedupe(self, values: list[str]) -> list[str]:
        return [value for value in dict.fromkeys(values) if value]

from difflib import SequenceMatcher

from app.schemas.document_verification import TextConsistencyAnalysis
from app.utils.text_utils import normalize_text


class TextConsistencyChecker:
    def compare(self, pdf_text: str | None, ocr_text: str | None) -> TextConsistencyAnalysis:
        normalized_pdf = normalize_text(pdf_text)
        normalized_ocr = normalize_text(ocr_text)

        if not normalized_pdf or not normalized_ocr:
            return TextConsistencyAnalysis(
                checked=True,
                similarity_score=0.0,
                risk_score=0.0,
                status="no_text_to_compare",
                flags=[],
                warnings=["PDF text or OCR text was unavailable, so consistency could not be compared."],
            )

        similarity = self._similarity(normalized_pdf, normalized_ocr)
        flags: list[str] = []
        warnings: list[str] = []

        if similarity >= 0.85:
            status = "strong_match"
            risk = 0.05
        elif similarity >= 0.60:
            status = "partial_match"
            risk = 0.35
            flags.append("partial_text_mismatch")
            warnings.append("Embedded PDF text and visible OCR text only partially match.")
        else:
            status = "low_match"
            risk = 0.70
            flags.append("low_text_match")
            warnings.append("Embedded PDF text and visible OCR text diverge significantly.")

        return TextConsistencyAnalysis(
            checked=True,
            similarity_score=round(similarity, 2),
            risk_score=risk,
            status=status,
            flags=flags,
            warnings=warnings,
        )

    def _similarity(self, left: str, right: str) -> float:
        try:
            from rapidfuzz import fuzz

            return fuzz.token_set_ratio(left, right) / 100
        except Exception:
            return SequenceMatcher(None, left, right).ratio()

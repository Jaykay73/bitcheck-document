import re
from urllib.parse import urlparse

import httpx

from app.schemas.document_verification import LiveQRVerification, SourceURLAnalysis
from app.utils.text_utils import excerpt_text

POSITIVE_TERMS = [
    "valid",
    "verified",
    "authentic",
    "issued",
    "certificate found",
    "record found",
    "successful",
]

NEGATIVE_TERMS = [
    "invalid",
    "not found",
    "expired",
    "revoked",
    "fake",
    "error",
    "unavailable",
    "failed",
]


class LiveQRVerifier:
    def verify(
        self,
        url: str,
        url_analysis: SourceURLAnalysis,
        extracted_fields: dict[str, str] | None = None,
    ) -> LiveQRVerification:
        eligible, blocked_reason = self._eligible(url_analysis)
        if not eligible:
            return LiveQRVerification(
                live_check_performed=False,
                eligible=False,
                blocked_reason=blocked_reason,
                risk_score=0.7,
                flags=["QR URL points to an unsafe/internal address."],
                warnings=[],
            )

        headers = {"User-Agent": "BitCheckBot/1.0"}
        try:
            with httpx.Client(timeout=5.0, follow_redirects=True, max_redirects=3, headers=headers) as client:
                response = client.get(url)
        except Exception:
            return LiveQRVerification(
                live_check_performed=True,
                eligible=True,
                reachable=False,
                status_code=None,
                risk_score=0.45,
                flags=["QR destination could not be reached during live verification."],
                warnings=["Network failure or timeout during QR live check."],
            )

        content_type = response.headers.get("content-type", "").split(";")[0].lower()
        if content_type not in {"text/html", "text/plain"}:
            return LiveQRVerification(
                live_check_performed=True,
                eligible=True,
                reachable=True,
                status_code=response.status_code,
                final_url=str(response.url),
                redirected=str(response.url) != url,
                domain_changed=self._domain(url) != self._domain(str(response.url)),
                content_type=content_type or None,
                risk_score=0.4,
                flags=["QR destination returned unsupported content type."],
                warnings=["Live QR verification only parses text/html or text/plain responses."],
            )

        content = response.content[: 1024 * 1024]
        text = content.decode(response.encoding or "utf-8", errors="ignore")
        plain_text = self._plain_text(text)
        matched_fields = self._matched_fields(plain_text, extracted_fields or {})
        positive_terms = self._terms_found(plain_text, POSITIVE_TERMS)
        negative_terms = self._terms_found(plain_text, NEGATIVE_TERMS)
        redirected = str(response.url) != url
        domain_changed = self._domain(url) != self._domain(str(response.url))

        risk = 0.1
        flags: list[str] = []
        warnings: list[str] = []
        if response.status_code >= 400:
            risk = max(risk, 0.45)
            flags.append("qr_destination_http_error")
        if domain_changed:
            risk = max(risk, 0.55)
            flags.append("qr_redirected_to_different_domain")
        if not matched_fields:
            risk = max(risk, 0.35)
            flags.append("qr_live_page_no_document_field_match")
        if negative_terms:
            risk = max(risk, 0.75)
            flags.append("qr_live_page_negative_terms")
        if positive_terms and matched_fields and not negative_terms and not domain_changed:
            risk = min(risk, 0.1)

        return LiveQRVerification(
            live_check_performed=True,
            eligible=True,
            reachable=True,
            status_code=response.status_code,
            final_url=str(response.url),
            redirected=redirected,
            domain_changed=domain_changed,
            content_type=content_type,
            page_title=self._title(text),
            page_text_excerpt=excerpt_text(plain_text, 500),
            matched_document_fields=matched_fields,
            positive_verification_terms=positive_terms,
            negative_verification_terms=negative_terms,
            risk_score=round(risk, 2),
            flags=flags,
            warnings=warnings,
        )

    def not_requested(self, eligible: bool) -> LiveQRVerification:
        return LiveQRVerification(
            live_check_performed=False,
            eligible=eligible,
            reason="Live QR verification was not requested.",
            risk_score=None,
            flags=[],
            warnings=[],
        )

    def _eligible(self, analysis: SourceURLAnalysis) -> tuple[bool, str | None]:
        if analysis.scheme not in {"http", "https"}:
            return False, "Unsupported URL scheme."
        if analysis.is_private_or_internal:
            return False, "Private or unsafe URL target."
        if not analysis.domain:
            return False, "Missing URL host."
        return True, None

    def _domain(self, url: str) -> str:
        return (urlparse(url).hostname or "").lower()

    def _title(self, html: str) -> str | None:
        match = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
        if not match:
            return None
        return excerpt_text(re.sub(r"\s+", " ", match.group(1)), 120)

    def _plain_text(self, text: str) -> str:
        without_scripts = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", text, flags=re.IGNORECASE | re.DOTALL)
        without_tags = re.sub(r"<[^>]+>", " ", without_scripts)
        return re.sub(r"\s+", " ", without_tags).strip()

    def _terms_found(self, text: str, terms: list[str]) -> list[str]:
        lowered = text.lower()
        return [term for term in terms if term in lowered]

    def _matched_fields(self, text: str, fields: dict[str, str]) -> list[str]:
        lowered = text.lower()
        matched: list[str] = []
        for key, value in fields.items():
            if value and str(value).lower() in lowered:
                matched.append(key)
        return matched

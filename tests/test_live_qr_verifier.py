import httpx

from app.services.live_qr_verifier import LiveQRVerifier
from app.services.source_url_analyzer import SourceURLAnalyzer


def analysis(url: str):
    return SourceURLAnalyzer().analyze(url)


def test_blocks_localhost_private_urls() -> None:
    result = LiveQRVerifier().verify("http://localhost/verify", analysis("http://localhost/verify"))

    assert result.live_check_performed is False
    assert result.eligible is False
    assert result.risk_score == 0.7


def test_handles_reachable_mocked_html_response(monkeypatch) -> None:
    class MockClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def get(self, url):
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                content=b"<html><title>Certificate Verification</title><body>Certificate valid and verified for John Aledare ABC-123</body></html>",
                request=httpx.Request("GET", url),
            )

    monkeypatch.setattr(httpx, "Client", MockClient)
    result = LiveQRVerifier().verify(
        "https://example.edu.ng/verify?id=ABC-123",
        analysis("https://example.edu.ng/verify?id=ABC-123"),
        {"certificate_number": "ABC-123", "name": "John Aledare"},
    )

    assert result.live_check_performed is True
    assert result.reachable is True
    assert result.page_title == "Certificate Verification"
    assert "certificate_number" in result.matched_document_fields


def test_handles_timeout_unreachable_response(monkeypatch) -> None:
    class MockClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def get(self, url):
            raise httpx.TimeoutException("timeout")

    monkeypatch.setattr(httpx, "Client", MockClient)
    result = LiveQRVerifier().verify("https://example.edu.ng/verify", analysis("https://example.edu.ng/verify"))

    assert result.reachable is False
    assert result.risk_score == 0.45
    assert result.warnings == ["Network failure or timeout during QR live check."]


def test_detects_positive_verification_terms(monkeypatch) -> None:
    monkeypatch.setattr(httpx, "Client", client_for("Certificate valid verified issued"))
    result = LiveQRVerifier().verify("https://example.edu.ng/verify", analysis("https://example.edu.ng/verify"))

    assert "valid" in result.positive_verification_terms
    assert "verified" in result.positive_verification_terms


def test_detects_negative_verification_terms(monkeypatch) -> None:
    monkeypatch.setattr(httpx, "Client", client_for("Certificate invalid not found revoked"))
    result = LiveQRVerifier().verify("https://example.edu.ng/verify", analysis("https://example.edu.ng/verify"))

    assert "invalid" in result.negative_verification_terms
    assert "not found" in result.negative_verification_terms
    assert result.risk_score >= 0.75


def test_detects_matching_document_fields_in_page_text(monkeypatch) -> None:
    monkeypatch.setattr(httpx, "Client", client_for("Record found for matric number MAT-2024"))
    result = LiveQRVerifier().verify(
        "https://example.edu.ng/verify",
        analysis("https://example.edu.ng/verify"),
        {"matric_number": "MAT-2024"},
    )

    assert result.matched_document_fields == ["matric_number"]


def test_detects_domain_change_after_redirect(monkeypatch) -> None:
    monkeypatch.setattr(httpx, "Client", client_for("Record found", final_url="https://other.example/verify"))
    result = LiveQRVerifier().verify("https://example.edu.ng/verify", analysis("https://example.edu.ng/verify"))

    assert result.redirected is True
    assert result.domain_changed is True
    assert "qr_redirected_to_different_domain" in result.flags


def client_for(body: str, final_url: str | None = None):
    class MockClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        def get(self, url):
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                content=f"<html><body>{body}</body></html>".encode(),
                request=httpx.Request("GET", final_url or url),
                extensions={"reason_phrase": b"OK"},
            )

    return MockClient

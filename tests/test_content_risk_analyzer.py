from pathlib import Path

from app.config import Settings
from app.services.content_risk_analyzer import ContentRiskAnalyzer


def make_settings(tmp_path: Path, deepseek_api_key: str | None = None) -> Settings:
    return Settings(
        app_name="BitCheck Document Verification API",
        version="1.0.0",
        upload_dir=tmp_path / "uploads",
        output_dir=tmp_path / "outputs",
        max_upload_mb=20,
        max_pdf_pages=5,
        deepseek_api_key=deepseek_api_key,
        deepseek_base_url="https://api.deepseek.com",
        deepseek_model="deepseek-chat",
        log_level="INFO",
    )


def test_deepseek_unavailable_path_does_not_crash(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    result, deepseek = ContentRiskAnalyzer(make_settings(tmp_path)).analyze(
        document_text="Certificate of completion issued to Ada Lovelace.",
        run_llm_analysis=True,
        metadata_summary={},
        qr_summary={},
        field_results={},
        heuristic_signals={},
    )

    assert result.checked is True
    assert deepseek.used is False
    assert deepseek.model == "deepseek-chat"
    assert deepseek.warnings


def test_heuristic_fraud_detection_detects_bvn_payment_and_urgent_keywords(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    text = "Urgent: transfer payment before midnight. Send your BVN, OTP and account number to release funds."

    result, deepseek = ContentRiskAnalyzer(make_settings(tmp_path)).analyze(
        document_text=text,
        run_llm_analysis=False,
        metadata_summary={},
        qr_summary={},
        field_results={},
        heuristic_signals={},
    )

    assert deepseek.used is False
    assert result.fraud_risk_score >= 0.7
    assert "urgency_language" in result.signals
    assert "financial_instruction_or_claim" in result.signals
    assert "sensitive_identifier_or_secret_request" in result.signals
    assert "fraud_like_wording" in result.signals
    assert "bvn" in result.suspicious_claims
    assert "payment" in result.suspicious_claims
    assert "urgent" in result.suspicious_claims

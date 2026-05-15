from pathlib import Path

from app.config import Settings
from app.services.deepseek_llm import DeepSeekLLM


def make_settings(tmp_path: Path) -> Settings:
    return Settings(
        app_name="BitCheck Document Verification API",
        version="1.0.0",
        upload_dir=tmp_path / "uploads",
        output_dir=tmp_path / "outputs",
        max_upload_mb=20,
        max_pdf_pages=5,
        deepseek_api_key=None,
        deepseek_base_url="https://api.deepseek.com",
        deepseek_model="deepseek-chat",
        log_level="INFO",
    )


def test_json_parser_handles_markdown_wrapped_json(tmp_path: Path) -> None:
    content = """
    ```json
    {
      "document_type": "certificate",
      "fraud_risk_score": 0.22,
      "ai_generated_text_likelihood": 0.41,
      "summary": "Risk signals are limited.",
      "external_verification_required": true
    }
    ```
    """

    parsed, warnings = DeepSeekLLM(make_settings(tmp_path)).parse_json_response(content)

    assert warnings == []
    assert parsed["document_type"] == "certificate"
    assert parsed["fraud_risk_score"] == 0.22
    assert parsed["ai_generated_text_likelihood"] == 0.41
    assert parsed["summary"] == "Risk signals are limited."
    assert parsed["external_verification_required"] is True


def test_json_parser_returns_safe_fallback_for_invalid_json(tmp_path: Path) -> None:
    parsed, warnings = DeepSeekLLM(make_settings(tmp_path)).parse_json_response("not json")

    assert parsed["external_verification_required"] is True
    assert parsed["fraud_risk_score"] == 0.0
    assert warnings == ["DeepSeek returned invalid JSON; safe fallback was used."]

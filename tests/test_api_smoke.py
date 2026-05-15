import asyncio
from io import BytesIO
from pathlib import Path
from typing import Any

import fitz
import pytest
from fastapi import HTTPException
from PIL import Image, ImageDraw
from starlette.datastructures import UploadFile

from app.config import Settings
from app.routes.verify_document import verify_document
from main import app, health, root


def make_settings() -> Settings:
    return Settings(
        app_name="BitCheck Document Verification API",
        version="1.0.0",
        upload_dir=Path("uploads"),
        output_dir=Path("outputs"),
        max_upload_mb=20,
        max_pdf_pages=5,
        deepseek_api_key=None,
        deepseek_base_url="https://api.deepseek.com",
        deepseek_model="deepseek-chat",
        log_level="INFO",
    )


def make_upload(filename: str, data: bytes) -> UploadFile:
    return UploadFile(filename=filename, file=BytesIO(data))


def make_png_bytes() -> bytes:
    buffer = BytesIO()
    image = Image.new("RGB", (360, 220), "white")
    draw = ImageDraw.Draw(image)
    draw.text((24, 32), "Certificate of Completion", fill="black")
    draw.text((24, 72), "Certificate No: CERT-2026-001", fill="black")
    draw.text((24, 112), "Issued to Ada Lovelace", fill="black")
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def make_pdf_bytes() -> bytes:
    document = fitz.open()
    page = document.new_page()
    page.insert_text((72, 72), "Invoice")
    page.insert_text((72, 100), "Invoice Number: INV-2026-001")
    page.insert_text((72, 128), "Total Amount: NGN 12,500.00")
    payload = document.tobytes()
    document.close()
    return payload


def run_verify(filename: str, data: bytes, **overrides):
    params = {
        "file": make_upload(filename, data),
        "document_type": "general",
        "run_ocr": True,
        "run_forensics": True,
        "run_qr": True,
        "run_live_qr_check": False,
        "run_llm_analysis": True,
        "max_pages": 5,
        "settings": make_settings(),
    }
    params.update(overrides)
    return asyncio.run(verify_document(**params))


def assert_final_report_shape(report: dict[str, Any]) -> None:
    expected_keys = {
        "verification_id",
        "service",
        "file_type",
        "status",
        "processing_time_ms",
        "input",
        "file_validation",
        "metadata",
        "text_extraction",
        "text_consistency",
        "qr_analysis",
        "fields",
        "content_risk",
        "deepseek_analysis",
        "trust",
        "risk_flags",
        "recommended_actions",
        "limitations",
        "warnings",
    }
    assert expected_keys.issubset(report)
    assert report["service"] == "BitCheck"
    assert report["file_type"] == "document"
    assert report["status"] in {"completed", "completed_with_warnings"}
    assert isinstance(report["processing_time_ms"], int)
    assert report["trust"]["risk_level"] in {"Likely Authentic", "Low Risk", "Suspicious", "High Risk", "Very High Risk"}
    assert report["limitations"]
    assert "BitCheck provides a risk-based estimate, not legal proof of forgery or authenticity." in report["limitations"]
    assert_no_absolute_paths(report)
    assert_no_full_ocr_text(report)


def assert_no_absolute_paths(value: Any) -> None:
    if isinstance(value, dict):
        for child in value.values():
            assert_no_absolute_paths(child)
    elif isinstance(value, list):
        for child in value:
            assert_no_absolute_paths(child)
    elif isinstance(value, str):
        assert not value.startswith("/mnt/")
        assert not value.startswith("/home/")


def assert_no_full_ocr_text(report: dict[str, Any]) -> None:
    extraction = report["text_extraction"]
    assert len(extraction.get("combined_text_excerpt", "")) <= 500
    assert all(len(page_text) <= 240 for page_text in extraction.get("page_texts", []))


def assert_output_urls_work(report: dict[str, Any]) -> None:
    assert any(getattr(route, "path", "") == "/outputs" for route in app.routes)
    candidates: list[str] = []
    if report.get("image_analysis"):
        candidates.append(report["image_analysis"].get("normalized_image", ""))
    if report.get("pdf_analysis"):
        candidates.extend(report["pdf_analysis"].get("rendered_pages", []))
    if report.get("forensics"):
        candidates.extend(report["forensics"].get("annotated_pages", []))

    output_paths = [path for path in candidates if path.startswith("outputs/")]
    assert output_paths
    for output_path in output_paths[:2]:
        assert Path(output_path).exists()


def test_get_root() -> None:
    assert root().model_dump() == {
        "service": "BitCheck Document Verification API",
        "status": "running",
        "version": "1.0.0",
    }


def test_get_health() -> None:
    response = health().model_dump()

    assert response["status"] == "ok"
    assert response["deepseek_available"] is False


def test_post_verify_document_with_generated_png_succeeds() -> None:
    report = run_verify("document.png", make_png_bytes()).model_dump()

    assert_final_report_shape(report)
    assert report["file_validation"]["extension"] == ".png"
    assert report["image_analysis"] is not None
    assert report["input"]["page_count"] == 1
    assert_output_urls_work(report)


def test_post_verify_document_with_generated_pdf_succeeds() -> None:
    report = run_verify("document.pdf", make_pdf_bytes()).model_dump()

    assert_final_report_shape(report)
    assert report["file_validation"]["extension"] == ".pdf"
    assert report["pdf_analysis"] is not None
    assert report["pdf_analysis"]["page_count"] == 1
    assert_output_urls_work(report)


def test_post_verify_document_unsupported_txt_returns_clean_failed_error() -> None:
    with pytest.raises(HTTPException) as exc:
        run_verify("document.txt", b"hello")

    assert exc.value.status_code == 400
    assert exc.value.detail == {
        "status": "failed",
        "code": "unsupported_file_type",
        "message": "Unsupported file type. Supported files: PDF, JPG, JPEG, PNG, WEBP.",
    }


def test_run_ocr_false_still_succeeds() -> None:
    report = run_verify("document.png", make_png_bytes(), run_ocr=False).model_dump()

    assert_final_report_shape(report)
    assert report["input"]["run_ocr"] is False
    assert report["text_extraction"]["ocr_status"] == "skipped"


def test_run_forensics_false_still_succeeds() -> None:
    report = run_verify("document.png", make_png_bytes(), run_forensics=False).model_dump()

    assert_final_report_shape(report)
    assert report["input"]["run_forensics"] is False
    assert report["forensics"] is None


def test_deepseek_missing_still_succeeds() -> None:
    report = run_verify("document.png", make_png_bytes(), run_llm_analysis=True).model_dump()

    assert_final_report_shape(report)
    assert report["deepseek_analysis"]["used"] is False
    assert "DeepSeek API key is not configured; LLM reasoning was skipped." in report["deepseek_analysis"]["warnings"]

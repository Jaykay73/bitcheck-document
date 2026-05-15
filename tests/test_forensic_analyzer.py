from pathlib import Path

from PIL import Image, ImageDraw

from app.config import Settings
from app.services.forensic_analyzer import ForensicAnalyzer


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


def test_synthetic_pasted_rectangle_returns_checked_and_annotated_output(tmp_path: Path) -> None:
    image_path = tmp_path / "synthetic_document.png"
    image = Image.new("RGB", (640, 640), "white")
    draw = ImageDraw.Draw(image)
    for y in range(80, 560, 40):
        draw.line((80, y, 560, y), fill=(220, 220, 220), width=2)
    draw.rectangle((260, 260, 430, 360), fill=(80, 80, 80))
    image.save(image_path)

    result = ForensicAnalyzer(make_settings(tmp_path)).analyze([str(image_path)])

    assert result.checked is True
    assert result.disclaimer == "Forensic indicators are risk signals, not definitive proof of tampering."
    assert result.annotated_pages
    annotated_path = tmp_path / result.annotated_pages[0]
    assert annotated_path.exists()
    assert result.visual_tampering_risk_score >= 0.0

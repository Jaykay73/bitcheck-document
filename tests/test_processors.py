from pathlib import Path

import fitz
from PIL import Image

from app.config import Settings
from app.services.image_processor import ImageProcessor
from app.services.pdf_processor import PdfProcessor


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


def create_pdf(path: Path, pages: int = 1) -> Path:
    document = fitz.open()
    for index in range(pages):
        page = document.new_page()
        page.insert_text((72, 72), f"BitCheck test page {index + 1}")
    document.save(path)
    document.close()
    return path


def test_pdf_processing(tmp_path: Path) -> None:
    pdf_path = create_pdf(tmp_path / "sample.pdf")
    analysis = PdfProcessor(make_settings(tmp_path)).process(pdf_path, max_pages=5)

    assert analysis.checked is True
    assert analysis.is_pdf is True
    assert analysis.is_encrypted is False
    assert analysis.has_text_layer is True
    assert analysis.image_only_pdf is False
    assert analysis.page_count == 1
    assert analysis.pages_processed == 1
    assert "BitCheck test page 1" in analysis.pdf_text
    assert len(analysis.rendered_pages) == 1
    assert Path(analysis.rendered_pages[0]).exists()


def test_image_processing(tmp_path: Path) -> None:
    image_path = tmp_path / "sample.png"
    Image.new("RGBA", (1000, 1000), (255, 255, 255, 255)).save(image_path)

    analysis = ImageProcessor(make_settings(tmp_path)).process(image_path)

    assert analysis.checked is True
    assert analysis.is_image is True
    assert analysis.width == 1000
    assert analysis.height == 1000
    assert analysis.format == "PNG"
    assert analysis.mode == "RGB"
    assert Path(analysis.normalized_image).exists()
    assert analysis.page_images == [analysis.normalized_image]


def test_max_pages_truncation_creates_warning(tmp_path: Path) -> None:
    pdf_path = create_pdf(tmp_path / "multi-page.pdf", pages=3)
    analysis = PdfProcessor(make_settings(tmp_path)).process(pdf_path, max_pages=1)

    assert analysis.page_count == 3
    assert analysis.pages_processed == 1
    assert analysis.flags == ["max_pages_truncated"]
    assert analysis.warnings == ["PDF page processing truncated from 3 to 1 page(s)."]

from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageFilter, ImageOps

from app.schemas.document_verification import TextExtractionAnalysis
from app.utils.text_utils import excerpt_text


@dataclass(frozen=True)
class OCRResult:
    analysis: TextExtractionAnalysis
    full_text: str


class OCRService:
    def extract_page_images(self, image_paths: list[str], run_ocr: bool = True) -> OCRResult:
        if not run_ocr:
            return OCRResult(
                analysis=TextExtractionAnalysis(
                    checked=True,
                    ocr_status="skipped",
                    ocr_text_found=False,
                    ocr_text_length=0,
                    ocr_confidence=0.0,
                    page_texts=[],
                    combined_text_excerpt="",
                    warnings=["OCR was skipped by request."],
                ),
                full_text="",
            )

        pytesseract = self._load_pytesseract()
        if pytesseract is None or not self._is_tesseract_available(pytesseract):
            return OCRResult(
                analysis=TextExtractionAnalysis(
                    checked=True,
                    ocr_status="not_available",
                    ocr_text_found=False,
                    ocr_text_length=0,
                    ocr_confidence=0.0,
                    page_texts=[],
                    combined_text_excerpt="",
                    warnings=["pytesseract or the Tesseract binary is unavailable."],
                ),
                full_text="",
            )

        warnings: list[str] = []
        page_texts: list[str] = []
        confidences: list[float] = []

        for image_path in image_paths:
            try:
                with Image.open(Path(image_path)) as image:
                    processed = self._preprocess(image)
                    page_text = pytesseract.image_to_string(processed).strip()
                    page_texts.append(page_text)
                    confidences.extend(self._page_confidences(pytesseract, processed))
            except Exception as exc:
                warnings.append(f"OCR failed for page image: {exc.__class__.__name__}")
                page_texts.append("")

        combined_text = "\n".join(text for text in page_texts if text).strip()
        confidence = sum(confidences) / len(confidences) if confidences else 0.0

        return OCRResult(
            analysis=TextExtractionAnalysis(
                checked=True,
                ocr_status="available",
                ocr_text_found=bool(combined_text),
                ocr_text_length=len(combined_text),
                ocr_confidence=round(confidence, 2),
                page_texts=[excerpt_text(text, 500) for text in page_texts],
                combined_text_excerpt=excerpt_text(combined_text, 500),
                warnings=warnings,
            ),
            full_text=combined_text,
        )

    def _load_pytesseract(self):
        try:
            import pytesseract

            return pytesseract
        except Exception:
            return None

    def _is_tesseract_available(self, pytesseract) -> bool:
        try:
            pytesseract.get_tesseract_version()
        except Exception:
            return False
        return True

    def _preprocess(self, image: Image.Image) -> Image.Image:
        grayscale = ImageOps.grayscale(image)
        denoised = grayscale.filter(ImageFilter.MedianFilter(size=3))
        return denoised.point(lambda pixel: 255 if pixel > 170 else 0, mode="1")

    def _page_confidences(self, pytesseract, image: Image.Image) -> list[float]:
        try:
            data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
        except Exception:
            return []

        confidences: list[float] = []
        for raw_confidence in data.get("conf", []):
            try:
                confidence = float(raw_confidence)
            except (TypeError, ValueError):
                continue
            if confidence >= 0:
                confidences.append(confidence / 100)
        return confidences

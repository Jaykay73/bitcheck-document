from pathlib import Path
from uuid import uuid4

import fitz

from app.config import Settings
from app.schemas.document_verification import PdfAnalysis


class PdfProcessor:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def process(self, pdf_path: Path, max_pages: int) -> PdfAnalysis:
        warnings: list[str] = []
        flags: list[str] = []
        rendered_pages: list[str] = []
        page_texts: list[str] = []

        try:
            document = fitz.open(pdf_path)
        except Exception as exc:
            raise ValueError("PDF could not be opened safely.") from exc

        with document:
            is_encrypted = document.is_encrypted
            page_count = document.page_count
            pages_processed = min(page_count, max(0, max_pages))
            metadata = {str(key): str(value) for key, value in (document.metadata or {}).items()}

            if is_encrypted:
                warnings.append("PDF is encrypted; text extraction and rendering were skipped.")
                flags.append("encrypted_pdf")
                return PdfAnalysis(
                    checked=True,
                    is_pdf=True,
                    is_encrypted=True,
                    has_text_layer=False,
                    image_only_pdf=False,
                    page_count=page_count,
                    pages_processed=0,
                    pdf_text="",
                    page_texts=[],
                    rendered_pages=[],
                    raw_metadata=metadata,
                    structure_risk_score=0.4,
                    flags=flags,
                    warnings=warnings,
                )

            if page_count > pages_processed:
                warnings.append(f"PDF page processing truncated from {page_count} to {pages_processed} page(s).")
                flags.append("max_pages_truncated")

            for page_index in range(pages_processed):
                page = document.load_page(page_index)
                text = page.get_text("text").strip()
                page_texts.append(text)
                rendered_pages.append(self._render_page(page, page_index))

            pdf_text = "\n".join(text for text in page_texts if text).strip()
            has_text_layer = any(text.strip() for text in page_texts)
            image_only_pdf = page_count > 0 and not has_text_layer
            structure_risk_score = 0.0
            if image_only_pdf:
                flags.append("image_only_pdf")
                structure_risk_score = 0.2

            return PdfAnalysis(
                checked=True,
                is_pdf=True,
                is_encrypted=False,
                has_text_layer=has_text_layer,
                image_only_pdf=image_only_pdf,
                page_count=page_count,
                pages_processed=pages_processed,
                pdf_text=pdf_text,
                page_texts=page_texts,
                rendered_pages=rendered_pages,
                raw_metadata=metadata,
                structure_risk_score=structure_risk_score,
                flags=flags,
                warnings=warnings,
            )

    def _render_page(self, page: fitz.Page, page_index: int) -> str:
        self.settings.output_dir.mkdir(parents=True, exist_ok=True)
        zoom = 200 / 72
        matrix = fitz.Matrix(zoom, zoom)
        pixmap = page.get_pixmap(matrix=matrix, alpha=False)
        output_path = self.settings.output_dir / f"pdf_page_{page_index + 1}_{uuid4().hex}.png"
        pixmap.save(output_path)
        return str(output_path.resolve())

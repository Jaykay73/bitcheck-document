from typing import Annotated
from pathlib import Path
from time import perf_counter
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from app.config import Settings, get_settings
from app.schemas.document_verification import (
    ContentRiskAnalysis,
    DeepSeekAnalysis,
    DocumentVerificationReport,
    FieldExtractionAnalysis,
    ImageAnalysis,
    MetadataAnalysis,
    PdfAnalysis,
    QRAnalysis,
    QRTextConsistency,
    TextConsistencyAnalysis,
    TextExtractionAnalysis,
    VerificationInput,
)
from app.services.content_risk_analyzer import ContentRiskAnalyzer
from app.services.document_context import canonical_document_type
from app.services.field_extractor import FieldExtractor
from app.services.file_validator import FileValidationError, FileValidator
from app.services.forensic_analyzer import ForensicAnalyzer
from app.services.image_processor import ImageProcessor
from app.services.metadata_analyzer import MetadataAnalyzer
from app.services.ocr_service import OCRService
from app.services.pdf_processor import PdfProcessor
from app.services.qr_code_analyzer import QRCodeAnalyzer
from app.services.report_builder import ReportBuilder
from app.services.text_consistency import TextConsistencyChecker

router = APIRouter(prefix="/verify", tags=["verification"])


@router.post("/document", response_model=DocumentVerificationReport)
async def verify_document(
    file: Annotated[UploadFile, File()],
    document_type: Annotated[str, Form()] = "general",
    run_ocr: Annotated[bool, Form()] = True,
    run_forensics: Annotated[bool, Form()] = True,
    run_qr: Annotated[bool, Form()] = True,
    run_live_qr_check: Annotated[bool, Form()] = False,
    run_llm_analysis: Annotated[bool, Form()] = True,
    max_pages: Annotated[int, Form()] = 5,
    settings: Settings = Depends(get_settings),
) -> DocumentVerificationReport:
    started_at = perf_counter()
    verification_id = str(uuid4())
    validator = FileValidator(settings)

    try:
        file_validation = await validator.validate_and_save(file)
    except FileValidationError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"status": "failed", "code": exc.code, "message": exc.message},
        ) from exc

    warnings: list[str] = []
    pdf_analysis = None
    image_analysis = None
    metadata_analyzer = MetadataAnalyzer()

    stored_path = Path(file_validation.stored_path)
    if file_validation.extension == ".pdf":
        try:
            pdf_analysis = PdfProcessor(settings).process(stored_path, max_pages)
        except Exception as exc:
            warnings.append(f"PDF processing failed: {exc.__class__.__name__}")
            pdf_analysis = _failed_pdf_analysis()
        warnings.extend(pdf_analysis.warnings)
        page_count = pdf_analysis.page_count
        pages_processed = pdf_analysis.pages_processed
        try:
            metadata = metadata_analyzer.analyze_pdf_metadata(pdf_analysis.raw_metadata)
        except Exception as exc:
            warnings.append(f"PDF metadata analysis failed: {exc.__class__.__name__}")
            metadata = _failed_metadata_analysis("PDF metadata analysis failed.")
        page_images = pdf_analysis.rendered_pages
        pdf_text = pdf_analysis.pdf_text
    else:
        try:
            image_analysis = ImageProcessor(settings).process(stored_path)
        except Exception as exc:
            warnings.append(f"Image processing failed: {exc.__class__.__name__}")
            image_analysis = _failed_image_analysis()
        warnings.extend(image_analysis.warnings)
        page_count = 1
        pages_processed = len(image_analysis.page_images)
        try:
            metadata = metadata_analyzer.analyze_image_exif(image_analysis.raw_exif)
        except Exception as exc:
            warnings.append(f"Image metadata analysis failed: {exc.__class__.__name__}")
            metadata = _failed_metadata_analysis("Image metadata analysis failed.")
        page_images = image_analysis.page_images
        pdf_text = ""

    try:
        ocr_result = OCRService().extract_page_images(page_images, run_ocr=run_ocr)
        text_extraction = ocr_result.analysis
        ocr_text = ocr_result.full_text
    except Exception as exc:
        warnings.append(f"OCR analysis failed: {exc.__class__.__name__}")
        text_extraction = _failed_text_extraction("OCR analysis failed.")
        ocr_text = ""
    warnings.extend(text_extraction.warnings)
    try:
        text_consistency = TextConsistencyChecker().compare(pdf_text, ocr_text)
    except Exception as exc:
        warnings.append(f"Text consistency check failed: {exc.__class__.__name__}")
        text_consistency = _failed_text_consistency("Text consistency check failed.")
    warnings.extend(text_consistency.warnings)
    try:
        qr_analysis = QRCodeAnalyzer().analyze(
            page_images=page_images,
            run_qr=run_qr,
            run_live_qr_check=run_live_qr_check,
            extracted_fields={},
        )
    except Exception as exc:
        warnings.append(f"QR analysis failed: {exc.__class__.__name__}")
        qr_analysis = _failed_qr_analysis("QR analysis failed.")
    warnings.extend(qr_analysis.warnings)
    forensics = None
    if run_forensics:
        try:
            forensics = ForensicAnalyzer(settings).analyze(page_images)
        except Exception as exc:
            warnings.append(f"Forensic analysis failed: {exc.__class__.__name__}")
            forensics = None
    field_text = "\n".join(text for text in [pdf_text, ocr_text] if text).strip()
    try:
        fields = FieldExtractor().extract(field_text, document_type)
    except Exception as exc:
        warnings.append(f"Field extraction failed: {exc.__class__.__name__}")
        fields = _failed_field_extraction("Field extraction failed.")
    warnings.extend(fields.warnings)
    if forensics:
        warnings.extend(forensics.warnings)
    try:
        content_risk, deepseek_analysis = ContentRiskAnalyzer(settings).analyze(
            document_text=field_text,
            run_llm_analysis=run_llm_analysis,
            metadata_summary=metadata.model_dump(),
            qr_summary=qr_analysis.model_dump(),
            field_results=fields.model_dump(),
            heuristic_signals={
                "metadata_risk_score": metadata.metadata_risk_score,
                "field_risk_score": fields.field_risk_score,
                "qr_risk_score": qr_analysis.risk_score,
                "text_consistency_risk_score": text_consistency.risk_score,
                "forensic_risk_score": forensics.visual_tampering_risk_score if forensics else None,
            },
        )
    except Exception as exc:
        warnings.append(f"Content risk analysis failed: {exc.__class__.__name__}")
        content_risk = _failed_content_risk("Content risk analysis failed.")
        deepseek_analysis = _skipped_deepseek(settings.deepseek_model, "DeepSeek analysis skipped after content risk failure.")
    warnings.extend(content_risk.warnings)
    llm_document_type = canonical_document_type(deepseek_analysis.document_type_inferred)
    if deepseek_analysis.used and llm_document_type != "general" and llm_document_type != fields.document_type:
        try:
            refined_fields = FieldExtractor().extract(field_text, llm_document_type)
            if refined_fields.document_type == llm_document_type:
                fields = refined_fields
                warnings.extend(refined_fields.warnings)
        except Exception as exc:
            warnings.append(f"LLM-guided field refinement failed: {exc.__class__.__name__}")

    verification_input = VerificationInput(
        document_type=document_type,
        run_ocr=run_ocr,
        run_forensics=run_forensics,
        run_qr=run_qr,
        run_live_qr_check=run_live_qr_check,
        run_llm_analysis=run_llm_analysis,
        max_pages=max_pages,
        page_count=page_count,
        pages_processed=pages_processed,
    )

    return ReportBuilder().build(
        verification_id=verification_id,
        status="completed_with_warnings" if warnings else "completed",
        processing_time_ms=round((perf_counter() - started_at) * 1000),
        verification_input=verification_input,
        file_validation=file_validation,
        pdf_analysis=pdf_analysis,
        image_analysis=image_analysis,
        metadata=metadata,
        text_extraction=text_extraction,
        text_consistency=text_consistency,
        fields=fields,
        content_risk=content_risk,
        deepseek_analysis=deepseek_analysis,
        qr_analysis=qr_analysis,
        forensics=forensics,
        warnings=warnings,
    )


def _failed_pdf_analysis() -> PdfAnalysis:
    return PdfAnalysis(
        checked=True,
        is_pdf=True,
        is_encrypted=False,
        has_text_layer=False,
        image_only_pdf=False,
        page_count=0,
        pages_processed=0,
        pdf_text="",
        page_texts=[],
        rendered_pages=[],
        raw_metadata={},
        structure_risk_score=0.5,
        flags=["pdf_processing_failed"],
        warnings=["PDF processing failed; downstream document checks used fallback values."],
    )


def _failed_image_analysis() -> ImageAnalysis:
    return ImageAnalysis(
        checked=True,
        is_image=True,
        width=0,
        height=0,
        format=None,
        mode="unknown",
        normalized_image="",
        page_images=[],
        raw_exif={},
        warnings=["Image processing failed; downstream image checks used fallback values."],
    )


def _failed_metadata_analysis(message: str) -> MetadataAnalysis:
    return MetadataAnalysis(
        checked=True,
        metadata_found=False,
        modified_after_creation=False,
        editing_software_detected=False,
        known_tools_detected=[],
        ai_tool_detected=False,
        detected_ai_tools=[],
        camera_metadata_found=False,
        gps_found=False,
        metadata_risk_score=0.0,
        flags=["metadata_analysis_failed"],
        warnings=[message],
    )


def _failed_text_extraction(message: str) -> TextExtractionAnalysis:
    return TextExtractionAnalysis(
        checked=True,
        ocr_status="failed",
        ocr_text_found=False,
        ocr_text_length=0,
        ocr_confidence=0.0,
        page_texts=[],
        combined_text_excerpt="",
        warnings=[message],
    )


def _failed_text_consistency(message: str) -> TextConsistencyAnalysis:
    return TextConsistencyAnalysis(
        checked=True,
        similarity_score=0.0,
        risk_score=0.0,
        status="failed",
        flags=["text_consistency_failed"],
        warnings=[message],
    )


def _failed_qr_analysis(message: str) -> QRAnalysis:
    return QRAnalysis(
        checked=True,
        qr_found=False,
        barcodes_found=False,
        items=[],
        qr_text_consistency=QRTextConsistency(
            checked=True,
            matched_document_fields=[],
            mismatch_flags=[],
            risk_score=0.0,
        ),
        risk_score=0.0,
        flags=["qr_analysis_failed"],
        warnings=[message],
    )


def _failed_field_extraction(message: str) -> FieldExtractionAnalysis:
    return FieldExtractionAnalysis(
        checked=True,
        document_type="general",
        extracted_fields={},
        missing_expected_fields=[],
        field_confidence=0.0,
        field_risk_score=0.0,
        field_flags=["field_extraction_failed"],
        warnings=[message],
    )


def _failed_content_risk(message: str) -> ContentRiskAnalysis:
    return ContentRiskAnalysis(
        checked=True,
        fraud_risk_score=0.0,
        ai_generated_text_likelihood=0.0,
        suspicious_claims=[],
        signals=["content_risk_analysis_failed"],
        summary="Content risk analysis was unavailable.",
        warnings=[message],
    )


def _skipped_deepseek(model: str, message: str) -> DeepSeekAnalysis:
    return DeepSeekAnalysis(
        used=False,
        model=model,
        document_type_inferred=None,
        summary="",
        external_verification_required=True,
        warnings=[message],
    )

from pydantic import BaseModel


class RootResponse(BaseModel):
    service: str
    status: str
    version: str


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    ocr_available: bool
    qr_available: bool
    deepseek_available: bool
    model: str


class FileValidationResult(BaseModel):
    valid: bool
    original_filename: str
    stored_filename: str
    stored_path: str
    sha256: str
    mime_type: str
    extension: str
    file_size_bytes: int
    warnings: list[str]


class VerificationInput(BaseModel):
    document_type: str
    run_ocr: bool
    run_forensics: bool
    run_qr: bool
    run_live_qr_check: bool
    run_llm_analysis: bool
    max_pages: int
    page_count: int | None = None
    pages_processed: int | None = None


class PdfAnalysis(BaseModel):
    checked: bool
    is_pdf: bool
    is_encrypted: bool
    has_text_layer: bool
    image_only_pdf: bool
    page_count: int
    pages_processed: int
    pdf_text: str
    page_texts: list[str]
    rendered_pages: list[str]
    raw_metadata: dict[str, str]
    structure_risk_score: float
    flags: list[str]
    warnings: list[str]


class ImageAnalysis(BaseModel):
    checked: bool
    is_image: bool
    width: int
    height: int
    format: str | None
    mode: str
    normalized_image: str
    page_images: list[str]
    raw_exif: dict[str, str]
    warnings: list[str]


class MetadataAnalysis(BaseModel):
    checked: bool
    metadata_found: bool
    creator: str | None = None
    producer: str | None = None
    author: str | None = None
    title: str | None = None
    subject: str | None = None
    keywords: str | None = None
    creation_date: str | None = None
    modification_date: str | None = None
    modified_after_creation: bool
    editing_software_detected: bool
    known_tools_detected: list[str]
    ai_tool_detected: bool
    detected_ai_tools: list[str]
    camera_metadata_found: bool
    gps_found: bool
    metadata_risk_score: float
    flags: list[str]
    warnings: list[str]


class TextExtractionAnalysis(BaseModel):
    checked: bool
    ocr_status: str
    ocr_text_found: bool
    ocr_text_length: int
    ocr_confidence: float
    page_texts: list[str]
    combined_text_excerpt: str
    warnings: list[str]


class TextConsistencyAnalysis(BaseModel):
    checked: bool
    similarity_score: float
    risk_score: float
    status: str
    flags: list[str]
    warnings: list[str]


class FieldExtractionAnalysis(BaseModel):
    checked: bool
    document_type: str
    extracted_fields: dict[str, object]
    missing_expected_fields: list[str]
    field_confidence: float
    field_risk_score: float
    field_flags: list[str]
    warnings: list[str]


class ContentRiskAnalysis(BaseModel):
    checked: bool
    fraud_risk_score: float
    ai_generated_text_likelihood: float
    suspicious_claims: list[str]
    signals: list[str]
    summary: str
    warnings: list[str]


class DeepSeekAnalysis(BaseModel):
    used: bool
    model: str
    document_type_inferred: str | None = None
    summary: str
    external_verification_required: bool
    warnings: list[str]


class TrustAnalysis(BaseModel):
    trust_score: int
    risk_score: float
    risk_level: str
    decision: str
    available_modules: list[str]
    applied_overrides: list[str]
    evidence_count: int


class QRBoundingBox(BaseModel):
    x: int
    y: int
    width: int
    height: int


class SourceURLAnalysis(BaseModel):
    checked: bool
    url: str
    domain: str | None
    scheme: str | None
    uses_https: bool
    is_shortened_url: bool
    is_ip_address: bool
    is_private_or_internal: bool
    has_suspicious_keywords: bool
    suspicious_tld: bool
    punycode_detected: bool
    excessive_hyphens: bool
    too_many_subdomains: bool
    risk_score: float
    flags: list[str]
    warnings: list[str]


class LiveQRVerification(BaseModel):
    live_check_performed: bool
    eligible: bool
    reachable: bool | None = None
    status_code: int | None = None
    final_url: str | None = None
    redirected: bool | None = None
    domain_changed: bool | None = None
    content_type: str | None = None
    page_title: str | None = None
    page_text_excerpt: str | None = None
    matched_document_fields: list[str] = []
    positive_verification_terms: list[str] = []
    negative_verification_terms: list[str] = []
    blocked_reason: str | None = None
    reason: str | None = None
    risk_score: float | None = None
    flags: list[str]
    warnings: list[str]


class QRAnalysisItem(BaseModel):
    type: str
    data: str
    data_type: str
    page: int
    bbox: QRBoundingBox
    url_analysis: SourceURLAnalysis | None = None
    live_verification: LiveQRVerification | None = None


class QRTextConsistency(BaseModel):
    checked: bool
    matched_document_fields: list[str]
    mismatch_flags: list[str]
    risk_score: float


class QRAnalysis(BaseModel):
    checked: bool
    qr_found: bool
    barcodes_found: bool
    items: list[QRAnalysisItem]
    qr_text_consistency: QRTextConsistency
    risk_score: float
    flags: list[str]
    warnings: list[str]


class SuspiciousRegion(BaseModel):
    page: int
    x: int
    y: int
    width: int
    height: int
    risk_score: float
    reason: str


class ForensicAnalysis(BaseModel):
    checked: bool
    visual_tampering_risk_score: float
    sharpness_score: float
    compression_risk: float
    noise_inconsistency_risk: float
    blur_inconsistency_risk: float
    edge_inconsistency_risk: float
    layout_risk: float
    suspicious_regions: list[SuspiciousRegion]
    annotated_pages: list[str]
    flags: list[str]
    warnings: list[str]
    disclaimer: str


class DocumentVerificationReport(BaseModel):
    verification_id: str
    service: str
    file_type: str
    status: str
    processing_time_ms: int
    input: VerificationInput
    file_validation: FileValidationResult
    pdf_analysis: PdfAnalysis | None = None
    image_analysis: ImageAnalysis | None = None
    metadata: MetadataAnalysis
    text_extraction: TextExtractionAnalysis
    text_consistency: TextConsistencyAnalysis
    fields: FieldExtractionAnalysis
    content_risk: ContentRiskAnalysis
    deepseek_analysis: DeepSeekAnalysis
    qr_analysis: QRAnalysis
    forensics: ForensicAnalysis | None = None
    trust: TrustAnalysis
    risk_flags: list[str]
    recommended_actions: list[str]
    limitations: list[str]
    warnings: list[str]

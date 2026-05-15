---
title: Bitcheck Document
emoji: 📊
colorFrom: blue
colorTo: pink
sdk: docker
pinned: false
---

# BitCheck Document Verification API

BitCheck Document Verification API is a FastAPI service for risk-based document verification. It accepts PDF and image documents, runs a sequence of local analysis modules, optionally adds DeepSeek reasoning when configured, and returns a structured trust report for review workflows.

The service is designed to run locally or on Hugging Face Spaces using Docker on port `7860`.

## Architecture

```text
Client
  |
  v
FastAPI /verify/document
  |
  +--> File validation and safe storage
  |
  +--> PDF processor or image processor
  |
  +--> Metadata analyzer
  |
  +--> OCR service
  |
  +--> PDF/OCR text consistency checker
  |
  +--> QR decoder and structural URL analyzer
  |
  +--> Visual forensic analyzer
  |
  +--> Rule-based field extractor
  |
  +--> Content risk analyzer
  |       |
  |       +--> Optional DeepSeek reasoning
  |
  +--> Dynamic trust scorer
  |
  +--> Report builder
  |
  v
Risk-based BitCheck JSON report
```

## Features

- FastAPI document verification endpoint.
- Safe upload validation by extension and file signature.
- PDF text-layer extraction and page rendering.
- Image normalization for OCR, QR, and forensic modules.
- Metadata analysis for editing tools, AI tools, timestamps, camera data, and GPS.
- OCR with graceful fallback when Tesseract is unavailable.
- PDF text versus OCR text consistency scoring.
- QR code detection and structural URL risk analysis.
- Visual forensic risk signals and annotated output images.
- Rule-based document type inference and structured field extraction.
- Heuristic content risk analysis for fraud-like wording.
- Optional DeepSeek reasoning when an API key is configured.
- Dynamic trust scoring with normalized module weights.
- Final report builder with limitations, warnings, risk flags, recommended actions, and relative output paths.

## Supported File Types

- PDF: `.pdf`
- Images: `.jpg`, `.jpeg`, `.png`, `.webp`

Unsupported file types return a clean `400` response with `status: "failed"`.

## How Each Module Works

### File Validation

The file validator checks the filename extension, reads the file with a size limit, validates the file signature, computes a SHA-256 hash, and stores the upload using a generated safe filename.

### PDF Processing

PDF files are opened with PyMuPDF. The service extracts embedded page text, renders each processed page to an output image, records document structure signals, and limits processing to `MAX_PDF_PAGES`.

### Image Processing

Image files are opened with Pillow, EXIF metadata is collected where available, and the image is normalized to RGB PNG for downstream modules.

### Metadata Analysis

Metadata is checked for known editing software, AI-generation tool names, creation/modification timestamps, camera metadata, and GPS fields. These signals affect risk but do not prove manipulation by themselves.

### OCR

OCR uses `pytesseract` when the Tesseract binary is available. If OCR is disabled or unavailable, BitCheck records a warning and continues.

### Text Consistency

For PDFs, embedded text is compared against visible OCR text. A low match raises a review signal because it can indicate an image overlay, replacement, or extraction mismatch.

### QR Code Checks

BitCheck decodes QR codes and barcodes from rendered page images. For QR URL payloads, it analyzes structure only:

- HTTPS versus HTTP
- shortened URLs
- IP address hosts
- private or internal addresses
- suspicious keywords such as login, payment, wallet, password, OTP, or claim
- suspicious TLDs
- punycode domains
- excessive hyphenation
- unusually deep subdomains

BitCheck does not browse or open QR destinations in the verification pipeline. QR detection does not mean the linked source is authentic unless the issuer is verified through an official channel.

### Visual Forensics

The forensic analyzer uses OpenCV and NumPy to estimate visual inconsistency risk from local sharpness, noise, edge density, compression artifacts, brightness, and contrast. It can generate annotated review images. These are risk signals, not court-grade evidence.

### Field Extraction

The field extractor uses regex and keyword rules to infer a document type and extract expected fields. Supported types include:

- `certificate`
- `academic_result`
- `invoice`
- `receipt`
- `business_registration`
- `identity_document`
- `bank_statement`
- `admission_letter`
- `result_slip`
- `contract`
- `general`

It computes missing expected fields, field confidence, and field risk.

### Content Risk

The content risk analyzer always runs local heuristics for:

- urgency wording
- suspicious payment instructions
- fake grant or scholarship wording
- BVN, NIN, OTP, password, PIN, or verification-code requests
- attempts to bypass official channels
- unrealistic claims

### Trust Scoring

The trust scorer combines available numeric module risks using normalized weights:

```text
metadata_risk:         0.12
pdf_structure_risk:    0.10
text_consistency_risk: 0.18
qr_risk:               0.15
forensic_risk:         0.20
field_risk:            0.12
content_risk:          0.13
```

Only modules with numeric risk scores are included. Missing modules are not over-penalized. If too little evidence is available, the trust level is capped at review.

Trust levels:

```text
80-100: Likely Authentic, approve
60-79:  Low Risk, approve
40-59:  Suspicious, review
20-39:  High Risk, block_or_manual_review
0-19:   Very High Risk, block_or_manual_review
```

## DeepSeek Usage

DeepSeek is optional. When `DEEPSEEK_API_KEY` is configured and `run_llm_analysis=true`, BitCheck sends a structured prompt containing:

- document text excerpt
- metadata summary
- QR summary
- field extraction results
- heuristic risk signals

The prompt instructs DeepSeek to return JSON only, avoid certainty claims, avoid inventing external facts, avoid browsing the web, and mark external verification needs when official issuer confirmation is required.

## Operation Without DeepSeek

The service works without DeepSeek. If `DEEPSEEK_API_KEY` is missing:

- local validation still runs
- PDF/image processing still runs
- metadata, OCR, QR, forensic, field, content-risk, trust scoring, and report building still run
- `deepseek_analysis.used` is `false`
- the response includes a warning that DeepSeek reasoning was skipped

## Local Setup

```bash
cd /mnt/c/Users/Admin/Desktop/bitcheck-document/bitcheck-document-service
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

If you use `uv`:

```bash
uv venv .venv
uv pip install --python .venv/bin/python -r requirements.txt
```

For OCR support, install the Tesseract binary on the host or use the Docker image, which installs it.

## Environment Variables

See `.env.example`.

```text
DEEPSEEK_API_KEY=your_deepseek_api_key_here
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat
MAX_UPLOAD_MB=20
MAX_PDF_PAGES=5
LOG_LEVEL=INFO
```

`DEEPSEEK_API_KEY` is optional. Do not commit real keys.

## Running The App

```bash
uvicorn main:app --host 0.0.0.0 --port 7860
```

Health check:

```bash
curl http://localhost:7860/health
```

Generated output files are served from:

```text
http://localhost:7860/outputs/{filename}
```

## Example Curl Requests

Verify a PDF:

```bash
curl -X POST http://localhost:7860/verify/document \
  -F "file=@sample.pdf" \
  -F "document_type=general" \
  -F "run_ocr=true" \
  -F "run_forensics=true" \
  -F "run_qr=true" \
  -F "run_live_qr_check=false" \
  -F "run_llm_analysis=true" \
  -F "max_pages=5"
```

Verify an image without OCR:

```bash
curl -X POST http://localhost:7860/verify/document \
  -F "file=@sample.png" \
  -F "run_ocr=false" \
  -F "run_forensics=true" \
  -F "run_qr=true"
```

## Example Response

```json
{
  "verification_id": "6a6e7b6f-4df4-4d4f-9318-59b01f55f970",
  "service": "BitCheck",
  "file_type": "document",
  "status": "completed_with_warnings",
  "processing_time_ms": 3244,
  "input": {
    "document_type": "general",
    "run_ocr": true,
    "run_forensics": true,
    "run_qr": true,
    "run_live_qr_check": false,
    "run_llm_analysis": true,
    "max_pages": 5,
    "page_count": 1,
    "pages_processed": 1
  },
  "file_validation": {
    "valid": true,
    "original_filename": "sample.pdf",
    "stored_filename": "generated-name.pdf",
    "stored_path": "uploads/generated-name.pdf",
    "sha256": "hash",
    "mime_type": "application/pdf",
    "extension": ".pdf",
    "file_size_bytes": 12345,
    "warnings": []
  },
  "metadata": {
    "checked": true,
    "metadata_found": false,
    "metadata_risk_score": 0.0,
    "flags": [],
    "warnings": ["No metadata found. This is a low-risk signal, not proof of authenticity."]
  },
  "fields": {
    "checked": true,
    "document_type": "certificate",
    "extracted_fields": {},
    "missing_expected_fields": [],
    "field_confidence": 0.72,
    "field_risk_score": 0.21,
    "field_flags": [],
    "warnings": []
  },
  "content_risk": {
    "checked": true,
    "fraud_risk_score": 0.0,
    "ai_generated_text_likelihood": 0.0,
    "suspicious_claims": [],
    "signals": [],
    "summary": "No high-risk content wording was detected by heuristic checks.",
    "warnings": []
  },
  "deepseek_analysis": {
    "used": false,
    "model": "deepseek-chat",
    "document_type_inferred": null,
    "summary": "",
    "external_verification_required": true,
    "warnings": ["DeepSeek API key is not configured; LLM reasoning was skipped."]
  },
  "trust": {
    "trust_score": 59,
    "risk_score": 0.12,
    "risk_level": "Suspicious",
    "decision": "review",
    "available_modules": ["metadata_risk", "pdf_structure_risk"],
    "applied_overrides": ["Too little evidence was available for a confident automated decision."],
    "evidence_count": 2
  },
  "risk_flags": [],
  "recommended_actions": ["Verify the document directly with the issuing authority or official portal."],
  "limitations": ["BitCheck provides a risk-based estimate, not legal proof of forgery or authenticity."],
  "warnings": []
}
```

The actual response includes all detailed module sections.

## Hugging Face Spaces Deployment Guide

1. Create a new Hugging Face Space.
2. Select **Docker** as the Space SDK.
3. Upload this repository content to the Space.
4. In Space settings, add optional secrets:
   - `DEEPSEEK_API_KEY`
   - `DEEPSEEK_BASE_URL`
   - `DEEPSEEK_MODEL`
5. Keep the exposed port as `7860`.
6. The Dockerfile installs Python dependencies, Tesseract, and runtime libraries.
7. Hugging Face will build and start the app with:

```bash
uvicorn main:app --host 0.0.0.0 --port 7860
```

8. Test the deployed Space:

```bash
curl https://YOUR-SPACE-URL/health
```

9. Submit a sample document to:

```text
POST https://YOUR-SPACE-URL/verify/document
```

## Testing Instructions

Run syntax compilation:

```bash
python -m compileall .
```

Run tests:

```bash
pytest -q
```

The test suite covers validators, PDF/image processors, metadata analysis, QR URL analysis, live verifier helper behavior, field extraction, content risk, DeepSeek JSON parsing, trust scoring, and route-level document verification smoke tests.

## Limitations

- BitCheck provides a risk-based estimate, not legal proof of forgery or authenticity.
- Missing metadata does not prove a document is fake.
- Editing software metadata does not automatically prove manipulation.
- OCR may be inaccurate on low-quality scans.
- QR code detection does not mean the linked source is authentic unless externally verified.
- QR URLs are analyzed structurally but are not opened or browsed.
- Forensic visual analysis is not court-grade evidence.
- DeepSeek analysis does not perform live web or issuer database verification.
- High-stakes documents should be manually verified with the issuing authority.

## Future Improvements

- live issuer verification
- school/company database verification
- official certificate number lookup
- QR destination live validation
- digital signature validation
- C2PA document provenance
- template matching per institution
- logo verification
- stamp/signature detection model
- document layout transformer
- Supabase storage and audit history

Check out the configuration reference at https://huggingface.co/docs/hub/spaces-config-reference

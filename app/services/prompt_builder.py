import json

SYSTEM_MESSAGE = (
    "You are BitCheck's document verification analyst. Analyze extracted document text, metadata summary, "
    "QR code summary, field extraction results, and heuristic risk signals. Return structured JSON for "
    "document type inference, field extraction refinement, suspicious claims, missing expected fields, "
    "fraud indicators, external verification needs, and risk summary. Do not claim certainty. Do not invent "
    "external facts. Do not browse the web. Do not verify issuer records. If official verification is needed, "
    "mark external_verification_required as true. Return valid JSON only. No markdown. No commentary."
)


class PromptBuilder:
    def build_document_analysis_prompt(
        self,
        document_text: str,
        metadata_summary: dict,
        qr_summary: dict,
        field_results: dict,
        heuristic_risk: dict,
    ) -> str:
        payload = {
            "document_text_excerpt": (document_text or "")[:6000],
            "metadata_summary": metadata_summary,
            "qr_code_summary": qr_summary,
            "field_extraction_results": field_results,
            "heuristic_risk_signals": heuristic_risk,
            "expected_json_schema": {
                "document_type": "",
                "extracted_fields": {},
                "missing_expected_fields": [],
                "field_confidence": 0.0,
                "field_flags": [],
                "fraud_risk_score": 0.0,
                "ai_generated_text_likelihood": 0.0,
                "suspicious_claims": [],
                "signals": [],
                "summary": "",
                "external_verification_required": True,
                "recommended_actions": [],
            },
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)

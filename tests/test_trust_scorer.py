from app.services.trust_scorer import TrustScorer


def test_high_trust_case() -> None:
    result = TrustScorer().score(
        {
            "metadata": {"metadata_risk_score": 0.02, "metadata_found": True},
            "pdf_analysis": {"structure_risk_score": 0.02, "has_text_layer": True, "is_encrypted": False},
            "text_extraction": {"ocr_text_found": True},
            "text_consistency": {"risk_score": 0.05, "status": "strong_match"},
            "qr_analysis": {"risk_score": 0.0, "flags": [], "qr_text_consistency": {"mismatch_flags": []}},
            "forensics": {"visual_tampering_risk_score": 0.03},
            "fields": {"field_risk_score": 0.05},
            "content_risk": {"fraud_risk_score": 0.02},
        }
    )

    assert result.risk_level == "Likely Authentic"
    assert result.decision == "approve"
    assert result.trust_score >= 80


def test_suspicious_case() -> None:
    result = TrustScorer().score(
        {
            "metadata": {"metadata_risk_score": 0.45, "metadata_found": True},
            "pdf_analysis": {"structure_risk_score": 0.35, "has_text_layer": True, "is_encrypted": False},
            "text_extraction": {"ocr_text_found": True},
            "text_consistency": {"risk_score": 0.55, "status": "partial_match"},
            "qr_analysis": {"risk_score": 0.45, "flags": [], "qr_text_consistency": {"mismatch_flags": []}},
            "forensics": {"visual_tampering_risk_score": 0.45},
            "fields": {"field_risk_score": 0.55},
            "content_risk": {"fraud_risk_score": 0.5},
        }
    )

    assert result.risk_level == "Suspicious"
    assert result.decision == "review"
    assert 40 <= result.trust_score <= 59


def test_high_risk_override() -> None:
    result = TrustScorer().score(
        {
            "metadata": {"metadata_risk_score": 0.02, "metadata_found": True},
            "pdf_analysis": {"structure_risk_score": 0.02, "has_text_layer": True, "is_encrypted": False},
            "text_extraction": {"ocr_text_found": True},
            "text_consistency": {"risk_score": 0.05, "status": "strong_match"},
            "qr_analysis": {"risk_score": 0.0, "flags": [], "qr_text_consistency": {"mismatch_flags": []}},
            "forensics": {"visual_tampering_risk_score": 0.72},
            "fields": {"field_risk_score": 0.05},
            "content_risk": {"fraud_risk_score": 0.02},
        }
    )

    assert result.risk_level == "High Risk"
    assert result.decision == "block_or_manual_review"
    assert result.trust_score <= 39
    assert "Strong visual tampering risk detected." in result.applied_overrides


def test_academic_publication_context_prevents_forensics_only_block() -> None:
    result = TrustScorer().score(
        {
            "metadata": {"metadata_risk_score": 0.0, "metadata_found": True},
            "pdf_analysis": {"structure_risk_score": 0.0, "has_text_layer": True, "is_encrypted": False},
            "text_extraction": {"ocr_text_found": True},
            "text_consistency": {"risk_score": 0.03, "status": "strong_match"},
            "qr_analysis": {"risk_score": 0.0, "flags": [], "qr_text_consistency": {"mismatch_flags": []}},
            "forensics": {"visual_tampering_risk_score": 1.0},
            "fields": {"document_type": "academic_publication", "field_risk_score": 0.2},
            "content_risk": {"fraud_risk_score": 0.05},
            "deepseek_analysis": {
                "used": True,
                "document_type_inferred": "academic_publication",
                "external_verification_required": False,
            },
        }
    )

    assert result.risk_level in {"Low Risk", "Suspicious"}
    assert result.decision in {"approve", "review"}
    assert "Strong visual tampering risk detected." not in result.applied_overrides
    assert any("downgraded" in override for override in result.applied_overrides)


def test_insufficient_evidence_cap() -> None:
    result = TrustScorer().score({"content_risk": {"fraud_risk_score": 0.01}})

    assert result.risk_level == "Suspicious"
    assert result.decision == "review"
    assert result.trust_score == 59
    assert "Too little evidence was available for a confident automated decision." in result.applied_overrides

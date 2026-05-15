from app.services.metadata_analyzer import MetadataAnalyzer


def test_metadata_with_adobe_detects_editing_software() -> None:
    result = MetadataAnalyzer().analyze_pdf_metadata(
        {
            "creator": "Adobe Acrobat",
            "producer": "Adobe PDF Library",
            "creationDate": "D:20240101000000",
            "modDate": "D:20240101000000",
        }
    )

    assert result.metadata_found is True
    assert result.editing_software_detected is True
    assert "Adobe Acrobat" in result.known_tools_detected
    assert result.ai_tool_detected is False
    assert result.metadata_risk_score >= 0.3


def test_metadata_with_openai_detects_ai_tool() -> None:
    result = MetadataAnalyzer().analyze_image_exif(
        {
            "Software": "OpenAI DALL-E export",
            "DateTimeOriginal": "2024:01:01 00:00:00",
        }
    )

    assert result.ai_tool_detected is True
    assert "OpenAI" in result.detected_ai_tools
    assert "DALL-E" in result.detected_ai_tools
    assert result.metadata_risk_score >= 0.8
    assert "ai_tool_metadata_detected" in result.flags


def test_missing_metadata_does_not_create_high_risk() -> None:
    result = MetadataAnalyzer().analyze_pdf_metadata({})

    assert result.checked is True
    assert result.metadata_found is False
    assert result.ai_tool_detected is False
    assert result.editing_software_detected is False
    assert result.metadata_risk_score < 0.5
    assert result.warnings == ["No metadata found. This is a low-risk signal, not proof of authenticity."]


def test_modified_after_creation_sets_medium_risk() -> None:
    result = MetadataAnalyzer().analyze_pdf_metadata(
        {
            "creationDate": "D:20240101000000",
            "modDate": "D:20240201000000",
        }
    )

    assert result.modified_after_creation is True
    assert result.metadata_risk_score >= 0.5
    assert "modified_after_creation" in result.flags

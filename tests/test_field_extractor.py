from app.services.field_extractor import FieldExtractor


def test_certificate_like_text_extracts_certificate_number_date_and_institution() -> None:
    text = """
    Lagos Technical Institute
    Certificate of Completion
    This is to certify that Ada Lovelace completed the Data Verification Program.
    Certificate No: CERT-2026-001
    Date: 15 May 2026
    Signed by Registrar with official seal and stamp.
    """

    result = FieldExtractor().extract(text, "general")

    assert result.checked is True
    assert result.document_type == "certificate"
    assert result.extracted_fields["certificate_number"] == "CERT-2026-001"
    assert result.extracted_fields["date"] == "15 May 2026"
    assert result.extracted_fields["institution"] == "Lagos Technical Institute"
    assert result.extracted_fields["signature_present"] is True
    assert result.extracted_fields["stamp_present"] is True


def test_invoice_like_text_extracts_amount_and_invoice_number() -> None:
    text = """
    Invoice
    Vendor: BitCheck Labs
    Bill To: Example Customer Ltd
    Invoice Number: INV-2026-044
    Invoice Date: 2026-05-15
    Due Date: 2026-05-30
    VAT: NGN 7,500.00
    Total Amount: NGN 107,500.00
    Account Number: 0123456789
    Bank Name: Example Bank
    """

    result = FieldExtractor().extract(text, "general")

    assert result.document_type == "invoice"
    assert result.extracted_fields["invoice_number"] == "INV-2026-044"
    assert result.extracted_fields["total_amount"] == "NGN 107,500.00"
    assert result.extracted_fields["currency"] == "NGN"


def test_missing_expected_fields_increases_risk() -> None:
    sparse = FieldExtractor().extract("Certificate of Completion Certificate No: ABC-123", "certificate")
    complete = FieldExtractor().extract(
        """
        BitCheck Academy
        Certificate of Completion
        This is to certify that Grace Hopper completed the Security Program.
        Certificate Number: CERT-12345
        Grade: Distinction
        Date: 01/05/2026
        Issued by BitCheck Academy Registrar
        Signature and stamp present.
        """,
        "certificate",
    )

    assert "many_expected_fields_missing" in sparse.field_flags
    assert sparse.missing_expected_fields
    assert sparse.field_risk_score > complete.field_risk_score
    assert sparse.field_confidence < complete.field_confidence

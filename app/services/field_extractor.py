import re
from collections.abc import Callable

from app.schemas.document_verification import FieldExtractionAnalysis
from app.services.document_context import canonical_document_type
from app.utils.text_utils import normalize_text

SUPPORTED_DOCUMENT_TYPES = {
    "certificate",
    "academic_result",
    "invoice",
    "receipt",
    "business_registration",
    "identity_document",
    "bank_statement",
    "admission_letter",
    "result_slip",
    "contract",
    "academic_publication",
    "report",
    "general",
}

EXPECTED_FIELDS = {
    "certificate": [
        "name",
        "institution",
        "issuer",
        "date",
        "certificate_number",
        "course_program",
        "grade_class",
        "signature_present",
        "stamp_present",
    ],
    "academic_result": [
        "student_name",
        "institution",
        "matric_number",
        "department",
        "level",
        "session",
        "courses",
        "grades",
        "gpa",
        "cgpa",
        "date",
    ],
    "invoice": [
        "vendor_name",
        "invoice_number",
        "invoice_date",
        "due_date",
        "total_amount",
        "currency",
        "account_number",
        "bank_name",
        "tax_vat",
        "customer_name",
    ],
    "receipt": ["merchant", "amount", "date", "transaction_id", "payment_method"],
    "business_registration": ["business_name", "registration_number", "issuer", "date", "address"],
    "identity_document": ["name", "document_number", "date_of_birth", "expiry_date", "issuing_country"],
    "bank_statement": ["account_name", "account_number", "bank_name", "statement_period", "opening_balance", "closing_balance"],
    "admission_letter": ["student_name", "institution", "program", "admission_date", "session"],
    "result_slip": ["student_name", "institution", "matric_number", "session", "courses", "grades"],
    "contract": ["parties", "effective_date", "termination_date", "governing_law", "payment_terms", "signatures_present"],
    "academic_publication": ["title", "author", "publication_date", "doi", "publisher"],
    "report": ["title", "author", "date"],
    "general": [],
}

TYPE_KEYWORDS = {
    "certificate": ["certificate", "certify", "completion", "award", "diploma"],
    "academic_result": ["academic result", "transcript", "gpa", "cgpa", "matric", "department", "semester"],
    "invoice": ["invoice", "invoice no", "invoice number", "due date", "bill to", "vat"],
    "receipt": ["receipt", "payment received", "transaction id", "paid by", "payment method"],
    "business_registration": ["certificate of incorporation", "business registration", "registration number", "corporate affairs"],
    "identity_document": ["identity", "passport", "national id", "date of birth", "expiry date"],
    "bank_statement": ["bank statement", "opening balance", "closing balance", "account statement"],
    "admission_letter": ["admission letter", "offered admission", "admitted to", "program of study"],
    "result_slip": ["result slip", "statement of result", "subject", "score", "grade"],
    "contract": ["agreement", "contract", "party", "effective date", "governing law", "termination"],
    "academic_publication": ["abstract", "citation", "doi", "journal", "keywords", "references", "published"],
    "report": ["executive summary", "report", "findings", "recommendations"],
}

DATE_PATTERN = r"(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4}|\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\.?\s+\d{4})"
AMOUNT_PATTERN = r"((?:NGN|N|₦|USD|US\$|\$|EUR|€|GBP|£)\s?[\d,]+(?:\.\d{2})?|[\d,]+(?:\.\d{2})?\s?(?:NGN|USD|EUR|GBP))"


class FieldExtractor:
    def extract(self, text: str, document_type: str | None = "general") -> FieldExtractionAnalysis:
        warnings: list[str] = []
        cleaned_text = self._clean_text(text)
        requested_type = self._normalize_type(document_type)
        inferred_type = self.infer_document_type(cleaned_text) if requested_type == "general" else requested_type

        if not cleaned_text:
            warnings.append("No OCR or PDF text was available for field extraction.")

        extractors: dict[str, Callable[[str], dict[str, object]]] = {
            "certificate": self._extract_certificate,
            "academic_result": self._extract_academic_result,
            "invoice": self._extract_invoice,
            "receipt": self._extract_receipt,
            "business_registration": self._extract_business_registration,
            "identity_document": self._extract_identity_document,
            "bank_statement": self._extract_bank_statement,
            "admission_letter": self._extract_admission_letter,
            "result_slip": self._extract_result_slip,
            "contract": self._extract_contract,
            "academic_publication": self._extract_academic_publication,
            "report": self._extract_report,
            "general": self._extract_general,
        }
        extracted_fields = extractors[inferred_type](cleaned_text)
        expected_fields = EXPECTED_FIELDS[inferred_type]
        missing = [field for field in expected_fields if not self._has_field_value(extracted_fields.get(field))]
        confidence = self._confidence(extracted_fields, expected_fields, bool(cleaned_text))
        risk = self._risk(confidence, missing, expected_fields)
        flags: list[str] = []

        if inferred_type == "general":
            flags.append("document_type_not_inferred")
        if expected_fields and len(missing) >= max(2, len(expected_fields) // 2):
            flags.append("many_expected_fields_missing")
        elif missing:
            flags.append("some_expected_fields_missing")
        if not cleaned_text:
            flags.append("field_extraction_text_unavailable")

        return FieldExtractionAnalysis(
            checked=True,
            document_type=inferred_type,
            extracted_fields=extracted_fields,
            missing_expected_fields=missing,
            field_confidence=confidence,
            field_risk_score=risk,
            field_flags=flags,
            warnings=warnings,
        )

    def infer_document_type(self, text: str) -> str:
        normalized = normalize_text(text)
        if not normalized:
            return "general"
        scores: dict[str, int] = {}
        for document_type, keywords in TYPE_KEYWORDS.items():
            scores[document_type] = sum(1 for keyword in keywords if normalize_text(keyword) in normalized)
        best_type, best_score = max(scores.items(), key=lambda item: item[1])
        return best_type if best_score > 0 else "general"

    def _extract_certificate(self, text: str) -> dict[str, object]:
        return self._compact(
            {
                "name": self._first_match(text, [r"(?:awarded to|presented to|certifies that|this is to certify that)\s+([A-Z][A-Za-z .,'-]{2,80})"]),
                "institution": self._line_with_keywords(text, ["university", "college", "institute", "academy", "school"]),
                "issuer": self._first_match(text, [r"(?:issued by|issuer|awarded by)[:\s]+([A-Za-z0-9 &.,'-]{3,100})"]),
                "date": self._date(text),
                "certificate_number": self._first_match(
                    text,
                    [
                        r"(?:certificate|cert\.?|serial)\s*(?:no\.?|number|#)[:\s-]*([A-Z0-9][A-Z0-9/-]{3,40})",
                        r"\bcert(?:ificate)?[-\s#:]?([A-Z0-9]{3,}[-/][A-Z0-9/-]+)",
                    ],
                ),
                "course_program": self._first_match(text, [r"(?:course|program(?:me)?|training)[:\s]+([A-Za-z0-9 &.,'/-]{3,100})"]),
                "grade_class": self._first_match(text, [r"(?:grade|class|classification)[:\s]+([A-Za-z0-9 .'-]{2,60})"]),
                "signature_present": self._contains_any(text, ["signature", "signed", "registrar"]),
                "stamp_present": self._contains_any(text, ["stamp", "seal"]),
            }
        )

    def _extract_academic_result(self, text: str) -> dict[str, object]:
        courses, grades = self._extract_course_grades(text)
        return self._compact(
            {
                "student_name": self._first_match(text, [r"(?:student name|name)[:\s]+([A-Za-z .,'-]{3,80})"]),
                "institution": self._line_with_keywords(text, ["university", "college", "polytechnic", "school"]),
                "matric_number": self._first_match(text, [r"(?:matric(?:ulation)?(?: no\.?| number)?|reg(?:istration)? no\.?)[:\s-]*([A-Z0-9/.-]{4,40})"]),
                "department": self._first_match(text, [r"department[:\s]+([A-Za-z &,'-]{3,80})"]),
                "level": self._first_match(text, [r"\blevel[:\s]+([A-Za-z0-9 -]{2,30})", r"\b([1-6]00\s*level)\b"]),
                "session": self._first_match(text, [r"(?:session|academic year)[:\s]+(\d{4}\s*/\s*\d{4}|\d{4}\s*-\s*\d{4})"]),
                "courses": courses,
                "grades": grades,
                "gpa": self._first_match(text, [r"\bGPA[:\s]+([0-9](?:\.\d{1,2})?)"]),
                "cgpa": self._first_match(text, [r"\bCGPA[:\s]+([0-9](?:\.\d{1,2})?)"]),
                "date": self._date(text),
            }
        )

    def _extract_invoice(self, text: str) -> dict[str, object]:
        amount = self._first_match(text, [rf"(?:total amount|grand total|amount due|total)[:\s]*{AMOUNT_PATTERN}", AMOUNT_PATTERN])
        return self._compact(
            {
                "vendor_name": self._first_labeled_line(text, ["vendor", "from", "seller"]),
                "invoice_number": self._first_match(text, [r"(?:invoice\s*(?:no\.?|number|#)|inv\s*(?:no\.?|#))[:\s-]*([A-Z0-9][A-Z0-9/-]{2,40})"]),
                "invoice_date": self._first_match(text, [rf"(?:invoice date|date)[:\s]*{DATE_PATTERN}"]),
                "due_date": self._first_match(text, [rf"due date[:\s]*{DATE_PATTERN}"]),
                "total_amount": amount,
                "currency": self._currency(amount or text),
                "account_number": self._first_match(text, [r"(?:account(?: no\.?| number)?|acct(?: no\.?)?)[:\s-]*([0-9]{6,20})"]),
                "bank_name": self._first_match(text, [r"bank(?: name)?[:\s]+([A-Za-z &.'-]{3,80})"]),
                "tax_vat": self._first_match(text, [rf"(?:tax|vat)[:\s]*{AMOUNT_PATTERN}", r"(?:tax|vat)[:\s]*([0-9]+(?:\.\d+)?%)"]),
                "customer_name": self._first_labeled_line(text, ["bill to", "customer", "client"]),
            }
        )

    def _extract_receipt(self, text: str) -> dict[str, object]:
        amount = self._first_match(text, [rf"(?:amount paid|amount|total)[:\s]*{AMOUNT_PATTERN}", AMOUNT_PATTERN])
        return self._compact(
            {
                "merchant": self._first_labeled_line(text, ["merchant", "store", "vendor"]),
                "amount": amount,
                "date": self._date(text),
                "transaction_id": self._first_match(text, [r"(?:transaction id|txn id|receipt no\.?|reference)[:\s-]*([A-Z0-9][A-Z0-9/-]{3,40})"]),
                "payment_method": self._first_match(text, [r"(?:payment method|paid by|method)[:\s]+([A-Za-z0-9 -]{3,40})"]),
            }
        )

    def _extract_business_registration(self, text: str) -> dict[str, object]:
        return self._compact(
            {
                "business_name": self._first_match(text, [r"(?:business name|company name|name)[:\s]+([A-Za-z0-9 &.,'-]{3,100})"]),
                "registration_number": self._first_match(text, [r"(?:registration|rc|bn)\s*(?:no\.?|number|#)?[:\s-]*([A-Z0-9/-]{3,40})"]),
                "issuer": self._line_with_keywords(text, ["corporate affairs", "commission", "registry", "registrar"]),
                "date": self._date(text),
                "address": self._first_labeled_line(text, ["address", "registered office"]),
            }
        )

    def _extract_identity_document(self, text: str) -> dict[str, object]:
        return self._compact(
            {
                "name": self._first_match(text, [r"(?:surname|name)[:\s]+([A-Za-z .,'-]{3,80})"]),
                "document_number": self._first_match(text, [r"(?:document|passport|id|nin)\s*(?:no\.?|number|#)?[:\s-]*([A-Z0-9/-]{4,40})"]),
                "date_of_birth": self._first_match(text, [rf"(?:date of birth|dob)[:\s]*{DATE_PATTERN}"]),
                "expiry_date": self._first_match(text, [rf"(?:expiry date|expires|valid until)[:\s]*{DATE_PATTERN}"]),
                "issuing_country": self._first_match(text, [r"(?:issuing country|country)[:\s]+([A-Za-z .'-]{3,60})"]),
            }
        )

    def _extract_bank_statement(self, text: str) -> dict[str, object]:
        return self._compact(
            {
                "account_name": self._first_match(text, [r"account name[:\s]+([A-Za-z .,'-]{3,80})"]),
                "account_number": self._first_match(text, [r"account(?: no\.?| number)?[:\s-]*([0-9]{6,20})"]),
                "bank_name": self._line_with_keywords(text, ["bank", "microfinance"]),
                "statement_period": self._first_match(text, [r"(?:statement period|period)[:\s]+([A-Za-z0-9 ,/-]{5,80})"]),
                "opening_balance": self._first_match(text, [rf"opening balance[:\s]*{AMOUNT_PATTERN}"]),
                "closing_balance": self._first_match(text, [rf"closing balance[:\s]*{AMOUNT_PATTERN}"]),
            }
        )

    def _extract_admission_letter(self, text: str) -> dict[str, object]:
        return self._compact(
            {
                "student_name": self._first_match(text, [r"(?:dear|student name|name)[:\s,]+([A-Za-z .,'-]{3,80})"]),
                "institution": self._line_with_keywords(text, ["university", "college", "polytechnic", "school"]),
                "program": self._first_match(text, [r"(?:programme?|course of study|admitted to)[:\s]+([A-Za-z0-9 &,'/-]{3,100})"]),
                "admission_date": self._date(text),
                "session": self._first_match(text, [r"(?:session|academic year)[:\s]+(\d{4}\s*/\s*\d{4}|\d{4}\s*-\s*\d{4})"]),
            }
        )

    def _extract_result_slip(self, text: str) -> dict[str, object]:
        base = self._extract_academic_result(text)
        return {key: value for key, value in base.items() if key in EXPECTED_FIELDS["result_slip"]}

    def _extract_contract(self, text: str) -> dict[str, object]:
        return self._compact(
            {
                "parties": self._extract_parties(text),
                "effective_date": self._first_match(text, [rf"effective date[:\s]*{DATE_PATTERN}"]),
                "termination_date": self._first_match(text, [rf"(?:termination date|expires|end date)[:\s]*{DATE_PATTERN}"]),
                "governing_law": self._first_match(text, [r"governing law[:\s]+([A-Za-z .,'-]{3,100})"]),
                "payment_terms": self._first_match(text, [r"payment terms?[:\s]+([A-Za-z0-9 .,/%'-]{3,160})"]),
                "signatures_present": self._contains_any(text, ["signature", "signed by", "executed by"]),
            }
        )

    def _extract_academic_publication(self, text: str) -> dict[str, object]:
        return self._compact(
            {
                "title": self._first_match(text, [r"Article\s+(.{10,180}?)(?:\n| Ali | Abstract:)", r"^(.{10,180}?)(?:\n.+\nAbstract:)"]),
                "author": self._first_match(text, [r"\n([A-Z][A-Za-z .,'-]{2,80}(?:\s*,\s*[A-Z][A-Za-z .,'-]{2,80}){0,5})\s*\n"]),
                "publication_date": self._first_match(text, [r"(?:Published|Accepted|Received)[:\s]+([^\n\r]{6,40})"]),
                "doi": self._first_match(text, [r"\b(?:https?://doi\.org/)?(10\.\d{4,9}/[-._;()/:A-Z0-9]+)", r"\bdoi[:\s]+(10\.\d{4,9}/[-._;()/:A-Z0-9]+)"]),
                "publisher": self._first_match(text, [r"Publisher[’']?s Note[:\s]+([^\n\r]{3,120})", r"Licensee\s+([A-Za-z .,'-]{3,80})"]),
            }
        )

    def _extract_report(self, text: str) -> dict[str, object]:
        return self._compact(
            {
                "title": self._first_match(text, [r"^(.{10,160}?)(?:\n|$)"]),
                "author": self._first_labeled_line(text, ["author", "prepared by", "submitted by"]),
                "date": self._date(text),
            }
        )

    def _extract_general(self, text: str) -> dict[str, object]:
        return self._compact({"date": self._date(text), "reference_number": self._first_match(text, [r"(?:reference|ref|no\.?)[:\s-]*([A-Z0-9/-]{4,40})"])})

    def _clean_text(self, text: str | None) -> str:
        lines = [re.sub(r"[ \t]+", " ", line).strip() for line in (text or "").splitlines()]
        return "\n".join(line for line in lines if line).strip()

    def _normalize_type(self, document_type: str | None) -> str:
        normalized = canonical_document_type(document_type)
        return normalized if normalized in SUPPORTED_DOCUMENT_TYPES else "general"

    def _first_match(self, text: str, patterns: list[str]) -> str | None:
        for pattern in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                values = [group for group in match.groups() if group]
                return self._clean_value(values[-1] if values else match.group(0))
        return None

    def _date(self, text: str) -> str | None:
        return self._first_match(text, [DATE_PATTERN])

    def _first_labeled_line(self, text: str, labels: list[str]) -> str | None:
        for label in labels:
            pattern = rf"{re.escape(label)}[:\s]+([^\n\r|]+?)(?=\s{{2,}}|$)"
            value = self._first_match(text, [pattern])
            if value:
                return value
        return None

    def _line_with_keywords(self, text: str, keywords: list[str]) -> str | None:
        for line in re.split(r"[\n\r]+| {2,}", text):
            if any(keyword in line.lower() for keyword in keywords):
                return self._clean_value(line)
        return None

    def _contains_any(self, text: str, keywords: list[str]) -> bool:
        lowered = text.lower()
        return any(keyword in lowered for keyword in keywords)

    def _currency(self, text: str | None) -> str | None:
        if not text:
            return None
        currency_map = {
            "₦": "NGN",
            "NGN": "NGN",
            "N": "NGN",
            "$": "USD",
            "US$": "USD",
            "USD": "USD",
            "€": "EUR",
            "EUR": "EUR",
            "£": "GBP",
            "GBP": "GBP",
        }
        for marker, code in currency_map.items():
            if marker in text:
                return code
        return None

    def _extract_course_grades(self, text: str) -> tuple[list[str], dict[str, str]]:
        courses: list[str] = []
        grades: dict[str, str] = {}
        pattern = re.compile(r"\b([A-Z]{2,4}\s?\d{3})\b\s+([A-Za-z][A-Za-z &'-]{2,60}?)\s+([A-F][+-]?)\b", re.IGNORECASE)
        for match in pattern.finditer(text):
            code = match.group(1).upper().replace(" ", "")
            title = self._clean_value(match.group(2))
            grade = match.group(3).upper()
            courses.append(f"{code} {title}")
            grades[code] = grade
        return courses, grades

    def _extract_parties(self, text: str) -> list[str]:
        parties: list[str] = []
        for pattern in [r"between\s+(.+?)\s+and\s+(.+?)(?:\.|,| effective|$)", r"party a[:\s]+([^,.;]+).*?party b[:\s]+([^,.;]+)"]:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                parties.extend(self._clean_value(group) for group in match.groups() if group)
                break
        return [party for party in parties if party]

    def _confidence(self, fields: dict[str, object], expected_fields: list[str], has_text: bool) -> float:
        if not has_text:
            return 0.0
        if not expected_fields:
            return 0.35 if fields else 0.15
        found = sum(1 for field in expected_fields if self._has_field_value(fields.get(field)))
        return round(found / len(expected_fields), 2)

    def _risk(self, confidence: float, missing: list[str], expected_fields: list[str]) -> float:
        if not expected_fields:
            return round(1 - confidence, 2)
        missing_ratio = len(missing) / len(expected_fields)
        return round(min(max((1 - confidence) * 0.75 + missing_ratio * 0.25, 0.0), 1.0), 2)

    def _has_field_value(self, value: object) -> bool:
        if value is None:
            return False
        if isinstance(value, bool):
            return value
        if isinstance(value, (list, dict)):
            return bool(value)
        return bool(str(value).strip())

    def _compact(self, fields: dict[str, object | None]) -> dict[str, object]:
        return {key: value for key, value in fields.items() if self._has_field_value(value)}

    def _clean_value(self, value: str) -> str:
        return re.sub(r"\s+", " ", value).strip(" :-|,")

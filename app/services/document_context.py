from app.utils.text_utils import normalize_text


DOCUMENT_TYPE_ALIASES = {
    "academic_paper": "academic_publication",
    "academic_article": "academic_publication",
    "academic_publication": "academic_publication",
    "article": "academic_publication",
    "journal_article": "academic_publication",
    "publication": "academic_publication",
    "research_paper": "academic_publication",
    "paper": "academic_publication",
    "report": "report",
    "whitepaper": "report",
}

CONTEXTUAL_LONGFORM_TYPES = {
    "academic_publication",
    "report",
}


def canonical_document_type(document_type: str | None) -> str:
    normalized = normalize_text((document_type or "").replace("_", " ").replace("-", " ")).replace(" ", "_")
    return DOCUMENT_TYPE_ALIASES.get(normalized, normalized or "general")


def is_contextual_longform(document_type: str | None) -> bool:
    return canonical_document_type(document_type) in CONTEXTUAL_LONGFORM_TYPES

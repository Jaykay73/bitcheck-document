import re
import string
import unicodedata


def normalize_text(text: str | None) -> str:
    if not text:
        return ""
    normalized = unicodedata.normalize("NFKC", text).lower()
    normalized = normalized.translate(str.maketrans("", "", string.punctuation))
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized.strip()


def excerpt_text(text: str | None, max_chars: int = 500) -> str:
    if not text:
        return ""
    collapsed = re.sub(r"\s+", " ", text).strip()
    if len(collapsed) <= max_chars:
        return collapsed
    return collapsed[: max_chars - 3].rstrip() + "..."

import hashlib
import mimetypes
from pathlib import Path
from uuid import uuid4


SUPPORTED_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png", ".webp"}


def normalize_extension(filename: str) -> str:
    return Path(filename or "").suffix.lower()


def safe_original_filename(filename: str) -> str:
    name = Path(filename or "upload").name
    return name or "upload"


def build_safe_stored_filename(extension: str) -> str:
    return f"{uuid4().hex}{extension}"


def ensure_child_path(parent: Path, candidate: Path) -> Path:
    resolved_parent = parent.resolve()
    resolved_candidate = candidate.resolve()
    if resolved_parent != resolved_candidate.parent:
        raise ValueError("Path traversal attempt rejected")
    return resolved_candidate


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def guess_mime_type(filename: str) -> str:
    return mimetypes.guess_type(filename)[0] or "application/octet-stream"

import asyncio
import hashlib
from io import BytesIO
from pathlib import Path

import pytest
from starlette.datastructures import UploadFile

from app.config import Settings
from app.services.file_validator import FileValidationError, FileValidator


def make_settings(tmp_path: Path, max_upload_mb: int = 20) -> Settings:
    return Settings(
        app_name="BitCheck Document Verification API",
        version="1.0.0",
        upload_dir=tmp_path / "uploads",
        output_dir=tmp_path / "outputs",
        max_upload_mb=max_upload_mb,
        max_pdf_pages=5,
        deepseek_api_key=None,
        deepseek_base_url="https://api.deepseek.com",
        deepseek_model="deepseek-chat",
        log_level="INFO",
    )


def make_upload(filename: str, data: bytes) -> UploadFile:
    return UploadFile(filename=filename, file=BytesIO(data))


def validate(tmp_path: Path, filename: str, data: bytes):
    validator = FileValidator(make_settings(tmp_path))
    return asyncio.run(validator.validate_and_save(make_upload(filename, data)))


def test_supported_extension_passes(tmp_path: Path) -> None:
    result = validate(tmp_path, "sample.pdf", b"%PDF-1.7\ncontent")

    assert result.valid is True
    assert result.extension == ".pdf"
    assert Path(result.stored_path).exists()


def test_unsupported_extension_fails(tmp_path: Path) -> None:
    validator = FileValidator(make_settings(tmp_path))

    with pytest.raises(FileValidationError) as exc:
        asyncio.run(validator.validate_and_save(make_upload("sample.txt", b"hello")))

    assert exc.value.code == "unsupported_file_type"


def test_invalid_file_signature_fails(tmp_path: Path) -> None:
    validator = FileValidator(make_settings(tmp_path))

    with pytest.raises(FileValidationError) as exc:
        asyncio.run(validator.validate_and_save(make_upload("sample.png", b"not a png")))

    assert exc.value.code == "invalid_document"


def test_hash_generation_works(tmp_path: Path) -> None:
    data = b"\xff\xd8jpeg bytes"
    result = validate(tmp_path, "sample.jpg", data)

    assert result.sha256 == hashlib.sha256(data).hexdigest()


def test_safe_filename_is_used(tmp_path: Path) -> None:
    result = validate(tmp_path, "../unsafe.png", b"\x89PNG\r\n\x1a\n")

    assert result.original_filename == "unsafe.png"
    assert result.stored_filename != "unsafe.png"
    assert result.stored_filename.endswith(".png")
    assert Path(result.stored_path).parent == (tmp_path / "uploads").resolve()

from fastapi import UploadFile

from app.config import Settings
from app.schemas.document_verification import FileValidationResult
from app.utils.file_utils import (
    SUPPORTED_EXTENSIONS,
    build_safe_stored_filename,
    ensure_child_path,
    guess_mime_type,
    normalize_extension,
    safe_original_filename,
    sha256_hex,
)


class FileValidationError(Exception):
    def __init__(self, code: str, message: str, status_code: int) -> None:
        self.code = code
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class FileValidator:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def validate_and_save(self, upload: UploadFile) -> FileValidationResult:
        original_filename = safe_original_filename(upload.filename or "")
        extension = normalize_extension(original_filename)

        if extension not in SUPPORTED_EXTENSIONS:
            raise FileValidationError(
                "unsupported_file_type",
                "Unsupported file type. Supported files: PDF, JPG, JPEG, PNG, WEBP.",
                400,
            )

        contents = await self._read_with_size_limit(upload)
        self._validate_signature(contents, extension)

        stored_filename = build_safe_stored_filename(extension)
        upload_dir = self.settings.upload_dir
        upload_dir.mkdir(parents=True, exist_ok=True)
        stored_path = ensure_child_path(upload_dir, upload_dir / stored_filename)
        stored_path.write_bytes(contents)

        return FileValidationResult(
            valid=True,
            original_filename=original_filename,
            stored_filename=stored_filename,
            stored_path=str(stored_path),
            sha256=sha256_hex(contents),
            mime_type=guess_mime_type(stored_filename),
            extension=extension,
            file_size_bytes=len(contents),
            warnings=[],
        )

    async def _read_with_size_limit(self, upload: UploadFile) -> bytes:
        limit = self.settings.max_upload_bytes
        data = bytearray()
        upload.file.seek(0)

        while chunk := upload.file.read(1024 * 1024):
            data.extend(chunk)
            if len(data) > limit:
                raise FileValidationError(
                    "file_too_large",
                    f"File exceeds maximum upload size of {self.settings.max_upload_mb} MB.",
                    413,
                )

        upload.file.seek(0)
        if not data:
            raise FileValidationError("invalid_document", "Uploaded file is empty.", 400)
        return bytes(data)

    def _validate_signature(self, data: bytes, extension: str) -> None:
        if extension == ".pdf" and data.startswith(b"%PDF"):
            return
        if extension in {".jpg", ".jpeg"} and data.startswith(b"\xff\xd8"):
            return
        if extension == ".png" and data.startswith(b"\x89PNG"):
            return
        if extension == ".webp" and len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            return

        raise FileValidationError(
            "invalid_document",
            "File content does not match the declared document type.",
            400,
        )

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    app_name: str
    version: str
    upload_dir: Path
    output_dir: Path
    max_upload_mb: int
    max_pdf_pages: int
    deepseek_api_key: str | None
    deepseek_base_url: str
    deepseek_model: str
    log_level: str

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    @property
    def deepseek_available(self) -> bool:
        return bool(self.deepseek_api_key)


@lru_cache
def get_settings() -> Settings:
    return Settings(
        app_name=os.getenv("APP_NAME", "BitCheck Document Verification API"),
        version=os.getenv("VERSION", "1.0.0"),
        upload_dir=Path(os.getenv("UPLOAD_DIR", "uploads")),
        output_dir=Path(os.getenv("OUTPUT_DIR", "outputs")),
        max_upload_mb=int(os.getenv("MAX_UPLOAD_MB", "20")),
        max_pdf_pages=int(os.getenv("MAX_PDF_PAGES", "5")),
        deepseek_api_key=os.getenv("DEEPSEEK_API_KEY"),
        deepseek_base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
        deepseek_model=os.getenv("DEEPSEEK_MODEL", "deepseek-chat"),
        log_level=os.getenv("LOG_LEVEL", "INFO"),
    )

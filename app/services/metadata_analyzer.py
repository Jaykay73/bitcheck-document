from datetime import datetime
from typing import Mapping

from app.schemas.document_verification import MetadataAnalysis

KNOWN_EDITING_TOOLS = [
    "Adobe Acrobat",
    "Adobe Photoshop",
    "Microsoft Word",
    "Canva",
    "WPS",
    "LibreOffice",
    "Preview",
    "Illustrator",
    "InDesign",
    "GIMP",
    "Scanner",
    "CamScanner",
    "Smallpdf",
    "iLovePDF",
]

KNOWN_AI_TOOLS = [
    "ChatGPT",
    "OpenAI",
    "DALL-E",
    "DALL·E",
    "Midjourney",
    "Stable Diffusion",
    "ComfyUI",
    "Firefly",
    "Gemini",
    "Imagen",
    "Google AI",
]

PDF_FIELD_MAP = {
    "creator": "creator",
    "producer": "producer",
    "author": "author",
    "title": "title",
    "subject": "subject",
    "keywords": "keywords",
    "creationDate": "creation_date",
    "creation_date": "creation_date",
    "modDate": "modification_date",
    "modification_date": "modification_date",
}

IMAGE_CAMERA_KEYS = {"make", "model", "cameramake", "cameramodel", "271", "272"}
IMAGE_SOFTWARE_KEYS = {"software", "305"}
IMAGE_DATE_KEYS = {"datetimeoriginal", "datetime original", "36867", "datetime", "306"}
IMAGE_GPS_KEYS = {"gps", "gpsinfo", "34853"}


class MetadataAnalyzer:
    def analyze_pdf_metadata(self, metadata: Mapping[str, str | None]) -> MetadataAnalysis:
        normalized = self._normalize_pdf_metadata(metadata)
        return self._build_result(normalized, metadata)

    def analyze_image_exif(self, exif: Mapping[str, str | None]) -> MetadataAnalysis:
        normalized = self._normalize_image_exif(exif)
        return self._build_result(normalized, exif)

    def _normalize_pdf_metadata(self, metadata: Mapping[str, str | None]) -> dict[str, str | None]:
        normalized: dict[str, str | None] = {}
        for source_key, target_key in PDF_FIELD_MAP.items():
            value = metadata.get(source_key)
            if self._has_value(value):
                normalized[target_key] = str(value)
        return normalized

    def _normalize_image_exif(self, exif: Mapping[str, str | None]) -> dict[str, str | None]:
        normalized: dict[str, str | None] = {}
        for key, value in exif.items():
            if not self._has_value(value):
                continue
            lowered_key = str(key).lower().replace("_", "").replace(" ", "")
            if lowered_key in IMAGE_CAMERA_KEYS:
                existing = normalized.get("camera") or ""
                normalized["camera"] = f"{existing} {value}".strip()
            elif lowered_key in IMAGE_SOFTWARE_KEYS:
                normalized["creator"] = str(value)
            elif lowered_key in IMAGE_DATE_KEYS:
                normalized["creation_date"] = str(value)
            elif lowered_key in IMAGE_GPS_KEYS or lowered_key.startswith("gps"):
                normalized["gps"] = str(value)
            else:
                normalized[str(key)] = str(value)
        return normalized

    def _build_result(
        self,
        normalized: Mapping[str, str | None],
        raw_metadata: Mapping[str, str | None],
    ) -> MetadataAnalysis:
        searchable_text = " ".join(str(value) for value in raw_metadata.values() if self._has_value(value))
        metadata_found = any(self._has_value(value) for value in raw_metadata.values())
        known_tools = self._detect_tools(searchable_text, KNOWN_EDITING_TOOLS)
        ai_tools = self._detect_tools(searchable_text, KNOWN_AI_TOOLS)
        modified_after_creation = self._modified_after_creation(
            normalized.get("creation_date"),
            normalized.get("modification_date"),
        )
        camera_metadata_found = bool(normalized.get("camera")) or any(
            str(key).lower().replace("_", "").replace(" ", "") in IMAGE_CAMERA_KEYS
            for key, value in raw_metadata.items()
            if self._has_value(value)
        )
        gps_found = bool(normalized.get("gps")) or any(
            str(key).lower().startswith("gps") or str(key) in IMAGE_GPS_KEYS
            for key, value in raw_metadata.items()
            if self._has_value(value)
        )

        flags: list[str] = []
        warnings: list[str] = []
        risk = 0.0

        if not metadata_found:
            warnings.append("No metadata found. This is a low-risk signal, not proof of authenticity.")
        if ai_tools:
            flags.append("ai_tool_metadata_detected")
            risk = max(risk, 0.85)
        if modified_after_creation:
            flags.append("modified_after_creation")
            risk = max(risk, 0.5)
        if known_tools:
            flags.append("editing_software_detected")
            risk = max(risk, 0.3)
        if camera_metadata_found:
            flags.append("camera_metadata_found")
            risk = max(0.0, risk - 0.1)
        if gps_found:
            flags.append("gps_metadata_found")

        return MetadataAnalysis(
            checked=True,
            metadata_found=metadata_found,
            creator=normalized.get("creator"),
            producer=normalized.get("producer"),
            author=normalized.get("author"),
            title=normalized.get("title"),
            subject=normalized.get("subject"),
            keywords=normalized.get("keywords"),
            creation_date=normalized.get("creation_date"),
            modification_date=normalized.get("modification_date"),
            modified_after_creation=modified_after_creation,
            editing_software_detected=bool(known_tools),
            known_tools_detected=known_tools,
            ai_tool_detected=bool(ai_tools),
            detected_ai_tools=ai_tools,
            camera_metadata_found=camera_metadata_found,
            gps_found=gps_found,
            metadata_risk_score=round(risk, 2),
            flags=flags,
            warnings=warnings,
        )

    def _detect_tools(self, text: str, tools: list[str]) -> list[str]:
        lowered_text = text.lower()
        return [tool for tool in tools if tool.lower() in lowered_text]

    def _has_value(self, value: str | None) -> bool:
        if value is None:
            return False
        return str(value).strip().lower() not in {"", "none", "null"}

    def _modified_after_creation(
        self,
        creation_date: str | None,
        modification_date: str | None,
    ) -> bool:
        if not creation_date or not modification_date:
            return False
        creation = self._parse_metadata_date(creation_date)
        modification = self._parse_metadata_date(modification_date)
        if not creation or not modification:
            return creation_date != modification_date
        return modification > creation

    def _parse_metadata_date(self, value: str) -> datetime | None:
        cleaned = value.strip()
        if cleaned.startswith("D:"):
            cleaned = cleaned[2:]
        cleaned = cleaned.replace("Z", "")
        cleaned = cleaned.split("+", maxsplit=1)[0].split("-", maxsplit=1)[0]
        for fmt in ("%Y%m%d%H%M%S", "%Y%m%d%H%M", "%Y%m%d", "%Y:%m:%d %H:%M:%S"):
            try:
                return datetime.strptime(cleaned[: len(datetime.now().strftime(fmt))], fmt)
            except ValueError:
                continue
        return None

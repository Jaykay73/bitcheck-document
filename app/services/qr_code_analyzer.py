from pathlib import Path
from urllib.parse import urlparse

from app.schemas.document_verification import (
    LiveQRVerification,
    QRAnalysis,
    QRAnalysisItem,
    QRBoundingBox,
    QRTextConsistency,
)
from app.services.live_qr_verifier import LiveQRVerifier
from app.services.source_url_analyzer import SourceURLAnalyzer


class QRCodeAnalyzer:
    def __init__(self) -> None:
        self.url_analyzer = SourceURLAnalyzer()
        self.live_verifier = LiveQRVerifier()

    def analyze(
        self,
        page_images: list[str],
        run_qr: bool,
        run_live_qr_check: bool,
        extracted_fields: dict[str, str] | None = None,
    ) -> QRAnalysis:
        warnings: list[str] = []
        flags: list[str] = []
        if not run_qr:
            if run_live_qr_check:
                warnings.append("QR live browsing is disabled; BitCheck only performs structural QR URL analysis.")
            return self._empty(warnings=warnings)
        if run_live_qr_check:
            warnings.append("QR live browsing is disabled; BitCheck only performs structural QR URL analysis.")

        cv2 = self._load_cv2()
        if cv2 is None:
            warnings.append("OpenCV QRCodeDetector is unavailable; optional pyzbar decoding will be attempted if installed.")

        items: list[QRAnalysisItem] = []
        barcodes_found = False
        seen: set[tuple[str, int]] = set()
        for page_index, image_path in enumerate(page_images, start=1):
            if cv2 is not None:
                image = cv2.imread(str(Path(image_path)))
                if image is None:
                    warnings.append(f"Could not read page image for QR analysis: {image_path}")
                    continue
                for data, bbox in self._detect_qr_cv2(cv2, image):
                    key = (data, page_index)
                    if not data or key in seen:
                        continue
                    seen.add(key)
                    items.append(self._build_item(data, page_index, bbox, False, extracted_fields or {}))
            pyzbar_items, pyzbar_barcodes = self._detect_with_pyzbar(image_path, page_index, seen, False, extracted_fields or {})
            items.extend(pyzbar_items)
            barcodes_found = barcodes_found or pyzbar_barcodes

        consistency = self._qr_text_consistency(items, extracted_fields or {})
        risk = max([item.url_analysis.risk_score for item in items if item.url_analysis] + [consistency.risk_score, 0.0])
        live_risks = [item.live_verification.risk_score for item in items if item.live_verification and item.live_verification.risk_score is not None]
        if live_risks:
            risk = max(risk, max(live_risks))
        for item in items:
            if item.url_analysis:
                flags.extend(item.url_analysis.flags)
            if item.live_verification:
                flags.extend(item.live_verification.flags)
        flags.extend(consistency.mismatch_flags)

        return QRAnalysis(
            checked=True,
            qr_found=bool(items),
            barcodes_found=barcodes_found,
            items=items,
            qr_text_consistency=consistency,
            risk_score=round(min(risk, 1.0), 2),
            flags=list(dict.fromkeys(flags)),
            warnings=warnings,
        )

    def _build_item(
        self,
        data: str,
        page: int,
        bbox: QRBoundingBox,
        run_live_qr_check: bool,
        extracted_fields: dict[str, str],
    ) -> QRAnalysisItem:
        data_type = self._classify_data(data)
        url_analysis = self.url_analyzer.analyze(data) if data_type == "url" else None
        live_verification: LiveQRVerification | None = None
        if url_analysis:
            eligible = url_analysis.scheme in {"http", "https"} and not url_analysis.is_private_or_internal
            live_verification = self.live_verifier.not_requested(eligible=eligible)
        return QRAnalysisItem(
            type="QR_CODE",
            data=data,
            data_type=data_type,
            page=page,
            bbox=bbox,
            url_analysis=url_analysis,
            live_verification=live_verification,
        )

    def _detect_qr_cv2(self, cv2, image) -> list[tuple[str, QRBoundingBox]]:
        detector = cv2.QRCodeDetector()
        results: list[tuple[str, QRBoundingBox]] = []
        try:
            ok, decoded_info, points, _ = detector.detectAndDecodeMulti(image)
            if ok and points is not None:
                for data, point_set in zip(decoded_info, points):
                    results.append((data, self._bbox_from_points(point_set)))
                return results
        except Exception:
            pass
        try:
            data, points, _ = detector.detectAndDecode(image)
            if data and points is not None:
                results.append((data, self._bbox_from_points(points[0])))
        except Exception:
            pass
        return results

    def _detect_with_pyzbar(
        self,
        image_path: str,
        page: int,
        seen: set[tuple[str, int]],
        run_live_qr_check: bool,
        extracted_fields: dict[str, str],
    ) -> tuple[list[QRAnalysisItem], bool]:
        try:
            from PIL import Image
            from pyzbar.pyzbar import decode
        except Exception:
            return [], False
        items: list[QRAnalysisItem] = []
        barcodes_found = False
        try:
            decoded = decode(Image.open(image_path))
        except Exception:
            return [], False
        for item in decoded:
            data = item.data.decode("utf-8", errors="ignore")
            key = (data, page)
            if key in seen:
                continue
            seen.add(key)
            rect = item.rect
            bbox = QRBoundingBox(x=rect.left, y=rect.top, width=rect.width, height=rect.height)
            if item.type == "QRCODE":
                items.append(self._build_item(data, page, bbox, run_live_qr_check, extracted_fields))
            else:
                barcodes_found = True
        return items, barcodes_found

    def _qr_text_consistency(self, items: list[QRAnalysisItem], fields: dict[str, str]) -> QRTextConsistency:
        matched: list[str] = []
        mismatches: list[str] = []
        searchable = " ".join(item.data for item in items).lower()
        for key, value in fields.items():
            if value and str(value).lower() in searchable:
                matched.append(key)
        return QRTextConsistency(
            checked=True,
            matched_document_fields=matched,
            mismatch_flags=mismatches,
            risk_score=0.0 if not mismatches else 0.4,
        )

    def _bbox_from_points(self, points) -> QRBoundingBox:
        xs = [int(point[0]) for point in points]
        ys = [int(point[1]) for point in points]
        return QRBoundingBox(x=min(xs), y=min(ys), width=max(xs) - min(xs), height=max(ys) - min(ys))

    def _classify_data(self, data: str) -> str:
        parsed = urlparse(data)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return "url"
        if data.lower().startswith("mailto:") or "@" in data:
            return "email"
        if data.lower().startswith("tel:") or data.replace("+", "").replace("-", "").replace(" ", "").isdigit():
            return "phone"
        if data.strip():
            return "plain_text"
        return "unknown"

    def _empty(self, warnings: list[str] | None = None) -> QRAnalysis:
        return QRAnalysis(
            checked=True,
            qr_found=False,
            barcodes_found=False,
            items=[],
            qr_text_consistency=QRTextConsistency(
                checked=True,
                matched_document_fields=[],
                mismatch_flags=[],
                risk_score=0.0,
            ),
            risk_score=0.0,
            flags=[],
            warnings=warnings or [],
        )

    def _load_cv2(self):
        try:
            import cv2

            return cv2
        except Exception:
            return None

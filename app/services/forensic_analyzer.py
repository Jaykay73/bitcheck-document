from pathlib import Path
from uuid import uuid4

from app.config import Settings
from app.schemas.document_verification import ForensicAnalysis, SuspiciousRegion

DISCLAIMER = "Forensic indicators are risk signals, not definitive proof of tampering."


class ForensicAnalyzer:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def analyze(self, page_images: list[str]) -> ForensicAnalysis:
        cv2, np = self._load_dependencies()
        if cv2 is None or np is None:
            return ForensicAnalysis(
                checked=True,
                visual_tampering_risk_score=0.0,
                sharpness_score=0.0,
                compression_risk=0.0,
                noise_inconsistency_risk=0.0,
                blur_inconsistency_risk=0.0,
                edge_inconsistency_risk=0.0,
                layout_risk=0.0,
                suspicious_regions=[],
                annotated_pages=[],
                flags=[],
                warnings=["OpenCV or numpy is unavailable; visual forensic analysis was skipped."],
                disclaimer=DISCLAIMER,
            )

        all_regions: list[SuspiciousRegion] = []
        annotated_pages: list[str] = []
        page_scores: list[dict[str, float]] = []
        warnings: list[str] = []

        for page_number, image_path in enumerate(page_images, start=1):
            image = cv2.imread(str(Path(image_path)))
            if image is None:
                warnings.append(f"Could not read page image for forensic analysis: {image_path}")
                continue
            page_result = self._analyze_page(cv2, np, image, page_number)
            page_scores.append(page_result["scores"])
            all_regions.extend(page_result["regions"])
            annotated_pages.append(self._save_annotated_page(cv2, image, page_result["regions"], page_number))

        top_regions = sorted(all_regions, key=lambda region: region.risk_score, reverse=True)[:10]
        aggregate = self._aggregate_scores(page_scores)
        flags: list[str] = []
        if top_regions:
            flags.append("possible_visual_inconsistency_regions")
        if aggregate["visual_tampering_risk_score"] >= 0.5:
            flags.append("suspicious_local_artifacts_require_manual_review")

        return ForensicAnalysis(
            checked=True,
            visual_tampering_risk_score=aggregate["visual_tampering_risk_score"],
            sharpness_score=aggregate["sharpness_score"],
            compression_risk=aggregate["compression_risk"],
            noise_inconsistency_risk=aggregate["noise_inconsistency_risk"],
            blur_inconsistency_risk=aggregate["blur_inconsistency_risk"],
            edge_inconsistency_risk=aggregate["edge_inconsistency_risk"],
            layout_risk=aggregate["layout_risk"],
            suspicious_regions=top_regions,
            annotated_pages=annotated_pages,
            flags=flags,
            warnings=warnings,
            disclaimer=DISCLAIMER,
        )

    def _analyze_page(self, cv2, np, image, page_number: int) -> dict:
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        laplacian = cv2.Laplacian(gray, cv2.CV_64F)
        sharpness = float(laplacian.var())
        edges = cv2.Canny(gray, 80, 180)
        compression_risk = self._compression_proxy(np, gray)

        rows, cols = 8, 8
        height, width = gray.shape
        block_metrics: list[dict] = []
        for row in range(rows):
            for col in range(cols):
                x1 = int(col * width / cols)
                x2 = int((col + 1) * width / cols)
                y1 = int(row * height / rows)
                y2 = int((row + 1) * height / rows)
                block = gray[y1:y2, x1:x2]
                block_edges = edges[y1:y2, x1:x2]
                if block.size == 0:
                    continue
                block_lap = cv2.Laplacian(block, cv2.CV_64F)
                blur_score = float(block_lap.var())
                noise_score = float((block.astype("float32") - cv2.GaussianBlur(block, (3, 3), 0).astype("float32")).std())
                edge_density = float((block_edges > 0).mean())
                brightness = float(block.mean())
                contrast = float(block.std())
                block_metrics.append(
                    {
                        "row": row,
                        "col": col,
                        "x": x1,
                        "y": y1,
                        "width": x2 - x1,
                        "height": y2 - y1,
                        "blur": blur_score,
                        "noise": noise_score,
                        "edge": edge_density,
                        "brightness": brightness,
                        "contrast": contrast,
                    }
                )

        suspicious_regions, risks = self._suspicious_regions(np, block_metrics, page_number)
        layout_risk = min(len(suspicious_regions) / 10, 1.0)
        visual_risk = max(
            risks["noise_inconsistency_risk"],
            risks["blur_inconsistency_risk"],
            risks["edge_inconsistency_risk"],
            compression_risk,
            layout_risk,
        )

        return {
            "regions": suspicious_regions,
            "scores": {
                "visual_tampering_risk_score": round(float(visual_risk), 2),
                "sharpness_score": round(sharpness, 2),
                "compression_risk": round(float(compression_risk), 2),
                "noise_inconsistency_risk": round(risks["noise_inconsistency_risk"], 2),
                "blur_inconsistency_risk": round(risks["blur_inconsistency_risk"], 2),
                "edge_inconsistency_risk": round(risks["edge_inconsistency_risk"], 2),
                "layout_risk": round(layout_risk, 2),
            },
        }

    def _suspicious_regions(self, np, block_metrics: list[dict], page_number: int) -> tuple[list[SuspiciousRegion], dict[str, float]]:
        if not block_metrics:
            return [], {"noise_inconsistency_risk": 0.0, "blur_inconsistency_risk": 0.0, "edge_inconsistency_risk": 0.0}

        metrics = {
            "blur": np.array([block["blur"] for block in block_metrics], dtype=float),
            "noise": np.array([block["noise"] for block in block_metrics], dtype=float),
            "edge": np.array([block["edge"] for block in block_metrics], dtype=float),
            "brightness": np.array([block["brightness"] for block in block_metrics], dtype=float),
            "contrast": np.array([block["contrast"] for block in block_metrics], dtype=float),
        }
        z_scores = {name: self._robust_z(np, values) for name, values in metrics.items()}
        regions: list[SuspiciousRegion] = []
        risks = {
            "noise_inconsistency_risk": float(min(max(abs(z_scores["noise"]).max() / 6, 0), 1)),
            "blur_inconsistency_risk": float(min(max(abs(z_scores["blur"]).max() / 6, 0), 1)),
            "edge_inconsistency_risk": float(min(max(abs(z_scores["edge"]).max() / 6, 0), 1)),
        }

        for index, block in enumerate(block_metrics):
            reasons: list[str] = []
            risk_components = [
                abs(float(z_scores["noise"][index])),
                abs(float(z_scores["blur"][index])),
                abs(float(z_scores["edge"][index])),
                abs(float(z_scores["brightness"][index])),
                abs(float(z_scores["contrast"][index])),
            ]
            if abs(float(z_scores["noise"][index])) >= 2.5:
                reasons.append("possible visual inconsistency in local noise")
            if abs(float(z_scores["blur"][index])) >= 2.5:
                reasons.append("suspicious local artifact in sharpness/blur")
            if abs(float(z_scores["edge"][index])) >= 2.5:
                reasons.append("region requiring manual review for edge density")
            if abs(float(z_scores["brightness"][index])) >= 2.8 or abs(float(z_scores["contrast"][index])) >= 2.8:
                reasons.append("possible visual inconsistency in brightness or contrast")
            if not reasons:
                continue
            regions.append(
                SuspiciousRegion(
                    page=page_number,
                    x=block["x"],
                    y=block["y"],
                    width=block["width"],
                    height=block["height"],
                    risk_score=round(float(min(max(risk_components) / 6, 1)), 2),
                    reason="; ".join(reasons),
                )
            )
        return regions, risks

    def _robust_z(self, np, values):
        median = np.median(values)
        mad = np.median(np.abs(values - median))
        if mad < 1e-6:
            std = values.std() or 1.0
            return (values - values.mean()) / std
        return 0.6745 * (values - median) / mad

    def _compression_proxy(self, np, gray) -> float:
        vertical = np.abs(np.diff(gray.astype("float32"), axis=1))
        horizontal = np.abs(np.diff(gray.astype("float32"), axis=0))
        boundary_v = vertical[:, 7::8].mean() if vertical.shape[1] > 8 else 0.0
        boundary_h = horizontal[7::8, :].mean() if horizontal.shape[0] > 8 else 0.0
        overall = (vertical.mean() + horizontal.mean()) / 2 + 1e-6
        return float(min(((boundary_v + boundary_h) / 2) / (overall * 3), 1.0))

    def _aggregate_scores(self, page_scores: list[dict[str, float]]) -> dict[str, float]:
        keys = [
            "visual_tampering_risk_score",
            "sharpness_score",
            "compression_risk",
            "noise_inconsistency_risk",
            "blur_inconsistency_risk",
            "edge_inconsistency_risk",
            "layout_risk",
        ]
        if not page_scores:
            return {key: 0.0 for key in keys}
        return {key: round(max(score[key] for score in page_scores), 2) for key in keys}

    def _save_annotated_page(self, cv2, image, regions: list[SuspiciousRegion], page_number: int) -> str:
        annotated = image.copy()
        for region in regions[:10]:
            start = (region.x, region.y)
            end = (region.x + region.width, region.y + region.height)
            cv2.rectangle(annotated, start, end, (0, 0, 255), 2)
            cv2.putText(annotated, "review", (region.x, max(12, region.y - 4)), cv2.FONT_HERSHEY_SIMPLEX, 0.4, (0, 0, 255), 1)
        self.settings.output_dir.mkdir(parents=True, exist_ok=True)
        filename = f"forensics_page_{page_number}_{uuid4().hex}.png"
        destination = self.settings.output_dir / filename
        cv2.imwrite(str(destination), annotated)
        return f"outputs/{filename}"

    def _load_dependencies(self):
        try:
            import cv2
            import numpy as np

            return cv2, np
        except Exception:
            return None, None

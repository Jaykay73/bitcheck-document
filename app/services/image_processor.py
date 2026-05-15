from pathlib import Path

from PIL import Image, UnidentifiedImageError

from app.config import Settings
from app.schemas.document_verification import ImageAnalysis
from app.utils.image_utils import clean_exif, save_rgb_image


class ImageProcessor:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def process(self, image_path: Path) -> ImageAnalysis:
        warnings: list[str] = []

        try:
            with Image.open(image_path) as image:
                width, height = image.size
                image_format = image.format
                raw_exif = clean_exif(image)
                normalized_path = save_rgb_image(image, self.settings.output_dir, "image_page")
        except UnidentifiedImageError as exc:
            raise ValueError("Image could not be opened safely.") from exc

        return ImageAnalysis(
            checked=True,
            is_image=True,
            width=width,
            height=height,
            format=image_format,
            mode="RGB",
            normalized_image=normalized_path,
            page_images=[normalized_path],
            raw_exif=raw_exif,
            warnings=warnings,
        )

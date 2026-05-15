from pathlib import Path
from uuid import uuid4

from PIL import Image


def output_image_path(output_dir: Path, prefix: str, suffix: str = ".png") -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir / f"{prefix}_{uuid4().hex}{suffix}"


def save_rgb_image(image: Image.Image, output_dir: Path, prefix: str) -> str:
    normalized = image.convert("RGB")
    destination = output_image_path(output_dir, prefix)
    normalized.save(destination, format="PNG")
    return str(destination.resolve())


def clean_exif(image: Image.Image) -> dict[str, str]:
    raw_exif = image.getexif()
    if not raw_exif:
        return {}
    return {str(key): str(value) for key, value in raw_exif.items()}

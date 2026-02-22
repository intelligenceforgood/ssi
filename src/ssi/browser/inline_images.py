"""Extract and analyse inline data-URI images from a web page.

Saves images above a configurable size threshold to the evidence directory,
runs QR/barcode detection on each, and returns structured metadata.  Any
wallet addresses found in QR codes are returned so the caller can merge
them into the investigation result.
"""

from __future__ import annotations

import base64
import hashlib
import io
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from PIL import Image

if TYPE_CHECKING:
    from playwright.sync_api import Page

logger = logging.getLogger(__name__)

# Minimum decoded image size (bytes) worth saving.  Tiny UI icons and
# single-pixel spacers are below this and can be ignored.
_MIN_IMAGE_BYTES = 1024  # 1 KB


@dataclass
class InlineImage:
    """Metadata for a single inline image extracted from the page."""

    filename: str
    saved_path: str
    mime_type: str
    size_bytes: int
    width: int
    height: int
    sha256: str
    qr_data: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize to a plain dict for JSON / Pydantic."""
        return {
            "filename": self.filename,
            "saved_path": self.saved_path,
            "mime_type": self.mime_type,
            "size_bytes": self.size_bytes,
            "width": self.width,
            "height": self.height,
            "sha256": self.sha256,
            "qr_data": self.qr_data,
        }


def extract_inline_images(
    page: Page,
    output_dir: Path,
    *,
    min_bytes: int = _MIN_IMAGE_BYTES,
) -> list[InlineImage]:
    """Extract data-URI images from *page* and save those above *min_bytes*.

    Args:
        page: A Playwright ``Page`` object (after navigation).
        output_dir: Directory to write extracted images into.
        min_bytes: Skip images smaller than this after base64 decoding.

    Returns:
        List of ``InlineImage`` metadata objects.
    """
    data_uris: list[dict[str, str]] = page.evaluate(
        """() => {
        const results = [];
        document.querySelectorAll('img[src^="data:image"]').forEach(el => {
            results.push({
                src: el.src,
                alt: el.alt || '',
                naturalWidth: el.naturalWidth || 0,
                naturalHeight: el.naturalHeight || 0,
            });
        });
        return results;
    }"""
    )

    if not data_uris:
        return []

    images_dir = output_dir / "inline_images"
    images_dir.mkdir(parents=True, exist_ok=True)

    results: list[InlineImage] = []
    seen_hashes: set[str] = set()

    for idx, entry in enumerate(data_uris):
        src: str = entry.get("src", "")
        if not src.startswith("data:image"):
            continue

        try:
            # Parse data URI: data:image/png;base64,AAAA...
            header, b64_data = src.split(",", 1)
            mime = header.split(";")[0].replace("data:", "")
            raw = base64.b64decode(b64_data)
        except Exception:
            logger.debug("Failed to parse data URI at index %d", idx)
            continue

        if len(raw) < min_bytes:
            continue

        digest = hashlib.sha256(raw).hexdigest()
        if digest in seen_hashes:
            continue
        seen_hashes.add(digest)

        # Determine file extension from MIME
        ext = _mime_to_ext(mime)
        filename = f"inline_{idx:03d}{ext}"
        saved_path = images_dir / filename

        # Save raw bytes
        saved_path.write_bytes(raw)

        # Get dimensions via Pillow
        width, height = 0, 0
        try:
            with Image.open(io.BytesIO(raw)) as img:
                width, height = img.size
        except Exception:
            logger.debug("Failed to read image dimensions for index %d", idx)

        # QR / barcode scan
        qr_data = _scan_qr(raw)

        info = InlineImage(
            filename=filename,
            saved_path=str(saved_path),
            mime_type=mime,
            size_bytes=len(raw),
            width=width,
            height=height,
            sha256=digest,
            qr_data=qr_data,
        )
        results.append(info)
        logger.info(
            "Saved inline image %s (%dx%d, %d bytes%s)",
            filename,
            width,
            height,
            len(raw),
            f", QR: {qr_data}" if qr_data else "",
        )

    return results


def _scan_qr(image_bytes: bytes) -> list[str]:
    """Decode QR codes / barcodes from *image_bytes*.

    Returns a list of decoded text strings.  Returns an empty list if
    pyzbar is not available or no codes are detected.
    """
    try:
        from pyzbar.pyzbar import decode as pyzbar_decode

        with Image.open(io.BytesIO(image_bytes)) as img:
            # Convert to RGB if necessary (pyzbar needs it)
            if img.mode not in ("L", "RGB"):
                img = img.convert("RGB")
            codes = pyzbar_decode(img)
            return [c.data.decode("utf-8", errors="replace") for c in codes]
    except ImportError:
        logger.debug("pyzbar not available — skipping QR detection")
        return []
    except Exception as e:
        logger.debug("QR scan failed: %s", e)
        return []


def _mime_to_ext(mime: str) -> str:
    """Map an image MIME type to a file extension."""
    mapping = {
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "image/gif": ".gif",
        "image/webp": ".webp",
        "image/svg+xml": ".svg",
        "image/bmp": ".bmp",
        "image/x-icon": ".ico",
    }
    return mapping.get(mime, ".png")

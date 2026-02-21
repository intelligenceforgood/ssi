"""Malware download interception and hash-based classification.

Hooks into Playwright's download events to capture file downloads
triggered during page visits.  Every captured file is:

1. Saved to a sandboxed directory with the original filename.
2. Hashed (SHA-256, MD5) for later malware-database lookups.
3. Optionally checked against VirusTotal's file-hash API.

The ``DownloadInterceptor`` class is designed to be attached to a
Playwright page *before* navigation so that all file downloads
(including drive-by downloads) are captured.
"""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from playwright.sync_api import Page

# Maximum file size we're willing to capture (50 MB)
_MAX_DOWNLOAD_SIZE_BYTES = 50 * 1024 * 1024


@dataclass
class CapturedDownload:
    """Record of a single file download intercepted during a session."""

    url: str
    suggested_filename: str
    saved_path: str = ""
    sha256: str = ""
    md5: str = ""
    size_bytes: int = 0
    content_type: str = ""
    vt_result: dict[str, Any] = field(default_factory=dict)
    is_malicious: bool = False
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dict."""
        return {
            "url": self.url,
            "suggested_filename": self.suggested_filename,
            "saved_path": self.saved_path,
            "sha256": self.sha256,
            "md5": self.md5,
            "size_bytes": self.size_bytes,
            "content_type": self.content_type,
            "vt_result": self.vt_result,
            "is_malicious": self.is_malicious,
            "error": self.error,
        }


class DownloadInterceptor:
    """Captures and classifies file downloads from a Playwright page.

    Attach to a page **before** navigation via :meth:`attach`:

    .. code-block:: python

        interceptor = DownloadInterceptor(output_dir=Path("evidence/downloads"))
        interceptor.attach(page)
        page.goto(url)
        # ... later ...
        for dl in interceptor.downloads:
            print(dl.sha256, dl.is_malicious)

    Args:
        output_dir: Sandboxed directory where downloaded files are stored.
        check_virustotal: When True, check each file hash against VirusTotal.
        max_size_bytes: Skip files larger than this threshold.
    """

    def __init__(
        self,
        output_dir: Path,
        check_virustotal: bool = False,
        max_size_bytes: int = _MAX_DOWNLOAD_SIZE_BYTES,
    ) -> None:
        self.output_dir = output_dir
        self.check_virustotal = check_virustotal
        self.max_size_bytes = max_size_bytes
        self.downloads: list[CapturedDownload] = []

        self.output_dir.mkdir(parents=True, exist_ok=True)

    def attach(self, page: Page) -> None:
        """Register download event handler on a Playwright page.

        Must be called **before** ``page.goto(...)`` to capture downloads
        triggered during page load.
        """
        page.on("download", self._on_download)
        logger.debug("Download interceptor attached to page")

    def _on_download(self, download) -> None:
        """Handle a Playwright Download event."""
        url = download.url
        suggested = download.suggested_filename
        record = CapturedDownload(url=url, suggested_filename=suggested)

        logger.info("Download intercepted: %s (%s)", suggested, url)

        try:
            # Save to sandboxed directory
            save_path = self.output_dir / suggested

            # Avoid overwriting — append counter if file exists
            counter = 1
            original_stem = save_path.stem
            while save_path.exists():
                save_path = save_path.with_name(f"{original_stem}_{counter}{save_path.suffix}")
                counter += 1

            download.save_as(str(save_path))
            record.saved_path = str(save_path)

            # Check file size
            file_size = save_path.stat().st_size
            record.size_bytes = file_size

            if file_size > self.max_size_bytes:
                record.error = f"File too large ({file_size} bytes > {self.max_size_bytes} limit)"
                logger.warning("Skipping hash for oversized download: %s (%d bytes)", suggested, file_size)
                self.downloads.append(record)
                return

            # Compute hashes
            sha256, md5 = _compute_hashes(save_path)
            record.sha256 = sha256
            record.md5 = md5

            logger.info("Download saved: %s (SHA-256: %s, %d bytes)", save_path.name, sha256[:16], file_size)

            # VirusTotal hash check
            if self.check_virustotal and sha256:
                vt_result = _check_hash_virustotal(sha256)
                record.vt_result = vt_result
                record.is_malicious = vt_result.get("malicious", False)
                if record.is_malicious:
                    logger.warning(
                        "MALICIOUS file detected: %s (SHA-256: %s) — %s",
                        suggested,
                        sha256,
                        vt_result.get("context", ""),
                    )

        except Exception as e:
            record.error = str(e)
            logger.warning("Failed to process download %s: %s", suggested, e)

        self.downloads.append(record)


def _compute_hashes(path: Path) -> tuple[str, str]:
    """Compute SHA-256 and MD5 hashes of a file.

    Reads the file in 64 KB chunks to handle large files without
    loading them entirely into memory.

    Returns:
        Tuple of (sha256_hex, md5_hex).
    """
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()  # noqa: S324 — MD5 used for VT lookup, not security

    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            sha256.update(chunk)
            md5.update(chunk)

    return sha256.hexdigest(), md5.hexdigest()


def _check_hash_virustotal(sha256: str) -> dict[str, Any]:
    """Check a file hash against VirusTotal's file report API.

    Requires ``SSI_OSINT__VIRUSTOTAL_API_KEY`` to be configured.

    Returns:
        A dict with ``malicious`` (bool), ``detections`` (int),
        ``total_engines`` (int), and ``context`` (str).
    """
    from ssi.settings import get_settings

    settings = get_settings()
    api_key = settings.osint.virustotal_api_key
    if not api_key:
        logger.debug("VirusTotal API key not configured — skipping file hash check")
        return {}

    import httpx

    headers = {"x-apikey": api_key}

    try:
        resp = httpx.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers=headers,
            timeout=15,
        )

        if resp.status_code == 404:
            logger.info("File hash %s not found in VirusTotal database", sha256[:16])
            return {"malicious": False, "context": "Hash not in VT database"}

        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        is_malicious = (malicious_count + suspicious_count) > 0

        return {
            "malicious": is_malicious,
            "detections": malicious_count + suspicious_count,
            "total_engines": total,
            "context": (
                f"VirusTotal: {malicious_count} malicious, {suspicious_count} suspicious out of {total} engines"
            ),
            "file_type": attrs.get("type_description", ""),
            "file_name": attrs.get("meaningful_name", ""),
        }

    except Exception as e:
        logger.warning("VirusTotal file hash check failed for %s: %s", sha256[:16], e)
        return {"malicious": False, "context": f"VT check error: {e}"}

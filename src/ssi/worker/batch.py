"""Batch manifest loading utilities.

Handles loading and validating investigation manifests from local
files or GCS URIs for the ``POST /investigate/batch`` endpoint.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def load_manifest(manifest_path: str) -> list[dict[str, Any]]:
    """Load a batch manifest from a local file or GCS URI.

    Args:
        manifest_path: Local filesystem path or ``gs://bucket/object`` URI.

    Returns:
        List of manifest entries, each with at least a ``url`` key.

    Raises:
        FileNotFoundError: If the local file does not exist.
        ValueError: If the manifest is not valid JSON or has no entries.
    """
    if manifest_path.startswith("gs://"):
        return _load_from_gcs(manifest_path)
    return _load_from_local(manifest_path)


def _load_from_local(path: str) -> list[dict[str, Any]]:
    """Load manifest from a local JSON file."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Manifest file not found: {path}")

    data = json.loads(p.read_text(encoding="utf-8"))
    return validate_manifest(data)


def _load_from_gcs(uri: str) -> list[dict[str, Any]]:
    """Load manifest from a GCS object (``gs://bucket/path.json``)."""
    try:
        from google.cloud import storage as gcs
    except ImportError:
        raise ImportError("google-cloud-storage is required for GCS manifests: pip install google-cloud-storage")

    parts = uri.replace("gs://", "").split("/", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid GCS URI: {uri} — expected gs://bucket/path")

    bucket_name, blob_name = parts
    client = gcs.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_name)

    if not blob.exists():
        raise FileNotFoundError(f"GCS object not found: {uri}")

    data = json.loads(blob.download_as_text())
    return validate_manifest(data)


def validate_manifest(data: Any) -> list[dict[str, Any]]:
    """Validate that the parsed manifest is a non-empty list with URLs.

    Args:
        data: Parsed JSON data (should be a list of dicts).

    Returns:
        List of valid manifest entries.

    Raises:
        ValueError: If the manifest is empty or has no valid entries.
    """
    if not isinstance(data, list) or not data:
        raise ValueError("Manifest must be a non-empty JSON array")

    valid_entries: list[dict[str, Any]] = []
    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            logger.warning("Manifest entry %d is not an object — skipping", i)
            continue
        url = entry.get("url", "").strip()
        if not url:
            logger.warning("Manifest entry %d has no URL — skipping", i)
            continue
        valid_entries.append(entry)

    if not valid_entries:
        raise ValueError("Manifest contains no valid entries (each must have a 'url' key)")

    return valid_entries

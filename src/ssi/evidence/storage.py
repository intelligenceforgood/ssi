"""GCS and local evidence storage for SSI investigations.

Provides a unified interface for uploading evidence artifacts to either
local filesystem or Google Cloud Storage, and generating signed download
URLs for GCS-backed evidence.
"""

from __future__ import annotations

import logging
import mimetypes
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from google.cloud.storage import Blob, Bucket, Client

logger = logging.getLogger(__name__)


class EvidenceStorageClient:
    """Upload evidence artifacts and generate download URLs.

    Supports two backends:

    * ``local`` — files remain on the local filesystem; download URLs point
      to the SSI API (``/investigations/{id}/evidence-bundle``).
    * ``gcs`` — files are uploaded to a Google Cloud Storage bucket and
      download URLs are time-limited signed URLs.

    Args:
        backend: ``"local"`` or ``"gcs"``.
        gcs_bucket: GCS bucket name (required when ``backend="gcs"``).
        gcs_prefix: Key prefix inside the bucket (default ``ssi/evidence``).
        signed_url_expiry_hours: Lifetime of signed download URLs (default 24).
    """

    def __init__(
        self,
        *,
        backend: str = "local",
        gcs_bucket: str = "",
        gcs_prefix: str = "ssi/evidence",
        signed_url_expiry_hours: int = 24,
    ) -> None:
        self.backend = backend.lower()
        self.gcs_bucket_name = gcs_bucket
        self.gcs_prefix = gcs_prefix.rstrip("/")
        self.signed_url_expiry = timedelta(hours=signed_url_expiry_hours)

        self._gcs_client: Client | None = None
        self._gcs_bucket: Bucket | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def upload_directory(self, investigation_id: str, inv_dir: Path) -> dict[str, str]:
        """Upload all files in *inv_dir* to the configured backend.

        Args:
            investigation_id: Unique investigation identifier used as the
                storage key prefix.
            inv_dir: Local directory containing evidence artifacts.

        Returns:
            Mapping of ``{relative_filename: remote_uri_or_local_path}``
            for every uploaded file.
        """
        if self.backend == "gcs":
            return self._upload_directory_gcs(investigation_id, inv_dir)
        return self._index_directory_local(investigation_id, inv_dir)

    def upload_file(self, investigation_id: str, file_path: Path) -> str:
        """Upload a single file and return its remote URI or local path.

        Args:
            investigation_id: Investigation identifier for key prefix.
            file_path: Local path of the file to upload.

        Returns:
            GCS URI (``gs://...``) or local file path string.
        """
        if self.backend == "gcs":
            return self._upload_file_gcs(investigation_id, file_path)
        return str(file_path)

    def generate_signed_url(self, gcs_uri: str) -> str:
        """Return a time-limited signed URL for a ``gs://`` URI.

        Args:
            gcs_uri: A ``gs://bucket/key`` URI.

        Returns:
            HTTPS signed URL valid for ``signed_url_expiry_hours``.

        Raises:
            ValueError: If *gcs_uri* is not a valid ``gs://`` URI.
            RuntimeError: If the backend is not GCS.
        """
        if self.backend != "gcs":
            raise RuntimeError("Signed URLs are only available with the GCS backend.")
        if not gcs_uri.startswith("gs://"):
            raise ValueError(f"Expected gs:// URI, got: {gcs_uri}")

        _, _, blob_name = gcs_uri.partition("gs://")
        bucket_name, _, key = blob_name.partition("/")
        bucket = self._get_gcs_client().bucket(bucket_name)
        blob = bucket.blob(key)
        return blob.generate_signed_url(expiration=self.signed_url_expiry, method="GET")

    def get_evidence_zip_url(self, investigation_id: str, inv_dir: Path) -> str | None:
        """Return a download URL for the evidence ZIP.

        For GCS backends, returns a signed URL. For local backends,
        returns ``None`` (the caller should serve the file directly).
        """
        zip_path = inv_dir / "evidence.zip"
        if not zip_path.exists():
            return None

        if self.backend == "gcs":
            gcs_uri = self._gcs_uri(investigation_id, "evidence.zip")
            try:
                return self.generate_signed_url(gcs_uri)
            except Exception:
                logger.warning("Failed to generate signed URL for %s", gcs_uri, exc_info=True)
                return None
        return None

    def get_file_url(self, investigation_id: str, filename: str) -> str | None:
        """Return a download URL for a specific evidence file.

        Args:
            investigation_id: Investigation identifier.
            filename: Relative filename within the evidence directory.

        Returns:
            Signed URL for GCS backend, or ``None`` for local backend.
        """
        if self.backend == "gcs":
            gcs_uri = self._gcs_uri(investigation_id, filename)
            try:
                return self.generate_signed_url(gcs_uri)
            except Exception:
                logger.warning("Failed to generate signed URL for %s", gcs_uri, exc_info=True)
                return None
        return None

    def exists(self, investigation_id: str, filename: str) -> bool:
        """Check whether a file exists in the backend."""
        if self.backend == "gcs":
            key = self._gcs_key(investigation_id, filename)
            bucket = self._get_gcs_bucket()
            blob = bucket.blob(key)
            return blob.exists()
        return False

    # ------------------------------------------------------------------
    # GCS internals
    # ------------------------------------------------------------------

    def _get_gcs_client(self) -> "Client":
        """Lazily initialise the GCS client."""
        if self._gcs_client is None:
            from google.cloud.storage import Client

            self._gcs_client = Client()
        return self._gcs_client

    def _get_gcs_bucket(self) -> "Bucket":
        """Return the configured GCS bucket object."""
        if self._gcs_bucket is None:
            self._gcs_bucket = self._get_gcs_client().bucket(self.gcs_bucket_name)
        return self._gcs_bucket

    def _gcs_key(self, investigation_id: str, filename: str) -> str:
        """Build the GCS object key for a file."""
        return f"{self.gcs_prefix}/{investigation_id}/{filename}"

    def _gcs_uri(self, investigation_id: str, filename: str) -> str:
        """Build the full ``gs://`` URI for a file."""
        key = self._gcs_key(investigation_id, filename)
        return f"gs://{self.gcs_bucket_name}/{key}"

    def _upload_file_gcs(self, investigation_id: str, file_path: Path) -> str:
        """Upload a single file to GCS and return its ``gs://`` URI."""
        key = self._gcs_key(investigation_id, file_path.name)
        bucket = self._get_gcs_bucket()
        blob = bucket.blob(key)

        content_type, _ = mimetypes.guess_type(file_path.name)
        blob.upload_from_filename(str(file_path), content_type=content_type or "application/octet-stream")

        uri = f"gs://{self.gcs_bucket_name}/{key}"
        logger.debug("Uploaded %s -> %s", file_path.name, uri)
        return uri

    def _upload_directory_gcs(self, investigation_id: str, inv_dir: Path) -> dict[str, str]:
        """Upload all files in a directory to GCS recursively."""
        uploaded: dict[str, str] = {}
        for file_path in sorted(inv_dir.rglob("*")):
            if not file_path.is_file():
                continue
            arcname = str(file_path.relative_to(inv_dir))
            key = self._gcs_key(investigation_id, arcname)
            bucket = self._get_gcs_bucket()
            blob = bucket.blob(key)

            content_type, _ = mimetypes.guess_type(file_path.name)
            blob.upload_from_filename(str(file_path), content_type=content_type or "application/octet-stream")

            uri = f"gs://{self.gcs_bucket_name}/{key}"
            uploaded[arcname] = uri
        logger.info(
            "Uploaded %d evidence files to gs://%s/%s/%s",
            len(uploaded),
            self.gcs_bucket_name,
            self.gcs_prefix,
            investigation_id,
        )
        return uploaded

    def _index_directory_local(self, investigation_id: str, inv_dir: Path) -> dict[str, str]:
        """Index local files (no upload needed for local backend)."""
        indexed: dict[str, str] = {}
        for file_path in sorted(inv_dir.rglob("*")):
            if file_path.is_file():
                arcname = str(file_path.relative_to(inv_dir))
                indexed[arcname] = str(file_path)
        return indexed


def build_evidence_storage_client() -> EvidenceStorageClient:
    """Factory: return an :class:`EvidenceStorageClient` using SSI settings."""
    from ssi.settings import get_settings

    settings = get_settings()
    return EvidenceStorageClient(
        backend=settings.evidence.storage_backend,
        gcs_bucket=settings.evidence.gcs_bucket,
        gcs_prefix=settings.evidence.gcs_prefix,
    )

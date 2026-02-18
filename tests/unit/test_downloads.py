"""Unit tests for the download interceptor module."""

from __future__ import annotations

from pathlib import Path

import pytest

from ssi.browser.downloads import CapturedDownload, _compute_hashes


class TestCapturedDownload:
    """Tests for the CapturedDownload dataclass."""

    def test_defaults(self):
        d = CapturedDownload(url="https://evil.com/malware.exe", suggested_filename="malware.exe")
        assert d.url == "https://evil.com/malware.exe"
        assert d.suggested_filename == "malware.exe"
        assert d.sha256 == ""
        assert d.md5 == ""
        assert d.size_bytes == 0
        assert d.is_malicious is False
        assert d.error == ""

    def test_to_dict(self):
        d = CapturedDownload(
            url="https://evil.com/payload.bin",
            suggested_filename="payload.bin",
            sha256="abc123",
            md5="def456",
            size_bytes=1024,
            is_malicious=True,
        )
        data = d.to_dict()
        assert data["sha256"] == "abc123"
        assert data["is_malicious"] is True
        assert data["size_bytes"] == 1024

    def test_to_dict_with_vt_result(self):
        d = CapturedDownload(
            url="https://evil.com/test.exe",
            suggested_filename="test.exe",
            vt_result={"malicious": True, "detections": 15, "total_engines": 70},
        )
        data = d.to_dict()
        assert data["vt_result"]["detections"] == 15


class TestComputeHashes:
    """Tests for file hash computation."""

    def test_compute_known_content(self, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello world")

        sha256, md5 = _compute_hashes(test_file)

        # Known hashes for "hello world"
        assert sha256 == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assert md5 == "5eb63bbbe01eeed093cb22bb8f5acdc3"

    def test_compute_empty_file(self, tmp_path):
        test_file = tmp_path / "empty.bin"
        test_file.write_bytes(b"")

        sha256, md5 = _compute_hashes(test_file)

        # Known hashes for empty content
        assert sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert md5 == "d41d8cd98f00b204e9800998ecf8427e"

    def test_compute_binary_content(self, tmp_path):
        test_file = tmp_path / "binary.bin"
        test_file.write_bytes(b"\x00\x01\x02\xff" * 100)

        sha256, md5 = _compute_hashes(test_file)
        assert len(sha256) == 64  # SHA-256 hex length
        assert len(md5) == 32  # MD5 hex length


class TestDownloadInterceptor:
    """Tests for the DownloadInterceptor class."""

    def test_output_dir_created(self, tmp_path):
        from ssi.browser.downloads import DownloadInterceptor

        dl_dir = tmp_path / "nested" / "downloads"
        interceptor = DownloadInterceptor(output_dir=dl_dir)

        assert dl_dir.is_dir()
        assert interceptor.downloads == []

    def test_max_size_default(self):
        from ssi.browser.downloads import DownloadInterceptor, _MAX_DOWNLOAD_SIZE_BYTES

        interceptor = DownloadInterceptor(output_dir=Path("/tmp/test"))
        assert interceptor.max_size_bytes == _MAX_DOWNLOAD_SIZE_BYTES

    def test_custom_max_size(self):
        from ssi.browser.downloads import DownloadInterceptor

        interceptor = DownloadInterceptor(output_dir=Path("/tmp/test"), max_size_bytes=1024)
        assert interceptor.max_size_bytes == 1024

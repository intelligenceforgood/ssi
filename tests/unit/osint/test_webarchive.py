from unittest.mock import patch

import pytest

from ssi.osint.webarchive import fetch_snapshots
from ssi.providers.gate import SkippedResult


@pytest.mark.anyio
@patch("ssi.osint.webarchive.phishdestroy_provider_enabled", return_value=False)
async def test_fetch_snapshots_disabled(mock_enabled):
    result = await fetch_snapshots("example.com")
    assert isinstance(result, SkippedResult)
    assert result.reason == "disabled"


@pytest.mark.anyio
@patch("ssi.osint.webarchive.phishdestroy_provider_enabled", return_value=True)
async def test_fetch_snapshots_success(mock_enabled):
    result = await fetch_snapshots("example.com")
    assert not isinstance(result, SkippedResult)
    assert result["status"] == "success"

from unittest.mock import PropertyMock, patch

import pytest

from ssi.osint.ghunt import analyze
from ssi.providers.gate import ProviderGate, SkippedResult


@pytest.mark.anyio
@patch.object(ProviderGate, "enabled", new_callable=PropertyMock, return_value=False)
async def test_analyze_quota_gated(mock_enabled):
    result = await analyze("test@gmail.com")
    assert isinstance(result, SkippedResult)
    assert result.reason == "quota_gated"


@pytest.mark.anyio
@patch.object(ProviderGate, "enabled", new_callable=PropertyMock, return_value=True)
async def test_analyze_success(mock_enabled):
    result = await analyze("test@gmail.com")
    assert not isinstance(result, SkippedResult)
    assert result["status"] == "success"

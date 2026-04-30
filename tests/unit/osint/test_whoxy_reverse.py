from unittest.mock import PropertyMock, patch

import pytest

from ssi.osint.whoxy_reverse import search
from ssi.providers.gate import ProviderGate, SkippedResult


@pytest.mark.anyio
@patch.object(ProviderGate, "enabled", new_callable=PropertyMock, return_value=False)
async def test_search_quota_gated(mock_enabled):
    result = await search("test@example.com")
    assert isinstance(result, SkippedResult)
    assert result.reason == "quota_gated"


@pytest.mark.anyio
@patch.object(ProviderGate, "enabled", new_callable=PropertyMock, return_value=True)
async def test_search_success(mock_enabled):
    result = await search("test@example.com")
    assert not isinstance(result, SkippedResult)
    assert result["status"] == "success"

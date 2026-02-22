"""Browser wallet extraction integration test.

Validates that the ``WalletValidator.scan_text()`` pipeline correctly
extracts wallet addresses from the HTML fixture files, verifying the
full regex → classify → deduplicate chain.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ssi.wallet.patterns import WalletValidator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def validator() -> WalletValidator:
    """Return a fresh WalletValidator."""
    return WalletValidator()


# Known addresses from the deposit.html fixture
EXPECTED_BTC = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
EXPECTED_ETH = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18"
EXPECTED_TRX = "TQn9Y2khEsLJW1ChVWFMSMzKC9BhFoqqvd"
EXPECTED_SOL = "4fYNw3dojWmQ4dXtSGE9epjRGy9pFSx62YypT7avPYvA"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDepositPageExtraction:
    """Extract wallets from the deposit.html fixture."""

    def test_extracts_btc_address(self, deposit_page: Path, validator: WalletValidator) -> None:
        """Bitcoin bech32 address is found in the deposit page."""
        html = deposit_page.read_text()
        matches = validator.scan_text(html)
        addresses = [m.address for m in matches]
        assert EXPECTED_BTC in addresses, f"Expected BTC address not found. Got: {addresses}"

    def test_extracts_eth_address(self, deposit_page: Path, validator: WalletValidator) -> None:
        """Ethereum address is found in the deposit page."""
        html = deposit_page.read_text()
        matches = validator.scan_text(html)
        addresses = [m.address for m in matches]
        assert EXPECTED_ETH in addresses, f"Expected ETH address not found. Got: {addresses}"

    def test_extracts_trx_address(self, deposit_page: Path, validator: WalletValidator) -> None:
        """Tron address is found in the deposit page."""
        html = deposit_page.read_text()
        matches = validator.scan_text(html)
        addresses = [m.address for m in matches]
        assert EXPECTED_TRX in addresses, f"Expected TRX address not found. Got: {addresses}"

    def test_extracts_sol_address(self, deposit_page: Path, validator: WalletValidator) -> None:
        """Solana address is found in the deposit page."""
        html = deposit_page.read_text()
        matches = validator.scan_text(html)
        addresses = [m.address for m in matches]
        assert EXPECTED_SOL in addresses, f"Expected SOL address not found. Got: {addresses}"

    def test_classifies_addresses_correctly(self, deposit_page: Path, validator: WalletValidator) -> None:
        """Each extracted address is classified with the correct token symbol."""
        html = deposit_page.read_text()
        matches = validator.scan_text(html)
        symbol_map = {m.address: m.symbol for m in matches}

        assert symbol_map.get(EXPECTED_BTC) == "BTC"
        assert symbol_map.get(EXPECTED_ETH) == "ETH"
        assert symbol_map.get(EXPECTED_TRX) == "TRX"
        assert symbol_map.get(EXPECTED_SOL) == "SOL"

    def test_no_duplicates(self, deposit_page: Path, validator: WalletValidator) -> None:
        """Each address appears exactly once in the results."""
        html = deposit_page.read_text()
        matches = validator.scan_text(html)
        addresses = [m.address for m in matches]
        assert len(addresses) == len(set(addresses)), "Duplicate addresses in results"


@pytest.mark.integration
class TestPhishingPageExtraction:
    """Confirm that the phishing page (credit card form) produces zero wallet matches."""

    def test_no_wallet_addresses(self, phishing_page: Path, validator: WalletValidator) -> None:
        """A credit card phishing page should contain no wallet addresses."""
        html = phishing_page.read_text()
        matches = validator.scan_text(html)
        # Filter out false positives from short common words
        wallet_addrs = [m.address for m in matches if len(m.address) > 30]
        assert len(wallet_addrs) == 0, f"Unexpected wallet addresses in phishing page: {wallet_addrs}"


@pytest.mark.integration
class TestRegisterPageExtraction:
    """Register page may or may not contain wallet addresses."""

    def test_register_page_has_no_wallets(self, register_page: Path, validator: WalletValidator) -> None:
        """Registration form page should not contain wallet addresses."""
        html = register_page.read_text()
        matches = validator.scan_text(html)
        # Filter for real wallet-length matches only
        wallet_addrs = [m.address for m in matches if len(m.address) > 30]
        assert len(wallet_addrs) == 0, f"Unexpected wallet addresses in register page: {wallet_addrs}"


class TestValidatorDirectAPI:
    """Unit-level validator tests to complement integration tests."""

    def test_validate_known_btc(self, validator: WalletValidator) -> None:
        result = validator.validate(EXPECTED_BTC)
        assert result is not None
        assert result.symbol == "BTC"

    def test_validate_known_eth(self, validator: WalletValidator) -> None:
        result = validator.validate(EXPECTED_ETH)
        assert result is not None
        assert result.symbol == "ETH"

    def test_validate_garbage_returns_none(self, validator: WalletValidator) -> None:
        result = validator.validate("not-a-wallet-address")
        assert result is None

    def test_validate_for_symbol_eth(self, validator: WalletValidator) -> None:
        assert validator.validate_for_symbol(EXPECTED_ETH, "ETH") is True
        assert validator.validate_for_symbol(EXPECTED_ETH, "BTC") is False

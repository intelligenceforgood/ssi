"""Token-network allowlist — loading, lookup, and filtering.

The allowlist defines which ``(token_symbol, network_short)`` pairs are
considered valid for output (XLSX export, database storage).  The agent
collects *all* wallets it finds; the allowlist is applied downstream.

The JSON file lives at ``config/wallet_allowlist.json`` by default and
can be overridden via ``SSI_WALLET__ALLOWLIST_PATH``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from ssi.wallet.models import TokenNetwork, WalletEntry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default allowlist (compiled from AWH's 26-pair list)
# ---------------------------------------------------------------------------

DEFAULT_TOKEN_NETWORKS: list[TokenNetwork] = [
    # Native tokens (12)
    TokenNetwork(token_name="BNB", token_symbol="BNB", network="BNB Smart Chain BEP-20", network_short="bsc"),
    TokenNetwork(token_name="Bitcoin", token_symbol="BTC", network="Bitcoin", network_short="btc"),
    TokenNetwork(token_name="Bitcoin Cash", token_symbol="BCH", network="Bitcoin Cash", network_short="bch"),
    TokenNetwork(token_name="Cardano", token_symbol="ADA", network="Cardano", network_short="ada"),
    TokenNetwork(token_name="Dash", token_symbol="DASH", network="Dash", network_short="dash"),
    TokenNetwork(token_name="Dogecoin", token_symbol="DOGE", network="Dogecoin", network_short="doge"),
    TokenNetwork(token_name="Ethereum", token_symbol="ETH", network="Ethereum", network_short="eth"),
    TokenNetwork(token_name="Litecoin", token_symbol="LTC", network="Litecoin", network_short="ltc"),
    TokenNetwork(token_name="Polygon", token_symbol="MATIC", network="Polygon PoS", network_short="matic"),
    TokenNetwork(token_name="Ripple", token_symbol="XRP", network="XRP Ledger", network_short="xrp"),
    TokenNetwork(token_name="Solana", token_symbol="SOL", network="Solana", network_short="sol"),
    TokenNetwork(token_name="Tron", token_symbol="TRX", network="Tron", network_short="trx"),
    # USDT variants (8)
    TokenNetwork(token_name="Tether", token_symbol="USDT", network="Arbitrum One", network_short="arb"),
    TokenNetwork(token_name="Tether", token_symbol="USDT", network="Avalanche C-Chain", network_short="avax"),
    TokenNetwork(token_name="Tether", token_symbol="USDT", network="BNB Smart Chain BEP-20", network_short="bsc"),
    TokenNetwork(token_name="Tether", token_symbol="USDT", network="Ethereum ERC-20", network_short="eth"),
    TokenNetwork(token_name="Tether", token_symbol="USDT", network="Optimism", network_short="op"),
    TokenNetwork(token_name="Tether", token_symbol="USDT", network="Polygon PoS", network_short="matic"),
    TokenNetwork(token_name="Tether", token_symbol="USDT", network="Solana SPL", network_short="sol"),
    TokenNetwork(token_name="Tether", token_symbol="USDT", network="Tron TRC-20", network_short="trx"),
    # USDC variants (6)
    TokenNetwork(token_name="USD Coin", token_symbol="USDC", network="Arbitrum One", network_short="arb"),
    TokenNetwork(token_name="USD Coin", token_symbol="USDC", network="Avalanche C-Chain", network_short="avax"),
    TokenNetwork(token_name="USD Coin", token_symbol="USDC", network="Ethereum ERC-20", network_short="eth"),
    TokenNetwork(token_name="USD Coin", token_symbol="USDC", network="Optimism", network_short="op"),
    TokenNetwork(token_name="USD Coin", token_symbol="USDC", network="Polygon PoS", network_short="matic"),
    TokenNetwork(token_name="USD Coin", token_symbol="USDC", network="Solana SPL", network_short="sol"),
]


def load_allowlist(path: str | Path | None = None) -> list[TokenNetwork]:
    """Load token-network pairs from a JSON file.

    Falls back to the compiled default if ``path`` is ``None`` or the file
    doesn't exist.

    Args:
        path: Path to a ``wallet_allowlist.json`` file.

    Returns:
        List of ``TokenNetwork`` instances.
    """
    if path is None:
        logger.debug("Using default built-in allowlist (%d pairs)", len(DEFAULT_TOKEN_NETWORKS))
        return list(DEFAULT_TOKEN_NETWORKS)

    filepath = Path(path)
    if not filepath.exists():
        logger.warning("Allowlist file not found at %s — using defaults", filepath)
        return list(DEFAULT_TOKEN_NETWORKS)

    try:
        data = json.loads(filepath.read_text(encoding="utf-8"))
        items = data.get("token_networks", [])
        pairs = [TokenNetwork(**item) for item in items]
        logger.info("Loaded %d token-network pairs from %s", len(pairs), filepath)
        return pairs
    except (json.JSONDecodeError, TypeError, KeyError) as exc:
        logger.error("Failed to parse allowlist %s: %s — using defaults", filepath, exc)
        return list(DEFAULT_TOKEN_NETWORKS)


# ---------------------------------------------------------------------------
# AllowlistFilter
# ---------------------------------------------------------------------------


class AllowlistFilter:
    """Filters wallet entries against a set of allowed token-network pairs.

    Usage::

        filt = AllowlistFilter.from_json("config/wallet_allowlist.json")
        accepted, discarded = filt.filter(wallet_entries)
    """

    def __init__(self, token_networks: list[TokenNetwork] | None = None) -> None:
        networks = token_networks or DEFAULT_TOKEN_NETWORKS
        self._pairs: set[tuple[str, str]] = {(tn.token_symbol, tn.network_short) for tn in networks}
        self._networks: list[TokenNetwork] = networks
        self._by_symbol: dict[str, list[TokenNetwork]] = {}
        for tn in networks:
            self._by_symbol.setdefault(tn.token_symbol, []).append(tn)

    @classmethod
    def from_json(cls, path: str | Path) -> "AllowlistFilter":
        """Create a filter from a JSON allowlist file."""
        return cls(load_allowlist(path))

    @classmethod
    def default(cls) -> "AllowlistFilter":
        """Create a filter using the built-in default allowlist."""
        return cls(DEFAULT_TOKEN_NETWORKS)

    @property
    def allowed_pairs(self) -> set[tuple[str, str]]:
        """The set of ``(token_symbol, network_short)`` pairs."""
        return set(self._pairs)

    @property
    def allowed_symbols(self) -> set[str]:
        """The set of distinct token symbols."""
        return {tn.token_symbol for tn in self._networks}

    @property
    def count(self) -> int:
        """Number of allowed token-network pairs."""
        return len(self._pairs)

    def is_allowed(self, entry: WalletEntry) -> bool:
        """Check if a single entry's ``(token_symbol, network_short)`` is in the allowlist."""
        return entry.pair in self._pairs

    def is_known_symbol(self, symbol: str) -> bool:
        """Check if a token symbol appears in the allowlist (any network)."""
        return symbol.upper() in self._by_symbol

    def networks_for_symbol(self, symbol: str) -> list[TokenNetwork]:
        """Return all allowed networks for a given token symbol."""
        return list(self._by_symbol.get(symbol.upper(), []))

    def filter(self, entries: list[WalletEntry]) -> tuple[list[WalletEntry], list[WalletEntry]]:
        """Split entries into (accepted, discarded) based on allowlist.

        Entries with empty ``token_symbol`` or ``network_short`` are always
        discarded (they need LLM enrichment first).

        Args:
            entries: Wallet entries to filter.

        Returns:
            Tuple of (accepted, discarded) lists.
        """
        accepted: list[WalletEntry] = []
        discarded: list[WalletEntry] = []
        for entry in entries:
            if not entry.token_symbol or not entry.network_short:
                logger.debug(
                    "Discarding entry with incomplete metadata: addr=%s...",
                    entry.wallet_address[:16],
                )
                discarded.append(entry)
            elif self.is_allowed(entry):
                accepted.append(entry)
            else:
                logger.debug(
                    "Discarding non-allowlisted pair (%s, %s): addr=%s...",
                    entry.token_symbol,
                    entry.network_short,
                    entry.wallet_address[:16],
                )
                discarded.append(entry)
        logger.info(
            "Allowlist filter: %d accepted, %d discarded out of %d",
            len(accepted),
            len(discarded),
            len(entries),
        )
        return accepted, discarded

    def summary(self) -> dict[str, Any]:
        """Return a dict summarizing the allowlist contents."""
        return {
            "total_pairs": self.count,
            "symbols": sorted(self.allowed_symbols),
            "pairs": sorted((s, n) for s, n in self._pairs),
        }

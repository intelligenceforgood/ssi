"""Python-side cryptocurrency wallet address patterns and validation.

Mirrors the JavaScript extraction patterns in ``zen_manager.py`` but runs
server-side for post-extraction validation, deduplication sanity checks,
and standalone use (e.g., scanning evidence text files).

Each ``WalletPattern`` maps a regex to a blockchain, enabling address
classification. The ``WalletValidator`` wraps all patterns into a single
entry point.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Individual wallet patterns
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WalletPattern:
    """A single regex pattern for matching cryptocurrency wallet addresses.

    Attributes:
        name: Human-readable blockchain name, e.g. ``"Ethereum"``.
        symbol: Token symbol, e.g. ``"ETH"``.
        regex: Compiled regex with one capturing group for the address.
        min_length: Minimum expected address length (approximate, for sanity checks).
        max_length: Maximum expected address length.
        example: A well-known example address for documentation / testing.
    """

    name: str
    symbol: str
    regex: re.Pattern[str]
    min_length: int = 26
    max_length: int = 100
    example: str = ""

    def match(self, text: str) -> str | None:
        """Return the captured address if *text* matches this pattern, else ``None``."""
        m = self.regex.search(text)
        if m:
            addr = m.group(1) if m.lastindex else m.group(0)
            if self.min_length <= len(addr) <= self.max_length:
                return addr
        return None

    def find_all(self, text: str) -> list[str]:
        """Return all distinct addresses in *text* that match this pattern."""
        seen: set[str] = set()
        results: list[str] = []
        for m in self.regex.finditer(text):
            addr = m.group(1) if m.lastindex else m.group(0)
            if self.min_length <= len(addr) <= self.max_length and addr not in seen:
                seen.add(addr)
                results.append(addr)
        return results


# ---------------------------------------------------------------------------
# Pattern registry — one per blockchain
# ---------------------------------------------------------------------------

# Keep in sync with the JS patterns in zen_manager.py's extract_wallet_address()
WALLET_PATTERNS: list[WalletPattern] = [
    WalletPattern(
        name="Ethereum / ERC-20",
        symbol="ETH",
        regex=re.compile(r"\b(0x[a-fA-F0-9]{40})\b"),
        min_length=42,
        max_length=42,
        example="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
    ),
    WalletPattern(
        name="Tron / TRC-20",
        symbol="TRX",
        regex=re.compile(r"\b(T[A-HJ-NP-Za-km-z1-9]{33})\b"),
        min_length=34,
        max_length=34,
        example="TJYqaPn323M2C7x7E5E3ypEGVgKYxxrWW1",
    ),
    WalletPattern(
        name="Bitcoin (bech32)",
        symbol="BTC",
        regex=re.compile(r"\b(bc1[a-z0-9]{39,59})\b"),
        min_length=42,
        max_length=62,
        example="bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
    ),
    WalletPattern(
        name="Bitcoin (legacy)",
        symbol="BTC",
        regex=re.compile(r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
        min_length=26,
        max_length=35,
        example="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    ),
    WalletPattern(
        name="XRP Ledger",
        symbol="XRP",
        regex=re.compile(r"\b(r[0-9a-zA-Z]{24,34})\b"),
        min_length=25,
        max_length=35,
        example="rN7n3473SaZBCG4dFL83w7p1W9cgZw6ihn",
    ),
    WalletPattern(
        name="Cardano",
        symbol="ADA",
        regex=re.compile(r"\b(addr1[a-z0-9]{50,120})\b"),
        min_length=55,
        max_length=130,
        example="addr1qxy2k5c2n5qfr9z7a3ggvpfqfkpt78eczgmd26qjqkmpv6lr2g7v5sc3wg0nfgfsdvlaq5g82dkyn5wsydmhqgemhd6kxegraeel",
    ),
    WalletPattern(
        name="Solana / Generic Base58",
        symbol="SOL",
        regex=re.compile(r"\b([A-HJ-NP-Za-km-z1-9]{32,44})\b"),
        min_length=32,
        max_length=44,
        example="7Np41oeYqPefeNQEHSv1UDhYrehxin3NStELsSKCT4K2",
    ),
    # -- Additional patterns not in the JS (less common but encountered) --
    WalletPattern(
        name="Litecoin (legacy)",
        symbol="LTC",
        regex=re.compile(r"\b(L[a-km-zA-HJ-NP-Z1-9]{26,33})\b"),
        min_length=27,
        max_length=34,
        example="LaMT348PWRnrqeeWArpwQPbuanpXDZGEUz",
    ),
    WalletPattern(
        name="Litecoin (bech32)",
        symbol="LTC",
        regex=re.compile(r"\b(ltc1[a-z0-9]{39,59})\b"),
        min_length=43,
        max_length=63,
        example="ltc1qg42tkwuuxefutzentevevhfhv0tyersh5z46vu",
    ),
    WalletPattern(
        name="Dogecoin",
        symbol="DOGE",
        regex=re.compile(r"\b(D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32})\b"),
        min_length=34,
        max_length=34,
        example="DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L",
    ),
    WalletPattern(
        name="Bitcoin Cash (cashaddr)",
        symbol="BCH",
        regex=re.compile(r"\b(bitcoincash:[qp][a-z0-9]{41})\b"),
        min_length=54,
        max_length=54,
        example="bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
    ),
    WalletPattern(
        name="Dash",
        symbol="DASH",
        regex=re.compile(r"\b(X[1-9A-HJ-NP-Za-km-z]{33})\b"),
        min_length=34,
        max_length=34,
        example="XyzSoLEFQxWUf3Nd83s2GFzTpPNdBi7LGG",
    ),
]


# Quick lookup by symbol
_PATTERNS_BY_SYMBOL: dict[str, list[WalletPattern]] = {}
for _p in WALLET_PATTERNS:
    _PATTERNS_BY_SYMBOL.setdefault(_p.symbol, []).append(_p)


# ---------------------------------------------------------------------------
# WalletValidator
# ---------------------------------------------------------------------------


@dataclass
class MatchResult:
    """Result of matching a text string against wallet patterns.

    Attributes:
        address: The extracted address string.
        pattern: The ``WalletPattern`` that matched.
        symbol: Token symbol inferred from the pattern.
    """

    address: str
    pattern: WalletPattern
    symbol: str

    def __repr__(self) -> str:
        return f"MatchResult({self.symbol}: {self.address[:20]}...)"


class WalletValidator:
    """Validates and classifies wallet address strings against known patterns.

    Can be used both for single-address validation and for bulk scanning
    of text blocks (evidence files, page content, etc.).
    """

    def __init__(self, patterns: list[WalletPattern] | None = None) -> None:
        self._patterns = patterns or WALLET_PATTERNS

    def validate(self, address: str) -> MatchResult | None:
        """Check if *address* matches any known wallet pattern.

        Returns a ``MatchResult`` on success, ``None`` if no pattern matches.
        Only the *first* matching pattern is returned (ordered by specificity).
        """
        text = address.strip()
        for pat in self._patterns:
            matched = pat.match(text)
            if matched:
                return MatchResult(address=matched, pattern=pat, symbol=pat.symbol)
        return None

    def is_valid_address(self, address: str) -> bool:
        """Return ``True`` if *address* matches any known wallet pattern."""
        return self.validate(address) is not None

    def classify(self, address: str) -> str | None:
        """Return the probable token symbol for *address*, or ``None``."""
        result = self.validate(address)
        return result.symbol if result else None

    def scan_text(self, text: str) -> list[MatchResult]:
        """Scan a block of text for all wallet addresses.

        Returns a deduplicated list of ``MatchResult`` ordered by position.
        """
        results: list[MatchResult] = []
        seen: set[str] = set()
        for pat in self._patterns:
            for addr in pat.find_all(text):
                if addr not in seen:
                    seen.add(addr)
                    results.append(MatchResult(address=addr, pattern=pat, symbol=pat.symbol))
        return results

    def validate_for_symbol(self, address: str, expected_symbol: str) -> bool:
        """Check if *address* is valid for a specific token symbol.

        Useful for verifying LLM-provided wallet entries where both the
        address and claimed symbol are available.
        """
        patterns = _PATTERNS_BY_SYMBOL.get(expected_symbol.upper(), [])
        return any(p.match(address) is not None for p in patterns)

    @property
    def supported_symbols(self) -> set[str]:
        """Set of token symbols this validator knows about."""
        return {p.symbol for p in self._patterns}

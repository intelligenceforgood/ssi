"""Wallet extraction pipeline — models, validation, allowlist, and export.

This module owns everything related to cryptocurrency wallet addresses
extracted from scam sites:

* ``models`` — Pydantic data models for entries, harvests, and token-network pairs.
* ``patterns`` — Python-side regex validation mirroring the JS extraction patterns.
* ``allowlist`` — Configurable token-network allowlist (JSON file or defaults).
* ``export`` — XLSX / CSV / JSON export utilities.

The browser-level JS extraction lives in ``ssi.browser.zen_manager``; this
module handles downstream validation, enrichment, filtering, and output.
"""

from ssi.wallet.allowlist import AllowlistFilter, load_allowlist
from ssi.wallet.export import WalletExporter, export_harvest
from ssi.wallet.models import TokenNetwork, WalletEntry, WalletHarvest
from ssi.wallet.patterns import WalletPattern, WalletValidator

__all__ = [
    "AllowlistFilter",
    "TokenNetwork",
    "WalletEntry",
    "WalletExporter",
    "WalletHarvest",
    "WalletPattern",
    "WalletValidator",
    "export_harvest",
    "load_allowlist",
]

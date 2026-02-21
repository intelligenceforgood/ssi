"""Pydantic models for wallet extraction pipeline.

``TokenNetwork`` — an approved token-network pair from the configurable allowlist.
``WalletEntry`` — a single wallet address harvested from a scam site.
``WalletHarvest`` — the full collection of wallets from a single run/site.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# TokenNetwork — allowlist pair
# ---------------------------------------------------------------------------


class TokenNetwork(BaseModel):
    """A token-network pair from the allowlist.

    Attributes:
        token_name: Full token name, e.g. ``"Tether"``.
        token_symbol: Uppercase ticker, e.g. ``"USDT"``.
        network: Display name of the network, e.g. ``"Tron TRC-20"``.
        network_short: Lowercase short code, e.g. ``"trx"``.
    """

    token_name: str
    token_symbol: str
    network: str
    network_short: str

    @field_validator("token_symbol")
    @classmethod
    def _normalize_symbol(cls, v: str) -> str:
        return v.strip().upper()

    @field_validator("network_short")
    @classmethod
    def _normalize_network(cls, v: str) -> str:
        return v.strip().lower()


# ---------------------------------------------------------------------------
# WalletEntry — single extracted address
# ---------------------------------------------------------------------------


class WalletEntry(BaseModel):
    """A single cryptocurrency wallet address harvested from a scam site.

    The browser agent populates all fields from page content.  Downstream
    processing (allowlist filter, XLSX export) validates against the
    ``(token_symbol, network_short)`` pair.

    Attributes:
        site_url: Source URL the wallet was harvested from.
        token_label: Raw label from the scam site, e.g. ``"USDT (TRC-20)"``.
        token_symbol: Agent's best mapping, e.g. ``"USDT"``.
        network_label: Raw network text from site, e.g. ``"Tron TRC-20"``.
        network_short: Short code, e.g. ``"trx"``.
        wallet_address: The crypto address string.
        harvested_at: UTC timestamp; auto-set if omitted.
        run_id: Identifier for the agent run that captured this entry.
        source: How the wallet was captured: ``"js"``, ``"llm"``, ``"opportunistic"``.
        confidence: Agent confidence 0.0–1.0 (1.0 = LLM verified with network info).
    """

    site_url: str = ""
    token_label: str = ""
    token_symbol: str = ""
    network_label: str = ""
    network_short: str = ""
    wallet_address: str = ""
    harvested_at: datetime | None = None
    run_id: str = ""
    source: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    @field_validator("wallet_address")
    @classmethod
    def _wallet_address_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("wallet_address must not be empty")
        return v

    @field_validator("token_symbol")
    @classmethod
    def _normalize_symbol(cls, v: str) -> str:
        return v.strip().upper() if v else ""

    @field_validator("network_short")
    @classmethod
    def _normalize_network(cls, v: str) -> str:
        return v.strip().lower() if v else ""

    def model_post_init(self, __context: Any) -> None:
        if not self.harvested_at:
            self.harvested_at = datetime.now(timezone.utc)

    @property
    def pair(self) -> tuple[str, str]:
        """Return the ``(token_symbol, network_short)`` tuple for allowlist lookup."""
        return (self.token_symbol, self.network_short)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict."""
        return {
            "site_url": self.site_url,
            "token_label": self.token_label,
            "token_symbol": self.token_symbol,
            "network_label": self.network_label,
            "network_short": self.network_short,
            "wallet_address": self.wallet_address,
            "harvested_at": self.harvested_at.isoformat() if self.harvested_at else None,
            "run_id": self.run_id,
            "source": self.source,
            "confidence": self.confidence,
        }


# ---------------------------------------------------------------------------
# WalletHarvest — aggregation for a run
# ---------------------------------------------------------------------------


class WalletHarvest(BaseModel):
    """Collection of wallets from a single investigation run.

    Provides convenience methods for filtering, deduplication, and export.

    Attributes:
        site_url: The site these wallets came from.
        site_id: Optional identifier for the site in the database.
        run_id: The agent run that produced this harvest.
        entries: All wallet entries (including unfiltered ones).
        started_at: When the extraction started.
        completed_at: When the extraction finished.
    """

    site_url: str = ""
    site_id: str = ""
    run_id: str = ""
    entries: list[WalletEntry] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None

    @model_validator(mode="after")
    def _propagate_run_id(self) -> "WalletHarvest":
        """Ensure all entries inherit the harvest run_id if not already set."""
        if self.run_id:
            for entry in self.entries:
                if not entry.run_id:
                    entry.run_id = self.run_id
        return self

    # -- Convenience properties ------------------------------------------

    @property
    def count(self) -> int:
        """Total number of wallet entries."""
        return len(self.entries)

    @property
    def unique_addresses(self) -> set[str]:
        """Set of distinct wallet addresses."""
        return {e.wallet_address for e in self.entries}

    @property
    def symbols_found(self) -> set[str]:
        """Set of distinct token symbols found."""
        return {e.token_symbol for e in self.entries if e.token_symbol}

    # -- Mutation helpers --------------------------------------------------

    def add(self, entry: WalletEntry) -> bool:
        """Add an entry, deduplicating by wallet_address. Returns True if added."""
        if entry.wallet_address in self.unique_addresses:
            return False
        if self.run_id and not entry.run_id:
            entry.run_id = self.run_id
        self.entries.append(entry)
        return True

    def merge_llm_results(self, llm_entries: list[WalletEntry]) -> None:
        """Merge LLM-verified entries, preferring LLM data for matching addresses.

        LLM entries typically have richer metadata (network_label, network_short)
        than JS-extracted entries. For addresses already present, the LLM entry
        replaces the existing one. New addresses are appended.
        """
        existing_by_addr = {e.wallet_address: i for i, e in enumerate(self.entries)}
        for llm_entry in llm_entries:
            idx = existing_by_addr.get(llm_entry.wallet_address)
            if idx is not None:
                self.entries[idx] = llm_entry
            else:
                self.entries.append(llm_entry)

    def deduplicate(self) -> int:
        """Remove duplicate addresses, keeping the entry with most metadata. Returns count removed."""
        seen: dict[str, int] = {}
        to_keep: list[WalletEntry] = []
        removed = 0
        for entry in self.entries:
            if entry.wallet_address in seen:
                existing_idx = seen[entry.wallet_address]
                existing = to_keep[existing_idx]
                # Keep the one with more metadata (network info)
                if entry.network_short and not existing.network_short:
                    to_keep[existing_idx] = entry
                removed += 1
            else:
                seen[entry.wallet_address] = len(to_keep)
                to_keep.append(entry)
        self.entries = to_keep
        return removed

    def complete(self) -> None:
        """Mark the harvest as completed."""
        self.completed_at = datetime.now(timezone.utc)

    # -- Serialization ----------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict."""
        return {
            "site_url": self.site_url,
            "site_id": self.site_id,
            "run_id": self.run_id,
            "count": self.count,
            "entries": [e.to_dict() for e in self.entries],
            "symbols_found": sorted(self.symbols_found),
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

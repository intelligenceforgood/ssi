"""Unit tests for ssi.wallet — models, patterns, allowlist, and export.

Tests cover:
- WalletEntry Pydantic validation (normalization, empty address, timestamps)
- WalletHarvest (add, deduplicate, merge_llm_results, serialization)
- TokenNetwork normalization
- WalletPattern regex matching for every supported blockchain
- WalletValidator (validate, classify, scan_text, validate_for_symbol)
- AllowlistFilter (allowed pairs, filtering, edge cases)
- WalletExporter (XLSX, CSV, JSON output)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ssi.wallet.allowlist import AllowlistFilter, DEFAULT_TOKEN_NETWORKS, load_allowlist
from ssi.wallet.export import HEADERS, WalletExporter, export_harvest
from ssi.wallet.models import TokenNetwork, WalletEntry, WalletHarvest
from ssi.wallet.patterns import WALLET_PATTERNS, MatchResult, WalletPattern, WalletValidator


# ---------------------------------------------------------------------------
# WalletEntry model tests
# ---------------------------------------------------------------------------


class TestWalletEntry:
    """WalletEntry Pydantic model validation."""

    def test_basic_creation(self) -> None:
        entry = WalletEntry(wallet_address="0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe")
        assert entry.wallet_address == "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
        assert entry.harvested_at is not None
        assert entry.source == ""

    def test_empty_address_rejected(self) -> None:
        with pytest.raises(ValueError, match="wallet_address must not be empty"):
            WalletEntry(wallet_address="")

    def test_whitespace_address_rejected(self) -> None:
        with pytest.raises(ValueError, match="wallet_address must not be empty"):
            WalletEntry(wallet_address="   ")

    def test_address_stripped(self) -> None:
        entry = WalletEntry(wallet_address="  0xabc123  ")
        assert entry.wallet_address == "0xabc123"

    def test_symbol_uppercased(self) -> None:
        entry = WalletEntry(wallet_address="abc123", token_symbol="usdt")
        assert entry.token_symbol == "USDT"

    def test_network_short_lowercased(self) -> None:
        entry = WalletEntry(wallet_address="abc123", network_short="TRX")
        assert entry.network_short == "trx"

    def test_pair_property(self) -> None:
        entry = WalletEntry(wallet_address="abc", token_symbol="usdt", network_short="TRX")
        assert entry.pair == ("USDT", "trx")

    def test_auto_timestamp(self) -> None:
        before = datetime.now(timezone.utc)
        entry = WalletEntry(wallet_address="abc")
        assert entry.harvested_at is not None
        assert entry.harvested_at >= before

    def test_explicit_timestamp_preserved(self) -> None:
        ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
        entry = WalletEntry(wallet_address="abc", harvested_at=ts)
        assert entry.harvested_at == ts

    def test_to_dict_includes_all_fields(self) -> None:
        entry = WalletEntry(
            wallet_address="0xabc",
            site_url="https://scam.com",
            token_symbol="ETH",
            network_short="eth",
            source="llm",
            confidence=0.9,
        )
        d = entry.to_dict()
        assert d["wallet_address"] == "0xabc"
        assert d["token_symbol"] == "ETH"
        assert d["source"] == "llm"
        assert d["confidence"] == 0.9
        assert "harvested_at" in d

    def test_confidence_bounds(self) -> None:
        entry = WalletEntry(wallet_address="abc", confidence=0.5)
        assert entry.confidence == 0.5

    def test_confidence_out_of_range(self) -> None:
        with pytest.raises(ValueError):
            WalletEntry(wallet_address="abc", confidence=1.5)


# ---------------------------------------------------------------------------
# TokenNetwork tests
# ---------------------------------------------------------------------------


class TestTokenNetwork:
    """TokenNetwork normalization."""

    def test_symbol_uppercased(self) -> None:
        tn = TokenNetwork(token_name="Test", token_symbol="btc", network="Bitcoin", network_short="BTC")
        assert tn.token_symbol == "BTC"
        assert tn.network_short == "btc"

    def test_whitespace_stripped(self) -> None:
        tn = TokenNetwork(token_name="X", token_symbol=" eth  ", network="Net", network_short=" ETH ")
        assert tn.token_symbol == "ETH"
        assert tn.network_short == "eth"


# ---------------------------------------------------------------------------
# WalletHarvest tests
# ---------------------------------------------------------------------------


class TestWalletHarvest:
    """WalletHarvest aggregation model."""

    def _make_entry(self, addr: str, **kwargs) -> WalletEntry:
        return WalletEntry(wallet_address=addr, **kwargs)

    def test_empty_harvest(self) -> None:
        h = WalletHarvest()
        assert h.count == 0
        assert h.unique_addresses == set()
        assert h.symbols_found == set()

    def test_add_deduplicates(self) -> None:
        h = WalletHarvest()
        assert h.add(self._make_entry("addr1")) is True
        assert h.add(self._make_entry("addr2")) is True
        assert h.add(self._make_entry("addr1")) is False  # duplicate
        assert h.count == 2

    def test_run_id_propagation(self) -> None:
        h = WalletHarvest(run_id="run-123", entries=[self._make_entry("addr1")])
        assert h.entries[0].run_id == "run-123"

    def test_run_id_on_add(self) -> None:
        h = WalletHarvest(run_id="run-456")
        h.add(self._make_entry("addr1"))
        assert h.entries[0].run_id == "run-456"

    def test_merge_llm_results_replaces_matching(self) -> None:
        h = WalletHarvest()
        h.add(self._make_entry("addr1", source="js"))
        h.add(self._make_entry("addr2", source="js"))

        # LLM provides enriched data for addr1 and a new addr3
        llm_entries = [
            self._make_entry("addr1", token_symbol="USDT", network_short="trx", source="llm"),
            self._make_entry("addr3", token_symbol="BTC", source="llm"),
        ]
        h.merge_llm_results(llm_entries)

        assert h.count == 3
        by_addr = {e.wallet_address: e for e in h.entries}
        assert by_addr["addr1"].source == "llm"
        assert by_addr["addr1"].token_symbol == "USDT"
        assert by_addr["addr2"].source == "js"
        assert by_addr["addr3"].source == "llm"

    def test_deduplicate_keeps_best(self) -> None:
        h = WalletHarvest()
        h.entries = [
            self._make_entry("addr1"),
            self._make_entry("addr1", network_short="trx"),
        ]
        removed = h.deduplicate()
        assert removed == 1
        assert h.count == 1
        assert h.entries[0].network_short == "trx"  # kept the one with metadata

    def test_symbols_found(self) -> None:
        h = WalletHarvest()
        h.add(self._make_entry("a1", token_symbol="ETH"))
        h.add(self._make_entry("a2", token_symbol="BTC"))
        h.add(self._make_entry("a3", token_symbol="ETH"))
        assert h.symbols_found == {"ETH", "BTC"}

    def test_complete_sets_timestamp(self) -> None:
        h = WalletHarvest()
        assert h.completed_at is None
        h.complete()
        assert h.completed_at is not None

    def test_to_dict(self) -> None:
        h = WalletHarvest(site_url="https://scam.com", run_id="r1")
        h.add(self._make_entry("addr1", token_symbol="ETH"))
        d = h.to_dict()
        assert d["site_url"] == "https://scam.com"
        assert d["count"] == 1
        assert len(d["entries"]) == 1
        assert "ETH" in d["symbols_found"]

    def test_to_json(self) -> None:
        h = WalletHarvest(run_id="r1")
        h.add(self._make_entry("addr1"))
        j = h.to_json()
        parsed = json.loads(j)
        assert parsed["count"] == 1


# ---------------------------------------------------------------------------
# WalletPattern + WalletValidator tests
# ---------------------------------------------------------------------------

# Well-known test addresses per blockchain
TEST_ADDRESSES = {
    "ETH": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
    "TRX": "TJYqaPn323M2C7x7E5E3ypEGVgKYxxrWW1",
    "BTC_BECH32": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
    "BTC_LEGACY": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "XRP": "rN7n3473SaZBCG4dFL83w7p1W9cgZw6ihn",
    "ADA": "addr1qxy2k5c2n5qfr9z7a3ggvpfqfkpt78eczgmd26qjqkmpv6lr2g7v5sc3wg0nfgfsdvlaq5g82dkyn5wsydmhqgemhd6kxegraeel",
    "SOL": "7Np41oeYqPefeNQEHSv1UDhYrehxin3NStELsSKCT4K2",
}


class TestWalletPatterns:
    """Individual wallet pattern matching."""

    def test_eth_address(self) -> None:
        result = WALLET_PATTERNS[0].match(TEST_ADDRESSES["ETH"])
        assert result == TEST_ADDRESSES["ETH"]

    def test_trx_address(self) -> None:
        result = WALLET_PATTERNS[1].match(TEST_ADDRESSES["TRX"])
        assert result == TEST_ADDRESSES["TRX"]

    def test_btc_bech32(self) -> None:
        result = WALLET_PATTERNS[2].match(TEST_ADDRESSES["BTC_BECH32"])
        assert result == TEST_ADDRESSES["BTC_BECH32"]

    def test_btc_legacy(self) -> None:
        result = WALLET_PATTERNS[3].match(TEST_ADDRESSES["BTC_LEGACY"])
        assert result == TEST_ADDRESSES["BTC_LEGACY"]

    def test_xrp_address(self) -> None:
        result = WALLET_PATTERNS[4].match(TEST_ADDRESSES["XRP"])
        assert result == TEST_ADDRESSES["XRP"]

    def test_ada_address(self) -> None:
        result = WALLET_PATTERNS[5].match(TEST_ADDRESSES["ADA"])
        assert result == TEST_ADDRESSES["ADA"]

    def test_sol_address(self) -> None:
        result = WALLET_PATTERNS[6].match(TEST_ADDRESSES["SOL"])
        assert result == TEST_ADDRESSES["SOL"]

    def test_no_match_for_garbage(self) -> None:
        for pat in WALLET_PATTERNS:
            assert pat.match("hello world") is None

    def test_find_all_multiple_eth(self) -> None:
        text = "Send to 0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe or 0x1234567890123456789012345678901234567890"
        results = WALLET_PATTERNS[0].find_all(text)
        assert len(results) == 2

    def test_find_all_deduplicates(self) -> None:
        addr = TEST_ADDRESSES["ETH"]
        text = f"First: {addr} Second: {addr}"
        results = WALLET_PATTERNS[0].find_all(text)
        assert len(results) == 1


class TestWalletValidator:
    """WalletValidator integration across all patterns."""

    def setup_method(self) -> None:
        self.validator = WalletValidator()

    def test_validate_eth(self) -> None:
        result = self.validator.validate(TEST_ADDRESSES["ETH"])
        assert result is not None
        assert result.symbol == "ETH"

    def test_validate_trx(self) -> None:
        result = self.validator.validate(TEST_ADDRESSES["TRX"])
        assert result is not None
        assert result.symbol == "TRX"

    def test_validate_btc_legacy(self) -> None:
        result = self.validator.validate(TEST_ADDRESSES["BTC_LEGACY"])
        assert result is not None
        assert result.symbol == "BTC"

    def test_validate_returns_none_for_invalid(self) -> None:
        assert self.validator.validate("not-a-wallet") is None

    def test_is_valid_address(self) -> None:
        assert self.validator.is_valid_address(TEST_ADDRESSES["ETH"]) is True
        assert self.validator.is_valid_address("invalid") is False

    def test_classify(self) -> None:
        assert self.validator.classify(TEST_ADDRESSES["ETH"]) == "ETH"
        assert self.validator.classify(TEST_ADDRESSES["TRX"]) == "TRX"
        assert self.validator.classify("nope") is None

    def test_scan_text(self) -> None:
        text = (
            f"ETH wallet: {TEST_ADDRESSES['ETH']}\n"
            f"TRX wallet: {TEST_ADDRESSES['TRX']}\n"
            "Some other text here\n"
        )
        results = self.validator.scan_text(text)
        assert len(results) >= 2
        symbols = {r.symbol for r in results}
        assert "ETH" in symbols
        assert "TRX" in symbols

    def test_scan_text_deduplicates(self) -> None:
        addr = TEST_ADDRESSES["ETH"]
        text = f"{addr} and again {addr}"
        results = self.validator.scan_text(text)
        addr_set = {r.address for r in results}
        assert addr in addr_set

    def test_validate_for_symbol(self) -> None:
        assert self.validator.validate_for_symbol(TEST_ADDRESSES["ETH"], "ETH") is True
        assert self.validator.validate_for_symbol(TEST_ADDRESSES["ETH"], "BTC") is False

    def test_supported_symbols(self) -> None:
        symbols = self.validator.supported_symbols
        assert "ETH" in symbols
        assert "BTC" in symbols
        assert "TRX" in symbols
        assert "SOL" in symbols


# ---------------------------------------------------------------------------
# AllowlistFilter tests
# ---------------------------------------------------------------------------


class TestAllowlistFilter:
    """AllowlistFilter filtering logic."""

    def setup_method(self) -> None:
        self.filt = AllowlistFilter.default()

    def test_default_has_26_pairs(self) -> None:
        assert self.filt.count == 26

    def test_allowed_symbols(self) -> None:
        symbols = self.filt.allowed_symbols
        assert "BTC" in symbols
        assert "ETH" in symbols
        assert "USDT" in symbols
        assert "USDC" in symbols

    def test_is_allowed_true(self) -> None:
        entry = WalletEntry(wallet_address="abc", token_symbol="BTC", network_short="btc")
        assert self.filt.is_allowed(entry) is True

    def test_is_allowed_false(self) -> None:
        entry = WalletEntry(wallet_address="abc", token_symbol="SHIB", network_short="eth")
        assert self.filt.is_allowed(entry) is False

    def test_usdt_trx_allowed(self) -> None:
        entry = WalletEntry(wallet_address="T123", token_symbol="USDT", network_short="trx")
        assert self.filt.is_allowed(entry) is True

    def test_usdc_sol_allowed(self) -> None:
        entry = WalletEntry(wallet_address="abc", token_symbol="USDC", network_short="sol")
        assert self.filt.is_allowed(entry) is True

    def test_is_known_symbol(self) -> None:
        assert self.filt.is_known_symbol("BTC") is True
        assert self.filt.is_known_symbol("SHIB") is False

    def test_networks_for_symbol(self) -> None:
        usdt_networks = self.filt.networks_for_symbol("USDT")
        assert len(usdt_networks) == 8
        short_codes = {tn.network_short for tn in usdt_networks}
        assert "trx" in short_codes
        assert "eth" in short_codes

    def test_filter_splits_correctly(self) -> None:
        entries = [
            WalletEntry(wallet_address="a", token_symbol="BTC", network_short="btc"),
            WalletEntry(wallet_address="b", token_symbol="SHIB", network_short="eth"),
            WalletEntry(wallet_address="c", token_symbol="USDT", network_short="trx"),
        ]
        accepted, discarded = self.filt.filter(entries)
        assert len(accepted) == 2
        assert len(discarded) == 1
        assert discarded[0].token_symbol == "SHIB"

    def test_filter_empty_metadata_discarded(self) -> None:
        entries = [
            WalletEntry(wallet_address="a"),  # no symbol or network
        ]
        accepted, discarded = self.filt.filter(entries)
        assert len(accepted) == 0
        assert len(discarded) == 1

    def test_summary(self) -> None:
        s = self.filt.summary()
        assert s["total_pairs"] == 26
        assert len(s["symbols"]) > 0

    def test_from_json(self, tmp_path: Path) -> None:
        data = {
            "token_networks": [
                {"token_name": "Bitcoin", "token_symbol": "BTC", "network": "Bitcoin", "network_short": "btc"},
                {"token_name": "Ethereum", "token_symbol": "ETH", "network": "Ethereum", "network_short": "eth"},
            ]
        }
        json_file = tmp_path / "test_allowlist.json"
        json_file.write_text(json.dumps(data))
        filt = AllowlistFilter.from_json(json_file)
        assert filt.count == 2


class TestLoadAllowlist:
    """load_allowlist function."""

    def test_none_returns_defaults(self) -> None:
        pairs = load_allowlist(None)
        assert len(pairs) == 26

    def test_missing_file_returns_defaults(self) -> None:
        pairs = load_allowlist("/nonexistent/path.json")
        assert len(pairs) == 26

    def test_valid_json(self, tmp_path: Path) -> None:
        data = {
            "token_networks": [
                {"token_name": "Bitcoin", "token_symbol": "BTC", "network": "Bitcoin", "network_short": "btc"},
            ]
        }
        p = tmp_path / "al.json"
        p.write_text(json.dumps(data))
        pairs = load_allowlist(p)
        assert len(pairs) == 1
        assert pairs[0].token_symbol == "BTC"

    def test_bad_json_returns_defaults(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("{invalid json")
        pairs = load_allowlist(p)
        assert len(pairs) == 26


# ---------------------------------------------------------------------------
# WalletExporter tests
# ---------------------------------------------------------------------------


class TestWalletExporter:
    """XLSX, CSV, and JSON export."""

    def _make_entries(self, n: int = 3) -> list[WalletEntry]:
        return [
            WalletEntry(
                wallet_address=f"0x{'a' * 38}{i:02d}",
                site_url="https://scam.com",
                token_symbol="ETH" if i % 2 == 0 else "USDT",
                network_short="eth" if i % 2 == 0 else "trx",
                token_label="Ethereum" if i % 2 == 0 else "Tether",
                source="llm",
                confidence=0.9,
                run_id="test-run",
            )
            for i in range(n)
        ]

    def test_xlsx_export(self, tmp_path: Path) -> None:
        exporter = WalletExporter()
        entries = self._make_entries(5)
        stats = exporter.to_xlsx(entries, tmp_path / "test.xlsx", apply_filter=False)
        assert stats["exported"] == 5
        assert (tmp_path / "test.xlsx").exists()
        assert (tmp_path / "test.xlsx").stat().st_size > 0

    def test_xlsx_with_filter(self, tmp_path: Path) -> None:
        filt = AllowlistFilter.default()
        exporter = WalletExporter(allowlist_filter=filt)
        entries = self._make_entries(3) + [
            WalletEntry(wallet_address="garbage", token_symbol="FAKE", network_short="nope"),
        ]
        stats = exporter.to_xlsx(entries, tmp_path / "filtered.xlsx")
        assert stats["exported"] == 3
        assert stats["discarded"] == 1

    def test_csv_export(self, tmp_path: Path) -> None:
        exporter = WalletExporter()
        entries = self._make_entries(3)
        stats = exporter.to_csv(entries, tmp_path / "test.csv", apply_filter=False)
        assert stats["exported"] == 3
        content = (tmp_path / "test.csv").read_text()
        lines = content.strip().split("\n")
        assert len(lines) == 4  # header + 3 rows
        assert lines[0].startswith("site_url,")

    def test_json_export(self, tmp_path: Path) -> None:
        exporter = WalletExporter()
        entries = self._make_entries(2)
        stats = exporter.to_json(entries, tmp_path / "test.json", apply_filter=False)
        assert stats["exported"] == 2
        data = json.loads((tmp_path / "test.json").read_text())
        assert data["count"] == 2
        assert len(data["entries"]) == 2

    def test_export_creates_parent_dirs(self, tmp_path: Path) -> None:
        exporter = WalletExporter()
        entries = self._make_entries(1)
        stats = exporter.to_json(entries, tmp_path / "sub" / "dir" / "test.json", apply_filter=False)
        assert stats["exported"] == 1


class TestExportHarvest:
    """export_harvest convenience function."""

    def test_default_formats(self, tmp_path: Path) -> None:
        harvest = WalletHarvest(run_id="test-run")
        harvest.add(WalletEntry(wallet_address="0xabc123", token_symbol="ETH", network_short="eth"))
        results = export_harvest(harvest, tmp_path)
        assert len(results) == 2  # xlsx + json
        formats = {r["format"] for r in results}
        assert "xlsx" in formats
        assert "json" in formats

    def test_custom_formats(self, tmp_path: Path) -> None:
        harvest = WalletHarvest(run_id="r1")
        harvest.add(WalletEntry(wallet_address="abc", token_symbol="BTC", network_short="btc"))
        results = export_harvest(harvest, tmp_path, formats=["csv"])
        assert len(results) == 1
        assert results[0]["format"] == "csv"


# ---------------------------------------------------------------------------
# Backward compatibility: models/results.py re-export
# ---------------------------------------------------------------------------


class TestBackwardCompat:
    """Ensure models/results.py still exports WalletEntry for existing code."""

    def test_import_from_results(self) -> None:
        from ssi.models.results import WalletEntry as WE

        assert WE is WalletEntry

    def test_site_result_accepts_pydantic_wallet(self) -> None:
        from ssi.models.results import SiteResult

        entry = WalletEntry(wallet_address="0xabc")
        result = SiteResult(wallets=[entry])
        assert len(result.wallets) == 1
        d = result.to_dict()
        assert d["wallets"][0]["wallet_address"] == "0xabc"

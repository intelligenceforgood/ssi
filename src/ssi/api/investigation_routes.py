"""REST API routes for investigation history and wallet search.

These endpoints expose the ScanStore's CRUD methods so the Next.js
console can list past investigations, view details, and search wallets
without needing direct DB access.
"""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse

from ssi.store import build_scan_store

logger = logging.getLogger(__name__)

investigation_router = APIRouter(tags=["investigations"])


# ---------------------------------------------------------------------------
# Investigation list / detail
# ---------------------------------------------------------------------------


@investigation_router.get("/investigations")
def list_investigations(
    domain: str | None = Query(None, description="Filter by domain."),
    status: str | None = Query(None, description="Filter by status (completed, failed, running)."),
    limit: int = Query(50, ge=1, le=200, description="Page size."),
    offset: int = Query(0, ge=0, description="Page offset."),
) -> dict[str, Any]:
    """Return a paginated list of historical investigations from the scan store."""
    store = build_scan_store()
    scans = store.list_scans(domain=domain, status=status, limit=limit, offset=offset)
    # Serialise datetime objects for JSON
    for scan in scans:
        for key, val in scan.items():
            if hasattr(val, "isoformat"):
                scan[key] = val.isoformat()
    return {"items": scans, "count": len(scans), "limit": limit, "offset": offset}


@investigation_router.get("/investigations/active", tags=["monitoring"])
def list_active_investigations_endpoint() -> dict[str, Any]:
    """List currently active (running) investigations with event buses."""
    from ssi.api.ws_routes import get_bus, list_active_investigations

    active = list_active_investigations()
    result: list[dict[str, Any]] = []
    for inv_id in active:
        bus = get_bus(inv_id)
        if bus:
            snap = bus.get_snapshot()
            result.append({"investigation_id": inv_id, **snap})
    return {"active": result, "count": len(result)}


@investigation_router.get("/investigations/{scan_id}")
def get_investigation(scan_id: str) -> dict[str, Any]:
    """Return full detail for a single investigation (scan + wallets + PII exposures)."""
    store = build_scan_store()
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    wallets = store.get_wallets(scan_id)
    pii_exposures = store.get_pii_exposures(scan_id)
    agent_actions = store.get_agent_actions(scan_id)

    # Serialise datetime objects for JSON
    for collection in [wallets, pii_exposures, agent_actions]:
        for row in collection:
            for key, val in row.items():
                if hasattr(val, "isoformat"):
                    row[key] = val.isoformat()
    for key, val in scan.items():
        if hasattr(val, "isoformat"):
            scan[key] = val.isoformat()

    return {
        "scan": scan,
        "wallets": wallets,
        "pii_exposures": pii_exposures,
        "agent_actions": agent_actions,
    }


# ---------------------------------------------------------------------------
# Wallet search
# ---------------------------------------------------------------------------


@investigation_router.get("/wallets")
def search_wallets(
    address: str | None = Query(None, description="Filter by wallet address."),
    token_symbol: str | None = Query(None, description="Filter by token symbol (e.g. ETH, BTC)."),
    limit: int = Query(100, ge=1, le=500, description="Max results."),
) -> dict[str, Any]:
    """Search wallet addresses across all investigations."""
    store = build_scan_store()
    wallets = store.search_wallets(address=address, token_symbol=token_symbol, limit=limit)
    for wallet in wallets:
        for key, val in wallet.items():
            if hasattr(val, "isoformat"):
                wallet[key] = val.isoformat()
    return {"items": wallets, "count": len(wallets)}


# ---------------------------------------------------------------------------
# Wallet export (XLSX / CSV)
# ---------------------------------------------------------------------------


@investigation_router.get(
    "/investigations/{scan_id}/wallets.xlsx",
    tags=["export"],
    response_class=FileResponse,
    responses={
        200: {"content": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {}}},
        404: {"description": "Investigation not found or has no wallets."},
    },
)
def export_wallets_xlsx(scan_id: str) -> FileResponse:
    """Export wallet addresses for a single investigation as XLSX.

    Returns a downloadable XLSX file with all wallet entries associated
    with the given ``scan_id``.
    """
    return _export_wallets(scan_id, fmt="xlsx")


@investigation_router.get(
    "/investigations/{scan_id}/wallets.csv",
    tags=["export"],
    response_class=FileResponse,
    responses={
        200: {"content": {"text/csv": {}}},
        404: {"description": "Investigation not found or has no wallets."},
    },
)
def export_wallets_csv(scan_id: str) -> FileResponse:
    """Export wallet addresses for a single investigation as CSV."""
    return _export_wallets(scan_id, fmt="csv")


def _export_wallets(scan_id: str, *, fmt: str) -> FileResponse:
    """Shared implementation for wallet export endpoints.

    Args:
        scan_id: Investigation scan ID.
        fmt: Export format — ``"xlsx"`` or ``"csv"``.

    Returns:
        A ``FileResponse`` streaming the exported file.

    Raises:
        HTTPException: If the investigation or its wallets are not found.
    """
    from ssi.wallet.export import WalletExporter
    from ssi.wallet.models import WalletEntry

    store = build_scan_store()
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    wallet_rows = store.get_wallets(scan_id)
    if not wallet_rows:
        raise HTTPException(status_code=404, detail="No wallets found for this investigation.")

    # Convert store rows back to WalletEntry model instances
    entries: list[WalletEntry] = []
    for row in wallet_rows:
        entries.append(
            WalletEntry(
                site_url=row.get("site_url", scan.get("url", "")),
                token_symbol=row.get("token_symbol", ""),
                network_short=row.get("network_short", ""),
                wallet_address=row.get("wallet_address", ""),
                source=row.get("source", ""),
                confidence=float(row.get("confidence", 0.0)),
            )
        )

    exporter = WalletExporter()
    tmp_dir = Path(tempfile.mkdtemp(prefix="ssi_export_"))
    filename = f"wallets_{scan_id[:8]}.{fmt}"
    output_path = tmp_dir / filename

    if fmt == "xlsx":
        exporter.to_xlsx(entries, output_path, apply_filter=False)
        media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    elif fmt == "csv":
        exporter.to_csv(entries, output_path, apply_filter=False)
        media_type = "text/csv"
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {fmt}")

    return FileResponse(
        path=str(output_path),
        filename=filename,
        media_type=media_type,
    )

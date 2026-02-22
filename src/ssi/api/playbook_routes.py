"""Playbook CRUD API endpoints.

Provides REST endpoints for managing playbooks:

* ``GET /playbooks`` — list all playbooks
* ``GET /playbooks/{playbook_id}`` — get a single playbook
* ``POST /playbooks`` — create a new playbook
* ``PUT /playbooks/{playbook_id}`` — update an existing playbook
* ``DELETE /playbooks/{playbook_id}`` — delete a playbook
* ``POST /playbooks/test-match`` — test a URL against all registered playbooks
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ssi.playbook.loader import load_playbooks_from_dir
from ssi.playbook.matcher import PlaybookMatcher
from ssi.playbook.models import Playbook
from ssi.settings import get_settings

logger = logging.getLogger(__name__)

playbook_router = APIRouter(prefix="/playbooks", tags=["playbooks"])


# ---------------------------------------------------------------------------
# Module-level matcher (loaded once, refreshed on write operations)
# ---------------------------------------------------------------------------


def _get_playbook_dir() -> Path:
    """Return the resolved playbook directory path."""
    return Path(get_settings().playbook.playbook_dir)


def _load_matcher() -> PlaybookMatcher:
    """Load all playbooks from disk into a fresh matcher."""
    matcher = PlaybookMatcher()
    playbooks = load_playbooks_from_dir(_get_playbook_dir())
    matcher.register_many(playbooks)
    return matcher


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class PlaybookSummary(BaseModel):
    """Lightweight playbook summary for list endpoints."""

    playbook_id: str
    url_pattern: str
    description: str = ""
    steps_count: int
    enabled: bool
    version: str = "1.0"
    tags: list[str] = Field(default_factory=list)


class TestMatchRequest(BaseModel):
    """Request body for the test-match endpoint."""

    url: str = Field(..., description="URL to test against all playbook patterns.")


class TestMatchResponse(BaseModel):
    """Response for the test-match endpoint."""

    matched: bool
    playbook_id: str | None = None
    playbook_description: str | None = None
    url_pattern: str | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@playbook_router.get("", response_model=list[PlaybookSummary])
def list_playbooks() -> list[PlaybookSummary]:
    """List all registered playbooks."""
    matcher = _load_matcher()
    return [
        PlaybookSummary(
            playbook_id=pb.playbook_id,
            url_pattern=pb.url_pattern,
            description=pb.description,
            steps_count=len(pb.steps),
            enabled=pb.enabled,
            version=pb.version,
            tags=pb.tags,
        )
        for pb in matcher.playbooks
    ]


@playbook_router.get("/{playbook_id}", response_model=Playbook)
def get_playbook(playbook_id: str) -> Playbook:
    """Retrieve a single playbook by ID."""
    matcher = _load_matcher()
    pb = matcher.get(playbook_id)
    if pb is None:
        raise HTTPException(status_code=404, detail=f"Playbook '{playbook_id}' not found")
    return pb


@playbook_router.post("", response_model=Playbook, status_code=201)
def create_playbook(playbook: Playbook) -> Playbook:
    """Create a new playbook and save it to disk.

    The playbook JSON file is written to the playbook directory as
    ``{playbook_id}.json``.
    """
    pb_dir = _get_playbook_dir()
    pb_dir.mkdir(parents=True, exist_ok=True)

    pb_file = pb_dir / f"{playbook.playbook_id}.json"
    if pb_file.exists():
        raise HTTPException(
            status_code=409,
            detail=f"Playbook '{playbook.playbook_id}' already exists",
        )

    pb_file.write_text(
        json.dumps(playbook.model_dump(), indent=2, default=str),
        encoding="utf-8",
    )
    logger.info("Created playbook %s at %s", playbook.playbook_id, pb_file)
    return playbook


@playbook_router.put("/{playbook_id}", response_model=Playbook)
def update_playbook(playbook_id: str, playbook: Playbook) -> Playbook:
    """Update an existing playbook on disk."""
    if playbook.playbook_id != playbook_id:
        raise HTTPException(
            status_code=400,
            detail="Playbook ID in URL does not match body",
        )

    pb_dir = _get_playbook_dir()
    pb_file = pb_dir / f"{playbook_id}.json"
    if not pb_file.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Playbook '{playbook_id}' not found",
        )

    pb_file.write_text(
        json.dumps(playbook.model_dump(), indent=2, default=str),
        encoding="utf-8",
    )
    logger.info("Updated playbook %s", playbook_id)
    return playbook


@playbook_router.delete("/{playbook_id}", status_code=204)
def delete_playbook(playbook_id: str) -> None:
    """Delete a playbook from disk."""
    pb_dir = _get_playbook_dir()
    pb_file = pb_dir / f"{playbook_id}.json"
    if not pb_file.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Playbook '{playbook_id}' not found",
        )
    pb_file.unlink()
    logger.info("Deleted playbook %s", playbook_id)


@playbook_router.post("/test-match", response_model=TestMatchResponse)
def test_match(req: TestMatchRequest) -> TestMatchResponse:
    """Test a URL against all registered playbook patterns."""
    matcher = _load_matcher()
    pb = matcher.match(req.url)
    if pb is None:
        return TestMatchResponse(matched=False)
    return TestMatchResponse(
        matched=True,
        playbook_id=pb.playbook_id,
        playbook_description=pb.description,
        url_pattern=pb.url_pattern,
    )

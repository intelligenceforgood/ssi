"""Scam Site Investigator — AI-driven scam URL reconnaissance and evidence packaging."""

from __future__ import annotations

try:
    from importlib.metadata import version

    __version__ = version("ssi")
except Exception:
    __version__ = "0.0.0"

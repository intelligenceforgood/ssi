"""Integration bridge between SSI and i4g core platform.

Provides functions to push SSI investigation results into the core
platform's case management, evidence storage, and dossier pipeline.
"""

from ssi.integration.core_bridge import CoreBridge

__all__ = ["CoreBridge"]

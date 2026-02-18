"""Fraud taxonomy classification for SSI investigations.

Bridges SSI investigation results into the i4g five-axis fraud taxonomy
(intent, channel, technique, action, persona) using LLM-based classification.
"""

from ssi.classification.classifier import classify_investigation

__all__ = ["classify_investigation"]

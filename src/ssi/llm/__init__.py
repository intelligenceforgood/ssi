"""LLM provider abstraction for SSI.

Supports ``ollama`` (local) and ``gemini`` (Vertex AI / Google Generative AI)
backends through a unified interface.
"""

from ssi.llm.base import LLMProvider, LLMResult
from ssi.llm.factory import create_llm_provider

__all__ = ["LLMProvider", "LLMResult", "create_llm_provider"]

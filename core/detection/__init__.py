"""marmot-nids — detection engine package.

Exports the public API consumed by the FastAPI layer and downstream
phases (LLM engine, blockchain logger).
"""

from core.detection.base import Alert, DetectionEngine

__all__ = ["Alert", "DetectionEngine"]

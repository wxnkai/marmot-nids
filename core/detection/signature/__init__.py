"""Signature-based detection engine sub-package.

Exports the public API used by the application layer to load and run
signature-based detection.
"""

from core.detection.signature.engine import SignatureEngine
from core.detection.signature.manager import SignatureLoadError, SignatureManager
from core.detection.signature.schema import Signature, SignatureCondition, SignatureSet

__all__ = [
    "Signature",
    "SignatureCondition",
    "SignatureEngine",
    "SignatureLoadError",
    "SignatureManager",
    "SignatureSet",
]

"""
core.detection.signature.manager
=================================
HMAC-SHA256-verified loader for ``signatures.json``.

Security relevance:
    A tampered signature file could suppress detection of known attacks or
    introduce malicious patterns.  HMAC-SHA256 verification on every load
    ensures that the active rule set is exactly what the operator signed.

    Design decisions:
    - HMAC is verified **before** JSON parsing.  A truncated or malformed
      payload never reaches the parser.
    - Comparison uses ``hmac.compare_digest`` for constant-time equality,
      preventing timing-oracle attacks.
    - If the secret is absent or the digest mismatches, the load fails
      immediately with a ``SignatureLoadError``.  There is no silent fallback
      to an unverified set.
    - The secret is read at construction time from the environment via
      ``python-decouple`` and is never logged or stored on the returned
      object.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from pathlib import Path

from decouple import UndefinedValueError, config
from pydantic import ValidationError

from core.detection.signature.schema import Signature, SignatureSet

logger = logging.getLogger(__name__)

#: Path to the default signatures file, relative to the project root.
_DEFAULT_SIGNATURES_PATH = (
    Path(__file__).parent.parent.parent.parent / "signatures" / "signatures.json"
)


class SignatureLoadError(Exception):
    """Raised when ``signatures.json`` cannot be loaded or verified.

    Covers:
    * Missing JSON or HMAC file
    * HMAC digest mismatch (potential tampering)
    * Malformed JSON
    * Pydantic schema validation failure

    Callers must treat any instance as a hard failure — the engine must not
    start with an unverified or invalid signature set.
    """


class SignatureManager:
    """Loads and HMAC-verifies ``signatures.json``.

    Args:
        signatures_path: Path to ``signatures.json``.  Defaults to
            ``<project_root>/signatures/signatures.json``.
        secret: HMAC secret to use for verification.  If ``None``, the
            value is read from the ``SIGNATURE_HMAC_SECRET`` environment
            variable (via ``python-decouple``).  Pass a value directly only
            in tests or tooling scripts.

    Raises:
        SignatureLoadError: On construction if ``secret`` is ``None`` and
            ``SIGNATURE_HMAC_SECRET`` is not set in the environment.

    Security note:
        Construct this class eagerly at application start-up, not lazily.
        Failing fast during startup is safer than discovering a bad signature
        set mid-operation while an attack is in progress.
    """

    def __init__(
        self,
        signatures_path: Path | None = None,
        *,
        secret: str | None = None,
    ) -> None:
        self._path: Path = signatures_path or _DEFAULT_SIGNATURES_PATH

        if secret is not None:
            self._secret: str = secret
        else:
            try:
                self._secret = config("SIGNATURE_HMAC_SECRET")
            except UndefinedValueError as exc:
                raise SignatureLoadError(
                    "SIGNATURE_HMAC_SECRET is not set. "
                    "Add it to your .env file before starting the application."
                ) from exc

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self) -> list[Signature]:
        """Load, verify, validate, and return the signature list.

        Returns:
            A list of validated ``Signature`` objects ready to be injected
            into ``SignatureEngine``.

        Raises:
            SignatureLoadError: On any load, verification, or validation
                failure.
        """
        json_bytes = self._read_file(self._path)
        self._verify_hmac(json_bytes)
        signatures = self._parse(json_bytes)

        if not signatures:
            logger.warning(
                "Signature file loaded successfully but contains zero rules. "
                "The engine will not generate any alerts."
            )

        return signatures

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _read_file(self, path: Path) -> bytes:
        if not path.exists():
            raise SignatureLoadError(f"Signatures file not found: {path}")
        return path.read_bytes()

    def _verify_hmac(self, json_bytes: bytes) -> None:
        """Compute and verify the HMAC-SHA256 digest of ``json_bytes``.

        Raises:
            SignatureLoadError: If the HMAC file is missing or the digest
                does not match.
        """
        hmac_path = self._path.with_suffix(".json.hmac")
        if not hmac_path.exists():
            raise SignatureLoadError(
                f"HMAC file not found: {hmac_path}. "
                "Run scripts/sign_signatures.py to generate it."
            )

        expected_digest = hmac_path.read_text().strip()

        actual_mac = hmac.new(
            key=self._secret.encode("utf-8"),
            msg=json_bytes,
            digestmod=hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(actual_mac, expected_digest):
            raise SignatureLoadError(
                "HMAC verification failed: signatures.json may have been "
                "tampered with. Re-run scripts/sign_signatures.py if you "
                "have intentionally edited the file."
            )

        logger.info("Signature HMAC verified: %s", self._path.name)

    def _parse(self, json_bytes: bytes) -> list[Signature]:
        """Parse raw JSON bytes into validated ``Signature`` objects.

        Raises:
            SignatureLoadError: On malformed JSON or schema validation failure.
        """
        try:
            raw = json.loads(json_bytes)
        except json.JSONDecodeError as exc:
            raise SignatureLoadError(
                f"Malformed JSON in signatures file: {exc}"
            ) from exc

        try:
            sig_set = SignatureSet.model_validate(raw)
        except ValidationError as exc:
            raise SignatureLoadError(
                f"Signature schema validation failed:\n{exc}"
            ) from exc

        logger.info(
            "Loaded %d signatures (schema version %s)",
            len(sig_set.signatures),
            sig_set.version,
        )
        return sig_set.signatures

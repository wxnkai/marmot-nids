#!/usr/bin/env python
"""
scripts/sign_signatures.py
===========================
HMAC-SHA256-sign ``signatures.json`` and write the digest to
``signatures.json.hmac``.

Usage::

    python scripts/sign_signatures.py
    python scripts/sign_signatures.py --signatures path/to/signatures.json

The HMAC secret is read from the ``SIGNATURE_HMAC_SECRET`` environment
variable (or a ``.env`` file via python-decouple).

Run this script every time ``signatures.json`` is intentionally modified.
The application's ``SignatureManager`` will refuse to load a file whose
HMAC does not match the stored digest.

Security note:
    The ``.hmac`` file contains only the hex-encoded SHA-256 digest — it
    does not contain the secret.  Committing the ``.hmac`` file to source
    control is safe as long as the secret stays out of the repository.

    The script intentionally prints the digest to stdout so operators can
    verify it matches the value stored in ``.hmac`` after signing.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Accept the project root as a relative import anchor for decouple
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from decouple import UndefinedValueError, config  # noqa: E402


def _compute_hmac(file_bytes: bytes, secret: str) -> str:
    return hmac.new(
        key=secret.encode("utf-8"),
        msg=file_bytes,
        digestmod=hashlib.sha256,
    ).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sign signatures.json with HMAC-SHA256."
    )
    parser.add_argument(
        "--signatures",
        type=Path,
        default=_PROJECT_ROOT / "signatures" / "signatures.json",
        help="Path to signatures.json (default: signatures/signatures.json)",
    )
    args = parser.parse_args(argv)

    # ------------------------------------------------------------------ secret
    try:
        secret = config("SIGNATURE_HMAC_SECRET")
    except UndefinedValueError:
        print(
            "Error: SIGNATURE_HMAC_SECRET is not set.\n"
            "Add it to your .env file and retry.",
            file=sys.stderr,
        )
        return 1

    # ---------------------------------------------------------------- read file
    json_path: Path = args.signatures
    if not json_path.exists():
        print(f"Error: {json_path} not found.", file=sys.stderr)
        return 1

    file_bytes = json_path.read_bytes()

    # --------------------------------------------------------------- compute + write
    digest = _compute_hmac(file_bytes, secret)
    hmac_path = json_path.with_suffix(".json.hmac")
    hmac_path.write_text(digest)

    print(f"Signed  : {json_path}")
    print(f"HMAC    : {digest}")
    print(f"Written : {hmac_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

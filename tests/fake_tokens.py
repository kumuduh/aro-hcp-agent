"""Token-shaped test data, built at run time.

The redaction tests need strings that look like JWTs and base64 blobs, but
written out literally they are flagged by secret scanners (Red Hat LeakTK
reported one as a "Generic Secret"). Encoding fake values here produces the
same strings without any of them appearing in the source.
"""

from __future__ import annotations

import base64


def b64url(data: bytes) -> str:
    """Unpadded base64url, as JWT segments are encoded."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


#: The opening of a JWT header followed by a marker: token-shaped, never valid.
JWT_FRAGMENT = b64url(b'{"typ":"JWT"') + "SENTINEL"

#: A JWT header on its own.
JWT_HEADER = b64url(b'{"alg":"RS256"}')


def fake_jwt(payload: bytes = b'{"sub":"xxxxxxx"}', signature: bytes = b"signaturesignature") -> str:
    """A complete three-segment JWT whose payload and signature are fake."""
    return f"{JWT_HEADER}.{b64url(payload)}.{b64url(signature)}"


def b64(data: bytes) -> str:
    """Standard padded base64, for blob-shaped values."""
    return base64.b64encode(data).decode("ascii")

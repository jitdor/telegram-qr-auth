"""telegram-qr-auth — Python client and verifier.

Python does not run the package (it is JavaScript) and does not need to. The package's web half
runs once as a Worker at, say, https://auth.example.com. Python either *verifies* the signed
session it issued, or *drives* a sign-in for a client with no browser.

Standard library only — hmac, hashlib, base64, json. No pip install, no dependency to audit.

    key       = HMAC-SHA256(key=key_label, msg=secret)      -> 32 raw bytes
    signature = HMAC-SHA256(key=key,       msg=payload_b64) -> lowercase hex
    value     = f"{payload_b64}.{signature}"

payload_b64 is unpadded base64url of the claims JSON.

Self-check against the package's own test vector:

    python3 telegram_qr_auth.py --selftest
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, Mapping

DEFAULT_KEY_LABEL = "TelegramQrAuthSessionKey"


@dataclass(frozen=True)
class Session:
    """The claims carried by a verified session."""

    id: int
    name: str
    username: str | None
    exp: int
    raw: Mapping[str, Any]

    @property
    def expires_at(self) -> float:
        return float(self.exp)


class Verifier:
    """Verifies signed session values locally: no HTTP call, no SDK, two HMACs."""

    def __init__(self, secret: str, key_label: str = DEFAULT_KEY_LABEL) -> None:
        if not secret:
            raise ValueError("secret is required")
        # Domain separation: the label is the HMAC *key* and the secret is the *message*, so a
        # signature produced under a different label cannot verify here.
        self._key = hmac.new(key_label.encode(), secret.encode(), hashlib.sha256).digest()

    def verify(self, value: str | None, *, now: float | None = None) -> Session | None:
        """Return the claims if validly signed and unexpired, else None.

        Accepts a bare value or an ``Authorization: Bearer ...`` header value.
        """
        if not value:
            return None

        if value[:7].lower() == "bearer ":
            value = value[7:].strip()

        payload_b64, _, signature = value.partition(".")
        if not payload_b64 or not signature:
            return None

        # Sign the *encoded* payload, never the decoded JSON: re-serializing would change the bytes
        # (key order, separators) and no signature would ever match.
        expected = hmac.new(self._key, payload_b64.encode(), hashlib.sha256).hexdigest()

        # compare_digest, not ==. A plain comparison leaks the signature a byte at a time to anyone
        # patient enough to time the responses.
        # Compared as bytes: str inputs must be ASCII or compare_digest raises TypeError, and a bad
        # credential has to come back as None, not as a 500.
        if not hmac.compare_digest(expected.encode(), signature.encode("utf-8", "replace")):
            return None

        claims = read_unverified_claims(value)
        if claims is None or not isinstance(claims.get("id"), int):
            return None

        exp = claims.get("exp")
        if not isinstance(exp, (int, float)):
            return None
        # The signature never expires on its own. A verifier that skips this check has built a
        # permanent credential.
        if exp < (time.time() if now is None else now):
            return None

        return Session(
            id=int(claims["id"]),
            name=str(claims.get("name", "")),
            username=claims.get("username") or None,
            exp=int(exp),
            raw=claims,
        )


def read_unverified_claims(value: str) -> dict[str, Any] | None:
    """Decode the claims WITHOUT checking the signature.

    Fine for showing a name in a UI. Never for an access decision — anyone can put anything in
    this half of the string.
    """
    payload_b64 = value.partition(".")[0]
    try:
        return json.loads(_b64url_decode(payload_b64))
    except (ValueError, json.JSONDecodeError):
        return None


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


# ---------------------------------------------------------------------------------------------
# Client — for a CLI, daemon or desktop app signing a human in.
#
# Needs `allowAssertions: true` on the auth service, which is off by default: it returns the signed
# session in the response body instead of an HttpOnly cookie, appropriate only for clients that
# have no cookie jar.
# ---------------------------------------------------------------------------------------------

class SignInError(Exception):
    """Raised when a sign-in ends in anything other than success."""

    def __init__(self, status: str, reason: str | None = None) -> None:
        super().__init__(f"sign-in {status}" + (f": {reason}" if reason else ""))
        self.status = status
        self.reason = reason


class Client:
    """Drives the QR sign-in. Uses urllib so this file stays dependency-free; swap in requests or
    httpx freely — the protocol is two GETs."""

    def __init__(self, auth_base: str, *, opener=None) -> None:
        self.auth_base = auth_base.rstrip("/")
        self._opener = opener

    def begin(self) -> dict[str, Any]:
        """Ask for a challenge: {token, deepLink, svg, expiresIn, pollPath}."""
        return self._get_json(f"{self.auth_base}/auth/qr")

    def wait_for_scan(self, token: str, *, interval: float = 2.0, timeout: float = 600.0) -> tuple[str, Session]:
        """Poll until the user scans. Returns (assertion, claims) or raises SignInError."""
        deadline = time.monotonic() + timeout

        while True:
            body = self._get_json(f"{self.auth_base}/auth/poll?token={token}&mode=token")
            status = body.get("status")

            if status == "confirmed":
                assertion = body["assertion"]
                claims = read_unverified_claims(assertion)
                # Claims are readable without the secret — signed, not encrypted. Displaying them
                # is fine; a client is in no position to *trust* them, and does not need to.
                return assertion, Session(
                    id=int(claims["id"]),
                    name=str(claims.get("name", "")),
                    username=claims.get("username") or None,
                    exp=int(claims["exp"]),
                    raw=claims,
                )

            if status in ("denied", "expired", "invalid"):
                # "invalid" is also what you get if allowAssertions is not enabled on the service.
                raise SignInError(status, body.get("reason") or body.get("error"))

            if time.monotonic() > deadline:
                raise SignInError("expired", "client timeout")

            time.sleep(interval)  # "pending" — still on screen, nobody has scanned it

    def _get_json(self, url: str) -> dict[str, Any]:
        import urllib.error
        import urllib.request

        opener = self._opener or urllib.request.urlopen
        try:
            with opener(url) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as err:
            # /auth/poll answers a malformed or unsupported request with a 400 that still carries a
            # JSON body ({"status": "invalid", ...}); surface that instead of a bare traceback.
            try:
                return json.loads(err.read())
            except ValueError:
                raise err


# ---------------------------------------------------------------------------------------------

# Known-answer vector, from the package's own tests/assertions.test.mjs.
TEST_VECTOR = {
    "secret": "123456:AAHfake-bot-token",
    "value": (
        "eyJpZCI6Mzk2NDQzNzIsIm5hbWUiOiJBbGljZSBOZyIsInVzZXJuYW1lIjoiYWxpY2UiLCJleHAiOjQxMDI0NDQ4MDB9"
        ".ae95d3dc79afa25ab27971f0ccf030a6e0c952d21b3f14872658f366666b2e95"
    ),
}


def selftest() -> bool:
    """True if this port agrees with the package. Run it in CI, not just once."""
    good = Verifier(TEST_VECTOR["secret"]).verify(TEST_VECTOR["value"])
    checks = [
        good is not None and good.id == 39644372,
        good is not None and good.name == "Alice Ng",
        # A bearer prefix must be accepted.
        Verifier(TEST_VECTOR["secret"]).verify("Bearer " + TEST_VECTOR["value"]) is not None,
        # The wrong secret must not verify.
        Verifier("wrong-secret").verify(TEST_VECTOR["value"]) is None,
        # The wrong key label must not verify.
        Verifier(TEST_VECTOR["secret"], key_label="SomeOtherLabel").verify(TEST_VECTOR["value"]) is None,
        # A tampered payload must not verify.
        Verifier(TEST_VECTOR["secret"]).verify("eyJpZCI6OTk5fQ." + TEST_VECTOR["value"].split(".")[1]) is None,
        # Expiry must be enforced even though the signature is good.
        Verifier(TEST_VECTOR["secret"]).verify(TEST_VECTOR["value"], now=4_102_444_801) is None,
        # Junk must not throw.
        Verifier(TEST_VECTOR["secret"]).verify("nonsense") is None,
        Verifier(TEST_VECTOR["secret"]).verify(None) is None,
    ]
    return all(checks)


if __name__ == "__main__":
    import sys

    if "--selftest" in sys.argv:
        ok = selftest()
        print("python verifier self-test:", "ok" if ok else "FAILED")
        sys.exit(0 if ok else 1)

    print(__doc__)

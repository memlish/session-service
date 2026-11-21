"""Creating and checking session tokens (HS256 JWTs)."""
import time
import uuid

from authlib.jose import JsonWebToken
from authlib.jose.errors import JoseError

from .config import Settings

_jwt = JsonWebToken(["HS256"])


class InvalidToken(Exception):
    """Raised when a bearer token cannot be accepted."""


def issue(settings: Settings, user_id: str, roles: list[str]) -> tuple[str, dict]:
    """Sign a new session token for ``user_id`` and return it with its claims."""
    now = int(time.time())
    claims = {
        "iss": settings.issuer,
        "aud": settings.audience,
        "sub": user_id,
        "roles": roles,
        "iat": now,
        "exp": now + settings.session_ttl_seconds,
        "jti": uuid.uuid4().hex,
    }
    token = _jwt.encode({"alg": "HS256", "typ": "JWT"}, claims, settings.signing_key)
    return token.decode("ascii"), claims


def verify(settings: Settings, token: str) -> dict:
    """Decode a session token and check its signature, issuer, audience and expiry."""
    claims_options = {
        "iss": {"essential": True, "value": settings.issuer},
        "aud": {"essential": True, "value": settings.audience},
        "sub": {"essential": True},
        "exp": {"essential": True},
        "jti": {"essential": True},
    }
    try:
        claims = _jwt.decode(token, settings.signing_key, claims_options=claims_options)
        claims.validate(leeway=settings.clock_leeway_seconds)
    except (JoseError, ValueError) as exc:
        raise InvalidToken(str(exc)) from exc
    return dict(claims)

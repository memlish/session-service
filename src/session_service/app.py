"""HTTP API for issuing session tokens and answering "who am I"."""
from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel

from . import tokens
from .config import DEV_USERS, settings

app = FastAPI(title="session-service", version="0.3.0")

# Session ids revoked through POST /sessions/revoke. Kept in memory; a restart
# clears it, which is acceptable because tokens are short-lived.
_revoked: set[str] = set()


class SessionRequest(BaseModel):
    user_id: str


class SessionResponse(BaseModel):
    token: str
    token_type: str = "Bearer"
    expires_at: int


class Me(BaseModel):
    user_id: str
    name: str
    email: str
    roles: list[str]
    session_expires_at: int


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def current_claims(authorization: str | None = Header(default=None)) -> dict:
    """Resolve the bearer token on the request to its verified claims."""
    if not authorization:
        raise _unauthorized("missing bearer token")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise _unauthorized("expected a bearer token")
    try:
        claims = tokens.verify(settings, token.strip())
    except tokens.InvalidToken:
        raise _unauthorized("invalid or expired token")
    if claims["jti"] in _revoked:
        raise _unauthorized("session has been revoked")
    return claims


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/sessions", response_model=SessionResponse, status_code=status.HTTP_201_CREATED)
def create_session(body: SessionRequest) -> SessionResponse:
    """Issue a session for a known user id (development seed only)."""
    user = DEV_USERS.get(body.user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown user")
    token, claims = tokens.issue(settings, body.user_id, user["roles"])
    return SessionResponse(token=token, expires_at=claims["exp"])


@app.get("/me", response_model=Me)
def me(claims: dict = Depends(current_claims)) -> Me:
    """Return the user behind the bearer token."""
    user = DEV_USERS.get(claims["sub"])
    if user is None:
        raise _unauthorized("user no longer exists")
    return Me(
        user_id=claims["sub"],
        name=user["name"],
        email=user["email"],
        roles=claims.get("roles", []),
        session_expires_at=claims["exp"],
    )


@app.post("/sessions/revoke", status_code=status.HTTP_204_NO_CONTENT)
def revoke_session(claims: dict = Depends(current_claims)) -> None:
    """Log out: revoke the session the bearer token belongs to."""
    _revoked.add(claims["jti"])

"""Runtime settings, read from the environment with development defaults."""
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    signing_key: bytes
    issuer: str
    audience: str
    session_ttl_seconds: int
    clock_leeway_seconds: int


def load_settings() -> Settings:
    """Build settings from SESSION_* environment variables."""
    return Settings(
        signing_key=os.environ.get("SESSION_SIGNING_KEY", "dev-only-change-me").encode(),
        issuer=os.environ.get("SESSION_ISSUER", "http://localhost:8000"),
        audience=os.environ.get("SESSION_AUDIENCE", "web"),
        session_ttl_seconds=int(os.environ.get("SESSION_TTL_SECONDS", "3600")),
        clock_leeway_seconds=int(os.environ.get("SESSION_CLOCK_LEEWAY_SECONDS", "30")),
    )


settings = load_settings()

# Users available in local development. In production these come from the
# account service; here they are enough to issue and resolve sessions.
DEV_USERS = {
    "u-1001": {"name": "Alice Example", "email": "alice@example.test", "roles": ["user"]},
    "u-1002": {"name": "Bob Example", "email": "bob@example.test", "roles": ["user", "support"]},
}

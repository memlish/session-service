# session-service

Issues short-lived session tokens and tells callers who a bearer token belongs to.
Tokens are HS256-signed JWTs carrying `iss`, `aud`, `sub`, `roles`, `iat`, `exp` and `jti`.

Users come from an in-memory development seed (`DEV_USERS` in `config.py`); revoked
sessions are tracked in memory and cleared on restart.

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness check |
| `POST` | `/sessions` | Body `{"user_id": "u-1001"}`. Issues a session token for a seeded user (404 if unknown) |
| `GET` | `/me` | `Authorization: Bearer <token>`. Returns the user and roles behind the token |
| `POST` | `/sessions/revoke` | `Authorization: Bearer <token>`. Revokes that session (logout) |

Invalid, expired, revoked or mis-addressed tokens get `401` with `WWW-Authenticate: Bearer`.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `SESSION_SIGNING_KEY` | `dev-only-change-me` | HMAC key for signing and checking tokens. Set a real one outside development |
| `SESSION_ISSUER` | `http://localhost:8000` | `iss` claim written and required |
| `SESSION_AUDIENCE` | `web` | `aud` claim written and required |
| `SESSION_TTL_SECONDS` | `3600` | Session lifetime |
| `SESSION_CLOCK_LEEWAY_SECONDS` | `30` | Allowed clock skew when checking `exp` |

## Running

```sh
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
PYTHONPATH=src .venv/bin/uvicorn session_service.app:app --reload
```

## Tests

```sh
.venv/bin/python -m pytest tests/ -q
```

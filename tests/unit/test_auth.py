"""
tests/unit/test_auth.py
════════════════════════
Unit tests for sin.api.auth.

Covers: password hashing, JWT lifecycle, get_current_user, require_role.
No live DB — all DB calls mocked at get_user_by_id.
"""
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from jose import jwt, JWTError

from sin.api.auth import (
    ALGORITHM,
    SECRET_KEY,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    hash_password,
    require_admin,
    require_analyst,
    require_viewer,
    verify_password,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_user(role: str = "admin", active: str = "true") -> MagicMock:
    u = MagicMock()
    u.role = role
    u.is_active = active
    u.last_login = None
    return u


def _make_expired_token() -> str:
    expire = datetime.now(timezone.utc) - timedelta(minutes=5)
    return jwt.encode(
        {"sub": "1", "username": "test", "role": "admin",
         "exp": expire, "type": "access"},
        SECRET_KEY, algorithm=ALGORITHM,
    )


def _mock_credentials(token: str) -> MagicMock:
    creds = MagicMock()
    creds.credentials = token
    return creds


# ── Password hashing ──────────────────────────────────────────────────────────

class TestPasswordHashing:
    def test_hash_creates_bcrypt_format(self):
        h = hash_password("mysecret")
        assert h.startswith("$2b$") or h.startswith("$2a$")

    def test_verify_correct_password(self):
        h = hash_password("correct-horse")
        assert verify_password("correct-horse", h) is True

    def test_verify_wrong_password_returns_false(self):
        h = hash_password("correct-horse")
        assert verify_password("wrong-horse", h) is False

    def test_hash_is_not_plaintext(self):
        h = hash_password("secret")
        assert "secret" not in h


# ── JWT token creation and decoding ──────────────────────────────────────────

class TestJWTTokens:
    def test_access_token_contains_role(self):
        token = create_access_token(user_id=1, username="admin", role="admin")
        payload = decode_token(token)
        assert payload["role"] == "admin"

    def test_access_token_contains_username(self):
        token = create_access_token(user_id=1, username="alice", role="analyst")
        payload = decode_token(token)
        assert payload["username"] == "alice"

    def test_access_token_type_is_access(self):
        token = create_access_token(user_id=1, username="u", role="viewer")
        payload = decode_token(token)
        assert payload["type"] == "access"

    def test_access_token_sub_is_user_id(self):
        token = create_access_token(user_id=42, username="u", role="admin")
        payload = decode_token(token)
        assert payload["sub"] == "42"

    def test_refresh_token_type_is_refresh(self):
        token = create_refresh_token(user_id=1)
        payload = decode_token(token)
        assert payload["type"] == "refresh"

    def test_decode_valid_token_returns_payload(self):
        token = create_access_token(user_id=5, username="bob", role="analyst")
        payload = decode_token(token)
        assert payload["sub"] == "5"

    def test_decode_expired_token_raises(self):
        token = _make_expired_token()
        with pytest.raises(JWTError):
            decode_token(token)

    def test_decode_tampered_token_raises(self):
        token = create_access_token(user_id=1, username="u", role="admin")
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(JWTError):
            decode_token(tampered)

    def test_decode_garbage_raises(self):
        with pytest.raises(JWTError):
            decode_token("not.a.jwt")


# ── get_current_user ──────────────────────────────────────────────────────────

class TestGetCurrentUser:
    def test_valid_token_returns_user(self):
        token    = create_access_token(user_id=1, username="admin", role="admin")
        mock_db  = MagicMock()
        mock_user = _make_user("admin")
        with patch("sin.api.auth.get_user_by_id", return_value=mock_user):
            user = get_current_user(
                credentials=_mock_credentials(token), db=mock_db
            )
        assert user.role == "admin"

    def test_missing_credentials_raises_401(self):
        with pytest.raises(HTTPException) as exc:
            get_current_user(credentials=None, db=MagicMock())
        assert exc.value.status_code == 401

    def test_invalid_token_raises_401(self):
        with pytest.raises(HTTPException) as exc:
            get_current_user(
                credentials=_mock_credentials("invalid.token.here"),
                db=MagicMock(),
            )
        assert exc.value.status_code == 401

    def test_expired_token_raises_401(self):
        token = _make_expired_token()
        with pytest.raises(HTTPException) as exc:
            get_current_user(
                credentials=_mock_credentials(token), db=MagicMock()
            )
        assert exc.value.status_code == 401

    def test_refresh_token_used_as_access_raises_401(self):
        token = create_refresh_token(user_id=1)
        with pytest.raises(HTTPException) as exc:
            get_current_user(
                credentials=_mock_credentials(token), db=MagicMock()
            )
        assert exc.value.status_code == 401

    def test_inactive_user_raises_401(self):
        token    = create_access_token(user_id=2, username="blocked", role="analyst")
        mock_user = _make_user("analyst", active="false")
        with patch("sin.api.auth.get_user_by_id", return_value=mock_user):
            with pytest.raises(HTTPException) as exc:
                get_current_user(
                    credentials=_mock_credentials(token), db=MagicMock()
                )
        assert exc.value.status_code == 401

    def test_user_not_found_raises_401(self):
        token = create_access_token(user_id=999, username="ghost", role="admin")
        with patch("sin.api.auth.get_user_by_id", return_value=None):
            with pytest.raises(HTTPException) as exc:
                get_current_user(
                    credentials=_mock_credentials(token), db=MagicMock()
                )
        assert exc.value.status_code == 401


# ── require_role ──────────────────────────────────────────────────────────────

class TestRequireRole:
    def test_admin_allowed_on_admin_route(self):
        user = require_admin(user=_make_user("admin"))
        assert user.role == "admin"

    def test_analyst_rejected_on_admin_route(self):
        with pytest.raises(HTTPException) as exc:
            require_admin(user=_make_user("analyst"))
        assert exc.value.status_code == 403

    def test_viewer_rejected_on_admin_route(self):
        with pytest.raises(HTTPException) as exc:
            require_admin(user=_make_user("viewer"))
        assert exc.value.status_code == 403

    def test_admin_allowed_on_analyst_route(self):
        user = require_analyst(user=_make_user("admin"))
        assert user.role == "admin"

    def test_analyst_allowed_on_analyst_route(self):
        user = require_analyst(user=_make_user("analyst"))
        assert user.role == "analyst"

    def test_viewer_rejected_on_analyst_route(self):
        with pytest.raises(HTTPException) as exc:
            require_analyst(user=_make_user("viewer"))
        assert exc.value.status_code == 403

    def test_admin_allowed_on_viewer_route(self):
        user = require_viewer(user=_make_user("admin"))
        assert user.role == "admin"

    def test_analyst_allowed_on_viewer_route(self):
        user = require_viewer(user=_make_user("analyst"))
        assert user.role == "analyst"

    def test_viewer_allowed_on_viewer_route(self):
        user = require_viewer(user=_make_user("viewer"))
        assert user.role == "viewer"

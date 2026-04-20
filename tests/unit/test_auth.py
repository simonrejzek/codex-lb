from __future__ import annotations

import base64
import json
import os
import stat

import pytest
from cryptography.fernet import Fernet, InvalidToken

from app.core.auth import claims_from_auth, extract_id_token_claims, parse_auth_json
from app.core.crypto import TokenEncryptor, get_or_create_key

pytestmark = pytest.mark.unit


def _encode_jwt(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    body = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return f"header.{body}.sig"


def test_extract_id_token_claims_valid_payload():
    payload = {"email": "user@example.com", "chatgpt_account_id": "acc_123"}
    token = _encode_jwt(payload)
    claims = extract_id_token_claims(token)
    assert claims.email == "user@example.com"
    assert claims.chatgpt_account_id == "acc_123"


def test_claims_from_auth_prefers_token_account_id():
    payload = {
        "email": "user@example.com",
        "chatgpt_account_id": "acc_payload",
        "https://api.openai.com/auth": {"chatgpt_plan_type": "plus"},
    }
    token = _encode_jwt(payload)
    auth_json = {
        "tokens": {
            "idToken": token,
            "accessToken": "access",
            "refreshToken": "refresh",
            "accountId": "acc_explicit",
        },
        "lastRefreshAt": "2024-01-01T00:00:00Z",
    }
    auth = parse_auth_json(json.dumps(auth_json).encode("utf-8"))
    claims = claims_from_auth(auth)
    assert claims.account_id == "acc_explicit"
    assert claims.email == "user@example.com"
    assert claims.plan_type == "plus"


def test_key_file_permissions_and_reuse(temp_key_file):
    first = get_or_create_key()
    second = get_or_create_key()
    assert first == second
    if os.name == "nt":
        pytest.skip("POSIX chmod semantics are not enforced on Windows")
    mode = stat.S_IMODE(temp_key_file.stat().st_mode)
    assert mode == 0o600


def test_token_encryptor_round_trip():
    encryptor = TokenEncryptor()
    value = "secret-token"
    encrypted = encryptor.encrypt(value)
    assert encryptor.decrypt(encrypted) == value


def test_explicit_encryption_key_env_is_used_and_seeds_key_file(monkeypatch, temp_key_file):
    direct_key = Fernet.generate_key()
    monkeypatch.setenv("CODEX_LB_ENCRYPTION_KEY", direct_key.decode("ascii"))
    from app.core.config.settings import get_settings

    get_settings.cache_clear()

    original = "secret-token"
    encrypted = TokenEncryptor().encrypt(original)
    assert temp_key_file.read_bytes() == direct_key
    assert TokenEncryptor().decrypt(encrypted) == original

    monkeypatch.delenv("CODEX_LB_ENCRYPTION_KEY")
    get_settings.cache_clear()

    assert TokenEncryptor().decrypt(encrypted) == original


def test_explicit_encryption_key_env_takes_precedence_over_existing_key_file(monkeypatch, temp_key_file):
    file_key = Fernet.generate_key()
    env_key = Fernet.generate_key()
    temp_key_file.write_bytes(file_key)
    if os.name != "nt":
        temp_key_file.chmod(0o600)
    monkeypatch.setenv("CODEX_LB_ENCRYPTION_KEY", env_key.decode("ascii"))
    from app.core.config.settings import get_settings

    get_settings.cache_clear()

    encrypted = TokenEncryptor().encrypt("secret-token")

    with pytest.raises(InvalidToken):
        TokenEncryptor(key=file_key).decrypt(encrypted)
    assert TokenEncryptor(key=env_key).decrypt(encrypted) == "secret-token"


def test_previous_encryption_keys_allow_decrypt_after_primary_key_change(monkeypatch, temp_key_file):
    old_primary_key = Fernet.generate_key()
    new_primary_key = Fernet.generate_key()

    monkeypatch.setenv("CODEX_LB_ENCRYPTION_KEY", old_primary_key.decode("ascii"))
    from app.core.config.settings import get_settings

    get_settings.cache_clear()
    encrypted = TokenEncryptor().encrypt("secret-token")

    monkeypatch.setenv("CODEX_LB_ENCRYPTION_KEY", new_primary_key.decode("ascii"))
    monkeypatch.setenv("CODEX_LB_ENCRYPTION_PREVIOUS_KEYS", old_primary_key.decode("ascii"))
    get_settings.cache_clear()

    assert TokenEncryptor().decrypt(encrypted) == "secret-token"
    reencrypted = TokenEncryptor().encrypt("fresh-secret")
    with pytest.raises(InvalidToken):
        TokenEncryptor(key=old_primary_key).decrypt(reencrypted)
    assert TokenEncryptor(key=new_primary_key).decrypt(reencrypted) == "fresh-secret"


def test_existing_key_file_remains_a_decrypt_fallback_when_primary_env_key_changes(monkeypatch, temp_key_file):
    file_key = Fernet.generate_key()
    new_primary_key = Fernet.generate_key()
    temp_key_file.write_bytes(file_key)
    if os.name != "nt":
        temp_key_file.chmod(0o600)

    encrypted = TokenEncryptor(key=file_key).encrypt("secret-token")

    monkeypatch.setenv("CODEX_LB_ENCRYPTION_KEY", new_primary_key.decode("ascii"))
    from app.core.config.settings import get_settings

    get_settings.cache_clear()

    assert TokenEncryptor().decrypt(encrypted) == "secret-token"


def test_token_encryptor_invalid_token_raises():
    encryptor = TokenEncryptor()
    with pytest.raises(InvalidToken):
        encryptor.decrypt(b"not-a-token")

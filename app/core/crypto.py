from __future__ import annotations

from pathlib import Path

from cryptography.fernet import Fernet

from app.core.config.settings import get_settings


def _get_or_create_key(key_file: Path) -> bytes:
    key_file.parent.mkdir(parents=True, exist_ok=True)
    if key_file.exists():
        return key_file.read_bytes()
    key = Fernet.generate_key()
    key_file.write_bytes(key)
    key_file.chmod(0o600)
    return key


def _seed_key_file_if_missing(key_file: Path, key: bytes) -> None:
    key_file.parent.mkdir(parents=True, exist_ok=True)
    if key_file.exists():
        return
    key_file.write_bytes(key)
    key_file.chmod(0o600)


def _normalize_key_bytes(key: str | bytes) -> bytes:
    if isinstance(key, bytes):
        return key
    return key.encode("ascii")


class TokenEncryptor:
    def __init__(self, key: str | bytes | None = None, key_file: Path | None = None) -> None:
        settings = get_settings()
        resolved_file = key_file or settings.encryption_key_file
        resolved_key = _normalize_key_bytes(key) if key is not None else None
        if resolved_key is None and settings.encryption_key is not None:
            resolved_key = _normalize_key_bytes(settings.encryption_key)
            _seed_key_file_if_missing(resolved_file, resolved_key)
        if resolved_key is None:
            resolved_key = _get_or_create_key(resolved_file)
        self._fernet = Fernet(resolved_key)

    def encrypt(self, token: str) -> bytes:
        return self._fernet.encrypt(token.encode())

    def decrypt(self, encrypted: bytes) -> str:
        return self._fernet.decrypt(encrypted).decode()


def get_or_create_key(key_file: Path | None = None) -> bytes:
    settings = get_settings()
    resolved_file = key_file or settings.encryption_key_file
    if settings.encryption_key is not None:
        resolved_key = _normalize_key_bytes(settings.encryption_key)
        _seed_key_file_if_missing(resolved_file, resolved_key)
        return resolved_key
    return _get_or_create_key(resolved_file)

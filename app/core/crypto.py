from __future__ import annotations

from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

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


def _append_unique_key(keys: list[bytes], seen: set[bytes], key: bytes) -> None:
    if key in seen:
        return
    keys.append(key)
    seen.add(key)


def _runtime_key_chain(*, key_file: Path) -> list[bytes]:
    settings = get_settings()
    keys: list[bytes] = []
    seen: set[bytes] = set()

    if settings.encryption_key is not None:
        primary_key = _normalize_key_bytes(settings.encryption_key)
        _seed_key_file_if_missing(key_file, primary_key)
    else:
        primary_key = _get_or_create_key(key_file)
    _append_unique_key(keys, seen, primary_key)

    if key_file.exists():
        file_key = key_file.read_bytes()
        _append_unique_key(keys, seen, file_key)

    for previous_key in settings.encryption_previous_keys:
        _append_unique_key(keys, seen, _normalize_key_bytes(previous_key))

    return keys


def _build_fernet_chain(keys: list[bytes]) -> list[Fernet]:
    decryptors: list[Fernet] = []
    for index, key in enumerate(keys):
        try:
            decryptors.append(Fernet(key))
        except ValueError:
            if index == 0:
                raise
            continue
    return decryptors


class TokenEncryptor:
    def __init__(self, key: str | bytes | None = None, key_file: Path | None = None) -> None:
        settings = get_settings()
        resolved_file = key_file or settings.encryption_key_file
        if key is not None:
            key_chain = [_normalize_key_bytes(key)]
        else:
            key_chain = _runtime_key_chain(key_file=resolved_file)
        self._fernet = Fernet(key_chain[0])
        self._decryptors = _build_fernet_chain(key_chain)

    def encrypt(self, token: str) -> bytes:
        return self._fernet.encrypt(token.encode())

    def decrypt(self, encrypted: bytes) -> str:
        last_error: InvalidToken | None = None
        for decryptor in self._decryptors:
            try:
                return decryptor.decrypt(encrypted).decode()
            except InvalidToken as exc:
                last_error = exc
        if last_error is not None:
            raise last_error
        raise InvalidToken()


def get_or_create_key(key_file: Path | None = None) -> bytes:
    settings = get_settings()
    resolved_file = key_file or settings.encryption_key_file
    if settings.encryption_key is not None:
        resolved_key = _normalize_key_bytes(settings.encryption_key)
        _seed_key_file_if_missing(resolved_file, resolved_key)
        return resolved_key
    return _get_or_create_key(resolved_file)

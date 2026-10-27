"""Encryption at rest for provider OAuth tokens.

Provider access/refresh tokens are bearer credentials for a person's health data, so they are
stored Fernet-encrypted (AES-128-CBC + HMAC-SHA256) behind a version prefix. Values written before
encryption was introduced have no prefix and are read back as-is until the
``encrypt_provider_tokens`` migration rewrites them.
"""

from base64 import urlsafe_b64encode
from functools import lru_cache

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import Text
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator

from app.config import settings

PREFIX = "owenc1:"


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    if settings.token_encryption_key is not None and settings.token_encryption_key.get_secret_value():
        return Fernet(settings.token_encryption_key.get_secret_value().encode("utf-8"))
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"open-wearables provider tokens v1",
    ).derive(settings.secret_key.encode("utf-8"))
    return Fernet(urlsafe_b64encode(derived))


def is_encrypted(value: str | None) -> bool:
    return value is not None and value.startswith(PREFIX)


def encrypt_token(value: str | None) -> str | None:
    if value is None or is_encrypted(value):
        return value
    return PREFIX + _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_token(value: str | None) -> str | None:
    if not is_encrypted(value):
        return value  # None, or a legacy plaintext value not yet migrated
    assert value is not None
    return _fernet().decrypt(value[len(PREFIX) :].encode("ascii")).decode("utf-8")


def encrypt_bytes(data: bytes) -> bytes:
    return _fernet().encrypt(data)


def decrypt_bytes(data: bytes) -> bytes:
    return _fernet().decrypt(data)


class EncryptedText(TypeDecorator[str]):
    """A TEXT column that is encrypted on write and decrypted on read."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect: Dialect) -> str | None:
        return encrypt_token(value)

    def process_result_value(self, value: str | None, dialect: Dialect) -> str | None:
        return decrypt_token(value)

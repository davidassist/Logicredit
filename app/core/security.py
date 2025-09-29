"""Security helpers for the authentication service."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from pathlib import Path
from typing import Iterable

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken

from .config import Settings, get_settings


BANNED_PASSWORDS_PATH = Path("data/banned-passwords.txt")


class PasswordValidationError(ValueError):
    """Raised when a password does not comply with policy."""


class PasswordPolicy:
    """Strong password policy enforcement."""

    min_length: int = 10

    def __init__(self, banned_passwords: Iterable[str]):
        self._banned = {password.strip() for password in banned_passwords if password.strip()}

    def validate(self, password: str) -> None:
        if len(password) < self.min_length:
            raise PasswordValidationError("Password must be at least 10 characters long.")
        if password.lower() in self._banned:
            raise PasswordValidationError("Password is present in the banned password list.")


def load_banned_passwords(path: Path = BANNED_PASSWORDS_PATH) -> set[str]:
    if not path.exists():
        return set()
    with path.open("r", encoding="utf-8") as file:
        return {line.strip().lower() for line in file if line.strip()}


def _fernet_from_secret(settings: Settings) -> Fernet:
    digest = hashlib.sha256(settings.totp_encryption_key.encode("utf-8")).digest()
    key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


class SecurityManager:
    """Centralized security helper operations."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.hasher = PasswordHasher(
            time_cost=self.settings.argon2_time_cost,
            memory_cost=self.settings.argon2_memory_cost,
            parallelism=self.settings.argon2_parallelism,
        )
        self.password_policy = PasswordPolicy(load_banned_passwords())
        self._fernet = _fernet_from_secret(self.settings)

    def hash_password(self, password: str) -> str:
        self.password_policy.validate(password)
        return self.hasher.hash(password)

    def verify_password(self, password: str, hashed: str) -> bool:
        try:
            return self.hasher.verify(hashed, password)
        except VerifyMismatchError:
            return False

    def encrypt_secret(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt_secret(self, ciphertext: str) -> str:
        try:
            return self._fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("Invalid encrypted payload") from exc

    @staticmethod
    def constant_time_compare(val1: str, val2: str) -> bool:
        return hmac.compare_digest(val1.encode("utf-8"), val2.encode("utf-8"))

    @staticmethod
    def generate_session_id() -> str:
        return secrets.token_hex(32)

    @staticmethod
    def generate_email_token() -> str:
        return secrets.token_hex(16)

    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def generate_csrf_token() -> str:
        return secrets.token_urlsafe(32)

    @staticmethod
    def generate_totp_secret() -> str:
        return pyotp.random_base32()

    @staticmethod
    def verify_totp_code(secret: str, code: str) -> bool:
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)

    @staticmethod
    def exponential_backoff_delay(attempt: int, base: float = 0.5, cap: float = 5.0) -> float:
        delay = min(cap, base * (2 ** max(0, attempt - 1)))
        return delay

    @staticmethod
    def delay_for_failed_login(attempt: int) -> None:
        delay = SecurityManager.exponential_backoff_delay(attempt)
        if delay > 0:
            time.sleep(delay)


security_manager = SecurityManager()

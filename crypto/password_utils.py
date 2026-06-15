import hmac
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from config import PBKDF2_ITERATIONS
from crypto.base_utils import b64d, b64e


def derive_password_hash(password: str, salt_b64: str) -> str:
    salt = b64d(salt_b64)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return b64e(kdf.derive(password.encode("utf-8")))


def verify_password(password: str, salt_b64: str, expected_hash: str) -> bool:
    try:
        actual = derive_password_hash(password, salt_b64)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected_hash)


def create_password_entry(field: str, username: str, password: str) -> dict:
    salt = b64e(os.urandom(16))
    return {
        field: username,
        "salt": salt,
        "password_hash": derive_password_hash(password, salt),
        "pbkdf2_iterations": PBKDF2_ITERATIONS,
    }

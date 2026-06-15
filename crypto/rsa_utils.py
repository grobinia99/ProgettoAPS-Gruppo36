from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from crypto.base_utils import b64d, b64e, canonical_json


def rsa_keygen(bits: int = 2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def private_key_to_pem(private_key) -> bytes:
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def public_key_to_pem(public_key) -> str:
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def load_private_key(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None)


def load_public_key(pem: str):
    return serialization.load_pem_public_key(pem.encode("utf-8"))


def sign_bytes(private_key, payload: bytes) -> str:
    signature = private_key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return b64e(signature)


def verify_bytes_signature(public_key, payload: bytes, signature_b64: str) -> bool:
    try:
        public_key.verify(
            b64d(signature_b64),
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def sign_json(private_key, obj: Any) -> str:
    return sign_bytes(private_key, canonical_json(obj))


def verify_json_signature(public_key, obj: Any, signature: str) -> bool:
    return verify_bytes_signature(public_key, canonical_json(obj), signature)


def rsa_encrypt(public_key, plaintext: bytes) -> str:
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return b64e(ciphertext)


def rsa_decrypt(private_key, ciphertext_b64: str) -> bytes:
    return private_key.decrypt(
        b64d(ciphertext_b64),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

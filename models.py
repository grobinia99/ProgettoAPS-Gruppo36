from dataclasses import dataclass


@dataclass(frozen=True)
class Student:
    matricola: str
    salt: str
    password_hash: str


@dataclass(frozen=True)
class Token:
    pseudonym_id: str
    pseudonymous_public_key: str
    election_id: str
    issued_at: str
    protocol_version: str
    expires_at: str


@dataclass(frozen=True)
class SignedToken:
    token: Token
    signature: str


@dataclass(frozen=True)
class HybridCiphertext:
    encrypted_key: str
    encrypted_ballot: str


@dataclass(frozen=True)
class BallotMessage:
    signed_token: SignedToken
    election_id: str
    encrypted_key: str
    encrypted_ballot: str
    request_nonce: str
    protocol_version: str
    ballot_signature: str


@dataclass
class BallotRecord:
    sequence_number: int
    ballot_id: str
    election_id: str
    encrypted_key: str
    encrypted_ballot: str
    request_nonce_hash: str
    previous_hash: str
    registered_at: str
    record_hash: str


@dataclass(frozen=True)
class SignedReceipt:
    receipt: dict
    signature: str

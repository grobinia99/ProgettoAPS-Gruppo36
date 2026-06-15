import json
import secrets
import threading
from dataclasses import asdict
from typing import List, Optional

from config import (
    BULLETIN_FILE, CHECKPOINT_FILE, CLOSURE_FILE, ELECTION_ID,
    PROTOCOL_VERSION, VOTAZIONI_FINE,
)
from crypto.base_utils import canonical_json, now_dt, now_iso, parse_dt, sha256_hex
from crypto.merkle import merkle_proof, merkle_root
from crypto.rsa_utils import sign_json
from models import BallotRecord
from storage.json_utils import atomic_write_json


class BulletinBoard:
    def __init__(self, ae_private_key):
        self.ae_private_key = ae_private_key
        self.records: List[BallotRecord] = []
        self.closed = False
        self._lock = threading.Lock()
        self.export()

    @property
    def last_hash(self) -> str:
        return self.records[-1].record_hash if self.records else "GENESIS"

    @staticmethod
    def _record_payload(record: BallotRecord) -> dict:
        data = asdict(record)
        data.pop("record_hash")
        return data

    def append(
        self,
        encrypted_key: str,
        encrypted_ballot: str,
        request_nonce: str,
    ) -> BallotRecord:
        with self._lock:
            if self.closed:
                raise RuntimeError("Bulletin Board chiusa")

            payload = {
                "sequence_number": len(self.records) + 1,
                "ballot_id": secrets.token_hex(16),
                "election_id": ELECTION_ID,
                "encrypted_key": encrypted_key,
                "encrypted_ballot": encrypted_ballot,
                "request_nonce_hash": sha256_hex(request_nonce.encode("utf-8")),
                "previous_hash": self.last_hash,
                "registered_at": now_iso(),
            }
            record = BallotRecord(
                **payload,
                record_hash=sha256_hex(canonical_json(payload)),
            )
            self.records.append(record)
            self.export()
            self.publish_checkpoint("BALLOT_REGISTERED")
            return record

    def verify_chain(self) -> bool:
        previous = "GENESIS"
        for expected_sequence, record in enumerate(self.records, start=1):
            if record.sequence_number != expected_sequence:
                return False
            if record.previous_hash != previous:
                return False
            if sha256_hex(canonical_json(self._record_payload(record))) != record.record_hash:
                return False
            previous = record.record_hash
        return True

    def root(self) -> str:
        return merkle_root([record.record_hash for record in self.records])

    def find(self, ballot_id: str) -> Optional[BallotRecord]:
        return next(
            (record for record in self.records if record.ballot_id == ballot_id),
            None,
        )

    def proof_for_ballot(self, ballot_id: str) -> Optional[List[dict]]:
        record = self.find(ballot_id)
        if record is None:
            return None
        hashes = [item.record_hash for item in self.records]
        return merkle_proof(hashes, record.record_hash)

    def export(self) -> None:
        atomic_write_json(BULLETIN_FILE, {
            "election_id": ELECTION_ID,
            "protocol_version": PROTOCOL_VERSION,
            "generated_at": now_iso(),
            "closed": self.closed,
            "record_count": len(self.records),
            "hash_chain_valid": self.verify_chain(),
            "merkle_root": self.root(),
            "last_hash": self.last_hash,
            "records": [asdict(record) for record in self.records],
            "privacy_note": (
                "La bacheca pubblica non contiene matricola, pseudonimo o firma del token."
            ),
        })

    def publish_checkpoint(self, reason: str) -> dict:
        checkpoint = {
            "election_id": ELECTION_ID,
            "protocol_version": PROTOCOL_VERSION,
            "reason": reason,
            "created_at": now_iso(),
            "record_count": len(self.records),
            "last_hash": self.last_hash,
            "merkle_root": self.root(),
            "hash_chain_valid": self.verify_chain(),
        }
        document = {
            "checkpoint": checkpoint,
            "signature": sign_json(self.ae_private_key, checkpoint),
            "signature_algorithm": "RSA-PSS-SHA256",
        }
        atomic_write_json(CHECKPOINT_FILE, document)
        return document

    def close(self, force_demo: bool = False) -> dict:
        with self._lock:
            if self.closed:
                return json.loads(CLOSURE_FILE.read_text(encoding="utf-8"))

            if now_dt() < parse_dt(VOTAZIONI_FINE) and not force_demo:
                raise RuntimeError("La data di chiusura non è ancora stata raggiunta")

            self.closed = True
            closure = {
                "election_id": ELECTION_ID,
                "protocol_version": PROTOCOL_VERSION,
                "closed_at": now_iso(),
                "scheduled_close": VOTAZIONI_FINE,
                "forced_demo_close": force_demo,
                "record_count": len(self.records),
                "last_hash": self.last_hash,
                "merkle_root": self.root(),
                "hash_chain_valid": self.verify_chain(),
            }
            document = {
                "closure": closure,
                "signature": sign_json(self.ae_private_key, closure),
                "signature_algorithm": "RSA-PSS-SHA256",
            }
            atomic_write_json(CLOSURE_FILE, document)
            self.export()
            self.publish_checkpoint("ELECTION_CLOSED")
            return document

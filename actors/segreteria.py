import json
from typing import Dict, List

from config import ELECTION_ID, PROTOCOL_VERSION, ROSTER_FILE, STUDENTI_FILE
from crypto.base_utils import now_iso
from crypto.merkle import merkle_proof, merkle_root
from crypto.password_utils import verify_password
from crypto.rsa_utils import public_key_to_pem, rsa_keygen, sign_json
from models import Student
from services.credentials import create_demo_credentials_files
from storage.json_utils import atomic_write_json


class Segreteria:
    def __init__(self):
        self.private_key = rsa_keygen()
        self.public_key = self.private_key.public_key()
        self.students = self._load_students()
        self.matricole = sorted(self.students)
        self.root = merkle_root(self.matricole)
        self.publish_signed_roster()

    def _load_students(self) -> Dict[str, Student]:
        create_demo_credentials_files()
        raw = json.loads(STUDENTI_FILE.read_text(encoding="utf-8"))
        result: Dict[str, Student] = {}
        for entry in raw["studenti"]:
            result[entry["matricola"]] = Student(
                matricola=entry["matricola"],
                salt=entry["salt"],
                password_hash=entry["password_hash"],
            )
        return result

    def publish_signed_roster(self) -> None:
        roster = {
            "election_id": ELECTION_ID,
            "generated_at": now_iso(),
            "protocol_version": PROTOCOL_VERSION,
            "matricole": self.matricole,
            "merkle_root": self.root,
        }
        atomic_write_json(ROSTER_FILE, {
            "roster": roster,
            "signature": sign_json(self.private_key, roster),
            "signature_algorithm": "RSA-PSS-SHA256",
            "segreteria_public_key": public_key_to_pem(self.public_key),
        })

    def authenticate(self, matricola: str, password: str) -> bool:
        student = self.students.get(matricola)
        return bool(
            student
            and verify_password(password, student.salt, student.password_hash)
        )

    def proof_for(self, matricola: str) -> List[dict]:
        return merkle_proof(self.matricole, matricola)

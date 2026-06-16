import hmac
import json
from typing import Dict, List
from models import Student
from services.credentials import create_demo_credentials_files
from storage.json_utils import atomic_write_json
from config import (
    ELECTION_ID,
    PROTOCOL_VERSION,
    ROSTER_FILE,
    STUDENTI_FILE,
)
from crypto.base_utils import now_iso
from crypto.merkle import (
    merkle_proof,
    merkle_root,
    verify_merkle_proof,
)
from crypto.password_utils import verify_password
from crypto.rsa_utils import (
    public_key_to_pem,
    rsa_keygen,
    sign_json,
    verify_json_signature,
)

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

    def verify_student_inclusion(
            self,
            matricola: str,
    ) -> dict:
        """
        Verifica pubblicamente che una matricola sia inclusa
        nella lista elettorale firmata.

        Il controllo comprende:
        - chiave pubblica ufficiale della Segreteria;
        - firma RSA-PSS della lista;
        - election_id e versione del protocollo;
        - ricalcolo della Merkle root;
        - Merkle proof individuale.
        """

        result = {
            "matricola": matricola,
            "roster_file_exists": False,
            "public_key_valid": False,
            "signature_valid": False,
            "election_id_valid": False,
            "protocol_version_valid": False,
            "merkle_root_valid": False,
            "included": False,
            "merkle_proof_valid": False,
            "merkle_proof": [],
            "overall_valid": False,
            "error": None,
        }

        try:
            if not ROSTER_FILE.exists():
                result["error"] = (
                    "File della lista elettorale non trovato"
                )
                return result

            result["roster_file_exists"] = True

            document = json.loads(
                ROSTER_FILE.read_text(
                    encoding="utf-8"
                )
            )

            roster = document["roster"]
            signature = document["signature"]
            published_public_key = document[
                "segreteria_public_key"
            ]

            official_public_key = public_key_to_pem(
                self.public_key
            )

            # La chiave contenuta nel documento deve coincidere
            # con la chiave pubblica ufficiale della Segreteria.
            result["public_key_valid"] = (
                hmac.compare_digest(
                    published_public_key,
                    official_public_key,
                )
            )

            # Verifica della firma sulla struttura roster.
            result["signature_valid"] = (
                verify_json_signature(
                    self.public_key,
                    roster,
                    signature,
                )
            )

            result["election_id_valid"] = (
                    roster.get("election_id")
                    == ELECTION_ID
            )

            result["protocol_version_valid"] = (
                    roster.get("protocol_version")
                    == PROTOCOL_VERSION
            )

            matricole = roster.get("matricole")
            published_root = roster.get("merkle_root")

            if not isinstance(matricole, list):
                result["error"] = (
                    "Formato della lista elettorale "
                    "non valido"
                )
                return result

            if not isinstance(published_root, str):
                result["error"] = (
                    "Merkle root mancante o non valida"
                )
                return result

            recalculated_root = merkle_root(
                matricole
            )

            result["merkle_root_valid"] = (
                hmac.compare_digest(
                    recalculated_root,
                    published_root,
                )
            )

            result["included"] = (
                    matricola in matricole
            )

            if result["included"]:
                proof = merkle_proof(
                    matricole,
                    matricola,
                )

                result["merkle_proof"] = proof

                result["merkle_proof_valid"] = (
                    verify_merkle_proof(
                        matricola,
                        proof,
                        published_root,
                    )
                )

            result["overall_valid"] = all(
                [
                    result["roster_file_exists"],
                    result["public_key_valid"],
                    result["signature_valid"],
                    result["election_id_valid"],
                    result["protocol_version_valid"],
                    result["merkle_root_valid"],
                    result["included"],
                    result["merkle_proof_valid"],
                ]
            )

            return result

        except (
                KeyError,
                ValueError,
                TypeError,
                json.JSONDecodeError,
        ) as exc:
            result["error"] = str(exc)
            return result
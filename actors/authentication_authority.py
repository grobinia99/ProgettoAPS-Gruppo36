import json
import secrets
import threading
from dataclasses import asdict
from typing import Dict, Optional

from actors.segreteria import Segreteria
from config import ELECTION_ID, PROTOCOL_VERSION, ROSTER_FILE, SA_REGISTRY_FILE, VOTAZIONI_FINE
from crypto.base_utils import now_iso, sha256_hex
from crypto.merkle import verify_merkle_proof
from crypto.rsa_utils import load_public_key, rsa_keygen, sign_json, verify_json_signature
from models import SignedToken, Token
from storage.json_utils import atomic_write_json


class AuthenticationAuthority:
    def __init__(self, segreteria: Segreteria):
        self.segreteria = segreteria
        self.private_key = rsa_keygen()
        self.public_key = self.private_key.public_key()
        self._lock = threading.Lock()
        self.registry: Dict[str, dict] = {}
        self._load_and_verify_roster()
        self._persist_registry()

    def _load_and_verify_roster(self) -> None:
        document = json.loads(ROSTER_FILE.read_text(encoding="utf-8"))
        roster = document["roster"]
        public_key = load_public_key(document["segreteria_public_key"])
        if not verify_json_signature(public_key, roster, document["signature"]):
            raise ValueError("Firma della lista elettorale non valida")
        if roster["election_id"] != ELECTION_ID:
            raise ValueError("Lista riferita a un'altra elezione")
        self.official_root = roster["merkle_root"]

    @staticmethod
    def _registry_key(matricola: str, election_id: str) -> str:
        return f"{matricola}|{election_id}"

    def _persist_registry(self) -> None:
        atomic_write_json(SA_REGISTRY_FILE, {
            "election_id": ELECTION_ID,
            "generated_at": now_iso(),
            "authorizations": list(self.registry.values()),
            "nota_privacy": (
                "Il registro contiene la mappatura matricola-pseudonimo e deve "
                "restare riservato al SA."
            ),
        })

    def login_and_issue_token(
        self,
        matricola: str,
        password: str,
        election_id: str,
        pseudonymous_public_key: str,
    ) -> Optional[SignedToken]:
        if election_id != ELECTION_ID:
            print("Election ID non valido")
            return None
        try:
            load_public_key(pseudonymous_public_key)
        except (ValueError, TypeError):
            print("Chiave pubblica pseudonima non valida")
            return None

        if not self.segreteria.authenticate(matricola, password):
            print("Credenziali non valide")
            return None

        proof = self.segreteria.proof_for(matricola)
        if not verify_merkle_proof(matricola, proof, self.official_root):
            print("Merkle proof non valida")
            return None

        key = self._registry_key(matricola, election_id)
        with self._lock:
            if key in self.registry:
                print("Autorizzazione già rilasciata per questa elezione")
                return None

            token = Token(
                pseudonym_id="PSEUDO-" + secrets.token_hex(16),
                pseudonymous_public_key=pseudonymous_public_key,
                election_id=election_id,
                issued_at=now_iso(),
                protocol_version=PROTOCOL_VERSION,
                expires_at=VOTAZIONI_FINE,
            )
            signed = SignedToken(
                token=token,
                signature=sign_json(self.private_key, asdict(token)),
            )
            self.registry[key] = {
                "matricola": matricola,
                "election_id": election_id,
                "pseudonym_id": token.pseudonym_id,
                "pseudonymous_public_key_fingerprint": sha256_hex(
                    pseudonymous_public_key.encode("utf-8")
                ),
                "issued_at": token.issued_at,
                "status": "ISSUED",
            }
            self._persist_registry()
            return signed

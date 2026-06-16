import json
import hmac
import threading
from dataclasses import asdict
from pathlib import Path
from typing import List, Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken

from components.bulletin_board import BulletinBoard
from config import (
    BULLETIN_FILE, CLOSURE_FILE, DATA_DIR, ELECTION_ID, MAX_FIELD_LENGTH, N_TRUSTEES,
    PROTOCOL_VERSION, PUBLIC_PARAMETERS_FILE, RESULT_FILE, THRESHOLD,
    TRUSTEE_SHARES_FILE, VOTAZIONI_FINE, VOTAZIONI_INIZIO,
)
from crypto.base_utils import b64d, canonical_json, now_dt, now_iso, parse_dt, sha256_hex
from crypto.merkle import verify_merkle_proof
from crypto.rsa_utils import (
    load_private_key, load_public_key, private_key_to_pem, public_key_to_pem, rsa_decrypt, rsa_keygen, sign_json, verify_json_signature,
)
from crypto.shamir import shamir_reconstruct, shamir_split
from models import (
    BallotMessage,
    BallotRecord,
    SignedReceipt,
    SignedToken,
)
from storage.json_utils import atomic_write_json


class ElectoralAuthority:
    def __init__(self, sa_public_key):
        self.sa_public_key = sa_public_key

        # Chiave utilizzata esclusivamente per firme RSA-PSS:
        # ricevute, checkpoint, chiusura e risultato.
        self.signing_private_key = rsa_keygen()
        self.signing_public_key = (
            self.signing_private_key.public_key()
        )

        # Chiave utilizzata esclusivamente per la cifratura
        # e la decifrazione delle schede tramite RSA-OAEP.
        decryption_private_key = rsa_keygen()
        self.decryption_public_key = (
            decryption_private_key.public_key()
        )

        # La chiave privata di decifrazione viene serializzata
        # e suddivisa tra i trustee.
        decryption_private_pem = private_key_to_pem(
            decryption_private_key
        )

        self.decryption_private_key_length = len(
            decryption_private_pem
        )

        self.trustee_shares = shamir_split(
            decryption_private_pem,
            N_TRUSTEES,
            THRESHOLD,
        )

        # La chiave privata completa non viene conservata
        # come attributo dell'Autorità Elettorale.
        del decryption_private_key
        del decryption_private_pem

        self.used_pseudonyms: set[str] = set()
        self.used_request_nonces: set[str] = set()
        self._accept_lock = threading.Lock()

        # La Bulletin Board riceve soltanto la chiave di firma.
        self.bulletin = BulletinBoard(
            self.signing_private_key
        )

        self._export_trustee_shares()
        self._publish_parameters()

    def _publish_parameters(self) -> None:
        atomic_write_json(
            PUBLIC_PARAMETERS_FILE,
            {
                "election_id": ELECTION_ID,
                "protocol_version": PROTOCOL_VERSION,
                "votazioni_inizio": VOTAZIONI_INIZIO,
                "votazioni_fine": VOTAZIONI_FINE,
                "opzioni_ammesse": ["SI", "NO"],

                # Chiave pubblica usata per verificare le firme AE.
                "ae_signing_public_key": public_key_to_pem(
                    self.signing_public_key
                ),

                # Chiave pubblica usata per cifrare
                # le chiavi simmetriche delle schede.
                "ae_decryption_public_key": public_key_to_pem(
                    self.decryption_public_key
                ),

                "sa_public_key": public_key_to_pem(
                    self.sa_public_key
                ),
                "trustees": N_TRUSTEES,
                "threshold": THRESHOLD,
                "hybrid_encryption": (
                    "Fernet + RSA-OAEP-SHA256"
                ),
                "signatures": "RSA-PSS-SHA256",
                "pseudonymous_ballot_signature": (
                    "RSA-PSS-SHA256"
                ),
                "key_separation": (
                    "Chiave AE distinta per firma e decifrazione"
                ),
                "bulletin_integrity": (
                    "SHA-256 hash-chain + Merkle root"
                ),
            },
        )

    def _export_trustee_shares(self) -> None:
        shares = []
        for index, (x, values) in enumerate(self.trustee_shares, start=1):
            share_payload = {
                "trustee_id": f"trustee{index}",
                "x": x,
                "values": values,
            }
            shares.append({
                **share_payload,
                "share_commitment": sha256_hex(canonical_json(share_payload)),
            })

        atomic_write_json(TRUSTEE_SHARES_FILE, {
            "election_id": ELECTION_ID,
            "threshold": THRESHOLD,
            "total_trustees": N_TRUSTEES,
            "secret_length": self.decryption_private_key_length,
            "shares": shares,
            "nota": (
                "Solo per demo locale: in un sistema reale ogni trustee custodisce "
                "esclusivamente la propria quota."
            ),
        })

    def election_is_open(self) -> bool:
        current = now_dt()
        return (
            parse_dt(VOTAZIONI_INIZIO) <= current < parse_dt(VOTAZIONI_FINE)
            and not self.bulletin.closed
        )

    @staticmethod
    def _ballot_signature_payload(
        signed_token: SignedToken,
        election_id: str,
        encrypted_key: str,
        encrypted_ballot: str,
        request_nonce: str,
        protocol_version: str,
    ) -> dict:
        return {
            "pseudonym_id": signed_token.token.pseudonym_id,
            "election_id": election_id,
            "encrypted_key": encrypted_key,
            "encrypted_ballot": encrypted_ballot,
            "request_nonce": request_nonce,
            "protocol_version": protocol_version,
        }

    def _validate_message_structure(self, message: BallotMessage) -> bool:
        fields = [
            message.election_id,
            message.encrypted_key,
            message.encrypted_ballot,
            message.request_nonce,
            message.protocol_version,
            message.ballot_signature,
            message.signed_token.signature,
            message.signed_token.token.pseudonym_id,
            message.signed_token.token.pseudonymous_public_key,
        ]
        if not all(isinstance(value, str) and value for value in fields):
            return False
        if any(len(value) > MAX_FIELD_LENGTH for value in fields):
            return False
        try:
            b64d(message.encrypted_key)
            b64d(message.encrypted_ballot)
            b64d(message.signed_token.signature)
            b64d(message.ballot_signature)
            load_public_key(
                message.signed_token.token.pseudonymous_public_key
            )
        except (ValueError, TypeError):
            return False
        return True

    def receive_ballot(self, message: BallotMessage) -> Optional[SignedReceipt]:
        if not self.election_is_open():
            print("Votazione non aperta o già chiusa")
            return None
        if not self._validate_message_structure(message):
            print("Struttura del messaggio non valida")
            return None
        if message.protocol_version != PROTOCOL_VERSION:
            print("Versione del protocollo non valida")
            return None
        if message.election_id != ELECTION_ID:
            print("Election ID del messaggio non valido")
            return None

        token = message.signed_token.token
        if token.election_id != ELECTION_ID:
            print("Token riferito a un'altra elezione")
            return None
        if token.protocol_version != PROTOCOL_VERSION:
            print("Versione del token non valida")
            return None
        if now_dt() > parse_dt(token.expires_at):
            print("Token scaduto")
            return None
        if not verify_json_signature(
            self.sa_public_key,
            asdict(token),
            message.signed_token.signature,
        ):
            print("Firma del token non valida")
            return None

        try:
            pseudonymous_public_key = load_public_key(
                token.pseudonymous_public_key
            )
        except (ValueError, TypeError):
            print("Chiave pubblica pseudonima non valida")
            return None

        signature_payload = self._ballot_signature_payload(
            signed_token=message.signed_token,
            election_id=message.election_id,
            encrypted_key=message.encrypted_key,
            encrypted_ballot=message.encrypted_ballot,
            request_nonce=message.request_nonce,
            protocol_version=message.protocol_version,
        )
        if not verify_json_signature(
            pseudonymous_public_key,
            signature_payload,
            message.ballot_signature,
        ):
            print("Firma pseudonima della scheda non valida")
            return None

        # Lock: nel prototipo rende atomici controllo anti-replay e registrazione.
        with self._accept_lock:
            if token.pseudonym_id in self.used_pseudonyms:
                print("Pseudonimo già utilizzato: double voting bloccato")
                return None
            if message.request_nonce in self.used_request_nonces:
                print("Request nonce già utilizzato: replay bloccato")
                return None

            self.used_pseudonyms.add(token.pseudonym_id)
            self.used_request_nonces.add(message.request_nonce)
            try:
                record = self.bulletin.append(
                    encrypted_key=message.encrypted_key,
                    encrypted_ballot=message.encrypted_ballot,
                    request_nonce=message.request_nonce,
                )
            except Exception:
                self.used_pseudonyms.discard(token.pseudonym_id)
                self.used_request_nonces.discard(message.request_nonce)
                raise

        proof = self.bulletin.proof_for_ballot(record.ballot_id) or []
        receipt_data = {
            "election_id": ELECTION_ID,
            "protocol_version": PROTOCOL_VERSION,
            "ballot_id": record.ballot_id,
            "record_hash": record.record_hash,
            "bulletin_merkle_root": self.bulletin.root(),
            "merkle_proof": proof,
            "issued_at": now_iso(),
        }
        signed_receipt = SignedReceipt(
            receipt=receipt_data,
            signature=sign_json(
                self.signing_private_key,
                receipt_data,
            ),
        )
        atomic_write_json(
            DATA_DIR / f"ricevuta_{record.ballot_id}.json",
            asdict(signed_receipt),
        )
        return signed_receipt

    def close_election(self, force_demo: bool = False) -> dict:
        return self.bulletin.close(force_demo=force_demo)

    def _verify_share_commitment(
        self,
        trustee_id: str,
        share: Tuple[int, List[int]],
    ) -> bool:
        document = json.loads(TRUSTEE_SHARES_FILE.read_text(encoding="utf-8"))
        expected = next(
            (
                item for item in document["shares"]
                if item["trustee_id"] == trustee_id
            ),
            None,
        )
        if expected is None:
            return False
        payload = {
            "trustee_id": trustee_id,
            "x": share[0],
            "values": share[1],
        }
        return hmac.compare_digest(
            sha256_hex(canonical_json(payload)),
            expected["share_commitment"],
        )

    def _decrypt_ballot(self, record: BallotRecord, private_key) -> dict:
        session_key = rsa_decrypt(private_key, record.encrypted_key)
        encrypted_ballot = b64d(record.encrypted_ballot)
        plaintext = Fernet(session_key).decrypt(encrypted_ballot)
        return json.loads(plaintext.decode("utf-8"))

    def scrutinio(
            self,
            authenticated_trustees: List[str],
    ) -> Optional[dict]:

        if (
                not self.bulletin.closed
                or not CLOSURE_FILE.exists()
        ):
            print(
                "Le urne devono essere chiuse "
                "prima dello scrutinio"
            )
            return None

        distinct = list(
            dict.fromkeys(authenticated_trustees)
        )

        if len(distinct) < THRESHOLD:
            print(
                f"Servono almeno {THRESHOLD} "
                "trustee distinti"
            )
            return None

        shares: List[Tuple[int, List[int]]] = []

        for username in distinct[:THRESHOLD]:
            try:
                index = (
                        int(username.replace("trustee", ""))
                        - 1
                )
            except ValueError:
                print(
                    f"Identificativo trustee non valido: "
                    f"{username}"
                )
                return None

            if not 0 <= index < len(
                    self.trustee_shares
            ):
                print(
                    f"Trustee non valido: {username}"
                )
                return None

            share = self.trustee_shares[index]

            if not self._verify_share_commitment(
                    username,
                    share,
            ):
                print(
                    "Commitment della quota "
                    f"non valido: {username}"
                )
                return None

            shares.append(share)

        try:
            reconstructed_pem = shamir_reconstruct(
                shares,
                self.decryption_private_key_length,
                THRESHOLD,
            )

            reconstructed_key = load_private_key(
                reconstructed_pem
            )

        except (ValueError, TypeError) as exc:
            print(
                "Ricostruzione della chiave fallita:",
                exc,
            )
            return None

        # Verifica che la chiave ricostruita corrisponda
        # alla chiave pubblica ufficiale di decifrazione.
        reconstructed_public = public_key_to_pem(
            reconstructed_key.public_key()
        )

        official_public = public_key_to_pem(
            self.decryption_public_key
        )

        if reconstructed_public != official_public:
            print(
                "La chiave ricostruita non corrisponde "
                "alla chiave pubblica di decifrazione AE"
            )
            return None

        si = 0
        no = 0
        invalidi = 0

        decrypted_ballots: List[dict] = []

        for record in self.bulletin.records:
            try:
                payload = self._decrypt_ballot(
                    record,
                    reconstructed_key,
                )

                if (
                        payload.get("election_id")
                        != ELECTION_ID
                ):
                    raise ValueError(
                        "Election ID errato"
                    )

                if (
                        payload.get("protocol_version")
                        != PROTOCOL_VERSION
                ):
                    raise ValueError(
                        "Versione del protocollo errata"
                    )

                vote = payload.get("vote")

                if vote not in {"SI", "NO"}:
                    raise ValueError(
                        "Preferenza non ammessa"
                    )

                if vote == "SI":
                    si += 1
                else:
                    no += 1

                decrypted_ballots.append(
                    {
                        "ballot_id": record.ballot_id,
                        "classification": "VALID",
                        "vote": vote,
                        "ballot_nonce": payload.get(
                            "ballot_nonce"
                        ),
                    }
                )

            except (
                    ValueError,
                    InvalidToken,
                    json.JSONDecodeError,
                    TypeError,
            ):
                invalidi += 1

                decrypted_ballots.append(
                    {
                        "ballot_id": record.ballot_id,
                        "classification": "INVALID",
                    }
                )

        if si > no:
            winner = "SI"
        elif no > si:
            winner = "NO"
        else:
            winner = "PAREGGIO"

        closure_document = json.loads(
            CLOSURE_FILE.read_text(
                encoding="utf-8"
            )
        )

        result_data = {
            "election_id": ELECTION_ID,
            "protocol_version": PROTOCOL_VERSION,
            "scrutinio_at": now_iso(),
            "totale_registrati": len(
                self.bulletin.records
            ),
            "totale_validi": si + no,
            "si": si,
            "no": no,
            "invalidi": invalidi,
            "vincitore": winner,
            "hash_chain_valid": (
                self.bulletin.verify_chain()
            ),
            "bulletin_last_hash": (
                self.bulletin.last_hash
            ),
            "bulletin_merkle_root": (
                self.bulletin.root()
            ),
            "closure_hash": sha256_hex(
                canonical_json(
                    closure_document["closure"]
                )
            ),
            "trustee_threshold": THRESHOLD,
            "trustee_used": len(shares),
            "trustee_ids": distinct[:THRESHOLD],
            "decrypted_ballots": decrypted_ballots,
        }

        # Il risultato viene firmato con la chiave
        # di firma dell'AE, non con quella ricostruita.
        document = {
            "result": result_data,
            "signature": sign_json(
                self.signing_private_key,
                result_data,
            ),
            "signature_algorithm": "RSA-PSS-SHA256",
            "ae_signing_public_key": public_key_to_pem(
                self.signing_public_key
            ),
        }

        atomic_write_json(
            RESULT_FILE,
            document,
        )

        # Elimina i riferimenti alla chiave ricostruita.
        # Non costituisce una cancellazione certificata
        # dei byte dalla memoria.
        del reconstructed_key
        del reconstructed_pem

        return document

    def verify_receipt(
            self,
            receipt_file: Path,
    ) -> bool:

        try:
            document = json.loads(
                receipt_file.read_text(
                    encoding="utf-8"
                )
            )

            receipt = document["receipt"]

            if not verify_json_signature(
                    self.signing_public_key,
                    receipt,
                    document["signature"],
            ):
                return False

            ballot_id = receipt["ballot_id"]

            record = self.bulletin.find(
                ballot_id
            )

            if record is None:
                return False

            if (
                    record.record_hash
                    != receipt["record_hash"]
            ):
                return False

            if not self.bulletin.verify_chain():
                return False

            if not verify_merkle_proof(
                    record.record_hash,
                    receipt["merkle_proof"],
                    receipt["bulletin_merkle_root"],
            ):
                return False

            return True

        except (
                KeyError,
                ValueError,
                TypeError,
                json.JSONDecodeError,
        ):
            return False
    def universal_verify(self) -> bool:
        required = [RESULT_FILE, BULLETIN_FILE, CLOSURE_FILE]
        if not all(path.exists() for path in required):
            print("Risultato, bacheca o chiusura mancanti")
            return False

        result_document = json.loads(RESULT_FILE.read_text(encoding="utf-8"))
        result = result_document["result"]
        public_key = load_public_key(
            result_document["ae_signing_public_key"]
        )
        result_signature_ok = verify_json_signature(
            public_key,
            result,
            result_document["signature"],
        )

        closure_document = json.loads(CLOSURE_FILE.read_text(encoding="utf-8"))
        closure = closure_document["closure"]
        closure_signature_ok = verify_json_signature(
            public_key,
            closure,
            closure_document["signature"],
        )

        bulletin_document = json.loads(BULLETIN_FILE.read_text(encoding="utf-8"))
        records = [BallotRecord(**item) for item in bulletin_document["records"]]
        temp_board = BulletinBoard.__new__(BulletinBoard)
        temp_board.signing_private_key = None
        temp_board.records = records
        temp_board.closed = bulletin_document["closed"]
        temp_board._lock = threading.Lock()

        chain_ok = temp_board.verify_chain()
        root_ok = (
            temp_board.root() == result["bulletin_merkle_root"]
            == closure["merkle_root"]
        )
        last_hash_ok = (
            temp_board.last_hash == result["bulletin_last_hash"]
            == closure["last_hash"]
        )
        count_ok = (
            len(records) == result["totale_registrati"]
            == closure["record_count"]
        )
        arithmetic_ok = (
            result["totale_validi"] == result["si"] + result["no"]
            and result["totale_registrati"]
            == result["totale_validi"] + result["invalidi"]
        )
        expected_winner = (
            "SI" if result["si"] > result["no"]
            else "NO" if result["no"] > result["si"]
            else "PAREGGIO"
        )
        winner_ok = result["vincitore"] == expected_winner
        threshold_ok = (
            result["trustee_used"] >= result["trustee_threshold"] == THRESHOLD
            and len(set(result["trustee_ids"])) == result["trustee_used"]
        )
        closure_hash_ok = result["closure_hash"] == sha256_hex(
            canonical_json(closure)
        )
        bulletin_metadata_ok = (
            bulletin_document["hash_chain_valid"] is True
            and bulletin_document["record_count"] == len(records)
            and bulletin_document["merkle_root"] == temp_board.root()
            and bulletin_document["last_hash"] == temp_board.last_hash
            and bulletin_document["closed"] is True
        )

        checks = {
            "firma risultato": result_signature_ok,
            "firma chiusura": closure_signature_ok,
            "hash-chain": chain_ok,
            "Merkle root": root_ok,
            "hash finale": last_hash_ok,
            "numero record": count_ok,
            "coerenza aritmetica": arithmetic_ok,
            "vincitore": winner_ok,
            "soglia trustee dichiarata": threshold_ok,
            "binding con chiusura": closure_hash_ok,
            "metadati bacheca": bulletin_metadata_ok,
        }
        print("\n=== VERIFICA UNIVERSALE ===")
        for label, value in checks.items():
            print(f"{label}: {value}")
        print(
            "Nota: la soglia trustee è verificata come dichiarazione firmata; "
            "non è una prova zero-knowledge dell'uso delle quote."
        )
        return all(checks.values())

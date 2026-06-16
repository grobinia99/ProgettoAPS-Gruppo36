import secrets

from cryptography.fernet import Fernet

from config import ELECTION_ID, PROTOCOL_VERSION
from crypto.base_utils import (
    b64e,
    canonical_json,
    now_iso,
)
from crypto.rsa_utils import (
    rsa_encrypt,
    sign_json,
)
from models import (
    BallotMessage,
    HybridCiphertext,
    SignedToken,
)


class VoterClient:
    """
    Componente che rappresenta il dispositivo
    dell'elettore.

    La preferenza viene costruita, cifrata e firmata
    localmente prima di essere inviata all'AE.
    """

    def __init__(
        self,
        ae_decryption_public_key,
        pseudonymous_private_key,
    ):
        self.ae_decryption_public_key = (
            ae_decryption_public_key
        )
        self.pseudonymous_private_key = (
            pseudonymous_private_key
        )

    def encrypt_vote(
        self,
        vote: str,
    ) -> HybridCiphertext:
        """
        Costruisce la scheda e la cifra localmente.

        La scheda è cifrata con Fernet.
        La chiave Fernet è cifrata con la chiave
        pubblica RSA-OAEP dell'AE.
        """

        if vote not in {"SI", "NO"}:
            raise ValueError("Voto non valido")

        ballot_payload = {
            "election_id": ELECTION_ID,
            "vote": vote,
            "ballot_nonce": secrets.token_hex(16),
            "created_at": now_iso(),
            "protocol_version": PROTOCOL_VERSION,
        }

        session_key = Fernet.generate_key()

        encrypted_ballot = Fernet(
            session_key
        ).encrypt(
            canonical_json(ballot_payload)
        )

        encrypted_key = rsa_encrypt(
            self.ae_decryption_public_key,
            session_key,
        )

        return HybridCiphertext(
            encrypted_key=encrypted_key,
            encrypted_ballot=b64e(
                encrypted_ballot
            ),
        )

    @staticmethod
    def _ballot_signature_payload(
        signed_token: SignedToken,
        encrypted_key: str,
        encrypted_ballot: str,
        request_nonce: str,
    ) -> dict:
        """
        Costruisce esattamente il payload
        protetto dalla firma pseudonima.
        """

        return {
            "pseudonym_id": (
                signed_token.token.pseudonym_id
            ),
            "election_id": ELECTION_ID,
            "encrypted_key": encrypted_key,
            "encrypted_ballot": encrypted_ballot,
            "request_nonce": request_nonce,
            "protocol_version": PROTOCOL_VERSION,
        }

    def build_ballot_message(
        self,
        signed_token: SignedToken,
        ciphertext: HybridCiphertext,
    ) -> BallotMessage:
        """
        Costruisce il messaggio inviato all'AE
        e lo firma con la chiave privata pseudonima.
        """

        request_nonce = secrets.token_hex(16)

        signature_payload = (
            self._ballot_signature_payload(
                signed_token=signed_token,
                encrypted_key=(
                    ciphertext.encrypted_key
                ),
                encrypted_ballot=(
                    ciphertext.encrypted_ballot
                ),
                request_nonce=request_nonce,
            )
        )

        ballot_signature = sign_json(
            self.pseudonymous_private_key,
            signature_payload,
        )

        return BallotMessage(
            signed_token=signed_token,
            election_id=ELECTION_ID,
            encrypted_key=(
                ciphertext.encrypted_key
            ),
            encrypted_ballot=(
                ciphertext.encrypted_ballot
            ),
            request_nonce=request_nonce,
            protocol_version=PROTOCOL_VERSION,
            ballot_signature=ballot_signature,
        )
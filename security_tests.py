from copy import deepcopy
from dataclasses import asdict, replace
from typing import Callable, Dict, Tuple

from clients.voter_client import VoterClient
from config import (
    ELECTION_ID,
    N_TRUSTEES,
    PROTOCOL_VERSION,
    THRESHOLD,
    TRUSTEE_SHARES_FILE,
)
from crypto.base_utils import (
    b64d,
    b64e,
    canonical_json,
    sha256_hex,
)
from crypto.rsa_utils import (
    private_key_to_pem,
    public_key_to_pem,
    rsa_keygen,
    sign_json,
)
from crypto.shamir import shamir_split
from models import BallotMessage
from storage.json_utils import atomic_write_json


SystemFactory = Callable[
    [bool],
    Tuple[object, object, object],
]


def _create_token(
    sa,
    matricola: str,
    password: str,
):
    """
    Genera una coppia pseudonima e richiede un token.

    Restituisce:
    - token firmato;
    - chiave privata pseudonima.
    """

    pseudonymous_private_key = rsa_keygen()

    pseudonymous_public_key = public_key_to_pem(
        pseudonymous_private_key.public_key()
    )

    token = sa.login_and_issue_token(
        matricola,
        password,
        ELECTION_ID,
        pseudonymous_public_key,
    )

    return token, pseudonymous_private_key


def _create_valid_message(
    sa,
    ae,
    matricola: str,
    password: str,
    vote: str = "SI",
):
    """
    Crea un token valido e un messaggio di voto
    cifrato e firmato dal VoterClient.
    """

    token, pseudonymous_private_key = _create_token(
        sa,
        matricola,
        password,
    )

    if token is None:
        return None, None, None

    voter_client = VoterClient(
        ae.decryption_public_key,
        pseudonymous_private_key,
    )

    ciphertext = voter_client.encrypt_vote(
        vote
    )

    message = voter_client.build_ballot_message(
        token,
        ciphertext,
    )

    return (
        message,
        token,
        pseudonymous_private_key,
    )


def _alter_base64_value(value: str) -> str:
    """
    Modifica un valore codificato Base64 mantenendo
    una codifica formalmente valida.
    """

    raw = bytearray(
        b64d(value)
    )

    if not raw:
        raise ValueError(
            "Impossibile alterare un valore vuoto"
        )

    raw[0] ^= 1

    return b64e(
        bytes(raw)
    )


def test_wrong_password(
    create_system: SystemFactory,
) -> bool:
    print("\n[TEST] Password errata")

    _, sa, _ = create_system(
        reset=True
    )

    token, _ = _create_token(
        sa,
        "IE22700271",
        "password_sbagliata",
    )

    passed = token is None

    print(
        "Esito:",
        "SUPERATO" if passed else "FALLITO",
    )

    return passed


def test_multiple_token(
    create_system: SystemFactory,
) -> bool:
    print(
        "\n[TEST] Rilascio multiplo del token"
    )

    _, sa, _ = create_system(
        reset=True
    )

    first_token, _ = _create_token(
        sa,
        "IE22700271",
        "password123",
    )

    second_token, _ = _create_token(
        sa,
        "IE22700271",
        "password123",
    )

    passed = (
        first_token is not None
        and second_token is None
    )

    print(
        "Primo token emesso:",
        first_token is not None,
    )
    print(
        "Secondo token rifiutato:",
        second_token is None,
    )
    print(
        "Esito:",
        "SUPERATO" if passed else "FALLITO",
    )

    return passed


def test_forged_token(
    create_system: SystemFactory,
) -> bool:
    print("\n[TEST] Token contraffatto")

    _, sa, ae = create_system(
        reset=True
    )

    token, pseudonymous_private_key = (
        _create_token(
            sa,
            "IE22700271",
            "password123",
        )
    )

    if token is None:
        print("Esito: FALLITO")
        return False

    # Modifica del contenuto del token senza
    # ricalcolare la firma del SA.
    forged_token_data = replace(
        token.token,
        pseudonym_id=(
            "PSEUDO-CONTRAFFATTO"
        ),
    )

    forged_signed_token = replace(
        token,
        token=forged_token_data,
    )

    voter_client = VoterClient(
        ae.decryption_public_key,
        pseudonymous_private_key,
    )

    ciphertext = voter_client.encrypt_vote(
        "SI"
    )

    message = voter_client.build_ballot_message(
        forged_signed_token,
        ciphertext,
    )

    receipt = ae.receive_ballot(
        message
    )

    passed = receipt is None

    print(
        "Token contraffatto rifiutato:",
        passed,
    )
    print(
        "Esito:",
        "SUPERATO" if passed else "FALLITO",
    )

    return passed


def test_altered_pseudonymous_signature(
    create_system: SystemFactory,
) -> bool:
    print(
        "\n[TEST] Firma pseudonima alterata"
    )

    _, sa, ae = create_system(
        reset=True
    )

    message, _, _ = _create_valid_message(
        sa,
        ae,
        "IE22700271",
        "password123",
    )

    if message is None:
        print("Esito: FALLITO")
        return False

    altered_message = replace(
        message,
        ballot_signature=_alter_base64_value(
            message.ballot_signature
        ),
    )

    receipt = ae.receive_ballot(
        altered_message
    )

    passed = receipt is None

    print(
        "Firma alterata rifiutata:",
        passed,
    )
    print(
        "Esito:",
        "SUPERATO" if passed else "FALLITO",
    )

    return passed


def test_altered_ciphertext_in_transit(
    create_system: SystemFactory,
) -> bool:
    print(
        "\n[TEST] Ciphertext alterato "
        "prima della ricezione"
    )

    _, sa, ae = create_system(
        reset=True
    )

    message, _, _ = _create_valid_message(
        sa,
        ae,
        "IE22700271",
        "password123",
    )

    if message is None:
        print("Esito: FALLITO")
        return False

    # Il ciphertext viene modificato dopo che il
    # VoterClient ha calcolato ballot_signature.
    altered_message = replace(
        message,
        encrypted_ballot=_alter_base64_value(
            message.encrypted_ballot
        ),
    )

    receipt = ae.receive_ballot(
        altered_message
    )

    passed = receipt is None

    print(
        "Ciphertext alterato rifiutato:",
        passed,
    )
    print(
        "Esito:",
        "SUPERATO" if passed else "FALLITO",
    )

    return passed


def test_same_message_replay(
    create_system: SystemFactory,
) -> bool:
    print(
        "\n[TEST] Replay dello stesso messaggio"
    )

    _, sa, ae = create_system(
        reset=True
    )

    message, _, _ = _create_valid_message(
        sa,
        ae,
        "IE22700271",
        "password123",
    )

    if message is None:
        print("Esito: FALLITO")
        return False

    first_receipt = ae.receive_ballot(
        message
    )

    second_receipt = ae.receive_ballot(
        message
    )

    passed = (
        first_receipt is not None
        and second_receipt is None
    )

    print(
        "Primo invio accettato:",
        first_receipt is not None,
    )
    print(
        "Secondo invio rifiutato:",
        second_receipt is None,
    )
    print(
        "Esito:",
        "SUPERATO" if passed else "FALLITO",
    )

    return passed


def test_request_nonce_replay(
    create_system: SystemFactory,
) -> bool:
    print(
        "\n[TEST] Replay del request_nonce"
    )

    _, sa, ae = create_system(
        reset=True
    )

    first_message, _, _ = (
        _create_valid_message(
            sa,
            ae,
            "IE22700271",
            "password123",
            "SI",
        )
    )

    if first_message is None:
        print("Esito: FALLITO")
        return False

    first_receipt = ae.receive_ballot(
        first_message
    )

    if first_receipt is None:
        print("Esito: FALLITO")
        return False

    (
        second_message,
        _,
        second_private_key,
    ) = _create_valid_message(
        sa,
        ae,
        "IE22700302",
        "password456",
        "NO",
    )

    if second_message is None:
        print("Esito: FALLITO")
        return False

    # Costruzione di un nuovo messaggio appartenente
    # a un altro elettore, ma con il nonce già usato.
    duplicated_nonce_message = replace(
        second_message,
        request_nonce=(
            first_message.request_nonce
        ),
    )

    signature_payload = {
        "pseudonym_id": (
            duplicated_nonce_message
            .signed_token.token.pseudonym_id
        ),
        "election_id": (
            duplicated_nonce_message.election_id
        ),
        "encrypted_key": (
            duplicated_nonce_message.encrypted_key
        ),
        "encrypted_ballot": (
            duplicated_nonce_message
            .encrypted_ballot
        ),
        "request_nonce": (
            duplicated_nonce_message
            .request_nonce
        ),
        "protocol_version": (
            duplicated_nonce_message
            .protocol_version
        ),
    }

    # La firma viene ricalcolata correttamente.
    # In questo modo il rifiuto dipende realmente
    # dal nonce duplicato e non da una firma errata.
    duplicated_nonce_message = replace(
        duplicated_nonce_message,
        ballot_signature=sign_json(
            second_private_key,
            signature_payload,
        ),
    )

    second_receipt = ae.receive_ballot(
        duplicated_nonce_message
    )

    passed = second_receipt is None

    print(
        "Nonce duplicato rifiutato:",
        passed,
    )
    print(
        "Esito:",
        "SUPERATO" if passed else "FALLITO",
    )

    return passed


def test_insufficient_trustees(
    create_system: SystemFactory,
) -> bool:
    print(
        "\n[TEST] Trustee insufficienti"
    )

    _, _, ae = create_system(
        reset=True
    )

    ae.close_election(
        force_demo=True
    )

    result = ae.scrutinio(
        [
            "trustee1",
            "trustee2",
        ]
    )

    passed = result is None

    print(
        "Scrutinio impedito:",
        passed,
    )
    print(
        "Esito:",
        "SUPERATO" if passed else "FALLITO",
    )

    return passed


def test_sufficient_trustees(
    create_system: SystemFactory,
) -> bool:
    print(
        "\n[TEST] Trustee sufficienti"
    )

    _, _, ae = create_system(
        reset=True
    )

    ae.close_election(
        force_demo=True
    )

    result = ae.scrutinio(
        [
            "trustee1",
            "trustee2",
            "trustee3",
        ]
    )

    passed = result is not None

    print(
        "Scrutinio eseguito:",
        passed,
    )
    print(
        "Esito:",
        "SUPERATO" if passed else "FALLITO",
    )

    return passed


def test_altered_trustee_share(
    create_system: SystemFactory,
) -> bool:
    print(
        "\n[TEST] Quota trustee alterata"
    )

    _, _, ae = create_system(
        reset=True
    )

    original_shares = deepcopy(
        ae.trustee_shares
    )

    try:
        x, values = ae.trustee_shares[0]

        altered_values = values.copy()

        altered_values[0] = (
            altered_values[0] + 1
        ) % 257

        ae.trustee_shares[0] = (
            x,
            altered_values,
        )

        ae.close_election(
            force_demo=True
        )

        result = ae.scrutinio(
            [
                "trustee1",
                "trustee2",
                "trustee3",
            ]
        )

        passed = result is None

        print(
            "Quota alterata rifiutata:",
            passed,
        )
        print(
            "Esito:",
            "SUPERATO" if passed else "FALLITO",
        )

        return passed

    finally:
        ae.trustee_shares = original_shares


def test_wrong_reconstructed_key(
    create_system: SystemFactory,
) -> bool:
    print(
        "\n[TEST] Chiave ricostruita errata"
    )

    _, _, ae = create_system(
        reset=True
    )

    original_shares = deepcopy(
        ae.trustee_shares
    )

    original_secret_length = (
        ae.decryption_private_key_length
    )

    original_file = (
        TRUSTEE_SHARES_FILE.read_bytes()
    )

    try:
        # Generazione di una chiave RSA valida,
        # ma estranea all'elezione.
        wrong_private_key = rsa_keygen()

        wrong_private_pem = private_key_to_pem(
            wrong_private_key
        )

        wrong_shares = shamir_split(
            wrong_private_pem,
            N_TRUSTEES,
            THRESHOLD,
        )

        ae.trustee_shares = wrong_shares

        ae.decryption_private_key_length = len(
            wrong_private_pem
        )

        exported_shares = []

        for index, (x, values) in enumerate(
            wrong_shares,
            start=1,
        ):
            trustee_id = f"trustee{index}"

            share_payload = {
                "trustee_id": trustee_id,
                "x": x,
                "values": values,
            }

            exported_shares.append(
                {
                    **share_payload,
                    "share_commitment": (
                        sha256_hex(
                            canonical_json(
                                share_payload
                            )
                        )
                    ),
                }
            )

        # I commitment vengono aggiornati, così il
        # test raggiunge il controllo di binding
        # con la chiave pubblica ufficiale.
        atomic_write_json(
            TRUSTEE_SHARES_FILE,
            {
                "election_id": ELECTION_ID,
                "threshold": THRESHOLD,
                "total_trustees": N_TRUSTEES,
                "secret_length": len(
                    wrong_private_pem
                ),
                "shares": exported_shares,
                "nota": (
                    "File temporaneo creato dal "
                    "test della chiave errata"
                ),
            },
        )

        ae.close_election(
            force_demo=True
        )

        result = ae.scrutinio(
            [
                "trustee1",
                "trustee2",
                "trustee3",
            ]
        )

        passed = result is None

        print(
            "Chiave estranea rifiutata:",
            passed,
        )
        print(
            "Esito:",
            "SUPERATO" if passed else "FALLITO",
        )

        return passed

    finally:
        ae.trustee_shares = original_shares

        ae.decryption_private_key_length = (
            original_secret_length
        )

        TRUSTEE_SHARES_FILE.write_bytes(
            original_file
        )


def test_valid_roster_inclusion(
    create_system: SystemFactory,
) -> bool:
    print(
        "\n[TEST] Inclusione valida "
        "nella lista elettorale"
    )

    segreteria, _, _ = create_system(
        reset=True
    )

    result = (
        segreteria.verify_student_inclusion(
            "IE22700271"
        )
    )

    passed = result["overall_valid"]

    print(
        "Inclusione verificata:",
        passed,
    )
    print(
        "Esito:",
        "SUPERATO" if passed else "FALLITO",
    )

    return passed


def test_missing_roster_inclusion(
    create_system: SystemFactory,
) -> bool:
    print(
        "\n[TEST] Matricola assente "
        "dalla lista elettorale"
    )

    segreteria, _, _ = create_system(
        reset=True
    )

    result = (
        segreteria.verify_student_inclusion(
            "IE99999999"
        )
    )

    passed = (
        result["signature_valid"]
        and result["merkle_root_valid"]
        and not result["included"]
        and not result["overall_valid"]
    )

    print(
        "Lista autentica:",
        (
            result["signature_valid"]
            and result["merkle_root_valid"]
        ),
    )
    print(
        "Matricola assente:",
        not result["included"],
    )
    print(
        "Esito:",
        "SUPERATO" if passed else "FALLITO",
    )

    return passed


def run_all_security_tests(
    create_system: SystemFactory,
) -> bool:
    """
    Esegue tutti i test su istanze indipendenti.

    Ogni funzione richiama create_system(reset=True),
    quindi i test non alterano il sistema del menu.
    """

    tests = [
        (
            "Password errata",
            test_wrong_password,
        ),
        (
            "Token multiplo",
            test_multiple_token,
        ),
        (
            "Token contraffatto",
            test_forged_token,
        ),
        (
            "Firma pseudonima alterata",
            test_altered_pseudonymous_signature,
        ),
        (
            "Ciphertext alterato in transito",
            test_altered_ciphertext_in_transit,
        ),
        (
            "Replay stesso messaggio",
            test_same_message_replay,
        ),
        (
            "Replay request_nonce",
            test_request_nonce_replay,
        ),
        (
            "Trustee insufficienti",
            test_insufficient_trustees,
        ),
        (
            "Trustee sufficienti",
            test_sufficient_trustees,
        ),
        (
            "Quota alterata",
            test_altered_trustee_share,
        ),
        (
            "Chiave ricostruita errata",
            test_wrong_reconstructed_key,
        ),
        (
            "Inclusione valida",
            test_valid_roster_inclusion,
        ),
        (
            "Inclusione assente",
            test_missing_roster_inclusion,
        ),
    ]

    results: Dict[str, bool] = {}

    print(
        "\n===================================="
    )
    print(
        " SUITE AUTOMATICA TEST DI SICUREZZA"
    )
    print(
        "===================================="
    )

    for name, test_function in tests:
        try:
            results[name] = test_function(
                create_system
            )
        except Exception as exc:
            results[name] = False
            print(
                f"\nErrore inatteso nel test "
                f"'{name}': {exc}"
            )

    print(
        "\n===================================="
    )
    print(
        " RIEPILOGO TEST"
    )
    print(
        "===================================="
    )

    for name, passed in results.items():
        print(
            f"{name}: "
            f"{'SUPERATO' if passed else 'FALLITO'}"
        )

    all_passed = all(
        results.values()
    )

    print(
        "\nESITO COMPLESSIVO:",
        (
            "TUTTI I TEST SUPERATI"
            if all_passed
            else "ALMENO UN TEST FALLITO"
        ),
    )

    return all_passed


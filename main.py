import argparse
import json
from pathlib import Path
from typing import List

from security_tests import run_all_security_tests
from actors.authentication_authority import AuthenticationAuthority
from actors.electoral_authority import ElectoralAuthority
from actors.segreteria import Segreteria
from config import (
    AE_CREDENTIALS_FILE, DATA_DIR, ELECTION_ID, THRESHOLD,
    TRUSTEE_CREDENTIALS_FILE, VOTAZIONI_FINE, VOTAZIONI_INIZIO,
)
from crypto.password_utils import verify_password
from crypto.rsa_utils import public_key_to_pem, rsa_keygen
from services.credentials import create_demo_credentials_files
from storage.json_utils import load_credentials
from clients.voter_client import VoterClient


def login_ae_interactive() -> bool:
    credentials = load_credentials(AE_CREDENTIALS_FILE)
    username = input("Username AE: ").strip()
    password = input("Password AE: ").strip()
    return (
        username == credentials["username"]
        and verify_password(
            password,
            credentials["salt"],
            credentials["password_hash"],
        )
    )


def collect_authenticated_trustees_interactive() -> List[str]:
    entries = load_credentials(TRUSTEE_CREDENTIALS_FILE, "trustees")
    credential_map = {entry["username"]: entry for entry in entries}
    selected: List[str] = []

    print(f"Servono almeno {THRESHOLD} trustee distinti.")
    while len(selected) < THRESHOLD:
        username = input(f"Trustee {len(selected) + 1} username: ").strip()
        password = input(f"Trustee {len(selected) + 1} password: ").strip()
        entry = credential_map.get(username)

        if not entry or not verify_password(
            password,
            entry["salt"],
            entry["password_hash"],
        ):
            print("Credenziali trustee non valide")
            continue
        if username in selected:
            print("Trustee già utilizzato")
            continue

        selected.append(username)
        print(f"Trustee autenticato ({len(selected)}/{THRESHOLD})")
    return selected


def reset_generated_outputs() -> None:
    patterns = [
        "lista_elettorale_firmata.json",
        "registro_sa.json",
        "parametri_pubblici.json",
        "bulletin_board.json",
        "checkpoint_bacheca.json",
        "chiusura_urne.json",
        "trustee_shares.json",
        "risultato.json",
        "ricevuta_*.json",
    ]
    for receipt_file in DATA_DIR.glob("ricevuta_*.json"):
        receipt_file.unlink(missing_ok=True)
    for pattern in patterns:
        for path in DATA_DIR.glob(pattern):
            path.unlink(missing_ok=True)


def create_system(reset: bool = True):
    create_demo_credentials_files()
    if reset:
        reset_generated_outputs()
    segreteria = Segreteria()
    sa = AuthenticationAuthority(segreteria)
    ae = ElectoralAuthority(sa.public_key)
    return segreteria, sa, ae


def vote_flow(sa: AuthenticationAuthority, ae: ElectoralAuthority) -> None:
    matricola = input("Matricola: ").strip()
    password = input("Password: ").strip()
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
    if token is None:
        return

    choice = input("Voto [1=SI, 0=NO]: ").strip()
    if choice not in {"0", "1"}:
        print("Scelta non valida")
        return

    voter_client = VoterClient(
        ae.decryption_public_key,
        pseudonymous_private_key,
    )

    ciphertext = voter_client.encrypt_vote(
        "SI" if choice == "1" else "NO"
    )

    message = voter_client.build_ballot_message(
        token,
        ciphertext,
    )
    voter_client.wait_before_send()
    receipt = ae.receive_ballot(message)
    if receipt:
        print("Voto registrato")
        print("Ballot ID:", receipt.receipt["ballot_id"])
        print(f"Ricevuta: ricevuta_{receipt.receipt['ballot_id']}.json")


def show_board(ae: ElectoralAuthority) -> None:
    ae.bulletin.export()
    print("\n=== BULLETIN BOARD ===")
    print("Chiusa:", ae.bulletin.closed)
    print("Record:", len(ae.bulletin.records))
    print("Hash-chain valida:", ae.bulletin.verify_chain())
    print("Merkle root:", ae.bulletin.root())
    for record in ae.bulletin.records:
        print(
            f"- #{record.sequence_number} {record.ballot_id} "
            f"{record.record_hash[:20]}..."
        )
def verify_roster_inclusion_flow(
    segreteria: Segreteria,
) -> None:
    print(
        "\n=== VERIFICA INCLUSIONE "
        "NELLA LISTA ELETTORALE ==="
    )

    matricola = input(
        "Inserisci la matricola da verificare: "
    ).strip()

    if not matricola:
        print("Matricola non valida")
        return

    result = (
        segreteria.verify_student_inclusion(
            matricola
        )
    )

    print(
        "\nFile lista presente:",
        result["roster_file_exists"],
    )
    print(
        "Chiave pubblica Segreteria valida:",
        result["public_key_valid"],
    )
    print(
        "Firma della lista valida:",
        result["signature_valid"],
    )
    print(
        "Election ID valido:",
        result["election_id_valid"],
    )
    print(
        "Versione protocollo valida:",
        result["protocol_version_valid"],
    )
    print(
        "Merkle root valida:",
        result["merkle_root_valid"],
    )
    print(
        "Matricola presente:",
        result["included"],
    )
    print(
        "Merkle proof valida:",
        result["merkle_proof_valid"],
    )

    if result["error"]:
        print(
            "Errore:",
            result["error"],
        )

    if result["overall_valid"]:
        print(
            "\nVERIFICA SUPERATA: "
            "la matricola è inclusa nella lista "
            "elettorale autentica e integra."
        )
    elif (
        result["signature_valid"]
        and result["merkle_root_valid"]
        and not result["included"]
    ):
        print(
            "\nVERIFICA FALLITA: "
            "la lista è autentica e integra, "
            "ma la matricola non è presente."
        )
    else:
        print(
            "\nVERIFICA FALLITA: "
            "non è possibile confermare "
            "l'autenticità o l'integrità "
            "della lista."
        )

def print_result(document: dict) -> None:
    result = document["result"]
    print("\n=== RISULTATO ===")
    print("Totale registrati:", result["totale_registrati"])
    print("Totale validi:", result["totale_validi"])
    print("SI:", result["si"])
    print("NO:", result["no"])
    print("Invalidi:", result["invalidi"])
    print("Vincitore:", result["vincitore"])


def show_credentials() -> None:
    print("""
Studenti:
IE22700271 / password123
IE22700302 / password456
IE22700100 / password789
IE22700200 / passwordabc
IE22700300 / passwordxyz

AE:
autorita / admin123

Trustee:
trustee1 / trustee123
trustee2 / trustee456
trustee3 / trustee789
trustee4 / trusteeabc
trustee5 / trusteexyz
""")


def demo_complete(
    sa: AuthenticationAuthority,
    ae: ElectoralAuthority,
) -> bool:
    scenarios = [
        ("IE22700271", "password123", "SI"),
        ("IE22700302", "password456", "NO"),
        ("IE22700100", "password789", "SI"),
    ]

    receipt_files: List[Path] = []

    for matricola, password, vote in scenarios:
        # La coppia pseudonima viene generata
        # sul lato dell'elettore.
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

        if token is None:
            print(
                "Emissione del token fallita per:",
                matricola,
            )
            return False

        # Il VoterClient rappresenta il dispositivo
        # dell'elettore e riceve soltanto la chiave
        # pubblica di decifrazione dell'AE.
        voter_client = VoterClient(
            ae.decryption_public_key,
            pseudonymous_private_key,
        )

        # La preferenza viene cifrata nel client.
        ciphertext = voter_client.encrypt_vote(
            vote
        )

        # Il messaggio cifrato viene firmato
        # con la chiave privata pseudonima.
        message = voter_client.build_ballot_message(
            token,
            ciphertext,
        )
        voter_client.wait_before_send(
            enabled=False
        )

        # L'AE riceve soltanto il messaggio già
        # cifrato e firmato.
        receipt = ae.receive_ballot(
            message
        )

        if receipt is None:
            print(
                "Registrazione del voto fallita per:",
                matricola,
            )
            return False

        receipt_files.append(
            DATA_DIR
            / (
                "ricevuta_"
                f"{receipt.receipt['ballot_id']}.json"
            )
        )

    # Verifica individuale di tutte le ricevute.
    for receipt_file in receipt_files:
        if not ae.verify_receipt(
            receipt_file
        ):
            print(
                "Verifica individuale fallita:",
                receipt_file,
            )
            return False

    # Chiusura anticipata soltanto per la demo.
    ae.close_election(
        force_demo=True
    )

    # Ricostruzione della chiave tramite
    # almeno tre trustee distinti.
    result = ae.scrutinio(
        [
            "trustee1",
            "trustee2",
            "trustee3",
        ]
    )

    if result is None:
        print(
            "Scrutinio non completato"
        )
        return False

    print_result(
        result
    )

    # Verifica pubblica finale.
    return ae.universal_verify()


def ae_menu(ae: ElectoralAuthority) -> None:
    if not login_ae_interactive():
        print("Login AE fallito")
        return

    while True:
        print("""
--- AREA AUTORITÀ ELETTORALE ---
1. Stato votazione
2. Chiudi urne (solo se scadute)
3. Chiudi urne anticipatamente per demo
4. Scrutinio
5. Verifica universale
6. Torna indietro
""")
        choice = input("Scelta: ").strip()

        if choice == "1":
            print("Apertura:", VOTAZIONI_INIZIO)
            print("Chiusura prevista:", VOTAZIONI_FINE)
            print("Votazione aperta:", ae.election_is_open())
            print("Bacheca chiusa:", ae.bulletin.closed)
            print("Voti registrati:", len(ae.bulletin.records))
        elif choice == "2":
            try:
                ae.close_election(force_demo=False)
                print("Urne chiuse e messaggio firmato generato")
            except RuntimeError as exc:
                print(exc)
        elif choice == "3":
            confirm = input("Confermare chiusura anticipata DEMO? [s/N]: ").lower()
            if confirm == "s":
                ae.close_election(force_demo=True)
                print("Urne chiuse in modalità dimostrativa")
        elif choice == "4":
            trustees = collect_authenticated_trustees_interactive()
            result = ae.scrutinio(trustees)
            if result:
                print_result(result)
        elif choice == "5":
            print("Verifica universale superata:", ae.universal_verify())
        elif choice == "6":
            return
        else:
            print("Scelta non valida")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Esegue una dimostrazione completa automatica.",
    )
    args = parser.parse_args()

    segreteria, sa, ae = create_system(
        reset=True
    )

    if args.self_test:
        ok = demo_complete(sa, ae)
        print("\nSELF-TEST:", "SUPERATO" if ok else "FALLITO")
        raise SystemExit(0 if ok else 1)

    print("Sistema inizializzato e file JSON di setup generati.")

    while True:
        print(
            """
        ===== SISTEMA DI VOTO ELETTRONICO =====
        1. Vota con login studente
        2. Mostra Bulletin Board
        3. Area Autorità Elettorale
        4. Verifica ricevuta
        5. Demo completa automatica
        6. Mostra credenziali demo
        7. Verifica inclusione nella lista elettorale
        8. Esegui test automatici di sicurezza
        9. Esci
        """
        )

        choice = input("Scelta: ").strip()

        if choice == "1":
            vote_flow(sa, ae)
        elif choice == "2":
            show_board(ae)
        elif choice == "3":
            ae_menu(ae)
        elif choice == "4":
            filename = input("Nome file ricevuta: ").strip()
            path = Path(filename)
            if not path.is_absolute() and not path.exists():
                path = DATA_DIR / filename
            if not path.exists():
                print(f"Ricevuta non trovata: {path}")
            else:
                print("Ricevuta valida:", ae.verify_receipt(path))
        elif choice == "5":
            print(
                "Demo superata:",
                demo_complete(sa, ae),
            )
        elif choice == "6":
            show_credentials()
        elif choice == "7":
            verify_roster_inclusion_flow(
                segreteria
            )

        elif choice == "8":
            confirm = input(
                "I test rigenerano più volte i file JSON. "
                "Continuare? [s/N]: "
            ).strip().lower()

            if confirm == "s":
                all_passed = (
                    run_all_security_tests(
                        create_system
                    )
                )

                print(
                    "\nSuite di sicurezza superata:",
                    all_passed,
                )

                # I test hanno rigenerato i file globali.
                # Ricreiamo il sistema utilizzato dal menu,
                # così memoria e JSON tornano allineati.
                segreteria, sa, ae = create_system(
                    reset=True
                )

                print(
                    "Sistema principale reinizializzato."
                )

        elif choice == "9":
            break

        else:
            print("Scelta non valida")

if __name__ == "__main__":
    main()

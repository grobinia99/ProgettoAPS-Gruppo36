from pathlib import Path

PROTOCOL_VERSION = "1.0"
ELECTION_ID = "REFERENDUM_UNISA_2026_001"
VOTAZIONI_INIZIO = "2026-01-01 00:00:00"
VOTAZIONI_FINE = "2026-12-31 23:59:59"

N_TRUSTEES = 5
THRESHOLD = 3
PBKDF2_ITERATIONS = 200_000
SHAMIR_FIELD = 257
MAX_FIELD_LENGTH = 50_000

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

STUDENTI_FILE = DATA_DIR / "studenti_COMPLETO.json"
AE_CREDENTIALS_FILE = DATA_DIR / "credenziali_ae.json"
TRUSTEE_CREDENTIALS_FILE = DATA_DIR / "credenziali_trustee.json"

ROSTER_FILE = DATA_DIR / "lista_elettorale_firmata.json"
SA_REGISTRY_FILE = DATA_DIR / "registro_sa.json"
PUBLIC_PARAMETERS_FILE = DATA_DIR / "parametri_pubblici.json"
BULLETIN_FILE = DATA_DIR / "bulletin_board.json"
CHECKPOINT_FILE = DATA_DIR / "checkpoint_bacheca.json"
CLOSURE_FILE = DATA_DIR / "chiusura_urne.json"
TRUSTEE_SHARES_FILE = DATA_DIR / "trustee_shares.json"
RESULT_FILE = DATA_DIR / "risultato.json"

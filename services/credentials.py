from config import AE_CREDENTIALS_FILE, STUDENTI_FILE, TRUSTEE_CREDENTIALS_FILE
from crypto.password_utils import create_password_entry
from storage.json_utils import atomic_write_json


def create_demo_credentials_files() -> None:
    if not STUDENTI_FILE.exists():
        students = {
            "studenti": [
                create_password_entry("matricola", "IE22700271", "password123"),
                create_password_entry("matricola", "IE22700302", "password456"),
                create_password_entry("matricola", "IE22700100", "password789"),
                create_password_entry("matricola", "IE22700200", "passwordabc"),
                create_password_entry("matricola", "IE22700300", "passwordxyz"),
            ]
        }
        atomic_write_json(STUDENTI_FILE, students)

    if not AE_CREDENTIALS_FILE.exists():
        atomic_write_json(
            AE_CREDENTIALS_FILE,
            create_password_entry("username", "autorita", "admin123"),
        )

    if not TRUSTEE_CREDENTIALS_FILE.exists():
        trustees = {
            "trustees": [
                create_password_entry("username", "trustee1", "trustee123"),
                create_password_entry("username", "trustee2", "trustee456"),
                create_password_entry("username", "trustee3", "trustee789"),
                create_password_entry("username", "trustee4", "trusteeabc"),
                create_password_entry("username", "trustee5", "trusteexyz"),
            ]
        }
        atomic_write_json(TRUSTEE_CREDENTIALS_FILE, trustees)

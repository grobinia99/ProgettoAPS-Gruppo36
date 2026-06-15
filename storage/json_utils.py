import json
from pathlib import Path
from typing import Any, Optional


def atomic_write_json(path: Path, data: Any) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding="utf-8")
    temp.replace(path)


def read_json(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"File non trovato: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def load_credentials(path: Path, collection_key: Optional[str] = None):
    raw = read_json(path)
    return raw[collection_key] if collection_key else raw

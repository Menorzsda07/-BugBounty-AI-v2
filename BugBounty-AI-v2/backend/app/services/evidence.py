from __future__ import annotations
import hashlib, json
from pathlib import Path
from datetime import datetime, timezone
from app.models.schemas import EvidenceItem

class EvidenceStore:
    def __init__(self, root: str = "../evidence") -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def save_text(self, investigation_id: str, filename: str, content: str, kind: str, description: str) -> EvidenceItem:
        folder = self.root / investigation_id
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / filename
        path.write_text(content, encoding="utf-8")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return EvidenceItem(type=kind, filename=str(path.name), description=description, sha256=digest)

    def save_metadata(self, investigation_id: str, payload: dict) -> EvidenceItem:
        payload = {**payload, "captured_at": datetime.now(timezone.utc).isoformat()}
        return self.save_text(investigation_id, "metadata.json", json.dumps(payload, indent=2, ensure_ascii=False), "metadata", "Metadados e cadeia de custódia da evidência.")

evidence_store = EvidenceStore()

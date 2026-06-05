"""
state.py — gestion du state file JSON pour vps-secure-agents.

State files:
  - cto_state.json       : état global du CTO (CVE vues, debounce, ack)
  - inventory.json       : dernier inventaire capturé
  - cve_cache.json       : cache des CVE brutes (déjà fetchées)
  - impact_cache.json    : cache des verdicts IMPACT_ASSESSOR
  - threat_cache.json    : cache des enrichissements THREAT_INTEL

Tous les fichiers sont lus/écrits en JSON UTF-8, chmod 600.
"""

import json
import os
import tempfile
import fcntl
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

DEFAULT_STATE = {
    "schema_version": "1.0",
    "last_run": None,
    "cves_seen": {},          # cve_id -> {first_seen, last_notified, class, component_id, user_acked_at, user_snoozed_until, fix_applied_at, user_dismissed_at, issue_url, issue_number, issue_created_at}
    "last_inventory_sha": None,
    "drift_alert_pending": False,
    "stats": {
        "total_runs": 0,
        "total_cves_processed": 0,
        "total_notifications_sent": 0,
        "total_acked": 0,
        "total_dismissed": 0,
        "total_issues_created": 0,
    }
}


class StateFile:
    """Wrapper pour un JSON file avec locking et écriture atomique."""

    def __init__(self, path: Path, default: dict):
        self.path = Path(path)
        self.default = default
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def read(self) -> dict:
        if not self.path.exists():
            return self.default.copy()
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                fcntl.flock(f, fcntl.LOCK_SH)
                data = json.load(f)
                fcntl.flock(f, fcntl.LOCK_UN)
            return data
        except (json.JSONDecodeError, OSError) as e:
            # Cache corrompu → reset (loggé par l'appelant)
            print(f"[WARN] {self.path} corrompu, reset: {e}")
            return self.default.copy()

    def write(self, data: dict) -> None:
        """Écriture atomique via fichier temp + rename."""
        data = _ensure_serializable(data)
        tmp_fd, tmp_path = tempfile.mkstemp(dir=self.path.parent, prefix=".tmp_", suffix=".json")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
                fcntl.flock(f, fcntl.LOCK_UN)
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, self.path)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    def update(self, mutator) -> dict:
        """Lit, applique mutator(state), écrit. Retourne le nouvel état."""
        state = self.read()
        new_state = mutator(state)
        self.write(new_state)
        return new_state


def _ensure_serializable(obj: Any) -> Any:
    """Convertit les types non-sérialisables (datetime, Path) en str."""
    if isinstance(obj, datetime):
        return obj.astimezone(timezone.utc).isoformat()
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, dict):
        return {k: _ensure_serializable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_ensure_serializable(v) for v in obj]
    return obj


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def debounce_check(state: dict, cve_id: str, component_id: str, debounce_days: int = 7) -> bool:
    """Retourne True si la CVE doit être re-notifiée, False sinon.

    Logique:
      - Si jamais vue → True
      - Si vue < debounce_days → False
      - Si vue > debounce_days → True
      - Si user_acked_at ou fix_applied_at → False (silence)
      - Si user_dismissed_at → False (silence définitif — l'utilisateur a tranché)
      - Si user_snoozed_until > now → False
    """
    key = cve_id
    seen = state.get("cves_seen", {}).get(key)
    if not seen:
        return True
    if seen.get("user_acked_at") or seen.get("fix_applied_at"):
        return False
    if seen.get("user_dismissed_at"):
        return False  # dismiss = silence définitif
    snoozed_until = seen.get("user_snoozed_until")
    if snoozed_until:
        try:
            until = datetime.fromisoformat(snoozed_until)
            if datetime.now(timezone.utc) < until:
                return False
        except ValueError:
            pass
    first_seen = seen.get("first_seen")
    if not first_seen:
        return True
    try:
        first_dt = datetime.fromisoformat(first_seen)
        age = datetime.now(timezone.utc) - first_dt
        return age.days >= debounce_days
    except ValueError:
        return True


# ════════════════════════════════════════════════════════════════════
# Actions utilisateur via Telegram callbacks
# ════════════════════════════════════════════════════════════════════

def mark_dismissed(state: dict, cve_id: str, user: str = "telegram") -> dict:
    """Marque la CVE comme dismissed (l'utilisateur a cliqué 'Pas OK').

    Retourne l'état modifié. Idempotent.
    """
    if "cves_seen" not in state:
        state["cves_seen"] = {}
    if cve_id not in state["cves_seen"]:
        state["cves_seen"][cve_id] = {}
    entry = state["cves_seen"][cve_id]
    if not entry.get("user_dismissed_at"):
        entry["user_dismissed_at"] = now_utc_iso()
        entry["user_dismissed_by"] = user
        state["stats"]["total_dismissed"] = state["stats"].get("total_dismissed", 0) + 1
    return state


def mark_issue_created(state: dict, cve_id: str, issue_url: str, issue_number: int) -> dict:
    """Enregistre qu'une GitHub issue a été créée pour cette CVE.

    Retourne l'état modifié. Idempotent (n'écrase pas une issue existante).
    """
    if "cves_seen" not in state:
        state["cves_seen"] = {}
    if cve_id not in state["cves_seen"]:
        state["cves_seen"][cve_id] = {}
    entry = state["cves_seen"][cve_id]
    if not entry.get("issue_url"):
        entry["issue_url"] = issue_url
        entry["issue_number"] = issue_number
        entry["issue_created_at"] = now_utc_iso()
        state["stats"]["total_issues_created"] = state["stats"].get("total_issues_created", 0) + 1
    return state


def is_dismissed(state: dict, cve_id: str) -> bool:
    return bool(state.get("cves_seen", {}).get(cve_id, {}).get("user_dismissed_at"))


def is_issue_created(state: dict, cve_id: str) -> bool:
    return bool(state.get("cves_seen", {}).get(cve_id, {}).get("issue_url"))

#!/usr/bin/env python
"""
E2E test: envoie un message Telegram de test avec les 2 boutons inline,
puis lance le polling pendant `POLL_SECS` secondes pour capturer le clic.

Usage:
  PYTHONPATH=agents/orchestrator .venv/bin/python scripts/e2e_button_test.py
  # ou
  bash scripts/e2e_button_test.sh
"""
import os
import sys
import time
import json
from pathlib import Path
from dotenv import load_dotenv

# Charge le .env du projet
PROJECT_ROOT = Path(__file__).parent.parent
load_dotenv(PROJECT_ROOT / "agents" / ".env")

sys.path.insert(0, str(PROJECT_ROOT / "agents" / "orchestrator"))

from telegram_notifier import TelegramNotifier, cve_action_buttons
from callback_handler import handle_callback_query
from state import StateFile, DEFAULT_STATE
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("e2e")

POLL_SECS = int(os.environ.get("POLL_SECS", "90"))

# CVE factice (clairement "TEST" dans le titre) pour pas confondre avec une vraie
TEST_CVE_ID = os.environ.get("TEST_CVE_ID", "CVE-2025-99999")
TEST_COMPONENT = "docker-ce (TEST)"
TEST_VERSION = "5:99.0.0-test"

# 1) Envoie le message
notifier = TelegramNotifier(dry_run=False)
text = (
    f"🧪 <b>TEST — bouton inline E2E</b>\n\n"
    f"Ceci est un message de test du système de boutons.\n\n"
    f"CVE simulée: <code>{TEST_CVE_ID}</code>\n"
    f"Composant: {TEST_COMPONENT} v{TEST_VERSION}\n"
    f"Impact: <b>critical (faux pour le test)</b>\n\n"
    f"<b>Clique sur ✅ OK pour créer une issue GitHub de test.</b>\n"
    f"<b>Clique sur ❌ Pas OK pour marquer dismissed.</b>\n\n"
    f"<i>Le polling écoute pendant {POLL_SECS}s.</i>"
)
buttons = cve_action_buttons(TEST_CVE_ID)
log.info("envoi du message de test avec boutons...")
resp = notifier.send_with_buttons(text, buttons)
msg_id = (resp.get("result") or {}).get("message_id")
log.info("message envoyé: msg_id=%s", msg_id)
print(f"\n>>> Ouvre Telegram, message_id={msg_id}")
print(f">>> Click un des 2 boutons (ou attends {POLL_SECS}s pour timeout)")
print(f">>> Polling démarré...\n")

# 2) Injecte le verdict dans cto_state pour que handle_ack le trouve
state_path = PROJECT_ROOT / "agents" / "state" / "cto_state.json"
cto = StateFile(state_path, DEFAULT_STATE).read()
cto.setdefault("cves_seen", {})[TEST_CVE_ID] = {
    "first_seen": "2025-06-05T10:00:00Z",
    "last_notified": "2025-06-05T10:00:00Z",
    "class": "critical",
    "component_id": "docker-ce",
    "verdict": {
        "cve_id": TEST_CVE_ID,
        "impact_class": "critical",
        "kev_listed": True,
        "impact_score": 9.9,
        "rationale": "[E2E TEST] Synthetic CVE for button click test. Click OK to create a real issue on the repo (will be labeled 'test,security' and you can close it after).",
        "matched_components": [
            {
                "component_name": TEST_COMPONENT,
                "installed_version": TEST_VERSION,
                "match_reason": "synthetic E2E test",
            }
        ],
    },
    "user_acked_at": None,
    "user_dismissed_at": None,
    "issue_url": None,
    "issue_number": None,
}
StateFile(state_path, DEFAULT_STATE).write(cto)
log.info("verdict de test injecté dans cto_state.json")

# 3) Long-polling
states = {
    "cto": StateFile(state_path, DEFAULT_STATE),
    "impact_cache": StateFile(PROJECT_ROOT / "agents" / "state" / "impact_cache.json", {"verdicts": []}),
}
repo = os.environ.get("GITHUB_REPO", "rockballslab/vps-secure")

# Direct getUpdates loop (skip lock file for one-shot)
import requests
offset = None
deadline = time.time() + POLL_SECS
url = f"https://api.telegram.org/bot{notifier.token}/getUpdates"
handled = 0

while time.time() < deadline:
    try:
        r = requests.post(
            url,
            json={"timeout": 20, "offset": offset, "allowed_updates": ["callback_query"]},
            timeout=25,
        )
        r.raise_for_status()
        for upd in r.json().get("result", []):
            offset = upd["update_id"] + 1
            cq = upd.get("callback_query")
            if not cq:
                continue
            result = handle_callback_query(
                callback_query=cq,
                notifier=notifier,
                states=states,
                repo=repo,
                dry_run=False,
            )
            handled += 1
            log.info("callback traité: %s", json.dumps(result, default=str)[:300])
    except requests.exceptions.Timeout:
        continue
    except Exception as e:
        log.error("polling error: %s", e)
        time.sleep(2)

print(f"\n=== E2E terminé: {handled} callback(s) traité(s) en {POLL_SECS}s ===")
print(f"Vérifie l'état final: cat {state_path} | python -m json.tool | head -50")

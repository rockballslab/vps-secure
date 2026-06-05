"""
callback_handler.py — dispatch des callback_query Telegram.

Reçoit les clics sur les boutons inline ("✅ OK" / "❌ Pas OK"),
appelle l'action correspondante (création d'issue GitHub ou dismiss),
met à jour le state, et confirme à l'utilisateur via editMessage.

Format callback_data: "<action>|<cve_id>"
  - "ack|CVE-2026-41567"     → crée issue GitHub + ack state
  - "dismiss|CVE-2026-41567" → mark dismissed dans state
"""

import logging
from typing import Any

from github_issues import create_issue_for_cve, find_existing_issue
from state import (
    mark_dismissed,
    mark_issue_created,
    is_dismissed,
    is_issue_created,
    now_utc_iso,
)

log = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════
# Parsing
# ════════════════════════════════════════════════════════════════════

def parse_callback_data(data: str) -> dict[str, str]:
    """
    Parse un callback_data du type "ack|CVE-XXXX-YYYY".

    Returns: {"action": "ack"|"dismiss"|"unknown", "cve_id": "..."|"", "raw": "..."}
    """
    if not data or "|" not in data:
        return {"action": "unknown", "cve_id": "", "raw": data or ""}
    action, _, cve_id = data.partition("|")
    action = action.strip().lower()
    cve_id = cve_id.strip()
    if action not in ("ack", "dismiss"):
        return {"action": "unknown", "cve_id": cve_id, "raw": data}
    return {"action": action, "cve_id": cve_id, "raw": data}


# ════════════════════════════════════════════════════════════════════
# Lookup du verdict dans le state
# ════════════════════════════════════════════════════════════════════

def _find_verdict_for_cve(cve_id: str, states: dict) -> dict | None:
    """
    Cherche le verdict complet dans le state cto (cves_seen) ou impact_cache.
    Priorité: cto_state.cves_seen → impact_cache → None.
    """
    cto = states["cto"].read()
    entry = cto.get("cves_seen", {}).get(cve_id)
    if entry and entry.get("verdict"):
        return entry["verdict"]

    # Fallback: impact_cache.json (le verdict brut)
    impact = states.get("impact_cache")
    if impact:
        try:
            cache = impact.read()
            for v in cache.get("verdicts", []):
                if v.get("cve_id") == cve_id:
                    return v
        except Exception as e:
            log.warning("impact_cache read failed: %s", e)
    return None


# ════════════════════════════════════════════════════════════════════
# Handlers par action
# ════════════════════════════════════════════════════════════════════

def handle_ack(
    cve_id: str,
    states: dict,
    repo: str,
    callback_query: dict,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Action: "✅ OK — créer issue".
    - Vérifie qu'une issue n'existe pas déjà (dedup)
    - Crée l'issue via gh CLI
    - Met à jour le state
    - Retourne {ok, issue_url|error}
    """
    user = (callback_query.get("from") or {}).get("username", "telegram")

    # 1) Dedup: si on a déjà créé une issue, on retourne l'URL existante
    cto = states["cto"].read()
    if is_issue_created(cto, cve_id):
        existing_url = cto["cves_seen"][cve_id]["issue_url"]
        return {
            "ok": True,
            "deduped": True,
            "issue_url": existing_url,
            "message": f"Issue déjà créée: {existing_url}",
        }

    # 2) Chercher si une issue existe déjà sur GitHub (autre source)
    existing = find_existing_issue(cve_id, repo) if not dry_run else None
    if existing:
        states["cto"].update(lambda s: mark_issue_created(s, cve_id, existing["url"], existing["number"]))
        return {
            "ok": True,
            "deduped": True,
            "issue_url": existing["url"],
            "message": f"Issue existante trouvée: {existing['url']}",
        }

    # 3) Récupérer le verdict complet
    verdict = _find_verdict_for_cve(cve_id, states)
    if not verdict:
        return {
            "ok": False,
            "error": f"verdict introuvable pour {cve_id} (pas dans cto_state ni impact_cache)",
        }

    # 4) Créer l'issue
    inv_match = (verdict.get("matched_components") or [{}])[0]
    result = create_issue_for_cve(verdict, repo, inv_match=inv_match, dry_run=dry_run)

    if not result.get("ok"):
        return {
            "ok": False,
            "error": result.get("error", "unknown gh error"),
            "payload": result.get("payload"),
        }

    # 5) Persister dans le state
    states["cto"].update(lambda s: mark_issue_created(s, cve_id, result["url"], result["number"]))

    return {
        "ok": True,
        "deduped": False,
        "issue_url": result["url"],
        "issue_number": result.get("number"),
        "by": user,
    }


def handle_dismiss(
    cve_id: str,
    states: dict,
    callback_query: dict,
) -> dict[str, Any]:
    """
    Action: "❌ Pas OK".
    - Marque la CVE comme dismissed dans le state
    - Idempotent
    """
    user = (callback_query.get("from") or {}).get("username", "telegram")
    cto = states["cto"].read()
    if is_dismissed(cto, cve_id):
        return {"ok": True, "deduped": True, "by": user, "message": "déjà dismiss"}
    states["cto"].update(lambda s: mark_dismissed(s, cve_id, user))
    return {"ok": True, "deduped": False, "by": user}


# ════════════════════════════════════════════════════════════════════
# Dispatch principal
# ════════════════════════════════════════════════════════════════════

def handle_callback_query(
    callback_query: dict,
    notifier,
    states: dict,
    repo: str,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Point d'entrée: reçoit un callback_query de Telegram, dispatche l'action,
    met à jour le message original pour confirmer.

    Args:
        callback_query: le dict complet venant de Telegram
        notifier: instance TelegramNotifier
        states: dict des StateFile ({"cto": ..., "impact_cache": ...})
        repo: "owner/repo" pour la création d'issues
        dry_run: si True, ne crée pas d'issue

    Returns: dict avec ok, action, result, etc.
    """
    callback_id = callback_query.get("id", "")
    data = callback_query.get("data", "")
    message = callback_query.get("message") or {}
    chat_id = message.get("chat", {}).get("id")
    message_id = message.get("message_id")

    parsed = parse_callback_data(data)
    action = parsed["action"]
    cve_id = parsed["cve_id"]

    log.info("callback received: id=%s data=%s → action=%s cve=%s",
             callback_id, data, action, cve_id)

    if action == "unknown" or not cve_id:
        notifier.answer_callback_query(callback_id, "Action inconnue.", show_alert=True)
        return {"ok": False, "action": action, "cve_id": cve_id, "error": "unknown action or empty cve_id"}

    # Dispatch
    if action == "ack":
        result = handle_ack(cve_id, states, repo, callback_query, dry_run=dry_run)
    else:  # dismiss
        result = handle_dismiss(cve_id, states, callback_query)

    # 6) Répondre à Telegram (acknowledge le clic) + éditer le message
    if result.get("ok"):
        if action == "ack":
            issue_url = result.get("issue_url", "?")
            ack_text = f"✅ Issue créée: {issue_url}" if not result.get("deduped") else f"ℹ️ Issue existante: {issue_url}"
            new_buttons: list[list[dict]] = []  # retire les boutons après action
            notifier.answer_callback_query(callback_id, ack_text[:200])
            if chat_id and message_id:
                _safe_edit(notifier, chat_id, message_id, message, ack_text, new_buttons)
        else:  # dismiss
            ack_text = "❌ Marquée comme 'Pas OK'. Silence définitif sur cette CVE."
            new_buttons = []
            notifier.answer_callback_query(callback_id, ack_text[:200])
            if chat_id and message_id:
                _safe_edit(notifier, chat_id, message_id, message, ack_text, new_buttons)
    else:
        err = result.get("error", "erreur inconnue")
        notifier.answer_callback_query(callback_id, f"⚠️ Échec: {err[:150]}", show_alert=True)

    return {
        "ok": result.get("ok", False),
        "action": action,
        "cve_id": cve_id,
        "result": result,
        "callback_id": callback_id,
        "timestamp": now_utc_iso(),
    }


def _safe_edit(notifier, chat_id, message_id, original_message, new_text, new_buttons):
    """Édite le message original en gardant le prefix 'OK fait' visible. Tolère les erreurs."""
    try:
        orig_text = original_message.get("text", "")
        # Tronque l'orig pour pas dépasser la limite 4096 chars Telegram
        prefix = f"~~{orig_text[:1500]}~~\n\n" if orig_text else ""
        full = f"{prefix}<b>{new_text}</b>"
        notifier.edit_message(chat_id, message_id, full, new_buttons)
    except Exception as e:
        log.warning("edit_message failed (non-blocking): %s", e)

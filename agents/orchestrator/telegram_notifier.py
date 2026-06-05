"""
telegram_notifier.py — envoi de messages Telegram via Bot API.

Pas de dépendance externe: utilise requests (déjà dans requirements).
"""

import os
import requests
from typing import Any

API_BASE = "https://api.telegram.org/bot{token}/{method}"


class TelegramNotifier:
    def __init__(self, token: str | None = None, chat_id: str | None = None, dry_run: bool = False):
        self.token = token or os.environ.get("TELEGRAM_BOT_TOKEN")
        self.chat_id = chat_id or os.environ.get("TELEGRAM_CHAT_ID")
        self.dry_run = dry_run
        if not self.dry_run and (not self.token or not self.chat_id):
            raise ValueError("TELEGRAM_BOT_TOKEN et TELEGRAM_CHAT_ID requis (ou DRY_RUN=true).")

    def send(self, text: str, parse_mode: str = "HTML", disable_preview: bool = True) -> dict[str, Any]:
        """Envoie un message Telegram. Retourne la réponse de l'API."""
        if self.dry_run:
            print(f"[DRY-RUN Telegram → chat_id={self.chat_id}]\n{text}\n---")
            return {"ok": True, "dry_run": True}

        url = API_BASE.format(token=self.token, method="sendMessage")
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": parse_mode,
            "disable_web_page_preview": disable_preview,
        }
        r = requests.post(url, json=payload, timeout=15)
        r.raise_for_status()
        return r.json()

    def send_with_buttons(
        self,
        text: str,
        buttons: list[list[dict[str, str]]],
        parse_mode: str = "HTML",
        disable_preview: bool = True,
    ) -> dict[str, Any]:
        """
        Envoie un message avec un clavier inline (boutons sous le message).

        buttons: liste de rangées, chaque rangée = liste de boutons.
        Chaque bouton = {"text": "Label", "callback_data": "action|param"}.
        callback_data DOIT faire ≤ 64 bytes (limite Telegram).

        Exemple:
            [[
                {"text": "✅ OK — créer issue", "callback_data": "ack|CVE-2026-41567"},
                {"text": "❌ Pas OK",            "callback_data": "dismiss|CVE-2026-41567"},
            ]]
        """
        for row in buttons:
            for btn in row:
                if len(btn.get("callback_data", "").encode("utf-8")) > 64:
                    raise ValueError(
                        f"callback_data > 64 bytes: {btn['callback_data']!r} "
                        f"({len(btn['callback_data'].encode('utf-8'))} bytes)"
                    )

        if self.dry_run:
            print(f"[DRY-RUN Telegram → chat_id={self.chat_id}] (avec {sum(len(r) for r in buttons)} boutons)")
            print(f"{text}\n---")
            return {"ok": True, "dry_run": True, "result": {"message_id": 0}}

        url = API_BASE.format(token=self.token, method="sendMessage")
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": parse_mode,
            "disable_web_page_preview": disable_preview,
            "reply_markup": {"inline_keyboard": buttons},
        }
        r = requests.post(url, json=payload, timeout=15)
        r.raise_for_status()
        return r.json()

    def edit_message(
        self,
        chat_id: str | int,
        message_id: int,
        new_text: str,
        new_buttons: list[list[dict[str, str]]] | None = None,
        parse_mode: str = "HTML",
    ) -> dict[str, Any]:
        """Édite un message existant (utile après un callback pour confirmer l'action)."""
        if self.dry_run:
            print(f"[DRY-RUN editMessage chat_id={chat_id} msg_id={message_id}]")
            print(f"{new_text}\n---")
            return {"ok": True, "dry_run": True}

        url = API_BASE.format(token=self.token, method="editMessageText")
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "message_id": message_id,
            "text": new_text,
            "parse_mode": parse_mode,
        }
        if new_buttons is not None:
            payload["reply_markup"] = {"inline_keyboard": new_buttons}
        r = requests.post(url, json=payload, timeout=15)
        r.raise_for_status()
        return r.json()

    def answer_callback_query(
        self,
        callback_query_id: str,
        text: str = "",
        show_alert: bool = False,
    ) -> dict[str, Any]:
        """Répond à un callback_query (acknowledge le clic, optionnellement avec un toast)."""
        if self.dry_run:
            print(f"[DRY-RUN answerCallbackQuery id={callback_query_id}] {text}")
            return {"ok": True, "dry_run": True}

        url = API_BASE.format(token=self.token, method="answerCallbackQuery")
        payload: dict[str, Any] = {
            "callback_query_id": callback_query_id,
            "show_alert": show_alert,
        }
        if text:
            payload["text"] = text[:200]  # Telegram limite
        r = requests.post(url, json=payload, timeout=15)
        r.raise_for_status()
        return r.json()

    def get_updates(
        self,
        offset: int | None = None,
        timeout: int = 30,
        allowed_updates: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Long-polling des updates Telegram.

        offset: dernier update_id + 1 (pour ack et ne pas le revoir).
        timeout: secondes d'attente longue côté Telegram (max 50).
        allowed_updates: ex. ['callback_query'] pour ne recevoir que les clics.
        """
        if self.dry_run:
            return []  # Pas d'updates en dry-run

        url = API_BASE.format(token=self.token, method="getUpdates")
        payload: dict[str, Any] = {
            "timeout": min(timeout, 50),
        }
        if offset is not None:
            payload["offset"] = offset
        if allowed_updates:
            payload["allowed_updates"] = allowed_updates

        r = requests.post(url, json=payload, timeout=timeout + 10)
        r.raise_for_status()
        data = r.json()
        return data.get("result", [])


def format_digest(verdicts: list[dict], stats: dict) -> str:
    """Formate le digest quotidien (tous verdicts groupés)."""
    p0 = [v for v in verdicts if v.get("impact_class") == "critical" and v.get("kev_listed")]
    p1_plus = [v for v in verdicts if v.get("impact_class") == "high" and v.get("kev_listed")]
    p1 = [v for v in verdicts if v.get("impact_class") == "high" and not v.get("kev_listed")]
    p2 = [v for v in verdicts if v.get("impact_class") == "medium"]
    p0_p1 = p0 + p1_plus + p1  # tous notifiables

    lines = [
        "🛡️ <b>vps-secure daily digest</b>",
        f"📅 {stats.get('date', 'N/A')}",
        "",
        f"<b>Impact:</b>",
        f"  🔴 P0 (KEV): {len(p0)}",
        f"  🟠 P1+ (KEV): {len(p1_plus)}",
        f"  🟠 P1: {len(p1)}",
        f"  🟡 P2: {len(p2)} (silence — query-state pour détails)",
        f"  ⚪ P3 / no-match: {stats.get('p3_count', 0)}",
        "",
    ]

    if p0_p1:
        lines.append("<b>⚠️ Action requise:</b>")
        for v in p0_p1[:10]:  # cap à 10
            comp = v.get("matched_components", [{}])[0]
            lines.append(
                f"  • <code>{v['cve_id']}</code> — {comp.get('component_name', '?')} "
                f"(score {v.get('impact_score', '?')}, class {v.get('impact_class')})"
            )
        if len(p0_p1) > 10:
            lines.append(f"  … et {len(p0_p1) - 10} autres. Voir state/cto_state.json")
    else:
        lines.append("✅ <b>Aucune CVE P0/P1 détectée.</b>")

    lines.extend([
        "",
        f"<i>Inventaire: {stats.get('components_count', 0)} composants, "
        f"{stats.get('containers_count', 0)} containers, "
        f"{stats.get('ports_count', 0)} ports.</i>",
        f"<i>Sources: {', '.join(stats.get('sources_fetched', []))}</i>",
    ])

    if stats.get("sources_failed"):
        lines.append(f"⚠️ <i>Sources KO: {', '.join(stats['sources_failed'])}</i>")

    return "\n".join(lines)


def format_p0_alert(verdict: dict) -> str:
    """Formate une alerte P0 individuelle (verdict détaillé)."""
    comp = verdict.get("matched_components", [{}])[0]
    return (
        f"🚨 <b>P0 — Action immédiate</b>\n\n"
        f"<code>{verdict['cve_id']}</code> (score {verdict.get('impact_score', '?')})\n"
        f"Composant: {comp.get('component_name', '?')} v{comp.get('installed_version', '?')}\n"
        f"Match reason: {comp.get('match_reason', '?')}\n"
        f"CISA KEV: {'OUI' if verdict.get('kev_listed') else 'non'}\n"
        f"Exposure: {verdict.get('exposure_detail', {})}\n\n"
        f"<b>Rationale:</b>\n<i>{verdict.get('rationale', '')}</i>\n\n"
        f"<i>Run: <code>cat state/inventory.json | jq</code> pour détails.</i>"
    )


def cve_action_buttons(cve_id: str) -> list[list[dict[str, str]]]:
    """
    Construit les 2 boutons inline pour une CVE:
      - "✅ OK — créer issue"  → callback_data: ack|CVE-XXXX-YYYY
      - "❌ Pas OK"            → callback_data: dismiss|CVE-XXXX-YYYY

    Le préfixe (ack| / dismiss|) est dispatché par callback_handler.
    La limite Telegram callback_data = 64 bytes (CVE-2025-XXXXX = 13 chars → OK).
    """
    if len(cve_id.encode("utf-8")) > 50:
        # Garde-fou: nos CVE IDs font <20 chars, mais on valide quand même
        raise ValueError(f"cve_id trop long pour callback_data: {cve_id!r}")
    return [[
        {"text": "✅ OK — créer issue", "callback_data": f"ack|{cve_id}"},
        {"text": "❌ Pas OK",            "callback_data": f"dismiss|{cve_id}"},
    ]]


def format_p0_alert_with_buttons(verdict: dict) -> tuple[str, list[list[dict[str, str]]]]:
    """Formate une alerte P0 + ses 2 boutons. Retourne (text, buttons)."""
    return format_p0_alert(verdict), cve_action_buttons(verdict["cve_id"])

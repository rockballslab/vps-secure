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

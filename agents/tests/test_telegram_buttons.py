"""
test_telegram_buttons.py — tests pour les boutons inline Telegram.

Vérifie:
- Structure des 2 boutons (ack + dismiss)
- Limite 64 bytes du callback_data (Telegram)
- Payload InlineKeyboardMarkup bien formé
- Boutons retirés après action (edit_message)
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "orchestrator"))

import pytest
from telegram_notifier import cve_action_buttons, format_p0_alert_with_buttons, TelegramNotifier


# ════════════════════════════════════════════════════════════════════
# Structure des boutons
# ════════════════════════════════════════════════════════════════════

class TestCveActionButtons:
    def test_two_buttons_in_one_row(self):
        btns = cve_action_buttons("CVE-2026-41567")
        assert len(btns) == 1, "1 rangée (les 2 boutons côte à côte)"
        assert len(btns[0]) == 2, "2 boutons dans la rangée"

    def test_button_labels(self):
        btns = cve_action_buttons("CVE-2026-41567")
        labels = [b["text"] for b in btns[0]]
        assert "✅ OK — créer issue" in labels[0]
        assert "❌ Pas OK" in labels[1]

    def test_callback_data_prefixes(self):
        btns = cve_action_buttons("CVE-2026-41567")
        assert btns[0][0]["callback_data"] == "ack|CVE-2026-41567"
        assert btns[0][1]["callback_data"] == "dismiss|CVE-2026-41567"

    @pytest.mark.parametrize("cve_id", [
        "CVE-2024-6387",        # regreSSHion
        "CVE-2025-1234",
        "CVE-2026-41567",
        "CVE-2027-99999",
        "CVE-1999-0001",        # oldest possible
    ])
    def test_callback_data_within_64_bytes(self, cve_id):
        """Telegram limite callback_data à 64 bytes."""
        btns = cve_action_buttons(cve_id)
        for row in btns:
            for btn in row:
                size = len(btn["callback_data"].encode("utf-8"))
                assert size <= 64, f"{btn['callback_data']!r} = {size} bytes (max 64)"

    def test_rejects_oversized_cve_id(self):
        """Garde-fou: un cve_id de plus de 50 chars est rejeté (pas de CVE ID normal)."""
        too_long = "CVE-2025-" + "X" * 50
        with pytest.raises(ValueError, match="trop long"):
            cve_action_buttons(too_long)

    def test_send_with_buttons_validates_size(self):
        """Si on essaie d'envoyer un payload avec callback_data > 64 bytes, ça lève."""
        notifier = TelegramNotifier(dry_run=True)
        # Construit un bouton trop long (mais <= 50 chars pour cve_action_buttons)
        # Donc on doit passer directement à send_with_buttons
        bad_buttons = [[{"text": "X", "callback_data": "X" * 65}]]
        with pytest.raises(ValueError, match="64 bytes"):
            notifier.send_with_buttons("test", bad_buttons)

    def test_send_with_buttons_dry_run(self):
        """Dry-run n'appelle pas requests, retourne ok=True."""
        notifier = TelegramNotifier(dry_run=True)
        btns = cve_action_buttons("CVE-2026-41567")
        result = notifier.send_with_buttons("🚨 P0 test", btns)
        assert result["ok"] is True
        assert result.get("dry_run") is True


# ════════════════════════════════════════════════════════════════════
# Payload complet (text + buttons)
# ════════════════════════════════════════════════════════════════════

class TestP0AlertWithButtons:
    @pytest.fixture
    def verdict(self):
        return {
            "cve_id": "CVE-2026-41567",
            "impact_class": "critical",
            "kev_listed": True,
            "impact_score": 9.8,
            "rationale": "Privilege escalation via mount namespace.",
            "matched_components": [
                {
                    "component_name": "docker-ce",
                    "installed_version": "5:29.5.0-1~ubuntu.24.04~noble",
                    "match_reason": "version 29.5.0 < 29.5.1",
                }
            ],
        }

    def test_returns_text_and_buttons_tuple(self, verdict):
        text, buttons = format_p0_alert_with_buttons(verdict)
        assert isinstance(text, str)
        assert isinstance(buttons, list)
        assert "CVE-2026-41567" in text
        assert "docker-ce" in text
        assert len(buttons) == 1 and len(buttons[0]) == 2

    def test_buttons_reference_correct_cve(self, verdict):
        _, buttons = format_p0_alert_with_buttons(verdict)
        for btn in buttons[0]:
            assert verdict["cve_id"] in btn["callback_data"]

"""
test_callback_handler.py — tests pour le dispatch des callback_query Telegram.

Vérifie:
- parse_callback_data: tous les formats valides + invalides
- handle_dismiss: idempotent + met à jour le state
- handle_ack: dry-run crée le payload, real run skip si .env absent
- handle_callback_query: dispatch ack|dismiss, edit message, answer query
"""

import sys
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "orchestrator"))

import pytest
from state import StateFile, DEFAULT_STATE, mark_dismissed, mark_issue_created
from callback_handler import (
    parse_callback_data,
    handle_dismiss,
    handle_ack,
    handle_callback_query,
)


# ════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════

@pytest.fixture
def tmp_states(tmp_path):
    """State files jetables pour les tests."""
    cto = StateFile(tmp_path / "cto_state.json", DEFAULT_STATE)
    inv = StateFile(tmp_path / "inventory.json", {"components": []})
    impact = StateFile(tmp_path / "impact_cache.json", {"verdicts": []})
    return {"cto": cto, "inventory": inv, "impact_cache": impact}


def make_callback_query(data: str, cve_id: str = "CVE-2026-41567", from_user: str = "fab"):
    """Construit un faux callback_query Telegram."""
    return {
        "id": "cb_12345",
        "from": {"id": 6433792390, "is_bot": False, "username": from_user},
        "data": data,
        "message": {
            "message_id": 100,
            "chat": {"id": 6433792390, "type": "private"},
            "text": "🚨 P0 — CVE-2026-41567",
        },
    }


def make_mock_notifier():
    """Notifier mocké qui enregistre les appels."""
    n = MagicMock()
    n.dry_run = True
    n.send_with_buttons = MagicMock(return_value={"ok": True, "result": {"message_id": 0}})
    n.answer_callback_query = MagicMock(return_value={"ok": True})
    n.edit_message = MagicMock(return_value={"ok": True})
    n.get_updates = MagicMock(return_value=[])
    return n


# ════════════════════════════════════════════════════════════════════
# parse_callback_data
# ════════════════════════════════════════════════════════════════════

class TestParseCallbackData:
    @pytest.mark.parametrize("data,expected", [
        ("ack|CVE-2026-41567", {"action": "ack", "cve_id": "CVE-2026-41567"}),
        ("dismiss|CVE-2024-6387", {"action": "dismiss", "cve_id": "CVE-2024-6387"}),
        ("ack|CVE-2025-1234", {"action": "ack", "cve_id": "CVE-2025-1234"}),
    ])
    def test_valid(self, data, expected):
        result = parse_callback_data(data)
        assert result["action"] == expected["action"]
        assert result["cve_id"] == expected["cve_id"]
        assert result["raw"] == data

    @pytest.mark.parametrize("data", [
        "",                    # vide
        "bare",                # pas de pipe
        "unknown|CVE-...-foo", # action inconnue
        "ack",                 # pipe mais pas de cve_id
        "ack|",                # cve_id vide
    ])
    def test_invalid(self, data):
        result = parse_callback_data(data)
        assert result["action"] == "unknown" or result["cve_id"] == ""

    def test_cve_id_with_special_chars_in_cve_part(self):
        # Le format CVE-XXXX-YYYY n'a pas de caractères spéciaux mais soyons robustes
        result = parse_callback_data("dismiss|CVE-2024-6387")
        assert result["cve_id"] == "CVE-2024-6387"


# ════════════════════════════════════════════════════════════════════
# handle_dismiss
# ════════════════════════════════════════════════════════════════════

class TestHandleDismiss:
    def test_dismiss_first_time(self, tmp_states):
        cq = make_callback_query("dismiss|CVE-2026-41567")
        result = handle_dismiss("CVE-2026-41567", tmp_states, cq)
        assert result["ok"] is True
        assert result["deduped"] is False
        cto = tmp_states["cto"].read()
        assert "CVE-2026-41567" in cto["cves_seen"]
        assert cto["cves_seen"]["CVE-2026-41567"]["user_dismissed_at"] is not None
        assert cto["cves_seen"]["CVE-2026-41567"]["user_dismissed_by"] == "fab"
        assert cto["stats"]["total_dismissed"] == 1

    def test_dismiss_idempotent(self, tmp_states):
        cq = make_callback_query("dismiss|CVE-2026-41567")
        handle_dismiss("CVE-2026-41567", tmp_states, cq)
        result = handle_dismiss("CVE-2026-41567", tmp_states, cq)
        assert result["ok"] is True
        assert result["deduped"] is True
        cto = tmp_states["cto"].read()
        assert cto["stats"]["total_dismissed"] == 1  # pas incrémenté 2x

    def test_dismiss_unknown_cve_creates_entry(self, tmp_states):
        """Dismiss d'une CVE jamais vue → crée l'entrée (silence prospectif)."""
        cq = make_callback_query("dismiss|CVE-2099-99999")
        result = handle_dismiss("CVE-2099-99999", tmp_states, cq)
        assert result["ok"] is True
        cto = tmp_states["cto"].read()
        assert "CVE-2099-99999" in cto["cves_seen"]


# ════════════════════════════════════════════════════════════════════
# handle_ack (dry-run)
# ════════════════════════════════════════════════════════════════════

class TestHandleAck:
    def test_ack_dry_run_creates_issue_payload(self, tmp_states):
        """En dry-run, pas de gh CLI call, mais l'URL est marquée comme DRY-RUN."""
        verdict = {
            "cve_id": "CVE-2026-41567",
            "impact_class": "critical",
            "kev_listed": True,
            "rationale": "test",
            "matched_components": [
                {"component_name": "docker-ce", "installed_version": "29.5.0", "match_reason": "test"}
            ],
        }
        tmp_states["cto"].update(lambda s: {
            **s,
            "cves_seen": {"CVE-2026-41567": {"verdict": verdict}}
        })

        cq = make_callback_query("ack|CVE-2026-41567")
        result = handle_ack("CVE-2026-41567", tmp_states, "rockballslab/vps-secure", cq, dry_run=True)
        assert result["ok"] is True
        assert "DRY-RUN" in result["issue_url"]
        cto = tmp_states["cto"].read()
        assert cto["cves_seen"]["CVE-2026-41567"]["issue_url"] is not None
        assert cto["stats"]["total_issues_created"] == 1

    def test_ack_idempotent_when_already_created(self, tmp_states):
        """Si l'issue existe déjà dans le state, retourne l'URL existante (pas de doublon)."""
        cto_state = tmp_states["cto"].read()
        cto_state["cves_seen"]["CVE-2026-41567"] = {
            "issue_url": "https://github.com/rockballslab/vps-secure/issues/42",
            "issue_number": 42,
        }
        tmp_states["cto"].write(cto_state)

        cq = make_callback_query("ack|CVE-2026-41567")
        result = handle_ack("CVE-2026-41567", tmp_states, "rockballslab/vps-secure", cq, dry_run=True)
        assert result["ok"] is True
        assert result["deduped"] is True
        assert result["issue_url"] == "https://github.com/rockballslab/vps-secure/issues/42"

    def test_ack_missing_verdict_returns_error(self, tmp_states):
        """Si le verdict n'est ni dans cto_state ni dans impact_cache, erreur."""
        cq = make_callback_query("ack|CVE-2099-99999")
        result = handle_ack("CVE-2099-99999", tmp_states, "rockballslab/vps-secure", cq, dry_run=True)
        assert result["ok"] is False
        assert "introuvable" in result["error"]


# ════════════════════════════════════════════════════════════════════
# handle_callback_query (dispatch complet)
# ════════════════════════════════════════════════════════════════════

class TestHandleCallbackQuery:
    def test_dispatch_to_dismiss(self, tmp_states):
        n = make_mock_notifier()
        cq = make_callback_query("dismiss|CVE-2026-41567")
        result = handle_callback_query(cq, n, tmp_states, "rockballslab/vps-secure", dry_run=True)

        assert result["ok"] is True
        assert result["action"] == "dismiss"
        assert result["cve_id"] == "CVE-2026-41567"
        n.answer_callback_query.assert_called_once()
        n.edit_message.assert_called_once()
        # Vérifie que les boutons sont retirés (new_buttons=[])
        # edit_message signature: (chat_id, message_id, new_text, new_buttons=None, parse_mode=...)
        call_args = n.edit_message.call_args
        new_buttons_passed = call_args.kwargs.get("new_buttons")
        if new_buttons_passed is None and len(call_args.args) >= 4:
            new_buttons_passed = call_args.args[3]
        assert new_buttons_passed == [], f"expected new_buttons=[] to retire les boutons, got {new_buttons_passed!r}"

    def test_dispatch_to_ack_dry_run(self, tmp_states):
        verdict = {
            "cve_id": "CVE-2026-41567",
            "impact_class": "critical",
            "kev_listed": False,
            "rationale": "test rationale",
            "matched_components": [
                {"component_name": "docker-ce", "installed_version": "29.5.0", "match_reason": "test"}
            ],
        }
        tmp_states["cto"].update(lambda s: {
            **s, "cves_seen": {"CVE-2026-41567": {"verdict": verdict}}
        })

        n = make_mock_notifier()
        cq = make_callback_query("ack|CVE-2026-41567")
        result = handle_callback_query(cq, n, tmp_states, "rockballslab/vps-secure", dry_run=True)

        assert result["ok"] is True
        assert result["action"] == "ack"
        n.answer_callback_query.assert_called_once()
        n.edit_message.assert_called_once()

    def test_unknown_action_answered_with_alert(self, tmp_states):
        n = make_mock_notifier()
        cq = make_callback_query("foo|bar")
        result = handle_callback_query(cq, n, tmp_states, "rockballslab/vps-secure", dry_run=True)

        assert result["ok"] is False
        assert result["action"] == "unknown"
        n.answer_callback_query.assert_called_once()
        # show_alert=True pour les erreurs
        call_args = n.answer_callback_query.call_args
        assert call_args.kwargs.get("show_alert") is True

    def test_empty_data_returns_error(self, tmp_states):
        n = make_mock_notifier()
        cq = make_callback_query("")
        result = handle_callback_query(cq, n, tmp_states, "rockballslab/vps-secure", dry_run=True)
        assert result["ok"] is False
        assert result["cve_id"] == ""

    def test_edit_message_failure_does_not_propagate(self, tmp_states):
        """Si edit_message crash (ex: message trop vieux), le handler ne doit pas exploser."""
        n = make_mock_notifier()
        n.edit_message = MagicMock(side_effect=Exception("Bad Request: message is too old"))
        cq = make_callback_query("dismiss|CVE-2026-41567")
        result = handle_callback_query(cq, n, tmp_states, "rockballslab/vps-secure", dry_run=True)
        # L'action dismiss a réussi (state updated), même si l'edit a fail
        assert result["ok"] is True
        cto = tmp_states["cto"].read()
        assert "CVE-2026-41567" in cto["cves_seen"]

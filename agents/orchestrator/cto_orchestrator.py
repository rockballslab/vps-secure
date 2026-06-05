"""
cto_orchestrator.py — chef d'orchestre du système multi-agents vps-secure.

Flow quotidien (07:30 Europe/Paris):
  1. STACK_INVENTORY.collect()  → state/inventory.json
  2. CVE_WATCHER.collect()     → state/cve_watch.json
  3. Pour chaque CVE brute → IMPACT_ASSESSOR.assess() → verdict
  4. Filtre verdicts (P0/P1 uniquement)
  5. Debounce check vs cto_state.json
  6. TelegramNotifier: digest quotidien + alertes individuelles P0

CLI:
  python3 cto_orchestrator.py run          # run complet
  python3 cto_orchestrator.py run --dry    # sans LLM/Telegram (default si DRY_RUN=true)
  python3 cto_orchestrator.py inventory    # juste l'inventaire
  python3 cto_orchestrator.py digest       # regenere le digest depuis les state files
  python3 cto_orchestrator.py ack <cve_id> # acquitte une CVE
  python3 cto_orchestrator.py status       # affiche les stats
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Permet l'import depuis n'importe quel cwd
sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
from inventory import collect as collect_inventory
from cve_watcher import collect as collect_cves
from impact_assessor import assess as assess_cve
from telegram_notifier import TelegramNotifier, format_digest, format_p0_alert
from state import StateFile, DEFAULT_STATE, now_utc_iso, debounce_check


PROJECT_ROOT = Path(__file__).parent.parent
CANON_PATH = PROJECT_ROOT / "canon" / "STACK_CANON.md"
STATE_DIR = Path(os.environ.get("STATE_DIR", PROJECT_ROOT / "state"))


def _get_state_files() -> dict[str, StateFile]:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    return {
        "cto": StateFile(STATE_DIR / "cto_state.json", DEFAULT_STATE),
        "inventory": StateFile(STATE_DIR / "inventory.json", {}),
        "cve_watch": StateFile(STATE_DIR / "cve_watch.json", {}),
    }


def step_inventory(states: dict[str, StateFile]) -> dict:
    """Étape 1: STACK_INVENTORY.collect()"""
    print("[1/4] STACK_INVENTORY.collect()")
    inv = collect_inventory(CANON_PATH)
    inv["trigger"] = "cron_daily"
    states["inventory"].write(inv)
    print(f"  → {len(inv['components'])} composants, {len(inv['containers'])} containers, {len(inv['listening_ports'])} ports")
    if inv.get("drift_detected"):
        print("  ⚠️  DRIFT: install.sh non trouvé localement (custom install?)")
    if inv.get("unknown_versions"):
        print(f"  ⚠️  {len(inv['unknown_versions'])} version(s) inconnue(s)")
    return inv


def step_cve_watch(states: dict[str, StateFile], window_hours: int = 24) -> dict:
    """Étape 2: CVE_WATCHER.collect()"""
    print(f"[2/4] CVE_WATCHER.collect() — window={window_hours}h")
    cves = collect_cves(CANON_PATH, window_hours=window_hours)
    states["cve_watch"].write(cves)
    print(f"  → {cves['cves_total_raw']} brutes → {cves['cves_after_dedup']} dédoublonnées → {cves['cves_after_prefilter']} après préfiltre")
    print(f"  Sources fetched: {cves['sources_fetched']}")
    if cves["sources_failed"]:
        print(f"  ⚠️  Sources KO: {cves['sources_failed']}")
    return cves


def step_assess(cve_watch: dict, inventory: dict) -> list[dict]:
    """Étape 3: IMPACT_ASSESSOR.assess() pour chaque CVE."""
    print(f"[3/4] IMPACT_ASSESSOR.assess() — {cve_watch['cves_after_prefilter']} CVE")
    verdicts = []
    for cve in cve_watch["cves"]:
        verdict = assess_cve(cve, inventory)
        if verdict.get("matched"):
            verdicts.append(verdict)
    matched = sum(1 for v in verdicts if v.get("matched"))
    print(f"  → {matched} matchent la stack")
    classes = {}
    for v in verdicts:
        c = v.get("impact_class", "?")
        classes[c] = classes.get(c, 0) + 1
    for c, n in sorted(classes.items(), key=lambda x: -x[1]):
        print(f"     {c}: {n}")
    return verdicts


def step_notify(verdicts: list[dict], inventory: dict, cve_watch: dict, states: dict[str, StateFile], dry_run: bool) -> None:
    """Étape 4: Telegram digest + alertes P0."""
    print("[4/4] TelegramNotifier")
    notifier = TelegramNotifier(dry_run=dry_run)
    stats = {
        "date": datetime.now().strftime("%Y-%m-%d"),
        "components_count": len(inventory["components"]),
        "containers_count": len(inventory.get("containers", [])),
        "ports_count": len(inventory.get("listening_ports", [])),
        "sources_fetched": cve_watch["sources_fetched"],
        "sources_failed": cve_watch["sources_failed"],
        "p3_count": cve_watch["cves_total_raw"] - len(verdicts),
    }

    # Filtre verdicts P0/P1
    notifiable = [
        v for v in verdicts
        if v.get("impact_class") in ("critical", "high")
    ]
    print(f"  → {len(notifiable)} verdicts P0/P1 à notifier (avant debounce)")

    # Debounce check via cto_state
    cto = states["cto"].read()
    to_send: list[dict] = []
    for v in notifiable:
        cid = v.get("matched_components", [{}])[0].get("component_id", "?")
        if debounce_check(cto, v["cve_id"], cid):
            to_send.append(v)
    print(f"  → {len(to_send)} après debounce")

    # Envoi digest groupé
    digest_text = format_digest(verdicts, stats)
    notifier.send(digest_text)
    print("  → digest envoyé")

    # Envoi alertes individuelles P0
    p0 = [v for v in to_send if v.get("impact_class") == "critical"]
    for v in p0[:3]:  # cap à 3 P0 détaillés
        notifier.send(format_p0_alert(v))
    if p0:
        print(f"  → {len(p0[:3])} alertes P0 individuelles envoyées")

    # Update state
    cto["last_run"] = now_utc_iso()
    cto["stats"]["total_runs"] += 1
    cto["stats"]["total_cves_processed"] += len(verdicts)
    cto["stats"]["total_notifications_sent"] += len(to_send) + 1
    for v in to_send:
        cid = v.get("matched_components", [{}])[0].get("component_id", "?")
        cto["cves_seen"].setdefault(v["cve_id"], {
            "first_seen": now_utc_iso(),
            "last_notified": now_utc_iso(),
            "class": v.get("impact_class"),
            "component_id": cid,
            "user_acked_at": None,
            "user_snoozed_until": None,
            "fix_applied_at": None,
        })
        cto["cves_seen"][v["cve_id"]]["last_notified"] = now_utc_iso()
    states["cto"].write(cto)
    print(f"  → state updated: {len(cto['cves_seen'])} CVE vues au total")


def cmd_run(args) -> int:
    """Run complet: inventaire + cve + assess + notify."""
    dry_run = args.dry or os.environ.get("DRY_RUN", "false").lower() == "true" or not os.environ.get("TELEGRAM_BOT_TOKEN")
    window_hours = int(os.environ.get("CVE_WINDOW_HOURS", "24"))
    if dry_run:
        print("=== DRY RUN MODE ===\n")
    if window_hours != 24:
        print(f"=== WINDOW: {window_hours}h (override via CVE_WINDOW_HOURS) ===\n")
    states = _get_state_files()
    inv = step_inventory(states)
    cve_watch = step_cve_watch(states, window_hours=window_hours)
    verdicts = step_assess(cve_watch, inv)
    step_notify(verdicts, inv, cve_watch, states, dry_run)
    print("\n=== DONE ===")
    return 0


def cmd_inventory(args) -> int:
    states = _get_state_files()
    inv = step_inventory(states)
    print(json.dumps(inv, indent=2, ensure_ascii=False)[:3000])
    return 0


def cmd_digest(args) -> int:
    states = _get_state_files()
    inv = states["inventory"].read()
    cve_watch = states["cve_watch"].read()
    if not inv or not cve_watch:
        print("ERREUR: state files vides. Run 'inventory' et 'run' d'abord.")
        return 1
    verdicts = step_assess(cve_watch, inv)
    dry_run = os.environ.get("DRY_RUN", "false").lower() == "true"
    step_notify(verdicts, inv, cve_watch, states, dry_run)
    return 0


def cmd_ack(args) -> int:
    states = _get_state_files()
    cto = states["cto"].read()
    cve_id = args.cve_id
    if cve_id not in cto["cves_seen"]:
        print(f"CVE {cve_id} pas dans le state (jamais notifiée?).")
        return 1
    cto["cves_seen"][cve_id]["user_acked_at"] = now_utc_iso()
    states["cto"].write(cto)
    print(f"✓ {cve_id} acquittée.")
    return 0


def cmd_status(args) -> int:
    states = _get_state_files()
    cto = states["cto"].read()
    inv = states["inventory"].read()
    cve_watch = states["cve_watch"].read()
    print(json.dumps({
        "last_run": cto.get("last_run"),
        "stats": cto.get("stats"),
        "cves_seen_count": len(cto.get("cves_seen", {})),
        "inventory_loaded": bool(inv),
        "components_in_inventory": len(inv.get("components", [])) if inv else 0,
        "last_cve_watch": cve_watch.get("fetch_window"),
    }, indent=2, ensure_ascii=False))
    return 0


def main():
    load_dotenv(PROJECT_ROOT / ".env")
    p = argparse.ArgumentParser(description="vps-secure-agents orchestrator")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("run", help="Run complet (inventaire + cve + assess + notify)").add_argument("--dry", action="store_true")
    sub.add_parser("inventory", help="Collecte juste l'inventaire")
    sub.add_parser("digest", help="Regénère un digest depuis le state actuel")
    ack_p = sub.add_parser("ack", help="Acquitte une CVE")
    ack_p.add_argument("cve_id")
    sub.add_parser("status", help="Affiche les stats du state")

    args = p.parse_args()
    return {
        "run": cmd_run,
        "inventory": cmd_inventory,
        "digest": cmd_digest,
        "ack": cmd_ack,
        "status": cmd_status,
    }[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())

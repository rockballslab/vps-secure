"""
telegram_polling.py — boucle de long-polling pour les callback_query Telegram.

Après l'envoi du digest quotidien, le bot reste en vie ~24h pour traiter
les clics sur les boutons inline. Au prochain cron (07:30 suivant), il sort
proprement.

Caractéristiques:
  - Long-polling getUpdates avec allowed_updates=["callback_query"]
  - Offset auto-incrémenté (ack implicite)
  - Graceful shutdown via SIGTERM/SIGINT
  - Lock file pour éviter 2 instances simultanées
  - Stop après `max_runtime_seconds` (défaut 86340 = 23h59)
"""

import logging
import os
import signal
import sys
import time
import fcntl
from pathlib import Path
from datetime import datetime, timezone

from telegram_notifier import TelegramNotifier
from callback_handler import handle_callback_query

log = logging.getLogger("polling")


# ════════════════════════════════════════════════════════════════════
# Lock file (empêche 2 instances de poll en même temps)
# ════════════════════════════════════════════════════════════════════

def _acquire_lock(lock_path: Path) -> int | None:
    """Pose un lock non-bloquant. Retourne le fd ou None si déjà verrouillé."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    # Stocke le PID pour debug
    os.write(fd, f"{os.getpid()}\n".encode())
    os.fsync(fd)
    return fd


def _release_lock(fd: int | None, lock_path: Path):
    if fd is not None:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        except OSError:
            pass
    if lock_path.exists():
        try:
            lock_path.unlink()
        except OSError:
            pass


# ════════════════════════════════════════════════════════════════════
# Polling loop
# ════════════════════════════════════════════════════════════════════

class PollingStop(Exception):
    """Sortie propre de la boucle (utilisée par les handlers de signaux)."""
    pass


def _setup_signals(stop_flag: dict):
    def _handle(signum, frame):
        log.info("signal %d reçu, arrêt du polling...", signum)
        stop_flag["stop"] = True
        raise PollingStop()
    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)


def run_polling_loop(
    notifier: TelegramNotifier,
    states: dict,
    repo: str,
    lock_path: Path,
    max_runtime_seconds: int = 86340,  # 23h59
    poll_timeout: int = 30,
    dry_run: bool = False,
) -> dict:
    """
    Boucle principale de polling.

    Returns: {"ok": bool, "updates_handled": N, "errors": N, "duration_s": N}
    """
    fd = _acquire_lock(lock_path)
    if fd is None:
        log.error("lock file %s déjà pris — une autre instance poll déjà, abandon", lock_path)
        return {"ok": False, "error": "lock_contention", "updates_handled": 0}

    stop_flag = {"stop": False}
    _setup_signals(stop_flag)

    start_ts = time.time()
    updates_handled = 0
    errors = 0
    offset: int | None = None

    log.info("polling démarré, max_runtime=%ds, poll_timeout=%ds, dry_run=%s",
             max_runtime_seconds, poll_timeout, dry_run)

    try:
        while not stop_flag["stop"]:
            elapsed = time.time() - start_ts
            if elapsed >= max_runtime_seconds:
                log.info("max_runtime atteint (%.0fs), arrêt propre", elapsed)
                break

            try:
                updates = notifier.get_updates(
                    offset=offset,
                    timeout=poll_timeout,
                    allowed_updates=["callback_query"],
                )
            except Exception as e:
                # Erreur réseau / API transitoire — log + retry
                log.warning("get_updates error: %s", e)
                errors += 1
                time.sleep(2)
                continue

            for upd in updates:
                offset = upd["update_id"] + 1
                callback_query = upd.get("callback_query")
                if not callback_query:
                    continue
                try:
                    result = handle_callback_query(
                        callback_query=callback_query,
                        notifier=notifier,
                        states=states,
                        repo=repo,
                        dry_run=dry_run,
                    )
                    updates_handled += 1
                    log.info("callback traité: %s", result)
                except Exception as e:
                    log.exception("handle_callback_query a crashé: %s", e)
                    errors += 1
                    # Important: answer_callback_query pour pas spinner le user
                    try:
                        notifier.answer_callback_query(
                            callback_query.get("id", ""),
                            "Erreur interne — voir logs.",
                            show_alert=True,
                        )
                    except Exception:
                        pass

    except PollingStop:
        pass
    finally:
        _release_lock(fd, lock_path)

    duration = time.time() - start_ts
    return {
        "ok": errors == 0,
        "updates_handled": updates_handled,
        "errors": errors,
        "duration_s": round(duration, 1),
        "stopped_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


# ════════════════════════════════════════════════════════════════════
# CLI entry point (pour debug)
# ════════════════════════════════════════════════════════════════════

def main():
    import argparse
    p = argparse.ArgumentParser(description="vps-secure-agents Telegram polling")
    p.add_argument("--max-runtime", type=int, default=86340, help="secondes (défaut 23h59)")
    p.add_argument("--poll-timeout", type=int, default=30, help="getUpdates long-poll timeout (max 50)")
    p.add_argument("--dry-run", action="store_true", help="n'envoie rien à Telegram/GitHub")
    p.add_argument("--log-level", default="INFO")
    args = p.parse_args()

    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    # Charge .env si dispo
    try:
        from dotenv import load_dotenv
        from pathlib import Path
        load_dotenv(Path(__file__).parent.parent / ".env")
    except ImportError:
        pass

    # Import tardif pour éviter circularité au test
    from state import StateFile
    from cto_orchestrator import _get_state_files  # type: ignore

    states = _get_state_files()
    dry_run = args.dry_run or os.environ.get("DRY_RUN", "false").lower() == "true"

    notifier = TelegramNotifier(dry_run=dry_run)
    repo = os.environ.get("GITHUB_REPO", "rockballslab/vps-secure")
    lock_path = Path(os.environ.get("STATE_DIR", "/home/vpsadmin/vps-secure-agents/state")) / ".polling.lock"

    result = run_polling_loop(
        notifier=notifier,
        states=states,
        repo=repo,
        lock_path=lock_path,
        max_runtime_seconds=args.max_runtime,
        poll_timeout=args.poll_timeout,
        dry_run=dry_run,
    )
    print(result)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())

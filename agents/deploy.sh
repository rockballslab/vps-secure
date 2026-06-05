#!/usr/bin/env bash
# deploy.sh — installe les dépendances + crée le cron job pour vps-secure-agents
# Usage: ./deploy.sh [--no-cron]
#
# Crée un venv uv, installe les deps, et ajoute une ligne cron à 07:30 Europe/Paris.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$PROJECT_DIR/.venv"
LOG_DIR="${LOG_DIR:-/var/log/vps-secure-agents}"
CRON_TZ="Europe/Paris"
CRON_SCHEDULE="30 7 * * *"
CRON_CMD="cd $PROJECT_DIR && CRON_TZ=$CRON_TZ $VENV_DIR/bin/python orchestrator/cto_orchestrator.py run >> $LOG_DIR/orchestrator.log 2>&1"
CRON_TAG="# vps-secure-agents — auto-deployed by deploy.sh"

SKIP_CRON=0
for arg in "$@"; do
    case $arg in
        --no-cron) SKIP_CRON=1 ;;
        *) echo "Unknown arg: $arg" && exit 1 ;;
    esac
done

echo "=== vps-secure-agents — deploy ==="
echo "Project: $PROJECT_DIR"
echo "Log dir: $LOG_DIR"

# 1. venv + deps
if [ ! -d "$VENV_DIR" ]; then
    echo "[1/4] Création du venv uv..."
    if command -v uv &>/dev/null; then
        uv venv "$VENV_DIR" --python python3.12
    else
        python3.12 -m venv "$VENV_DIR"
    fi
else
    echo "[1/4] venv déjà présent: $VENV_DIR"
fi

echo "[2/4] Installation des dépendances..."
if command -v uv &>/dev/null; then
    uv pip install --python "$VENV_DIR/bin/python" -r "$PROJECT_DIR/requirements.txt"
else
    "$VENV_DIR/bin/pip" install -r "$PROJECT_DIR/requirements.txt"
fi

# 2. .env
if [ ! -f "$PROJECT_DIR/.env" ]; then
    echo "[3/4] Création du .env (à compléter manuellement avec OPENROUTER_API_KEY, TELEGRAM_*)..."
    cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
    echo "  ⚠️  ÉDITE $PROJECT_DIR/.env MAINTENANT:"
    echo "      OPENROUTER_API_KEY, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID"
else
    echo "[3/4] .env déjà présent"
fi

# 3. log dir
mkdir -p "$LOG_DIR"
touch "$LOG_DIR/orchestrator.log"

# 4. cron
if [ $SKIP_CRON -eq 0 ]; then
    echo "[4/4] Installation du cron job..."
    CURRENT_CRONTAB=$(crontab -l 2>/dev/null || true)
    if echo "$CURRENT_CRONTAB" | grep -q "$CRON_TAG"; then
        echo "  Cron job déjà présent. Skipping."
    else
        (echo "$CURRENT_CRONTAB"; echo ""; echo "$CRON_TAG"; echo "CRON_TZ=$CRON_TZ $CRON_CMD") | crontab -
        echo "  ✓ Cron installé: $CRON_SCHEDULE (TZ=$CRON_TZ)"
        crontab -l | grep -A1 "$CRON_TAG"
    fi
else
    echo "[4/4] --no-cron: cron non installé. À ajouter manuellement si besoin."
fi

echo ""
echo "=== DEPLOY DONE ==="
echo "Test manuel: cd $PROJECT_DIR && $VENV_DIR/bin/python orchestrator/cto_orchestrator.py status"
echo "Dry-run:     cd $PROJECT_DIR && $VENV_DIR/bin/python orchestrator/cto_orchestrator.py run --dry"
echo "Run complet: cd $PROJECT_DIR && $VENV_DIR/bin/python orchestrator/cto_orchestrator.py run"

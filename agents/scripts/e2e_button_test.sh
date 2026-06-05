#!/usr/bin/env bash
# Helper pour lancer le E2E test des boutons inline.
# Ajuste POLL_SECS si tu veux plus de temps pour cliquer.
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHONPATH=agents/orchestrator \
  POLL_SECS="${POLL_SECS:-90}" \
  /home/vpsadmin/vps-secure-agents/.venv/bin/python \
  agents/scripts/e2e_button_test.py

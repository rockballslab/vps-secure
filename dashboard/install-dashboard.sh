#!/usr/bin/env bash
# install-dashboard.sh — VPS Secure Monitor
# Usage : bash <(curl -fsSL https://raw.githubusercontent.com/rockballslab/vps-secure/main/dashboard/install-dashboard.sh)
set -euo pipefail

REPO="https://raw.githubusercontent.com/rockballslab/vps-secure/main/dashboard"
DEST="$HOME/vps-monitor"

# ── Dépendances ───────────────────────────────────────────────────────────────
command -v docker  >/dev/null 2>&1      || { echo "✗ Docker requis."; exit 1; }
docker compose version >/dev/null 2>&1  || { echo "✗ Docker Compose v2 requis."; exit 1; }
command -v curl    >/dev/null 2>&1      || { echo "✗ curl requis."; exit 1; }
command -v python3 >/dev/null 2>&1      || { echo "✗ python3 requis."; exit 1; }

# ── Téléchargement ────────────────────────────────────────────────────────────
echo "→ Téléchargement des fichiers dashboard..."
mkdir -p "$DEST/api" "$DEST/frontend"

curl -fsSL "$REPO/api/app.py"               -o "$DEST/api/app.py"
curl -fsSL "$REPO/api/Dockerfile"           -o "$DEST/api/Dockerfile"
curl -fsSL "$REPO/frontend/index.html"      -o "$DEST/frontend/index.html"
curl -fsSL "$REPO/frontend/login.html"      -o "$DEST/frontend/login.html"
curl -fsSL "$REPO/docker-compose.yml"       -o "$DEST/docker-compose.yml"
curl -fsSL "$REPO/Caddyfile"                -o "$DEST/Caddyfile"

echo "✓ Fichiers téléchargés dans $DEST"

# ── Config ────────────────────────────────────────────────────────────────────
echo ""
read -rp  "Domaine du dashboard (ex: monvps.example.com) : " DOMAIN
read -rsp "Mot de passe dashboard : " PASS; echo ""
read -rsp "Confirmer le mot de passe : " PASS2; echo ""

if [[ "$PASS" != "$PASS2" ]]; then
  echo "✗ Les mots de passe ne correspondent pas."; exit 1
fi
if [[ ${#PASS} -lt 8 ]]; then
  echo "✗ Mot de passe trop court (minimum 8 caractères)."; exit 1
fi

# ── Hash bcrypt — écrit directement dans Caddyfile via Python3 ───────────────
# (évite le bug $$ de docker compose qui tronque les variables contenant $)
echo "→ Génération du hash bcrypt..."
HASH=$(docker run --rm caddy:2-alpine caddy hash-password --plaintext "$PASS") \
  || { echo "✗ Échec génération hash (docker run caddy)."; exit 1; }
[[ -z "$HASH" ]] && { echo "✗ Hash vide — vérifier l'accès à Docker Hub."; exit 1; }

# Patch Caddyfile avec domaine + hash via Python3 (pas de sed, pas de problème $/\)
python3 - "$DEST/Caddyfile" "$DOMAIN" "$HASH" <<'PYEOF'
import sys
path, domain, hash_val = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as f:
    content = f.read()
content = content.replace('VPS_DOMAIN', domain)
content = content.replace('HASH_PLACEHOLDER', hash_val)
with open(path, 'w') as f:
    f.write(content)
PYEOF

# Patch index.html avec le domaine
python3 - "$DEST/frontend/index.html" "$DOMAIN" <<'PYEOF'
import sys
path, domain = sys.argv[1], sys.argv[2]
with open(path) as f:
    content = f.read()
content = content.replace('VPS_DOMAIN', domain)
with open(path, 'w') as f:
    f.write(content)
PYEOF

# ── Auto-détection Endlessh ───────────────────────────────────────────────────
ENDLESSH_NAME=$(docker ps --format '{{.Names}}' | grep -i endlessh | head -1) || true
ENDLESSH_NAME="${ENDLESSH_NAME:-endlessh}"
echo "→ Container Endlessh : $ENDLESSH_NAME"

# ── Auto-détection CrowdSec + génération clé API ─────────────────────────────
CS_KEY=""
CROWDSEC_NAME="crowdsec"

CROWDSEC_CONTAINER=$(docker ps --format '{{.Names}}' | grep -i crowdsec | head -1) || true

if [[ -n "$CROWDSEC_CONTAINER" ]]; then
  echo "→ CrowdSec détecté en container : $CROWDSEC_CONTAINER"
  CROWDSEC_NAME="$CROWDSEC_CONTAINER"
  CS_KEY=$(docker exec "$CROWDSEC_CONTAINER" cscli bouncers add vps-dashboard 2>/dev/null \
    | grep -oE '[a-zA-Z0-9]{32,}' | tail -1) || true  # optionnel : peut échouer si déjà existant
else
  echo "→ CrowdSec détecté en service système"
  CS_KEY=$(sudo cscli bouncers add vps-dashboard 2>/dev/null \
    | grep -oE '[a-zA-Z0-9]{32,}' | tail -1) || true
fi

if [[ -z "$CS_KEY" ]]; then
  echo "⚠ Clé CrowdSec non générée automatiquement (bouncer existant ?)."
  echo "  Pour la créer manuellement : sudo cscli bouncers add vps-dashboard"
  echo "  Puis ajoute CROWDSEC_API_KEY=<clé> dans $DEST/.env"
fi

# ── .env ──────────────────────────────────────────────────────────────────────
cat > "$DEST/.env" <<EOF
# Mot de passe du dashboard (conservé ici en cas d'oubli)
DASHBOARD_PASS=$PASS

# CrowdSec
CROWDSEC_API_KEY=${CS_KEY:-}

# Noms des containers
ENDLESSH_CONTAINER=$ENDLESSH_NAME
CROWDSEC_CONTAINER=$CROWDSEC_NAME
EOF
chmod 600 "$DEST/.env"

# ── Fichier historique dashboard ─────────────────────────────────────────────
sudo touch /var/log/vps-monitor-history.json
sudo chmod 644 /var/log/vps-monitor-history.json

# ── Lancement ─────────────────────────────────────────────────────────────────
echo ""
echo "→ Build et démarrage des containers..."
cd "$DEST"
docker compose up -d --build

# ── Vérification ──────────────────────────────────────────────────────────────
echo ""
echo "→ Vérification des containers (attente 8s)..."
sleep 8

API_UP=0
CADDY_UP=0
docker ps --format '{{.Names}}' | grep -q "vps-monitor-api"   && API_UP=1
docker ps --format '{{.Names}}' | grep -q "vps-monitor-caddy" && CADDY_UP=1

if [[ $API_UP -eq 1 && $CADDY_UP -eq 1 ]]; then
  echo ""
  echo "✓ Dashboard disponible sur https://$DOMAIN"
  echo "  Login : admin / (mot de passe saisi)"
  echo "  Mot de passe sauvegardé dans : $DEST/.env"
  echo ""
  echo "  Commandes utiles :"
  echo "    docker compose -f $DEST/docker-compose.yml logs -f"
  echo "    docker compose -f $DEST/docker-compose.yml down"
else
  echo "⚠ Un ou plusieurs containers ne sont pas démarrés."
  echo "  Diagnostic : docker compose -f $DEST/docker-compose.yml logs"
  exit 1
fi

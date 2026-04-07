#!/usr/bin/env bash
# install-dashboard.sh — VPS Secure Monitor
# Usage : bash <(curl -fsSL https://raw.githubusercontent.com/rockballslab/vps-secure/main/dashboard/install-dashboard.sh)
set -euo pipefail

REPO="https://raw.githubusercontent.com/rockballslab/vps-secure/main/dashboard"
DEST="$HOME/vps-monitor"

# ── Dépendances ───────────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1       || { echo "✗ Docker requis."; exit 1; }
docker compose version >/dev/null 2>&1  || { echo "✗ Docker Compose v2 requis."; exit 1; }
command -v curl >/dev/null 2>&1         || { echo "✗ curl requis."; exit 1; }

# ── Téléchargement ────────────────────────────────────────────────────────────
echo "→ Téléchargement des fichiers dashboard..."
mkdir -p "$DEST/api" "$DEST/frontend"

curl -fsSL "$REPO/api/app.py"          -o "$DEST/api/app.py"
curl -fsSL "$REPO/api/Dockerfile"      -o "$DEST/api/Dockerfile"
curl -fsSL "$REPO/frontend/index.html" -o "$DEST/frontend/index.html"
curl -fsSL "$REPO/docker-compose.yml"  -o "$DEST/docker-compose.yml"
curl -fsSL "$REPO/Caddyfile"           -o "$DEST/Caddyfile"

echo "✓ Fichiers téléchargés dans $DEST"

# ── Config ────────────────────────────────────────────────────────────────────
echo ""
read -rp  "Domaine du dashboard (ex: monvps.aiforceone.fr) : " DOMAIN
read -rsp "Mot de passe dashboard : " PASS; echo ""
read -rsp "Confirmer le mot de passe : " PASS2; echo ""

if [[ "$PASS" != "$PASS2" ]]; then
  echo "✗ Les mots de passe ne correspondent pas."; exit 1
fi
if [[ ${#PASS} -lt 8 ]]; then
  echo "✗ Mot de passe trop court (minimum 8 caractères)."; exit 1
fi

echo "→ Génération du hash bcrypt..."
HASH=$(docker run --rm caddy:2-alpine caddy hash-password --plaintext "$PASS") \
  || { echo "✗ Échec génération hash (docker run caddy)."; exit 1; }
[[ -z "$HASH" ]] && { echo "✗ Hash vide — vérifier l'accès à Docker Hub."; exit 1; }

echo ""
read -rp "Clé API CrowdSec (Entrée pour ignorer → fallback docker exec) : " CS_KEY

read -rp "Nom du container Endlessh [endlessh] : " ENDLESSH_NAME
ENDLESSH_NAME="${ENDLESSH_NAME:-endlessh}"

read -rp "Nom du container CrowdSec [crowdsec] : " CROWDSEC_NAME
CROWDSEC_NAME="${CROWDSEC_NAME:-crowdsec}"

# ── .env ──────────────────────────────────────────────────────────────────────
cat > "$DEST/.env" <<EOF
DASHBOARD_USER=admin
DASHBOARD_PASS_HASH=$HASH
CROWDSEC_API_KEY=${CS_KEY:-}
ENDLESSH_CONTAINER=$ENDLESSH_NAME
CROWDSEC_CONTAINER=$CROWDSEC_NAME
EOF
chmod 600 "$DEST/.env"

# ── Caddyfile : patch domaine ─────────────────────────────────────────────────
ESCAPED_DOMAIN=$(printf '%s\n' "$DOMAIN" | sed 's/[\/&]/\\&/g')
sed -i "s/monvps\.aiforceone\.fr/$ESCAPED_DOMAIN/" "$DEST/Caddyfile"
sed -i "s/VPS_DOMAIN/$ESCAPED_DOMAIN/g"            "$DEST/frontend/index.html"

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
  echo "✓ Dashboard disponible sur https://$DOMAIN"
  echo "  Login : admin / [mot de passe saisi]"
  echo ""
  echo "  Commandes utiles :"
  echo "    docker compose -f $DEST/docker-compose.yml logs -f"
  echo "    docker compose -f $DEST/docker-compose.yml down"
else
  echo "⚠ Un ou plusieurs containers ne sont pas démarrés."
  echo "  Diagnostic : docker compose -f $DEST/docker-compose.yml logs"
  exit 1
fi

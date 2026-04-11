#!/usr/bin/env bash
# ============================================================
# install-n8n.sh — n8n + n8n-MCP sur VPS sécurisé vps-secure
#
# Ce script installe :
#   1. n8n          → https://n8n.aiforceone.fr
#   2. n8n-MCP      → https://mcpn8n.aiforceone.fr
#   3. Caddy        → HTTPS automatique pour les deux domaines
#
# Prérequis :
#   - vps-secure installé (Docker, UFW, Caddy en place)
#   - DNS A n8n.aiforceone.fr       → IP du VPS
#   - DNS A mcpn8n.aiforceone.fr    → IP du VPS
#
# Usage :
#   ssh vpsadmin@IP -p 2222
#   curl -O https://raw.githubusercontent.com/rockballslab/vps-secure/main/install-n8n.sh
#   chmod +x install-n8n.sh && sudo ./install-n8n.sh
# ============================================================
set -euo pipefail

_cleanup() {
    local exit_code=$?
    [[ $exit_code -ne 0 ]] && \
        echo -e "\n\033[1;33m[WARN]  Script interrompu — vérifie l'état du serveur.\033[0m" >&2
}
trap _cleanup EXIT

unset HISTFILE
umask 077

# ============================================================
# Couleurs et fonctions de log
# ============================================================
ROUGE='\033[0;31m'
VERT='\033[0;32m'
JAUNE='\033[1;33m'
BLANC='\033[0;37m'
GRAS='\033[1m'
RESET='\033[0m'

log_info()    { echo -e "${BLANC}[INFO]  $*${RESET}"; }
log_success() { echo -e "${VERT}[OK]    $*${RESET}"; }
log_warn()    { echo -e "${JAUNE}[WARN]  $*${RESET}"; }
log_error()   { echo -e "${ROUGE}[ERR]   $*${RESET}" >&2; }

etape() {
    local num="$1" total="$2" label="$3"
    echo -e "\n${GRAS}${VERT}[$num/$total] $label${RESET}"
    echo -e "${VERT}$(printf '─%.0s' {1..60})${RESET}"
}

# ============================================================
# Vérifications initiales
# ============================================================
if [[ "$(id -u)" -ne 0 ]]; then
    log_error "Ce script doit être lancé en ROOT (sudo)."
    exit 1
fi

if ! command -v docker &>/dev/null; then
    log_error "Docker non trouvé — lance d'abord install.sh de vps-secure."
    exit 1
fi

TOTAL_ETAPES=4
N8N_DATA_DIR="/home/vpsadmin/n8n"
N8N_PORT=5678
MCP_PORT=3000
N8N_DOMAIN="n8n.aiforceone.fr"
MCP_DOMAIN="mcpn8n.aiforceone.fr"

echo -e "${VERT}"
cat << 'EOF'
  ███╗   ██╗ █████╗ ███╗  ██╗
  ████╗  ██║██╔══██╗████╗ ██║
  ██╔██╗ ██║╚█████╔╝██╔██╗██║
  ██║╚██╗██║██╔══██╗██║╚████║
  ██║ ╚████║╚█████╔╝██║ ╚███║
  ╚═╝  ╚═══╝ ╚════╝ ╚═╝  ╚══╝  + MCP
EOF
echo -e "${RESET}"
echo -e "${BLANC}  n8n + n8n-MCP · vps-secure · github.com/rockballslab/vps-secure${RESET}"
echo -e "${VERT}$(printf '═%.0s' {1..60})${RESET}\n"

# ============================================================
# Étape 1 : Paramètres
# ============================================================
etape "1" "$TOTAL_ETAPES" "Configuration"

echo -e "${BLANC}  Ces valeurs seront utilisées pour configurer n8n et n8n-MCP.${RESET}"
echo ""

# Mot de passe n8n
read -rsp "  → Mot de passe admin n8n (sera haché — non visible) : " N8N_PASSWORD
echo ""
if [[ -z "$N8N_PASSWORD" ]] || [[ ${#N8N_PASSWORD} -lt 8 ]]; then
    log_error "Mot de passe trop court (minimum 8 caractères)."
    exit 1
fi

# Email admin n8n
read -rp "  → Email admin n8n : " N8N_EMAIL
if [[ ! "$N8N_EMAIL" =~ ^[^@]+@[^@]+\.[^@]+$ ]]; then
    log_error "Email invalide."
    exit 1
fi

# Token MCP (généré automatiquement si vide)
echo ""
echo -e "${BLANC}  Token d'authentification MCP (laisse vide pour auto-générer) :${RESET}"
read -rsp "  → Token MCP : " MCP_TOKEN
echo ""
if [[ -z "$MCP_TOKEN" ]]; then
    MCP_TOKEN=$(openssl rand -hex 32)
    log_info "Token MCP généré automatiquement."
fi

# Vérification DNS
echo ""
log_info "Vérification DNS des deux domaines..."
VPS_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}')

N8N_DNS=$(dig +short "$N8N_DOMAIN" 2>/dev/null | tail -1 || echo "")
MCP_DNS=$(dig +short "$MCP_DOMAIN" 2>/dev/null | tail -1 || echo "")

DNS_OK=true
if [[ "$N8N_DNS" != "$VPS_IP" ]]; then
    log_warn "$N8N_DOMAIN pointe vers '$N8N_DNS' — attendu : $VPS_IP"
    log_warn "  Caddy ne pourra pas obtenir le certificat SSL si le DNS n'est pas configuré."
    DNS_OK=false
fi
if [[ "$MCP_DNS" != "$VPS_IP" ]]; then
    log_warn "$MCP_DOMAIN pointe vers '$MCP_DNS' — attendu : $VPS_IP"
    DNS_OK=false
fi

if [[ "$DNS_OK" == "false" ]]; then
    echo ""
    read -rp "  DNS non configuré — continuer quand même ? (oui/non) : " dns_answer
    [[ "$dns_answer" == "oui" ]] || exit 1
else
    log_success "DNS OK — les deux domaines pointent vers $VPS_IP."
fi

# ============================================================
# Étape 2 : Répertoires et volumes
# ============================================================
etape "2" "$TOTAL_ETAPES" "Création des répertoires"

mkdir -p "$N8N_DATA_DIR"
chown -R vpsadmin:vpsadmin "$N8N_DATA_DIR"
chmod 750 "$N8N_DATA_DIR"
log_success "Répertoire n8n créé : $N8N_DATA_DIR"

# ============================================================
# Étape 3 : Docker — n8n + n8n-MCP
# ============================================================
etape "3" "$TOTAL_ETAPES" "Lancement des containers Docker"

# ── Arrêter les containers existants si présents ──
if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q '^n8n$'; then
    log_warn "Container n8n déjà présent — suppression."
    docker rm -f n8n 2>/dev/null || true
fi
if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q '^n8n-mcp$'; then
    log_warn "Container n8n-mcp déjà présent — suppression."
    docker rm -f n8n-mcp 2>/dev/null || true
fi

# ── Réseau Docker dédié ──
if ! docker network ls --format '{{.Name}}' | grep -q '^vps-secure-net$'; then
    docker network create vps-secure-net
    log_success "Réseau Docker vps-secure-net créé."
else
    log_info "Réseau Docker vps-secure-net déjà présent."
fi

# ── n8n ──
log_info "Lancement de n8n..."
docker run -d \
    --name n8n \
    --restart unless-stopped \
    --network vps-secure-net \
    --security-opt no-new-privileges:true \
    --cap-drop ALL \
    --cap-add CHOWN \
    --cap-add SETUID \
    --cap-add SETGID \
    --log-opt max-size=10m \
    --log-opt max-file=3 \
    -p 127.0.0.1:${N8N_PORT}:5678 \
    -v "${N8N_DATA_DIR}:/home/node/.n8n" \
    -e N8N_HOST="${N8N_DOMAIN}" \
    -e N8N_PORT=5678 \
    -e N8N_PROTOCOL=https \
    -e WEBHOOK_URL="https://${N8N_DOMAIN}/" \
    -e N8N_BASIC_AUTH_ACTIVE=true \
    -e N8N_BASIC_AUTH_USER=admin \
    -e N8N_BASIC_AUTH_PASSWORD="${N8N_PASSWORD}" \
    -e N8N_EMAIL_MODE=smtp \
    -e N8N_DIAGNOSTICS_ENABLED=false \
    -e N8N_VERSION_NOTIFICATIONS_ENABLED=false \
    -e N8N_TEMPLATES_ENABLED=true \
    -e EXECUTIONS_DATA_PRUNE=true \
    -e EXECUTIONS_DATA_MAX_AGE=168 \
    -e TZ=Europe/Paris \
    docker.n8n.io/n8nio/n8n \
    > /dev/null

sleep 3
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^n8n$'; then
    log_success "n8n actif — port interne $N8N_PORT."
else
    log_error "n8n n'a pas démarré — vérifie : sudo docker logs n8n"
    exit 1
fi

# ── n8n-MCP ──
log_info "Lancement de n8n-MCP..."

# Récupérer la clé API n8n (disponible après premier démarrage)
log_info "  Attente démarrage n8n complet (30s)..."
sleep 30

docker run -d \
    --name n8n-mcp \
    --restart unless-stopped \
    --network vps-secure-net \
    --security-opt no-new-privileges:true \
    --cap-drop ALL \
    --log-opt max-size=10m \
    --log-opt max-file=3 \
    -p 127.0.0.1:${MCP_PORT}:3000 \
    -e MCP_MODE=http \
    -e PORT=3000 \
    -e AUTH_TOKEN="${MCP_TOKEN}" \
    -e N8N_API_URL="http://n8n:5678" \
    -e N8N_API_KEY="" \
    -e LOG_LEVEL=error \
    -e DISABLE_CONSOLE_OUTPUT=true \
    ghcr.io/czlonkowski/n8n-mcp:latest \
    > /dev/null

sleep 3
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^n8n-mcp$'; then
    log_success "n8n-MCP actif — port interne $MCP_PORT."
else
    log_warn "n8n-MCP n'a pas démarré — vérifie : sudo docker logs n8n-mcp"
    log_warn "  Non bloquant — n8n fonctionne indépendamment."
fi

# ============================================================
# Étape 4 : Caddy — HTTPS pour n8n et n8n-MCP
# ============================================================
etape "4" "$TOTAL_ETAPES" "Configuration Caddy HTTPS"

# Détecter le Caddyfile existant
CADDYFILE=""
CADDY_CONTAINER=""

if docker ps --format '{{.Names}}' 2>/dev/null | grep -q 'caddy'; then
    CADDY_CONTAINER=$(docker ps --format '{{.Names}}' | grep caddy | head -1)
    log_info "Container Caddy détecté : $CADDY_CONTAINER"
fi

# Chercher le Caddyfile monté
CADDYFILE_PATHS=(
    "/home/vpsadmin/vps-monitor/Caddyfile"
    "/etc/caddy/Caddyfile"
    "/home/vpsadmin/Caddyfile"
)

for path in "${CADDYFILE_PATHS[@]}"; do
    if [[ -f "$path" ]]; then
        CADDYFILE="$path"
        log_info "Caddyfile trouvé : $CADDYFILE"
        break
    fi
done

if [[ -z "$CADDYFILE" ]]; then
    log_warn "Caddyfile non trouvé dans les chemins habituels."
    read -rp "  → Chemin complet du Caddyfile : " CADDYFILE
    if [[ ! -f "$CADDYFILE" ]]; then
        log_error "Fichier introuvable : $CADDYFILE"
        exit 1
    fi
fi

# Backup du Caddyfile
cp "$CADDYFILE" "${CADDYFILE}.backup.$(date '+%Y%m%d-%H%M%S')"
log_success "Backup Caddyfile créé."

# Ajouter les deux blocs au Caddyfile
cat >> "$CADDYFILE" << CADDYBLOCKS

# ── n8n ──────────────────────────────────────────────────────────────────────
${N8N_DOMAIN} {

  reverse_proxy 127.0.0.1:${N8N_PORT} {
    header_up Host {host}
    header_up X-Real-IP {remote_host}
    header_up X-Forwarded-For {remote_host}
    header_up X-Forwarded-Proto {scheme}
  }

  log {
    output file /data/n8n-access.log {
      roll_size  50mb
      roll_keep  3
    }
    format console
    level  WARN
  }

  header {
    Strict-Transport-Security "max-age=31536000; includeSubDomains"
    X-Frame-Options           "SAMEORIGIN"
    X-Content-Type-Options    "nosniff"
    Referrer-Policy           "no-referrer"
    -Server
  }
}

# ── n8n-MCP ──────────────────────────────────────────────────────────────────
${MCP_DOMAIN} {

  reverse_proxy 127.0.0.1:${MCP_PORT} {
    header_up Host {host}
    header_up X-Real-IP {remote_host}
    header_up X-Forwarded-For {remote_host}
    header_up X-Forwarded-Proto {scheme}
  }

  log {
    output file /data/mcp-access.log {
      roll_size  50mb
      roll_keep  3
    }
    format console
    level  WARN
  }

  header {
    Strict-Transport-Security "max-age=31536000; includeSubDomains"
    X-Content-Type-Options    "nosniff"
    Referrer-Policy           "no-referrer"
    -Server
  }
}
CADDYBLOCKS

log_success "Blocs n8n et n8n-MCP ajoutés au Caddyfile."

# Recharger Caddy
if [[ -n "$CADDY_CONTAINER" ]]; then
    log_info "Rechargement de Caddy..."
    docker exec "$CADDY_CONTAINER" caddy reload --config /etc/caddy/Caddyfile 2>/dev/null \
        || docker restart "$CADDY_CONTAINER" 2>/dev/null \
        || log_warn "Rechargement Caddy manuel requis : sudo docker restart $CADDY_CONTAINER"
    sleep 3
    log_success "Caddy rechargé."
else
    log_warn "Container Caddy non détecté — recharge manuellement : sudo docker restart <caddy_container>"
fi

# ── Stocker le token MCP de façon sécurisée ──
mkdir -p /etc/vps-secure
cat >> /etc/vps-secure/n8n.conf << EOF
N8N_DOMAIN="${N8N_DOMAIN}"
MCP_DOMAIN="${MCP_DOMAIN}"
MCP_TOKEN="${MCP_TOKEN}"
N8N_EMAIL="${N8N_EMAIL}"
EOF
chmod 600 /etc/vps-secure/n8n.conf
log_success "Config sauvegardée dans /etc/vps-secure/n8n.conf (chmod 600)."

# ── Ajouter n8n au cache vps-secure-stats si présent ──
if [[ -f /usr/local/bin/vps-secure-stats-cache.sh ]]; then
    log_info "Exclusion du volume n8n de AIDE..."
    if ! grep -q "n8n" /etc/aide/aide.conf 2>/dev/null; then
        echo "!/home/vpsadmin/n8n" >> /etc/aide/aide.conf
        log_success "Volume n8n exclu de AIDE (évite les faux positifs sur les données workflow)."
    fi
fi

# ============================================================
# Résumé final
# ============================================================
echo ""
echo -e "${GRAS}${VERT}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${GRAS}${VERT}║         n8n + n8n-MCP — Installation terminée ✓                 ║${RESET}"
echo -e "${GRAS}${VERT}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${VERT}✅${RESET} n8n              : ${BLANC}https://${N8N_DOMAIN}${RESET}"
echo -e "  ${VERT}✅${RESET} n8n-MCP          : ${BLANC}https://${MCP_DOMAIN}${RESET}"
echo -e "  ${VERT}✅${RESET} Login n8n        : ${BLANC}admin / [mot de passe saisi]${RESET}"
echo -e "  ${VERT}✅${RESET} Token MCP        : ${BLANC}$(cat /etc/vps-secure/n8n.conf | grep MCP_TOKEN | cut -d'"' -f2)${RESET}"
echo -e "  ${VERT}✅${RESET} Données n8n      : ${BLANC}${N8N_DATA_DIR}${RESET}"
echo -e "  ${VERT}✅${RESET} Config           : ${BLANC}/etc/vps-secure/n8n.conf${RESET}"
echo ""
echo -e "${GRAS}  Configuration Claude Desktop (ajoute dans claude_desktop_config.json) :${RESET}"
echo ""
echo -e "${VERT}  {${RESET}"
echo -e "${VERT}    \"mcpServers\": {${RESET}"
echo -e "${VERT}      \"n8n-mcp\": {${RESET}"
echo -e "${VERT}        \"command\": \"npx\",${RESET}"
echo -e "${VERT}        \"args\": [\"n8n-mcp\"],${RESET}"
echo -e "${VERT}        \"env\": {${RESET}"
echo -e "${VERT}          \"MCP_MODE\": \"http\",${RESET}"
echo -e "${VERT}          \"N8N_API_URL\": \"https://${MCP_DOMAIN}\",${RESET}"
echo -e "${VERT}          \"AUTH_TOKEN\": \"$(cat /etc/vps-secure/n8n.conf | grep MCP_TOKEN | cut -d'"' -f2)\",${RESET}"
echo -e "${VERT}          \"LOG_LEVEL\": \"error\"${RESET}"
echo -e "${VERT}        }${RESET}"
echo -e "${VERT}      }${RESET}"
echo -e "${VERT}    }${RESET}"
echo -e "${VERT}  }${RESET}"
echo ""
echo -e "${GRAS}  Configuration Claude.ai (Settings → Integrations → MCP) :${RESET}"
echo ""
echo -e "  ${BLANC}URL    : ${VERT}https://${MCP_DOMAIN}${RESET}"
echo -e "  ${BLANC}Token  : ${VERT}$(cat /etc/vps-secure/n8n.conf | grep MCP_TOKEN | cut -d'"' -f2)${RESET}"
echo ""
echo -e "${JAUNE}  ⚠️  Note importante — clé API n8n pour n8n-MCP :${RESET}"
echo -e "${BLANC}  1. Connecte-toi sur https://${N8N_DOMAIN}${RESET}"
echo -e "${BLANC}  2. Settings → API → Create API Key${RESET}"
echo -e "${BLANC}  3. Lance : sudo docker rm -f n8n-mcp && relance avec N8N_API_KEY=<ta_clé>${RESET}"
echo -e "${BLANC}  Ou utilise : sudo /usr/local/bin/vps-secure-n8n-apikey.sh <ta_clé>${RESET}"
echo ""

# Créer le script helper pour la clé API
# Note : heredoc avec guillemets simples 'APIKEYEOF' — évite l'expansion des variables au moment de la création
cat > /usr/local/bin/vps-secure-n8n-apikey.sh << 'APIKEYEOF'
#!/usr/bin/env bash
# Usage : sudo vps-secure-n8n-apikey.sh <N8N_API_KEY>
set -euo pipefail
[[ -z "${1:-}" ]] && echo "Usage : sudo $0 <N8N_API_KEY>" && exit 1
API_KEY="${1}"
MCP_TOKEN_VAL=$(grep MCP_TOKEN /etc/vps-secure/n8n.conf | cut -d'"' -f2)
docker rm -f n8n-mcp 2>/dev/null || true
docker run -d \
    --name n8n-mcp \
    --restart unless-stopped \
    --network vps-secure-net \
    --security-opt no-new-privileges:true \
    --cap-drop ALL \
    --log-opt max-size=10m \
    --log-opt max-file=3 \
    -p 127.0.0.1:3000:3000 \
    -e MCP_MODE=http \
    -e PORT=3000 \
    -e AUTH_TOKEN="${MCP_TOKEN_VAL}" \
    -e N8N_API_URL="http://n8n:5678" \
    -e N8N_API_KEY="${API_KEY}" \
    -e LOG_LEVEL=error \
    -e DISABLE_CONSOLE_OUTPUT=true \
    ghcr.io/czlonkowski/n8n-mcp:latest
echo "n8n-MCP relancé avec la clé API n8n."
APIKEYEOF
chmod +x /usr/local/bin/vps-secure-n8n-apikey.sh

echo -e "${GRAS}${VERT}  🎉 n8n prêt. Connecte-toi sur https://${N8N_DOMAIN}${RESET}"
echo ""

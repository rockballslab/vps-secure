#!/usr/bin/env bash
# =============================================================================
# install-secure.sh — Vérification d'intégrité GPG + installation sécurisée
# Clé : VPS-SECURE <security@aiforceone.fr> — RSA 4096 — expire 2028-04-11
# Usage : bash <(curl -fsSL https://raw.githubusercontent.com/rockballslab/vps-secure/main/install-secure.sh)
# Compatible : Linux (grep -P) + macOS (grep -E)
# =============================================================================
set -euo pipefail

REPO_RAW="https://raw.githubusercontent.com/rockballslab/vps-secure/main"
EXPECTED_FP="2A14DE7501B7D69AA48C0B4B58FE504BFFAD2922"
KEY_EMAIL="security@aiforceone.fr"

if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BOLD='\033[1m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BOLD=''; CYAN=''; NC=''
fi

log_ok()   { echo -e "${GREEN}  ✓${NC}  $*"; }
log_fail() { echo -e "${RED}  ✗  ERREUR : $*${NC}" >&2; exit 1; }
log_info() { echo -e "${YELLOW}  ~${NC}  $*"; }
log_sep()  { echo -e "${CYAN}──────────────────────────────────────────────────${NC}"; }

echo ""
echo -e "${BOLD}  VPS-SECURE — Vérification d'intégrité${NC}"
log_sep

command -v gpg  >/dev/null 2>&1 || log_fail "gpg requis : apt install -y gnupg"
command -v curl >/dev/null 2>&1 || log_fail "curl requis"

TMPDIR_VPS=$(mktemp -d /tmp/vps-secure-XXXXXX)
trap 'rm -rf "${TMPDIR_VPS}"' EXIT

log_info "Téléchargement de install.sh..."
curl -fsSL "${REPO_RAW}/install.sh" -o "${TMPDIR_VPS}/install.sh" \
    || log_fail "Téléchargement install.sh échoué"

log_info "Téléchargement de la signature GPG (install.sh.asc)..."
curl -fsSL "${REPO_RAW}/install.sh.asc" -o "${TMPDIR_VPS}/install.sh.asc" \
    || log_fail "Signature GPG introuvable — release non signée"

log_info "Import de la clé publique VPS-SECURE..."
curl -fsSL "${REPO_RAW}/vps-secure-public.asc" \
    | gpg --import --batch 2>/dev/null \
    || log_fail "Import clé publique échoué"

log_info "Vérification de la signature cryptographique..."

# Capturer la sortie GPG — gpg --verify retourne 0 si bonne signature
if ! gpg --verify "${TMPDIR_VPS}/install.sh.asc" "${TMPDIR_VPS}/install.sh" 2>"${TMPDIR_VPS}/gpg.err"; then
    cat "${TMPDIR_VPS}/gpg.err" >&2
    log_fail "Signature GPG invalide — fichier potentiellement compromis. Abandon."
fi

# Afficher la sortie GPG pour info
cat "${TMPDIR_VPS}/gpg.err"

# Extraire le fingerprint — compatible macOS (grep -E) et Linux
SIGNER_FP=$(grep -oE '[0-9A-Fa-f]{40}' "${TMPDIR_VPS}/gpg.err" | head -1 | tr '[:lower:]' '[:upper:]')

if [[ -z "${SIGNER_FP}" ]]; then
    log_fail "Impossible d'extraire le fingerprint GPG. Abandon."
fi

if [[ "${SIGNER_FP}" != "${EXPECTED_FP}" ]]; then
    log_fail "Fingerprint inattendu : ${SIGNER_FP} — clé non reconnue. Abandon."
fi

log_sep
log_ok "Signature GPG valide"
log_ok "Clé vérifiée : VPS-SECURE <${KEY_EMAIL}>"
log_ok "Fingerprint  : ${EXPECTED_FP}"
log_sep
echo ""
log_ok "Intégrité confirmée — lancement de l'installation..."
echo ""

bash "${TMPDIR_VPS}/install.sh"

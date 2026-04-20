#!/usr/bin/env bash
# ============================================================
# VPS-secure — Bootstrap VPS
# À lancer en ROOT sur un Ubuntu 24.04 LTS vierge
#
# Ce script fait :
#   1.  Crée l'utilisateur vpsadmin avec sudo
#   2.  Configure SSH (port 2222, clés uniquement, root désactivé)
#   3.  Met à jour le système + active DNS over TLS (avant tout téléchargement réseau)
#   4.  Installe CrowdSec (IDS/IPS communautaire)
#   5.  Configure UFW (ports 2222/80/443 uniquement)
#   6.  Installe Docker Engine + Compose v2
#   7.  Active les mises à jour de sécurité automatiques
#   8.  Durcit le noyau Linux (sysctl)
#   9.  Active l'audit système (auditd)
#   10. Configure le swap (2 GB)
#   11. Installe le scanner de rootkits (rkhunter)
#   12. Désactive les services inutiles (avahi, cups, bluetooth…)
#   13. Alertes Telegram (optionnel)
#   14. Honeypot SSH Endlessh (port 22 — piège les bots)
#   15. Integrity monitoring AIDE (détecte toute modification de binaire système)
#
# Usage :
#   ssh root@IP_DU_VPS
#   curl -O https://raw.githubusercontent.com/rockballslab/vps-secure/main/install.sh
#   chmod +x install.sh && ./install.sh
#
# Après le script :
#   ssh vpsadmin@IP_DU_VPS -p 2222 -i ~/.ssh/id_ed25519_vps
#
# Testé sur : Ubuntu 24.04 LTS (Hostinger KVM2/KVM4, Hetzner CX)
# Repo      : https://github.com/rockballslab/vps-secure
# ============================================================
set -euo pipefail

# Nettoyage garanti en cas d'interruption inattendue
# $? capturé en premier — rm et les commandes suivantes écraseraient le code de sortie du script
_cleanup() {
    local exit_code=$?
    rm -f /tmp/tmpkey-* 2>/dev/null || true  # optionnel : rm -f ne lève pas d'erreur si le fichier est absent — redondant mais explicite
    [[ $exit_code -ne 0 ]] && \
        echo -e "\n\033[1;33m[WARN]  Script interrompu — vérifie l'état du serveur.\033[0m" >&2
}
trap _cleanup EXIT

# Empêcher le token Telegram et les secrets de s'écrire dans l'historique bash
unset HISTFILE
# Fichiers créés par ce script (root) non lisibles par les autres utilisateurs
umask 077

# ============================================================
# Vérifications initiales
# ============================================================
if [[ "$(id -u)" -ne 0 ]]; then
    echo "❌ Ce script doit être lancé en ROOT."
    echo "   Usage : sudo ./install.sh"
    exit 1
fi

if ! grep -q "Ubuntu 24" /etc/os-release 2>/dev/null; then
    echo "⚠️  Ce script est conçu pour Ubuntu 24.04 LTS."
    read -rp "  Continuer quand même ? (oui/non) : " confirm
    [[ "$confirm" == "oui" ]] || exit 1
fi

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

_wait_dpkg() {
    if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
        log_info "Verrou dpkg occupé — attente (max 120s)..."
        timeout 120 bash -c 'while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do sleep 2; done' \
            || true  # optionnel : timeout 120s — si toujours verrouillé on tente quand même
    fi
}

etape() {
    local num="$1" total="$2" label="$3"
    echo -e "\n${GRAS}${VERT}[$num/$total] $label${RESET}"
    echo -e "${VERT}$(printf '─%.0s' {1..60})${RESET}"
}

# ============================================================
# Bannière
# ============================================================
echo -e "${VERT}"
cat << 'EOF'
  ██╗   ██╗██████╗ ███████╗      ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗
  ██║   ██║██╔══██╗██╔════╝      ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝
  ██║   ██║██████╔╝███████╗█████╗███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗
  ╚██╗ ██╔╝██╔═══╝ ╚════██║╚════╝╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝
   ╚████╔╝ ██║     ███████║      ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗
    ╚═══╝  ╚═╝     ╚══════╝      ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
EOF
echo -e "${RESET}"
echo -e "${BLANC}  Sécurisation VPS · Ubuntu 24.04 LTS · github.com/rockballslab/vps-secure${RESET}"
echo -e "${VERT}$(printf '═%.0s' {1..75})${RESET}\n"

USERNAME="vpsadmin"
TOTAL_ETAPES=15

# ============================================================
# CONFIGURATION ENVIRONNEMENT (À AJOUTER ICI)
# ============================================================
# Évite les interruptions "needrestart" ou les popups violets d'apt
export DEBIAN_FRONTEND=noninteractive

# Garantit que les outils système (ufw, ip, systemctl) sont toujours trouvés
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# ============================================================
# Étape 1 : Créer l'utilisateur vpsadmin
# ============================================================
etape "1" "$TOTAL_ETAPES" "Création de l'utilisateur $USERNAME"

if id "$USERNAME" &>/dev/null; then
    log_warn "L'utilisateur $USERNAME existe déjà — on continue."
else
    adduser --disabled-password --gecos "VPS Admin" "$USERNAME"
    usermod -aG sudo "$USERNAME"
    # use_pty : empêche le sudo hijacking depuis un terminal détaché (CIS 1.3.1)
    printf 'Defaults:%s use_pty\n%s ALL=(ALL) NOPASSWD:ALL\n' "$USERNAME" "$USERNAME" \
        > /etc/sudoers.d/"$USERNAME"
    chmod 440 /etc/sudoers.d/"$USERNAME"
    log_success "Utilisateur $USERNAME créé avec accès sudo sans mot de passe (use_pty actif)."
fi

# ============================================================
# Étape 2 : Configurer SSH (port 2222, clés uniquement)
# ============================================================
etape "2" "$TOTAL_ETAPES" "Configuration SSH sécurisée"

echo -e "${BLANC}  Colle ta clé publique SSH (commence par ssh-ed25519 ou ssh-rsa) :${RESET}"
echo -e "${BLANC}  Tu n'en as pas ? Génère-la sur ton ordinateur :${RESET}"
echo -e "${VERT}    ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_vps${RESET}"
echo -e "${BLANC}  Puis récupère-la avec :${RESET}"
echo -e "${VERT}    cat ~/.ssh/id_ed25519_vps.pub${RESET}"
echo ""
read -rp "  → Clé publique : " SSH_PUB_KEY

if [[ ! "$SSH_PUB_KEY" =~ ^ssh- ]]; then
    log_error "La clé doit commencer par ssh-ed25519 ou ssh-rsa."
    log_error "Vérifie : cat ~/.ssh/id_ed25519_vps.pub (sur ton ordinateur)"
    exit 1
fi

# Validation complète de la clé avec ssh-keygen
TMPKEY=$(mktemp /tmp/tmpkey-XXXXXX)
# Pas de second trap ici — _cleanup (défini plus haut) supprime /tmp/tmpkey-* à la sortie
echo "$SSH_PUB_KEY" > "$TMPKEY"
if ! ssh-keygen -l -f "$TMPKEY" &>/dev/null; then
    log_error "Clé SSH invalide ou corrompue — impossible de la valider."
    exit 1
fi
# Lire toutes les infos d'un seul appel — TMPKEY sera supprimé par _cleanup à la sortie
KEY_INFO=$(ssh-keygen -l -f "$TMPKEY")

KEY_TYPE=$(echo "$KEY_INFO" | awk '{print $4}' | tr -d '()')
KEY_BITS=$(echo "$KEY_INFO" | awk '{print $1}')

if [[ "$KEY_TYPE" == "DSA" ]]; then
    log_error "Clé DSA refusée (cryptographiquement obsolète)."
    log_error "Génère une clé ed25519 : ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_vps"
    exit 1
fi

if [[ "$KEY_TYPE" == "RSA" ]] && [[ -n "$KEY_BITS" ]] && [[ "$KEY_BITS" -lt 3072 ]]; then
    log_warn "Clé RSA $KEY_BITS bits — minimum recommandé : 3072 bits."
    read -rp "  Continuer quand même ? (oui/non) : " weak_key
    [[ "$weak_key" == "oui" ]] || exit 1
fi
log_success "Clé SSH validée ($KEY_TYPE)."

# Installer la clé
ADMIN_HOME="/home/$USERNAME"
mkdir -p "$ADMIN_HOME/.ssh"
echo "$SSH_PUB_KEY" > "$ADMIN_HOME/.ssh/authorized_keys"
chmod 700 "$ADMIN_HOME/.ssh"
chmod 600 "$ADMIN_HOME/.ssh/authorized_keys"
chown -R "$USERNAME:$USERNAME" "$ADMIN_HOME/.ssh"
log_success "Clé SSH installée pour $USERNAME."

# Backup de la config SSH d'origine
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup."$(date '+%Y%m%d')"
# rkhunter ne gère pas les Include SSH — aligner le fichier de base avec le drop-in
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# Config SSH durcie
cat > /etc/ssh/sshd_config.d/00-vps-secure.conf << 'SSHEOF'
# vps-secure — SSH Hardening
# Port 2222, clés uniquement, root login désactivé
Port 2222

PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
KbdInteractiveAuthentication no
UsePAM yes
PermitEmptyPasswords no
StrictModes yes

# Limiter les connexions à vpsadmin uniquement
AllowUsers vpsadmin

# Logging renforcé (fingerprint des clés utilisées — utile en forensique)
LogLevel VERBOSE

# Bannière légale (CIS L1, DISA STIG)
Banner /etc/issue.net

MaxAuthTries 3
MaxSessions 2
MaxStartups 10:30:60
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2

X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no

# Désactivation GSSAPI — CVE-2026-3497 (CVSS 8.2, pre-auth heap corruption)
# GSSAPI = Kerberos enterprise, jamais utilisé sur un VPS standalone
GSSAPIAuthentication no
GSSAPIKeyExchange no
GSSAPICleanupCredentials no
GSSAPIStrictAcceptorCheck yes

# Restreindre le host key du serveur à Ed25519 (CIS L1 — plus moderne que RSA/ECDSA)
# Note : PubkeyAcceptedAlgorithms n'est PAS restreint — le script accepte les clés RSA client.
HostKeyAlgorithms ssh-ed25519
SSHEOF

# Bannière légale
cat > /etc/issue.net << 'BANNER'
*************************************************************
*  AUTHORIZED ACCESS ONLY                                   *
*  All activity is monitored and logged.                    *
*  Unauthorized access will be prosecuted.                  *
*************************************************************
BANNER
cp /etc/issue.net /etc/issue

# Valider la config AVANT de redémarrer
if ! sshd -t 2>/dev/null; then
    log_error "Config SSH invalide — restauration du backup."
    rm -f /etc/ssh/sshd_config.d/00-vps-secure.conf
    systemctl restart ssh
    exit 1
fi

# Fix Ubuntu 24.04 : SSH géré par socket systemd
mkdir -p /etc/systemd/system/ssh.socket.d
cat > /etc/systemd/system/ssh.socket.d/override.conf << 'SOCKETEOF'
[Socket]
ListenStream=
ListenStream=0.0.0.0:2222
ListenStream=[::]:2222
SOCKETEOF

systemctl daemon-reload
systemctl restart ssh.socket
systemctl restart ssh
log_success "SSH reconfiguré : port 2222, clés uniquement, root désactivé."

# --- Rollback SSH (fonction réutilisable) ---
_ssh_rollback() {
    echo ""
    log_warn "Rollback SSH — restauration de la configuration d'origine."
    rm -f /etc/ssh/sshd_config.d/00-vps-secure.conf
    rm -f /etc/systemd/system/ssh.socket.d/override.conf
    systemctl daemon-reload
    systemctl restart ssh.socket ssh
    log_warn "SSH restauré : port 22, root autorisé."
    log_warn "Relance le script après avoir vérifié ta clé SSH."
    exit 1
}

# --- Vérification côté serveur : SSH écoute bien sur 2222 ---
if ! ss -tlnp | grep -q ':2222'; then
    log_error "SSH n'écoute pas sur le port 2222 — rollback automatique."
    _ssh_rollback
fi
log_success "SSH écoute sur le port 2222 ✓"

# --- Confirmation obligatoire côté utilisateur ---
# Détecter l'IP publique via la table de routage (plus fiable que hostname -I sur Hetzner/Hostinger)
VPS_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}')
VPS_IP="${VPS_IP:-$(hostname -I | awk '{print $1}')}"
echo ""
echo -e "${GRAS}${JAUNE}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${GRAS}${JAUNE}║  🔐 TEST SSH OBLIGATOIRE — NE FERME PAS CETTE SESSION            ║${RESET}"
echo -e "${GRAS}${JAUNE}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${BLANC}1. Ouvre un NOUVEAU terminal sur ton ordinateur${RESET}"
echo -e "  ${BLANC}2. Lance cette commande (remplace NOM_CLE par ton fichier) :${RESET}"
echo ""
echo -e "     ${VERT}ssh $USERNAME@$VPS_IP -p 2222 -i ~/.ssh/NOM_CLE${RESET}"
echo ""
echo -e "  ${BLANC}3. Si tu vois un prompt $USERNAME@... → connexion OK ✓${RESET}"
echo -e "  ${BLANC}4. Tape 'exit' dans ce terminal de test, puis reviens ici${RESET}"
echo ""

SSH_OK=false
for attempt in 1 2 3; do
    read -rp "  La connexion SSH fonctionne ? (oui / non / rollback) : " ssh_answer
    case "$ssh_answer" in
        oui)
            SSH_OK=true
            break
            ;;
        rollback)
            _ssh_rollback
            ;;
        non)
            echo ""
            echo -e "  ${JAUNE}Vérifie ces 3 points :${RESET}"
            echo -e "  ${BLANC}  - Tu utilises le fichier de clé PRIVÉE (sans .pub)${RESET}"
            echo -e "  ${BLANC}  - La commande contient bien -p 2222${RESET}"
            echo -e "  ${BLANC}  - L'utilisateur est : $USERNAME (pas root)${RESET}"
            echo ""
            [[ $attempt -lt 3 ]] && echo -e "  ${BLANC}Réessaie. Tentative $((attempt+1))/3${RESET}\n"
            ;;
        *)
            echo -e "  ${JAUNE}Réponds par 'oui', 'non', ou 'rollback'.${RESET}"
            ;;
    esac
done

if [[ "$SSH_OK" != "true" ]]; then
    _ssh_rollback
fi

log_success "Connexion SSH confirmée — le script continue."

# ============================================================
# Étape 3 : Mise à jour du système
# ============================================================
etape "3" "$TOTAL_ETAPES" "Mise à jour du système"

_wait_dpkg
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \
    curl wget gnupg lsb-release ca-certificates \
    apt-transport-https software-properties-common \
    unzip jq htop ncdu tree openssl python3 \
    debsums apt-show-versions acct sysstat \
    libpam-pwquality

DEBIAN_FRONTEND=noninteractive pam-auth-update --force 2>/dev/null || true
# PKGS-7370 — debsums cron daily (juste installé ne suffit pas)
sed -i 's/^#\?CRON_CHECK.*/CRON_CHECK=daily/' /etc/default/debsums 2>/dev/null || \
  echo "CRON_CHECK=daily" >> /etc/default/debsums
log_success "Système mis à jour — debsums cron daily configuré."

systemctl enable --now acct 2>/dev/null || true
systemctl enable --now sysstat 2>/dev/null || true
# ACCT-9626 — activer la collecte sysstat (ENABLED=true requis, sinon service démarré mais inactif)
sed -i 's/^ENABLED=.*/ENABLED="true"/' /etc/default/sysstat 2>/dev/null || \
  echo 'ENABLED="true"' >> /etc/default/sysstat
systemctl restart sysstat 2>/dev/null || true
log_success "sysstat activé — collecte système démarrée."

# Sécuriser /tmp (CIS Benchmark L1)
if ! grep -q "tmpfs /tmp" /etc/fstab; then
    # Désactiver tmp.mount systemd pour éviter un conflit au boot
    if systemctl is-enabled tmp.mount &>/dev/null; then
        systemctl mask tmp.mount
        log_info "tmp.mount systemd masqué — gestion via fstab."
    fi
    echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
    mount -o remount /tmp 2>/dev/null || true  # optionnel : remount échoue si le noyau n'a pas encore pris en compte l'entrée fstab — effectif au prochain reboot
    log_success "/tmp sécurisé (noexec, nosuid, nodev)."
else
    log_warn "/tmp déjà configuré dans fstab — on continue."
fi

# Vérification AppArmor (actif par défaut sur Ubuntu 24.04)
if command -v aa-status &>/dev/null; then
    if aa-status 2>/dev/null | grep -q "apparmor module is loaded"; then
        ENFORCING=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}' || echo "?")
        log_success "AppArmor actif — ${ENFORCING} profils en mode enforcing."
    else
        log_warn "AppArmor chargé mais aucun profil en enforcing."
        log_warn "  Vérifier : sudo aa-status"
    fi
else
    log_warn "AppArmor non détecté — installation manuelle recommandée :"
    log_warn "  sudo apt-get install apparmor apparmor-utils && sudo aa-enforce /etc/apparmor.d/*"
fi

# ── DNS over TLS (activé ici, avant tout téléchargement réseau) ──
# Raison :  et Docker sont téléchargés ensuite.
# Sans DoT, les résolutions DNS transitent en clair — fenêtre de DNS poisoning.
log_info "Activation du DNS chiffré avant les téléchargements..."
mkdir -p /etc/systemd/resolved.conf.d
# ── DNS over TLS — étape 3 install.sh ──────────────────────

# 1. Config resolved globale
cat > /etc/systemd/resolved.conf.d/vps-secure-dns.conf << 'DNSEOF'
# vps-secure — DNS over TLS
# Quad9 (filtrage malware, Suisse) + Cloudflare (fallback)
[Resolve]
DNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net 1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com
FallbackDNS=9.9.9.10#dns.quad9.net 149.112.112.10#dns.quad9.net
DNSOverTLS=opportunistic
DNSSEC=allow-downgrade
MulticastDNS=no
LLMNR=no
Domains=~.
DNSEOF

# 2. Drop-in networkd — remplace le DNS statique Hostinger par Quad9/Cloudflare
NETPLAN_NET=$(ls /run/systemd/network/10-netplan-*.network 2>/dev/null | head -1)
if [[ -n "$NETPLAN_NET" ]]; then
    DROPIN_DIR="/etc/systemd/network/$(basename "${NETPLAN_NET}").d"
    mkdir -p "$DROPIN_DIR"
    cat > "$DROPIN_DIR/50-vps-secure-dns.conf" << 'NETEOF'
[Network]
DNS=
DNS=9.9.9.9#dns.quad9.net
DNS=149.112.112.112#dns.quad9.net
DNS=1.1.1.1#cloudflare-dns.com
DNS=1.0.0.1#cloudflare-dns.com
Domains=~.
DNSOverTLS=opportunistic

[DHCP]
UseDNS=no
NETEOF
    chmod 755 "$DROPIN_DIR"
    chmod 644 "$DROPIN_DIR/50-vps-secure-dns.conf"
    systemctl restart systemd-networkd
    sleep 2
    systemctl restart systemd-resolved 2>/dev/null || true
    log_success "DNS Quad9 DoT configuré (per-link override Hostinger)."
else
    log_warn "Fichier .network Hostinger non trouvé — DNS non configuré."
fi

# 3. Restart + vérification
systemctl restart systemd-resolved
sleep 2
if resolvectl query quad9.net 2>&1 | grep -q "encrypted transport: yes"; then
    log_success "DNS over TLS actif — Quad9 + Cloudflare (trafic DNS chiffré confirmé)"
else
    log_warn "DNS over TLS configuré — résolution OK, DoT à vérifier manuellement"
fi

systemctl enable systemd-resolved
systemctl restart systemd-resolved
# Forcer /etc/resolv.conf vers le stub systemd-resolved
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

if resolvectl query quad9.net &>/dev/null; then
    log_success "DNS over TLS actif — Quad9 + Cloudflare (mDNS/LLMNR désactivés)."
else
    log_warn "DNS over TLS configuré — vérification transitoire échouée."
    log_warn "  Vérifie après install : resolvectl query google.com"
fi

# /var/tmp noexec (CIS Benchmark 1.1.x — persiste après reboot, vecteur malware)
if ! grep -q "/var/tmp" /etc/fstab; then
    echo "tmpfs /var/tmp tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
    mount -o remount /var/tmp 2>/dev/null || true  # optionnel : remount échoue si le noyau n'a pas encore pris en compte l'entrée fstab — effectif au prochain reboot
    log_success "/var/tmp sécurisé (noexec, nosuid, nodev)."
else
    log_warn "/var/tmp déjà configuré dans fstab — on continue."
fi

# /dev/shm noexec (CIS 1.1.x, DISA V-238374 — RAM partagée entre processus)
# ⚠️ Certains containers JVM utilisent /dev/shm pour des mmap exécutables.
# Si un container plante après install, retire noexec : sudo mount -o remount,exec /dev/shm
if ! grep -q "/dev/shm" /etc/fstab; then
    echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
    mount -o remount /dev/shm 2>/dev/null || true  # optionnel : remount échoue si le noyau n'a pas encore pris en compte l'entrée fstab — effectif au prochain reboot
    log_success "/dev/shm sécurisé (noexec, nosuid, nodev)."
else
    log_warn "/dev/shm déjà configuré dans fstab — on continue."
fi

# ============================================================
# Étape 4 : Installer CrowdSec
# ============================================================
etape "4" "$TOTAL_ETAPES" "Installation de CrowdSec (IDS/IPS communautaire)"

if ! command -v crowdsec &>/dev/null; then
    log_info "Installation de CrowdSec via dépôt GPG signé..."

    curl -fsSL https://packagecloud.io/crowdsec/crowdsec/gpgkey \
        | gpg --dearmor -o /usr/share/keyrings/crowdsec.gpg

    # Vérification de l'empreinte GPG CrowdSec officielle
    # ⚠️  MAINTENEUR : vérifier cette valeur avant chaque release avec :
    #   curl -fsSL https://packagecloud.io/crowdsec/crowdsec/gpgkey \
    #     | gpg --dearmor -o /tmp/cs-test.gpg && \
    #     gpg --with-fingerprint --with-colons /tmp/cs-test.gpg \
    #     | grep '^fpr' | head -1 | cut -d: -f10 && rm /tmp/cs-test.gpg
    CROWDSEC_EXPECTED="6A89E3C2303A901A889971D3376ED5326E93CD0C"
    CROWDSEC_ACTUAL=$(gpg --with-fingerprint --with-colons /usr/share/keyrings/crowdsec.gpg \
        2>/dev/null | grep '^fpr' | head -1 | cut -d: -f10)
    if [[ "$CROWDSEC_ACTUAL" != "$CROWDSEC_EXPECTED" ]]; then
        log_error "Empreinte GPG CrowdSec invalide — abandon."
        log_error "  Attendu  : $CROWDSEC_EXPECTED"
        log_error "  Reçu     : $CROWDSEC_ACTUAL"
        exit 1
    fi
    log_success "Empreinte GPG CrowdSec vérifiée ✓"

    chmod a+r /usr/share/keyrings/crowdsec.gpg

    echo "deb [signed-by=/usr/share/keyrings/crowdsec.gpg] \
https://packagecloud.io/crowdsec/crowdsec/ubuntu \
$(lsb_release -cs) main" > /etc/apt/sources.list.d/crowdsec.list

    _wait_dpkg
    apt-get update -qq
    apt-get install -y -qq crowdsec crowdsec-firewall-bouncer-iptables
    log_success "CrowdSec installé via dépôt signé GPG."
else
    log_warn "CrowdSec déjà installé — on continue."
fi

# Collections de base — échec visible (CrowdSec sans règles = IDS aveugle)
for collection in crowdsecurity/linux crowdsecurity/sshd; do
    if cscli collections install "$collection" 2>/dev/null; then
        log_success "Collection $collection installée."
    else
        log_warn "Collection $collection non installée — CrowdSec partiellement actif."
        log_warn "  Réinstalle : sudo cscli collections install $collection"
    fi
done

# Fix CPU : setup.linux.yaml généré par cscli setup inclut syslog et kern.log
# CrowdSec n'a pas de parseur pour ces sources sur Ubuntu — il les lit pour rien
# (~150k lignes/min ingérées, 0 parsées = 28% CPU idle pour zéro valeur)
if [[ -f /etc/crowdsec/acquis.d/setup.linux.yaml ]]; then
    python3 - /etc/crowdsec/acquis.d/setup.linux.yaml << 'PYEOF'
import sys, re
with open(sys.argv[1]) as f:
    content = f.read()
# Retirer /var/log/syslog et /var/log/kern.log de la liste filenames
content = re.sub(r'\s*- /var/log/syslog\n', '\n', content)
content = re.sub(r'\s*- /var/log/kern\.log\n', '\n', content)
with open(sys.argv[1], 'w') as f:
    f.write(content)
PYEOF
    log_success "CrowdSec : syslog + kern.log retirés de l'acquisition (fix CPU)."
fi

# nginx uniquement si nginx est installé (sinon CrowdSec génère des warnings inutiles)
if command -v nginx &>/dev/null; then
    if cscli collections install crowdsecurity/nginx 2>/dev/null; then
        log_success "Collection crowdsecurity/nginx installée (nginx détecté)."
    fi
else
    log_info "nginx non détecté — collection nginx non installée."
    log_info "  Si tu installes nginx plus tard : sudo cscli collections install crowdsecurity/nginx"
fi

# Adapter la config pour le port SSH 2222
# Le séparateur --- est requis par CrowdSec v1.4+ pour les entrées multi-documents YAML
if [[ -f /etc/crowdsec/acquis.yaml ]]; then
    if ! grep -q "/var/log/auth.log" /etc/crowdsec/acquis.yaml; then
        cat >> /etc/crowdsec/acquis.yaml << 'CSEOF'
---
source: file
filenames:
  - /var/log/auth.log
labels:
  type: syslog
CSEOF
        log_success "Source auth.log ajoutée à CrowdSec (port 2222)."
    else
        log_info "auth.log déjà configuré dans CrowdSec — ignoré."
    fi
fi

# Vérifier que auth.log existe — absent si rsyslog non installé (journald seul)
# Sans auth.log, CrowdSec est silencieusement aveugle aux attaques SSH
if [[ ! -f /var/log/auth.log ]]; then
    log_warn "⚠️  /var/log/auth.log absent — rsyslog non installé ?"
    log_warn "   CrowdSec ne peut pas détecter les attaques SSH sans ce fichier."
    log_warn "   Correction : sudo apt-get install -y rsyslog && sudo systemctl enable --now rsyslog"
    _wait_dpkg
    apt-get install -y -qq rsyslog
    systemctl enable --now rsyslog
    log_success "rsyslog installé — /var/log/auth.log sera disponible."
fi

# ── Fix #28 : Enregistrer le bouncer CrowdSec (génération clé API) ──
log_info "Enregistrement du bouncer CrowdSec (génération clé API)..."

# Attendre que la LAPI CrowdSec soit prête avant de générer la clé
_wait_crowdsec_lapi() {
    local max_wait=30 elapsed=0
    # cscli lapi status fait une vraie connexion HTTP à la LAPI — contrairement à cscli version qui est purement local
    while ! cscli lapi status &>/dev/null; do
        sleep 2; elapsed=$((elapsed + 2))
        [[ $elapsed -ge $max_wait ]] && { log_warn "LAPI CrowdSec non prête après ${max_wait}s"; return 1; }
    done
    return 0
}

systemctl enable crowdsec
systemctl restart crowdsec
_wait_crowdsec_lapi || true  # optionnel : non bloquant — la clé sera absente mais le reste continue

# Enregistrer le bouncer — idempotent : suppression + recréation si déjà présent
BOUNCER_NAME="cs-firewall-bouncer-$(hostname -s)"
BOUNCER_API_KEY=""

if cscli bouncers list 2>/dev/null | grep -q "$BOUNCER_NAME"; then
    log_warn "Bouncer $BOUNCER_NAME déjà enregistré — suppression et recréation."
    cscli bouncers delete "$BOUNCER_NAME" 2>/dev/null || true  # optionnel : non bloquant
fi

BOUNCER_API_KEY=$(cscli bouncers add "$BOUNCER_NAME" \
    --key "$(openssl rand -hex 16)" -o raw 2>/dev/null || echo "")

if [[ -z "$BOUNCER_API_KEY" ]]; then
    log_warn "Impossible de générer la clé API bouncer — CrowdSec détectera mais ne bannira pas."
    log_warn "  Correction manuelle : sudo cscli bouncers add cs-firewall-bouncer"
else
    log_success "Bouncer enregistré : $BOUNCER_NAME"

    if [[ -f /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml ]]; then
        if grep -q "^api_key:" /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml; then
            sed -i "s|^api_key:.*|api_key: ${BOUNCER_API_KEY}|" \
                /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
        else
            echo "api_key: ${BOUNCER_API_KEY}" >> \
                /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
        fi
        chmod 600 /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
        log_success "Clé API injectée dans crowdsec-firewall-bouncer.yaml"
    else
        # Fichier absent — créer la config complète
        mkdir -p /etc/crowdsec/bouncers
        cat > /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml << EOF
mode: iptables
pid_dir: /var/run/
update_frequency: 10s
log_level: info
api_url: http://127.0.0.1:8081/
api_key: ${BOUNCER_API_KEY}
disable_ipv6: false
deny_action: DROP
deny_log: true
deny_log_prefix: "crowdsec: "
supported_decisions_types:
  - ban
iptables_chains:
  - INPUT
  - FORWARD
ip6tables_chains:
  - INPUT
  - FORWARD
EOF
        chmod 600 /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
        log_success "Config bouncer créée avec clé API (fichier absent — recréé)."
    fi
fi
# NOTE : les sed port 8080→8081 ci-dessous s'appliquent aussi à crowdsec-firewall-bouncer.yaml — intentionnel.

# CrowdSec API sur port 8081 (8080 souvent occupé)
log_info "Configuration de CrowdSec sur le port 8081..."
sed -i 's/listen_uri: 127.0.0.1:8080/listen_uri: 127.0.0.1:8081/' /etc/crowdsec/config.yaml 2>/dev/null || true  # optionnel : fichier absent si arborescence CrowdSec modifiée
# FIX #66 — Restreindre Prometheus CrowdSec à localhost (était exposé publiquement)
sed -i 's/prometheus_listen_addr: 0\.0\.0\.0/prometheus_listen_addr: 127.0.0.1/' \
    /etc/crowdsec/config.yaml 2>/dev/null || true
log_success "CrowdSec Prometheus : restreint à localhost:6060 (non exposé sur Internet)."
sed -i 's/127.0.0.1:8080/127.0.0.1:8081/' /etc/crowdsec/local_api_credentials.yaml 2>/dev/null || true  # optionnel : même raison
sed -i 's/127.0.0.1:8080/127.0.0.1:8081/' /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml 2>/dev/null || true  # optionnel : même raison

# Vérification post-sed : si 8080 subsiste dans un fichier présent, la config est incohérente.
# Le bouncer démarrerait, ne se connecterait pas à l'API, détecterait mais ne bannirait plus rien.
_crowdsec_port_verify() {
    local file="$1" name="$2"
    [[ ! -f "$file" ]] && log_warn "CrowdSec : $name absent — port 8081 non appliqué pour ce composant." && return
    if grep -q "127.0.0.1:8080" "$file"; then
        log_warn "CrowdSec : $name contient encore ':8080' — sed n'a pas fonctionné (clé renommée ?)."
        log_warn "  Correction manuelle : sudo grep -n '8080' $file"
    fi
}
_crowdsec_port_verify /etc/crowdsec/config.yaml "config.yaml"
_crowdsec_port_verify /etc/crowdsec/local_api_credentials.yaml "local_api_credentials.yaml"
_crowdsec_port_verify /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml "crowdsec-firewall-bouncer.yaml"

# Redémarrer CrowdSec pour qu'il écoute sur 8081 — OBLIGATOIRE avant le restart bouncer
# Sans ce restart, la LAPI tourne encore sur 8080 et le bouncer échoue à se connecter
systemctl restart crowdsec
_wait_crowdsec_lapi || true  # optionnel : non bloquant — le bouncer tentera quand même

systemctl enable crowdsec-firewall-bouncer
systemctl restart crowdsec-firewall-bouncer 2>/dev/null || true  # optionnel : le bouncer peut échouer au 1er démarrage si CrowdSec n'est pas encore prêt — vérifié par sleep+is-active ci-dessous

# Valider que le bouncer est actif — sans lui CrowdSec détecte mais ne bannit pas
sleep 3
if systemctl is-active crowdsec-firewall-bouncer &>/dev/null; then
    log_success "CrowdSec bouncer actif — bannissement IP opérationnel."
else
    log_warn "⚠️  CrowdSec bouncer non actif — CrowdSec détecte mais ne bannit PAS les IPs."
    log_warn "   Vérifie : sudo systemctl status crowdsec-firewall-bouncer"
    log_warn "   Log     : sudo journalctl -u crowdsec-firewall-bouncer -n 20"
fi

log_success "CrowdSec actif — protection SSH + HTTP communautaire."

# ============================================================
# Étape 5 : Configurer UFW
# ============================================================
etape "5" "$TOTAL_ETAPES" "Configuration du pare-feu UFW"

# On s'assure que le binaire est là (le PATH peut varier)
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

if ! command -v ufw >/dev/null 2>&1; then
    log_info "ufw non trouvé — installation..."
    _wait_dpkg && apt-get install -y -qq ufw
fi

# Reset pour repartir sur une base saine
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw default deny forward

# Ports de base
ufw allow 2222/tcp comment 'SSH vps-secure'
ufw allow 80/tcp  comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw deny  6060/tcp  comment 'CrowdSec Prometheus - localhost only - fix #66'

# Détection de l'interface et Forwarding Docker
MAIN_IFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
if [[ -z "$MAIN_IFACE" ]]; then
    log_warn "Interface réseau principale non détectée — forwarding Docker bridge ignoré."
else
    UFW_ROUTE_OK=true
    # On autorise le passage du trafic entre Docker et l'extérieur
    ufw route allow in on docker0 out on "$MAIN_IFACE" 2>/dev/null || UFW_ROUTE_OK=false
    ufw route allow in on "$MAIN_IFACE" out on docker0 2>/dev/null || UFW_ROUTE_OK=false
    
    if [[ "$UFW_ROUTE_OK" == "true" ]]; then
        log_success "Forwarding Docker bridge via $MAIN_IFACE autorisé."
    else
        log_warn "Forwarding Docker bridge incomplet — vérifie manuellement."
    fi
fi

# Activation de UFW
echo "y" | ufw enable >/dev/null
ufw logging medium

# IMPORTANT : On ne met PAS iptables-persistent ici. 
# UFW est déjà persistant via son propre service systemd.
systemctl enable ufw >/dev/null 2>&1

log_success "UFW activé : ports 2222/80/443."

# ============================================================
# Étape 6 : Installer Docker Engine + Compose v2
# ============================================================
etape "6" "$TOTAL_ETAPES" "Installation de Docker Engine"

if ! command -v docker &>/dev/null; then
    log_info "Installation de Docker Engine..."

    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc

    # Vérification de l'empreinte GPG Docker officielle
    DOCKER_EXPECTED="9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
    DOCKER_ACTUAL=$(gpg --with-fingerprint --with-colons /etc/apt/keyrings/docker.asc \
        2>/dev/null | grep '^fpr' | head -1 | cut -d: -f10)
    if [[ "$DOCKER_ACTUAL" != "$DOCKER_EXPECTED" ]]; then
        log_error "Empreinte GPG Docker invalide — abandon."
        log_error "  Attendu  : $DOCKER_EXPECTED"
        log_error "  Reçu     : $DOCKER_ACTUAL"
        exit 1
    fi
    log_success "Empreinte GPG Docker vérifiée ✓"
    chmod a+r /etc/apt/keyrings/docker.asc

    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
      https://download.docker.com/linux/ubuntu \
      $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
      tee /etc/apt/sources.list.d/docker.list > /dev/null
      
    _wait_dpkg
    apt-get update -qq
    apt-get install -y -qq \
        docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin

    usermod -aG docker "$USERNAME"
    log_warn "⚠️  Groupe docker = root effectif (docker run peut monter / en lecture-écriture)."
    log_warn "   Protège ta clé SSH comme une clé root — compromis clé = compromis serveur."
    log_warn "   Si tu n'utilises pas Docker sans sudo : sudo gpasswd -d $USERNAME docker"
    systemctl enable docker
    systemctl start docker

    # Empêcher Docker de bypasser UFW via iptables directement
    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json << 'DOCKEREOF'
{
  "iptables": false,
  "live-restore": true,
  "log-driver": "json-file",
  "log-opts": {"max-size": "10m", "max-file": "3"}
}
DOCKEREOF
    systemctl restart docker

    log_success "Docker Engine installé : $(docker --version)"
else
    log_warn "Docker déjà installé : $(docker --version)"
    usermod -aG docker "$USERNAME" 2>/dev/null || true  # optionnel : l'utilisateur est peut-être déjà dans le groupe docker
fi

if docker compose version &>/dev/null; then
    log_success "Docker Compose v2 : $(docker compose version --short)"
else
    log_error "Docker Compose v2 non disponible. Vérifie l'installation Docker."
    exit 1
fi

# ── Vérification version minimum Docker (issue #49) ──────────────────────
DOCKER_MIN_VERSION="29.3.1"
version_lt() { printf '%s\n%s\n' "$1" "$2" | sort -V -C; }
DOCKER_INSTALLED_VERSION=$(docker --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1)
if [ -n "$DOCKER_INSTALLED_VERSION" ] && version_lt "$DOCKER_INSTALLED_VERSION" "$DOCKER_MIN_VERSION"; then
    log_warn "Docker $DOCKER_INSTALLED_VERSION < $DOCKER_MIN_VERSION — mise à jour..."
    apt-get install -y -qq --only-upgrade docker-ce docker-ce-cli containerd.io
    log_success "Docker mis à jour : $(docker --version)"
else
    log_success "Docker version OK : $DOCKER_INSTALLED_VERSION ≥ $DOCKER_MIN_VERSION"
fi

# ── Règle NAT Docker dans UFW (CRITIQUE avec iptables:false) ──
# Sans MASQUERADE dans POSTROUTING, les containers n'ont pas accès à internet
# malgré les règles UFW route allow (qui ouvrent le FORWARD mais pas le NAT).
log_info "Ajout de la règle NAT Docker dans UFW (requis avec iptables:false)..."
DOCKER_SUBNET=$(docker network inspect bridge \
    --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null || true)  # optionnel : docker inspect peut échouer si le daemon vient de démarrer — fallback ligne suivante
if [[ -z "$DOCKER_SUBNET" ]]; then
    log_warn "Subnet Docker bridge vide après inspect — fallback 172.17.0.0/16."
    DOCKER_SUBNET="172.17.0.0/16"
fi

if [[ ! -f /etc/ufw/before.rules ]]; then
    log_warn "⚠️  /etc/ufw/before.rules absent — UFW non initialisé, règle NAT Docker ignorée."
    log_warn "   Lance 'sudo ufw enable' puis relance le script."
else
    if ! grep -q "DOCKER-MASQ" /etc/ufw/before.rules; then
        # Insérer le bloc *nat AVANT la section *filter dans before.rules
        sed -i "/^\*filter/i # vps-secure — Docker NAT (requis avec iptables:false)\n*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s ${DOCKER_SUBNET} ! -o docker0 -j MASQUERADE -m comment --comment \"DOCKER-MASQ\"\nCOMMIT\n" \
            /etc/ufw/before.rules
        # Vérifier que l'insertion a réussi (sed échoue silencieusement si *filter absent)
        if grep -q "DOCKER-MASQ" /etc/ufw/before.rules; then
            if ufw reload >/dev/null 2>&1; then
                log_success "Règle NAT Docker ajoutée et UFW rechargé (subnet : $DOCKER_SUBNET) — containers avec accès internet."
            else
                log_warn "Règle NAT Docker écrite dans before.rules mais ufw reload a échoué."
                log_warn "  Relance : sudo ufw reload"
            fi
        else
            log_warn "⚠️  Insertion NAT Docker échouée — la ligne *filter est absente de before.rules."
            log_warn "   Ajoute manuellement dans /etc/ufw/before.rules AVANT *filter :"
            log_warn "   *nat"
            log_warn "   :POSTROUTING ACCEPT [0:0]"
            log_warn "   -A POSTROUTING -s ${DOCKER_SUBNET} ! -o docker0 -j MASQUERADE"
            log_warn "   COMMIT"
        fi
    else
        log_info "Règle NAT Docker déjà présente dans before.rules."
    fi
fi

# ============================================================
# Étape 7 : Mises à jour de sécurité automatiques
# ============================================================
etape "7" "$TOTAL_ETAPES" "Activation des mises à jour de sécurité automatiques"

_wait_dpkg
apt-get install -y -qq unattended-upgrades

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'AUTOEOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
AUTOEOF

cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'UNATTEOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
UNATTEOF

systemctl enable unattended-upgrades
systemctl restart unattended-upgrades
log_success "Patches de sécurité automatiques activés."

# FIX #64 — Forcer sudo patchée (CVE-2025-32463 CVSS 9.3 CISA KEV — LPE via --chroot)
apt-get install -y -qq --only-upgrade sudo 2>/dev/null || true
log_success "sudo mis à jour — protection CVE-2025-32463."

# ── Blacklist snapd (issue #51 — CVE-2026-3888 LPE CVSS 7.8) ─────────────
if dpkg -l snapd 2>/dev/null | grep -q '^ii'; then
    log_warn "snapd détecté — suppression (CVE-2026-3888)..."
    apt-get purge -y -qq snapd
    rm -rf /snap /var/snap /var/lib/snapd 2>/dev/null || true
    log_success "snapd supprimé."
fi

cat > /etc/apt/preferences.d/99-no-snapd << 'SNAPEOF'
# vps-secure — Blacklist snapd (CVE-2026-3888 LPE CVSS 7.8)
Package: snapd
Pin: release *
Pin-Priority: -1
SNAPEOF
chmod 644 /etc/apt/preferences.d/99-no-snapd
apt-mark hold snapd 2>/dev/null || true
log_success "snapd blacklisté : Pin-Priority: -1 + apt-mark hold (CVE-2026-3888)."

# Extension unattended-upgrades → Docker CE (issue #49)
# Prérequis : "live-restore": true dans daemon.json (Étape 6) — daemon restart sans kill containers
cat > /etc/apt/apt.conf.d/52docker-upgrade << 'DOCKERUPDEOF'
// vps-secure — Auto-upgrade Docker CE
// Prérequis : live-restore=true dans /etc/docker/daemon.json
Unattended-Upgrade::Origins-Pattern {
    "origin=Docker,suite=noble";
};
Unattended-Upgrade::Automatic-Reboot "false";
DOCKERUPDEOF
log_success "Auto-upgrade Docker CE activé (52docker-upgrade) — live-restore: true actif."

# ============================================================
# Étape 8 : Durcissement du noyau Linux (sysctl)
# ============================================================
etape "8" "$TOTAL_ETAPES" "Durcissement du noyau Linux (sysctl)"

cat > /etc/sysctl.d/99-vps-secure.conf << 'SYSEOF'
# vps-secure — Kernel Hardening
# Source : CIS Benchmark Ubuntu 24.04 + DISA STIG

# Protection contre l'IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignorer les requêtes ICMP broadcast (anti-smurf)
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Désactiver les redirections ICMP (anti-MITM)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Désactiver le routage source (anti-spoofing)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Protection SYN flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# Journaliser les paquets martiens
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Forwarding IPv4 activé pour Docker (requis pour les réseaux bridge)
# Docker gère ses propres règles iptables pour isoler les containers.
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 0

# Désactiver IPv6 Router Advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# ASLR — randomisation de l'espace mémoire (CIS 1.5.3, DISA V-238369)
kernel.randomize_va_space = 2

# Protection ptrace — empêche l'espionnage entre processus (DISA V-238370)
kernel.yama.ptrace_scope = 1

# Désactiver les core dumps setuid — évite la fuite de mémoire sensible (DISA V-238371)
fs.suid_dumpable = 0

# Anti-redirect ICMP "sécurisé" — même les redirections dites sécurisées sont refusées (DISA V-238229)
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Perf events — lecture des compteurs kernel restreinte (CIS 1.5.4)
kernel.perf_event_paranoid = 3

# Restriction dmesg aux non-root — évite la fuite d'infos kernel (CIS 1.5.1)
kernel.dmesg_restrict = 1

# Masquer les adresses kernel dans /proc — anti-exploitation ASLR bypass (CIS 1.5.2)
kernel.kptr_restrict = 2

# Durcissement JIT eBPF — mitigation JIT spraying (CIS 1.5.5)
net.core.bpf_jit_harden = 2

# Interdire eBPF aux non-root — vecteur d'exploitation connu (CIS 1.5.5)
kernel.unprivileged_bpf_disabled = 1

# Port non-privilégié minimum abaissé à 22 — requis pour Endlessh (honeypot port 22)
net.ipv4.ip_unprivileged_port_start = 22


# ── KRNL-6000 — sysctl manquants Lynis 3.1.6 ──────────────────
# TTY line discipline — désactive autoload modules TTY inutiles (VPS)
dev.tty.ldisc_autoload = 0
# FIFOs — protection renforcée niveau 2 (CIS)
fs.protected_fifos = 2
# Core dumps — inclure PID dans le nom de fichier
kernel.core_uses_pid = 1
# SysRq — désactivé sur VPS (pas d'accès physique clavier)
kernel.sysrq = 0
# Log martians — journaliser les paquets à adresse source impossible
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
# NOTE : kernel.modules_disabled=1 et net.ipv4.conf.all.forwarding=0
#        intentionnellement exclus — Docker dépendant

SYSEOF

chmod 644 /etc/sysctl.d/99-vps-secure.conf
SYSCTL_OUTPUT=$(sysctl --system 2>&1)
# Ancrage immédiat — certains services (CrowdSec bouncer) peuvent resetter ces valeurs
sysctl -w net.ipv4.conf.all.log_martians=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.log_martians=1 >/dev/null 2>&1 || true
SYSCTL_ERRORS=$(echo "$SYSCTL_OUTPUT" | grep -c "^sysctl: " 2>/dev/null || echo "0")
SYSCTL_ERRORS=$(echo "$SYSCTL_ERRORS" | tr -d '[:space:]' | grep -E '^[0-9]+$' || echo "0")
if [[ "$SYSCTL_ERRORS" -gt 0 ]]; then
    log_warn "sysctl --system : $SYSCTL_ERRORS paramètre(s) rejeté(s) par le noyau :"
    echo "$SYSCTL_OUTPUT" | grep "^sysctl: " | head -5 | while IFS= read -r line; do
        log_warn "  $line"
    done
    log_warn "  Vérifie l'intégralité : sudo sysctl --system 2>&1 | grep '^sysctl:'"
else
    log_success "Noyau durci — anti-spoofing, SYN flood, ICMP, dmesg/kptr/eBPF restreints, forwarding Docker OK."
fi

# ── AppArmor userns (issue #48) — CIS compliance, Ubuntu 24.04 defaults explicites ──
if sysctl -n kernel.apparmor_restrict_unprivileged_userns &>/dev/null; then
    cat >> /etc/sysctl.d/99-vps-secure.conf << 'AAEOF'

# AppArmor userns restriction (CIS compliance — défaut Ubuntu 24.04 rendu explicite)
# Remplace kernel.unprivileged_userns_clone (Debian-only, absent Ubuntu)
# Docker non impacté (containers tournent sous profil docker-default)
kernel.apparmor_restrict_unprivileged_userns = 1
kernel.apparmor_restrict_unprivileged_unconfined = 1
AAEOF
    sysctl -p /etc/sysctl.d/99-vps-secure.conf >/dev/null 2>&1
    log_success "AppArmor userns restriction : ancré dans 99-vps-secure.conf (CIS compliance)."
else
    log_warn "AppArmor userns sysctl non disponible sur ce kernel — skipped."
fi

# Blacklist protocoles réseau inutiles (NETW-3200 — CIS 3.x)
cat >> /etc/modprobe.d/vps-secure-blacklist.conf << 'EOF'
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF
log_success "Protocoles réseau inutiles blacklistés (dccp, sctp, rds, tipc)."

# Désactiver les core dumps (KRNL-5820 — CIS 1.5.1)
grep -q "hard core" /etc/security/limits.conf \
  || printf "* hard core 0\n* soft core 0\n" >> /etc/security/limits.conf
log_success "Core dumps désactivés (limits.conf)."

# login.defs — délai minimum changement mot de passe (AUTH-9286)
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
log_success "PASS_MIN_DAYS=7 configuré (login.defs)."

# AUTH-9230 + AUTH-9229 — Password hashing rounds (Lynis 3.1.6)
grep -q "^SHA_CRYPT_MIN_ROUNDS" /etc/login.defs \
  || echo "SHA_CRYPT_MIN_ROUNDS 65536" >> /etc/login.defs
grep -q "^SHA_CRYPT_MAX_ROUNDS" /etc/login.defs \
  || echo "SHA_CRYPT_MAX_ROUNDS 65536" >> /etc/login.defs
log_success "Password hashing rounds configurés (AUTH-9229/9230)."


# ============================================================
# Étape 9 : Audit système (auditd)
# ============================================================
etape "9" "$TOTAL_ETAPES" "Activation de l'audit système (auditd)"

_wait_dpkg
apt-get install -y -qq auditd audispd-plugins 2>/dev/null || apt-get install -y -qq auditd  # optionnel : audispd-plugins absent sur certaines versions Ubuntu — fallback sur auditd seul

cat > /etc/audit/rules.d/vps-secure.rules << 'AUDITEOF'
# vps-secure — Règles d'audit ciblées
# Traçabilité des actions critiques sans surcharge disque

-D
-b 8192
-r 200

# Fichiers d'authentification et d'identité
-w /etc/passwd  -p wa -k identity
-w /etc/group   -p wa -k identity
-w /etc/shadow  -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/sudoers.d/ -p wa -k identity

# Configuration SSH
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/sshd_config.d/ -p wa -k sshd_config

# Pare-feu et réseau
-w /etc/ufw/    -p wa -k firewall
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/   -p wa -k sysctl

# Docker socket
-w /var/run/docker.sock -p rwxa -k docker_socket

# Fichiers sensibles du home vpsadmin (pas tout le home — trop verbeux)
-w /home/vpsadmin/.ssh/        -p wa -k vpsadmin_ssh
-w /home/vpsadmin/.bashrc      -p wa -k vpsadmin_profile
-w /home/vpsadmin/.profile     -p wa -k vpsadmin_profile

# Escalade de privilèges
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k privilege_escalation

# Modification de l'heure système
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time_change

# CrowdSec config
-w /etc/crowdsec/ -p wa -k crowdsec_config

# Chargement de modules kernel (DISA STIG)
-w /sbin/insmod   -p x -k kernel_modules
-w /sbin/rmmod    -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules

# gshadow (mots de passe de groupes)
-w /etc/gshadow -p wa -k identity

# ptrace — détection d'espionnage inter-processus (DISA V-238370)
-a always,exit -F arch=b64 -S ptrace -k ptrace

# Crontabs — vecteur de persistence classique
-w /etc/crontab    -p wa -k cron
-w /etc/cron.d/    -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# /etc/hosts — redirection DNS locale (MITM)
-w /etc/hosts -p wa -k hosts

# ── Anti-VoidLink (issue #46) ────────────────────────────────────────────
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -F auid!=-1 -k kernel_module_load
-a always,exit -F arch=b32 -S init_module -S finit_module -S delete_module -F auid!=-1 -k kernel_module_load
-a always,exit -F arch=b64 -S bpf -F auid>=1000 -F auid!=4294967295 -k suspicious_bpf
-a always,exit -F arch=b64 -S memfd_create -F auid>=1000 -F auid!=4294967295 -k fileless_exec
-a always,exit -F arch=b64 -S execveat -F auid>=1000 -F auid!=4294967295 -k fileless_exec
-a always,exit -F arch=b64 -S bpf -F a0=8 -k bpf_obj_pin
-a always,exit -F arch=b64 -S bpf -F a0=7 -k bpf_obj_get
-w /sys/fs/bpf -p wa -k bpf_pinned_maps

# FIX E-AUDIT — io_uring bypass auditd (CVE-2025-71239) + userfaultfd (CVE-2026-23241)
-a always,exit -F arch=b64 -S io_uring_setup -S io_uring_enter -k io_uring
-a always,exit -F arch=b64 -S userfaultfd -F auid>=1000 -F auid!=4294967295 -k userfaultfd
-e 2
AUDITEOF

# Rotation des logs audit (éviter de remplir le disque)
if [[ -d /etc/audit/auditd.conf.d ]]; then
cat > /etc/audit/auditd.conf.d/vps-secure.conf << 'AUDITCONFEOF'
max_log_file = 50
num_logs = 5
space_left_action = ROTATE
admin_space_left_action = SUSPEND
disk_full_action = ROTATE
disk_error_action = SYSLOG
backlog_wait_time = 60000
AUDITCONFEOF
else
    sed -i 's/^max_log_file .*/max_log_file = 50/'         /etc/audit/auditd.conf 2>/dev/null || true  # optionnel : clé absente si auditd.conf.d est utilisé (branche précédente)
    sed -i 's/^num_logs .*/num_logs = 5/'                  /etc/audit/auditd.conf 2>/dev/null || true  # optionnel : même raison
    sed -i 's/^space_left_action .*/space_left_action = ROTATE/' /etc/audit/auditd.conf 2>/dev/null || true  # optionnel : même raison
fi

systemctl enable auditd
systemctl restart auditd

# Note : les règles auditd sont immuables (-e 2).
# Pour les modifier, un reboot est nécessaire.

rules_count=$(auditctl -l 2>/dev/null | grep -cv "^No rules" || echo "0")
if (( rules_count > 0 )); then
    log_success "Auditd actif — ${rules_count} règles chargées."
    log_info "  Surveillance : identité, SSH, Docker socket, sudo, CrowdSec"
    log_info "  Logs : /var/log/audit/audit.log (rotation 50 MB × 5)"
    log_info "  Consulter : ausearch -k docker_socket"
else
    log_warn "Auditd installé mais règles non chargées — vérifie : auditctl -l"
fi

# ── voidlink-detect (issue #46) ──────────────────────────────────────────
cat > /usr/local/bin/voidlink-detect << 'VOIDLINKEOF'
#!/usr/bin/env bash
set -uo pipefail
ALERTS=()

for pid_dir in /proc/[0-9]*/; do
    pid="${pid_dir%/}"; pid="${pid##*/}"
    [[ -d "/proc/${pid}" ]] || continue
    comm=$(cat "/proc/${pid}/comm" 2>/dev/null) || continue
    if ! ps -p "$pid" > /dev/null 2>&1; then
        [[ -d "/proc/${pid}" ]] || continue
        ALERTS+=("PROCESSUS CACHÉ : PID ${pid} (${comm})")
    fi
done

LSMOD_NAMES=$(lsmod 2>/dev/null | awk 'NR>1 {print $1}' | sort)
while IFS= read -r mod; do
    echo "$LSMOD_NAMES" | grep -qx "$mod" && continue
    case "$mod" in
        kernel|parameters|uevent_seqnum|version|srcversion|holders|notes|sections|initrd|refcnt) continue ;;
    esac
    ALERTS+=("MODULE CACHÉ : ${mod} présent dans /sys/module mais absent de lsmod")
done < <(ls /sys/module/ 2>/dev/null | sort)

WHITELIST_PATTERNS=("^/sys/fs/bpf/tc/" "^/sys/fs/bpf/cgroup/" "^/sys/fs/bpf/crowdsec" "^/sys/fs/bpf/xdp/")
if [[ -d /sys/fs/bpf ]]; then
    while IFS= read -r pin; do
        whitelisted=0
        for pattern in "${WHITELIST_PATTERNS[@]}"; do
            [[ "$pin" =~ $pattern ]] && { whitelisted=1; break; }
        done
        [[ $whitelisted -eq 1 ]] || ALERTS+=("MAP eBPF SUSPECTE : ${pin}")
    done < <(find /sys/fs/bpf -type f 2>/dev/null || true)
fi

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
if [[ ${#ALERTS[@]} -eq 0 ]]; then
    echo "[${TIMESTAMP}] voidlink-detect : OK"
    exit 0
fi
echo "[${TIMESTAMP}] voidlink-detect : ⚠️ ${#ALERTS[@]} ALERTE(S)"
for alert in "${ALERTS[@]}"; do echo "  → ${alert}"; done

CONFIG="/etc/vps-secure/telegram.conf"
if [[ -f "$CONFIG" ]]; then
    TELEGRAM_TOKEN=$(grep '^TELEGRAM_TOKEN=' "$CONFIG" | cut -d'"' -f2)
    TELEGRAM_CHAT_ID=$(grep '^TELEGRAM_CHAT_ID=' "$CONFIG" | cut -d'"' -f2)
    if [[ -n "$TELEGRAM_TOKEN" ]] && [[ -n "$TELEGRAM_CHAT_ID" ]]; then
        HOST=$(hostname)
        MSG="🚨 voidlink-detect ALERTE sur ${HOST}
📅 ${TIMESTAMP}
⚠️ ${#ALERTS[@]} anomalie(s) :
$(printf '  → %s\n' "${ALERTS[@]}")"
        CURLCFG=$(mktemp); chmod 600 "$CURLCFG"
        printf 'url = "https://api.telegram.org/bot%s/sendMessage"\ndata = "chat_id=%s"\n' \
            "$TELEGRAM_TOKEN" "$TELEGRAM_CHAT_ID" > "$CURLCFG"
        curl -s --config "$CURLCFG" --data-urlencode "text=${MSG}" > /dev/null 2>&1
        rm -f "$CURLCFG"
    fi
fi
exit 2
VOIDLINKEOF

chmod 700 /usr/local/bin/voidlink-detect
chattr +i /usr/local/bin/voidlink-detect

echo "30 2 * * * root /usr/local/bin/voidlink-detect >> /var/log/voidlink-detect.log 2>&1" \
    > /etc/cron.d/voidlink-detect
chmod 644 /etc/cron.d/voidlink-detect

cat > /etc/logrotate.d/voidlink-detect << 'LOGROTEOF'
/var/log/voidlink-detect.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    create 640 root root
}
LOGROTEOF

log_success "voidlink-detect installé — scan quotidien 02h30 UTC."
log_info "  Script   : /usr/local/bin/voidlink-detect"
log_info "  Log      : /var/log/voidlink-detect.log"
log_info "  Tester   : sudo /usr/local/bin/voidlink-detect"

# ============================================================
# Étape 10 : Swap
# ============================================================
etape "10" "$TOTAL_ETAPES" "Configuration du swap"

SWAP_FILE="/swapfile"
SWAP_SIZE="2G"

# Vérifier l'espace disque disponible avant de créer le swap
AVAILABLE_KB=$(df --output=avail / | tail -1)
if [[ "$AVAILABLE_KB" -lt 2621440 ]]; then
    log_warn "Espace disque limité ($(( AVAILABLE_KB / 1024 )) MB disponible) — swap réduit à 512M."
    SWAP_SIZE="512M"
fi

if swapon --show | grep -q "$SWAP_FILE"; then
    log_warn "Swap déjà actif — on continue."
    swapon --show
elif [[ -f "$SWAP_FILE" ]]; then
    log_warn "Fichier swap existant mais inactif — réactivation..."
    chmod 600 "$SWAP_FILE"
    swapon "$SWAP_FILE"
    grep -q "$SWAP_FILE" /etc/fstab || echo "$SWAP_FILE none swap sw 0 0" >> /etc/fstab
    log_success "Swap réactivé."
else
    # Créer le fichier swap
    log_info "Création d'un swap de $SWAP_SIZE..."
    SWAP_MB=$(numfmt --from=iec "$SWAP_SIZE" 2>/dev/null \
        | awk '{print int($1/1024/1024)}' || echo "512")
    SWAP_MB=$(echo "$SWAP_MB" | tr -d '[:space:]')
    SWAP_MB="${SWAP_MB:-512}"
    fallocate -l "$SWAP_SIZE" "$SWAP_FILE" 2>/dev/null || \
        dd if=/dev/zero of="$SWAP_FILE" bs=1M count="$SWAP_MB" status=none
    chmod 600 "$SWAP_FILE"
    mkswap "$SWAP_FILE" > /dev/null
    swapon "$SWAP_FILE"

    # Rendre le swap permanent au reboot
    if ! grep -q "$SWAP_FILE" /etc/fstab; then
        echo "$SWAP_FILE none swap sw 0 0" >> /etc/fstab
    fi

    # Optimiser pour un serveur (swap utilisé en dernier recours)
    echo "vm.swappiness=10"         >> /etc/sysctl.d/99-vps-secure.conf
    echo "vm.vfs_cache_pressure=50" >> /etc/sysctl.d/99-vps-secure.conf
    SYSCTL_SWAP_OUTPUT=$(sysctl -p /etc/sysctl.d/99-vps-secure.conf 2>&1)
    SYSCTL_SWAP_ERRORS=$(echo "$SYSCTL_SWAP_OUTPUT" | grep -c "^sysctl: " 2>/dev/null || echo "0")
    SYSCTL_SWAP_ERRORS=$(echo "$SYSCTL_SWAP_ERRORS" | tr -d '[:space:]')
    SYSCTL_SWAP_ERRORS="${SYSCTL_SWAP_ERRORS:-0}"
    if [[ "$SYSCTL_SWAP_ERRORS" -gt 0 ]]; then
        log_warn "sysctl -p : $SYSCTL_SWAP_ERRORS paramètre(s) rejeté(s) (swappiness/vfs_cache_pressure) :"
        echo "$SYSCTL_SWAP_OUTPUT" | grep "^sysctl: " | while IFS= read -r line; do
            log_warn "  $line"
        done
    fi

    log_success "Swap de $SWAP_SIZE actif (swappiness=10 — utilisé en dernier recours)."
fi

# ============================================================
# Étape 11 : Scanner de rootkits (rkhunter)
# ============================================================
etape "11" "$TOTAL_ETAPES" "Installation du scanner de rootkits (rkhunter)"
# NOTE : rkhunter 1.4.6 (2018) est la version disponible dans les dépôts Ubuntu 24.04.
# Sa base de signatures couvre les rootkits connus jusqu'à ~2020.
# Les rootkits post-2022 (BPFDoor, Symbiote, OrBit) ne sont pas détectés par rkhunter.
# La couverture est complétée par AIDE (étape 15) + auditd (étape 9).

_wait_dpkg
# M2 : unhide ajouté — améliore la détection de processus cachés par rkhunter
apt-get install -y -qq rkhunter unhide

# Supprimer les faux positifs connus sur Ubuntu 24.04 + Docker
# Sans ce fichier : chaque apt upgrade génère des warnings sur les binaires mis à jour,
# et egrep/fgrep/which sont flagués "suspicious script replacement" dès le premier scan.
cat > /etc/rkhunter.conf.local << 'RKHEOF'
# vps-secure — Suppressions faux positifs rkhunter
# Ubuntu 24.04 LTS + Docker Engine
PKGMGR=DPKG
# Scripts bash légitimes (wrappers grep, utilitaires user/group, ldd)
SCRIPTWHITELIST=/usr/bin/egrep
SCRIPTWHITELIST=/usr/bin/fgrep
SCRIPTWHITELIST=/usr/bin/which
SCRIPTWHITELIST=/usr/bin/ldd
SCRIPTWHITELIST=/usr/sbin/adduser
SCRIPTWHITELIST=/usr/sbin/deluser
SCRIPTWHITELIST=/usr/sbin/addgroup
SCRIPTWHITELIST=/usr/sbin/delgroup
# Fichiers cachés légitimes Ubuntu 24.04 / systemd-resolved
ALLOWHIDDENFILE=/etc/.resolv.conf.systemd-resolved.bak
ALLOWHIDDENFILE=/etc/.updated
ALLOWHIDDENFILE=/etc/.pwd.lock
TMPDIR=/var/lib/rkhunter/tmp
# M1 : Transmettre alertes rkhunter à syslog (authpriv.warning)
# Visible dans /var/log/auth.log — corrélable avec auditd
USE_SYSLOG=authpriv.warning
# E3 : Docker overlay2 génère des faux positifs "deleted files" pour les containers actifs
# (libs des containers marquées "(deleted)" dans /proc/maps — comportement normal overlay2)
# Ce test est redondant avec AIDE — désactivé pour éliminer l'alert fatigue quotidienne
DISABLE_TESTS=deleted_files
WEB_CMD=""
RKHEOF
mkdir -p /var/lib/rkhunter/tmp
chmod 700 /var/lib/rkhunter/tmp
chmod 640 /etc/rkhunter.conf.local

# rkhunter --update : volontairement omis (fix #42)
# Raisons :
#   1. WEB_CMD="" dans rkhunter.conf.local désactive les requêtes HTTP (sécurité — CIS 1.x)
#   2. Upstream SourceForge rkhunter 1.4.6 abandonné depuis 2018 — téléchargement échoue systématiquement
# Protection réelle = baseline --propupd (hashes binaires installés) — créée ci-dessous
log_info "  Signatures rkhunter : base v1.4.6 intégrée (rootkits classiques couverts)."
log_info "  Baseline binaires   : création via --propupd en cours..."

# Construire la baseline (empreinte initiale du système — état "sain")
rkhunter --propupd --nocolors > /dev/null 2>&1 || true  # optionnel : peut échouer si des fichiers sont verrouillés — non bloquant, scan quotidien continuera

# Vérifier que rkhunter.conf.local est bien pris en compte (après --propupd, base initialisée)
if rkhunter --config-check --nocolors > /dev/null 2>&1; then
    log_success "rkhunter.conf.local validé (--config-check OK)."
else
    log_warn "rkhunter --config-check a retourné des erreurs — vérifier : sudo rkhunter --config-check"
fi

# Premier scan silencieux pour valider l'installation
rkhunter --check --sk --nocolors > /tmp/rkhunter-first-scan.log 2>&1 || true  # optionnel : warnings attendus sur install fraîche (Docker, etc.) — résultat dans le log, non bloquant

log_success "rkhunter installé — baseline enregistrée · faux positifs Ubuntu/Docker supprimés."
log_info "  Baseline créée après Docker — les fichiers Docker sont inclus dans l'état 'sain'."
log_info "  Les futures modifications Docker ne déclencheront PAS d'alertes rkhunter."
log_info "  Scanner manuellement : sudo rkhunter --check --report-warnings-only"
log_info "  Dernier rapport      : /var/log/rkhunter.log"

# Cron rkhunter quotidien à 00h00 UTC (02h00 Paris) — indépendant de Telegram
# (si Telegram n'est pas configuré, rkhunter scanne quand même)
if [[ ! -f /etc/cron.d/rkhunter-daily ]]; then
    echo "0 0 * * * root rkhunter --check --sk --report-warnings-only --nocolors >> /var/log/rkhunter-cron.log 2>&1" \
        > /etc/cron.d/rkhunter-daily
    chmod 644 /etc/cron.d/rkhunter-daily
    log_success "Scan rkhunter quotidien configuré à 00h00 UTC (02h00 Paris) (log : /var/log/rkhunter-cron.log)."
fi

# Hook apt — rkhunter --propupd automatique après chaque apt upgrade
# Sans ça, tout binaire mis à jour par apt déclenche une fausse alerte rkhunter
# C3 : Hook APT maintenu (évite faux positifs rkhunter) mais rendu traçable dans les logs
cat > /etc/apt/apt.conf.d/99-rkhunter-propupd << 'RKHAPTEOF'
DPkg::Post-Invoke {
    "if command -v rkhunter >/dev/null 2>&1; then rkhunter --propupd --nocolors >> /var/log/rkhunter-propupd.log 2>&1 || true; fi";
};
RKHAPTEOF
chmod 640 /etc/apt/apt.conf.d/99-rkhunter-propupd
touch /var/log/rkhunter-propupd.log
chmod 640 /var/log/rkhunter-propupd.log
log_success "Hook apt rkhunter configuré — baseline mise à jour automatiquement après chaque apt upgrade."

# Nettoyage du log du premier scan — lire les warnings avant suppression
FIRST_SCAN_WARNINGS=$(grep -c "Warning" /tmp/rkhunter-first-scan.log 2>/dev/null || true)
FIRST_SCAN_WARNINGS=$(echo "${FIRST_SCAN_WARNINGS:-0}" | tr -d '[:space:]' | grep -E '^[0-9]+$' || echo "0")
if [[ "$FIRST_SCAN_WARNINGS" -gt 0 ]]; then
    log_warn "rkhunter premier scan : ${FIRST_SCAN_WARNINGS} warning(s) détecté(s)."
    log_warn "  Rapport complet : sudo cat /var/log/rkhunter.log | grep -A2 'Warning'"
    log_warn "  Si faux positifs : ajouter SCRIPTWHITELIST ou ALLOWHIDDENFILE dans /etc/rkhunter.conf.local"
fi
rm -f /tmp/rkhunter-first-scan.log

# ============================================================
# Étape 12 : Désactivation des services inutiles
# ============================================================
etape "12" "$TOTAL_ETAPES" "Désactivation des services inutiles"

# Ctrl-Alt-Delete désactivé (DISA STIG V-238330 — empêche reboot non intentionnel)
systemctl mask ctrl-alt-del.target 2>/dev/null || true  # optionnel : déjà masqué sur certaines images hébergeur
log_success "Ctrl-Alt-Delete désactivé."

# Services réseau inutiles — chaque service actif = surface d'attaque (CIS 2.x)
SERVICES_INUTILES=(avahi-daemon cups bluetooth ModemManager whoopsie apport)
for svc in "${SERVICES_INUTILES[@]}"; do
    if systemctl is-active "$svc" &>/dev/null || systemctl is-enabled "$svc" &>/dev/null; then
        systemctl disable --now "$svc" 2>/dev/null || true  # optionnel : service peut ne pas être installé sur cette image
        log_success "Service $svc désactivé."
    fi
done
# Postfix hardening — cacher banner OS + désactiver VRFY (MAIL-8818, MAIL-8820)
if command -v postconf &>/dev/null; then
    postconf -e 'smtpd_banner = $myhostname ESMTP'
    postconf -e 'disable_vrfy_command = yes'
    systemctl reload postfix 2>/dev/null || true
    log_success "Postfix durci — banner OS masqué, VRFY désactivé."
fi
log_info "  Services vérifiés : avahi-daemon, cups, bluetooth, ModemManager, whoopsie, apport, postfix"
log_info "  Pour voir les services actifs : systemctl list-units --type=service --state=active"

# ============================================================
# Étape 13 : Alertes Telegram (optionnel)
# ============================================================
etape "13" "$TOTAL_ETAPES" "Alertes de sécurité Telegram (optionnel)"

echo ""
echo -e "  ${BLANC}Reçois un rapport quotidien sur Telegram :${RESET}"
echo -e "  ${VERT}  ✅ Tout va bien${RESET} ${BLANC}ou${RESET} ${ROUGE}🔴 Anomalie détectée + solution${RESET}"
echo ""
read -rp "  Configurer les alertes Telegram ? (oui/non) : " tg_answer

if [[ "$tg_answer" != "oui" ]]; then
    log_warn "Alertes ignorées — configurable plus tard en relançant le script."
else
    echo ""
    echo -e "  ${BLANC}Étapes rapides :${RESET}"
    echo -e "  ${BLANC}  1. Ouvre Telegram → cherche @BotFather → /newbot → copie le token${RESET}"
    echo -e "  ${BLANC}  2. Cherche @userinfobot → /start → copie ton ID${RESET}"
    echo ""
    read -rp "  → Token du bot (ex: 123456789:AAF...) : " TG_TOKEN
    read -rp "  → Ton chat ID  (ex: 987654321)       : " TG_CHAT_ID

    # Validation basique
    if [[ -z "$TG_TOKEN" ]] || [[ -z "$TG_CHAT_ID" ]]; then
        log_warn "Token ou chat ID vide — alertes non configurées."
    else
        log_info "Test de la connexion Telegram..."
        CURLCFG=$(mktemp)
        chmod 600 "$CURLCFG"
        cat > "$CURLCFG" << EOF
url = "https://api.telegram.org/bot${TG_TOKEN}/sendMessage"
data = "chat_id=${TG_CHAT_ID}&text=✅ vps-secure actif sur ce VPS. Tu recevras un rapport de sécurité quotidien à 07h00."
EOF
        TG_TEST=$(curl -s --config "$CURLCFG" 2>/dev/null)
        rm -f "$CURLCFG"

        if echo "$TG_TEST" | grep -q '"ok":true'; then
            log_success "Message Telegram envoyé — connexion OK."

            # Stocker les credentials
            mkdir -p /etc/vps-secure
            cat > /etc/vps-secure/telegram.conf << EOF
TELEGRAM_TOKEN="${TG_TOKEN}"
TELEGRAM_CHAT_ID="${TG_CHAT_ID}"
EOF
            chmod 600 /etc/vps-secure/telegram.conf
            log_success "Credentials stockés dans /etc/vps-secure/telegram.conf (chmod 600)."

            # Créer le script de vérification quotidien
            cat > /usr/local/bin/vps-secure-check.sh << 'CHECKEOF'
#!/usr/bin/env bash
# vps-secure — Rapport de sécurité quotidien
# Lancé par cron chaque jour à 07h00

CONFIG="/etc/vps-secure/telegram.conf"
[[ -f "$CONFIG" ]] || exit 0

# Parsing explicite — évite les injections via source
TELEGRAM_TOKEN=$(grep '^TELEGRAM_TOKEN=' "$CONFIG" | cut -d'"' -f2)
TELEGRAM_CHAT_ID=$(grep '^TELEGRAM_CHAT_ID=' "$CONFIG" | cut -d'"' -f2)

[[ -z "$TELEGRAM_TOKEN" ]] || [[ -z "$TELEGRAM_CHAT_ID" ]] && exit 0

DATE=$(date '+%d/%m/%Y')
HOST=$(hostname)
DETAILS=""
ISSUES=0

send_telegram() {
    local CURLCFG
    CURLCFG=$(mktemp)
    chmod 600 "$CURLCFG"
    printf 'url = "https://api.telegram.org/bot%s/sendMessage"\ndata = "chat_id=%s"\n' \
        "$TELEGRAM_TOKEN" "$TELEGRAM_CHAT_ID" > "$CURLCFG"
    curl -s --config "$CURLCFG" --data-urlencode "text=$1" > /dev/null 2>&1
    rm -f "$CURLCFG"
}

# ── CrowdSec ──
CS_COUNT=$(cscli alerts list --since 24h -o json 2>/dev/null \
    | python3 -c "import sys,json
try:
    d=json.load(sys.stdin)
    print(len(d) if d else 0)
except:
    print(0)" 2>/dev/null || echo "0")

if [[ "$CS_COUNT" -gt 0 ]]; then
    ISSUES=$((ISSUES + 1))
    DETAILS+="🛡️ CrowdSec : ${CS_COUNT} alerte(s) en 24h
  → Normal si IPs bannies : CrowdSec fait son travail.
  → Détail : sudo cscli alerts list --since 24h

"
else
    DETAILS+="✅ CrowdSec : aucune alerte
"
fi

# ── rkhunter ──
# mktemp évite l'attaque symlink (/tmp world-writable, script tourne en root)
RKHUNTER_LOG=$(mktemp /tmp/rkhunter-XXXXXX.log)
# FIX B-1 — Lire le scan 00h00 (évite double scan coûteux sur KVM2)
RKHUNTER_CRON_LOG="/var/log/rkhunter-cron.log"
if [[ -f "$RKHUNTER_CRON_LOG" ]] && find "$RKHUNTER_CRON_LOG" -mmin -480 -quiet 2>/dev/null; then
    RKHUNTER_LOG="$RKHUNTER_CRON_LOG"
else
    RKHUNTER_LOG=$(mktemp /tmp/rkhunter-XXXXXX.log)
    trap 'rm -f "$RKHUNTER_LOG"' EXIT
    rkhunter --check --sk --report-warnings-only --nocolors > "$RKHUNTER_LOG" 2>&1
fi
RK_WARNINGS=$(grep -c "Warning" "$RKHUNTER_LOG" 2>/dev/null || true); RK_WARNINGS="${RK_WARNINGS:-0}"

if [[ "$RK_WARNINGS" -gt 0 ]]; then
    ISSUES=$((ISSUES + 1))
    DETAILS+="🔴 rkhunter : ${RK_WARNINGS} anomalie(s) détectée(s)
  → Lance : sudo rkhunter --check --report-warnings-only
  → Si faux positif : sudo rkhunter --propupd
  → Log : /var/log/rkhunter.log

"
else
    DETAILS+="✅ rkhunter : aucune anomalie
"
fi

# C3 : Notifier si baseline rkhunter a été mise à jour par apt dans les 27h
PROPUPD_LOG="/var/log/rkhunter-propupd.log"
PROPUPD_RECENT=""
if [[ -f "$PROPUPD_LOG" ]] && find "$PROPUPD_LOG" -mmin -1620 -quiet 2>/dev/null; then
    PROPUPD_DATE=$(stat -c "%y" "$PROPUPD_LOG" 2>/dev/null | cut -d'.' -f1 | sed 's/ /T/' | cut -c1-16 || echo "jamais")
    PROPUPD_RECENT="ℹ️ Baseline rkhunter mise à jour par apt le ${PROPUPD_DATE}"
fi

# ── auditd ──
# Seuil : n'alerter que si AUDIT_TOTAL > 10 (quelques sudo normaux = bruit)
# ET : détecter uniquement les vrais comportements anormaux

PRIV_COUNT=$(ausearch -k privilege_escalation --start today -i 2>/dev/null | grep -c "type=" || true); PRIV_COUNT="${PRIV_COUNT:-0}"
DOCK_COUNT=$(ausearch -k docker_socket --start today -i 2>/dev/null | grep -c "type=" || true); DOCK_COUNT="${DOCK_COUNT:-0}"
SSH_COUNT=$(ausearch -k sshd_config --start today -i 2>/dev/null | grep -c "type=" || true); SSH_COUNT="${SSH_COUNT:-0}"
AUDIT_TOTAL=$((PRIV_COUNT + DOCK_COUNT + SSH_COUNT))

# Seuil adaptatif : alerte si > 10 événements/jour (admin normal = 3-5 sudo max)
AUDIT_THRESHOLD=10

if [[ "$AUDIT_TOTAL" -gt "$AUDIT_THRESHOLD" ]]; then
    ISSUES=$((ISSUES + 1))
    DETAILS+="🔴 auditd : ${AUDIT_TOTAL} événements suspects (seuil : ${AUDIT_THRESHOLD})\n"
    DETAILS+="   Escalades privilèges : ${PRIV_COUNT} | Docker : ${DOCK_COUNT} | SSH config : ${SSH_COUNT}\n"
elif [[ "$AUDIT_TOTAL" -gt 0 ]]; then
    DETAILS+="ℹ️ auditd : ${AUDIT_TOTAL} événement(s) normal(aux) (admin quotidien)\n"
else
    DETAILS+="✅ auditd : aucun événement suspect\n"
fi

# ── Endlessh (honeypot port 22) ──
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^endlessh$'; then
    HONEY_COUNT=$(docker logs endlessh --since 1440m 2>&1 | grep -ci "accept" || echo "0")
    DETAILS+="🍯 Endlessh : ${HONEY_COUNT} bot(s) piégé(s) en 24h
"
else
    DETAILS+="⚠️ Endlessh : container non actif
  → Relance : sudo docker start endlessh
"
fi

# ── AIDE (integrity monitoring) ──
AIDE_EXIT_FILE="/var/log/aide-daily.exit"
AIDE_CONTEXT_FILE="/var/log/aide-daily.exit.context"
# E1 : Vérification de fraîcheur — le scan AIDE tourne à 03h00, rapport à 07h00, marge = 28h
if [[ ! -f "$AIDE_EXIT_FILE" ]]; then
    DETAILS+="⚠️ AIDE — fichier résultat manquant (cron désactivé ?)
"
    ISSUES=$(( ISSUES + 1 ))
elif ! find "$AIDE_EXIT_FILE" -mmin -1680 -quiet 2>/dev/null; then
    DETAILS+="⚠️ AIDE — pas de scan depuis +28h (cron en panne ?)
"
    ISSUES=$(( ISSUES + 1 ))
else
    AIDE_EXIT=$(cat "$AIDE_EXIT_FILE" 2>/dev/null || echo "99")
    # C2 : Tester les erreurs techniques EN PREMIER (& 56 avant & 7)
    # Évite de classifier les exits 14/15/17/18/19 comme "modifications détectées"
    if [[ "$AIDE_EXIT" -ge 128 ]]; then
        DETAILS+="⚠️ AIDE — erreur système (signal $(( AIDE_EXIT - 128 )))
"
        ISSUES=$(( ISSUES + 1 ))
    elif [[ $(( AIDE_EXIT & 56 )) -ne 0 ]]; then
        DETAILS+="⚠️ AIDE — erreur technique (code $AIDE_EXIT)
"
        ISSUES=$(( ISSUES + 1 ))
    elif [[ $(( AIDE_EXIT & 7 )) -ne 0 ]]; then
        # C1 : Message contextuel non-anxiogène si apt a tourné
        if [[ -f "$AIDE_CONTEXT_FILE" ]]; then
            DPKG_PKG_COUNT=$(grep -oP 'dpkg_active:\K[0-9]+' "$AIDE_CONTEXT_FILE" 2>/dev/null || echo "?")
            DETAILS+="ℹ️ AIDE — apt a mis à jour ~${DPKG_PKG_COUNT} pkg(s). OK si attendu — validez : aide --update
"
        else
            # Fix #44 : context file absent — apt a peut-être tourné APRÈS le scan AIDE (01h UTC)
            # Double vérification via dpkg.log (couvre unattended-upgrades post-01h UTC)
            APT_ACTIVITY=$(awk -v cutoff="$(date -d '12 hours ago' '+%Y-%m-%d %H:%M:%S')" \
                '$0 > cutoff && / status installed / {count++} END {print count+0}' \
                /var/log/dpkg.log 2>/dev/null | tr -d '[:space:]')
                APT_ACTIVITY="${APT_ACTIVITY:-0}"
            if [[ "$APT_ACTIVITY" -gt 0 ]]; then
                DETAILS+="ℹ️ AIDE — ${APT_ACTIVITY} pkg(s) via apt après le scan. OK si attendu — rebase : sudo vps-secure-aide-rebase
"
            else
                DETAILS+="🚨 AIDE — MODIFICATIONS INATTENDUES (aucune activité apt)
  → Vérifier : sudo aide --check --config /etc/aide/aide.conf
"
                ISSUES=$(( ISSUES + 1 ))
            fi
        fi
    else
        DETAILS+="✅ AIDE OK
"
    fi
fi

# ── Envoi du rapport ──
if [[ "$ISSUES" -eq 0 ]]; then
    HEADER="✅ Tout va bien sur ton VPS"
    FOOTER="Aucune action requise."
else
    HEADER="⚠️ ${ISSUES} point(s) à vérifier sur ton VPS"
    FOOTER="Suis les instructions ci-dessus pour chaque point."
fi

MESSAGE="🔐 vps-secure — Rapport quotidien
📅 ${DATE} · ${HOST}

${HEADER}

${DETAILS}
${PROPUPD_RECENT:+${PROPUPD_RECENT}
}${FOOTER}"

send_telegram "$MESSAGE"
CHECKEOF

            chmod +x /usr/local/bin/vps-secure-check.sh

            # Rapport Telegram quotidien 07h00 UTC (= 09h00 Paris heure d'été CEST / 08h00 heure d'hiver CET)
            echo "0 7 * * * root /usr/local/bin/vps-secure-check.sh" > /etc/cron.d/vps-secure
            chmod 644 /etc/cron.d/vps-secure

            log_success "Rapport quotidien configuré — tous les jours à 07h00 UTC (09h00 Paris CEST / 08h00 CET)."
            log_info "  Script    : /usr/local/bin/vps-secure-check.sh"
            log_info "  Config    : /etc/vps-secure/telegram.conf"
            log_info "  Cron      : /etc/cron.d/vps-secure"
            log_info "  Tester maintenant : sudo /usr/local/bin/vps-secure-check.sh"

            # ── Alerte SSH en temps réel (PAM) ──
            # Notification Telegram immédiate à chaque connexion SSH réussie
            cat > /usr/local/bin/vps-secure-ssh-alert.sh << 'SSHALERTEOF'
#!/usr/bin/env bash
# vps-secure — Alerte SSH temps réel
# Déclenché par PAM à chaque ouverture de session SSH réussie

# Uniquement les ouvertures de session SSH (pas sudo, cron, su...)
[[ "$PAM_TYPE"    != "open_session" ]] && exit 0
[[ "$PAM_SERVICE" != "sshd"         ]] && exit 0

CONFIG="/etc/vps-secure/telegram.conf"
[[ -f "$CONFIG" ]] || exit 0

TELEGRAM_TOKEN=$(grep '^TELEGRAM_TOKEN=' "$CONFIG" | cut -d'"' -f2)
TELEGRAM_CHAT_ID=$(grep '^TELEGRAM_CHAT_ID=' "$CONFIG" | cut -d'"' -f2)
[[ -z "$TELEGRAM_TOKEN" ]] || [[ -z "$TELEGRAM_CHAT_ID" ]] && exit 0

DATE=$(date '+%d/%m/%Y %H:%M:%S')
HOST=$(hostname)

CURLCFG=$(mktemp)
chmod 600 "$CURLCFG"
printf 'url = "https://api.telegram.org/bot%s/sendMessage"\ndata = "chat_id=%s"\n' \
    "$TELEGRAM_TOKEN" "$TELEGRAM_CHAT_ID" > "$CURLCFG"
curl -s --config "$CURLCFG" \
    --data-urlencode "text=🔐 Connexion SSH sur ${HOST}
👤 Utilisateur : ${PAM_USER:-inconnu}
🌐 IP source   : ${PAM_RHOST:-inconnue}
📅 ${DATE}" > /dev/null 2>&1
rm -f "$CURLCFG"
SSHALERTEOF

            chmod +x /usr/local/bin/vps-secure-ssh-alert.sh

            # Injecter la règle PAM dans /etc/pam.d/sshd (optionnel — ne bloque pas le login si erreur)
            PAM_SSHD="/etc/pam.d/sshd"
            if ! grep -q "vps-secure-ssh-alert" "$PAM_SSHD" 2>/dev/null; then
                echo "session optional pam_exec.so /usr/local/bin/vps-secure-ssh-alert.sh" >> "$PAM_SSHD"
                log_success "Alerte SSH temps réel configurée — notification à chaque connexion."
            else
                log_warn "Règle PAM SSH déjà présente — non dupliquée."
            fi
            log_info "  Script PAM : /usr/local/bin/vps-secure-ssh-alert.sh"
            log_info "  Variables  : PAM_USER (utilisateur) · PAM_RHOST (IP source)"

        else
            log_warn "Connexion Telegram échouée — alertes non configurées."
            log_warn "Vérifie ton token et ton chat ID, puis relance le script."
            log_info "  Erreur : $(echo "$TG_TEST" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('description','inconnue'))" 2>/dev/null || echo 'inconnue')"
        fi
    fi
fi

# ============================================================
# Étape 14 : Honeypot SSH (Endlessh — port 22)
# ============================================================
etape "14" "$TOTAL_ETAPES" "Honeypot SSH (Endlessh — port 22)"

log_info "Port 22 libéré — Endlessh le capture pour piéger les bots."

# On vérifie si UFW est là, mais on n'installe RIEN (pour éviter le conflit avec Docker)
if command -v ufw >/dev/null 2>&1; then
    # On ouvre le port 22. Le || true évite de crash si Docker a "verrouillé" iptables
    ufw allow 22/tcp comment 'Honeypot Endlessh' || log_warn "UFW busy, vérifie le port 22 plus tard."
    log_success "Port 22 ouvert dans UFW."
else
    log_error "UFW introuvable (problème étape 5). Le honeypot risque d'être bloqué."
fi

# Lancer le container (Ta logique originale est parfaite ici)
if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q '^endlessh$'; then
    log_warn "Container Endlessh déjà présent — redémarrage."
    docker rm -f endlessh 2>/dev/null || true
fi

docker run -d \
    --name endlessh \
    --restart unless-stopped \
    --network=host \
    --security-opt no-new-privileges:true \
    --cap-drop ALL \
    --cap-add NET_BIND_SERVICE \
    --read-only \
    shizunge/endlessh-go@sha256:c9c5cd7084fda893f2b9f2c15d0b5867ba91ed06727375a3ca0f2678474fc09a \
    -logtostderr -v=1 -port=22 > /dev/null || true

sleep 2
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^endlessh$'; then
    log_success "Endlessh actif sur le port 22."
else
    log_warn "Endlessh n'a pas démarré."
fi

# ============================================================
# Étape 14b : Bot Funnel — redirection bots SSH vers Endlessh
# ============================================================
etape "14b" "$TOTAL_ETAPES" "Bot Funnel — redirection bots SSH vers Endlessh"

BOT_FUNNEL_SCRIPT="/usr/local/bin/vps-secure-bot-funnel.sh"
BOT_FUNNEL_SERVICE="/etc/systemd/system/vps-secure-bot-funnel.service"
BOT_FUNNEL_KEY_FILE="/etc/crowdsec/vps-secure-bot-funnel.key"

# Déployer le script Bot Funnel (inline — pas de dépendance réseau)
cat > "$BOT_FUNNEL_SCRIPT" << 'BOTFUNNELEOF'
#!/bin/bash
# =============================================================================
# vps-secure-bot-funnel.sh v1.0.1 — Bot Funnel (SSH Honeypot Redirect)
# Rôle    : Redirige les bots SSH détectés par CrowdSec vers Endlessh (port 22)
#           au lieu de les bloquer.
# Prérequis : CrowdSec LAPI actif (port 8081), Endlessh sur port 22 (host network)
# =============================================================================

set -euo pipefail

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
readonly LAPI_URL="http://localhost:8081"
readonly BOUNCER_KEY_FILE="/etc/crowdsec/vps-secure-bot-funnel.key"
readonly REDIRECT_CHAIN="VPS_BOT_FUNNEL"
readonly SSH_REAL_PORT="2222"
readonly HONEYPOT_PORT="22"
readonly LOG_TAG="VPS-SECURE-BOT-FUNNEL"
readonly POLL_INTERVAL=30
readonly WHITELIST_FILE="/etc/crowdsec/parsers/s00-raw/known-ips.conf"

# ─────────────────────────────────────────────
# Pré-requis
# ─────────────────────────────────────────────
[[ $EUID -ne 0 ]] && { echo "ERROR: root requis" >&2; exit 1; }

mkdir -p /var/lib/vps-secure

BOUNCER_KEY=$(cat "$BOUNCER_KEY_FILE" 2>/dev/null) || {
    logger -t "$LOG_TAG" "ERREUR: Clé API introuvable — $BOUNCER_KEY_FILE"
    exit 1
}

# ─────────────────────────────────────────────
# Gestion de la chaîne iptables NAT
# ─────────────────────────────────────────────
init_chain() {
    # Note : PREROUTING NAT est évalué AVANT INPUT par iptables.
    # Les IPs SSH bannies par CrowdSec (DROP en INPUT via firewall bouncer)
    # sont redirigées vers Endlessh (REDIRECT en PREROUTING) — intentionnel :
    # les bots sont piégés dans le honeypot plutôt que simplement bloqués.
    iptables -t nat -N "$REDIRECT_CHAIN" 2>/dev/null || true
    if ! iptables -t nat -C PREROUTING \
         -p tcp --dport "$SSH_REAL_PORT" -j "$REDIRECT_CHAIN" 2>/dev/null; then
        iptables -t nat -I PREROUTING \
            -p tcp --dport "$SSH_REAL_PORT" -j "$REDIRECT_CHAIN"
        logger -t "$LOG_TAG" "Chaîne $REDIRECT_CHAIN initialisée"
    fi
}

cleanup_chain() {
    iptables -t nat -D PREROUTING \
        -p tcp --dport "$SSH_REAL_PORT" -j "$REDIRECT_CHAIN" 2>/dev/null || true
    iptables -t nat -F "$REDIRECT_CHAIN" 2>/dev/null || true
    iptables -t nat -X "$REDIRECT_CHAIN" 2>/dev/null || true
    logger -t "$LOG_TAG" "Chaîne nettoyée"
}

# ─────────────────────────────────────────────
# Redirections individuelles
# ─────────────────────────────────────────────
is_whitelisted() {
    grep -qxF "$1" "$WHITELIST_FILE" 2>/dev/null
}

add_redirect() {
    local ip="$1"
    [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && return
    # FIX M-6 — Jamais rediriger les IPs privées (Docker gateway, localhost)
    if [[ "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.) ]]; then
        logger -t "$LOG_TAG" "Skip $ip (RFC-1918 — non redirigé)"
        return
    fi
    is_whitelisted "$ip" && { logger -t "$LOG_TAG" "Skip $ip (whitelist)"; return; }
    if ! iptables -t nat -C "$REDIRECT_CHAIN" \
         -s "$ip" -j REDIRECT --to-port "$HONEYPOT_PORT" 2>/dev/null; then
        iptables -t nat -A "$REDIRECT_CHAIN" \
            -s "$ip" -j REDIRECT --to-port "$HONEYPOT_PORT"
        logger -t "$LOG_TAG" "PIEGE: $ip -> Endlessh :$HONEYPOT_PORT"
    fi
}

remove_redirect() {
    local ip="$1"
    if iptables -t nat -C "$REDIRECT_CHAIN" \
       -s "$ip" -j REDIRECT --to-port "$HONEYPOT_PORT" 2>/dev/null; then
        iptables -t nat -D "$REDIRECT_CHAIN" \
            -s "$ip" -j REDIRECT --to-port "$HONEYPOT_PORT"
        logger -t "$LOG_TAG" "LIBERE: $ip (décision expirée)"
    fi
}

get_current_redirects() {
    iptables -t nat -L "$REDIRECT_CHAIN" -n 2>/dev/null \
        | grep "REDIRECT" \
        | awk '{print $4}' \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true
}

# ─────────────────────────────────────────────
# Poll LAPI CrowdSec — décisions SSH uniquement
# ─────────────────────────────────────────────
poll_ssh_decisions() {
    local raw
    raw=$(curl -sf --max-time 10 \
        -H "X-Api-Key: ${BOUNCER_KEY}" \
        "${LAPI_URL}/v1/decisions?type=ban&scope=Ip" 2>/dev/null) || { echo ""; return; }

    echo "$raw" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    if not data:
        sys.exit(0)
    for d in data:
        if 'ssh' in d.get('scenario', '').lower():
            print(d['value'])
except Exception:
    sys.exit(0)
" 2>/dev/null || true
}

# ─────────────────────────────────────────────
# Signal handlers
# ─────────────────────────────────────────────
handle_exit() {
    logger -t "$LOG_TAG" "Arrêt — nettoyage iptables"
    cleanup_chain
    exit 0
}
trap handle_exit SIGTERM SIGINT

# ─────────────────────────────────────────────
# Boucle principale
# ─────────────────────────────────────────────
logger -t "$LOG_TAG" "Démarrage Bot Funnel (LAPI: ${LAPI_URL}, poll: ${POLL_INTERVAL}s)"
init_chain

LAST_DAILY=0

while true; do
    mapfile -t active_ips < <(poll_ssh_decisions)

    # Ajouter nouvelles redirections
    for ip in "${active_ips[@]:-}"; do
        [[ -n "$ip" ]] && add_redirect "$ip"
    done

    # Supprimer redirections expirées
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        found=0
        for a in "${active_ips[@]:-}"; do [[ "$a" == "$ip" ]] && { found=1; break; }; done
        [[ $found -eq 0 ]] && remove_redirect "$ip"
    done < <(get_current_redirects)

    # Rapport journalier (toutes les 24h)
    now=$(date +%s)
    if (( now - LAST_DAILY >= 86400 )); then
        count=$(get_current_redirects | wc -l)
        logger -t "$LOG_TAG" "DAILY: $count bot(s) actuellement piégé(s) dans Endlessh"
        LAST_DAILY=$now
    fi

    sleep "$POLL_INTERVAL"
done
BOTFUNNELEOF
chmod 750 "$BOT_FUNNEL_SCRIPT"
log_success "Script Bot Funnel déployé : $BOT_FUNNEL_SCRIPT"

# FIX #67 — Créer le fichier whitelist et whitelister l'IP admin automatiquement
WHITELIST_FILE_MAIN="/etc/crowdsec/parsers/s00-raw/known-ips.conf"
mkdir -p "$(dirname "$WHITELIST_FILE_MAIN")"
touch "$WHITELIST_FILE_MAIN"
chmod 640 "$WHITELIST_FILE_MAIN"

ADMIN_INSTALL_IP=$(echo "${SSH_CLIENT:-}" | awk '{print $1}')
if [[ -n "$ADMIN_INSTALL_IP" && "$ADMIN_INSTALL_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "$ADMIN_INSTALL_IP" >> "$WHITELIST_FILE_MAIN"
    log_success "Bot Funnel : IP admin ($ADMIN_INSTALL_IP) whitelistée — lockout impossible."
else
    log_warn "Bot Funnel : IP admin non détectée (SSH_CLIENT vide)."
    log_warn "  → Ajoute-la manuellement : echo 'TON_IP' >> $WHITELIST_FILE_MAIN"
fi

# Enregistrer un bouncer dédié pour le Bot Funnel
BOT_FUNNEL_KEY=""
BOT_FUNNEL_BOUNCER="vps-secure-bot-funnel"

if cscli bouncers list 2>/dev/null | grep -q "$BOT_FUNNEL_BOUNCER"; then
    cscli bouncers delete "$BOT_FUNNEL_BOUNCER" 2>/dev/null || true  # optionnel : idempotence
fi

BOT_FUNNEL_KEY=$(cscli bouncers add "$BOT_FUNNEL_BOUNCER" \
    --key "$(openssl rand -hex 16)" -o raw 2>/dev/null || echo "")

if [[ -z "$BOT_FUNNEL_KEY" ]]; then
    log_warn "Bot Funnel : impossible de créer la clé bouncer — feature désactivée."
    log_warn "  Réactivation : sudo cscli bouncers add vps-secure-bot-funnel"
else
    echo "$BOT_FUNNEL_KEY" > "$BOT_FUNNEL_KEY_FILE"
    chmod 600 "$BOT_FUNNEL_KEY_FILE"
    chattr +i "$BOT_FUNNEL_KEY_FILE"
    log_success "Clé API Bot Funnel générée et stockée."

    # Installer le service systemd
    cat > "$BOT_FUNNEL_SERVICE" << 'SERVICEEOF'
[Unit]
Description=VPS-SECURE Bot Funnel — SSH honeypot redirect via CrowdSec
After=network-online.target crowdsec.service
Wants=network-online.target
Requires=crowdsec.service

[Service]
Type=simple
ExecStart=/usr/local/bin/vps-secure-bot-funnel.sh
Restart=always
RestartSec=10
User=root
StandardOutput=journal
StandardError=journal
SyslogIdentifier=vps-secure-bot-funnel
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
SERVICEEOF

    systemctl daemon-reload
    systemctl enable --now vps-secure-bot-funnel

    if systemctl is-active --quiet vps-secure-bot-funnel; then
        log_success "Bot Funnel actif — bots SSH persistants redirigés vers Endlessh."
    else
        log_warn "Bot Funnel non démarré — vérifier : sudo journalctl -u vps-secure-bot-funnel"
    fi

    # Sauvegarder les règles iptables NAT pour le reboot
    netfilter-persistent save 2>/dev/null || \
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true  # optionnel : netfilter-persistent peut être absent sur kernels minimalistes
    log_success "Règles iptables NAT sauvegardées (persistance reboot)."
fi

# ============================================================
# Étape 15 : Integrity monitoring (AIDE)
# ============================================================
etape "15" "$TOTAL_ETAPES" "Integrity monitoring (AIDE)"

log_info "AIDE hash tous les binaires système à l'installation."
log_info "Un scan quotidien détecte toute modification — binaire remplacé, rootkit, backdoor."

_wait_dpkg
apt-get install -y -qq aide aide-common

# Exclure les fichiers dynamiques — évite les faux positifs permanents
cat >> /etc/aide/aide.conf << 'AIDEEXCLEOF'

# ── vps-secure — exclusions fichiers dynamiques ──────────────────
!/home/[^/]+/\.bash_history$
!/var/lib/crowdsec/data
!/var/cache/apt/pkgcache\.bin$
!/var/lib/snapd/state\.json$
!/var/lib/update-notifier
!/var/lib/dpkg/triggers
!/var/log/sysstat
!/var/log/aide(/.*)?$
!/run(/.*)?$
!/var/log/crowdsec(/.*)?$
!/var/log/audit(/.*)?$
!/var/lib/docker(/.*)?$
!/var/lib/containerd(/.*)?$
!/run/docker(/.*)?$
!/var/run/docker(/.*)?$
!/home/[^/]+/\.docker(/.*)?$
!/root/\.docker(/.*)?$
!/var/lib/command-not-found(/.*)?$
# E2 : Exclusions manquantes — ces fichiers sont modifiés à chaque unattended-upgrades
!/var/lib/dpkg/status$
!/etc/ld\.so\.cache$
!/run/utmp$
!/var/lib/crowdsec/hub(/.*)?$
!/var/lib/apt/lists(/.*)?$
!/var/cache/apt(/.*)?$
!/etc/alternatives(/.*)?$
!/home/[^/]+/\.gnupg(/.*)?$
!/home/[^/]+/\.npm(/.*)?$
!/root/\.gnupg(/.*)?$
!/root/\.npm(/.*)?$
!/var/log/vps-monitor-history\.json$
!/etc/vps-secure/known-ips\.conf$
!/etc/update-motd\.d/
!/etc/cron\.d/vps-secure
!/etc/cron\.d/aide-daily
!/etc/systemd/system/motd-news\.timer$
!/etc/systemd/system/update-notifier-motd\.timer$
!/^/$
# ── Ubuntu 24.04 — fichiers système dynamiques ───────────────────
!/var/lib/dpkg/info/
!/var/lib/dpkg/status-old$
!/var/lib/dpkg/lock.*
!/var/lib/apt/lists/
!/var/cache/apt/
!/var/log/journal/
!/var/log/btmp$
!/var/log/wtmp$
!/var/log/lastlog$
!/var/lib/systemd/
!/var/cache/ldconfig/
!/var/cache/debconf/
!/var/lib/snapd/
!/snap/
!/var/lib/docker/volumes/
!/var/lib/docker/overlay2/
AIDEEXCLEOF

# AIDE --init : déplacé en fin de script (issue #43)
# La baseline est construite APRÈS logrotate, dashboard et tous les fichiers VPS-SECURE


# Mise à jour baseline rkhunter — _aide user/group créés par AIDE absent de la baseline initiale (étape 11)
rkhunter --propupd --nocolors > /dev/null 2>&1 || true  # optionnel : non bloquant

# Smart-check AIDE v2.4.0 — script dédié (bitmask + contexte dpkg + protection chattr)
cat > /usr/local/bin/vps-secure-aide-check.sh << 'AIDESMART'
#!/usr/bin/env bash
set -euo pipefail
readonly AIDE_CONF="/etc/aide/aide.conf"
readonly AIDE_DB="/var/lib/aide/aide.db"
readonly AIDE_DB_NEW="/var/lib/aide/aide.db.new"
readonly AIDE_LOG="/var/log/aide-daily.log"
readonly AIDE_EXIT_FILE="/var/log/aide-daily.exit"
readonly AIDE_CONTEXT_FILE="/var/log/aide-daily.exit.context"
readonly DPKG_LOG="/var/log/dpkg.log"
readonly DPKG_WINDOW_HOURS=26

AIDE_EXIT=0
# E1 : Lever la protection chattr avant écriture
chattr -i "$AIDE_EXIT_FILE" "$AIDE_LOG" 2>/dev/null || true  # optionnel : les deux fichiers peuvent avoir chattr +i post-rebase
aide --check --config "$AIDE_CONF" > "$AIDE_LOG" 2>&1 || AIDE_EXIT=$?
echo "$AIDE_EXIT" > "$AIDE_EXIT_FILE"
# E1 : Protéger le fichier contre falsification post-compromise
chattr +i "$AIDE_EXIT_FILE" "$AIDE_LOG" 2>/dev/null || true  # optionnel : symétrie chattr -i ligne précédente
chattr -i "$AIDE_CONTEXT_FILE" 2>/dev/null || true

[[ "$AIDE_EXIT" -eq 0 ]] && { rm -f "$AIDE_CONTEXT_FILE"; exit 0; }
[[ $(( AIDE_EXIT & 56 )) -ne 0 ]] && exit 0

CUTOFF=$(date -d "${DPKG_WINDOW_HOURS} hours ago" '+%Y-%m-%d %H:%M:%S')
DPKG_ACTIVITY=$(awk -v c="$CUTOFF" '$0 > c && / status installed / {count++} END {print count+0}' "$DPKG_LOG" 2>/dev/null || echo 0)
[[ "$DPKG_ACTIVITY" -eq 0 ]] && { rm -f "$AIDE_CONTEXT_FILE"; exit 0; }

# C1 v2.4.0 : NE PAS auto-mettre à jour la baseline silencieusement
# Écrire le contexte dpkg — vps-secure-check.sh affichera une alerte informative
# Validation manuelle : sudo aide --update && sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
echo "dpkg_active:${DPKG_ACTIVITY}" > "$AIDE_CONTEXT_FILE"
chattr +i "$AIDE_CONTEXT_FILE" 2>/dev/null || true
exit 0
AIDESMART
chmod 700 /usr/local/bin/vps-secure-aide-check.sh
log_success "Script vps-secure-aide-check.sh installé."
chattr +i /usr/local/bin/vps-secure-aide-check.sh
log_success "vps-secure-aide-check.sh protégé en écriture (chattr +i — issue #6)."

# Cron quotidien AIDE à 01h00 UTC (4h avant le rapport Telegram de 07h00 UTC)
# Le résultat est lu par vps-secure-check.sh pour le rapport Telegram
cat > /etc/cron.d/aide-daily << 'AIDECRONEOF'
# vps-secure — AIDE integrity check quotidien à 01h00 UTC (03h00 Paris)
# Résultat lu par vps-secure-check.sh pour le rapport Telegram 07h00 UTC (09h00 Paris CEST)
# Exit code AIDE (bitmask) : 0=OK · 1=ajouts · 2=suppressions · 4=modifications · 7=les trois · 8+=erreur technique
0 1 * * * root /usr/local/bin/vps-secure-aide-check.sh
AIDECRONEOF
chmod 644 /etc/cron.d/aide-daily
chattr +i /etc/cron.d/aide-daily
log_success "/etc/cron.d/aide-daily protégé en écriture (chattr +i — issue #6)."
rm -f /etc/cron.d/vps-secure-aide

# Rotation des logs AIDE (évite accumulation sur 1 an)
cat > /etc/logrotate.d/aide-daily << 'LOGROTEOF'
/var/log/aide-daily.log {
    weekly
    rotate 8
    compress
    dateext
    missingok
    notifempty
}
LOGROTEOF

cat > /etc/logrotate.d/vps-secure-rkhunter << 'RKLOGROTEOF'
/var/log/rkhunter-cron.log
/var/log/rkhunter-propupd.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    create 640 root root
}
RKLOGROTEOF

log_success "AIDE configuré — scan quotidien à 01h00 UTC (03h00 Paris)."
log_info "  Base de référence : /var/lib/aide/aide.db"
log_info "  Log quotidien     : /var/log/aide-daily.log"
log_info "  Scanner manuellement : sudo aide --check"
log_info "  Après mise à jour OS : sudo vps-secure-aide-rebase"

# Script vps-secure-aide-rebase — rebase baseline AIDE post-apt (fix #44)
cat > /usr/local/bin/vps-secure-aide-rebase << 'REBASEEOF'
#!/bin/bash
# vps-secure-aide-rebase — Rebase la baseline AIDE après un apt upgrade
# Usage : sudo vps-secure-aide-rebase
[[ "$EUID" -ne 0 ]] && { echo "❌ Utiliser : sudo vps-secure-aide-rebase"; exit 1; }
echo "🔄 Rebase baseline AIDE en cours (~2-3 min)..."
chattr -i /var/lib/aide/aide.db 2>/dev/null || true
aide --update --config /etc/aide/aide.conf > /dev/null 2>&1 || true
if [[ -f /var/lib/aide/aide.db.new ]]; then
    cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    # FIX #65 — Remettre à zéro les exit files (évite alertes résiduelles 22h)
    chattr -i /var/log/aide-daily.exit 2>/dev/null || true
    echo "0" > /var/log/aide-daily.exit
    chattr +i /var/log/aide-daily.exit 2>/dev/null || true
    rm -f /var/log/aide-daily.exit.context
    chmod 600 /var/lib/aide/aide.db
    chattr +i /var/lib/aide/aide.db
    rm -f /var/lib/aide/aide.db.new

    # ── Mise à jour statut dashboard ──────────────────────────────────────
    chattr -i /var/log/aide-daily.log /var/log/aide-daily.exit 2>/dev/null || true
    echo "Rebase effectué le \$(date '+%Y-%m-%d %H:%M:%S') — baseline réinitialisée" \
        > /var/log/aide-daily.log
    echo "0" > /var/log/aide-daily.exit
    chattr +i /var/log/aide-daily.log /var/log/aide-daily.exit 2>/dev/null || true
    # ─────────────────────────────────────────────────────────────────────

    echo "✅ Baseline AIDE mise à jour. Dashboard actualisé immédiatement."
else
    echo "❌ Échec — vérifier : sudo aide --config-check"; exit 1
fi
REBASEEOF
chmod 750 /usr/local/bin/vps-secure-aide-rebase
chown root:sudo /usr/local/bin/vps-secure-aide-rebase
log_success "Commande vps-secure-aide-rebase disponible (sudo vps-secure-aide-rebase)."
chattr +i /usr/local/bin/vps-secure-aide-rebase
log_success "vps-secure-aide-rebase protégé en écriture (chattr +i — issue #6)."

# ============================================================
# Installation de vps-secure-stats
# ============================================================
cat > /usr/local/bin/vps-secure-stats << 'STATSEOF'
#!/usr/bin/env bash
# ============================================================
# vps-secure-stats — Tableau de bord de sécurité instantané
# Usage : sudo vps-secure-stats
# ============================================================

VERT='\033[0;32m'
ROUGE='\033[0;31m'
JAUNE='\033[1;33m'
BLANC='\033[0;37m'
CYAN='\033[0;36m'
GRAS='\033[1m'
RESET='\033[0m'

# ── Endlessh ──
# Lecture du cache security-stats.json (évite docker logs synchrone)
CACHE_FILE="/var/cache/vps-secure/security-stats.json"
if [[ -f "$CACHE_FILE" ]]; then
    CACHE_JSON=$(cat "$CACHE_FILE" 2>/dev/null || echo "{}")
    CACHE_RUNNING=$(echo "$CACHE_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(str(d.get('running',False)).lower())" 2>/dev/null || echo "false")
    BOTS_24H=$(echo "$CACHE_JSON"     | python3 -c "import sys,json; print(json.load(sys.stdin).get('last24h',0))" 2>/dev/null || echo "0")
    BOTS_TOTAL=$(echo "$CACHE_JSON"   | python3 -c "import sys,json; print(json.load(sys.stdin).get('total',0))" 2>/dev/null || echo "0")
    if [[ "$CACHE_RUNNING" == "true" ]]; then
        ENDLESSH_STATUS="${VERT}actif${RESET}"
    else
        ENDLESSH_STATUS="${ROUGE}inactif${RESET}"
        BOTS_24H="0"; BOTS_TOTAL="0"
    fi
elif docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^endlessh$'; then
    BOTS_24H=$(docker logs endlessh --since 1440m 2>&1 | { grep -ci "accept" || true; })
    BOTS_TOTAL=$(docker logs endlessh 2>&1 | { grep -ci "accept" || true; })
    ENDLESSH_STATUS="${VERT}actif${RESET}"
else
    BOTS_24H="0"; BOTS_TOTAL="0"
    ENDLESSH_STATUS="${ROUGE}inactif${RESET}"
fi

# ── CrowdSec ──
if command -v cscli &>/dev/null; then
    if [[ -f "$CACHE_FILE" ]]; then
        CS_BANNED=$(cat "$CACHE_FILE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('cs_banned',0))" 2>/dev/null || echo "0")
    else
        CS_BANNED=$(cscli decisions list -o json 2>/dev/null \
            | python3 -c "import sys,json
try:
    d=json.load(sys.stdin)
    print(len(d) if d else 0)
except:
    print(0)" 2>/dev/null || echo "0")
    fi
    CS_ALERTS_24H=$(cscli alerts list --since 24h -o json 2>/dev/null \
        | python3 -c "import sys,json
try:
    d=json.load(sys.stdin)
    print(len(d) if d else 0)
except:
    print(0)" 2>/dev/null || echo "0")
    CS_STATUS="${VERT}actif${RESET}"
else
    CS_BANNED="0"
    CS_ALERTS_24H="0"
    CS_STATUS="${ROUGE}inactif${RESET}"
fi

# ── UFW ──
UFW_BLOCKS=$(grep -c "\[UFW BLOCK\]" /var/log/ufw.log 2>/dev/null) || UFW_BLOCKS=0

# ── auditd ──
AUDIT_PRIVESC=$(ausearch -k privilege_escalation --start today -i 2>/dev/null \
    | grep -c "^----" ) || AUDIT_PRIVESC=0
AUDIT_PRIVESC=$(echo "$AUDIT_PRIVESC" | tr -d '[:space:]')
AUDIT_PRIVESC="${AUDIT_PRIVESC:-0}"

# ── rkhunter ──
if [[ -f /var/log/rkhunter-cron.log ]]; then
    RK_LAST=$(stat -c "%y" /var/log/rkhunter-cron.log 2>/dev/null \
        | cut -d'.' -f1 || echo "jamais")
    RK_WARN=$(grep -c "Warning" /var/log/rkhunter-cron.log 2>/dev/null) || RK_WARN=0
    if [[ "$RK_WARN" -eq 0 ]]; then
        RK_STATUS="${VERT}OK${RESET}"
    else
        RK_STATUS="${ROUGE}${RK_WARN} warning(s)${RESET}"
    fi
else
    RK_LAST="jamais"
    RK_STATUS="${JAUNE}pas encore exécuté${RESET}"
fi

# ── AIDE ──
if [[ -f /var/log/aide-daily.exit ]]; then
    AIDE_EXIT=$(cat /var/log/aide-daily.exit 2>/dev/null | tr -d '[:space:]')
    if ! [[ "$AIDE_EXIT" =~ ^[0-9]+$ ]]; then
        AIDE_STATUS="${JAUNE}Fichier exit invalide — sudo aide --check${RESET}"
    elif [[ "$AIDE_EXIT" -eq 0 ]]; then
        AIDE_STATUS="${VERT}Aucune modification${RESET}"
    elif [[ $(( AIDE_EXIT & 56 )) -ne 0 ]]; then
        # C2 : erreurs techniques testées AVANT les modifications (évite faux positifs bitmask)
        AIDE_STATUS="${JAUNE}Erreur technique AIDE (exit ${AIDE_EXIT}) — sudo aide --check 2>&1 | tail -5${RESET}"
    elif [[ $(( AIDE_EXIT & 7 )) -ne 0 ]]; then
        AIDE_STATUS="${JAUNE}Baseline à mettre à jour — sudo vps-secure-aide-rebase${RESET}"
    else
        AIDE_STATUS="${JAUNE}État inconnu (exit ${AIDE_EXIT}) — sudo aide --check${RESET}"
    fi
else
    AIDE_STATUS="${JAUNE}Pas encore exécuté (scan à 01h00 UTC)${RESET}"
fi

# ── Système ──
UPTIME=$(uptime -p 2>/dev/null | sed 's/up //' || echo "inconnu")
LOAD=$(uptime | awk -F'load average:' '{print $2}' | xargs || echo "inconnu")
MEM_USED=$(free -h | awk '/^Mem:/ {print $3}')
MEM_TOTAL=$(free -h | awk '/^Mem:/ {print $2}')

# ── Affichage ──
echo ""
echo -e "${GRAS}${VERT}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${GRAS}${VERT}║          vps-secure — Tableau de bord                ║${RESET}"
echo -e "${GRAS}${VERT}╚══════════════════════════════════════════════════════╝${RESET}"
echo -e "  ${BLANC}$(hostname) · $(date '+%d/%m/%Y %H:%M')${RESET}"
echo ""
echo -e "  ${GRAS}${CYAN}🍯 HONEYPOT (Endlessh)${RESET}          ${ENDLESSH_STATUS}"
echo -e "  ${BLANC}   Bots piégés (24h)     :${RESET} ${GRAS}${JAUNE}${BOTS_24H}${RESET}"
echo -e "  ${BLANC}   Bots piégés (total)   :${RESET} ${GRAS}${BOTS_TOTAL}${RESET}"
echo ""
echo -e "  ${GRAS}${CYAN}🛡️  CROWDSEC${RESET}                     ${CS_STATUS}"
echo -e "  ${BLANC}   IP bannies actives    :${RESET} ${GRAS}${JAUNE}${CS_BANNED}${RESET}"
echo -e "  ${BLANC}   Alertes (24h)         :${RESET} ${GRAS}${CS_ALERTS_24H}${RESET}"
echo ""
echo -e "  ${GRAS}${CYAN}🔥 PARE-FEU (UFW)${RESET}"
echo -e "  ${BLANC}   Blocages totaux       :${RESET} ${GRAS}${UFW_BLOCKS}${RESET}"
echo ""
echo -e "  ${GRAS}${CYAN}📋 AUDIT (auditd)${RESET}"
echo -e "  ${BLANC}   Escalades privilèges  :${RESET} ${GRAS}${AUDIT_PRIVESC}${RESET} aujourd'hui"
[[ "$AUDIT_PRIVESC" -gt 100 ]] && \
    echo -e "  ${BLANC}   ⓘ  Nombre élevé normal le jour d'installation — le script tourne en root${RESET}"
echo ""
echo -e "  ${GRAS}${CYAN}🔍 ROOTKITS (rkhunter)${RESET}          ${RK_STATUS}"
echo -e "  ${BLANC}   Dernier scan          :${RESET} ${RK_LAST}"
echo ""
echo -e "  ${GRAS}${CYAN}🔐 INTÉGRITÉ (AIDE)${RESET}"
echo -e "  ${BLANC}   Dernier scan          :${RESET} ${AIDE_STATUS}"
echo ""
echo -e "  ${GRAS}${CYAN}💻 SYSTÈME${RESET}"
echo -e "  ${BLANC}   Uptime                :${RESET} ${UPTIME}"
echo -e "  ${BLANC}   Charge                :${RESET} ${LOAD}"
echo -e "  ${BLANC}   Mémoire               :${RESET} ${MEM_USED} / ${MEM_TOTAL}"
echo ""
echo -e "${VERT}$(printf '─%.0s' {1..56})${RESET}"
echo -e "  ${BLANC}Rapport complet : sudo vps-secure-stats${RESET}"
echo ""
STATSEOF

chmod +x /usr/local/bin/vps-secure-stats
log_success "Tableau de bord installé — commande disponible : sudo vps-secure-stats"

# Installer vps-secure-verify pour usage post-reboot (évite le curl manuel)
curl -fsSL https://raw.githubusercontent.com/rockballslab/vps-secure/main/vps-secure-verify.sh \
    -o /usr/local/bin/vps-secure-verify 2>/dev/null || true  # optionnel : réseau peut échouer — non bloquant
chmod +x /usr/local/bin/vps-secure-verify 2>/dev/null || true
log_success "vps-secure-verify installé — commande disponible : sudo vps-secure-verify"

# ── MOTD personnalisé (affiché à chaque connexion SSH) ──
# Désactiver le MOTD Ubuntu par défaut (publicitaire et verbeux)
chmod -x /etc/update-motd.d/* 2>/dev/null || true
# Désactiver les timers systemd qui régénèrent le MOTD Ubuntu après chmod -x
systemctl disable --now motd-news.timer 2>/dev/null || true
systemctl disable --now update-notifier-motd.timer 2>/dev/null || true
truncate -s 0 /run/motd.dynamic 2>/dev/null || true   # ← vide le cache MOTD Ubuntu
truncate -s 0 /etc/motd 2>/dev/null || true            # ← vide le MOTD statique
cat > /etc/update-motd.d/00-vps-secure << 'MOTDEOF'
#!/usr/bin/env bash

CPU_CORES=$(nproc 2>/dev/null || echo "?")
LOAD=$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ', ')
MEM_USED=$(free -m 2>/dev/null | awk '/^Mem:/ {print $3}')
MEM_TOTAL=$(free -m 2>/dev/null | awk '/^Mem:/ {print $2}')
MEM_PCT=$(( MEM_TOTAL > 0 ? MEM_USED * 100 / MEM_TOTAL : 0 ))
DISK_USED=$(df -h / 2>/dev/null | awk 'NR==2 {print $3}')
DISK_TOTAL=$(df -h / 2>/dev/null | awk 'NR==2 {print $2}')
DISK_PCT=$(df / 2>/dev/null | awk 'NR==2 {print $5}')
UPTIME=$(uptime -p 2>/dev/null | sed 's/up //')
CS_BANNED=$(cscli decisions list -o json 2>/dev/null \
    | python3 -c "import sys,json
try: print(len(json.load(sys.stdin) or []))
except: print(0)" 2>/dev/null || echo "0")
BOTS=$(docker logs endlessh --since 1440m 2>&1 | { grep -ci "accept" || true; })
UFW_BLOCKS=$(grep -c "\[UFW BLOCK\]" /var/log/ufw.log 2>/dev/null || echo "0")

G='\033[0;32m'
Y='\033[1;33m'
W='\033[0;37m'
R='\033[0m'

echo -e "${G}"
VPS_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}')
echo -e "  🔐 $(hostname) · ${VPS_IP} · vps-secure"
echo -e "  ──────────────────────────────────"
echo -e "  ${W}CPU     ${G}${CPU_CORES} cores · load ${LOAD}"
echo -e "  ${W}RAM     ${G}${MEM_USED} MB / ${MEM_TOTAL} MB (${MEM_PCT}%)"
echo -e "  ${W}Disk    ${G}${DISK_USED} / ${DISK_TOTAL} (${DISK_PCT})"
echo -e "  ${W}Uptime  ${G}${UPTIME}"
echo -e "  ${G}──────────────────────────────────"
echo -e "  ${Y}🛡  CrowdSec  ${W}actif · ${CS_BANNED} IP bannies"
echo -e "  ${Y}🍯 Endlessh  ${W}${BOTS} bots pieges/24h"
echo -e "  ${Y}🔥 UFW       ${W}${UFW_BLOCKS} blocages"
echo -e "${R}"
MOTDEOF
chmod +x /etc/update-motd.d/00-vps-secure
log_success "MOTD personnalisé installé — affiché à chaque connexion SSH."

# ════════════════════════════════════════════════════════════════════
# ÉTAPE FINALE — Baseline AIDE (système entièrement configuré)
# Doit être LA DERNIÈRE opération : logrotate, dashboard et tous les
# fichiers VPS-SECURE sont écrits AVANT cette baseline.
# ════════════════════════════════════════════════════════════════════
log_info "Construction baseline AIDE — peut prendre 2 à 5 minutes..."
log_info "  (tous les fichiers VPS-SECURE sont maintenant inclus dans la référence)"

# Supprimer l'ancienne baseline si re-installation
if [[ -f /var/lib/aide/aide.db ]]; then
    chattr -i /var/lib/aide/aide.db 2>/dev/null || true  # optionnel : db peut ne pas avoir chattr +i si installation partielle
    rm -f /var/lib/aide/aide.db
fi

# FINT-4402 — SHA512 ajouté aux checksums AIDE (Lynis 3.1.6)
grep -q "sha512" /etc/aide/aide.conf \
  || printf "\n# FINT-4402\nCONTENT_LYNIS = sha256+sha512+p+i+n+u+g+s+m+ftype\n" \
     >> /etc/aide/aide.conf
log_success "AIDE checksums : sha256+sha512 (FINT-4402)."

DEBIAN_FRONTEND=noninteractive aideinit -y -f 2>/dev/null || \
    aide --init --config /etc/aide/aide.conf 2>/dev/null || true  # optionnel : fallback si aideinit absent

if [[ -f /var/lib/aide/aide.db.new ]]; then
    cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    chmod 600 /var/lib/aide/aide.db
    chattr +i /var/lib/aide/aide.db
    rm -f /var/lib/aide/aide.db.new
    log_success "Baseline AIDE construite — système complet inclus (logrotate, dashboard, scripts)."
    log_info "  Fichier protégé en écriture (chattr +i) — 0 alerte AIDE demain matin."
else
    log_warn "Baseline AIDE non créée — lancer manuellement :"
    log_warn "  sudo aideinit -y -f && sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
    log_warn "  sudo chattr +i /var/lib/aide/aide.db && sudo rm -f /var/lib/aide/aide.db.new"
fi

# Résumé final
# ============================================================
echo ""
echo -e "${GRAS}${VERT}╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${GRAS}${VERT}║             vps-secure — Installation terminée ✓                 ║${RESET}"
echo -e "${GRAS}${VERT}╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${VERT}✅${RESET} Utilisateur         : ${BLANC}$USERNAME · sudo NOPASSWD + use_pty${RESET}"
echo -e "  ${VERT}✅${RESET} SSH                 : ${BLANC}Port 2222 · clés uniquement · root désactivé · HostKey Ed25519${RESET}"
echo -e "  ${VERT}✅${RESET} CrowdSec            : ${BLANC}IDS/IPS communautaire SSH + HTTP${RESET}"
echo -e "  ${VERT}✅${RESET} UFW                 : ${BLANC}Ports 2222 / 80 / 443 · NAT Docker · forwarding bridge${RESET}"
echo -e "  ${VERT}✅${RESET} Docker              : ${BLANC}$(docker --version | grep -oP '\d+\.\d+\.\d+' | head -1) + Compose v2${RESET}"
echo -e "  ${JAUNE}⚠️ ${RESET} Docker group        : ${BLANC}vpsadmin dans le groupe docker — traite ta clé SSH comme une clé root${RESET}"
echo -e "  ${VERT}✅${RESET} Auto-updates        : ${BLANC}Patches de sécurité automatiques${RESET}"
echo -e "  ${VERT}✅${RESET} Kernel hardening    : ${BLANC}Anti-spoofing · SYN flood · ICMP · ASLR · ptrace · perf restreint${RESET}"
echo -e "  ${VERT}✅${RESET} DNS chiffré         : ${BLANC}DNS over TLS — Quad9 + Cloudflare (activé avant les téléchargements)${RESET}"
echo -e "  ${VERT}✅${RESET} Audit système       : ${BLANC}auditd — identité · SSH · Docker · crontabs · /etc/hosts${RESET}"
echo -e "  ${VERT}✅${RESET} Swap                : ${BLANC}2 GB actif (swappiness=10)${RESET}"
echo -e "  ${VERT}✅${RESET} rkhunter            : ${BLANC}Scanner de rootkits — baseline + scan quotidien 00h00 UTC (minuit)${RESET}"
echo -e "  ${VERT}✅${RESET} Services inutiles   : ${BLANC}avahi · cups · bluetooth · ModemManager désactivés${RESET}"
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^endlessh$'; then
    echo -e "  ${VERT}✅${RESET} Endlessh            : ${BLANC}Honeypot actif — bots piégés sur le port 22${RESET}"
else
    echo -e "  ${BLANC}ℹ️ ${RESET} Endlessh            : ${BLANC}Container non actif — sudo docker start endlessh${RESET}"
fi
if [[ -f /var/lib/aide/aide.db ]]; then
    echo -e "  ${VERT}✅${RESET} AIDE                : ${BLANC}Integrity monitoring — baseline enregistrée · scan 03h00${RESET}"
else
    echo -e "  ${BLANC}ℹ️ ${RESET} AIDE                : ${BLANC}Baseline non créée — voir instructions ci-dessus${RESET}"
fi
if command -v aa-status &>/dev/null && aa-status 2>/dev/null | grep -q "apparmor module is loaded"; then
    echo -e "  ${VERT}✅${RESET} AppArmor            : ${BLANC}Actif — profils en mode enforcing${RESET}"
else
    echo -e "  ${JAUNE}⚠️ ${RESET} AppArmor            : ${BLANC}Non vérifié — sudo aa-status${RESET}"
fi
if [[ -f /etc/vps-secure/telegram.conf ]]; then
    echo -e "  ${VERT}✅${RESET} Alertes Telegram    : ${BLANC}Rapport quotidien 07h00 · alerte SSH temps réel${RESET}"
else
    echo -e "  ${JAUNE}⏭️ ${RESET} Alertes Telegram    : ${BLANC}Non configurées${RESET}"
fi
echo -e "  ${VERT}✅${RESET} Stats rapides       : ${BLANC}sudo vps-secure-stats${RESET}"
echo ""
echo -e "${GRAS}  Se connecter ensuite :${RESET}"
echo ""
echo -e "    ${VERT}ssh $USERNAME@$VPS_IP -p 2222 -i ~/.ssh/id_ed25519_vps${RESET}"
echo ""
echo -e "${GRAS}${VERT}  🎉 VPS sécurisé et prêt.${RESET}"
echo ""

# ============================================================
# Reboot
# ============================================================
echo -e "${GRAS}${JAUNE}  Un redémarrage est recommandé pour finaliser :${RESET}"
echo -e "${BLANC}  - Règles auditd pleinement actives (-e 2)${RESET}"
echo -e "${BLANC}  - Kernel hardening garanti dès le boot${RESET}"
echo -e "${BLANC}  - Services désactivés confirmés au démarrage${RESET}"
echo -e "${BLANC}  - AIDE : premier scan automatique à 03h00 (résultat dans Telegram à 07h00)${RESET}"
echo ""
read -rp "  Redémarrer maintenant ? (oui/non) : " reboot_answer
if [[ "$reboot_answer" == "oui" ]]; then
    echo ""
    echo -e "${BLANC}  Reconnecte-toi ensuite avec :${RESET}"
    echo -e "    ${VERT}ssh $USERNAME@$VPS_IP -p 2222 -i ~/.ssh/id_ed25519_vps${RESET}"
    echo ""
    echo -e "${BLANC}  Une fois reconnecté, vérifie l'installation :${RESET}"
    echo -e "    ${VERT}sudo vps-secure-verify${RESET}"
    echo ""
    read -rp "  Prêt ? Appuie sur Entrée pour redémarrer..." _
    reboot
else
    echo ""
    echo -e "${JAUNE}  Pense à redémarrer dès que possible : ${VERT}sudo reboot${RESET}"
    echo ""
    echo -e "${BLANC}  Après le redémarrage, vérifie l'installation :${RESET}"
    echo -e "    ${VERT}sudo vps-secure-verify${RESET}"
    echo ""
fi

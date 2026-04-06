#!/usr/bin/env bash
# ============================================================
# vps-secure-verify.sh — Vérification post-installation
# Vérifie chaque composant installé par install.sh
#
# Usage  : sudo ./vps-secure-verify.sh
# Sortie : [PASS] / [FAIL] / [WARN] par composant
# Exit   : 0 = tout PASS · 1 = au moins un FAIL
#
# Ce script ne modifie rien — lecture seule.
# Repo : https://github.com/rockballslab/vps-secure
# ============================================================
set -uo pipefail
# Pas de set -e : chaque vérification peut échouer sans arrêter le script

VERT='\033[0;32m'
ROUGE='\033[0;31m'
JAUNE='\033[1;33m'
BLANC='\033[0;37m'
GRAS='\033[1m'
RESET='\033[0m'

FAILURES=0
WARNINGS=0

_pass() { echo -e "  ${VERT}[PASS]${RESET} ${GRAS}${1}${RESET} : ${2}"; }
_fail() { echo -e "  ${ROUGE}[FAIL]${RESET} ${GRAS}${1}${RESET} : ${2}"; FAILURES=$(( FAILURES + 1 )); }
_warn() { echo -e "  ${JAUNE}[WARN]${RESET} ${GRAS}${1}${RESET} : ${2}"; WARNINGS=$(( WARNINGS + 1 )); }

if [[ "$(id -u)" -ne 0 ]]; then
    echo "❌ Ce script doit être lancé en ROOT : sudo ./vps-secure-verify.sh"
    exit 1
fi

echo ""
echo -e "${GRAS}${VERT}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${GRAS}${VERT}║     vps-secure — Vérification post-installation     ║${RESET}"
echo -e "${GRAS}${VERT}╚══════════════════════════════════════════════════════╝${RESET}"
echo -e "  ${BLANC}$(hostname) · $(date '+%d/%m/%Y %H:%M')${RESET}"
echo ""

# ── SSH ────────────────────────────────────────────────────────
SSH_FAILS=()
ss -tlnp 2>/dev/null | grep -q ':2222' \
    || SSH_FAILS+=("port 2222 n'écoute pas")
sshd -T 2>/dev/null | grep -qi "^permitrootlogin no" \
    || SSH_FAILS+=("PermitRootLogin non désactivé")
sshd -T 2>/dev/null | grep -qi "^passwordauthentication no" \
    || SSH_FAILS+=("PasswordAuthentication non désactivé")
[[ -f /etc/systemd/system/ssh.socket.d/override.conf ]] \
    && grep -q "2222" /etc/systemd/system/ssh.socket.d/override.conf \
    || SSH_FAILS+=("override.conf socket absent ou sans port 2222")

if [[ ${#SSH_FAILS[@]} -eq 0 ]]; then
    _pass "SSH" "port 2222 actif · root désactivé · PasswordAuth off · socket override OK"
else
    _fail "SSH" "$(IFS=', '; echo "${SSH_FAILS[*]}")"
fi

# ── UFW ────────────────────────────────────────────────────────
UFW_FAILS=()
ufw status 2>/dev/null | grep -qi "^status: active" \
    || UFW_FAILS+=("UFW inactif")
ufw status 2>/dev/null | grep -q "2222/tcp" \
    || UFW_FAILS+=("port 2222 absent")
ufw status 2>/dev/null | grep -q " 80/tcp" \
    || UFW_FAILS+=("port 80 absent")
ufw status 2>/dev/null | grep -q "443/tcp" \
    || UFW_FAILS+=("port 443 absent")
grep -q "DOCKER-MASQ" /etc/ufw/before.rules 2>/dev/null \
    || UFW_FAILS+=("règle NAT Docker absente de before.rules")
ufw status verbose 2>/dev/null | grep -qi "^logging: medium\|^logging: high\|^logging: full" \
    || UFW_FAILS+=("logging inactif — vps-secure-stats ne verra aucun blocage")

if [[ ${#UFW_FAILS[@]} -eq 0 ]]; then
    _pass "UFW" "actif · ports 2222/80/443 ouverts · règle NAT Docker présente · logging medium"
else
    _fail "UFW" "$(IFS=', '; echo "${UFW_FAILS[*]}")"
fi

# ── CrowdSec ───────────────────────────────────────────────────
CS_FAILS=()
systemctl is-active crowdsec &>/dev/null \
    || CS_FAILS+=("service crowdsec inactif")
systemctl is-active crowdsec-firewall-bouncer &>/dev/null \
    || CS_FAILS+=("bouncer inactif — bannissement IP non opérationnel")
command -v cscli &>/dev/null \
    || CS_FAILS+=("cscli introuvable")
# Vérifier cohérence port 8081
if [[ -f /etc/crowdsec/config.yaml ]]; then
    grep -q "127.0.0.1:8080" /etc/crowdsec/config.yaml \
        && CS_FAILS+=("config.yaml contient encore :8080 (migration port 8081 incomplète)")
fi
if [[ -f /etc/crowdsec/local_api_credentials.yaml ]]; then
    grep -q "127.0.0.1:8080" /etc/crowdsec/local_api_credentials.yaml \
        && CS_FAILS+=("local_api_credentials.yaml contient encore :8080")
fi
if [[ -f /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml ]]; then
    grep -q "127.0.0.1:8080" /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml \
        && CS_FAILS+=("bouncer.yaml contient encore :8080 — bannissement inopérant")
fi

if [[ ${#CS_FAILS[@]} -eq 0 ]]; then
    CS_COLS=$(cscli collections list -o raw 2>/dev/null | grep -c "enabled" || echo "?")
    _pass "CrowdSec" "actif · bouncer actif · port 8081 · ${CS_COLS} collection(s)"
else
    _fail "CrowdSec" "$(IFS=', '; echo "${CS_FAILS[*]}")"
fi

# ── Docker ─────────────────────────────────────────────────────
DOCKER_FAILS=()
systemctl is-active docker &>/dev/null \
    || DOCKER_FAILS+=("service docker inactif")
if [[ -f /etc/docker/daemon.json ]]; then
    grep -q '"iptables": false' /etc/docker/daemon.json \
        || DOCKER_FAILS+=("iptables:false absent de daemon.json — Docker bypass UFW")
else
    DOCKER_FAILS+=("daemon.json absent")
fi
# Avertissement non bloquant : vpsadmin absent du groupe docker
id vpsadmin &>/dev/null && ! groups vpsadmin 2>/dev/null | grep -q '\bdocker\b' \
    && _warn "Docker" "vpsadmin absent du groupe docker — les commandes docker nécessitent sudo"

if [[ ${#DOCKER_FAILS[@]} -eq 0 ]]; then
    DOCKER_VER=$(docker --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1 || echo "?")
    _pass "Docker" "actif · v${DOCKER_VER} · iptables:false confirmé"
else
    _fail "Docker" "$(IFS=', '; echo "${DOCKER_FAILS[*]}")"
fi

# ── Endlessh ───────────────────────────────────────────────────
ENDLESSH_FAILS=()
docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^endlessh$' \
    || ENDLESSH_FAILS+=("container endlessh non actif — sudo docker start endlessh")
ss -tlnp 2>/dev/null | grep -qP ':22\s' \
    || ENDLESSH_FAILS+=("port 22 n'écoute pas")
ufw status 2>/dev/null | grep -q "22/tcp" \
    || ENDLESSH_FAILS+=("port 22 absent des règles UFW")

if [[ ${#ENDLESSH_FAILS[@]} -eq 0 ]]; then
    _pass "Endlessh" "container actif · port 22 en écoute · règle UFW présente"
else
    _fail "Endlessh" "$(IFS=', '; echo "${ENDLESSH_FAILS[*]}")"
fi

# ── AIDE ───────────────────────────────────────────────────────
if [[ -f /var/lib/aide/aide.db ]]; then
    AIDE_AGE=$(( ( $(date +%s) - $(stat -c %Y /var/lib/aide/aide.db 2>/dev/null || echo 0) ) / 86400 ))
    AIDE_CRON=""
    [[ -f /etc/cron.d/aide-daily ]] \
        && AIDE_CRON=" · cron 03h00 configuré" \
        || AIDE_CRON=" · ⚠️ cron absent"
    _pass "AIDE" "baseline présente (âge : ${AIDE_AGE}j)${AIDE_CRON}"
else
    _fail "AIDE" "baseline absente (/var/lib/aide/aide.db introuvable) — sudo aideinit"
fi

# ── rkhunter ──────────────────────────────────────────────────
RK_FAILS=()
command -v rkhunter &>/dev/null \
    || RK_FAILS+=("rkhunter non installé")
[[ -f /var/lib/rkhunter/db/rkhunter.dat ]] \
    || RK_FAILS+=("baseline absente — sudo rkhunter --propupd")
[[ -f /etc/cron.d/rkhunter-daily ]] \
    || RK_FAILS+=("cron quotidien absent")
[[ -f /etc/rkhunter.conf.local ]] \
    || RK_FAILS+=("conf.local absent — faux positifs non supprimés (alertes Telegram bruitées)")


if [[ ${#RK_FAILS[@]} -eq 0 ]]; then
    RK_LAST="jamais"
    [[ -f /var/log/rkhunter-cron.log ]] \
        && RK_LAST=$(stat -c "%y" /var/log/rkhunter-cron.log 2>/dev/null | cut -d'.' -f1 || echo "?")
    _pass "rkhunter" "installé · baseline présente · conf.local OK · cron 04h00 · dernier scan : ${RK_LAST}"
else
    _fail "rkhunter" "$(IFS=', '; echo "${RK_FAILS[*]}")"
fi

# ── auditd ─────────────────────────────────────────────────────
AUDIT_FAILS=()
systemctl is-active auditd &>/dev/null \
    || AUDIT_FAILS+=("auditd inactif")
AUDIT_RULES=$(auditctl -l 2>/dev/null | grep -cv "^$" || echo "0")
[[ "$AUDIT_RULES" -gt 0 ]] \
    || AUDIT_FAILS+=("aucune règle auditd chargée — reboot requis si -e 2 actif")

if [[ ${#AUDIT_FAILS[@]} -eq 0 ]]; then
    _pass "auditd" "actif · ${AUDIT_RULES} règle(s) chargée(s)"
else
    _fail "auditd" "$(IFS=', '; echo "${AUDIT_FAILS[*]}")"
fi

# ── Swap ───────────────────────────────────────────────────────
SWAP_MB=$(free -m 2>/dev/null | awk '/^Swap:/ {print $2}' || echo "0")
if [[ -n "$SWAP_MB" ]] && [[ "$SWAP_MB" -gt 0 ]]; then
    SWAPPINESS=$(cat /proc/sys/vm/swappiness 2>/dev/null || echo "?")
    _pass "Swap" "actif · ${SWAP_MB} MB · swappiness=${SWAPPINESS}"
else
    _fail "Swap" "inactif ou absent"
fi

# ── Kernel hardening ──────────────────────────────────────────
KERNEL_FAILS=()
ASLR=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "?")
PTRACE=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "?")
SYNCOOKIES=$(cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null || echo "?")
IPFORWARD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "?")
SUID_DUMP=$(cat /proc/sys/fs/suid_dumpable 2>/dev/null || echo "?")
DMESG=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo "?")
KPTR=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo "?")
BPF_HARDEN=$(cat /proc/sys/net/core/bpf_jit_harden 2>/dev/null || echo "?")
BPF_UNPRIV=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo "?")


[[ "$ASLR" == "2" ]]       || KERNEL_FAILS+=("ASLR=${ASLR} (attendu 2)")
[[ "$PTRACE" == "1" ]]     || KERNEL_FAILS+=("ptrace_scope=${PTRACE} (attendu 1)")
[[ "$SYNCOOKIES" == "1" ]] || KERNEL_FAILS+=("tcp_syncookies=${SYNCOOKIES} (attendu 1)")
[[ "$IPFORWARD" == "1" ]]  || KERNEL_FAILS+=("ip_forward=${IPFORWARD} (attendu 1 pour Docker)")
[[ "$SUID_DUMP" == "0" ]]  || KERNEL_FAILS+=("suid_dumpable=${SUID_DUMP} (attendu 0)")
[[ "$DMESG" == "1" ]]      || KERNEL_FAILS+=("dmesg_restrict=${DMESG} (attendu 1)")
[[ "$KPTR" == "2" ]]       || KERNEL_FAILS+=("kptr_restrict=${KPTR} (attendu 2)")
[[ "$BPF_HARDEN" == "2" ]] || KERNEL_FAILS+=("bpf_jit_harden=${BPF_HARDEN} (attendu 2)")
[[ "$BPF_UNPRIV" == "1" ]] || KERNEL_FAILS+=("unprivileged_bpf_disabled=${BPF_UNPRIV} (attendu 1)")


if [[ ${#KERNEL_FAILS[@]} -eq 0 ]]; then
    _pass "Kernel" "ASLR=2 · ptrace_scope=1 · syncookies=1 · ip_forward=1 · suid_dumpable=0 · dmesg/kptr/eBPF restreints"
else
    _fail "Kernel" "$(IFS=', '; echo "${KERNEL_FAILS[*]}")"
fi

# ── DNS over TLS ──────────────────────────────────────────────
DNS_FAILS=()
systemctl is-active systemd-resolved &>/dev/null \
    || DNS_FAILS+=("systemd-resolved inactif")
resolvectl show 2>/dev/null | grep -qi "^DNSOverTLS=yes" \
    || DNS_FAILS+=("DNS over TLS non confirmé (resolvectl show | grep DNSOverTLS)")
RESOLV_LINK=$(readlink /etc/resolv.conf 2>/dev/null || echo "")
[[ "$RESOLV_LINK" == "/run/systemd/resolve/stub-resolv.conf" ]] \
    || DNS_FAILS+=("/etc/resolv.conf ne pointe pas vers le stub systemd-resolved")

if [[ ${#DNS_FAILS[@]} -eq 0 ]]; then
    DNS_SRV=$(resolvectl status 2>/dev/null | grep "DNS Servers:" | head -1 \
        | sed 's/.*DNS Servers: //' | awk '{print $1}' || echo "?")
    _pass "DNS over TLS" "systemd-resolved actif · DoT=yes · serveur principal : ${DNS_SRV}"
else
    _fail "DNS over TLS" "$(IFS=', '; echo "${DNS_FAILS[*]}")"
fi

# ── Telegram ──────────────────────────────────────────────────
if [[ ! -f /etc/vps-secure/telegram.conf ]]; then
    _warn "Telegram" "non configuré (optionnel) — relance install.sh pour configurer"
else
    TG_TOKEN=$(grep '^TELEGRAM_TOKEN=' /etc/vps-secure/telegram.conf | cut -d'"' -f2 2>/dev/null || echo "")
    TG_CHAT=$(grep '^TELEGRAM_CHAT_ID=' /etc/vps-secure/telegram.conf | cut -d'"' -f2 2>/dev/null || echo "")
    if [[ -z "$TG_TOKEN" ]] || [[ -z "$TG_CHAT" ]]; then
        _fail "Telegram" "config présente mais token ou chat_id vide"
    else
        TG_RESP=$(curl -sf --max-time 5 \
            "https://api.telegram.org/bot${TG_TOKEN}/getMe" 2>/dev/null || echo "")
        if echo "$TG_RESP" | grep -q '"ok":true'; then
            TG_BOT=$(echo "$TG_RESP" | python3 -c \
                "import sys,json; d=json.load(sys.stdin); print(d['result'].get('username','?'))" \
                2>/dev/null || echo "?")
            _pass "Telegram" "config présente · API OK · bot : @${TG_BOT}"
        else
            _fail "Telegram" "token invalide ou API injoignable (curl timeout / réseau)"
        fi
    fi
fi

# ── Résumé ─────────────────────────────────────────────────────
echo ""
echo -e "${GRAS}${VERT}$(printf '═%.0s' {1..56})${RESET}"
if [[ "$FAILURES" -eq 0 ]] && [[ "$WARNINGS" -eq 0 ]]; then
    echo -e "  ${VERT}${GRAS}✅ Installation complète — tous les composants sont opérationnels.${RESET}"
elif [[ "$FAILURES" -eq 0 ]]; then
    echo -e "  ${JAUNE}${GRAS}⚠️  Aucun FAIL — ${WARNINGS} avertissement(s) à examiner.${RESET}"
else
    echo -e "  ${ROUGE}${GRAS}❌ ${FAILURES} FAIL détecté(s) — intervention requise.${RESET}"
    [[ "$WARNINGS" -gt 0 ]] && \
        echo -e "  ${JAUNE}${GRAS}   ${WARNINGS} avertissement(s) supplémentaire(s).${RESET}"
fi
echo ""
[[ "$FAILURES" -eq 0 ]] && exit 0 || exit 1

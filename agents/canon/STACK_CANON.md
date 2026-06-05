# STACK_CANON

> **Source de vérité unique** pour la liste des composants installés par `vps-secure/install.sh` (+ `install-dashboard.sh` optionnel).
> Lu par: `STACK_INVENTORY` (génère l'inventaire runtime), `CVE_WATCHER` (filtre CPE pour NVD), `IMPACT_ASSESSOR` (matching CVE × stack), `REMEDIATION_PLANNER` (politique de restart).
>
> **Versioning:** ce fichier est versionné dans le repo `rockballslab/vps-secure` sous `agents/STACK_CANON.md`. Toute modification = bump `schema_version` + commit daté.

---

## Metadata

```yaml
schema_version: 1.0
last_updated: 2026-06-06
target_os: ubuntu-24.04-lts
source_script: install.sh (commit ecd1f1651507)
generated_by: human (extracted from install.sh source)
```

## Schéma

Chaque composant est un objet avec ces champs:

| Champ | Type | Requis | Description |
|---|---|---|---|
| `id` | string | ✓ | Identifiant canonique (lowercase, dash-separated) |
| `name` | string | ✓ | Nom lisible (utilisé dans les notifs Telegram) |
| `category` | enum | ✓ | `os \| kernel \| ssh \| firewall \| ids_ips \| honeypot \| container \| integrity \| accounting \| hardening \| logs \| utilities \| custom_vps_secure \| dashboard_optional` |
| `install_method` | enum | ✓ | `apt \| packagecloud \| docker_repo \| sha_pinned_docker \| custom_python \| systemd_unit \| config_file` |
| `version_pin` | string | ✗ | Si version figée (ex: "1.4.6", ">=29.4.1", "sha256:abc…") |
| `ubuntu_package` | string | ✗ | Nom du paquet apt (si install_method = apt) |
| `cpe_prefix` | string | ✗ | CPE prefix pour matching NVD (ex: `cpe:2.3:a:openbsd:openssh`) |
| `docker_image` | string | ✗ | Image complète (ex: `shizunge/endlessh-go`) |
| `docker_sha256` | string | ✗ | Si sha-pinned |
| `upstream_url` | string | ✗ | Site officiel / repo GitHub upstream |
| `cve_sources` | array | ✓ | Sources CVE autorisées pour ce composant (cf. CVE_WATCHER whitelist) |
| `default_port` | int | ✗ | Port par défaut si applicable |
| `default_bind` | string | ✗ | `127.0.0.1 \| 0.0.0.0` (informational) |
| `notes` | string | ✗ | Cas spéciaux (ex: rkhunter 1.4.6 gap signatures 2018) |

## Composants canoniques (24)

```yaml
components:

  # ─── OS ─────────────────────────────────────────────────────────
  - id: ubuntu-os
    name: Ubuntu 24.04 LTS (Noble Numbat)
    category: os
    install_method: apt
    ubuntu_package: ubuntu-base
    cpe_prefix: cpe:2.3:o:canonical:ubuntu_linux:24.04
    upstream_url: https://releases.ubuntu.com/noble/
    cve_sources: [nvd, ubuntu-sn]
    version_pin: "24.04 LTS"
    notes: "Suivre les LTS security patches via unattended-upgrades"

  # ─── Kernel ─────────────────────────────────────────────────────
  - id: linux-kernel-hwe
    name: Linux kernel HWE 6.8.x
    category: kernel
    install_method: apt
    ubuntu_package: linux-generic-hwe-24.04
    cpe_prefix: cpe:2.3:o:canonical:ubuntu_linux:24.04
    upstream_url: https://kernel.ubuntu.com/
    cve_sources: [nvd, ubuntu-sn, ghsa]
    version_pin: "6.8.x HWE (latest)"
    notes: "Patch kernel = reboot obligatoire"

  # ─── SSH ────────────────────────────────────────────────────────
  - id: openssh-server
    name: OpenSSH server
    category: ssh
    install_method: apt
    ubuntu_package: openssh-server
    cpe_prefix: cpe:2.3:a:openbsd:openssh
    upstream_url: https://www.openssh.com/
    cve_sources: [nvd, ubuntu-sn, ghsa]
    default_port: 2222
    default_bind: "0.0.0.0"
    notes: "Port non-standard (2222). Clés only. Root désactivé. Pre-auth RCE = critique."

  # ─── Firewall ───────────────────────────────────────────────────
  - id: ufw
    name: Uncomplicated Firewall
    category: firewall
    install_method: apt
    ubuntu_package: ufw
    cpe_prefix: cpe:2.3:a:canonical:ufw
    upstream_url: https://launchpad.net/ufw
    cve_sources: [nvd, ubuntu-sn]
    notes: "Allow incoming: 2222/80/443. deny by default. Ne pas systemctl restart (window d'exposition)."

  # ─── IDS/IPS ────────────────────────────────────────────────────
  - id: crowdsec
    name: CrowdSec (IDS/IPS communautaire)
    category: ids_ips
    install_method: packagecloud
    cpe_prefix: cpe:2.3:a:crowdsec:crowdsec
    upstream_url: https://crowdsec.net/
    cve_sources: [nvd, ghsa, crowdsec-blog]
    version_pin: "latest (packagecloud repo)"
    notes: "v1.7.8+ sur Ubuntu 24.04. Compilé pragmatique. LAPI écoute 127.0.0.1:8080."

  - id: crowdsec-firewall-bouncer
    name: CrowdSec firewall bouncer (iptables)
    category: ids_ips
    install_method: packagecloud
    cpe_prefix: cpe:2.3:a:crowdsec:crowdsec
    upstream_url: https://crowdsec.net/
    cve_sources: [nvd, ghsa, crowdsec-blog]
    notes: "Restart APRÈS crowdsec engine (sinon perd LAPI)."

  - id: crowdsec-collections
    name: CrowdSec collections (linux, sshd, nginx)
    category: ids_ips
    install_method: cscli-collections
    cve_sources: [crowdsec-blog]
    notes: "Metadata seulement, pas de binaire. Mis à jour via cscli hub update."

  # ─── Honeypot ───────────────────────────────────────────────────
  - id: endlessh-go
    name: Endlessh-go (SSH tarpit)
    category: honeypot
    install_method: sha_pinned_docker
    docker_image: shizunge/endlessh-go
    docker_sha256: c9c5cd7084fda893f2b9f2c15d0b5867ba91ed06727375a3ca0f2678474fc09a
    upstream_url: https://github.com/shizunge/endlessh
    cve_sources: [nvd, ghsa, oss-fuzz]
    default_port: 22
    default_bind: "0.0.0.0"
    notes: "Tarpit SSH port 22. CVE mineures (DoS) = impact faible (honeypot)."

  # ─── Container runtime ─────────────────────────────────────────
  - id: docker-ce
    name: Docker Engine Community
    category: container
    install_method: apt
    ubuntu_package: docker-ce
    cpe_prefix: cpe:2.3:a:docker:docker
    upstream_url: https://docs.docker.com/engine/
    cve_sources: [nvd, ghsa, docker-security]
    version_pin: ">=29.4.1"
    notes: "daemon.json: iptables=false, live-restore=true. RCE docker = root effectif."

  - id: docker-compose-plugin
    name: Docker Compose v2 (plugin)
    category: container
    install_method: apt
    ubuntu_package: docker-compose-plugin
    cpe_prefix: cpe:2.3:a:docker:docker_compose
    upstream_url: https://docs.docker.com/compose/
    cve_sources: [nvd, ghsa, docker-security]

  # ─── Integrity ──────────────────────────────────────────────────
  - id: aide
    name: AIDE (Advanced Intrusion Detection Environment)
    category: integrity
    install_method: apt
    ubuntu_package: aide
    cpe_prefix: cpe:2.3:a:canonical:aide
    upstream_url: https://github.com/aide/aide
    cve_sources: [nvd, ubuntu-sn]
    version_pin: "0.18.x"
    notes: "Patch binaire = re-run aide --init et replace db. Hook apt: 99-rkhunter-propupd (uniquement rkhunter, pas aide)."

  - id: rkhunter
    name: Rootkit Hunter
    category: integrity
    install_method: apt
    ubuntu_package: rkhunter
    cpe_prefix: cpe:2.3:a:rkhunter:rkhunter
    upstream_url: https://sourceforge.net/projects/rkhunter/
    cve_sources: [nvd, ubuntu-sn]
    version_pin: "1.4.6 (2018, dernière version upstream)"
    notes: "GAP DOCUMENTÉ: signatures datées 2018, ne couvre pas BPFDoor/Symbiote/OrBit/Reptile. Couverture complétée par AIDE + auditd."

  - id: unhide
    name: Unhide (processus cachés)
    category: integrity
    install_method: apt
    ubuntu_package: unhide
    cve_sources: [nvd, ubuntu-sn]
    notes: "Améliore détection rkhunter. Pas de signature CVE publique."

  - id: debsums
    name: Debsums (intégrité paquets installés)
    category: integrity
    install_method: apt
    ubuntu_package: debsums
    cve_sources: [ubuntu-sn]
    notes: "Cron daily (CRON_CHECK=daily). PKGS-7370 fixé par install.sh."

  - id: auditd
    name: auditd (audit système Linux)
    category: integrity
    install_method: apt
    ubuntu_package: auditd
    cpe_prefix: cpe:2.3:a:linux:auditd
    upstream_url: https://github.com/linux-audit/audit-userspace
    cve_sources: [nvd, ubuntu-sn, ghsa]
    notes: "Règles CIS installées par install.sh. audispd-plugins optionnel (fallback)."

  - id: audispd-plugins
    name: audispd-plugins
    category: integrity
    install_method: apt
    ubuntu_package: audispd-plugins
    cve_sources: [ubuntu-sn]
    notes: "Optionnel — peut être absent sur certaines versions Ubuntu."

  # ─── Accounting ─────────────────────────────────────────────────
  - id: acct
    name: Process accounting (acct)
    category: accounting
    install_method: apt
    ubuntu_package: acct
    cve_sources: [ubuntu-sn]
    notes: "Traçabilité process. systemd enable --now."

  - id: sysstat
    name: sysstat (sar, iostat, mpstat)
    category: accounting
    install_method: apt
    ubuntu_package: sysstat
    cpe_prefix: cpe:2.3:a:sysstat:sysstat
    upstream_url: http://sebastien.godard.pagesperso-orange.fr/
    cve_sources: [ubuntu-sn, nvd]
    notes: "ENABLED=true requis. Restart après modif /etc/default/sysstat."

  # ─── Hardening ──────────────────────────────────────────────────
  - id: libpam-pwquality
    name: libpam-pwquality (politique mots de passe)
    category: hardening
    install_method: apt
    ubuntu_package: libpam-pwquality
    cve_sources: [ubuntu-sn]
    notes: "Patch apt ne nécessite pas restart (PAM rechargé sur next login)."

  - id: apparmor
    name: AppArmor (MAC Linux natif)
    category: hardening
    install_method: apt
    ubuntu_package: apparmor
    cpe_prefix: cpe:2.3:a:canonical:apparmor
    upstream_url: https://gitlab.com/apparmor/apparmor
    cve_sources: [nvd, ubuntu-sn]
    notes: "Actif par défaut sur Ubuntu 24.04. Profils enforcing vérifiés par install.sh."

  - id: unattended-upgrades
    name: Unattended Upgrades
    category: hardening
    install_method: apt
    ubuntu_package: unattended-upgrades
    cpe_prefix: cpe:2.3:a:canonical:unattended-upgrades
    upstream_url: https://github.com/mvo5/unattended-upgrades
    cve_sources: [ubuntu-sn]
    notes: "Security-only. Hook apt déclenche STACK_INVENTORY.refresh()."

  # ─── Logs ───────────────────────────────────────────────────────
  - id: rsyslog
    name: rsyslog (system log daemon)
    category: logs
    install_method: apt
    ubuntu_package: rsyslog
    cpe_prefix: cpe:2.3:a:rsyslog:rsyslog
    upstream_url: https://www.rsyslog.com/
    cve_sources: [nvd, ubuntu-sn, ghsa]
    notes: "Produit /var/log/auth.log (requis par CrowdSec)."

  # ─── Utilities (batch installé) ─────────────────────────────────
  - id: utilities-base
    name: Base utilities (curl, wget, gnupg, openssl, jq, …)
    category: utilities
    install_method: apt
    ubuntu_package: [curl, wget, gnupg, lsb-release, ca-certificates, apt-transport-https, software-properties-common, unzip, jq, htop, ncdu, tree, openssl, python3, apt-show-versions, needrestart]
    cve_sources: [nvd, ubuntu-sn, ghsa]
    notes: "Patch via unattended-upgrades. Pas de monitoring dédié (bas niveau)."

  # ─── Custom vps-secure ─────────────────────────────────────────
  - id: vps-secure-bot-funnel
    name: vps-secure-bot-funnel (custom Python systemd)
    category: custom_vps_secure
    install_method: custom_python
    cpe_prefix: null
    upstream_url: https://github.com/rockballslab/vps-secure
    cve_sources: [ghsa, custom-repo]
    notes: "Auteur: rockballslab. Polling LAPI CrowdSec. iptables NAT. Update via git pull du repo."

  - id: vps-secure-configs
    name: vps-secure systemd drop-ins
    category: custom_vps_secure
    install_method: config_file
    notes: "Fichiers: /etc/systemd/system/docker.service.d/99-vps-monitor-socket-refresh.conf, /etc/apt/apt.conf.d/99-rkhunter-propupd"

  # ─── Dashboard optionnel ────────────────────────────────────────
  - id: caddy
    name: Caddy reverse proxy (dashboard)
    category: dashboard_optional
    install_method: docker_repo
    docker_image: caddy:2-alpine
    upstream_url: https://caddyserver.com/
    cve_sources: [nvd, ghsa, docker-security]
    default_port: 443
    default_bind: "0.0.0.0"
    notes: "Zero-downtime reload. Tag 2-alpine = à résoudre en @sha256 via docker inspect."

  - id: vps-monitor-metrics-api
    name: vps-monitor-metrics-api (custom FastAPI)
    category: dashboard_optional
    install_method: custom_python
    upstream_url: https://github.com/rockballslab/vps-secure
    cve_sources: [custom-repo, ghsa]
    notes: "Read-only API: /var/log/{auth.log,sysstat,crowdsec,audit,rkhunter,aide} + Docker. JWT auth."
```

## Synchronisation avec install.sh

Ce canon est dérivé du `install.sh` à commit `ecd1f1651507` (2026-06-04). Pour régénérer après un bump de `install.sh`:

1. Lire le nouveau `install.sh` ligne par ligne
2. Identifier chaque `apt-get install` et noter le(s) paquet(s)
3. Identifier chaque `docker run` / `docker pull` et noter l'image + digest
4. Identifier chaque `systemctl enable` et noter le service
5. Identifier chaque `cat > /etc/...` qui crée un fichier de config custom
6. Comparer au canon actuel
7. Si diff → bump `schema_version` du canon, ajouter un changelog entry
8. Commit + push (PR review par mainteneur vps-secure)

## Changelog

| Date | Version | Changement | Auteur |
|---|---|---|---|
| 2026-06-06 | 1.0 | Création initiale depuis install.sh @ ecd1f1651507 | rockballslab |

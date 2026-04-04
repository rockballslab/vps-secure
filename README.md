# 🔐 vps-secure

**Le seul repo GitHub français qui sécurise vraiment ton serveur.**

"Si tu veux ton propre serveur, par exemple un VPS, pour faire tourner n8n / OpenClaw / ton SaaS. Avant d'installer quoi que ce soit, lance ce script. 
15 minutes, une seule commande, ton serveur passe du stade 'cible facile' à 'cible qui n'en vaut pas la peine'."

Un VPS Hostinger, livré nu, tourne avec root ouvert sur le port 22, sans firewall, sans détection d'intrusion. 
Les bots le trouvent en moins de 2 minutes. Ce script change ça en moins de 15.

---

<p align="center">
  <img src="./WATCHME.jpg" alt="Mon VPS avant et après install.sh" width="100%">
</p>

---

## Ce que fait `install.sh`

15 étapes automatiques, zéro compétence technique requise.

| # | Quoi | Pourquoi |
|---|---|---|
| 1 | Crée l'utilisateur `vpsadmin` | Fini le root — impossible de faire une erreur fatale |
| 2 | SSH port 2222, clé uniquement | Port 22 scanné en permanence par des bots — on déménage. Connexion limitée à `vpsadmin` uniquement |
| 3 | Mise à jour système + DNS chiffré + `/tmp`, `/var/tmp` et `/dev/shm` sécurisés | Ferme les failles connues. DNS over TLS activé **avant** tout téléchargement — élimine la fenêtre de DNS poisoning. `/tmp`, `/var/tmp` et `/dev/shm` montés `noexec` — les scripts malveillants ne peuvent pas s'y exécuter |
| 4 | **CrowdSec** | Détecte et bannit les IP malveillantes. Installé via dépôt GPG signé avec vérification d'empreinte — intégrité vérifiée |
| 5 | **UFW** (pare-feu) | Tout bloqué sauf les ports 2222, 80 et 443. Le forwarding Docker est ciblé — pas global |
| 6 | **Docker** Engine + Compose v2 | Docker permet de faire tourner des applications dans des "boîtes isolées" (containers). Configuré pour ne **pas** bypasser UFW — les ports exposés restent sous contrôle du pare-feu. Règle NAT ajoutée dans UFW — les containers ont accès à internet |
| 7 | unattended-upgrades | Patches de sécurité installés automatiquement chaque nuit |
| 8 | Kernel hardening | 26 paramètres : réseau (spoofing, SYN flood, ICMP, redirections sécurisées) + ASLR + protection ptrace + core dumps désactivés + perf events restreints |
| 9 | **auditd** | Journalise tout : SSH, sudo, Docker, fichiers sensibles, crontabs (vecteur de persistence) et `/etc/hosts` (MITM DNS local) |
| 10 | Swap 2 GB | Mémoire virtuelle d'urgence — évite les crashs |
| 11 | **rkhunter** | Scanne les backdoors et rootkits. Scan quotidien automatique à 04h00 — indépendant de Telegram |
| 12 | Désactivation des services inutiles | avahi, cups, bluetooth, ModemManager désactivés — chaque service actif = surface d'attaque (CIS 2.x). Ctrl-Alt-Delete masqué (DISA STIG) |
| 13 | Alertes **Telegram** | Rapport de sécurité quotidien + alerte immédiate à chaque connexion SSH — optionnel |
| 14 | **Endlessh** (honeypot port 22) | SSH est sur le port 2222 — le port 22 est libre. Endlessh le capture et maintient les bots connectés des heures en leur envoyant un banner SSH infini. Ils ne peuvent pas attaquer ailleurs pendant ce temps |
| 15 | **AIDE** (integrity monitoring) | Hash SHA512 de tous les binaires système à l'installation. Scan quotidien à 03h00 — toute modification (binaire remplacé, backdoor, rootkit) déclenche une alerte dans le rapport Telegram de 07h00 |

---

## Prérequis

Avant de commencer, tu as besoin de :

- ✅ Un VPS **Ubuntu 24.04 LTS** (Hostinger, Hetzner,…)
- ✅ L'**IP** et le **mot de passe root** fournis par ton hébergeur
- ✅ Une **clé SSH** générée sur ton ordinateur

> 💡 Pas encore de VPS ? [-20% sur Hostinger avec le code **WP7SERVERWR1**](https://www.hostinger.com/fr?REFERRALCODE=WP7SERVERWR1)

---

## Installation

### Étape 0 — Utilise le guide interactif (recommandé)

Avant de commencer, ouvre [`guide_installation.html`](./guide_installation.html) dans ton navigateur.

Il te permet de :
- Noter ton IP et ta clé SSH au même endroit
- Exporter ta config en `.txt` ou `.pdf`
- Déverrouiller la commande de lancement quand tout est prêt

> 💡 Télécharge le fichier `guide_installation.html` depuis le repo GitHub, puis ouvre-le avec ton navigateur (double-clic ou clic droit → Ouvrir avec).

### Étape 1 — Génère ta clé SSH (sur ton ordinateur)

Ouvre un terminal sur ton ordinateur :
- **Mac** → Spotlight (`Cmd+Espace`) → tape `Terminal` → Entrée
- **Windows** → touche `Windows` → tape `Windows Terminal` ou `PowerShell` → Entrée
- **Linux** → `Ctrl+Alt+T`

Puis lance cette commande :
```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_vps
```

Appuie sur Entrée 3 fois (pas besoin de mot de passe).

Récupère la clé publique — tu en auras besoin pendant le script :
```bash
cat ~/.ssh/id_ed25519_vps.pub
```

Copie la ligne qui s'affiche (elle commence par `ssh-ed25519`).

### Étape 2 — Connecte-toi en root

```bash
ssh root@IP_DU_VPS
```

### Étape 3 — Lance le script

```bash
curl -O https://raw.githubusercontent.com/rockballslab/vps-secure/main/install.sh
chmod +x install.sh && ./install.sh
```

Le script est interactif. Il te pose **2 questions obligatoires** :

1. Ta clé SSH publique (colle le contenu de `id_ed25519_vps.pub`)
2. Confirme que la connexion fonctionne depuis un 2ème terminal

Et **1 question optionnelle** à la fin : configurer les alertes Telegram.

> ⚠️ **Ne ferme pas cette session root avant que le script te le demande.**
> Il vérifie lui-même que tu peux te reconnecter avant de désactiver root.

### Étape 4 — Reconnecte-toi en vpsadmin

```bash
ssh vpsadmin@IP_DU_VPS -p 2222 -i ~/.ssh/id_ed25519_vps
```

C'est tout. Le VPS est sécurisé.

---

## Alertes de sécurité sur Telegram (optionnel)

À la fin de l'installation, le script te propose de configurer deux niveaux d'alertes :

- **Rapport quotidien à 07h00** — état global du serveur (CrowdSec, rkhunter, auditd)
- **Alerte immédiate** — notification Telegram à chaque connexion SSH réussie (utilisateur + IP source)

**Ce dont tu as besoin :**
1. Crée un bot → ouvre [@BotFather](https://t.me/BotFather) → `/newbot` → copie le token
2. Récupère ton chat ID → ouvre [@userinfobot](https://t.me/userinfobot) → `/start` → copie l'`id`

**Ce que tu reçois chaque matin à 07h00 :**

```
🔐 vps-secure — Rapport quotidien
📅 05/04/2026 · monvps

✅ Tout va bien sur ton VPS

✅ CrowdSec : aucune alerte
✅ rkhunter : aucune anomalie
✅ auditd : aucun événement critique
🍯 Endlessh : 247 bot(s) piégé(s) en 24h
✅ AIDE : aucune modification système détectée

Aucune action requise.
```

**Ce que tu reçois à chaque connexion SSH :**

```
🔐 Connexion SSH sur monvps
👤 Utilisateur : vpsadmin
🌐 IP source   : 92.184.x.x
📅 05/04/2026 14:32:17
```

Si une anomalie est détectée dans le rapport quotidien, le message inclut le détail et la commande exacte pour réparer.

> Tu as passé cette étape ? Relance `./install.sh` pour la configurer plus tard.

---

## ⚠️ Docker et le pare-feu UFW

Par défaut, Docker bypass UFW et expose directement les ports sur internet, même si UFW les bloque. **Ce script corrige ce comportement** en désactivant la gestion iptables de Docker.

Sans configuration supplémentaire, désactiver iptables dans Docker empêche aussi les containers d'accéder à internet (pas de règle NAT). **Ce script ajoute automatiquement la règle MASQUERADE nécessaire dans `/etc/ufw/before.rules`** — les containers ont accès à internet, les ports restent sous contrôle d'UFW.

**Ce que ça change concrètement :** si tu lances un container avec `-p 8080:8080`, le port **ne sera pas** accessible depuis internet tant que tu ne l'as pas autorisé dans UFW :

```bash
sudo ufw allow 8080/tcp comment 'Mon application'
```

---

## Niveau de sécurité

Ce script couvre environ **80% du CIS Benchmark Ubuntu 24.04 Level 1** et **70% du DISA STIG Ubuntu 24.04** — largement au-dessus de n'importe quel script public comparable.

| Standard | Couverture |
|---|---|
| CIS Benchmark L1 | ~80% |
| DISA STIG Ubuntu 24.04 | ~70% |
| OWASP Infrastructure | Supply chain (GPG + empreinte vérifiée), secrets, logging |

| CIS Benchmark
CIS = Center for Internet Security. C'est une organisation américaine à but non lucratif qui publie des guides de configuration sécurisée pour tous les OS majeurs.
Level 1 — sécurité raisonnable sans impact sur les fonctionnalités. C'est le minimum recommandé pour n'importe quel serveur en production. Pas "basique" au sens débutant — c'est le standard utilisé par les entreprises pour leurs serveurs. La majorité des orgas visent Level 1.

> Donc 80% CIS L1 c'est bien — tu couvres 4 contrôles sur 5 du standard que les entreprises appliquent. Les 20% restants sont soit des contrôles non applicables sur VPS (partitions dédiées /var, /home), soit des contrôles volontairement exclus pour garder le script accessible.

| DISA STIG
DISA = Defense Information Systems Agency. C'est l'agence IT du Département de la Défense américain. Les STIGs (Security Technical Implementation Guides) sont leurs guides de configuration — plus stricts que CIS, obligatoires pour tous les systèmes du gouvernement US.

> 70% DISA STIG c'est très bien pour un script public. Les 30% restants sont soit des contrôles militaires sans sens pour un VPS perso (accès physique, smartcard auth), soit des contrôles qui nécessitent une infrastructure d'entreprise (LDAP, SIEM centralisé).


A NOTER:

> ⚠️ **Note sur sudo :** `vpsadmin` a un accès sudo sans mot de passe (`NOPASSWD`). C'est intentionnel pour simplifier l'usage. Le script ajoute `use_pty` pour bloquer le sudo hijacking depuis un terminal détaché, mais si ta clé SSH privée est compromise, l'attaquant a root immédiatement. **Protège ta clé privée** — ne la stocke jamais dans le cloud, ne la copie pas sur un serveur.

> ⚠️ **Note sur Docker :** `vpsadmin` est dans le groupe `docker`, ce qui donne un accès root effectif via les containers (`docker run` peut monter le système de fichiers complet). Traite ta clé SSH comme une clé root.

---

## Ce que ce script ne fait PAS

- ❌ Pas de configuration d'application (n8n, Wordpress, etc.) — ce repo sécurise l'OS, pas le reste
- ❌ Pas de certificat HTTPS — à configurer avec Caddy ou Nginx selon ton usage

---

## Commandes utiles après installation

```bash
# Voir les alertes CrowdSec (dernières 24h)
sudo cscli alerts list --since 24h

# Consulter les logs d'audit
sudo ausearch -k privilege_escalation --start today -i
sudo ausearch -k docker_socket --start today -i
sudo aureport --summary

# Lancer un scan de rootkits
sudo rkhunter --check --report-warnings-only

# Voir le log du scan rkhunter quotidien (04h00)
sudo cat /var/log/rkhunter-cron.log

# Statut du pare-feu
sudo ufw status verbose

# Vérifier les ports exposés par Docker
sudo docker ps --format "table {{.Names}}\t{{.Ports}}"

# Tester le rapport Telegram manuellement
sudo /usr/local/bin/vps-secure-check.sh

# Honeypot Endlessh — stats des bots piégés (dernières 24h)
sudo docker logs endlessh --since 24h | grep -ci accept

# Honeypot Endlessh — logs en direct
sudo docker logs -f endlessh

# AIDE — lancer un scan d'intégrité manuellement
sudo aide --check

# AIDE — mettre à jour la baseline après une mise à jour OS
sudo aide --update && sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

---

## Compatibilité

Testé sur **Ubuntu 24.04 LTS** — Hostinger KVM2, KVM4 · Hetzner AX ·

---

## Licence

MIT — libre d'utilisation, de modification et de redistribution.

---

*Fait avec ❤️ par [@rockballslab](https://github.com/rockballslab)* pour AI FORCE ONE

#!/usr/bin/env python3
"""
VPS Secure Monitor — Metrics API
Stdlib only. No external dependencies.
"""

import json
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
import base64
import hmac
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────
API_HOST            = os.environ.get("API_HOST", "127.0.0.1")
API_PORT            = int(os.environ.get("API_PORT", "5055"))
CACHE_TTL           = int(os.environ.get("CACHE_TTL", "30"))
CROWDSEC_URL        = os.environ.get("CROWDSEC_URL", "http://127.0.0.1:8081")
CROWDSEC_KEY        = os.environ.get("CROWDSEC_API_KEY", "")
ENDLESSH_CONTAINER  = os.environ.get("ENDLESSH_CONTAINER", "endlessh")
CROWDSEC_CONTAINER  = os.environ.get("CROWDSEC_CONTAINER", "crowdsec")
HOSTFS              = os.environ.get("HOSTFS", "/")

# ── Geo IP ────────────────────────────────────────────────────────────────────
_geo_cache: dict = {}

def _flag(code: str) -> str:
    """ISO 3166-1 alpha-2 → emoji drapeau.  'CN' → '🇨🇳'  'FR' → '🇫🇷'"""
    if not code or len(code) != 2:
        return ""
    return (chr(0x1F1E6 + ord(code[0].upper()) - ord("A")) +
            chr(0x1F1E6 + ord(code[1].upper()) - ord("A")))

_PRIV = ("10.", "192.168.", "127.", "::1",
         "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
         "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
         "172.28.", "172.29.", "172.30.", "172.31.")

def get_geo(ip: str) -> dict:
    """Retourne {country, code, flag} pour une IP publique.
    Cache mémoire — ip-api.com gratuit (sans clé, 45 req/min) — timeout 2s.
    Retourne {} pour les IPs privées/loopback ou en cas d'erreur réseau.
    """
    if not ip or any(ip.startswith(p) for p in _PRIV):
        return {}
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode"
        req = urllib.request.Request(url, headers={"User-Agent": "vps-monitor/1.0"})
        with urllib.request.urlopen(req, timeout=2) as r:
            d = json.loads(r.read().decode())
        if d.get("status") == "success":
            code = d.get("countryCode", "")
            geo  = {"country": d.get("country", ""), "code": code, "flag": _flag(code)}
            _geo_cache[ip] = geo
            return geo
    except Exception:
        pass
    _geo_cache[ip] = {}
    return {}

def _geo_tag(ip: str) -> str:
    """Retourne ' · 🇨🇳 CN' pour une IP. Chaîne vide si pas de données."""
    g = _geo_cache.get(ip, {})
    f, c = g.get("flag", ""), g.get("code", "")
    return f" · {f} {c}" if f else ""

def _prefetch_geo(ips: list) -> None:
    """Lookup parallèle pour toutes les IPs inconnues du cache.
    Utilise threading (déjà importé). Timeout total : 3 secondes.
    Résultats stockés dans _geo_cache — lookups suivants instantanés.
    """
    unknown = [ip for ip in dict.fromkeys(ips) if ip and ip not in _geo_cache]
    if not unknown:
        return
    threads = [
        threading.Thread(target=get_geo, args=(ip,), daemon=True)
        for ip in unknown
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=3.0)

# ── Auth & Rate Limiting ──────────────────────────────────────────────────────
DASHBOARD_USER   = os.environ.get("DASHBOARD_USER", "admin")
DASHBOARD_PASS   = os.environ.get("DASHBOARD_PASS", "")   # vide = auth désactivée
RL_MAX_ATTEMPTS  = int(os.environ.get("AUTH_MAX_ATTEMPTS", "5"))
RL_WINDOW_SEC    = int(os.environ.get("AUTH_WINDOW_SEC",  "300"))   # 5 min
RL_LOCKOUT_SEC   = int(os.environ.get("AUTH_LOCKOUT_SEC", "900"))   # 15 min

_rl_lock      = threading.Lock()
_rl_failed:   dict[str, list[float]] = {}
_rl_lockouts: dict[str, float]       = {}

def _client_ip(handler: "Handler") -> str:
    """Extrait l'IP réelle — gère X-Forwarded-For de Caddy."""
    xff = handler.headers.get("X-Forwarded-For", "")
    return xff.split(",")[0].strip() if xff else handler.client_address[0]

def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    with _rl_lock:
        if ip in _rl_lockouts:
            if now < _rl_lockouts[ip]:
                return True
            del _rl_lockouts[ip]
            _rl_failed.pop(ip, None)
        _rl_failed[ip] = [t for t in _rl_failed.get(ip, []) if now - t < RL_WINDOW_SEC]
        return len(_rl_failed[ip]) >= RL_MAX_ATTEMPTS

def _record_auth_failure(ip: str) -> None:
    now = time.time()
    with _rl_lock:
        _rl_failed.setdefault(ip, []).append(now)
        if len(_rl_failed[ip]) >= RL_MAX_ATTEMPTS:
            _rl_lockouts[ip] = now + RL_LOCKOUT_SEC
            print(f"[VPS Monitor] ⚠️  RATE LIMIT {ip} — lockout {RL_LOCKOUT_SEC}s", flush=True)

def _check_basic_auth(handler: "Handler") -> bool:
    """HTTP Basic Auth avec hmac.compare_digest (anti timing-attack)."""
    if not DASHBOARD_PASS:
        return True  # Auth désactivée — usage interne 127.0.0.1 uniquement
    auth = handler.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(auth[6:]).decode("utf-8", errors="replace")
        username, _, password = decoded.partition(":")
        return (
            hmac.compare_digest(username.encode(), DASHBOARD_USER.encode()) and
            hmac.compare_digest(password.encode(), DASHBOARD_PASS.encode())
        )
    except Exception:
        return False

_cache: dict | None = None
_cache_time: float  = 0.0

# ── Historique en mémoire + persistance disque (24h max) ─────────────────────
HISTORY_MAX_SECONDS = 86400  # 24h
HISTORY_FILE        = "/var/log/vps-monitor-history.json"
_history: list[dict] = []

def _load_history() -> None:
    global _history
    try:
        with open(HISTORY_FILE) as f:
            data = json.load(f)
        cutoff = time.time() - HISTORY_MAX_SECONDS
        _history = [p for p in data if p.get("ts", 0) > cutoff]
        print(f"[VPS Monitor] Historique chargé : {len(_history)} points", flush=True)
    except Exception:
        _history = []

def _save_history() -> None:
    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(_history, f)
    except Exception:
        pass

def push_history(metrics: dict) -> None:
    now = time.time()
    _history.append({
        "ts":       now,
        "endlessh": metrics["endlessh"].get("last24h", 0),
        "crowdsec": metrics["crowdsec"].get("active_bans", 0),
        "ufw":      metrics["ufw"].get("total", 0),
    })
    cutoff = now - HISTORY_MAX_SECONDS
    while _history and _history[0]["ts"] < cutoff:
        _history.pop(0)
    _save_history()

def get_last_update_date():
    try:
        path = "/var/lib/apt/periodic/update-success-stamp"
        if os.path.exists(path):
            return datetime.fromtimestamp(os.path.getmtime(path)).strftime('%d/%m/%Y %H:%M')
        return "Inconnue"
    except:
        return "Erreur"

# ── Helpers ───────────────────────────────────────────────────────────────────
def run(cmd: list[str], timeout: int = 10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""


def _parse_ts(s: str) -> float:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0


def _lapi(path: str) -> list | None:
    """Query CrowdSec LAPI with bouncer API key."""
    if not CROWDSEC_KEY:
        return None
    try:
        req = urllib.request.Request(
            f"{CROWDSEC_URL}{path}",
            headers={"X-Api-Key": CROWDSEC_KEY, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


# ── Collectors ────────────────────────────────────────────────────────────────
def get_endlessh() -> dict:
    out24   = run(["docker", "logs", "--since", "24h", ENDLESSH_CONTAINER], timeout=20)
    out_all = run(["docker", "logs", "--tail", "200000", ENDLESSH_CONTAINER], timeout=30)
    pat     = re.compile(r"ACCEPT|\"accepted\"", re.IGNORECASE)

    # Durée moyenne de piège — parser les lignes CLOSE avec time=
    # Format shizunge/endlessh-go : "CLOSE host=x.x.x.x port=N time=3723.4 bytes=N"
    durations = []
    for m in re.finditer(r"CLOSE\b.*?\btime=([0-9]+(?:\.[0-9]+)?)", out_all):
        try:
            durations.append(float(m.group(1)))
        except Exception:
            pass
    avg_duration_s = round(sum(durations) / len(durations)) if durations else 0

    # Formater en h/min/s lisible
    def fmt_duration(s: int) -> str:
        if s <= 0:
            return "—"
        if s >= 3600:
            return f"{s // 3600}h{(s % 3600) // 60}m"
        if s >= 60:
            return f"{s // 60}m{s % 60}s"
        return f"{s}s"

    return {
        "last24h":          len(pat.findall(out24)),
        "total":            len(pat.findall(out_all)),
        "avg_duration_s":   avg_duration_s,
        "avg_duration_fmt": fmt_duration(avg_duration_s),
        "trap_count":       len(durations),
    }


def get_crowdsec() -> dict:
    active_bans = 0
    alerts_24h  = 0

    if CROWDSEC_KEY:
        decisions = _lapi("/v1/decisions?limit=50000")
        active_bans = len(decisions) if decisions else 0

        alerts = _lapi("/v1/alerts?limit=500")
        if alerts:
            cutoff = time.time() - 86400
            alerts_24h = sum(
                1 for a in alerts
                if _parse_ts(a.get("created_at", "")) > cutoff
            )
    else:
        out = run(
            ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "decisions", "list", "-o", "json"],
            timeout=15,
        )
        try:
            d = json.loads(out)
            active_bans = len(d) if d else 0
        except Exception:
            pass

        out2 = run(
            ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "alerts", "list",
             "--since", "24h", "-o", "json"],
            timeout=15,
        )
        try:
            d2 = json.loads(out2)
            alerts_24h = len(d2) if d2 else 0
        except Exception:
            pass

    return {"active_bans": active_bans, "alerts_24h": alerts_24h}


def get_bouncer_status() -> dict:
    # Vérifier que le bouncer firewall communique avec l'API
    # Un bouncer actif crée des décisions — on vérifie juste si l'API répond
    try:
        req = urllib.request.Request(
            f"{CROWDSEC_URL}/v1/decisions",
            headers={"X-Api-Key": CROWDSEC_KEY} if CROWDSEC_KEY else {},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            # Si l'API répond = CrowdSec actif = bouncer présumé actif
            return {"status": "active"}
    except Exception:
        return {"status": "unknown"}


def get_telegram_status() -> dict:
    """Statut des alertes Telegram — rapport quotidien et alerte SSH."""
    conf = "/etc/vps-secure/telegram.conf"
    configured = os.path.exists(conf)

    report = False
    try:
        cron = Path("/etc/cron.d/vps-secure")
        if cron.exists():
            c = cron.read_text()
            report = bool(re.search(r"^[^#].*vps-secure-check\.sh", c, re.MULTILINE))
    except Exception:
        pass

    ssh_alert = False
    try:
        pam = Path("/etc/pam.d/sshd")
        if pam.exists():
            c = pam.read_text()
            ssh_alert = bool(re.search(r"^[^#].*vps-secure-ssh-alert\.sh", c, re.MULTILINE))
    except Exception:
        pass

    return {"configured": configured, "report": report, "ssh": ssh_alert}


def toggle_telegram(toggle_type: str) -> dict:
    """Activer/désactiver rapport quotidien ou alerte SSH Telegram."""
    if toggle_type == "report":
        cron_path = "/etc/cron.d/vps-secure"
        try:
            content = Path(cron_path).read_text()
            if re.search(r"^[^#].*vps-secure-check\.sh", content, re.MULTILINE):
                new = re.sub(r"^(.*vps-secure-check\.sh.*)$", r"#\1", content, flags=re.MULTILINE)
                enabled = False
            else:
                new = re.sub(r"^#(.*vps-secure-check\.sh.*)$", r"\1", content, flags=re.MULTILINE)
                enabled = True
            Path(cron_path).write_text(new)
            return {"ok": True, "report": enabled}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    elif toggle_type == "ssh":
        pam_path = "/etc/pam.d/sshd"
        try:
            content = Path(pam_path).read_text()
            if re.search(r"^[^#].*vps-secure-ssh-alert\.sh", content, re.MULTILINE):
                new = re.sub(r"^(.*vps-secure-ssh-alert\.sh.*)$", r"#\1", content, flags=re.MULTILINE)
                enabled = False
            else:
                new = re.sub(r"^#(.*vps-secure-ssh-alert\.sh.*)$", r"\1", content, flags=re.MULTILINE)
                enabled = True
            Path(pam_path).write_text(new)
            return {"ok": True, "ssh": enabled}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    return {"ok": False, "error": "type invalide"}


def get_ufw() -> dict:
    total = 0
    for path in ["/var/log/ufw.log", "/var/log/ufw.log.1"]:
        try:
            with open(path, errors="replace") as f:
                total += f.read().count("UFW BLOCK")
        except Exception:
            pass
    return {"total": total}


def get_auditd() -> dict:
    sudo_today = 0
    today_iso = datetime.now().strftime("%Y-%m-%d")

    for path in ["/var/log/auth.log", "/var/log/secure"]:
        try:
            with open(path, errors="replace") as f:
                for line in f:
                    if "sudo:" in line and "COMMAND=" in line and today_iso in line:
                        sudo_today += 1
            break
        except Exception:
            continue

    return {"sudo_today": sudo_today}


def get_rkhunter() -> dict:
    status    = "unknown"
    last_scan = "Jamais"

    try:
        with open("/var/log/rkhunter.log", errors="replace") as f:
            content = f.read()

        if "Warning:" in content:
            status = "warning"
        elif len(content) > 100:
            status = "clean"

        dates = re.findall(r"Start date is\s+(.+?)\n", content)
        if dates:
            try:
                dt = datetime.strptime(dates[-1].strip(), "%a %b %d %H:%M:%S %Z %Y")
                last_scan = dt.strftime("%d/%m/%Y %H:%M")
            except Exception:
                last_scan = dates[-1].strip()
    except Exception:
        pass

    return {"status": status, "last_scan": last_scan}


def get_aide() -> dict:
    status    = "unknown"
    last_scan = "Jamais"

    # Lire l'exit code du script vps-secure-aide-check.sh
    try:
        with open("/var/log/aide-daily.exit") as f:
            exit_code = int(f.read().strip())
        if exit_code == 0:
            status = "clean"
        elif (exit_code & 56) != 0:
            status = "unknown"
        elif (exit_code & 7) != 0:
            if os.path.exists("/var/log/aide-daily.exit.context"):
                status = "rebase"    # apt a tourné — rebase attendu
            else:
                status = "changes"   # aucune activité apt — suspect
        else:
            status = "unknown"
    except Exception:
        pass

    # Date depuis aide-daily.log
    try:
        p = Path("/var/log/aide-daily.log")
        if p.exists() and p.stat().st_size > 0:
            last_scan = datetime.fromtimestamp(p.stat().st_mtime).strftime("%d/%m/%Y %H:%M")
    except Exception:
        pass

    return {"status": status, "last_scan": last_scan}


def get_system() -> dict:
    # Uptime
    try:
        with open("/proc/uptime") as f:
            sec = float(f.read().split()[0])
        d, h, m = int(sec // 86400), int(sec % 86400 // 3600), int(sec % 3600 // 60)
        uptime_str = (f"{d}j {h}h" if d else f"{h}h {m}m")
    except Exception:
        uptime_str = "—"

    # Load
    try:
        with open("/proc/loadavg") as f:
            p = f.read().split()
        load = {"1m": p[0], "5m": p[1], "15m": p[2]}
        load["cores"] = os.cpu_count() or 1
    except Exception:
        load = {"1m": "—", "5m": "—", "15m": "—"}

    # Memory
    memory = {"total_mb": 0, "used_mb": 0, "pct": 0.0}
    try:
        mem: dict[str, int] = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                mem[k.strip()] = int(v.split()[0])
        total = mem["MemTotal"]
        used  = total - mem["MemAvailable"]
        memory = {
            "total_mb": total // 1024,
            "used_mb":  used  // 1024,
            "pct":      round(used / total * 100, 1),
        }
    except Exception:
        pass

    # Disk
    disk_info = {"total_gb": 0.0, "used_gb": 0.0, "pct": 0.0}
    try:
        du = shutil.disk_usage(HOSTFS)
        disk_info = {
            "total_gb": round(du.total / 1e9, 1),
            "used_gb":  round(du.used  / 1e9, 1),
            "pct":      round(du.used  / du.total * 100, 1),
        }
    except Exception:
        pass

    # IP publique du VPS
    vps_ip = "—"
    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=5) as resp:
            vps_ip = json.loads(resp.read()).get("ip", "—")
    except Exception:
        pass

    return {"uptime": uptime_str, "load": load, "memory": memory, "disk": disk_info, "ip": vps_ip}


def get_ssh_last() -> dict:
    """Dernière connexion SSH réussie — IP + heure."""
    last_ip   = "—"
    last_time = "—"

    for path in ["/var/log/auth.log", "/var/log/secure"]:
        try:
            with open(path, errors="replace") as f:
                lines = f.readlines()
            for line in reversed(lines):
                if "Accepted" in line and "sshd" in line:
                    m = re.search(r"from\s+(\S+)\s+port", line)
                    if m:
                        last_ip = m.group(1)
                    m2 = re.search(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
                    if m2:
                        try:
                            dt = datetime.strptime(
                                f"{datetime.now().year} {m2.group(1).strip()}",
                                "%Y %b %d %H:%M:%S"
                            )
                            last_time = dt.strftime("%d/%m/%Y %H:%M")
                        except Exception:
                            pass
                    break
            break
        except Exception:
            continue

    return {"ip": last_ip, "time": last_time}


def get_updates() -> dict:
    """Nombre de paquets avec mise à jour disponible."""
    count = 0
    try:
        out = run(["apt", "list", "--upgradable"], timeout=15)
        count = len([l for l in out.splitlines() if "upgradable from" in l])
    except Exception:
        pass
    return {"count": count}


def get_connections() -> dict:
    count = 0
    try:
        for path in ["/proc/net/tcp", "/proc/net/tcp6"]:
            try:
                with open(path) as f:
                    lines = f.readlines()[1:]
                count += sum(1 for l in lines if l.split()[3] == "01")
            except Exception:
                pass
    except Exception:
        pass
    return {"established": count}


def get_open_ports() -> dict:
    EXPECTED = {22, 25, 53, 80, 443, 2222, 5055, 6060, 8081}
    ports = []
    seen = set()
    for path in ["/proc/net/tcp", "/proc/net/tcp6"]:
        try:
            with open(path) as f:
                lines = f.readlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) < 4:
                    continue
                # État 0A = LISTEN
                if parts[3] != "0A":
                    continue
                local = parts[1]
                port = int(local.split(":")[1], 16)
                if port in seen:
                    continue
                seen.add(port)
                ports.append({
                    "port":     port,
                    "process":  "",
                    "expected": port in EXPECTED,
                })
        except Exception:
            pass
    unexpected = [p for p in ports if not p["expected"]]
    return {
        "ports":      sorted(ports, key=lambda x: x["port"]),
        "unexpected": unexpected,
        "alert":      len(unexpected) > 0,
    }

def get_alerts() -> list:
    """Journal de sécurité 24h — 4 statuts :
       action      -> 🔴 Action requise   (doit être traité manuellement)
       detected    -> 👁️  Détectée         (anomalie, protection active)
       reported    -> 📢 Signalée          (notifié via Telegram)
       neutralized -> ✅ Neutralisée       (VPS-SECURE a géré automatiquement)
    """
    alerts = []
    now    = time.time()
    cutoff = now - 86400  # 24h

    # ── 1. CrowdSec bans → ✅ Neutralisée ─────────────────────────────────────
    try:
        out = run(
            ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "alerts",
             "list", "--since", "24h", "-o", "json"],
            timeout=15,
        )
        cs_list   = json.loads(out) if out.strip().startswith("[") else []
        ban_count = len(cs_list) if cs_list else 0
        if ban_count > 0:
            last_ts = max((_parse_ts(a.get("created_at", "")) for a in cs_list), default=now)
            s = "s" if ban_count > 1 else ""
            alerts.append({
                "service": "CrowdSec",
                "status":  "neutralized",
                "icon":    "✅",
                "label":   "Neutralisée",
                "detail":  f"{ban_count} IP{s} bannie{s} automatiquement",
                "ts":      last_ts,
            })
    except Exception:
        pass

    # ── 2. Endlessh bots → ✅ Neutralisée ─────────────────────────────────────
    try:
        out24     = run(["docker", "logs", "--since", "24h", ENDLESSH_CONTAINER], timeout=20)
        bot_count = len(re.findall(r'ACCEPT|"accepted"', out24, re.IGNORECASE))
        if bot_count > 0:
            s = "s" if bot_count > 1 else ""
            alerts.append({
                "service": "Endlessh",
                "status":  "neutralized",
                "icon":    "✅",
                "label":   "Neutralisée",
                "detail":  f"{bot_count} bot{s} piégé{s} sur port 22",
                "ts":      now,
            })
    except Exception:
        pass

    # ── 3. UFW blocks → ✅ Neutralisée ────────────────────────────────────────
    try:
        ufw_total = 0
        for path in ["/var/log/ufw.log", "/var/log/ufw.log.1"]:
            try:
                with open(path, errors="replace") as f:
                    ufw_total += f.read().count("UFW BLOCK")
            except Exception:
                pass
        if ufw_total > 0:
            s = "s" if ufw_total > 1 else ""
            alerts.append({
                "service": "UFW",
                "status":  "neutralized",
                "icon":    "✅",
                "label":   "Neutralisée",
                "detail":  f"{ufw_total} connexion{s} bloquée{s} (cumul 24h)",
                "ts":      now,
            })
    except Exception:
        pass

    # ── 4. Telegram actif → 📢 Signalée ───────────────────────────────────────
    try:
        tg = get_telegram_status()
        if tg.get("configured") and tg.get("report"):
            alerts.append({
                "service": "Telegram",
                "status":  "reported",
                "icon":    "📢",
                "label":   "Signalée",
                "detail":  "Rapport quotidien actif — tu es notifié chaque matin à 09h00",
                "ts":      now,
            })
        if tg.get("configured") and tg.get("ssh"):
            alerts.append({
                "service": "Telegram",
                "status":  "reported",
                "icon":    "📢",
                "label":   "Signalée",
                "detail":  "Alerte SSH active — tu es notifié à chaque connexion",
                "ts":      now,
            })
    except Exception:
        pass

    # ── 5. rkhunter → 👁️ Détectée ou 🔴 Action requise ───────────────────────
    # Warnings sur binaires critiques = Action requise
    CRIT_BINS = ["/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"]
    # Faux positifs rkhunter connus → silence total (ne pas alarmer pour rien)
    FP = [
        "lwp-request", "lwp-rget", "GET", "HEAD", "POST",
        "mail", "mailx", "hidden files", "hidden directories",
        "package manager", "gpg", "passwd file", "group file",
    ]
    try:
        with open("/var/log/rkhunter.log", errors="replace") as f:
            content = f.read()
        dates   = re.findall(r"Start date is\s+(.+?)\n", content)
        scan_ts = now - 3600
        if dates:
            try:
                scan_ts = datetime.strptime(
                    dates[-1].strip(), "%a %b %d %H:%M:%S %Z %Y"
                ).timestamp()
            except Exception:
                pass
        for w in re.findall(r"Warning:\s+(.+?)(?:\n|$)", content):
            w = w.strip()
            if not w or any(fp.lower() in w.lower() for fp in FP):
                continue   # faux positif connu → silence
            is_crit = any(b in w for b in CRIT_BINS)
            alerts.append({
                "service": "rkhunter",
                "status":  "action" if is_crit else "detected",
                "icon":    "🔴" if is_crit else "👁️",
                "label":   "Action requise" if is_crit else "Détectée",
                "detail":  w[:120],
                "ts":      scan_ts,
            })
    except Exception:
        pass

    # ── 6. AIDE integrity ─────────────────────────────────────────────────────
    try:
        with open("/var/log/aide-daily.exit") as f:
            exit_code = int(f.read().strip())
        aide_ts = now
        try:
            p = Path("/var/log/aide-daily.log")
            if p.exists() and p.stat().st_size > 0:
                aide_ts = p.stat().st_mtime
        except Exception:
            pass
        if (exit_code & 7) != 0:
            has_ctx = os.path.exists("/var/log/aide-daily.exit.context")
            if has_ctx:
                # Modif après apt upgrade → normal, pas d'urgence
                alerts.append({
                    "service": "AIDE",
                    "status":  "reported",
                    "icon":    "📢",
                    "label":   "Signalée",
                    "detail":  "Modifications liées à une mise à jour apt — comportement attendu",
                    "ts":      aide_ts,
                })
            else:
                # Modif sans contexte apt → suspect
                alerts.append({
                    "service": "AIDE",
                    "status":  "action",
                    "icon":    "🔴",
                    "label":   "Action requise",
                    "detail":  "Fichiers système modifiés hors mise à jour — vérification requise",
                    "ts":      aide_ts,
                })
    except Exception:
        pass

    # ── 7. SSH brute force (seuil ≥ 20 tentatives en 24h) ────────────────────
    fail_count   = 0
    last_fail_ts = cutoff
    last_fail_ip = "IP inconnue"
    for path in ["/var/log/auth.log", "/var/log/secure"]:
        try:
            with open(path, errors="replace") as f:
                for line in f:
                    if (("Failed password" not in line and "Invalid user" not in line)
                            or "sshd" not in line):
                        continue
                    m_t  = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
                    m_t2 = re.search(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
                    ts = 0.0
                    if m_t:
                        try:
                            ts = datetime.fromisoformat(m_t.group(1)).timestamp()
                        except Exception:
                            pass
                    elif m_t2:
                        try:
                            ts = datetime.strptime(
                                f"{datetime.now().year} {m_t2.group(1).strip()}",
                                "%Y %b %d %H:%M:%S",
                            ).timestamp()
                        except Exception:
                            pass
                    if ts > cutoff:
                        fail_count += 1
                        if ts > last_fail_ts:
                            last_fail_ts = ts
                            m_ip = re.search(r"from\s+(\S+)\s+port", line)
                            last_fail_ip = m_ip.group(1) if m_ip else "IP inconnue"
            break
        except Exception:
            continue

    if fail_count >= 20:
        bouncer_ok = get_bouncer_status().get("status") == "active"
        if not bouncer_ok:
            alerts.append({
                "service": "SSH",
                "status":  "action",
                "icon":    "🔴",
                "label":   "Action requise",
                "detail":  (f"{fail_count} tentatives SSH + bouncer inactif "
                            f"— protection compromise"),
                "ts":      last_fail_ts,
            })
        else:
            alerts.append({
                "service": "SSH",
                "status":  "detected",
                "icon":    "👁️",
                "label":   "Détectée",
                "detail":  (f"{fail_count} tentatives bloquées par CrowdSec "
                            f"(dernière IP : {last_fail_ip})"),
                "ts":      last_fail_ts,
            })

    # ── 8. Ports inattendus → 🔴 Action requise ───────────────────────────────
    try:
        for p in get_open_ports().get("unexpected", []):
            alerts.append({
                "service": "Ports",
                "status":  "action",
                "icon":    "🔴",
                "label":   "Action requise",
                "detail":  f"Port inattendu en écoute : {p['port']} — quelle app l'utilise ?",
                "ts":      now,
            })
    except Exception:
        pass

    # ── 9. Disque ─────────────────────────────────────────────────────────────
    try:
        du  = shutil.disk_usage(HOSTFS)
        pct = round(du.used / du.total * 100, 1)
        ugb = round(du.used  / 1e9, 1)
        tgb = round(du.total / 1e9, 1)
        if pct > 90:
            alerts.append({
                "service": "Disque",
                "status":  "action",
                "icon":    "🔴",
                "label":   "Action requise",
                "detail":  f"Espace disque à {pct}% ({ugb}Go / {tgb}Go) — risque de crash",
                "ts":      now,
            })
        elif pct > 80:
            alerts.append({
                "service": "Disque",
                "status":  "detected",
                "icon":    "👁️",
                "label":   "Détectée",
                "detail":  f"Espace disque à {pct}% ({ugb}Go / {tgb}Go) — prévoir du nettoyage",
                "ts":      now,
            })
    except Exception:
        pass

    # ── 10. Mémoire ───────────────────────────────────────────────────────────
    try:
        mem: dict[str, int] = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                mem[k.strip()] = int(v.split()[0])
        total = mem["MemTotal"]
        used  = total - mem["MemAvailable"]
        pct   = round(used / total * 100, 1)
        if pct > 95:
            alerts.append({
                "service": "Mémoire",
                "status":  "action",
                "icon":    "🔴",
                "label":   "Action requise",
                "detail":  f"RAM à {pct}% ({used // 1024}Mo / {total // 1024}Mo) — risque crash containers",
                "ts":      now,
            })
        elif pct > 85:
            alerts.append({
                "service": "Mémoire",
                "status":  "detected",
                "icon":    "👁️",
                "label":   "Détectée",
                "detail":  f"RAM à {pct}% ({used // 1024}Mo / {total // 1024}Mo) — surveiller",
                "ts":      now,
            })
    except Exception:
        pass

    # ── 11. CrowdSec bouncer inactif → 🔴 Action requise ──────────────────────
    try:
        if get_bouncer_status().get("status") != "active":
            alerts.append({
                "service": "CrowdSec",
                "status":  "action",
                "icon":    "🔴",
                "label":   "Action requise",
                "detail":  "Bouncer inactif — les IPs malveillantes ne sont plus bannies",
                "ts":      now,
            })
    except Exception:
        pass

    # ── 12. Mises à jour en retard (> 30 paquets) → 👁️ Détectée ──────────────
    try:
        out   = run(["apt", "list", "--upgradable"], timeout=15)
        count = len([l for l in out.splitlines() if "upgradable from" in l])
        if count > 30:
            alerts.append({
                "service": "Mises à jour",
                "status":  "detected",
                "icon":    "👁️",
                "label":   "Détectée",
                "detail":  f"{count} paquets en retard — mise à jour manuelle recommandée",
                "ts":      now,
            })
    except Exception:
        pass

    # ── Format timestamps & tri ───────────────────────────────────────────────
    ORDER = {"action": 0, "detected": 1, "reported": 2, "neutralized": 3}
    for a in alerts:
        try:
            a["datetime"] = datetime.fromtimestamp(a["ts"]).strftime("%d/%m %H:%M")
        except Exception:
            a["datetime"] = "—"
        del a["ts"]
    alerts.sort(key=lambda x: ORDER.get(x["status"], 9))
    return alerts

def get_timeline() -> list:
    """20 derniers événements sécurité triés par heure (SSH, bans CrowdSec, sudo critique, rkhunter)."""
    events = []
    now = time.time()
    cutoff = now - 86400  # 24h

    # ── SSH connections (auth.log) ──
    ssh_by_ip: dict = {}  # grouper par IP — une seule ligne avec count

    for path in ["/var/log/auth.log", "/var/log/secure"]:
        try:
            with open(path, errors="replace") as f:
                lines = f.readlines()
            year = datetime.now().year
            for line in lines:
                if "Accepted publickey" in line and "sshd" in line:
                    m_ip   = re.search(r"from\s+(\S+)\s+port", line)
                    m_user = re.search(r"for\s+(\S+)\s+from", line)
                    m_time = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
                    if m_time:
                        try:
                            ts = datetime.fromisoformat(m_time.group(1)).timestamp()
                        except Exception:
                            continue
                    else:
                        m_time2 = re.search(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
                        if not m_time2:
                            continue
                        try:
                            ts = datetime.strptime(f"{year} {m_time2.group(1).strip()}", "%Y %b %d %H:%M:%S").timestamp()
                        except Exception:
                            continue
                    if ts < cutoff:
                        continue
                    ip   = m_ip.group(1) if m_ip else "?"
                    user = m_user.group(1) if m_user else "inconnu"
                    if ip not in ssh_by_ip:
                        ssh_by_ip[ip] = {"ts": ts, "count": 0, "user": user}
                    ssh_by_ip[ip]["count"] += 1
                    if ts > ssh_by_ip[ip]["ts"]:
                        ssh_by_ip[ip]["ts"] = ts

                elif "Failed password" in line or "Invalid user" in line:
                    m_ip   = re.search(r"from\s+(\S+)\s+port", line)
                    m_time = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
                    if m_time:
                        try:
                            ts = datetime.fromisoformat(m_time.group(1)).timestamp()
                        except Exception:
                            continue
                    else:
                        m_time2 = re.search(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
                        if not m_time2:
                            continue
                        try:
                            ts = datetime.strptime(f"{year} {m_time2.group(1).strip()}", "%Y %b %d %H:%M:%S").timestamp()
                        except Exception:
                            continue
                    if ts < cutoff:
                        continue
                    events.append({
                        "ts":    ts,
                        "type":  "ssh_fail",
                        "icon":  "⚠️",
                        "color": "rose",
                        "title": "Tentative SSH échouée",
                        "detail": m_ip.group(1) if m_ip else "IP inconnue",
                        "_ip":   m_ip.group(1) if m_ip else "",
                        "count": 1,
                    })
            break
        except Exception:
            continue

    # Convertir ssh_by_ip en events
    for ip, data in ssh_by_ip.items():
        events.append({
            "ts":    data["ts"],
            "type":  "ssh",
            "icon":  "🔑",
            "color": "teal",
            "title": f"Connexion SSH — {data['user']}",
            "detail": ip,
            "_ip":   ip,
            "count": data["count"],
        })

            
    # ── CrowdSec bans (via docker exec cscli) ──
    try:
        out = run(
            ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "alerts", "list",
             "--since", "24h", "-o", "json"],
            timeout=15,
        )
        alerts = json.loads(out) if out.strip().startswith("[") else []
        for a in (alerts or []):
            ts = _parse_ts(a.get("created_at", ""))
            if ts < cutoff:
                continue
            src = a.get("source", {})
            ip  = src.get("ip", "IP inconnue")
            reason = a.get("scenario", a.get("reason", "Règle CrowdSec"))
            events.append({
                "ts":    ts,
                "type":  "ban",
                "icon":  "🛡️",
                "color": "purple",
                "title": f"IP bannie — {ip}",
                "detail": reason,
                "_ip":   ip,
            })
    except Exception:
        pass

    # ── Sudo commands critiques ──
    CRITICAL_CMDS = ["useradd", "userdel", "passwd", "chmod 777", "visudo", "crontab", "iptables", "ufw"]
    today_iso = datetime.now().strftime("%Y-%m-%d")
    for path in ["/var/log/auth.log", "/var/log/secure"]:
        try:
            with open(path, errors="replace") as f:
                lines = f.readlines()
            year = datetime.now().year
            for line in lines:
                if "sudo:" not in line or "COMMAND=" not in line:
                    continue
                cmd_m = re.search(r"COMMAND=(.+?)(?:\s*$)", line)
                if not cmd_m:
                    continue
                cmd = cmd_m.group(1).strip()
                is_critical = any(c in cmd for c in CRITICAL_CMDS)
                if not is_critical:
                    continue
                m_time = re.search(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
                if m_time:
                    try:
                        ts = datetime.strptime(f"{year} {m_time.group(1).strip()}", "%Y %b %d %H:%M:%S").timestamp()
                    except Exception:
                        continue
                    if ts < cutoff:
                        continue
                    m_user = re.search(r"sudo:\s+(\S+)\s+:", line)
                    events.append({
                        "ts":    ts,
                        "type":  "sudo",
                        "icon":  "⚡",
                        "color": "gold",
                        "title": f"Commande sudo critique — {m_user.group(1) if m_user else 'inconnu'}",
                        "detail": cmd[:80],
                    })
            break
        except Exception:
            continue

    # ── rkhunter warnings ──
    try:
        with open("/var/log/rkhunter.log", errors="replace") as f:
            content = f.read()
        for m in re.finditer(r"Warning:\s+(.+?)(?:\n|$)", content):
            events.append({
                "ts":    now - 3600,  # approximatif si pas de timestamp
                "type":  "rkhunter",
                "icon":  "🔍",
                "color": "red",
                "title": "rkhunter — warning détecté",
                "detail": m.group(1).strip()[:80],
            })
    except Exception:
        pass

    # Trier par timestamp décroissant, garder les 25 plus récents
    events.sort(key=lambda x: x["ts"], reverse=True)
    events = events[:25]
    

    # ── Géolocalisation IPs (parallèle, cache mémoire) ───────────────────────
    _prefetch_geo([e["_ip"] for e in events if e.get("_ip")])
    for e in events:
        _ip = e.pop("_ip", None)
        if _ip:
            tag = _geo_tag(_ip)
            if tag:
                e["detail"] = (e.get("detail") or "") + tag

    # Formater les timestamps pour l'affichage
    for e in events:
        try:
            e["time"] = datetime.fromtimestamp(e["ts"]).strftime("%H:%M:%S")
            e["date"] = datetime.fromtimestamp(e["ts"]).strftime("%d/%m")
        except Exception:
            e["time"] = "—"
            e["date"] = "—"

    return events


def get_score(metrics: dict) -> dict:
    """Score de santé global 0-100 basé sur l'état de tous les composants."""
    score = 100
    issues = []

    # Bouncer CrowdSec (critique — sans lui rien n'est banni)
    bouncer = metrics.get("bouncer", {}).get("status", "unknown")
    if bouncer != "active":
        score -= 30
        issues.append({"sev": "critical", "msg": "Bouncer CrowdSec inactif — les IPs ne sont plus bannies"})

    # rkhunter
    rk = metrics.get("rkhunter", {}).get("status", "unknown")
    if rk == "warning":
        score -= 20
        issues.append({"sev": "high", "msg": "rkhunter — anomalie détectée"})
    elif rk == "unknown":
        score -= 5
        issues.append({"sev": "info", "msg": "rkhunter — pas encore exécuté"})

    # AIDE
    ai = metrics.get("aide", {}).get("status", "unknown")
    if ai == "changes":
        score -= 20
        issues.append({"sev": "high", "msg": "AIDE — modifications système détectées"})
    elif ai == "unknown":
        score -= 5
        issues.append({"sev": "info", "msg": "AIDE — baseline pas encore scannée"})

    # Ports inattendus
    ports = metrics.get("open_ports", {})
    unexpected = ports.get("unexpected", [])
    if unexpected:
        score -= 15 * min(len(unexpected), 2)
        for p in unexpected[:3]:
            issues.append({"sev": "high", "msg": f"Port inattendu ouvert : {p['port']} ({p.get('process','?')})"})

    # Mises à jour en attente
    upd = metrics.get("updates", {}).get("count", 0)
    if upd > 20:
        score -= 10
        issues.append({"sev": "medium", "msg": f"{upd} mises à jour en attente"})
    elif upd > 0:
        score -= 5
        issues.append({"sev": "info", "msg": f"{upd} mises à jour disponibles"})

    # Disque
    disk_pct = metrics.get("system", {}).get("disk", {}).get("pct", 0)
    if disk_pct > 90:
        score -= 10
        issues.append({"sev": "high", "msg": f"Disque presque plein : {disk_pct}%"})
    elif disk_pct > 80:
        score -= 5
        issues.append({"sev": "medium", "msg": f"Disque à {disk_pct}%"})

    # Mémoire
    mem_pct = metrics.get("system", {}).get("memory", {}).get("pct", 0)
    if mem_pct > 95:
        score -= 5
        issues.append({"sev": "medium", "msg": f"Mémoire critique : {mem_pct}%"})

    score = max(0, min(100, score))

    if score >= 90:
        level = "excellent"
        label = "Forteresse"
        color = "green"
    elif score >= 70:
        level = "good"
        label = "Bon état"
        color = "teal"
    elif score >= 50:
        level = "warning"
        label = "À surveiller"
        color = "gold"
    else:
        level = "critical"
        label = "Action requise"
        color = "red"

    return {
        "score":  score,
        "level":  level,
        "label":  label,
        "color":  color,
        "issues": issues,
    }


# ── Cache & Aggregator ────────────────────────────────────────────────────────
def collect() -> dict:
    base = {
        "endlessh":    get_endlessh(),
        "crowdsec":    get_crowdsec(),
        "bouncer":     get_bouncer_status(),
        "ufw":         get_ufw(),
        "auditd":      get_auditd(),
        "rkhunter":    get_rkhunter(),
        "aide":        get_aide(),
        "system":      get_system(),
        "ssh_last":    get_ssh_last(),
        "updates": {
            "count": get_updates()["count"],
            "last_check": get_last_update_date()
        },
        "connections": get_connections(),
        "open_ports":  get_open_ports(),
        "collected_at": int(time.time()),
    }
    # Score calculé après les autres métriques
    base["score"] = get_score(base)
    return base


def get_metrics() -> dict:
    global _cache, _cache_time
    now = time.time()
    if _cache and (now - _cache_time) < CACHE_TTL:
        return _cache
    _cache      = collect()
    _cache_time = now
    push_history(_cache)
    return _cache


# ── HTTP Handler ──────────────────────────────────────────────────────────────
ROUTES = {
    "/api/metrics":  lambda: get_metrics(),
    "/api/health":   lambda: {"status": "ok", "ts": int(time.time())},
    "/api/history":  lambda: _history,
    "/api/timeline": lambda: get_timeline(),
    "/api/telegram/status": lambda: get_telegram_status(),
    "/api/alerts":          lambda: get_alerts(),
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        ip = _client_ip(self)

        # 1. Rate limiting (avant auth)
        if _is_rate_limited(ip):
            self.send_response(429)
            self.send_header("Retry-After", str(RL_LOCKOUT_SEC))
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b'{"error":"too_many_requests"}')
            return

        # 2. Authentification HTTP Basic
        if DASHBOARD_PASS and not _check_basic_auth(self):
            _record_auth_failure(ip)
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="VPS-SECURE Dashboard"')
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b'{"error":"unauthorized"}')
            return

        # 3. Routing
        fn = ROUTES.get(self.path.rstrip("/"))
        if fn is None:
            self.send_error(404)
            return
        try:
            body = json.dumps(fn(), ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type",   "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control",  "no-store")
            self.end_headers()
            self.wfile.write(body)
        except Exception as exc:
            self.send_error(500, str(exc))


    def do_POST(self) -> None:
        path = self.path.rstrip("/")
        if path == "/api/telegram/toggle":
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length)) if length else {}
                toggle_type = body.get("type", "")
                result = toggle_telegram(toggle_type)
                resp = json.dumps(result, ensure_ascii=False).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)
            except Exception as exc:
                self.send_error(500, str(exc))
        else:
            self.send_error(404)

    def log_message(self, fmt: str, *args) -> None:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] {fmt % args}", flush=True)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    _load_history()
    srv = HTTPServer((API_HOST, API_PORT), Handler)
    print(f"[VPS Monitor] API on {API_HOST}:{API_PORT} — cache TTL {CACHE_TTL}s", flush=True)
    srv.serve_forever()

# ── Telegram status & toggle ─────────────────────────────────────────────────

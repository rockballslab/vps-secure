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
import hashlib
import base64
import hmac
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

# ── Config ────────────────────────────────────────────────────────────────────
API_HOST            = os.environ.get("API_HOST", "127.0.0.1")
API_PORT            = int(os.environ.get("API_PORT", "5055"))
CACHE_TTL           = int(os.environ.get("CACHE_TTL", "120"))
ALERTS_CACHE_TTL   = int(os.environ.get("ALERTS_CACHE_TTL",   str(CACHE_TTL)))
TIMELINE_CACHE_TTL = int(os.environ.get("TIMELINE_CACHE_TTL", str(CACHE_TTL)))
CONTAINERS_CACHE_TTL = int(os.environ.get("CONTAINERS_CACHE_TTL", "30"))
CROWDSEC_URL        = os.environ.get("CROWDSEC_URL", "http://127.0.0.1:8081")
CROWDSEC_KEY        = os.environ.get("CROWDSEC_API_KEY", "")
ENDLESSH_CONTAINER  = os.environ.get("ENDLESSH_CONTAINER", "endlessh")
CROWDSEC_CONTAINER  = os.environ.get("CROWDSEC_CONTAINER", "crowdsec")
HOSTFS              = os.environ.get("HOSTFS", "/")

# ── AIDE trigger file (issue #109) ───────────────────────────────────────────
AIDE_TRIGGER = Path("/var/lib/vps-monitor/aide_rebase_trigger")
AIDE_RESULT  = Path("/var/lib/vps-monitor/aide_rebase_result")

# ── Variables de cache (globales) ────────────────────────────────────────────
_alerts_cache: dict       = {}
_alerts_cache_time: dict  = {}
_timeline_cache: list | None = None
_timeline_cache_time: float  = 0.0
_containers_cache: list | None = None
_containers_cache_time: float  = 0.0


# ── Geo IP ────────────────────────────────────────────────────────────────────
_geo_cache: dict = {}
_vps_ip_cache: str = ""
_vps_ip_cache_time: float = 0.0
_GEO_CACHE_MAX = 5000  # évite la croissance illimitée sous attaque

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
    Cache memoire — ip-api.com gratuit (sans cle, 45 req/min) — timeout 2s.
    Retourne {} pour les IPs privees/loopback ou en cas d'erreur reseau.
    """
    if not ip or any(ip.startswith(p) for p in _PRIV):
        return {}
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        # FIX M-GEO — ipapi.co (HTTPS gratuit) remplace ip-api.com (HTTP only)
        url = f"https://ipapi.co/{ip}/json/"
        req = urllib.request.Request(url, headers={"User-Agent": "vps-monitor/1.0"})
        with urllib.request.urlopen(req, timeout=2) as r:
            d = json.loads(r.read().decode())
        code = d.get("country_code", "")
        country = d.get("country_name", d.get("country", ""))
        if code:
            geo = {"country": country, "code": code, "flag": _flag(code)}
            if len(_geo_cache) >= _GEO_CACHE_MAX:
                # Purge simple : vider la moitié la plus ancienne
                keys = list(_geo_cache.keys())
                for k in keys[:_GEO_CACHE_MAX // 2]:
                    del _geo_cache[k]
            _geo_cache[ip] = geo
            return geo
    except Exception:
        pass
    _geo_cache[ip] = {}
    return {}

def _geo_tag(ip: str) -> str:
    """Retourne ' · flag CC' pour une IP. Chaine vide si pas de donnees."""
    g = _geo_cache.get(ip, {})
    f, c = g.get("flag", ""), g.get("code", "")
    return f" · {f} {c}" if f else ""

def _prefetch_geo(ips: list) -> None:
    """Lookup parallele pour toutes les IPs inconnues du cache."""
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
DASHBOARD_PASS   = os.environ.get("DASHBOARD_PASS", "")
RL_MAX_ATTEMPTS  = int(os.environ.get("AUTH_MAX_ATTEMPTS", "5"))
RL_WINDOW_SEC    = int(os.environ.get("AUTH_WINDOW_SEC",  "300"))
RL_LOCKOUT_SEC   = int(os.environ.get("AUTH_LOCKOUT_SEC", "900"))

_rl_lock = threading.Lock()
_rl_failed: dict[str, list[float]] = {}
_rl_lockouts: dict[str, float] = {}
# FIX M-RL — Persistance des lockouts sur disque (survit aux restarts container)
RL_STATE_FILE = "/var/lib/vps-monitor/rl_state.json"

def _save_rl_state() -> None:
    try:
        os.makedirs(os.path.dirname(RL_STATE_FILE), exist_ok=True)
        with open(RL_STATE_FILE, "w") as f:
            json.dump({"lockouts": _rl_lockouts}, f)
    except Exception:
        pass

def _load_rl_state() -> None:
    global _rl_lockouts
    try:
        with open(RL_STATE_FILE) as f:
            d = json.load(f)
            now = time.time()
            _rl_lockouts = {ip: t for ip, t in d.get("lockouts", {}).items() if t > now}
    except Exception:
        pass

TRUSTED_PROXIES = {"127.0.0.1", "::1"}

def _client_ip(handler) -> str:
    peer_ip = handler.client_address[0]
    if peer_ip in TRUSTED_PROXIES:
        xff = handler.headers.get("X-Forwarded-For", "").strip()
        if xff:
            for ip in reversed([i.strip() for i in xff.split(",")]):
                if ip not in TRUSTED_PROXIES:
                    return ip
    return peer_ip

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
            print(f"[VPS Monitor] RATE LIMIT {ip} — lockout {RL_LOCKOUT_SEC}s", flush=True)
            _save_rl_state()

def _check_basic_auth(handler: "Handler") -> bool:
    if not DASHBOARD_PASS:
        return True
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

# ── Historique en memoire + persistance disque (24h max) ─────────────────────
HISTORY_MAX_SECONDS = 86400
HISTORY_FILE        = "/var/lib/vps-monitor/history.json"
_history: list[dict] = []

def _load_history() -> None:
    global _history
    try:
        with open(HISTORY_FILE) as f:
            data = json.load(f)
        cutoff = time.time() - HISTORY_MAX_SECONDS
        _history = [p for p in data if p.get("ts", 0) > cutoff]
        print(f"[VPS Monitor] Historique charge : {len(_history)} points", flush=True)
    except Exception:
        _history = []

def _save_history() -> None:
    try:
        tmp = HISTORY_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_history, f)
        os.replace(tmp, HISTORY_FILE)  # atomique sur Linux
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
    except Exception:
        return "Erreur"
        
# ── F5 : Event Log Persistant (historique 30j) ───────────────────────────────
EVENTS_FILE     = "/var/lib/vps-monitor/events.json"
EVENTS_MAX_DAYS = 30
_ev_lock        = threading.Lock()
_ev_by_fp: dict[str, dict] = {}   # fingerprint → event (index de dédup)


def _ev_fp(service: str, ip: str, key: str, day: str) -> str:
    """Fingerprint unique par événement agrégé (service + ip + clé + jour)."""
    raw = f"{service}|{ip}|{key}|{day}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _ev_load() -> None:
    """Charge events.json au démarrage, purge les entrées > 30j."""
    global _ev_by_fp
    try:
        with open(EVENTS_FILE) as f:
            data = json.load(f)
        cutoff = time.time() - EVENTS_MAX_DAYS * 86400
        _ev_by_fp = {fp: ev for fp, ev in data.items() if ev.get("ts", 0) > cutoff}
        print(f"[VPS Monitor] Events chargés : {len(_ev_by_fp)}", flush=True)
    except Exception:
        _ev_by_fp = {}


def _ev_save() -> None:
    """Sauvegarde atomique de _ev_by_fp sur disque."""
    try:
        tmp = EVENTS_FILE + ".tmp"
        os.makedirs(os.path.dirname(EVENTS_FILE), exist_ok=True)
        with open(tmp, "w") as f:
            json.dump(_ev_by_fp, f)
        os.replace(tmp, EVENTS_FILE)
    except Exception:
        pass


def _ev_upsert(fp: str, event: dict) -> None:
    """Insère un nouvel événement ou met à jour count + ts si déjà connu."""
    if fp in _ev_by_fp:
        existing = _ev_by_fp[fp]
        if event.get("count", 1) > existing.get("count", 0):
            existing["count"]  = event["count"]
            existing["detail"] = event["detail"]
        existing["ts"] = max(existing.get("ts", 0), event["ts"])
    else:
        _ev_by_fp[fp] = dict(event)


def _ev_prune() -> None:
    """Supprime les événements antérieurs à 30 jours."""
    cutoff = time.time() - EVENTS_MAX_DAYS * 86400
    stale  = [fp for fp, ev in _ev_by_fp.items() if ev.get("ts", 0) < cutoff]
    for fp in stale:
        del _ev_by_fp[fp]


def _collect_historical_events() -> None:
    """
    Scanne les logs système, détecte les événements de sécurité
    et les persiste dans _ev_by_fp (30 jours de rétention).
    Appelé toutes les 5 minutes par le thread de collecte.
    """
    now        = time.time()
    cutoff_30d = now - EVENTS_MAX_DAYS * 86400
    year       = datetime.now().year

    # ── 1. SSH ───────────────────────────────────────────────────────────────
    ssh_by_key: dict[tuple, dict] = {}   # (ip, day) → {count, ts, user}
    ssh_ok_ips: set[str]          = set()

    for auth_path in ["/var/log/sshd.log", "/var/log/auth.log", "/var/log/secure"]:
        lines: list[str] = []
        for candidate in [auth_path + ".1", auth_path]:   # .1 d'abord = plus ancien
            try:
                with open(candidate, errors="replace") as f:
                    lines += f.readlines()
            except Exception:
                pass
        if not lines:
            continue

        for line in lines:
            if "sshd" not in line:
                continue
            ts  = 0.0
            m_iso = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
            m_sys = re.search(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
            if m_iso:
                try:    ts = datetime.fromisoformat(m_iso.group(1)).timestamp()
                except: continue
            elif m_sys:
                try:    ts = datetime.strptime(f"{year} {m_sys.group(1).strip()}", "%Y %b %d %H:%M:%S").timestamp()
                except: continue
            else:
                continue
            if ts < cutoff_30d:
                continue

            day  = datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
            m_ip = re.search(r"from\s+(\S+)\s+port", line)
            ip   = m_ip.group(1) if m_ip else ""

            if "Accepted publickey" in line or "Accepted password" in line:
                if ip:
                    ssh_ok_ips.add(ip)
            elif any(kw in line for kw in [
                "Failed password", "Failed publickey",
                "Invalid user", "Connection closed by invalid user"
            ]):
                if not ip:
                    continue
                m_user = re.search(r"(?:for invalid user|for)\s+(\S+)\s+from", line)
                user   = m_user.group(1) if m_user else "inconnu"
                k      = (ip, day)
                if k not in ssh_by_key:
                    ssh_by_key[k] = {"count": 0, "ts": ts, "user": user}
                ssh_by_key[k]["count"] += 1
                ssh_by_key[k]["ts"]     = max(ssh_by_key[k]["ts"], ts)
        break   # Premier fichier trouvé = source de vérité (évite les doublons)

    with _ev_lock:
        for (ip, day), data in ssh_by_key.items():
            if ip in ssh_ok_ips:
                continue   # IP avec connexion réussie → pas hostile
            count = data["count"]
            fp    = _ev_fp("SSH", ip, f"fail_{day}", day)
            _ev_upsert(fp, {
                "ts":      data["ts"],
                "service": "SSH :2222",
                "detail":  f"{count} tentative(s) échouée(s) — user cible : {data['user']}",
                "ip":      ip,
                "status":  "action" if count >= 20 else "detected",
                "icon":    "🔴" if count >= 20 else "👁️",
                "label":   "Action requise" if count >= 20 else "Détectée",
                "count":   count,
            })

    # ── 2. UFW ───────────────────────────────────────────────────────────────
    PORTS_WATCHED  = {"2222", "22", "80", "443", "3389", "5900", "6379", "8080", "27017"}
    ufw_by_key: dict[tuple, dict] = {}

    # Toujours lire ufw.log ET ufw.log.1 (pas de break prématuré)
    for log_path in ["/var/log/ufw.log", "/var/log/ufw.log.1"]:
        try:
            with open(log_path, errors="replace") as f:
                lines = f.readlines()
            for line in lines:
                if "UFW BLOCK" not in line:
                    continue
                m_iso = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
                m_sys = re.search(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
                if m_iso:
                    try:    ts = datetime.fromisoformat(m_iso.group(1)).timestamp()
                    except: continue
                elif m_sys:
                    try:    ts = datetime.strptime(f"{year} {m_sys.group(1).strip()}", "%Y %b %d %H:%M:%S").timestamp()
                    except: continue
                else:
                    continue
                if ts < cutoff_30d:
                    continue
                m_src = re.search(r"SRC=(\S+)", line)
                m_dpt = re.search(r"DPT=(\d+)", line)
                if not m_src:
                    continue
                ip  = m_src.group(1)
                dpt = m_dpt.group(1) if m_dpt else "?"
                if dpt not in PORTS_WATCHED:
                    continue
                day = datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
                k   = (ip, dpt, day)
                if k not in ufw_by_key:
                    ufw_by_key[k] = {"count": 0, "ts": ts, "ip": ip, "dpt": dpt}
                ufw_by_key[k]["count"] += 1
                ufw_by_key[k]["ts"]     = max(ufw_by_key[k]["ts"], ts)
        except Exception:
            continue

    # Fallback kern.log/syslog uniquement si aucune entrée UFW trouvée
    if not ufw_by_key:
        for log_path in ["/var/log/kern.log", "/var/log/syslog"]:
            try:
                with open(log_path, errors="replace") as f:
                    lines = f.readlines()
                found = False
                for line in lines:
                    if "UFW BLOCK" not in line:
                        continue
                    found = True
                    # (même parsing que ci-dessus)
                    m_iso = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
                    m_sys = re.search(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
                    if m_iso:
                        try:    ts = datetime.fromisoformat(m_iso.group(1)).timestamp()
                        except: continue
                    elif m_sys:
                        try:    ts = datetime.strptime(f"{year} {m_sys.group(1).strip()}", "%Y %b %d %H:%M:%S").timestamp()
                        except: continue
                    else:
                        continue
                    if ts < cutoff_30d:
                        continue
                    m_src = re.search(r"SRC=(\S+)", line)
                    m_dpt = re.search(r"DPT=(\d+)", line)
                    if not m_src:
                        continue
                    ip  = m_src.group(1)
                    dpt = m_dpt.group(1) if m_dpt else "?"
                    if dpt not in PORTS_WATCHED:
                        continue
                    day = datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
                    k   = (ip, dpt, day)
                    if k not in ufw_by_key:
                        ufw_by_key[k] = {"count": 0, "ts": ts, "ip": ip, "dpt": dpt}
                    ufw_by_key[k]["count"] += 1
                    ufw_by_key[k]["ts"]     = max(ufw_by_key[k]["ts"], ts)
                if found:
                    break
            except Exception:
                continue

    with _ev_lock:
        for (ip, dpt, day), data in ufw_by_key.items():
            fp         = _ev_fp("UFW", ip, f"{dpt}_{day}", day)
            port_label = "SSH :2222" if dpt == "2222" else f"port {dpt}"
            _ev_upsert(fp, {
                "ts":      data["ts"],
                "service": "UFW",
                "detail":  f"Bloqué sur {port_label} — {data['count']}x",
                "ip":      ip,
                "status":  "neutralized",
                "icon":    "✅",
                "label":   "Neutralisée",
                "count":   data["count"],
            })

    # ── 3. CrowdSec ──────────────────────────────────────────────────────────
    try:
        out = run(
            ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "alerts",
             "list", "--since", f"{EVENTS_MAX_DAYS * 24}h", "-o", "json"],
            timeout=15,
        )
        raw     = out.strip()
        cs_list = (json.loads(raw) if raw.startswith("[") else []) or []
        with _ev_lock:
            for a in cs_list:
                ts = _parse_ts(a.get("created_at", ""))
                if ts < cutoff_30d:
                    continue
                src    = a.get("source", {})
                ip     = src.get("ip", "IP inconnue")
                reason = a.get("scenario", a.get("reason", "Règle CrowdSec"))
                day    = datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
                fp     = _ev_fp("CrowdSec", ip, reason[:40], day)
                _ev_upsert(fp, {
                    "ts":      ts,
                    "service": "CrowdSec",
                    "detail":  reason[:80],
                    "ip":      ip,
                    "status":  "neutralized",
                    "icon":    "✅",
                    "label":   "Neutralisée",
                    "count":   1,
                })
    except Exception:
        pass

    # ── 4. Endlessh (par jour) ────────────────────────────────────────────────
    try:
        out_all    = run(["docker", "logs", "--since", f"{EVENTS_MAX_DAYS * 24}h",
                          ENDLESSH_CONTAINER], timeout=30)
        pat_accept = re.compile(r"ACCEPT|\"accepted\"", re.IGNORECASE)
        day_counts: dict[str, int] = {}
        for line in out_all.splitlines():
            if not pat_accept.search(line):
                continue
            m_d = re.search(r"(\d{4}-\d{2}-\d{2})", line)
            day_str = m_d.group(1) if m_d else datetime.now().strftime("%Y-%m-%d")
            day_counts[day_str] = day_counts.get(day_str, 0) + 1
        with _ev_lock:
            for day_str, count in day_counts.items():
                try:
                    ts = datetime.strptime(day_str, "%Y-%m-%d").replace(hour=12).timestamp()
                except Exception:
                    ts = now
                fp = _ev_fp("Endlessh", "---", "bots", day_str)
                _ev_upsert(fp, {
                    "ts":      ts,
                    "service": "Endlessh",
                    "detail":  f"{count} bot(s) piégé(s) sur port 22",
                    "ip":      "---",
                    "status":  "neutralized",
                    "icon":    "✅",
                    "label":   "Neutralisée",
                    "count":   count,
                })
    except Exception:
        pass

    # ── 5. rkhunter (toutes les sessions du log) ──────────────────────────────
    CRIT_BINS = ["/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"]
    RK_FP     = ["lwp-request", "lwp-rget", "GET", "HEAD", "POST", "mail", "mailx",
                 "hidden files", "hidden directories", "package manager",
                 "gpg", "passwd file", "group file"]
    try:
        with open("/var/log/rkhunter.log", errors="replace") as f:
            content = f.read()
        dates = re.findall(r"Start date is\s+(.+?)\n", content)
        for i, date_str in enumerate(dates):
            idx_s   = content.find(f"Start date is {date_str}")
            idx_e   = content.find(f"Start date is {dates[i+1]}") if i + 1 < len(dates) else len(content)
            session = content[idx_s:idx_e]
            scan_ts = now - 3600
            for fmt in ("%a %b %d %I:%M:%S %p %Z %Y", "%a %b %d %H:%M:%S %Z %Y"):
                try:
                    scan_ts = datetime.strptime(date_str.strip(), fmt).timestamp()
                    break
                except Exception:
                    pass
            if scan_ts < cutoff_30d:
                continue
            day_str = datetime.fromtimestamp(scan_ts).strftime("%Y-%m-%d")
            for w in re.findall(r"Warning:\s+(.+?)(?:\n|$)", session):
                w = w.strip()
                if not w or any(fp_str.lower() in w.lower() for fp_str in RK_FP):
                    continue
                is_crit = any(b in w for b in CRIT_BINS)
                w_hash  = hashlib.md5(w.encode()).hexdigest()[:8]
                fp      = _ev_fp("rkhunter", "---", w_hash, day_str)
                with _ev_lock:
                    _ev_upsert(fp, {
                        "ts":      scan_ts,
                        "service": "rkhunter",
                        "detail":  w[:120],
                        "ip":      "---",
                        "status":  "action" if is_crit else "detected",
                        "icon":    "🔴" if is_crit else "👁️",
                        "label":   "Action requise" if is_crit else "Détectée",
                        "count":   1,
                    })
    except Exception:
        pass

    # ── Prune + Save ─────────────────────────────────────────────────────────
    with _ev_lock:
        _ev_prune()
        _ev_save()
    print(f"[VPS Monitor] Events collectés : {len(_ev_by_fp)} en mémoire", flush=True)


def _events_collector_loop() -> None:
    """Thread daemon — collecte les événements toutes les 5 minutes."""
    while True:
        try:
            _collect_historical_events()
        except Exception as e:
            print(f"[VPS Monitor] Event collector error: {e}", flush=True)
        time.sleep(300)   # 5 minutes

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
    out_all = run(["docker", "logs", "--tail", "50000", ENDLESSH_CONTAINER], timeout=20)
    pat     = re.compile(r"ACCEPT|\"accepted\"", re.IGNORECASE)

    durations = []
    for m in re.finditer(r"CLOSE\b.*?\btime=([0-9]+(?:\.[0-9]+)?)", out_all):
        try:
            durations.append(float(m.group(1)))
        except Exception:
            pass
    avg_duration_s = round(sum(durations) / len(durations)) if durations else 0

    def fmt_duration(s: int) -> str:
        if s <= 0:
            return "---"
        if s >= 3600:
            return f"{s // 3600}h{(s % 3600) // 60}m"
        if s >= 60:
            return f"{s // 60}m{s % 60}s"
        return f"{s}s"

    # Persistance du total cumulatif (survit aux redémarrages container)
    ENDLESSH_PERSIST = "/var/lib/vps-monitor/endlessh-total.json"
    persisted_total = 0
    try:
        with open(ENDLESSH_PERSIST) as f:
            persisted_total = json.load(f).get("total", 0)
    except Exception:
        pass
    total_now = len(pat.findall(out_all))
    final_total = max(total_now, persisted_total)
    if final_total > persisted_total:
        try:
            os.makedirs(os.path.dirname(ENDLESSH_PERSIST), exist_ok=True)
            with open(ENDLESSH_PERSIST, "w") as f:
                json.dump({"total": final_total, "updated_at": int(time.time())}, f)
        except Exception:
            pass

    return {
        "last24h": len(pat.findall(out24)),
        "total": final_total,
        "avg_duration_s": avg_duration_s,
        "avg_duration_fmt": fmt_duration(avg_duration_s),
        "trap_count": len(durations),
    }

def get_crowdsec() -> dict:
    active_bans = 0
    alerts_24h  = 0

    if CROWDSEC_KEY:
        # Bouncer key → LAPI pour decisions uniquement (pas d'accès /v1/alerts)
        decisions = _lapi("/v1/decisions?limit=50000")
        active_bans = len(decisions) if decisions else 0
    else:
        # Pas de clé → cscli direct (CrowdSec natif, binaire monté)
        out = run(["cscli", "decisions", "list", "-o", "json"], timeout=15)
        try:
            d = json.loads(out)
            active_bans = len(d) if d else 0
        except Exception:
            pass

    # Alerts : toujours cscli direct (bouncer key bloquée par 401 sur /v1/alerts)
    out2 = run(
        ["cscli", "alerts", "list", "--since", "24h", "-o", "json"],
        timeout=15,
    )
    try:
        d2 = json.loads(out2)
        alerts_24h = len(d2) if d2 else 0
    except Exception:
        pass

    return {"active_bans": active_bans, "alerts_24h": alerts_24h}
    
def get_top_countries(limit: int = 5) -> list:
    """Top pays attaquants depuis les décisions CrowdSec actives."""
    out = run(
        ["cscli", "decisions", "list", "--limit", "1000", "-o", "json"],
        timeout=20,
    )
    try:
        decisions = json.loads(out.strip()) or []
        counts: dict[str, int] = {}
        for d in decisions:
            cc = (d.get("country") or "").strip().upper()
            if cc and len(cc) == 2:
                counts[cc] = counts.get(cc, 0) + 1
        if not counts:
            return []
        total = sum(counts.values())
        top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        return [
            {"code": cc, "flag": _flag(cc), "count": n, "pct": round(n / total * 100)}
            for cc, n in top
        ]
    except Exception:
        return []

def get_bouncer_status() -> dict:
    # Priorité 1 : service systemd (source de vérité réelle)
    for cmd in [
        ["systemctl", "is-active", "crowdsec-firewall-bouncer"],
        ["nsenter", "-t", "1", "-m", "--", "systemctl", "is-active", "crowdsec-firewall-bouncer"],
    ]:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if r.stdout.strip() == "active":
                return {"status": "active"}
        except Exception:
            continue
    # Fallback : LAPI
    if CROWDSEC_KEY:
        try:
            req = urllib.request.Request(
                f"{CROWDSEC_URL}/v1/decisions",
                headers={"X-Api-Key": CROWDSEC_KEY},
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                return {"status": "active"}
        except Exception:
            pass
    return {"status": "unknown"}

def get_telegram_status() -> dict:
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
    ALLOWED_SECTIONS = {"pam", "cron", "report", "ssh"}
    if toggle_type not in ALLOWED_SECTIONS:
        return {"ok": False, "error": f"Section non autorisée : {toggle_type}"}
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

    elif toggle_type in ("ssh", "ssh_alert"):
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
        # FIX M-3 — Dernière session uniquement (log cumulatif)
        dates = re.findall(r"Start date is\s+(.+?)\n", content)
        if dates:
            idx = content.rfind(f"Start date is {dates[-1]}")
            if idx != -1:
                content = content[idx:]
        if "Warning:" in content:
            status = "warning"
        elif len(content) > 100:
            status = "clean"
        if dates:
            for _fmt in ("%a %b %d %I:%M:%S %p %Z %Y", "%a %b %d %H:%M:%S %Z %Y"):
                try:
                    dt = datetime.strptime(dates[-1].strip(), _fmt)
                    last_scan = dt.strftime("%d/%m/%Y %H:%M")
                    break
                except Exception:
                    continue
            else:
                last_scan = dates[-1].strip()
    except Exception:
        pass
    return {"status": status, "last_scan": last_scan}

def get_aide() -> dict:
    status    = "unknown"
    last_scan = "Jamais"
    try:
        with open("/var/log/aide-daily.exit") as f:
            exit_code = int(f.read().strip())
        if exit_code == 0:
            status = "clean"
        elif exit_code >= 128:        # Signal système (OOM, kill -9) — pas une alerte réelle
            status = "unknown"
        elif (exit_code & 56) != 0:
            status = "unknown"
        elif (exit_code & 7) != 0:
            if os.path.exists("/var/log/aide-daily.exit.context"):
                status = "rebase"
            else:
                status = "changes"
        else:
            status = "unknown"
    except Exception:
        pass
    try:
        p = Path("/var/log/aide-daily.log")
        if p.exists() and p.stat().st_size > 0:
            last_scan = datetime.fromtimestamp(p.stat().st_mtime).strftime("%d/%m/%Y %H:%M")
    except Exception:
        pass
    return {"status": status, "last_scan": last_scan}

def get_system() -> dict:
    try:
        with open("/proc/uptime") as f:
            sec = float(f.read().split()[0])
        d, h, m = int(sec // 86400), int(sec % 86400 // 3600), int(sec % 3600 // 60)
        uptime_str = (f"{d}j {h}h" if d else f"{h}h {m}m")
    except Exception:
        uptime_str = "---"

    try:
        with open("/proc/loadavg") as f:
            p = f.read().split()
        load = {"1m": p[0], "5m": p[1], "15m": p[2]}
        load["cores"] = os.cpu_count() or 1
    except Exception:
        load = {"1m": "---", "5m": "---", "15m": "---"}

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

    vps_ip = "---"
    try:
        # Cache l'IP 1h — elle ne change pas entre les refreshes de 30s
        global _vps_ip_cache, _vps_ip_cache_time
        if _vps_ip_cache and (time.time() - _vps_ip_cache_time) < 3600:
            vps_ip = _vps_ip_cache
        else:
            with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=5) as resp:
                vps_ip = json.loads(resp.read()).get("ip", "---")
            _vps_ip_cache = vps_ip
            _vps_ip_cache_time = time.time()
    except Exception:
        vps_ip = _vps_ip_cache if _vps_ip_cache else "---"

    return {"uptime": uptime_str, "load": load, "memory": memory, "disk": disk_info, "ip": vps_ip}

def get_ssh_last() -> dict:
    last_ip   = "---"
    last_time = "---"
    for path in ["/var/log/sshd.log", "/var/log/auth.log", "/var/log/secure"]:
        try:
            lines = []
            for candidate in [path + ".1", path]:
                try:
                    with open(candidate, errors="replace") as f:
                        lines += f.readlines()
                except Exception:
                    pass
            if not lines:
                continue
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
                    break  # ligne trouvée → stop boucle interne
            if last_ip != "---":
                break  # résultat trouvé → stop boucle fichiers
        except Exception:
            continue
    return {"ip": last_ip, "time": last_time}

def get_updates() -> dict:
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
    
def _load_expected_ports() -> set:
    """Charge les ports attendus depuis le fichier de config + les ports système de base."""
    BASE = {22, 25, 53, 80, 443, 2222, 5055, 6060, 8081, 9119, 3000, 39783}
    conf_file = "/etc/vps-secure/expected-ports.conf"
    try:
        if os.path.exists(conf_file):
            with open(conf_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        try:
                            BASE.add(int(line))
                        except ValueError:
                            pass
    except Exception:
        pass
    return BASE

def get_open_ports() -> dict:
    EXPECTED = _load_expected_ports()
    # Adresses loopback en little-endian hex (/proc/net/tcp format)
    LOOPBACK = {"0100007F", "00000000000000000000000001000000"}
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
                if parts[3] != "0A":
                    continue
                local = parts[1]
                addr_hex, port_hex = local.split(":")
                port = int(port_hex, 16)
                if port in seen:
                    continue
                seen.add(port)
                ports.append({
                    "port":       port,
                    "process":    "",
                    "expected":   port in EXPECTED,
                    "local_only": addr_hex.upper() in LOOPBACK,
                })
        except Exception:
            pass
    # Alerte uniquement sur les ports inattendus ET exposés (pas localhost-only)
    unexpected = [p for p in ports if not p["expected"] and not p["local_only"]]
    return {
        "ports":      sorted(ports, key=lambda x: x["port"]),
        "unexpected": unexpected,
        "alert":      len(unexpected) > 0,
    }

def get_alerts(period_hours: int = 24) -> list:
    """
    Journal de sécurité — lit depuis l'event log persistant (SSH, UFW,
    CrowdSec, Endlessh, rkhunter) + état système live (Telegram, Ports,
    Bouncer, Disque, RAM, AIDE, MAJ).
    """
    now    = time.time()
    cutoff = now - (period_hours * 3600)

    def fmt_dt(ts: float) -> str:
        return datetime.fromtimestamp(ts).strftime("%d/%m %H:%M")

    # ── 1. Événements historiques (depuis event log persistant) ──────────────
    with _ev_lock:
        historical = [
            {**ev, "datetime": fmt_dt(ev["ts"])}
            for ev in _ev_by_fp.values()
            if ev.get("ts", 0) >= cutoff
        ]

    # ── 2. État système live (toujours calculé en temps réel) ────────────────
    live: list[dict] = []

    # Telegram
    try:
        tg = get_telegram_status()
        if tg.get("configured") and tg.get("report"):
            live.append({
                "service": "Telegram", "ip": "---", "datetime": fmt_dt(now),
                "detail":  "Rapport quotidien actif — notifie chaque matin à 09h00",
                "status":  "reported", "icon": "📢", "label": "Signalée", "ts": now,
            })
        if tg.get("configured") and tg.get("ssh"):
            live.append({
                "service": "Telegram", "ip": "---", "datetime": fmt_dt(now),
                "detail":  "Alerte SSH active — notifie à chaque connexion",
                "status":  "reported", "icon": "📢", "label": "Signalée", "ts": now,
            })
    except Exception:
        pass

    # Bouncer inactif
    try:
        if get_bouncer_status().get("status") != "active":
            live.append({
                "service": "CrowdSec", "ip": "---", "datetime": fmt_dt(now),
                "detail":  "Bouncer inactif — IPs malveillantes plus bannies",
                "status":  "action", "icon": "🔴", "label": "Action requise", "ts": now,
            })
    except Exception:
        pass

    # Ports inattendus
    try:
        for p in get_open_ports().get("unexpected", []):
            live.append({
                "service": "Ports", "ip": "---", "datetime": fmt_dt(now),
                "detail":  f"Port inattendu en écoute : {p['port']}",
                "status":  "action", "icon": "🔴", "label": "Action requise", "ts": now,
            })
    except Exception:
        pass

    # AIDE
    try:
        with open("/var/log/aide-daily.exit") as f:
            exit_code = int(f.read().strip())
        aide_ts = now
        try:
            p = Path("/var/log/aide-daily.log")
            if p.exists():
                aide_ts = p.stat().st_mtime
        except Exception:
            pass
        if aide_ts >= cutoff and (exit_code & 7) != 0:
            has_ctx = os.path.exists("/var/log/aide-daily.exit.context")
            live.append({
                "service": "AIDE", "ip": "---", "datetime": fmt_dt(aide_ts),
                "detail":  "Modifications liées à une MAJ apt — comportement attendu"
                           if has_ctx else "Fichiers système modifiés hors MAJ — vérification requise",
                "status":  "reported" if has_ctx else "action",
                "icon":    "📢"       if has_ctx else "🔴",
                "label":   "Signalée" if has_ctx else "Action requise",
                "ts":      aide_ts,
            })
    except Exception:
        pass

    # Disque
    try:
        du  = shutil.disk_usage(HOSTFS)
        pct = round(du.used / du.total * 100, 1)
        ugb = round(du.used  / 1e9, 1)
        tgb = round(du.total / 1e9, 1)
        if pct > 90:
            live.append({
                "service": "Disque", "ip": "---", "datetime": fmt_dt(now),
                "detail":  f"Espace disque à {pct}% ({ugb}Go / {tgb}Go) — risque crash",
                "status":  "action", "icon": "🔴", "label": "Action requise", "ts": now,
            })
        elif pct > 80:
            live.append({
                "service": "Disque", "ip": "---", "datetime": fmt_dt(now),
                "detail":  f"Espace disque à {pct}% ({ugb}Go / {tgb}Go) — prévoir nettoyage",
                "status":  "detected", "icon": "👁️", "label": "Détectée", "ts": now,
            })
    except Exception:
        pass

    # RAM
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
            live.append({
                "service": "Mémoire", "ip": "---", "datetime": fmt_dt(now),
                "detail":  f"RAM à {pct}% ({used // 1024}Mo / {total // 1024}Mo) — risque crash",
                "status":  "action", "icon": "🔴", "label": "Action requise", "ts": now,
            })
        elif pct > 85:
            live.append({
                "service": "Mémoire", "ip": "---", "datetime": fmt_dt(now),
                "detail":  f"RAM à {pct}% ({used // 1024}Mo / {total // 1024}Mo) — surveiller",
                "status":  "detected", "icon": "👁️", "label": "Détectée", "ts": now,
            })
    except Exception:
        pass

    # MAJ en retard
    try:
        out   = run(["apt", "list", "--upgradable"], timeout=15)
        count = len([l for l in out.splitlines() if "upgradable from" in l])
        if count > 30:
            live.append({
                "service": "Mises à jour", "ip": "---", "datetime": fmt_dt(now),
                "detail":  f"{count} paquets en retard — MAJ manuelle recommandée",
                "status":  "detected", "icon": "👁️", "label": "Détectée", "ts": now,
            })
    except Exception:
        pass

    # ── 3. Merge, géolocalisation, tri ───────────────────────────────────────
    alerts = historical + live

    all_ips = [a.get("ip", "") for a in alerts if a.get("ip") and a["ip"] not in ("---", "")]
    if all_ips:
        _prefetch_geo(all_ips)
        for a in alerts:
            ip = a.get("ip", "")
            if ip and ip != "---":
                tag = _geo_tag(ip)
                if tag:
                    a["ip"] = ip + tag

    ORDER = {"action": 0, "detected": 1, "reported": 2, "neutralized": 3}
    alerts.sort(key=lambda x: (ORDER.get(x.get("status", ""), 9), -x.get("ts", 0)))

    # Nettoyer les champs internes avant envoi
    for a in alerts:
        a.pop("ts",    None)
        a.pop("count", None)

    return alerts[:100]


def get_alerts_cached(period_hours: int = 24) -> list:
    """Cache court (ALERTS_CACHE_TTL) par période — évite les scans répétés."""
    global _alerts_cache, _alerts_cache_time
    now = time.time()
    if (period_hours in _alerts_cache and
            (now - _alerts_cache_time.get(period_hours, 0)) < ALERTS_CACHE_TTL):
        return _alerts_cache[period_hours]
    result                        = get_alerts(period_hours)
    _alerts_cache[period_hours]   = result
    _alerts_cache_time[period_hours] = now
    return result

def get_timeline() -> list:
    """25 derniers evenements securite (SSH, bans CrowdSec, sudo critique, rkhunter)."""
    events = []
    now = time.time()
    cutoff = now - 86400

    ssh_by_ip: dict = {}

    for path in ["/var/log/sshd.log", "/var/log/auth.log", "/var/log/secure"]:
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
                        "title": "Tentative SSH echouee",
                        "detail": m_ip.group(1) if m_ip else "IP inconnue",
                        "_ip":   m_ip.group(1) if m_ip else "",
                        "count": 1,
                    })
        except Exception:
            continue

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
        

    # ── CrowdSec bans ─────────────────────────────────────────────────────────
    try:
        out = run(
            ["docker", "exec", CROWDSEC_CONTAINER, "cscli", "alerts", "list",
             "--since", "24h", "-o", "json"],
            timeout=15,
        )
        raw = out.strip()
        cs_alerts = (json.loads(raw) if raw.startswith("[") else []) or []
        for a in (cs_alerts or []):
            ts = _parse_ts(a.get("created_at", ""))
            if ts < cutoff:
                continue
            src = a.get("source", {})
            ip  = src.get("ip", "IP inconnue")
            reason = a.get("scenario", a.get("reason", "Regle CrowdSec"))
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

    # ── Sudo critiques ────────────────────────────────────────────────────────
    CRITICAL_CMDS = ["useradd", "userdel", "passwd", "chmod 777", "visudo", "crontab", "iptables", "ufw"]
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
                if not any(c in cmd for c in CRITICAL_CMDS):
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

    # ── rkhunter warnings ─────────────────────────────────────────────────────
    try:
        with open("/var/log/rkhunter.log", errors="replace") as f:
            content = f.read()
        # FIX M-3 — Dernière session uniquement
        _rk_dates = re.findall(r"Start date is\s+(.+?)\n", content)
        if _rk_dates:
            _idx = content.rfind(f"Start date is {_rk_dates[-1]}")
            if _idx != -1:
                content = content[_idx:]
        for m in re.finditer(r"Warning:\s+(.+?)(?:\n|$)", content):
            events.append({
                "ts":    now - 3600,
                "type":  "rkhunter",
                "icon":  "🔍",
                "color": "red",
                "title": "rkhunter — warning detecte",
                "detail": m.group(1).strip()[:80],
            })
    except Exception:
        pass

    events.sort(key=lambda x: x["ts"], reverse=True)
    events = events[:25]

    _prefetch_geo([e["_ip"] for e in events if e.get("_ip")])
    for e in events:
        _ip = e.pop("_ip", None)
        if _ip:
            tag = _geo_tag(_ip)
            if tag:
                e["detail"] = (e.get("detail") or "") + tag

    for e in events:
        try:
            e["time"] = datetime.fromtimestamp(e["ts"]).strftime("%H:%M:%S")
            e["date"] = datetime.fromtimestamp(e["ts"]).strftime("%d/%m")
        except Exception:
            e["time"] = "---"
            e["date"] = "---"
            
    # ── UFW blocks summary ────────────────────────────────────────────────────
    try:
        ufw_total = 0
        for log_path in ["/var/log/ufw.log", "/var/log/ufw.log.1"]:
            try:
                with open(log_path, errors="replace") as f:
                    for line in f:
                        if "UFW BLOCK" in line:
                            ufw_total += 1
            except Exception:
                pass
        if ufw_total > 0:
            events.append({
                "ts": now - 60,
                "type": "ufw",
                "icon": "🔥",
                "color": "orange",
                "title": f"UFW — {ufw_total} connexions bloquées",
                "detail": "Pare-feu actif",
            })
    except Exception:
        pass

    # ── Endlessh summary ──────────────────────────────────────────────────────
    try:
        e_data = get_endlessh()
        bot_count = e_data.get("total", 0)
        if bot_count > 0:
            events.append({
                "ts": now - 120,
                "type": "endlessh",
                "icon": "🪤",
                "color": "blue",
                "title": f"Endlessh — {bot_count} bots piégés (total)",
                "detail": f"Durée moy. : {e_data.get('avg_duration_fmt', '---')}",
            })
    except Exception:
        pass

    return events
    
def get_timeline_cached() -> list:
    global _timeline_cache, _timeline_cache_time
    now = time.time()
    if _timeline_cache is not None and (now - _timeline_cache_time) < TIMELINE_CACHE_TTL:
        return _timeline_cache
    _timeline_cache = get_timeline()
    _timeline_cache_time = now
    return _timeline_cache


def get_score(metrics: dict) -> dict:
    score = 100
    issues = []

    bouncer = metrics.get("bouncer", {}).get("status", "unknown")
    if bouncer != "active":
        score -= 30
        issues.append({"sev": "critical", "msg": "Bouncer CrowdSec inactif"})

    rk = metrics.get("rkhunter", {}).get("status", "unknown")
    if rk == "warning":
        score -= 20
        issues.append({"sev": "high", "msg": "rkhunter — anomalie detectee"})
    elif rk == "unknown":
        score -= 5
        issues.append({"sev": "info", "msg": "rkhunter — pas encore execute"})

    ai = metrics.get("aide", {}).get("status", "unknown")
    if ai == "changes":
        score -= 20
        issues.append({"sev": "high", "msg": "AIDE — modifications systeme detectees"})
    elif ai == "unknown":
        score -= 5
        issues.append({"sev": "info", "msg": "AIDE — baseline pas encore scannee"})

    ports = metrics.get("open_ports", {})
    unexpected = ports.get("unexpected", [])
    if unexpected:
        score -= 15 * min(len(unexpected), 2)
        for p in unexpected[:3]:
            issues.append({"sev": "high", "msg": f"Port inattendu ouvert : {p['port']}"})

    upd = metrics.get("updates", {}).get("count", 0)
    if upd > 20:
        score -= 10
        issues.append({"sev": "medium", "msg": f"{upd} mises a jour en attente"})
    elif upd > 0:
        score -= 5
        issues.append({"sev": "info", "msg": f"{upd} mises a jour disponibles"})

    disk_pct = metrics.get("system", {}).get("disk", {}).get("pct", 0)
    if disk_pct > 90:
        score -= 10
        issues.append({"sev": "high", "msg": f"Disque presque plein : {disk_pct}%"})
    elif disk_pct > 80:
        score -= 5
        issues.append({"sev": "medium", "msg": f"Disque a {disk_pct}%"})

    mem_pct = metrics.get("system", {}).get("memory", {}).get("pct", 0)
    if mem_pct > 95:
        score -= 5
        issues.append({"sev": "medium", "msg": f"Memoire critique : {mem_pct}%"})

    score = max(0, min(100, score))

    if score >= 90:
        level, label = "excellent", "Forteresse"
    elif score >= 70:
        level, label = "good", "Bon etat"
    elif score >= 50:
        level, label = "warning", "A surveiller"
    else:
        level, label = "critical", "Action requise"

    return {"score": score, "level": level, "label": label, "issues": issues}


# ── Containers ───────────────────────────────────────────────────────────────
def get_containers() -> list:
    containers_raw = []
    try:
        ps = subprocess.run(
            ['docker', 'ps', '-a', '--format', '{{json .}}'],
            capture_output=True, text=True, timeout=10
        )
        for line in ps.stdout.strip().split('\n'):
            if line.strip():
                try:
                    containers_raw.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        return []

    stats_map = {}
    try:
        st = subprocess.run(
            ['docker', 'stats', '--no-stream', '--format', '{{json .}}'],
            capture_output=True, text=True, timeout=15
        )
        for line in st.stdout.strip().split('\n'):
            if line.strip():
                try:
                    s = json.loads(line)
                    stats_map[s.get('Name', '')] = s
                except Exception:
                    pass
    except Exception:
        pass

    result = []
    for c in containers_raw:
        name   = c.get('Names', '').lstrip('/')
        state  = c.get('State', 'unknown')
        status = c.get('Status', '')
        image  = c.get('Image', '')
        ports  = c.get('Ports', '')

        if state == 'running':
            if   '(healthy)'          in status: health = 'healthy'
            elif '(unhealthy)'        in status: health = 'unhealthy'
            elif '(health: starting)' in status: health = 'starting'
            else:                                health = 'running'
        elif state == 'exited': health = 'stopped'
        elif state == 'paused': health = 'paused'
        else:                   health = state

        image_clean = image.split(':')[0].split('/')[-1]
        s = stats_map.get(name, {})

        result.append({
            'name': name.replace('saaskit-', '', 1),   # strip prefix cosmétique pour le display
            'image':       image,
            'image_clean': image_clean,
            'state':       state,
            'status':      status,
            'health':      health,
            'cpu':         s.get('CPUPerc', '—'),
            'mem':         s.get('MemUsage', '—'),
            'ports':       ports
        })

    return result

def get_containers_cached() -> list:
    global _containers_cache, _containers_cache_time
    now = time.time()
    if _containers_cache is not None and (now - _containers_cache_time) < CONTAINERS_CACHE_TTL:
        return _containers_cache
    _containers_cache = get_containers()
    _containers_cache_time = now
    return _containers_cache

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
            "count":      get_updates()["count"],
            "last_check": get_last_update_date(),
        },
        "connections": get_connections(),
        "open_ports":  get_open_ports(),
        "collected_at": int(time.time()),
    }
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


# ── Container update checks ───────────────────────────────────────────────────
# Maps image_clean name → Docker Hub namespace/repo
# Le tag est détecté dynamiquement depuis le champ image du container.
REGISTRY_MAP = {
    'n8n':      ('n8nio',    'n8n'),
    'baserow':  ('baserow',  'baserow'),
    'caddy':    ('library',  'caddy'),
    'minio':    ('minio',    'minio'),
    'postgres': ('library',  'postgres'),
}

_updates_cache: dict | None = None
_updates_cache_time: float  = 0.0
UPDATES_CACHE_TTL = 3600  # 1 heure

def _hub_remote_digest(namespace: str, repo: str, tag: str) -> str | None:
    """Retourne le manifest list digest depuis l'API registry Docker v2.
    Utilise le header Docker-Content-Digest — identique à ce que docker inspect
    retourne dans RepoDigests. Fonctionne pour tous les tags (latest, 2-alpine, etc.)
    """
    try:
        full_repo = f"library/{repo}" if namespace == 'library' else f"{namespace}/{repo}"

        # 1. Token anonyme pour ce repo
        token_url = (
            f"https://auth.docker.io/token"
            f"?service=registry.docker.io&scope=repository:{full_repo}:pull"
        )
        req = urllib.request.Request(token_url, headers={"User-Agent": "vps-monitor/1.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            token = json.loads(resp.read()).get('token', '')
        if not token:
            return None

        # 2. HEAD sur le manifest — Accept multi-arch en priorité
        manifest_url = f"https://registry-1.docker.io/v2/{full_repo}/manifests/{tag}"
        req2 = urllib.request.Request(manifest_url, headers={
            "User-Agent":    "vps-monitor/1.0",
            "Authorization": f"Bearer {token}",
            "Accept": (
                "application/vnd.docker.distribution.manifest.list.v2+json,"
                "application/vnd.oci.image.index.v1+json,"
                "application/vnd.docker.distribution.manifest.v2+json"
            ),
        })
        req2.get_method = lambda: "HEAD"
        with urllib.request.urlopen(req2, timeout=6) as resp:
            digest = resp.headers.get("Docker-Content-Digest", "")
        return digest or None
    except Exception:
        return None

def _local_image_digest(image_name: str) -> str | None:
    """Retourne le RepoDigest de l'image locale via docker image inspect.
    Prend le nom complet de l'image (ex: caddy:2-alpine, n8nio/n8n:latest).
    """
    try:
        out = subprocess.run(
            ['docker', 'image', 'inspect', image_name,
             '--format', '{{index .RepoDigests 0}}'],
            capture_output=True, text=True, timeout=5
        ).stdout.strip()
        # Format : "caddy@sha256:abc123" → extrait le sha256
        if '@' in out:
            return out.split('@')[1]  # "sha256:abc123"
        return None
    except Exception:
        return None

def get_container_updates() -> dict:
    """
    Retourne { image_clean: status } avec status dans :
      'up_to_date' | 'update_available' | 'unknown'
    Résultat mis en cache 1h — les appels Docker Hub sont externes.
    """
    global _updates_cache, _updates_cache_time
    now = time.time()
    if _updates_cache and (now - _updates_cache_time) < UPDATES_CACHE_TTL:
        return _updates_cache

    # Liste containers actifs pour récupérer les noms et images réels
    containers_raw = []
    try:
        ps = subprocess.run(
            ['docker', 'ps', '--format', '{{json .}}'],
            capture_output=True, text=True, timeout=10
        )
        for line in ps.stdout.strip().split('\n'):
            if line.strip():
                try:
                    containers_raw.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        return {}

    result = {}

    for c in containers_raw:
        name        = c.get('Names', '').lstrip('/')
        image       = c.get('Image', '')           # ex: "caddy:2-alpine" ou "n8nio/n8n:latest"
        image_clean = image.split(':')[0].split('/')[-1]   # ex: "caddy", "n8n"
        # Tag réel utilisé : ce qui est après ':' ou 'latest' par défaut
        image_tag   = image.split(':')[1] if ':' in image else 'latest'

        map_key = next(
            (k for k in REGISTRY_MAP if
             image_clean.lower() == k or image_clean.lower().startswith(k)),
            None
        )
        if not map_key:
            continue  # service non surveillé

        namespace, repo = REGISTRY_MAP[map_key]

        local_digest  = _local_image_digest(image)   # ex: "caddy:2-alpine"
        remote_digest = _hub_remote_digest(namespace, repo, image_tag)

        if not local_digest or not remote_digest:
            result[image_clean] = 'unknown'
        elif local_digest == remote_digest:
            result[image_clean] = 'up_to_date'
        else:
            result[image_clean] = 'update_available'

    _updates_cache      = result
    _updates_cache_time = now
    return result

# ── Geomap ───────────────────────────────────────────────────────────────────
_geomap_cache: dict = {'ts': 0, 'data': None}
_server_coords: dict | None = None


def _get_public_ip() -> str:
    try:
        with urllib.request.urlopen(
            'https://api.ipify.org?format=json', timeout=5
        ) as resp:
            return json.loads(resp.read()).get('ip', '')
    except Exception:
        return ''


def _resolve_server_coords(server_ip: str) -> dict:
    try:
        req = urllib.request.Request(
            f'http://ip-api.com/json/{server_ip}',
            headers={'User-Agent': 'vps-monitor/1.0'},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            d = json.loads(resp.read())
            if d.get('status') == 'success':
                return {'lat': d['lat'], 'lng': d['lon']}
    except Exception:
        pass
    return {'lat': 48.8566, 'lng': 2.3522}


def _get_crowdsec_ips() -> list:
    try:
        out = subprocess.check_output(
            ['docker', 'exec', CROWDSEC_CONTAINER,
             'cscli', 'decisions', 'list', '-o', 'json'],
            stderr=subprocess.DEVNULL, timeout=10,
        )
        decisions = json.loads(out) or []
        ips = []
        for d in decisions:
            val = d.get('value', '')
            ip = val.split(':')[0].split('/')[0]
            if ip:
                ips.append(ip)
        return list(set(ips))
    except Exception:
        return []


def _get_endlessh_ips() -> list:
    try:
        out = subprocess.check_output(
            ['docker', 'logs', ENDLESSH_CONTAINER, '--tail', '500'],
            stderr=subprocess.STDOUT, timeout=10,
        )
        return list(set(re.findall(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b', out.decode('utf-8', 'ignore')
        )))
    except Exception:
        return []


def _geolocate_ips(ips: list) -> list:
    results = []
    try:
        for i in range(0, len(ips), 100):
            batch = [
                {'query': ip, 'fields': 'status,lat,lon,countryCode,query'}
                for ip in ips[i:i + 100]
            ]
            data = json.dumps(batch).encode('utf-8')
            req = urllib.request.Request(
                'http://ip-api.com/batch',
                data=data,
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': 'vps-monitor/1.0',
                },
                method='POST',
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                results.extend(json.loads(resp.read()))
    except Exception:
        pass
    return results


def api_geomap() -> dict:
    global _geomap_cache, _server_coords
    if _geomap_cache['data'] and time.time() - _geomap_cache['ts'] < 300:
        return _geomap_cache['data']
    if not _server_coords:
        server_ip = _get_public_ip()
        _server_coords = _resolve_server_coords(server_ip)
    ips = list(set(_get_crowdsec_ips() + _get_endlessh_ips()))[:200]
    geo_results = _geolocate_ips(ips) if ips else []
    from collections import defaultdict
    groups: dict = defaultdict(
        lambda: {'lat': 0, 'lng': 0, 'count': 0, 'country': ''}
    )
    for g in geo_results:
        if g.get('status') != 'success':
            continue
        key = g['countryCode']
        groups[key]['lat'] = g['lat']
        groups[key]['lng'] = g['lon']
        groups[key]['country'] = g['countryCode']
        groups[key]['count'] += 1
    attackers = sorted(
        groups.values(), key=lambda x: x['count'], reverse=True
    )
    data = {'server': _server_coords, 'attackers': list(attackers)}
    _geomap_cache = {'ts': time.time(), 'data': data}
    return data
    
# ── AIDE Rebase via trigger file systemd (issue #109) ────────────────────────
_rebase_lock = threading.Lock()
_rebase_status = "idle"
_rebase_status_lock = threading.Lock()

def _get_rebase_status() -> dict:
    with _rebase_status_lock:
        return {"status": _rebase_status}

def _set_rebase_status(s: str) -> None:
    global _rebase_status
    with _rebase_status_lock:
        _rebase_status = s

def _run_rebase_bg() -> None:
    """Déclenche le rebase AIDE via trigger file systemd (issue #109).
    Remplace nsenter — container sans privileged: true.
    Prérequis host : vps-aide-trigger.path actif.
    """
    status = "error:init"
    try:
        _set_rebase_status("running")
        AIDE_RESULT.unlink(missing_ok=True)
        AIDE_TRIGGER.touch()          # systemd vps-aide-trigger.path réagit ici
        for _ in range(1200):          # polling max 10 min
            time.sleep(1)
            if AIDE_RESULT.exists():
                try:
                    rc_text = AIDE_RESULT.read_text().strip()
                    rc = int(rc_text) if rc_text.isdigit() else 1
                except Exception:
                    rc = 1
                AIDE_RESULT.unlink(missing_ok=True)
                status = "ok" if rc == 0 else f"error:{rc}"
                break
        else:
            AIDE_TRIGGER.unlink(missing_ok=True)
            status = "timeout"
    except Exception as exc:
        status = f"error:{type(exc).__name__}"
    finally:
        _set_rebase_status(status)
        try:
            _rebase_lock.release()
        except RuntimeError:
            pass


def _send_telegram_api(message: str) -> bool:
    """Envoie une notification Telegram via /etc/vps-secure/telegram.conf."""
    conf_path = f"{HOSTFS}etc/vps-secure/telegram.conf"
    try:
        conf      = Path(conf_path).read_text()
        m_token   = re.search(r'TELEGRAM_TOKEN="([^"]+)"',   conf)
        m_chat_id = re.search(r'TELEGRAM_CHAT_ID="([^"]+)"', conf)
        if not m_token or not m_chat_id:
            return False
        payload = json.dumps({
            "chat_id": m_chat_id.group(1),
            "text":    message,
        }).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{m_token.group(1)}/sendMessage",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10):
            return True
    except Exception:
        return False



# ── HTTP Handler ──────────────────────────────────────────────────────────────

def _aide_diff() -> dict:
    log_path = f"{HOSTFS}var/log/aide-daily.log"
    try:
        with open(log_path, "r", errors="replace") as f2:
            raw = f2.read(2_000_000)
        keep, ins = [], False
        for l in raw.splitlines():
            if any(l.startswith(k) for k in ("Summary","Changed","Added","Removed","---")):
                ins = True
            if ins: keep.append(l)
            if len(keep) > 200: keep.append("... (tronque)"); break
        _added   = re.search(r'Added entries:\s+(\d+)',   raw)
        _removed = re.search(r'Removed entries:\s+(\d+)', raw)
        _changed = re.search(r'Changed entries:\s+(\d+)', raw)
        return {
            "available": True,
            "log":     chr(10).join(keep) if keep else raw[:3000],
            "added":   int(_added.group(1))   if _added   else None,
            "removed": int(_removed.group(1)) if _removed else None,
            "changed": int(_changed.group(1)) if _changed else None,
        }
    except FileNotFoundError:
        return {"available": False, "log": "Log AIDE non trouve",
                "added": None, "removed": None, "changed": None}
    except Exception as e:
        return {"available": False, "log": f"Erreur: {e}",
                "added": None, "removed": None, "changed": None}

ROUTES = {
    "/api/metrics":             lambda: get_metrics(),
    "/api/health":              lambda: {"status": "ok", "ts": int(time.time())},
    "/api/history":             lambda: _history,
    "/api/timeline":            lambda: get_timeline_cached(),
    "/api/telegram/status":     lambda: get_telegram_status(),
    "/api/aide/rebase/status":  lambda: _get_rebase_status(),
    "/api/aide/diff":           _aide_diff,
    "/api/containers":          lambda: get_containers_cached(),
    "/api/containers/updates":  lambda: get_container_updates(),
    "/api/geomap":              api_geomap,
    "/api/top-countries": get_top_countries,
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        ip = _client_ip(self)

        # 1. Rate limiting
        if _is_rate_limited(ip):
            self.send_response(429)
            self.send_header("Retry-After", str(RL_LOCKOUT_SEC))
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b'{"error":"too_many_requests"}')
            return

        # 2. Auth HTTP Basic
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
        parsed     = urlparse(self.path)
        clean_path = parsed.path.rstrip("/")
        params     = parse_qs(parsed.query)

        if clean_path == "/api/alerts":
            period_str   = params.get("period", ["1d"])[0]
            period_map   = {"1d": 24, "7d": 168, "30d": 720}
            period_hours = period_map.get(period_str, 24)
            fn = lambda: get_alerts_cached(period_hours)
        else:
            fn = ROUTES.get(clean_path)

        # ── Envoi de la reponse HTTP ──────────────────────────────────────────
        if fn is None:
            self.send_error(404)
            return
        try:
            result = fn()
            body   = json.dumps(result, ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type",   "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control",  "no-store")
            self.end_headers()
            self.wfile.write(body)
        except Exception as exc:
            self.send_error(500, str(exc))

    def do_POST(self) -> None:
        ip = _client_ip(self)
        # Rate limiting
        if _is_rate_limited(ip):
            self.send_response(429)
            self.send_header("Retry-After", str(RL_LOCKOUT_SEC))
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b'{"error":"too_many_requests"}')
            return
        # Auth Basic
        if DASHBOARD_PASS and not _check_basic_auth(self):
            _record_auth_failure(ip)
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="VPS-SECURE Dashboard"')
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b'{"error":"unauthorized"}')
            return
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
            return
        elif path == "/api/aide/rebase":  # ← AJOUT : route dédiée
            # Lock non-bloquant — 409 si rebase déjà actif
            if not _rebase_lock.acquire(blocking=False):
                resp = json.dumps({"status": "already_running"}).encode()
                self.send_response(409)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)
                return
            # Telegram AVANT le lancement (BLOCKER #2)
            _send_telegram_api(
                f"⚠️ AIDE rebase déclenché depuis le dashboard\n"
                f"🌐 IP source : {ip}\n"
                f"📅 {time.strftime('%d/%m/%Y %H:%M:%S')}\n"
                f"ℹ️  La baseline AIDE va être mise à jour."
            )
            # Thread background (BLOCKER #1 — app.py single-threaded)
            threading.Thread(target=_run_rebase_bg, daemon=True).start()
            resp = json.dumps({"status": "started"}).encode()
            self.send_response(202)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

        else:
            self.send_error(404)

    def log_message(self, fmt: str, *args) -> None:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] {fmt % args}", flush=True)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    _load_history()
    _load_rl_state()
    _ev_load()   # ← AJOUT : charge l'event log persistant

    # Thread collecte événements (premier run immédiat + boucle 5 min)
    threading.Thread(target=_collect_historical_events, daemon=True).start()   # ← AJOUT
    threading.Thread(target=_events_collector_loop, daemon=True).start()       # ← AJOUT

    srv = ThreadingHTTPServer((API_HOST, API_PORT), Handler)
    print(f"[VPS Monitor] API on {API_HOST}:{API_PORT} — cache TTL {CACHE_TTL}s", flush=True)
    srv.serve_forever()

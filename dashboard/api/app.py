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

_cache: dict | None = None
_cache_time: float  = 0.0

# ── Historique en mémoire (24h max) ──────────────────────────────────────────
HISTORY_MAX_SECONDS = 86400  # 24h
_history: list[dict] = []

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
    out24  = run(["docker", "logs", "--since", "24h", ENDLESSH_CONTAINER], timeout=20)
    out_all = run(["docker", "logs", "--tail", "200000", ENDLESSH_CONTAINER], timeout=30)
    pat = re.compile(r"ACCEPT|\"accepted\"", re.IGNORECASE)
    return {
        "last24h": len(pat.findall(out24)),
        "total":   len(pat.findall(out_all)),
    }


def get_crowdsec() -> dict:
    active_bans = 0
    alerts_24h  = 0

    if CROWDSEC_KEY:
        count = _lapi("/v1/decisions?limit=1")
        # CrowdSec retourne X-Total-Count dans le header — non accessible via urllib simplement
        # Alternative : limit élevée
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
        # Fallback: docker exec cscli
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
        elif len(content) > 100:  # optionnel : log non vide = scan effectué
            status = "clean"

        dates = re.findall(r"Start date is\s+(.+?)\n", content)
        if dates:
            last_scan = dates[-1].strip()
    except Exception:
        pass

    return {"status": status, "last_scan": last_scan}


def get_aide() -> dict:
    status    = "unknown"
    last_scan = "Jamais"

    for path in ["/var/log/aide/aide.log", "/var/log/aide.log", "/var/log/aide/check.log"]:
        try:
            p = Path(path)
            if not p.exists() or p.stat().st_size == 0:
                continue
            content = p.read_text(errors="replace")

            if re.search(r"found no differences|0 changed.*0 added.*0 removed|Looks okay|No differences", content, re.IGNORECASE):
                status = "clean"
            elif re.search(r"[1-9]\d* changed|[1-9]\d* added|[1-9]\d* removed|Changed entries:|Added entries:|Removed entries:", content):
                status = "changes"

            last_scan = datetime.fromtimestamp(p.stat().st_mtime).strftime("%d/%m/%Y %H:%M")
            break
        except Exception:
            continue

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
    except Exception:
        load = {"1m": "—", "5m": "—", "15m": "—"}

    # Memory (not namespaced — reflects host)
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
    today_iso = datetime.now().strftime("%Y-%m-%d")

    for path in ["/var/log/auth.log", "/var/log/secure"]:
        try:
            with open(path, errors="replace") as f:
                lines = f.readlines()
            for line in reversed(lines):
                if "Accepted" in line and "sshd" in line:
                    # Format : "...Accepted publickey for vpsadmin from 1.2.3.4 port..."
                    m = re.search(r"from\s+(\S+)\s+port", line)
                    if m:
                        last_ip = m.group(1)
                    # Timestamp ISO
                    m2 = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
                    if m2:
                        try:
                            dt = datetime.fromisoformat(m2.group(1))
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
        # Chaque ligne upgradable se termine par "[upgradable from: ...]"
        count = len([l for l in out.splitlines() if "upgradable from" in l])
    except Exception:
        pass
    return {"count": count}


def get_connections() -> dict:
    """Connexions réseau TCP établies."""
    count = 0
    try:
        out = run(["ss", "-tn", "state", "established"], timeout=5)
        # Première ligne = entête, reste = connexions
        lines = [l for l in out.splitlines() if l and not l.startswith("Recv")]
        count = len(lines)
    except Exception:
        pass
    return {"established": count}


# ── Cache & Aggregator ────────────────────────────────────────────────────────
def collect() -> dict:
    return {
        "endlessh":    get_endlessh(),
        "crowdsec":    get_crowdsec(),
        "ufw":         get_ufw(),
        "auditd":      get_auditd(),
        "rkhunter":    get_rkhunter(),
        "aide":        get_aide(),
        "system":      get_system(),
        "ssh_last":    get_ssh_last(),
        "updates":     get_updates(),
        "connections": get_connections(),
        "collected_at": int(time.time()),
    }


def get_metrics() -> dict:
    global _cache, _cache_time
    now = time.time()
    if _cache and (now - _cache_time) < CACHE_TTL:
        return _cache
    _cache     = collect()
    _cache_time = now
    push_history(_cache)
    return _cache


# ── HTTP Handler ──────────────────────────────────────────────────────────────
ROUTES = {
    "/api/metrics": lambda: get_metrics(),
    "/api/health":  lambda: {"status": "ok", "ts": int(time.time())},
    "/api/history": lambda: _history,
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
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

    def log_message(self, fmt: str, *args) -> None:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] {fmt % args}", flush=True)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    srv = HTTPServer((API_HOST, API_PORT), Handler)
    print(f"[VPS Monitor] API on {API_HOST}:{API_PORT} — cache TTL {CACHE_TTL}s", flush=True)
    srv.serve_forever()

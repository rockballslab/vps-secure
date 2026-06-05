"""
cve_watcher.py — CVE_WATCHER agent (MVP, deterministic, no LLM).

Fetch les CVE depuis les 3 sources critiques (NVD, Ubuntu SN, CISA KEV),
filtre par CPE prefixes du STACK_CANON, dédoublonne, normalise.

Output: dict conforme au schéma v1.0 (cf. CVE_WATCHER.md)
"""

import json
import os
import re
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import defusedxml.ElementTree as ET

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

from canon_parser import parse_canon


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_KEY = os.environ.get("NVD_API_KEY")  # optionnel mais recommandé
UBUNTU_RSS = "https://ubuntu.com/security/notices/rss.xml"
CISA_KEV_PRIMARY = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# Mirror GitHub (cisagov/kev-data) — fonctionne quand cisa.gov est bloqué par Cloudflare.
# Testé 2026-06-05: 1611 entries, données identiques à la primary.
CISA_KEV_MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"

# Mots-clés de filtrage Ubuntu SN RSS
UBUNTU_KEYWORDS = [
    "kernel", "openssh", "ufw", "auditd", "rkhunter", "aide",
    "rsyslog", "unattended-upgrades", "apparmor", "libpam", "debsums",
    "unhide", "acct", "sysstat", "docker.io", "containerd",
]

DEFAULT_WINDOW_HOURS = 24


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
def _http_get(url: str, params: dict | None = None, headers: dict | None = None, timeout: int = 30) -> dict | str:
    r = requests.get(url, params=params, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.json() if "json" in r.headers.get("Content-Type", "") else r.text


def _fetch_nvd(cpe_prefixes: list[str], start: str, end: str) -> tuple[list[dict], str | None]:
    """Fetch NVD pour chaque CPE prefix du canon. Retourne (cves, error).

    Stratégie: extrait `vendor:product` de chaque CPE et utilise keywordSearch.
    Plus fiable que cpeName/cpeMatchString (qui exigent des CPE complets en v2.0).
    """
    headers = {"User-Agent": "vps-secure-agents/1.0 (security)"}
    if NVD_KEY:
        headers["apiKey"] = NVD_KEY

    # Dédup les vendor:product pour éviter des requêtes dupliquées
    keywords = set()
    for cpe in cpe_prefixes:
        parts = cpe.split(":")
        if len(parts) >= 5:
            vendor, product = parts[3], parts[4]
            if vendor and product:
                keywords.add(f"{vendor} {product}")

    all_cves: list[dict] = []
    last_error: str | None = None
    for kw in keywords:
        try:
            data = _http_get(NVD_API, params={
                "keywordSearch": kw,
                "lastModStartDate": start,
                "lastModEndDate": end,
                "resultsPerPage": 50,
            }, headers=headers)
            for v in data.get("vulnerabilities", []):
                cve = v.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id:
                    continue
                metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])
                cvss = metrics[0].get("cvssData", {}) if metrics else {}
                all_cves.append({
                    "cve_id": cve_id,
                    "published": cve.get("published"),
                    "last_modified": cve.get("lastModified"),
                    "cvss_v3": {
                        "base_score": cvss.get("baseScore"),
                        "vector": cvss.get("vectorString"),
                    } if cvss else None,
                    "description_en": next(
                        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                        ""
                    ),
                    "cpe_list": [
                        c.get("criteria", "")
                        for config in cve.get("configurations", [])
                        for node in config.get("nodes", [])
                        for c in node.get("cpeMatch", [])
                    ],
                    "configurations": cve.get("configurations", []),  # full block for version range check
                    "refs": [{"url": r["url"], "type": "external"} for r in cve.get("references", [])[:5]],
                    "source": "nvd",
                    "matched_keyword": kw,
                })
        except Exception as e:
            last_error = f"nvd_error: {e}"
            continue
    return all_cves, last_error


def _fetch_ubuntu_rss(start: datetime) -> tuple[list[dict], str | None]:
    """Parse ubuntu.com/security/notices/rss.xml et filtre par mots-clés."""
    try:
        text = _http_get(UBUNTU_RSS)
        root = ET.fromstring(text)
        items = []
        for item in root.findall(".//item"):
            title = item.findtext("title", "")
            desc = item.findtext("description", "")
            link = item.findtext("link", "")
            pub = item.findtext("pubDate", "")
            # Filtre mots-clés
            if not any(kw in (title + desc).lower() for kw in UBUNTU_KEYWORDS):
                continue
            # Filtre date
            try:
                pub_dt = datetime.strptime(pub, "%a, %d %b %Y %H:%M:%S %z").astimezone(timezone.utc)
                if pub_dt < start:
                    continue
            except ValueError:
                pass
            # Extraire USN ID du titre (ex: "USN-6789-1: openssh-server vulnerability")
            usn_match = re.search(r"USN-\d+-\d+", title)
            usn_id = usn_match.group(0) if usn_match else None
            items.append({
                "cve_id": usn_id or f"USN-{link.split('/')[-1]}",
                "usn_id": usn_id,
                "published": pub,
                "description_en": desc[:500],
                "refs": [{"url": link, "type": "advisory"}],
                "source": "ubuntu-sn",
            })
        return items, None
    except Exception as e:
        return [], f"ubuntu-sn_error: {e}"


def _fetch_cisa_kev() -> tuple[set[str], str | None]:
    """Retourne l'ensemble des CVE IDs actuellement dans CISA KEV (cross-ref).

    Stratégie: tente la primary URL, fallback sur le mirror GitHub.
    Données identiques (les deux sont tenues par CISA/cisagov).

    Returns:
        (set_cve_ids, error_or_none)
        error_or_none: None si OK, sinon str décrivant l'échec.
    """
    headers = {"User-Agent": "vps-secure-agents/1.0 (security)"}
    for url, label in [(CISA_KEV_PRIMARY, "cisa-kev-primary"), (CISA_KEV_MIRROR, "cisa-kev-mirror")]:
        try:
            data = _http_get(url, headers=headers)
            # GitHub raw mirror retourne Content-Type: text/plain — _http_get renvoie str.
            # CISA primary retourne application/json — _http_get renvoie dict.
            if isinstance(data, str):
                data = json.loads(data)
            ids = {v["cveID"] for v in data.get("vulnerabilities", [])}
            return ids, None
        except Exception as e:
            # Continue au mirror
            continue
    return set(), "cisa-kev_error: primary ET mirror ont tous deux échoué"


def _dedup(cves: list[dict]) -> list[dict]:
    """Dédup par cve_id, merge sources si multi-source."""
    by_id: dict[str, dict] = {}
    for c in cves:
        cid = c["cve_id"]
        if cid not in by_id:
            by_id[cid] = c
        else:
            by_id[cid].setdefault("sources", [by_id[cid].get("source")])
            if c.get("source") not in by_id[cid]["sources"]:
                by_id[cid]["sources"].append(c["source"])
    return list(by_id.values())


def collect(canon_path: Path, window_hours: int = DEFAULT_WINDOW_HOURS) -> dict[str, Any]:
    """Collecte les CVE des 3 sources critiques sur la fenêtre temporelle."""
    canon = parse_canon(canon_path)
    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(hours=window_hours)
    start_iso = start_dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    end_iso = end_dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    sources_fetched: list[str] = []
    sources_failed: list[str] = []
    raw_cves: list[dict] = []

    # 1) NVD
    nvd_cves, nvd_err = _fetch_nvd(canon["cpe_prefixes"], start_iso, end_iso)
    raw_cves.extend(nvd_cves)
    if nvd_err:
        sources_failed.append("nvd")
    else:
        sources_fetched.append("nvd")

    # 2) Ubuntu SN
    time.sleep(1)  # rate-limit polite
    usn_cves, usn_err = _fetch_ubuntu_rss(start_dt)
    raw_cves.extend(usn_cves)
    if usn_err:
        sources_failed.append("ubuntu-sn")
    else:
        sources_fetched.append("ubuntu-sn")

    # 3) CISA KEV (cross-ref only, pour marquer `kev_listed`)
    kev_set, kev_err = _fetch_cisa_kev()
    if kev_err:
        sources_failed.append("cisa-kev")
    else:
        sources_fetched.append("cisa-kev")
    for c in raw_cves:
        c["kev_listed"] = c.get("cve_id", "").upper() in {k.upper() for k in kev_set}
        c["fetched_at"] = _now()

    # 4) Dédup
    deduped = _dedup(raw_cves)

    # 5) Pré-filtrage: pas de CPE match ou CVSS < 4.0 → drop
    filtered = []
    for c in deduped:
        if c.get("cvss_v3") and c["cvss_v3"].get("base_score") is not None and c["cvss_v3"]["base_score"] < 4.0:
            continue
        filtered.append(c)

    return {
        "schema_version": "1.0",
        "fetch_window": {"start": start_iso, "end": end_iso, "hours": window_hours},
        "sources_fetched": sources_fetched,
        "sources_failed": sources_failed,
        "cves_total_raw": len(raw_cves),
        "cves_after_dedup": len(deduped),
        "cves_after_prefilter": len(filtered),
        "cves": filtered,
    }


if __name__ == "__main__":
    canon_path = Path(__file__).parent.parent / "canon" / "STACK_CANON.md"
    result = collect(canon_path, window_hours=24)
    print(json.dumps({
        "fetch_window": result["fetch_window"],
        "sources": {"fetched": result["sources_fetched"], "failed": result["sources_failed"]},
        "counts": {
            "raw": result["cves_total_raw"],
            "dedup": result["cves_after_dedup"],
            "after_prefilter": result["cves_after_prefilter"],
        },
        "first_5_cves": result["cves"][:5],
    }, indent=2, ensure_ascii=False))

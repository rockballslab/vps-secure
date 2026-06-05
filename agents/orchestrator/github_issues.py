"""
github_issues.py — création d'issues GitHub via le CLI `gh` (auth déjà gérée).

Avantage vs API REST: pas de token à gérer dans ce projet.
On délègue tout à `gh` (déjà authentifié via `gh auth login`).

Usage:
    from github_issues import create_issue_for_cve
    result = create_issue_for_cve(verdict, inventory_match, repo="rockballslab/vps-secure")
    # → {"url": "https://github.com/.../issues/123", "number": 123, "ok": True}
    # ou {"ok": False, "error": "..."}
"""

import json
import subprocess
import shutil
from typing import Any
from datetime import datetime, timezone


def _gh_available() -> bool:
    """Vérifie que le CLI `gh` est installé et auth."""
    if not shutil.which("gh"):
        return False
    try:
        r = subprocess.run(
            ["gh", "auth", "status"],
            capture_output=True, text=True, timeout=10
        )
        return r.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _nvd_url(cve_id: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def _ghsa_url(cve_id: str) -> str:
    # GHSA est lié par GHSA-ID, pas par CVE-ID. On tente le search public.
    return f"https://github.com/advisories?query={cve_id}"


def build_issue_payload(verdict: dict, inv_match: dict | None = None) -> dict[str, str]:
    """
    Construit title + body d'une issue GitHub pour une CVE.

    Args:
        verdict: dict avec cve_id, rationale, impact_class, kev_listed, matched_components, etc.
        inv_match: dict optionnel avec component_name, installed_version, match_reason

    Returns: {"title": "...", "body": "...", "labels": "..."}
    """
    cve_id = verdict["cve_id"]
    inv_match = inv_match or (verdict.get("matched_components", [{}]) or [{}])[0]

    component = inv_match.get("component_name", "?")
    version = inv_match.get("installed_version", "?")
    match_reason = inv_match.get("match_reason", "?")

    # Title court et exploitable (GH truncate après ~256 chars dans les listes)
    title = f"[vps-secure] {cve_id}: {component} v{version}"

    # Body structuré pour faciliter le triage
    body_lines = [
        f"## {cve_id}",
        "",
        f"- **Component**: `{component}` v{version}",
        f"- **Match reason**: {match_reason}",
        f"- **Impact class**: `{verdict.get('impact_class', '?')}`",
        f"- **CISA KEV listed**: {'YES ⚠️' if verdict.get('kev_listed') else 'no'}",
        f"- **Auto-detected by**: vps-secure-agents daily run @ {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        "",
        "### Rationale",
        "",
        verdict.get("rationale", "_no rationale available_"),
        "",
        "### Links",
        "",
        f"- NVD: {_nvd_url(cve_id)}",
        f"- GHSA search: {_ghsa_url(cve_id)}",
        f"- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "",
        "---",
        "_Created by vps-secure-agents via `ack` Telegram button._",
    ]
    body = "\n".join(body_lines)

    # Labels: au moins "security" + classe d'impact
    labels = ["security", "cve", f"impact:{verdict.get('impact_class', 'unknown')}"]
    if verdict.get("kev_listed"):
        labels.append("kev")

    return {"title": title, "body": body, "labels": ",".join(labels)}


def create_issue_for_cve(
    verdict: dict,
    repo: str,
    inv_match: dict | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Crée une GitHub issue pour le verdict donné.

    Args:
        verdict: dict IMPACT_ASSESSOR
        repo: "owner/repo" (ex. "rockballslab/vps-secure")
        inv_match: matched component optionnel
        dry_run: si True, n'exécute PAS gh, retourne juste le payload

    Returns:
        {"ok": True, "url": "...", "number": N} en cas de succès
        {"ok": False, "error": "...", "payload": {...}} en cas d'échec
    """
    payload = build_issue_payload(verdict, inv_match)

    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "url": f"https://github.com/{repo}/issues/DRY-RUN",
            "number": -1,
            "payload": payload,
        }

    if not _gh_available():
        return {
            "ok": False,
            "error": "gh CLI not installed or not authenticated",
            "payload": payload,
        }

    cmd = [
        "gh", "issue", "create",
        "--repo", repo,
        "--title", payload["title"],
        "--body", payload["body"],
        "--label", payload["labels"],
    ]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return {
                "ok": False,
                "error": f"gh issue create failed: {r.stderr.strip()}",
                "stdout": r.stdout.strip(),
                "payload": payload,
            }
        # gh output: "https://github.com/owner/repo/issues/NNN"
        url = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
        if "/issues/" not in url:
            return {
                "ok": False,
                "error": f"gh issue create: no issue URL in output: {r.stdout!r}",
                "payload": payload,
            }
        try:
            number = int(url.rsplit("/", 1)[-1])
        except (ValueError, IndexError):
            number = 0
        return {"ok": True, "url": url, "number": number, "payload": payload}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "gh issue create timed out", "payload": payload}
    except OSError as e:
        return {"ok": False, "error": f"gh exec failed: {e}", "payload": payload}


def find_existing_issue(cve_id: str, repo: str) -> dict[str, Any] | None:
    """
    Cherche si une issue existe déjà pour ce CVE (via search).
    Retourne {"url": ..., "number": ...} ou None.
    """
    if not _gh_available():
        return None
    try:
        r = subprocess.run(
            [
                "gh", "issue", "list",
                "--repo", repo,
                "--search", f"{cve_id} in:title",
                "--state", "all",
                "--json", "number,url,title",
                "--limit", "5",
            ],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode != 0:
            return None
        issues = json.loads(r.stdout) if r.stdout.strip() else []
        # Match exact sur le titre (gh search est permissif)
        for issue in issues:
            if cve_id in issue.get("title", ""):
                return {"url": issue["url"], "number": issue["number"]}
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return None
    return None

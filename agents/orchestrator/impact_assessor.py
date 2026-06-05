"""
impact_assessor.py — IMPACT_ASSESSOR agent (MVP, rule-based, no LLM).

Pour chaque CVE brute du CVE_WATCHER, détermine si elle touche la stack
installée et calcule un impact_score (0-10) basé sur la table du .md.

Logique:
  - Match CPE (simplified: match par mot-clé dans description)
  - Calcul A×B×C×D comme dans le .md
  - Output: verdict structuré

Mode LLM: optionnel, activé si env LLM_MODEL est défini. Le LLM reçoit le
.md comme system prompt + la CVE brute + l'inventaire, et retourne le verdict.
Pour le MVP, on reste en mode rule-based (déterministe, cheap, fast).
"""

import re
import subprocess
from pathlib import Path
from typing import Any

from packaging.version import Version, InvalidVersion
from canon_parser import parse_canon


def _normalize_debian_version(v: str) -> str:
    """Normalise une version Debian/Ubuntu pour comparaison.

    Strip:
      - epoch: "1:foo" → "foo"
      - "v" prefix (Go semver style): "v2.0.0" → "2.0.0"

    NE strip PAS la debian revision (kernel en a besoin).

    Pourquoi strip le "v":
      - CVE descriptions utilisent souvent "v2.0.0" (Go/Moby upstream)
      - dpkg traite "v" comme un char alphabétique (sort avant les digits)
      - "v2.0.0" devient ainsi < "29.5.3" pour dpkg (v < 2 < 29)
      - Faux positif: on dirait que 29.5.3 est vulnérable à "v2.0.0"
      - Après strip: "2.0.0" → 2.0.0 < 29.5.3 → pas vulnérable

    Returns: version normalisée
    Retourne "" si input None ou empty.
    """
    if not v:
        return ""
    # Strip "v" prefix (Go semver)
    if v.startswith("v") and len(v) > 1 and (v[1].isdigit() or v[1] == "."):
        v = v[1:]
    # Strip epoch (digits:)
    if ":" in v:
        v = v.split(":", 1)[1]
    return v


def _dpkg_compare(v1: str, op: str, v2: str) -> bool:
    """Compare deux versions Debian/Ubuntu via dpkg APRÈS normalisation upstream.

    Les epochs Debian (1:, 2:...) et revisions (-1ubuntu2) sont strippées des deux côtés
    pour comparer uniquement la version upstream (29.5.3 vs 29.5.1).

    Op: 'lt' | 'le' | 'eq' | 'ne' | 'ge' | 'gt'
    Returns: True si la comparaison est vraie.
    """
    n1 = _normalize_debian_version(v1)
    n2 = _normalize_debian_version(v2)
    try:
        r = subprocess.run(
            ["dpkg", "--compare-versions", n1, op, n2],
            capture_output=True, timeout=5
        )
        return r.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        # Fallback sur packaging.Version
        try:
            c1, c2 = Version(n1), Version(n2)
            return {"lt": c1 < c2, "le": c1 <= c2, "eq": c1 == c2,
                    "ne": c1 != c2, "ge": c1 >= c2, "gt": c1 > c2}.get(op, False)
        except InvalidVersion:
            return False


# Table de criticité composant (synchronisée avec IMPACT_ASSESSOR.md)
COMPONENT_CRITICALITY = {
    "ubuntu-os": 3,
    "openssh-server": 3,
    "docker-ce": 3,
    "crowdsec": 3,
    "ufw": 3,
    "auditd": 2,
    "aide": 2,
    "rsyslog": 2,
    "rkhunter": 2,
    "unattended-upgrades": 2,
    "libpam-pwquality": 2,
    "apparmor": 2,
    "debsums": 1,
    "unhide": 1,
    "acct": 1,
    "sysstat": 1,
    "endlessh-go": 1,
    "vps-secure-bot-funnel": 1,
    "caddy": 1,
    "vps-monitor-metrics-api": 1,
}

# Mapping composant → mots-clés (regex word-boundary) pour matching précis
# Format: list de patterns regex compilés.
# Les patterns utilisent \b pour word boundary — évite "ssh " de matcher "sshKey"
COMPONENT_KEYWORDS = {
    "openssh-server": [r"\bopenssh\b", r"\bsshd\b", r"\bopenssh-server\b", r"\bopen ssh\b"],
    "ubuntu-os": [r"\bubuntu\b", r"\blinux kernel\b", r"\bglibc\b", r"\blibc6\b", r"\bsystemd\b"],
    "docker-ce": [r"\bdocker engine\b", r"\bdocker-ce\b", r"\bdockerd\b", r"\bmoby\b", r"\bcontainerd\b", r"\brunc\b"],
    "crowdsec": [r"\bcrowdsec\b"],
    "ufw": [r"\bufw\b", r"\buncomplicated firewall\b"],
    "auditd": [r"\bauditd\b", r"\blinux audit\b", r"\baudit daemon\b"],
    "aide": [r"\baide\b", r"\badvanced intrusion detection\b"],
    "rsyslog": [r"\brsyslog\b"],
    "rkhunter": [r"\brkhunter\b", r"\brootkit hunter\b"],
    "unattended-upgrades": [r"\bunattended-upgrades\b", r"\bunattended upgrade\b"],
    "apparmor": [r"\bapparmor\b"],
    "caddy": [r"\bcaddy\b", r"\bcaddyserver\b"],
    "endlessh-go": [r"\bendlessh\b"],
    "libpam-pwquality": [r"\bpam_pwquality\b", r"\bpwquality\b", r"\blibpam-pwquality\b"],
    "debsums": [r"\bdebsums\b"],
    "unhide": [r"\bunhide\b"],
    "acct": [r"\bprocess accounting\b", r"\bacct\b"],
    "sysstat": [r"\bsysstat\b"],
}


def _match_components(cve: dict, installed_components: list[dict]) -> list[dict]:
    """Match une CVE contre les composants installés.

    Logique en 3 phases:
      1. Match grossier par mot-clé dans la description OU CPE prefix dans cpe_list
      2. Pour chaque match potentiel, **comparaison de version** vs affected_range NVD
      3. Si la version installée est HORS de la plage affectée → drop (faux positif)

    Le check de version est CRITIQUE: il évite de notifier des CVE sur des
    composants déjà patchés (ex: docker-ce 29.5.3 alors que CVE affecte < 29.5.1).
    """
    desc = (cve.get("description_en") or "").lower()
    cpe_list = [c.lower() for c in cve.get("cpe_list", [])]

    matches = []
    for comp in installed_components:
        cid = comp["component_id"]
        # Phase 1: match par mot-clé description (regex word-boundary)
        kw_patterns = COMPONENT_KEYWORDS.get(cid, [])
        kw_match = any(re.search(pat, desc) for pat in kw_patterns)
        # Match par CPE (préfixe du composant présent dans cpe_list)
        cpe_prefix = (comp.get("cpe_prefix") or "").lower()
        cpe_match = bool(cpe_prefix) and any(cpe_prefix in c for c in cpe_list)

        if not (kw_match or cpe_match):
            continue

        # Phase 2: comparaison de version vs affected_range NVD
        installed_version = comp.get("version", "unknown")
        affected = _extract_affected_ranges(cve)
        if affected:
            in_range, range_detail = _version_in_ranges(installed_version, affected, cpe_prefix)
            if not in_range:
                # Faux positif: la version installée est hors plage affectée
                continue
            match_reason = f"keyword+version_in_range" if kw_match else "cpe+version_in_range"
            version_check = {"in_range": True, "detail": range_detail, "affected_ranges": affected}
        else:
            # Pas de CPE config dans la CVE (cas Ubuntu SN, USN) — on match par keyword seulement
            # et on n'a pas de version range. Match accepté mais avec note.
            match_reason = "keyword_only" if kw_match else "cpe_only"
            version_check = {"in_range": None, "detail": "no version range in CVE (USN/keyed)", "affected_ranges": []}

        matches.append({
            "component_id": cid,
            "component_name": comp.get("name", cid),
            "installed_version": installed_version,
            "match_reason": match_reason,
            "version_check": version_check,
        })
    return matches


def _extract_affected_ranges(cve: dict) -> list[dict]:
    """Extrait les plages de versions affectées depuis la structure NVD configurations.

    NVD format:
      configurations[].nodes[].cpeMatch[]:
        - criteria: CPE 2.3 complet
        - versionStartIncluding/Excluding
        - versionEndIncluding/Excluding
    Retourne: [{"cpe_prefix": str, "start": str|None, "end": str|None,
                 "end_inclusive": bool, "start_inclusive": bool}, ...]
    """
    ranges = []
    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                criteria = match.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) < 6:
                    continue
                # parts[5] = version field. "*" = toutes versions
                if parts[5] == "*" and not (match.get("versionStartIncluding") or match.get("versionStartExcluding")
                                            or match.get("versionEndIncluding") or match.get("versionEndExcluding")):
                    # Pas de range explicite + version wildcard → skip (trop générique)
                    continue
                prefix = ":".join(parts[:5])  # cpe:2.3:a:vendor:product
                ranges.append({
                    "cpe_prefix": prefix.lower(),
                    "start": match.get("versionStartIncluding") or match.get("versionStartExcluding"),
                    "end": match.get("versionEndIncluding") or match.get("versionEndExcluding"),
                    "end_inclusive": "versionEndIncluding" in match,
                    "start_inclusive": "versionStartIncluding" in match,
                })

    # Fallback: parser la description pour hints de version si pas de CPE config
    # Patterns courants: "prior to 29.5.1", "before X.Y.Z", "versions < X", "below X"
    if not ranges:
        desc_ranges = _parse_description_version_ranges(cve.get("description_en", ""))
        if desc_ranges:
            # Attache un cpe_prefix générique — le filtre par cpe_prefix dans _version_in_ranges
            # matchera si le composant a un cpe_prefix
            ranges.extend(desc_ranges)

    return ranges


def _parse_description_version_ranges(description: str) -> list[dict]:
    """Parse la description CVE pour des hints de version.

    Patterns gérés:
      - "prior to X.Y.Z" / "before X.Y.Z" → end=X.Y.Z, end_inclusive=False
      - "versions prior to and including X.Y.Z" → end=X.Y.Z, end_inclusive=True
      - "from X.Y to Y.Z" → start=X.Y, end=Y.Z (inclusif des deux côtés)
      - "< X.Y.Z" → end=X.Y.Z, end_inclusive=False
      - "<= X.Y.Z" → end=X.Y.Z, end_inclusive=True
      - "affected: X.Y.Z" → end=X.Y.Z, end_inclusive=True

    Retourne: [{"cpe_prefix": "*", "start": ..., "end": ..., ...}, ...]
    """
    if not description:
        return []
    desc = description.lower()
    ranges = []
    wildcard_prefix = {"cpe_prefix": "*", "start_inclusive": True, "end_inclusive": False}

    # Pattern: "prior to X.Y.Z" / "before X.Y.Z" → end=version, exclusive
    # Le terminator exclut "." (qui est valide DANS une version: 29.5.1)
    for m in re.finditer(r"\b(?:prior to|before|earlier than|below)\s+(v?[\w.:+-]+?)(?=\s|,|;|\)|$)", desc):
        ver = m.group(1).rstrip(".,;)")
        if _looks_like_version(ver):
            ranges.append({**wildcard_prefix, "start": None, "end": ver})

    # Pattern: "versions prior to and including X.Y.Z" → end=version, inclusive
    for m in re.finditer(r"\b(?:prior to and including|through|up to and including)\s+(v?[\w.:+-]+?)(?=\s|,|;|\)|$)", desc):
        ver = m.group(1).rstrip(".,;)")
        if _looks_like_version(ver):
            ranges.append({**wildcard_prefix, "start": None, "end": ver, "end_inclusive": True})

    # Pattern: "from X.Y to Y.Z" ou ">= X.Y, < Y.Z" → start et end
    for m in re.finditer(r"\b(?:from|since)\s+(v?[\w.:+-]+?)\s+(?:to|through|until)\s+(v?[\w.:+-]+?)(?=\s|,|;|\)|$)", desc):
        start_v, end_v = m.group(1).rstrip(".,;):"), m.group(2).rstrip(".,;):")
        if _looks_like_version(start_v) and _looks_like_version(end_v):
            ranges.append({**wildcard_prefix, "start": start_v, "end": end_v, "end_inclusive": True})

    return ranges


def _looks_like_version(s: str) -> bool:
    """Heuristique cheap: ça ressemble à un numéro de version?

    Accepte: "1.0", "29.5.1", "9.6p1", "1.2.3-rc1", "1.2.3+build5", "6.8.0-60.63"
    Rejette: "the", "abc", "1" seul (trop court), strings > 20 chars
    """
    if not s or len(s) > 20:
        return False
    # Doit commencer par un digit (optionnellement préfixé par 'v')
    # Puis zéro ou plus: séparateur (. : - +) + word chars
    if re.match(r"^v?\d+([.:\-+][\w]+)*$", s):
        return True
    # Nombre pur (rare mais OK pour "1" ou "2024")
    if re.match(r"^\d+$", s):
        return True
    return False


def _version_in_ranges(version_str: str, ranges: list[dict], cpe_prefix: str) -> tuple[bool, str]:
    """Vérifie si version_str est dans l'une des plages affectées (filtrées par cpe_prefix).

    Returns: (in_range, detail_str)
    """
    if not version_str or version_str == "unknown":
        return False, "installed version unknown, skipping match"

    # Filtrer les ranges par cpe_prefix (substring match, ou wildcard "*")
    relevant = []
    for r in ranges:
        r_prefix = r.get("cpe_prefix", "")
        if r_prefix == "*" or not cpe_prefix:
            # Wildcard range → applicable à tous les composants
            relevant.append(r)
        elif r_prefix and (cpe_prefix in r_prefix or r_prefix in cpe_prefix):
            relevant.append(r)
    if not relevant:
        # Pas de range applicable → on accepte le match par défaut (cas incertain)
        return True, "no applicable version range for this CPE in CVE (assumed vulnerable)"

    # Sanity check: la version installée doit être parseable (sinon on skip)
    if not _normalize_debian_version(version_str):
        return False, f"cannot parse installed version '{version_str}'"

    for r in relevant:
        # Construire la borne et check via dpkg (gère epoch, ~, +, p1, ubuntu, etc.)
        start_v, end_v = r.get("start"), r.get("end")
        if not start_v and not end_v:
            # Range vide = toutes versions affectées
            detail = f"installed {version_str}: all versions affected (no range)"
            return True, detail

        in_range = True
        if start_v and start_v != "*":
            if r["start_inclusive"]:
                if not _dpkg_compare(version_str, "ge", start_v):
                    in_range = False
            else:
                if not _dpkg_compare(version_str, "gt", start_v):
                    in_range = False
        if end_v and end_v != "*" and in_range:
            if r["end_inclusive"]:
                if not _dpkg_compare(version_str, "le", end_v):
                    in_range = False
            else:
                if not _dpkg_compare(version_str, "lt", end_v):
                    in_range = False

        if in_range:
            detail = f"installed {version_str} in range [{start_v or '*'}, {end_v or '*'}]"
            return True, detail

    detail = f"installed {version_str} NOT in any range: " + ", ".join(
        f"[{r.get('start') or '*'}, {r.get('end') or '*'}]" for r in relevant
    )
    return False, detail


def _calc_exposure(component_id: str, listening_ports: list[dict]) -> tuple[int, dict]:
    """Facteur B (exposition réseau) — table hardcodée des bind addresses."""
    # Table des composants avec port par défaut
    PORT_TABLE = {
        "openssh-server": (2222, "0.0.0.0"),
        "endlessh-go": (22, "0.0.0.0"),
        "caddy": (443, "0.0.0.0"),
        "crowdsec": (8080, "127.0.0.1"),  # LAPI
    }
    default_port, default_bind = PORT_TABLE.get(component_id, (None, "127.0.0.1"))
    # Vérifier ss
    for p in listening_ports:
        if default_port and str(default_port) in p.get("local_address", ""):
            bind = p["local_address"].rsplit(":", 1)[0]
            if bind in ("0.0.0.0", "::"):
                return 3, {"port": default_port, "bind": bind, "process": p.get("process"), "internet_reachable": True}
            elif bind.startswith("127."):
                return 1, {"port": default_port, "bind": bind, "process": p.get("process"), "internet_reachable": False}
    # Pas trouvé dans ss → utiliser default
    if default_bind in ("0.0.0.0", "::"):
        return 3, {"port": default_port, "bind": default_bind, "process": None, "internet_reachable": True}
    return 1, {"port": default_port, "bind": default_bind or "n/a", "process": None, "internet_reachable": False}


def _calc_vuln_type(cve: dict) -> float:
    """Facteur C (type de vuln) — basé sur le vector CVSS v3."""
    vector = (cve.get("cvss_v3") or {}).get("vector", "")
    if not vector:
        return 1.0  # défaut
    # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = RCE sans auth
    if "PR:N" in vector and "UI:N" in vector and "C:H" in vector and "I:H" in vector and "A:H" in vector:
        return 2.0
    if "AV:L" in vector and ("C:H" in vector or "I:H" in vector):  # LPE
        return 1.5
    if "AV:N" in vector and ("C:H" in vector or "I:H" in vector):  # RCE auth
        return 1.5
    if "C:H" in vector or "I:H" in vector:
        return 1.0
    return 0.5


def _calc_cvss_intrinsic(cve: dict) -> float:
    """Facteur D (CVSS intrinsèque)."""
    score = (cve.get("cvss_v3") or {}).get("base_score")
    if score is None:
        return 0.5
    if score >= 9.0:
        return 2.0
    if score >= 7.0:
        return 1.5
    if score >= 4.0:
        return 1.0
    return 0.5


def assess(cve: dict, inventory: dict) -> dict[str, Any]:
    """Évalue une CVE contre l'inventaire. Retourne le verdict structuré."""
    installed = inventory.get("components", [])
    matches = _match_components(cve, installed)

    if not matches:
        return {
            "schema_version": "1.0",
            "cve_id": cve.get("cve_id"),
            "matched": False,
            "rationale": "Aucun composant installé ne match (keyword ou CPE).",
        }

    # Pour le MVP, on prend le 1er match (cas multi-composants = iteration 2)
    primary = matches[0]
    cid = primary["component_id"]
    A = COMPONENT_CRITICALITY.get(cid, 1)
    B, exposure_detail = _calc_exposure(cid, inventory.get("listening_ports", []))
    C = _calc_vuln_type(cve)
    D = _calc_cvss_intrinsic(cve)
    impact_score = round(A + B + C + D, 1)

    if impact_score >= 9.0:
        impact_class = "critical"
    elif impact_score >= 7.0:
        impact_class = "high"
    elif impact_score >= 5.0:
        impact_class = "medium"
    elif impact_score >= 3.0:
        impact_class = "low"
    else:
        impact_class = "informational"

    rationale = (
        f"{primary['component_name']} v{primary['installed_version']} matche la CVE "
        f"(CVSS {(cve.get('cvss_v3') or {}).get('base_score', 'N/A')}). "
        f"Version check: {primary.get('version_check', {}).get('detail', 'n/a')}. "
        f"Score: A={A} (criticité) + B={B} (exposition) + C={C} (type) + D={D} (CVSS) = {impact_score}."
    )

    return {
        "schema_version": "1.0",
        "cve_id": cve.get("cve_id"),
        "matched": True,
        "matched_components": [primary],  # MVP: premier match seulement
        "impact_score": impact_score,
        "impact_class": impact_class,
        "factors": {"A_criticality": A, "B_exposure": B, "C_vuln_type": C, "D_cvss_intrinsic": D},
        "exposure_detail": exposure_detail,
        "rationale": rationale,
        "kev_listed": cve.get("kev_listed", False),
        "remediation_difficulty": "easy" if impact_class in ("low", "medium") else "moderate",
    }

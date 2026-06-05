"""
inventory.py — STACK_INVENTORY agent (MVP, deterministic, no LLM).

Lit STACK_CANON.md + interroge le VPS (dpkg-query, docker ps, ss, uname)
pour produire l'inventaire runtime JSON (schema v1.0).

Output: ~/vps-secure-agents/state/inventory.json
"""

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from canon_parser import parse_canon


def _run(cmd: str, timeout: int = 10) -> str:
    """Exécute une commande shell, retourne stdout. Log silencieux."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout, check=False
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, OSError) as e:
        return f"ERROR: {e}"


def _dpkg_versions(packages: list[str]) -> dict[str, str]:
    """Retourne {package: version} pour la liste fournie."""
    if not packages:
        return {}
    pkg_list = " ".join(packages)
    out = _run(f"dpkg-query -W -f='${{Package}}=${{Version}}\\n' {pkg_list} 2>/dev/null")
    versions = {}
    for line in out.splitlines():
        if "=" in line and not line.startswith("ERROR"):
            k, v = line.split("=", 1)
            versions[k.strip()] = v.strip()
    return versions


def _dpkg_version(pkg: str) -> str | None:
    """Retourne la version d'un paquet unique, ou None."""
    out = _run(f"dpkg-query -W -f='${{Version}}' {pkg} 2>/dev/null")
    if out and not out.startswith("ERROR"):
        return out
    return None


def _special_version(component_id: str) -> str | None:
    """Cas spéciaux pour les méta-paquets et composants non-installables via dpkg-query direct.

    Mapping:
      - ubuntu-os       → /etc/lsb-release DISTRIB_RELEASE + (DISTRIB_DESCRIPTION)
      - linux-kernel-hwe→ linux-image-$(uname -r) (le vrai paquet installé)
    Retourne None si la résolution échoue.
    """
    if component_id == "ubuntu-os":
        lsb = _run("cat /etc/lsb-release 2>/dev/null")
        distrib_release = distrib_desc = ""
        for line in lsb.splitlines():
            if line.startswith("DISTRIB_RELEASE="):
                distrib_release = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("DISTRIB_DESCRIPTION="):
                distrib_desc = line.split("=", 1)[1].strip().strip('"')
        # Fallback sur /etc/os-release VERSION_ID
        if not distrib_release:
            os_rel = _run("cat /etc/os-release 2>/dev/null")
            for line in os_rel.splitlines():
                if line.startswith("VERSION_ID="):
                    distrib_release = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("PRETTY_NAME="):
                    distrib_desc = line.split("=", 1)[1].strip().strip('"')
        if distrib_release:
            return f"{distrib_release} ({distrib_desc})" if distrib_desc else distrib_release
        return None

    if component_id == "linux-kernel-hwe":
        kernel = _run("uname -r")
        if not kernel or kernel.startswith("ERROR"):
            return None
        # Le paquet réel = linux-image-{version}
        pkg = f"linux-image-{kernel}"
        ver = _dpkg_version(pkg)
        if ver:
            return ver
        # Fallback: linux-image-unsigned-{version} (kernel HWE peut être unsigned)
        pkg = f"linux-image-unsigned-{kernel}"
        ver = _dpkg_version(pkg)
        if ver:
            return ver
        # Dernier fallback: linux-modules-{version}
        pkg = f"linux-modules-{kernel}"
        ver = _dpkg_version(pkg)
        return ver

    return None


def _docker_containers() -> list[dict]:
    """Retourne la liste des containers running avec image complète + digest."""
    fmt = "{{.Names}}|{{.Image}}|{{.State}}"
    out = _run(f"docker ps --format '{fmt}' 2>/dev/null")
    containers = []
    for line in out.splitlines():
        if "|" not in line or "ERROR" in line:
            continue
        name, image, state = line.split("|", 2)
        # Résoudre en sha256 via docker inspect
        digest = _run(f"docker inspect {name} --format '{{{{index .Image \"sha256:\"}}}}' 2>/dev/null")
        containers.append({
            "name": name.strip(),
            "image": image.strip(),
            "state": state.strip(),
            "image_digest": digest.strip() if not digest.startswith("ERROR") else None,
        })
    return containers


def _listening_ports() -> list[dict]:
    """Retourne les ports TCP/UDP en écoute avec process."""
    out = _run("ss -tlnpH 2>/dev/null")
    ports = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        proto, _, local, _, process = parts[0], parts[1], parts[2], parts[3], " ".join(parts[4:]) if len(parts) > 4 else ""
        ports.append({
            "proto": proto,
            "local_address": local,
            "process": process,
        })
    return ports


def _system_info() -> dict:
    """Info système: kernel, OS, hostname, uptime."""
    os_release = _run("cat /etc/os-release")
    os_id = version_id = ""
    for line in os_release.splitlines():
        if line.startswith("VERSION_ID="):
            version_id = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("ID="):
            os_id = line.split("=", 1)[1].strip().strip('"')
    return {
        "hostname": _run("hostname"),
        "os_id": os_id,
        "os_version_id": version_id,
        "kernel": _run("uname -r"),
        "uptime_seconds": _parse_uptime(_run("cat /proc/uptime")),
    }


def _parse_uptime(s: str) -> int:
    try:
        return int(float(s.split()[0]))
    except (ValueError, IndexError):
        return 0


def _install_manifest_hash(canon_path: Path) -> str | None:
    """SHA256 de install.sh local (si encore présent)."""
    candidates = [
        Path("/root/install.sh"),
        Path("/root/install-secure.sh"),
        Path("/home/vpsadmin/install.sh"),
        Path("/tmp/install.sh"),
    ]
    for p in candidates:
        try:
            if p.exists() and p.is_file() and os.access(p, os.R_OK):
                return hashlib.sha256(p.read_bytes()).hexdigest()
        except (PermissionError, OSError):
            continue
    return None


def collect(canon_path: Path) -> dict[str, Any]:
    """Collecte l'inventaire complet. Retourne le dict conforme au schéma v1.0."""
    canon = parse_canon(canon_path)
    sysinfo = _system_info()
    installed_versions = _dpkg_versions(canon["ubuntu_packages"])
    containers = _docker_containers()
    ports = _listening_ports()
    install_sha = _install_manifest_hash(canon_path)

    components = []
    for c in canon["components"]:
        cid = c["id"]
        if c.get("ubuntu_package"):
            pkgs = c["ubuntu_package"] if isinstance(c["ubuntu_package"], list) else [c["ubuntu_package"]]
            for pkg in pkgs:
                # 1) Tenter dpkg-query direct
                ver = installed_versions.get(pkg)
                # 2) Si meta-package non trouvé, tenter la résolution spéciale
                if not ver or ver == "unknown":
                    special = _special_version(cid)
                    if special:
                        ver = special
                # 3) Dernier recours
                if not ver:
                    ver = "unknown"
                components.append({
                    "component_id": cid,
                    "name": c.get("name", cid),
                    "category": c.get("category", "unknown"),
                    "version": ver,
                    "version_pin": c.get("version_pin"),
                    "source": "apt",
                    "ubuntu_package": pkg,
                    "cpe_prefix": c.get("cpe_prefix"),
                    "cve_relevance": "high" if c.get("category") in ("ssh", "firewall", "ids_ips", "kernel", "container") else "medium",
                })
        elif c.get("docker_image"):
            # Trouver le container correspondant
            matching = [c2 for c2 in containers if c2["name"] == cid or c2["image"].startswith(c["docker_image"])]
            image_str = matching[0]["image"] if matching else c["docker_image"]
            digest = matching[0]["image_digest"] if matching else None
            components.append({
                "component_id": cid,
                "name": c.get("name", cid),
                "category": c.get("category", "unknown"),
                "version": digest or image_str,
                "version_pin": c.get("docker_sha256"),
                "source": "docker",
                "docker_image": c["docker_image"],
                "image_digest": digest,
                "cpe_prefix": c.get("cpe_prefix"),
                "cve_relevance": "medium",
            })

    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "trigger": "manual",
        "host": sysinfo,
        "install_manifest": {
            "source_repo": "rockballslab/vps-secure",
            "source_branch": "main",
            "install_sh_sha256": install_sha,
            "drift_detected": install_sha is None,  # drift = on n'a pas le script = custom install
        },
        "components": components,
        "containers": containers,
        "listening_ports": ports,
        "missing_from_canon": [],  # à dériver si besoin
        "unknown_versions": [
            {"component_id": c["component_id"], "package": c.get("ubuntu_package"), "reason": "version == 'unknown'"}
            for c in components
            if c.get("version") == "unknown"
        ],
    }


if __name__ == "__main__":
    import sys
    canon_path = Path(__file__).parent.parent / "canon" / "STACK_CANON.md"
    inv = collect(canon_path)
    print(json.dumps(inv, indent=2, ensure_ascii=False)[:2000])
    print(f"\n... ({len(inv['components'])} components collected, {len(inv['listening_ports'])} ports, {len(inv['containers'])} containers)")

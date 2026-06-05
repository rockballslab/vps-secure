"""
canon_parser.py — parse STACK_CANON.md (Markdown + YAML embedded) → dict Python.

Le STACK_CANON.md contient:
  - Un bloc YAML dans fence ```yaml (le "schema_version", "last_updated", etc.)
  - Un bloc YAML dans fence ```yaml avec `components:` (la liste des 24 composants)
  - Du texte Markdown entre les deux (ignoré)

Le parser extrait les 2 blocs YAML et les merge en un seul dict.
"""

import re
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # fallback regex ci-dessous


YAML_FENCE_RE = re.compile(r"```yaml\s*\n(.*?)```", re.DOTALL)


def parse_canon(path: Path) -> dict[str, Any]:
    """Lit STACK_CANON.md et retourne un dict structuré.

    Returns:
        {
            "metadata": {"schema_version": "1.0", "last_updated": "...", ...},
            "components": [
                {"id": "openssh-server", "name": "...", "category": "...",
                 "cpe_prefix": "...", "docker_image": "...", ...},
                ...
            ]
        }
    """
    text = Path(path).read_text(encoding="utf-8")
    blocks = YAML_FENCE_RE.findall(text)

    if len(blocks) < 2:
        raise ValueError(
            f"STACK_CANON.md doit contenir au moins 2 blocs YAML (metadata + components). "
            f"Trouvés: {len(blocks)}. Vérifier le fichier source."
        )

    if yaml is None:
        raise ImportError(
            "PyYAML non installé. Run: uv pip install pyyaml"
        )

    # Premier bloc = metadata
    metadata = yaml.safe_load(blocks[0]) or {}
    # Deuxième bloc = components (le seul avec la clé `components:`)
    components_yaml = yaml.safe_load(blocks[1]) or {}
    components = components_yaml.get("components", [])

    if not components:
        raise ValueError("Bloc YAML 'components' vide ou mal formé.")

    # Indexation par id pour lookup rapide
    components_by_id = {c["id"]: c for c in components if "id" in c}

    return {
        "metadata": metadata,
        "components": components,
        "components_by_id": components_by_id,
        "cpe_prefixes": [c["cpe_prefix"] for c in components if c.get("cpe_prefix")],
        "ubuntu_packages": [
            pkg
            for c in components
            for pkg in (c.get("ubuntu_package") if isinstance(c.get("ubuntu_package"), list) else [c.get("ubuntu_package")] if c.get("ubuntu_package") else [])
        ],
        "docker_images": [c["docker_image"] for c in components if c.get("docker_image")],
    }

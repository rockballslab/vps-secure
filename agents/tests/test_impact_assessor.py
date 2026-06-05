"""
test_impact_assessor.py — tests unitaires pour le path critique du version-range check.

Ces tests valident que IMPACT_ASSESSOR ne génère PAS de faux positif sur des
versions déjà patchées. C'est le bug critique que le CTO Dust a attrapé sur
CVE-2026-41567 (Docker 29.5.3 vs < 29.5.1).

Lancement:
    cd ~/vps-secure-agents
    .venv/bin/python -m pytest tests/test_impact_assessor.py -v
    # OU
    .venv/bin/python -m pytest tests/ -v
"""

import sys
from pathlib import Path

# Permet l'import depuis n'importe quel cwd
sys.path.insert(0, str(Path(__file__).parent.parent / "orchestrator"))

import pytest
from impact_assessor import (
    _version_in_ranges,
    _parse_description_version_ranges,
    _extract_affected_ranges,
    _normalize_debian_version,
    _dpkg_compare,
    assess,
    COMPONENT_KEYWORDS,
)


# ════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════

def make_range(start=None, end=None, start_inclusive=True, end_inclusive=False, cpe_prefix="*"):
    """Construit un range normalisé pour `_version_in_ranges`."""
    return {
        "cpe_prefix": cpe_prefix,
        "start": start,
        "end": end,
        "start_inclusive": start_inclusive,
        "end_inclusive": end_inclusive,
    }


# ════════════════════════════════════════════════════════════════════════
# Tests des 5 cas proposés par le CTO Dust (adaptés à ma signature)
# ════════════════════════════════════════════════════════════════════════

class TestSylvieCases:
    """Les 5 cas proposés par Sylvie, adaptés à ma signature `_version_in_ranges`."""

    def test_cas1_openssh_9_6p1_patche(self):
        """OpenSSH 1:9.6p1-3ubuntu13.13 patché vs < 1:9.6p1-3ubuntu13.3."""
        in_range, _ = _version_in_ranges(
            "1:9.6p1-3ubuntu13.13",
            [make_range(end="1:9.6p1-3ubuntu13.3")],
            "*"
        )
        assert in_range is False, "9.6p1-3ubuntu13.13 > 9.6p1-3ubuntu13.3 → PATCHÉ"

    def test_cas2_docker_29_5_3_patche(self):
        """Docker 29.5.3 patché vs < 29.5.1 — le bug critique du CTO Dust."""
        in_range, _ = _version_in_ranges(
            "29.5.3",
            [make_range(end="29.5.1")],
            "*"
        )
        assert in_range is False, "29.5.3 > 29.5.1 → PATCHÉ (pas de faux positif Docker)"

    def test_cas3_kernel_dans_plage(self):
        """Kernel 6.8.0-60.63~22.04.1 DANS [6.8.0-1, 6.8.0-65) → vulnérable."""
        in_range, _ = _version_in_ranges(
            "6.8.0-60.63~22.04.1",
            [make_range(start="6.8.0-1", end="6.8.0-65")],
            "*"
        )
        assert in_range is True, "6.8.0-60 ∈ [6.8.0-1, 6.8.0-65) → VULNÉRABLE"

    def test_cas4_epoch_edge_case(self):
        """2:8.5p1-3 patché vs < 2:8.5p1-2 — epoch matching strict."""
        in_range, _ = _version_in_ranges(
            "2:8.5p1-3",
            [make_range(end="2:8.5p1-2")],
            "*"
        )
        assert in_range is False, "2:8.5p1-3 > 2:8.5p1-2 → PATCHÉ"

    def test_cas5_fallback_description(self):
        """Pas de CPE ranges, fallback sur parser de description."""
        # Pas de CPE ranges → on accepte (assumed vulnerable) par défaut
        # C'est le comportement fail-safe: si on ne peut pas vérifier, on conserve
        in_range, detail = _version_in_ranges(
            "29.5.0",
            [],  # empty ranges → fallback
            "*"
        )
        # Avec ranges vides, le comportement actuel est "no applicable range → assumed vulnerable"
        # Cela matche la fail-safe philosophy de Sylvie
        assert in_range is True
        assert "no applicable" in detail.lower() or "assumed" in detail.lower()


# ════════════════════════════════════════════════════════════════════════
# Cas edge découverts pendant le dev (epoch 5, OpenSSH p1 vs .1, etc.)
# ════════════════════════════════════════════════════════════════════════

class TestEdgeCases:

    def test_epoch_5_docker(self):
        """Le bug d'epoch 5 que j'ai eu: '5:29.5.3' doit être comparé en upstream."""
        in_range, _ = _version_in_ranges(
            "5:29.5.3-1~ubuntu.24.04~noble",
            [make_range(end="29.5.1")],
            "*"
        )
        assert in_range is False, "epoch 5 strippé, 29.5.3 > 29.5.1 → PATCHÉ"

    def test_openssh_p1_vs_dot_1(self):
        """Le bug que Sylvie aurait loupé: 9.6p1 < 9.6.1 (p = patch, sort avant .release)."""
        # Vulnérable: 9.6p1 < 9.6.1 (CVE affecte < 9.6.1)
        in_range, _ = _version_in_ranges(
            "1:9.6p1-3ubuntu13.13",
            [make_range(end="9.6.1")],
            "*"
        )
        assert in_range is True, "9.6p1 < 9.6.1 en Debian → VULNÉRABLE (Sylvie aurait dit PATCHÉ)"

    def test_openssh_p1_pas_dans_plage_9_6_2(self):
        """9.6p1 < 9.6.2 → vulnérable."""
        in_range, _ = _version_in_ranges(
            "1:9.6p1-3ubuntu13.13",
            [make_range(end="9.6.2")],
            "*"
        )
        assert in_range is True

    def test_tilde_debian_revision(self):
        """Le tilde ~ dans les versions Debian sort AVANT le caractère vide."""
        # 1~ubuntu1 < 1ubuntu1 (le ~ indique "avant" en Debian)
        # Donc si on a 1~ubuntu2 installé et on check < 1ubuntu1:
        # 1~ubuntu2 < 1ubuntu1 → True → vulnérable
        in_range, _ = _version_in_ranges(
            "5:1~ubuntu2",  # installé
            [make_range(end="1ubuntu1")],  # borne sup
            "*"
        )
        # 1~ubuntu2 < 1ubuntu1 → True (tilde sort avant rien)
        assert in_range is True

    def test_inclusive_end(self):
        """end_inclusive=True doit inclure la borne."""
        in_range, _ = _version_in_ranges(
            "29.5.1",
            [make_range(end="29.5.1", end_inclusive=True)],
            "*"
        )
        assert in_range is True, "end_inclusive=True → 29.5.1 ∈ range"

    def test_exclusive_end(self):
        """end_inclusive=False doit exclure la borne."""
        in_range, _ = _version_in_ranges(
            "29.5.1",
            [make_range(end="29.5.1", end_inclusive=False)],
            "*"
        )
        assert in_range is False, "end_inclusive=False → 29.5.1 ∉ range"

    def test_multi_range_match_any(self):
        """CVE avec plusieurs ranges: vulnérable si installé matche AU MOINS une."""
        # Simule: range1=ancien, range2=récent — installé dans range2
        in_range, _ = _version_in_ranges(
            "29.5.0",
            [
                make_range(start="29.4.0", end="29.4.5"),
                make_range(start="29.5.0", end="29.5.3"),
            ],
            "*"
        )
        assert in_range is True, "29.5.0 ∈ [29.5.0, 29.5.3) → VULNÉRABLE"

    def test_multi_range_hors_toutes(self):
        """Si installé hors de toutes les ranges → non vulnérable."""
        in_range, _ = _version_in_ranges(
            "30.0.0",
            [
                make_range(start="29.4.0", end="29.4.5"),
                make_range(start="29.5.0", end="29.5.3"),
            ],
            "*"
        )
        assert in_range is False

    def test_wildcard_cpe_prefix(self):
        """Range avec cpe_prefix='*' doit s'appliquer à tous les composants."""
        in_range, _ = _version_in_ranges(
            "29.5.3",
            [make_range(end="29.5.1", cpe_prefix="*")],
            cpe_prefix="cpe:2.3:a:docker:docker"
        )
        assert in_range is False, "wildcard range s'applique au composant docker"

    def test_specific_cpe_prefix_filter(self):
        """Range avec cpe_prefix spécifique ne s'applique qu'à ce composant."""
        in_range, _ = _version_in_ranges(
            "29.5.3",
            [make_range(end="29.5.1", cpe_prefix="cpe:2.3:a:other:product")],
            cpe_prefix="cpe:2.3:a:docker:docker"
        )
        # Le range est pour "other", pas "docker" → pas applicable
        # Comportement: si aucun range applicable → assumed vulnerable
        assert in_range is True, "no applicable range → assumed vulnerable"


# ════════════════════════════════════════════════════════════════════════
# Tests de normalisation
# ════════════════════════════════════════════════════════════════════════

class TestNormalizeVersion:

    def test_strip_epoch_only(self):
        """V1.1: on strip l'epoch mais PAS la debian revision (laisser dpkg comparer)."""
        assert _normalize_debian_version("1:9.6p1") == "9.6p1"
        assert _normalize_debian_version("5:29.5.3") == "29.5.3"
        # Revision CONSERVÉE (contrairement à v1.0)
        assert _normalize_debian_version("9.6p1-3ubuntu13.13") == "9.6p1-3ubuntu13.13"
        assert _normalize_debian_version("29.5.3-1~ubuntu.24.04~noble") == "29.5.3-1~ubuntu.24.04~noble"

    def test_strip_both(self):
        """strip epoch, garde revision (v1.1 behavior)."""
        assert _normalize_debian_version("1:9.6p1-3ubuntu13.13") == "9.6p1-3ubuntu13.13"
        assert _normalize_debian_version("5:29.5.3-1~ubuntu.24.04~noble") == "29.5.3-1~ubuntu.24.04~noble"

    def test_empty(self):
        assert _normalize_debian_version("") == ""
        assert _normalize_debian_version(None) == ""


class TestDpkgCompare:

    def test_basic_lt(self):
        assert _dpkg_compare("29.5.0", "lt", "29.5.1") is True
        assert _dpkg_compare("29.5.3", "lt", "29.5.1") is False

    def test_basic_ge(self):
        assert _dpkg_compare("29.5.3", "ge", "29.5.1") is True
        assert _dpkg_compare("29.5.0", "ge", "29.5.1") is False

    def test_with_epoch(self):
        """v1.1: on strip l'epoch puis on compare avec dpkg.
        Docker 5:29.5.0 stripped → 29.5.0 vs 29.5.1 → lt → True (VULNERABLE).
        C'est ce qu'on veut: epoch Docker (5) est un détail de packaging, pas de version.
        """
        assert _dpkg_compare("5:29.5.0-1~ubuntu.24.04~noble", "lt", "29.5.1") is True
        assert _dpkg_compare("5:29.5.3-1~ubuntu.24.04~noble", "lt", "29.5.1") is False

    def test_with_debian_revision(self):
        """On garde la revision (kernel, docker) — dpkg compare correctement."""
        # Kernel: 6.8.0-60.63 vs 6.8.0-65 — revision matters
        assert _dpkg_compare("6.8.0-60.63~22.04.1", "lt", "6.8.0-65") is True
        # Docker: 5:29.5.3-1~ubuntu... stripped → 29.5.3-1~ubuntu vs 29.5.1
        # dpkg compare upstream 29.5.3 vs 29.5.1 → pas lt → PATCHED
        assert _dpkg_compare("5:29.5.3-1~ubuntu.24.04~noble", "lt", "29.5.1") is False


# ════════════════════════════════════════════════════════════════════════
# Tests du parser de description (fallback NVD)
# ════════════════════════════════════════════════════════════════════════

class TestDescriptionParser:

    def test_prior_to_pattern(self):
        desc = "Moby is an open source container framework. In versions prior to 29.5.1, ..."
        ranges = _parse_description_version_ranges(desc)
        assert len(ranges) >= 1
        assert any(r["end"] == "29.5.1" for r in ranges)
        assert all(r["end_inclusive"] is False for r in ranges if r.get("end") == "29.5.1")

    def test_before_pattern(self):
        desc = "A vulnerability in OpenSSH before 9.6p1 allows attackers to ..."
        ranges = _parse_description_version_ranges(desc)
        assert any(r["end"] == "9.6p1" for r in ranges)

    def test_including_pattern(self):
        desc = "This affects versions prior to and including 8.5.1 of the software."
        ranges = _parse_description_version_ranges(desc)
        assert any(r["end"] == "8.5.1" and r["end_inclusive"] is True for r in ranges)

    def test_no_match(self):
        desc = "This CVE has no version information in its description."
        ranges = _parse_description_version_ranges(desc)
        assert ranges == []

    def test_multiple_versions(self):
        desc = "In versions prior to 1.0 and from 2.0 to 3.0, the system was vulnerable."
        ranges = _parse_description_version_ranges(desc)
        # Devrait avoir au moins 1 range détecté
        assert len(ranges) >= 1

    def test_v_prefix_go_semver(self):
        """CVE descriptions utilisent souvent 'v2.0.0' (Go/Moby). Doit être strip."""
        desc = "Affected in versions prior to v2.0.0-beta.14 of the upstream."
        ranges = _parse_description_version_ranges(desc)
        # Le 'v' doit être préservé dans la capture (puis strip au compare)
        # Mais pour le test, on vérifie juste qu'un range est détecté
        assert len(ranges) >= 1
        # Le end doit être 'v2.0.0-beta.14' (ou stripped — peu importe, c'est au compare de gérer)
        # Le test critique: avec le strip 'v' dans _normalize_debian_version,
        # v2.0.0-beta.14 doit être comparable à 2.0.0-beta.14
        # et l'install 29.5.3 doit être > 2.0.0-beta.14 → PATCHED
        in_range, _ = _version_in_ranges(
            "5:29.5.3-1~ubuntu.24.04~noble",
            [make_range(end="v2.0.0-beta.14")],  # avec le v prefix
            "*"
        )
        assert in_range is False, \
            "29.5.3 > 2.0.0-beta.14 même avec le 'v' prefix (doit être stripé) → PATCHÉ"

    def test_docker_moby_double_version(self):
        """Le bug live: description avec 2 versions 'prior to 29.5.1' ET 'prior to v2.0.0-beta.14'."""
        desc = "Moby is an open source container framework. In versions prior to 29.5.1 and in moby/moby v2 prior to v2.0.0-beta.14..."
        ranges = _parse_description_version_ranges(desc)
        # 2 ranges détectés
        assert len(ranges) == 2
        ends = sorted([r["end"] for r in ranges])
        assert "29.5.1" in ends
        # Le second est soit "v2.0.0-beta.14" soit "2.0.0-beta.14" selon capture
        assert any("2.0.0" in e for e in ends)

        # Test critique: 29.5.3 vs les 2 ranges
        in_range, detail = _version_in_ranges(
            "5:29.5.3-1~ubuntu.24.04~noble",
            ranges,
            "*"
        )
        # 29.5.3 > 29.5.1 ET 29.5.3 > 2.0.0-beta.14 → PATCHED sur les 2 ranges
        assert in_range is False, f"29.5.3 doit être PATCHÉ sur les 2 ranges. Got: {detail}"


class TestExtractAffectedRanges:
    """Test de l'extraction depuis NVD configurations block."""

    def test_empty_configurations(self):
        cve = {"configurations": []}
        ranges = _extract_affected_ranges(cve)
        assert ranges == []

    def test_configurations_with_version_range(self):
        cve = {
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "criteria": "cpe:2.3:a:docker:docker:29.5.0:*:*:*:*:*:*:*",
                        "versionEndExcluding": "29.5.1"
                    }]
                }]
            }]
        }
        ranges = _extract_affected_ranges(cve)
        assert len(ranges) == 1
        assert ranges[0]["cpe_prefix"] == "cpe:2.3:a:docker:docker"
        assert ranges[0]["end"] == "29.5.1"
        assert ranges[0]["end_inclusive"] is False

    def test_multiple_nodes(self):
        """NVD peut avoir plusieurs nodes (un par plateforme)."""
        cve = {
            "configurations": [
                {"nodes": [{"cpeMatch": [{
                    "criteria": "cpe:2.3:a:docker:docker:29.5.0:*:*:*:*:*:*:*",
                    "versionEndExcluding": "29.5.1"
                }]}]},
                {"nodes": [{"cpeMatch": [{
                    "criteria": "cpe:2.3:a:docker:docker:29.5.0:~~~ubuntu20.04:*:*:*:*:*",
                    "versionEndExcluding": "29.5.1"
                }]}]}
            ]
        }
        ranges = _extract_affected_ranges(cve)
        assert len(ranges) == 2  # les 2 nodes extraits

    def test_fallback_to_description(self):
        """Si pas de CPE config, parser la description."""
        cve = {
            "configurations": [],
            "description_en": "In versions prior to 29.5.1, the system was vulnerable."
        }
        ranges = _extract_affected_ranges(cve)
        assert len(ranges) >= 1
        assert any(r["end"] == "29.5.1" for r in ranges)


# ════════════════════════════════════════════════════════════════════════
# Tests d'intégration: full assess() sur CVE réaliste
# ════════════════════════════════════════════════════════════════════════

class TestAssessIntegration:

    @pytest.fixture
    def docker_inventory(self):
        return {
            "components": [
                {
                    "component_id": "docker-ce",
                    "name": "Docker Engine Community",
                    "version": "5:29.5.3-1~ubuntu.24.04~noble",
                    "cpe_prefix": "cpe:2.3:a:docker:docker",
                    "category": "container",
                }
            ],
            "listening_ports": [],
        }

    def test_docker_29_5_3_pas_match_cve_29_5_1(self, docker_inventory):
        """Le bug critique CTO: Docker 29.5.3 ne doit PAS matcher CVE < 29.5.1."""
        cve = {
            "cve_id": "CVE-2026-41567",
            "cvss_v3": {"base_score": 7.2, "vector": "AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"},
            "description_en": "Moby is an open source container framework. In versions prior to 29.5.1, the daemon resolves decompression binaries from the container's filesystem rather than the host's, allowing arbitrary code execution.",
            "cpe_list": [],
            "configurations": [],
        }
        verdict = assess(cve, docker_inventory)
        assert verdict["matched"] is False, \
            f"Docker 29.5.3 doit être PATCHÉ vs CVE < 29.5.1. Got: {verdict.get('rationale')}"

    def test_docker_29_5_0_matche_cve_29_5_1(self, docker_inventory):
        """Docker 29.5.0 (avant le fix) DOIT matcher."""
        inv = {**docker_inventory, "components": [
            {**docker_inventory["components"][0], "version": "5:29.5.0-1~ubuntu.24.04~noble"}
        ]}
        cve = {
            "cve_id": "CVE-2026-41567",
            "cvss_v3": {"base_score": 7.2},
            "description_en": "Moby is an open source container framework. In versions prior to 29.5.1...",
            "configurations": [],
        }
        verdict = assess(cve, inv)
        assert verdict["matched"] is True
        assert verdict["impact_class"] in ("medium", "high")

    def test_arcane_openssh_pas_match(self):
        """Le bug keyword ssh/sshKey: Arcane ne doit PAS matcher openssh-server."""
        inv = {"components": [{
            "component_id": "openssh-server",
            "name": "OpenSSH server",
            "version": "1:9.6p1-3ubuntu13.13",
            "cpe_prefix": "cpe:2.3:a:openbsd:openssh",
            "category": "ssh",
        }], "listening_ports": []}
        cve = {
            "cve_id": "CVE-2026-45625",
            "cvss_v3": {"base_score": 9.5},
            # La description parle de "sshKey" (credential), pas OpenSSH
            "description_en": "Arcane is an interface for managing Docker containers. By repointing an existing repository's URL to an attacker-controlled host while omitting the token/sshKey fields, the attacker causes Arcane to decrypt the legitimate PAT/SSH key.",
            "configurations": [],
        }
        verdict = assess(cve, inv)
        assert verdict["matched"] is False, \
            f"Arcane (mentionne sshKey, pas OpenSSH) ne doit PAS matcher openssh-server. Got: {verdict.get('rationale')}"


# ════════════════════════════════════════════════════════════════════════
# Tests des keywords (word-boundary)
# ════════════════════════════════════════════════════════════════════════

class TestKeywordWordBoundary:

    @pytest.mark.parametrize("desc,component_id,should_match", [
        # Vrais positifs
        ("OpenSSH server vulnerability allows RCE", "openssh-server", True),
        ("The sshd daemon is affected", "openssh-server", True),
        ("OpenSSH 9.6p1 vulnerability", "openssh-server", True),
        # Faux positifs qui doivent être filtrés
        ("Arcane uses sshKey for authentication", "openssh-server", False),
        ("SSH tunnel via jump host", "openssh-server", False),  # pas openssh-server
        ("libssh is a C library", "openssh-server", False),  # libssh != openssh
        # Docker
        ("Moby is an open source container framework", "docker-ce", True),
        ("Docker engine vulnerability", "docker-ce", True),
        ("A vulnerability in runc allows privilege escalation", "docker-ce", True),
        # Pas docker
        ("An issue in Docker Compose file syntax", "docker-ce", False),  # pas docker-ce
    ])
    def test_keyword_matching(self, desc, component_id, should_match):
        from impact_assessor import _match_components
        inv_comp = {"component_id": component_id, "version": "1.0", "cpe_prefix": "cpe:2.3:a:test:test"}
        cve = {
            "description_en": desc,
            "cpe_list": [],
            "configurations": [],  # pas de version range → match par keyword
        }
        matches = _match_components(cve, [inv_comp])
        if should_match:
            assert any(m["component_id"] == component_id for m in matches), \
                f"expected match for '{desc}' on {component_id}"
        else:
            assert not any(m["component_id"] == component_id for m in matches), \
                f"false positive: '{desc}' should NOT match {component_id}"

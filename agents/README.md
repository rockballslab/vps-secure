# vps-secure-agents

> Système multi-agents autonome pour la veille CVE sur les VPS ayant installé [`vps-secure`](https://github.com/rockballslab/vps-secure).
> Remplace l'ancienne stack Dust.tt — recréé from scratch dans Hermes avec les agents comme code Python déterministe.

## Architecture

```
                   cron 07:30 Europe/Paris
                            │
                            ▼
                  ┌──────────────────┐
                  │  cto_orchestrator│
                  │      .py run     │
                  └────────┬─────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
  STACK_INVENTORY    CVE_WATCHER     IMPACT_ASSESSOR
  (inventory.py)     (cve_watcher.py)  (impact_assessor.py)
        │                  │                  │
        ▼                  ▼                  ▼
  state/inventory   state/cve_watch    verdicts[]
  .json             .json                   │
                                            ▼
                            ┌────────────────────────┐
                            │  debounce (state.py)   │
                            └────────┬───────────────┘
                                     │
                                     ▼
                            ┌─────────────────────┐
                            │  TelegramNotifier   │
                            │  (digest + P0 alert)│
                            └─────────┬───────────┘
                                      │
                                      ▼
                            state/cto_state.json
                            (vue unique, ack, snooze)
```

## Structure

```
~/vps-secure-agents/
├── agents/                  ← les .md (system prompts de référence, optionnels en mode rule-based)
│   ├── STACK_INVENTORY.md
│   ├── CVE_WATCHER.md
│   ├── IMPACT_ASSESSOR.md
│   ├── THREAT_INTEL.md          (pas implémenté en MVP)
│   ├── REMEDIATION_PLANNER.md   (pas implémenté en MVP)
│   └── CTO_SECURITY.md
├── canon/
│   └── STACK_CANON.md        ← source de vérité composants (YAML inside markdown)
├── orchestrator/             ← code Python des agents
│   ├── cto_orchestrator.py   ← entrée principale (CLI: run, inventory, digest, ack, status)
│   ├── state.py              ← state files JSON avec locking + écriture atomique
│   ├── canon_parser.py       ← parse STACK_CANON.md
│   ├── inventory.py          ← STACK_INVENTORY agent (shell + parsing)
│   ├── cve_watcher.py        ← CVE_WATCHER agent (NVD + Ubuntu SN + CISA KEV)
│   ├── impact_assessor.py    ← IMPACT_ASSESSOR agent (rule-based MVP)
│   └── telegram_notifier.py  ← Telegram Bot API wrapper
├── state/                    ← JSON runtime (gitignore)
│   ├── cto_state.json
│   ├── inventory.json
│   └── cve_watch.json
├── requirements.txt
├── .env.example
├── deploy.sh                 ← venv + deps + cron
└── README.md
```

## Quick start

```bash
cd ~/vps-secure-agents
./deploy.sh                       # crée venv, install deps, ajoute cron 07:30 Paris
# Éditer .env avec OPENROUTER_API_KEY + TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID
nano .env

# Test dry-run (pas de LLM, pas de Telegram, juste les state files)
./.venv/bin/python orchestrator/cto_orchestrator.py run --dry

# Test inventory seul
./.venv/bin/python orchestrator/cto_orchestrator.py inventory

# Status
./.venv/bin/python orchestrator/cto_orchestrator.py status

# Acquitter une CVE manuellement
./.venv/bin/python orchestrator/cto_orchestrator.py ack CVE-2024-XXXXX
```

## CLI

| Commande | Description |
|---|---|
| `run [--dry]` | Run complet quotidien: inventaire → CVE → assess → notify |
| `run --dry` | Idem mais sans Telegram (les state files sont remplis) |
| `inventory` | Collecte juste l'inventaire (debug, peut être long) |
| `digest` | Régénère un digest depuis le state existant (sans re-fetch) |
| `ack <cve_id>` | Marque une CVE comme acquittée (silence jusqu'à nouveau hit) |
| `status` | Affiche les stats du state |

## Cron

`deploy.sh` ajoute automatiquement:
```
CRON_TZ=Europe/Paris
30 7 * * * /home/vpsadmin/vps-secure-agents/.venv/bin/python /home/vpsadmin/vps-secure-agents/orchestrator/cto_orchestrator.py run >> /var/log/vps-secure-agents/orchestrator.log 2>&1
```

DST-aware: 07:30 heure Paris toute l'année (05:30 UTC hiver, 05:30 UTC été en pratique — vérifié par `CRON_TZ=Europe/Paris`).

## State files

| File | Contenu | Mis à jour par |
|---|---|---|
| `state/inventory.json` | Inventaire complet (composants, containers, ports) | STACK_INVENTORY |
| `state/cve_watch.json` | CVE brutes fetchées (NVD + Ubuntu SN + CISA KEV) | CVE_WATCHER |
| `state/cto_state.json` | CVE vues, debounce, ack, snooze | CTO orchestrator |

Tous les fichiers sont `chmod 600`, JSON UTF-8, écriture atomique (tmp file + rename).

## Debounce

Le state `cto_state.json` implémente un debounce de 7 jours par CVE × composant:
- 1ère détection → notification
- 2-6 jours → silence (sauf si CVSS révisé, KEV ajouté, PoC apparu, user pas acked)
- 7+ jours → re-notification

Cas particuliers:
- `user_acked_at` ou `fix_applied_at` → silence permanent
- `user_snoozed_until` > now → silence temporaire
- KEV ajouté après 1ère notif → upgrade P0 immédiat

## MVP scope (vs agents .md complets)

| Agent | Status MVP | Mode |
|---|---|---|
| `STACK_INVENTORY` | ✅ Implémenté | Rule-based (shell + parsing) |
| `CVE_WATCHER` | ✅ Implémenté (3 sources) | Rule-based (HTTP) |
| `IMPACT_ASSESSOR` | ✅ Implémenté | Rule-based (table criticité du .md) |
| `THREAT_INTEL` | ⏳ Pas implémenté | À faire (HTTP calls: CISA KEV, Exploit-DB, etc.) |
| `REMEDIATION_PLANNER` | ⏳ Pas implémenté | À faire (LLM call: génère commande + rollback) |
| `CTO_SECURITY` | ✅ Implémenté (digest + debounce) | Rule-based |

Pour passer en **mode LLM**, voir `agents_runtime.py` (TODO): il faudra charger les .md comme system prompts et appeler OpenRouter.

## Sources CVE (whitelist stricte)

Cf. `agents/CVE_WATCHER.md` pour la liste complète et justifiée.

**Implémentées en MVP** (3):
- NVD CVE 2.0
- Ubuntu Security Notices RSS
- CISA KEV (cross-ref)

**À ajouter** (post-MVP):
- MITRE CVE 5.0
- GHSA
- oss-security
- OpenSSH changelog
- OSV.dev
- Docker Security
- CrowdSec blog

## Logs

- Orchestrator: `/var/log/vps-secure-agents/orchestrator.log`
- State files: `~/vps-secure-agents/state/*.json`
- Rotation: TODO (logrotate config à ajouter)

## Sécurité

- `.env` est en `chmod 600` (à vérifier post-deploy)
- State files: `chmod 600`
- Pas de privilege escalation nécessaire: tourne en user `vpsadmin`, sudo via les commandes shell (qui s'auto-échouent si pas sudo)
- Telegram bot token: via env var, jamais en clair dans le code ou les logs
- HTTP sortant: whitelist stricte des domains (cf. CVE_WATCHER.md)

## Roadmap

1. **THREAT_INTEL** (P0/P1 enrichment): ajouter CISA KEV enrichment + Exploit-DB + Metasploit lookup
2. **REMEDIATION_PLANNER** (génération de commande): LLM call (OpenRouter) avec .md comme system prompt
3. **Mode LLM** pour IMPACT_ASSESSOR: charger le .md comme system prompt pour les cas ambigus
4. **Telegram polling** (ack/snooze/fix): long-poll l'API Telegram pour capter les réponses user
5. **Webhooks** (GitHub Advisory push, CISA KEV update): passer de cron-only à event-driven
6. **Dashboard output**: écrire dans `state/cto_state.json` au format attendu par le vps-monitor dashboard
7. **Logrotate** + alerting (si orchestrator crash 2 jours de suite → Telegram P0)
8. **Tests unitaires** dans `tests/` (un par agent)

## License

MIT (ou celle de vps-secure upstream).

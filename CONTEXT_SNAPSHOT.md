# FrostGate Core – Context Snapshot

Generated: 2025-12-29T12:02:19Z

## Mission Lock
- Product: FrostGate Core
- Phase: MVP → Demo-Ready
- Goal: Undeniable security telemetry with explainable decisions
- Buyer Signal: stats endpoint tells a story in 10 seconds

## Active Instance
- Expected API: http://127.0.0.1:8000
- DB Backend: SQLite (local dev)
- DB Path: $FG_STATE_DIR/frostgate.db

## Environment
(no FG env vars exported)

## Running Listeners
LISTEN 0      2048         0.0.0.0:8080       0.0.0.0:*    users:(("uvicorn",pid=46885,fd=13))

## Directory Tree (3 levels)
.
secrets
.github
.github/workflows
agent
agent/app
agent/app/scripts
agent/contracts
docs
docs/patches
security
security/pss
demo
frostgate_core.egg-info
engine
engine/__pycache__
.venv
.venv/bin
.venv/include
.venv/include/site
.venv/include/python3.12
.venv/lib
.venv/lib/python3.12
tools
tools/telemetry
tools/tenants
tools/tenants/__pycache__
.git
.git/info
.git/refs
.git/refs/heads
.git/refs/tags
.git/refs/remotes
.git/branches
.git/hooks
.git/objects
.git/objects/9d
.git/objects/d6
.git/objects/56
.git/objects/25
.git/objects/d7
.git/objects/ed
.git/objects/8a
.git/objects/f9
.git/objects/84
.git/objects/1c
.git/objects/45
.git/objects/ef
.git/objects/44
.git/objects/9f
.git/objects/db
.git/objects/3e
.git/objects/50
.git/objects/7f
.git/objects/30
.git/objects/16
.git/objects/4d
.git/objects/ab
.git/objects/15
.git/objects/e7
.git/objects/e9
.git/objects/dc
.git/objects/0d
.git/objects/08
.git/objects/70
.git/objects/61
.git/objects/5e
.git/objects/13
.git/objects/46
.git/objects/f8
.git/objects/07
.git/objects/info
.git/objects/6c
.git/objects/3b
.git/objects/92
.git/objects/2c
.git/objects/5b
.git/objects/19
.git/objects/97
.git/objects/b4
.git/objects/75
.git/objects/fa
.git/objects/6d
.git/objects/1f
.git/objects/7d
.git/objects/e0
.git/objects/69
.git/objects/32
.git/objects/c2
.git/objects/bd
.git/objects/62
.git/objects/ee
.git/objects/b9
.git/objects/38
.git/objects/cf
.git/objects/20
.git/objects/dd
.git/objects/fc
.git/objects/85
.git/objects/e8
.git/objects/c7
.git/objects/8b
.git/objects/64
.git/objects/cd
.git/objects/f5
.git/objects/89
.git/objects/d9
.git/objects/f6
.git/objects/b5
.git/objects/aa
.git/objects/86
.git/objects/f0
.git/objects/df
.git/objects/35
.git/objects/59
.git/objects/65
.git/objects/23
.git/objects/eb
.git/objects/bb
.git/objects/f2
.git/objects/5a
.git/objects/63
.git/objects/04
.git/objects/73
.git/objects/47
.git/objects/28
.git/objects/a5
.git/objects/4e
.git/objects/da
.git/objects/d0
.git/objects/f1
.git/objects/79
.git/objects/5f
.git/objects/0c
.git/objects/e2
.git/objects/3a
.git/objects/0b
.git/objects/91
.git/objects/2d
.git/objects/27
.git/objects/a7
.git/objects/37
.git/objects/c8
.git/objects/ff
.git/objects/6b
.git/objects/ca
.git/objects/e5
.git/objects/68
.git/objects/06
.git/objects/e6
.git/objects/24
.git/objects/8c
.git/objects/39
.git/objects/83
.git/objects/26
.git/objects/a6
.git/objects/c1
.git/objects/8d
.git/objects/fb
.git/objects/6e
.git/objects/ec
.git/objects/ac
.git/objects/43
.git/objects/40
.git/objects/c3
.git/objects/a9
.git/objects/33
.git/objects/71
.git/objects/d2
.git/objects/ce
.git/objects/9c
.git/objects/74
.git/objects/b6
.git/objects/02
.git/objects/b7
.git/objects/4c
.git/objects/78
.git/objects/e3
.git/objects/b0
.git/objects/51
.git/objects/60
.git/objects/d5
.git/objects/d1
.git/objects/2a
.git/objects/5c
.git/objects/a4
.git/objects/e1
.git/objects/ae
.git/objects/e4
.git/objects/48
.git/objects/34
.git/objects/3f
.git/objects/14
.git/objects/98
.git/objects/49
.git/objects/31
.git/objects/09
.git/objects/5d
.git/objects/4a
.git/objects/b1
.git/objects/d8
.git/objects/c5
.git/objects/52
.git/objects/4b
.git/objects/72
.git/objects/42
.git/objects/95
.git/objects/0a
.git/objects/58
.git/objects/ea
.git/objects/82
.git/objects/1a
.git/objects/a3
.git/objects/ba
.git/objects/76
.git/objects/b8
.git/objects/pack
.git/objects/9a
.git/objects/17
.git/objects/3c
.git/objects/57
.git/objects/6a
.git/objects/d4
.git/objects/11
.git/objects/2b
.git/objects/7a
.git/objects/a8
.git/objects/29
.git/objects/af
.git/objects/de
.git/objects/a1
.git/objects/cb
.git/objects/8f
.git/objects/c9
.git/objects/bc
.git/objects/0e
.git/objects/1e
.git/objects/05
.git/objects/7e
.git/objects/c4
.git/objects/87
.git/objects/f3
.git/objects/fd
.git/objects/12
.git/objects/93
.git/objects/10
.git/objects/90
.git/objects/2e
.git/objects/94
.git/objects/a2
.git/objects/21
.git/objects/be
.git/objects/53
.git/objects/41
.git/objects/3d
.git/objects/99
.git/objects/55
.git/objects/36
.git/objects/8e
.git/objects/22
.git/objects/96
.git/objects/80
.git/objects/1b
.git/objects/01
.git/objects/77
.git/objects/bf
.git/objects/00
.git/objects/54
.git/objects/03
.git/objects/1d
.git/logs
.git/logs/refs
deploy
deploy/charts
deploy/helm
deploy/helm/frostgatecore
deploy/k8s
deploy/k8s/dev
deploy/frostgate-core
deploy/frostgate-core/templates
api
api/db
api/__pycache__
api/config
api/config/__pycache__
tests
tests/__pycache__
agent_queue
agent_queue/sent
state
jobs
jobs/chaos
jobs/chaos/__pycache__
jobs/__pycache__
jobs/sim_validator
jobs/sim_validator/__pycache__
jobs/merkle_anchor
jobs/merkle_anchor/__pycache__
scripts
scripts/__pycache__
supervisor-sidecar
backend
backend/tests
backend/tests/__pycache__
backend/app
backend/app/api
backend/app/__pycache__
backend/app/services

## Key Files
-rw-rw-r-- 1 jcosat jcosat 4229 Dec 23 09:11 docker-compose.yml

api:
total 148
drwxrwxr-x  5 jcosat jcosat  4096 Dec 27 17:17 .
drwxrwxr-x 22 jcosat jcosat  4096 Dec 29 06:49 ..
-rw-rw-r--  1 jcosat jcosat  1691 Dec 25 12:27 auth.py
-rw-rw-r--  1 jcosat jcosat  4745 Dec 27 15:56 auth_scopes.py
drwxrwxr-x  3 jcosat jcosat  4096 Dec 23 17:01 config
-rw-rw-r--  1 jcosat jcosat  1221 Nov 18 18:35 config.py
drwxrwxr-x  2 jcosat jcosat  4096 Dec 23 14:42 db
-rw-rw-r--  1 jcosat jcosat  2137 Dec 28 20:10 db_models.py
-rw-rw-r--  1 jcosat jcosat  1408 Dec 23 12:57 db.py
-rw-rw-r--  1 jcosat jcosat  6353 Dec 19 12:26 decisions.py
-rw-rw-r--  1 jcosat jcosat 17500 Dec 28 20:11 defend.py
-rw-rw-r--  1 jcosat jcosat  3143 Dec 27 15:56 feed.py
-rw-rw-r--  1 jcosat jcosat  6280 Dec 22 19:04 ingest.py
-rw-rw-r--  1 jcosat jcosat   443 Dec 22 15:05 ingest_schemas.py
-rw-rw-r--  1 jcosat jcosat     0 Nov 22 17:15 __init__.py
-rw-rw-r--  1 jcosat jcosat   533 Nov 18 07:13 logging_config.py
-rw-rw-r--  1 jcosat jcosat  3587 Dec 28 20:17 main.py
-rw-rw-r--  1 jcosat jcosat   767 Nov 22 18:46 metrics.py
-rw-rw-r--  1 jcosat jcosat  2139 Dec 23 10:57 models.py
-rw-rw-r--  1 jcosat jcosat  1971 Dec 19 12:26 persist.py
drwxrwxr-x  2 jcosat jcosat  4096 Dec 28 20:17 __pycache__
-rw-rw-r--  1 jcosat jcosat   314 Dec 22 14:59 rate_limit.py
-rw-rw-r--  1 jcosat jcosat  7856 Dec 19 12:26 ratelimit.py
-rw-rw-r--  1 jcosat jcosat  2493 Dec 23 14:46 schemas.py
-rw-rw-r--  1 jcosat jcosat  8971 Dec 28 17:45 stats.py
-rw-rw-r--  1 jcosat jcosat  3021 Dec 15 09:00 telemetry.py
-rw-rw-r--  1 jcosat jcosat  4592 Dec 19 12:26 token_useage.py

scripts:
total 392
drwxrwxr-x  3 jcosat jcosat 4096 Dec 29 06:48 .
drwxrwxr-x 22 jcosat jcosat 4096 Dec 29 06:49 ..
-rw-rw-r--  1 jcosat jcosat 4089 Dec 23 09:26 apply_decisions_indexes.py
-rwxrwxr-x  1 jcosat jcosat 1061 Dec 22 19:07 audit_changes.sh
-rwxrwxr-x  1 jcosat jcosat 1120 Dec 19 12:26 auth_audit.sh
-rwxrwxr-x  1 jcosat jcosat  607 Nov 21 09:29 build.sh
-rwxrwxr-x  1 jcosat jcosat 1131 Nov 21 06:16 common.sh
-rw-rw-r--  1 jcosat jcosat 1556 Dec 19 12:26 create_api_key.py
-rwxrwxr-x  1 jcosat jcosat 4200 Dec 28 14:43 demo.sh
-rwxrwxr-x  1 jcosat jcosat 1011 Nov 21 14:11 deploy_dev.sh
-rwxrwxr-x  1 jcosat jcosat  888 Nov 21 07:01 deploy_prod.sh
-rwxrwxr-x  1 jcosat jcosat  278 Dec 14 20:02 dev-api.sh
-rwxrwxr-x  1 jcosat jcosat  526 Dec 23 09:26 dev-api-with-db.sh
-rwxrwxr-x  1 jcosat jcosat 1275 Nov 22 16:07 dev-deploy-core.sh
-rwxrwxr-x  1 jcosat jcosat  295 Dec 22 11:41 dev_env.sh
-rwxrwxr-x  1 jcosat jcosat  432 Nov 18 07:58 dev-supervisor.sh
-rwxrwxr-x  1 jcosat jcosat  993 Dec 22 13:49 diag_core_crash.sh
-rwxrwxr-x  1 jcosat jcosat  258 Dec 19 12:26 env.sh
-rwxrwxr-x  1 jcosat jcosat  245 Dec 22 13:50 find_corrupted_scripts.sh
-rwxrwxr-x  1 jcosat jcosat  173 Dec 22 19:04 fix_and_test.sh
-rwxrwxr-x  1 jcosat jcosat 2475 Dec 19 12:26 fix_db_url.sh
-rw-rw-r--  1 jcosat jcosat 1404 Dec 22 19:37 fix_engine_rules_now.py
-rwxrwxr-x  1 jcosat jcosat  465 Dec 19 12:26 gen_keys_and_env.sh
-rw-rw-r--  1 jcosat jcosat    0 Dec 22 14:46 __init__.py
-rwxrwxr-x  1 jcosat jcosat 1057 Nov 22 16:01 k8s-dev-cluster.sh
-rwxrwxr-x  1 jcosat jcosat 1623 Dec 19 12:26 migrate_auth_to_scopes.sh
-rw-rw-r--  1 jcosat jcosat  997 Dec 23 08:37 mint_api_key.py
-rwxrwxr-x  1 jcosat jcosat  743 Dec 22 14:02 patch_add_classificationring.sh
-rwxrwxr-x  1 jcosat jcosat 1498 Dec 22 14:01 patch_add_missing_mitigationaction.sh
-rw-rw-r--  1 jcosat jcosat 1940 Dec 22 19:11 patch_api_auth_verify.py
-rw-rw-r--  1 jcosat jcosat 4827 Dec 23 08:13 patch_api_keys_insert.py
-rwxrwxr-x  1 jcosat jcosat 2063 Dec 23 13:57 patch_defend_timestamp_parse.sh
-rwxrwxr-x  1 jcosat jcosat 1817 Dec 23 16:41 patch_defend_to_utc_any.sh
-rwxrwxr-x  1 jcosat jcosat 1625 Dec 23 14:49 patch_defend_to_utc_replace_all.sh
-rwxrwxr-x  1 jcosat jcosat 5594 Dec 23 14:00 patch_doctrine_all_in_one.sh
-rwxrwxr-x  1 jcosat jcosat 2788 Dec 23 13:51 patch_doctrine_telemetry.sh
-rw-rw-r--  1 jcosat jcosat  944 Dec 22 19:11 patch_engine_rules_bruteforce_keys.py
-rw-rw-r--  1 jcosat jcosat  991 Dec 22 19:27 patch_engine_rules_bruteforce_logic.py
-rw-rw-r--  1 jcosat jcosat  625 Dec 22 19:11 patch_engine_rules_eventtype.py
-rwxrwxr-x  1 jcosat jcosat 9253 Dec 23 08:33 patch_failing_tests.py
-rwxrwxr-x  1 jcosat jcosat 2343 Dec 22 13:32 patch_ingest_defendresponse_import.sh
-rwxrwxr-x  1 jcosat jcosat 1692 Dec 22 19:09 patch_ingest_rate_limit_missing.sh
-rwxrwxr-x  1 jcosat jcosat 4964 Dec 23 14:27 patch_main_auth_hard_freeze.sh
-rwxrwxr-x  1 jcosat jcosat 4527 Dec 23 14:18 patch_main_clean.sh
-rwxrwxr-x  1 jcosat jcosat 4990 Dec 23 14:23 patch_main_dedupe_health.sh
-rwxrwxr-x  1 jcosat jcosat 4474 Dec 23 14:25 patch_main_freeze_auth_enabled.sh
-rwxrwxr-x  1 jcosat jcosat 4759 Dec 23 14:37 patch_main_health_debug.sh
-rwxrwxr-x  1 jcosat jcosat 3595 Dec 23 14:49 patch_main_health_first.sh
-rwxrwxr-x  1 jcosat jcosat 5019 Dec 23 14:33 patch_main_kill_all_health_routes.sh
-rwxrwxr-x  1 jcosat jcosat 5367 Dec 23 14:31 patch_main_no_closure_health.sh
-rwxrwxr-x  1 jcosat jcosat 1607 Dec 22 13:45 patch_main_optional_ingest_router.sh
-rwxrwxr-x  1 jcosat jcosat 1158 Dec 22 13:50 patch_main_router_imports_nonfatal.sh
-rwxrwxr-x  1 jcosat jcosat 1316 Dec 23 14:29 patch_main_strict_auth_bool.sh
-rwxrwxr-x  1 jcosat jcosat 9585 Dec 23 14:42 patch_mvp_all_fixed.sh
-rwxrwxr-x  1 jcosat jcosat 8818 Dec 23 14:09 patch_mvp_auth_doctrine.sh
-rwxrwxr-x  1 jcosat jcosat 3882 Dec 22 19:04 patch_repo.py
-rwxrwxr-x  1 jcosat jcosat 2409 Dec 23 13:53 patch_telemetry_backfill.sh
-rwxrwxr-x  1 jcosat jcosat 2812 Dec 23 13:55 patch_telemetry_event_payload_compat.sh
-rw-rw-r--  1 jcosat jcosat 2396 Dec 22 19:27 patch_test_defend_auth.py
-rw-rw-r--  1 jcosat jcosat 1077 Dec 22 19:38 patch_test_defend_key_schema.py
-rw-rw-r--  1 jcosat jcosat 1115 Dec 22 19:38 patch_test_ingest_key_schema.py
-rw-rw-r--  1 jcosat jcosat 1843 Dec 22 19:26 patch_test_ingest_persists_fix.py
-rw-rw-r--  1 jcosat jcosat 1490 Dec 22 19:10 patch_test_ingest_persists.py
-rwxrwxr-x  1 jcosat jcosat 1389 Dec 22 13:46 patch_wait_core_ready.sh
-rwxrwxr-x  1 jcosat jcosat  636 Dec 23 08:24 psql.sh
drwxrwxr-x  2 jcosat jcosat 4096 Dec 23 17:08 __pycache__
-rwxrwxr-x  1 jcosat jcosat  528 Dec 23 09:26 run_agent_local.sh
-rwxrwxr-x  1 jcosat jcosat  446 Nov 18 08:04 run-chaos.sh
-rwxrwxr-x  1 jcosat jcosat   94 Dec 14 20:03 run-dev.sh
-rwxrwxr-x  1 jcosat jcosat  268 Nov 18 07:38 run-merkle-anchor.sh
-rwxrwxr-x  1 jcosat jcosat 2123 Dec 20 15:13 seed_apikeys_db.py
-rwxrwxr-x  1 jcosat jcosat 1698 Dec 28 20:02 seed_demo_decisions.sh
-rwxrwxr-x  1 jcosat jcosat 1350 Dec 19 12:26 smoke_agent.sh
-rwxrwxr-x  1 jcosat jcosat 1266 Dec 19 12:26 smoke_core.sh
-rwxrwxr-x  1 jcosat jcosat 3293 Dec 20 15:35 smoke_ingest_decisions.sh
-rwxrwxr-x  1 jcosat jcosat 5891 Dec 20 14:26 smoke.sh
-rwxrwxr-x  1 jcosat jcosat 1853 Dec 29 06:48 snapshot_context.sh
-rw-rw-r--  1 jcosat jcosat 1274 Dec 23 08:37 test_ingest_persists.py
-rwxrwxr-x  1 jcosat jcosat  504 Nov 21 06:17 test.sh
-rwxrwxr-x  1 jcosat jcosat  973 Dec 22 13:47 wait_core_ready.sh
-rwxrwxr-x  1 jcosat jcosat  408 Dec 19 12:26 wait-for-api.sh
-rwxrwxr-x  1 jcosat jcosat  721 Dec 19 15:08 write_file.py

tests:
total 68
drwxrwxr-x  3 jcosat jcosat 4096 Dec 28 15:31 .
drwxrwxr-x 22 jcosat jcosat 4096 Dec 29 06:49 ..
-rw-rw-r--  1 jcosat jcosat  758 Dec 23 09:51 conftest.py
-rw-rw-r--  1 jcosat jcosat    0 Dec 23 11:46 __init__.py
-rw-rw-r--  1 jcosat jcosat  671 Dec 22 20:25 _mk_test_key.py
drwxrwxr-x  2 jcosat jcosat 4096 Dec 28 15:31 __pycache__
-rw-rw-r--  1 jcosat jcosat  695 Nov 19 14:46 test_auth_contract.py
-rw-rw-r--  1 jcosat jcosat 2674 Nov 19 14:46 test_auth.py
-rw-rw-r--  1 jcosat jcosat 2846 Nov 19 16:54 test_auth_tenants.py
-rw-rw-r--  1 jcosat jcosat  620 Dec 23 09:26 test_db_fallback.py
-rw-rw-r--  1 jcosat jcosat 1098 Dec 22 20:24 test_defend_endpoint.py
-rw-rw-r--  1 jcosat jcosat 3674 Nov 19 12:53 test_doctrine.py
-rw-rw-r--  1 jcosat jcosat 1244 Dec 22 20:23 test_engine_rules.py
-rw-rw-r--  1 jcosat jcosat  927 Dec 22 20:07 test_feed_endpoint.py
-rw-rw-r--  1 jcosat jcosat  537 Nov 19 07:58 test_jobs_smoke.py
-rw-rw-r--  1 jcosat jcosat  290 Dec 27 15:57 test_main_integrity.py
-rw-rw-r--  1 jcosat jcosat  774 Dec 23 09:26 test_paths.py
-rw-rw-r--  1 jcosat jcosat  740 Dec 28 15:31 test_stats_endpoint.py

## Decision Schema (SQLite)
⚠️ SQLite DB not found at FG_STATE_DIR

## Stats Snapshot
(stats unavailable)

## Known Truths
- rules_triggered_json is authoritative
- response_json is persisted correctly
- top_rules requires non-empty rules_triggered_json
- dockerized core uses Postgres and a different DB

## Immediate Next Steps
- Add rule diversity (more than default_allow)
- Add time-bucket trend deltas (24h vs 7d)
- Lock demo narrative
- Optional: /stats/debug endpoint

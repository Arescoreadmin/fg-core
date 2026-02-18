from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MIGRATIONS = [
    REPO / 'migrations/postgres/0024_agent_phase2_enterprise.sql',
    REPO / 'migrations/postgres/0025_agent_phase21_hardening.sql',
]
TABLES = [
    'agent_device_identities',
    'agent_commands',
    'agent_policy_bundles',
    'agent_log_anchors',
    'agent_quarantine_events',
    'agent_update_rollouts',
    'agent_rate_budget_counters',
]


def main() -> int:
    text = "\n".join(m.read_text(encoding='utf-8') for m in MIGRATIONS)
    missing: list[str] = []
    for table in TABLES:
        if f'ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;' not in text:
            missing.append(f'{table}: missing RLS enable')
        if f'POLICY {table}_tenant_isolation' not in text:
            missing.append(f'{table}: missing tenant policy')
        if "current_setting('app.tenant_id', true)" not in text:
            missing.append(f'{table}: missing tenant binding expression')
    if missing:
        print('agent phase2 rls check: FAILED')
        for item in missing:
            print(f' - {item}')
        return 1
    print('agent phase2 rls check: OK')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

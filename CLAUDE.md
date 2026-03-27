# Repo rules

- Smallest diff wins.
- Do not edit unrelated files.
- Do not edit generated files unless source + regen are both included.
- Prefer make targets and scripts in this repo.
- Never modify secrets, env files, or credentials.
- Never mutate deployment or CI config silently.
- If touching contracts, schemas, migrations, or infra, say so explicitly.

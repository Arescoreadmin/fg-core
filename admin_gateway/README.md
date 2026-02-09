# Admin Gateway

## Local development

Create the admin gateway virtualenv and install dependencies:

```bash
make admin-venv
```

## Offline or mirrored installs

If PyPI access is unavailable, set a mirror index URL and/or point pip at a local
wheelhouse. The Makefile respects the standard pip environment variables and
propagates them to the admin gateway install.

### Mirror index

```bash
export AG_PIP_INDEX_URL="https://my.mirror/simple"
make admin-venv
```

### Wheelhouse (offline)

```bash
export AG_PIP_NO_INDEX=1
export AG_PIP_FIND_LINKS="/path/to/wheelhouse"
make admin-venv
```

### Mirror + wheelhouse fallback

```bash
export AG_PIP_INDEX_URL="https://my.mirror/simple"
export AG_PIP_FIND_LINKS="/path/to/wheelhouse"
make admin-venv
```

If you need to pre-build a wheelhouse from another machine with internet
access, run:

```bash
python -m pip wheel -r admin_gateway/requirements.txt -r admin_gateway/requirements-dev.txt -w /path/to/wheelhouse
```

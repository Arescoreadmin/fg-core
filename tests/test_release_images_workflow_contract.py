"""Contract tests for the frostgate-release-images workflow + Makefile targets.

These tests enforce the invariant that the release-images workflow invokes
real `make docker-build` / `make docker-push` targets, and that those targets
actually build the Dockerfiles present in the repo. They defend against the
POST-775 regression where `make docker-build` existed in CI but not in the
Makefile, so the workflow silently failed after Buildx + GHCR login had
already succeeded.

Scope:
    A — Makefile exposes docker-build / docker-push / docker-release
    B — docker-build recipe references the actual Dockerfiles (no echo stub)
    C — push-without-build is prevented (existence guard + workflow ordering)
    D — release-images workflow calls `make docker-build` and `make docker-push`
    E — docker-build normalizes IMAGE_OWNER to lowercase (GHCR requirement)
    F — print-images resolves REGISTRY/IMAGE_OWNER/VERSION deterministically
"""

from __future__ import annotations

import pathlib
import re
import subprocess

_REPO = pathlib.Path(__file__).resolve().parents[1]
_MAKEFILE = _REPO / "Makefile"
_WORKFLOW = _REPO / ".github" / "workflows" / "release-images.yml"
_DOCKERFILE_CORE = _REPO / "Dockerfile"
_DOCKERFILE_SIDE = _REPO / "supervisor-sidecar" / "Dockerfile"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def _extract_recipe(makefile_text: str, target: str) -> str:
    """Return the recipe (TAB-indented lines) for `target` from Makefile text.

    This is a static parser that does NOT invoke make. Using `make -n` is
    unsafe here because recipes contain `$(MAKE) -s ...` sub-make invocations
    which GNU Make executes even under `-n` by its command-recursion rule,
    and would attempt a real `docker build`.
    """
    pattern = re.compile(
        rf"(?ms)^{re.escape(target)}\s*:[^\n]*\n((?:\t[^\n]*\n|\n)+?)(?=^\S|\Z)"
    )
    match = pattern.search(makefile_text)
    assert match, f"recipe for target {target!r} not found in Makefile"
    return match.group(1)


def _make_run(target: str, **overrides: str) -> subprocess.CompletedProcess[str]:
    """Actually run `make <target>` (no dry-run). Safe only for cheap targets
    like `print-images` that have no side effects."""
    env_args = [f"{k}={v}" for k, v in overrides.items()]
    cmd = ["make", target, *env_args]
    return subprocess.run(cmd, cwd=_REPO, capture_output=True, text=True)


# ---------------------------------------------------------------------------
# A — Makefile exposes docker-build / docker-push / docker-release
# ---------------------------------------------------------------------------


def test_A1_makefile_defines_docker_build_target() -> None:
    text = _read(_MAKEFILE)
    # Target must exist as a real recipe target (not just a .PHONY line).
    assert re.search(r"(?m)^docker-build\s*:", text), (
        "docker-build target missing from Makefile — "
        "release-images workflow will fail at 'make docker-build'"
    )


def test_A2_makefile_defines_docker_push_target() -> None:
    text = _read(_MAKEFILE)
    assert re.search(r"(?m)^docker-push\s*:", text), (
        "docker-push target missing from Makefile — "
        "release-images workflow will fail at 'make docker-push'"
    )


def test_A3_makefile_defines_docker_release_target() -> None:
    text = _read(_MAKEFILE)
    assert re.search(r"(?m)^docker-release\s*:", text), (
        "docker-release target missing from Makefile"
    )


# ---------------------------------------------------------------------------
# B — docker-build recipe references the actual Dockerfiles
# ---------------------------------------------------------------------------


def test_B1_dockerfile_exists_at_repo_root() -> None:
    assert _DOCKERFILE_CORE.exists(), "root Dockerfile missing"


def test_B2_sidecar_dockerfile_exists() -> None:
    assert _DOCKERFILE_SIDE.exists(), "supervisor-sidecar/Dockerfile missing"


def test_B3_docker_build_invokes_real_docker_build_core() -> None:
    """docker-build must shell out to `docker build .` for the core image."""
    recipe = _extract_recipe(_read(_MAKEFILE), "docker-build")
    assert "docker build" in recipe, "docker-build must invoke `docker build`"
    # Must build the core image from repo root (`docker build ... .`).
    assert re.search(
        r"docker build[^\n]*(?:\\\n[^\n]*)*\n\s*\.(?:\s|$)",
        recipe,
    ) or re.search(r"docker build[^\n]*\s\.(?:\s|$)", recipe), (
        "docker-build must build the root Dockerfile (`docker build ... .`)"
    )
    # Must build the sidecar image from supervisor-sidecar/.
    assert "supervisor-sidecar" in recipe, (
        "docker-build must build the supervisor-sidecar/ Dockerfile"
    )


def test_B4_docker_build_is_not_an_echo_stub() -> None:
    """Guard against someone 'repairing' docker-build by making it an echo stub."""
    recipe = _extract_recipe(_read(_MAKEFILE), "docker-build")
    assert "docker build" in recipe
    # Belt-and-braces: ensure there is no `echo "docker build"` pretending.
    assert not re.search(r'echo\s+["\']docker build', recipe), (
        "docker-build recipe appears to echo-stub `docker build` instead of running it"
    )


# ---------------------------------------------------------------------------
# C — push-without-build is prevented (existence guard + workflow ordering)
# ---------------------------------------------------------------------------


def test_C1_docker_push_fails_closed_without_prior_build() -> None:
    """docker-push must fail immediately if the core image is absent locally.

    The canonical release workflow enforces build→push ordering at the workflow
    step level: the "Build images" step (`make docker-build`) runs before the
    "Push images" step (`make docker-push`) in the same job; step failure stops
    execution before push is attempted.  The Makefile target provides a
    belt-and-suspenders guard for direct invocations: if someone calls
    `make docker-push` without a prior `make docker-build`, the recipe detects
    the absent image via `docker image inspect` and exits non-zero immediately
    with an actionable error — no push attempt is made.
    """
    recipe = _extract_recipe(_read(_MAKEFILE), "docker-push")
    # Guard must inspect the image and branch on its absence.
    assert re.search(r"docker\s+image\s+inspect", recipe), (
        "docker-push must check image existence via `docker image inspect` "
        "before attempting any push"
    )
    # The absent-image branch must call `exit 1` (fail closed, not silently skip).
    assert "exit 1" in recipe, (
        "docker-push must call `exit 1` when the image is not found locally — "
        "silent return would allow a stale or missing image to go undetected"
    )
    # Error message must be actionable — the operator must know what to run.
    assert "docker-build" in recipe, (
        "docker-push error path must reference docker-build so the operator "
        "knows which target to run first"
    )

    # Workflow-level ordering: the release-images workflow must call
    # `make docker-build` in a step that appears before `make docker-push`.
    workflow_text = _read(_WORKFLOW)
    build_pos = workflow_text.find("make docker-build")
    push_pos = workflow_text.find("make docker-push")
    assert build_pos != -1, "release-images workflow must call `make docker-build`"
    assert push_pos != -1, "release-images workflow must call `make docker-push`"
    assert build_pos < push_pos, (
        "release-images workflow must invoke `make docker-build` before "
        "`make docker-push` — current ordering would allow push to run "
        "against an unbuilt image"
    )


def test_C2_docker_release_builds_and_pushes() -> None:
    """docker-release is the composite target used by operators."""
    text = _read(_MAKEFILE)
    match = re.search(r"(?m)^docker-release\s*:([^\n]*)$", text)
    assert match, "docker-release target line not found"
    deps = match.group(1).strip().split()
    assert "docker-build" in deps
    assert "docker-push" in deps


# ---------------------------------------------------------------------------
# D — release-images workflow calls `make docker-build` + `make docker-push`
# ---------------------------------------------------------------------------


def test_D1_workflow_file_exists() -> None:
    assert _WORKFLOW.exists(), "release-images.yml workflow is missing"


def test_D2_workflow_calls_make_docker_build() -> None:
    text = _read(_WORKFLOW)
    assert "make docker-build" in text, (
        "release-images workflow must invoke `make docker-build`"
    )


def test_D3_workflow_calls_make_docker_push() -> None:
    text = _read(_WORKFLOW)
    assert "make docker-push" in text, (
        "release-images workflow must invoke `make docker-push`"
    )


def test_D4_workflow_passes_required_env_vars_to_make() -> None:
    """Workflow must thread REGISTRY, IMAGE_OWNER, VERSION into make."""
    text = _read(_WORKFLOW)
    assert "REGISTRY=" in text
    assert "IMAGE_OWNER=" in text
    assert "VERSION=" in text


# ---------------------------------------------------------------------------
# E — IMAGE_OWNER lowercase normalization (GHCR requirement)
# ---------------------------------------------------------------------------


def test_E1_image_owner_normalized_lowercase() -> None:
    """GHCR rejects uppercase repository names; the Makefile must normalize.

    github.repository_owner may be mixed-case ('Arescoreadmin') and the
    workflow passes it through verbatim. The Makefile owns the normalization.
    """
    result = _make_run(
        "print-images",
        REGISTRY="ghcr.io",
        IMAGE_OWNER="Arescoreadmin",
        VERSION="edge-abc123",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ghcr.io/arescoreadmin/frostgate-core:edge-abc123" in result.stdout, (
        f"IMAGE_OWNER must be lowercased for GHCR; got:\n{result.stdout}"
    )
    assert (
        "ghcr.io/arescoreadmin/frostgate-supervisor-sidecar:edge-abc123"
        in result.stdout
    )


# ---------------------------------------------------------------------------
# F — REGISTRY / IMAGE_OWNER / VERSION resolve deterministically
# ---------------------------------------------------------------------------


def test_F1_print_images_includes_passed_version() -> None:
    result = _make_run(
        "print-images",
        REGISTRY="ghcr.io",
        IMAGE_OWNER="arescoreadmin",
        VERSION="v1.2.3",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "VERSION=v1.2.3" in result.stdout
    assert ":v1.2.3" in result.stdout


def test_F2_print_images_defaults_do_not_leak_through() -> None:
    """When operator passes concrete values, defaults must not override."""
    result = _make_run(
        "print-images",
        REGISTRY="example.registry.local",
        IMAGE_OWNER="myorg",
        VERSION="edge-xyz",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "example.registry.local/myorg/frostgate-core:edge-xyz" in result.stdout


# ---------------------------------------------------------------------------
# G — docker-build recipe includes the require-docker precondition
#     (static assertion: no real docker invocation during tests)
# ---------------------------------------------------------------------------


def test_G1_docker_build_recipe_requires_docker_cli() -> None:
    """docker-build must gate on the require-docker precondition.

    The recipe must invoke `$(MAKE) -s require-docker` so a runner without
    docker CLI fails fast with a clear message instead of attempting a
    doomed `docker build` call or silently returning success.
    """
    recipe = _extract_recipe(_read(_MAKEFILE), "docker-build")
    assert "require-docker" in recipe, (
        "docker-build recipe must call require-docker before `docker build`"
    )


def test_G2_docker_push_recipe_requires_docker_cli() -> None:
    """docker-push must also gate on require-docker."""
    recipe = _extract_recipe(_read(_MAKEFILE), "docker-push")
    assert "require-docker" in recipe, (
        "docker-push recipe must call require-docker before `docker push`"
    )

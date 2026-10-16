#!/usr/bin/env python3
"""Static gate: AWS audit resource lifecycle protection.

Enforces that every preserved AWS audit resource in `infra/aws_audit.tf`
declares `lifecycle { prevent_destroy = true }` at the Terraform static level.

Rationale (CUSTOMER-ZERO-RUN3-AWS-AUDIT-LIFECYCLE-001):
  The ceremony state records 6 AWS resources as PERSISTENT_AUDIT_AUTHORITY —
  4 WRITER (CloudWatch log group + IAM user/policy/attachment that streams
  Vault audit events) and 2 READER (IAM role + policy attachment for
  independent operator verification). Loss of any of these resources would
  destroy the audit boundary that the Customer-Zero trust ceremony depends on.
  `prevent_destroy` is a static-time Terraform guard: any `terraform destroy`
  (or plan that implies destruction) against a protected resource errors out
  before touching the cloud API.

What this gate does (and does not do):
  - Verifies the exact expected inventory of protected addresses is present
    in `infra/aws_audit.tf`.
  - Verifies each has `lifecycle { prevent_destroy = true }` directly inside
    its resource block (not inherited, not conditional).
  - Rejects `prevent_destroy = false` or duplicate lifecycle blocks.
  - Fails CLOSED on any parse/structural anomaly.
  - Does NOT run terraform. Does NOT touch state. Does NOT talk to AWS.

Exit codes:
  0 — all expected addresses present with `prevent_destroy = true`.
  1 — any address missing, unprotected, duplicated, or structurally invalid.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

AWS_AUDIT_TF_RELPATH = "infra/aws_audit.tf"

# Canonical inventory — mirrors customer_one/ceremony_state.yaml
# preserved_aws_resources list (6 entries, 4 WRITER + 2 READER).
WRITER_ADDRESSES: tuple[tuple[str, str], ...] = (
    ("aws_cloudwatch_log_group", "vault_audit"),
    ("aws_iam_user", "vault_audit"),
    ("aws_iam_policy", "vault_audit"),
    ("aws_iam_user_policy_attachment", "vault_audit"),
)
READER_ADDRESSES: tuple[tuple[str, str], ...] = (
    ("aws_iam_role", "vault_audit_reader"),
    ("aws_iam_role_policy_attachment", "vault_audit_reader"),
)
PROTECTED_ADDRESSES: tuple[tuple[str, str], ...] = WRITER_ADDRESSES + READER_ADDRESSES


@dataclass(frozen=True)
class ResourceBlock:
    """A parsed top-level `resource "type" "name" { ... }` block."""

    type_: str
    name: str
    body: str  # text between the opening `{` and matching closing `}`
    start: int
    end: int

    @property
    def address(self) -> str:
        return f"{self.type_}.{self.name}"


def _find_matching_brace(text: str, open_pos: int) -> int:
    """Return index of matching `}` for the `{` at `open_pos`.

    Depth counter honouring HCL quoted strings and `#`/`//` line comments.
    Raises IndexError on unbalanced input (triggers fail-closed in caller).
    """
    assert text[open_pos] == "{"
    depth = 0
    i = open_pos
    in_string = False
    while i < len(text):
        c = text[i]
        if in_string:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
            continue
        # line-comment skip
        if c == "#" or (c == "/" and i + 1 < len(text) and text[i + 1] == "/"):
            nl = text.find("\n", i)
            if nl == -1:
                return -1
            i = nl + 1
            continue
        if c == '"':
            in_string = True
            i += 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise IndexError("unbalanced braces")


def parse_resource_blocks(tf_text: str) -> list[ResourceBlock]:
    """Return every top-level `resource "..." "..." { ... }` block in order."""
    pattern = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')
    blocks: list[ResourceBlock] = []
    for m in pattern.finditer(tf_text):
        open_brace = m.end() - 1
        close_brace = _find_matching_brace(tf_text, open_brace)
        if close_brace == -1:
            raise ValueError(
                f"unterminated resource block for {m.group(1)}.{m.group(2)}"
            )
        body = tf_text[open_brace + 1 : close_brace]
        blocks.append(
            ResourceBlock(
                type_=m.group(1),
                name=m.group(2),
                body=body,
                start=m.start(),
                end=close_brace + 1,
            )
        )
    return blocks


def find_lifecycle_blocks(body: str) -> list[str]:
    """Return the inner text of every top-level `lifecycle { ... }` block.

    Nested lifecycle references inside quoted strings or deeper blocks are
    ignored by requiring `lifecycle` to appear only at depth-0 of `body`.
    """
    results: list[str] = []
    i = 0
    depth = 0
    in_string = False
    while i < len(body):
        c = body[i]
        if in_string:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
            continue
        if c == "#" or (c == "/" and i + 1 < len(body) and body[i + 1] == "/"):
            nl = body.find("\n", i)
            i = nl + 1 if nl != -1 else len(body)
            continue
        if c == '"':
            in_string = True
            i += 1
            continue
        if c == "{":
            depth += 1
            i += 1
            continue
        if c == "}":
            depth -= 1
            i += 1
            continue
        if depth == 0 and body.startswith("lifecycle", i):
            # must be a word boundary and followed (after whitespace) by `{`
            after = i + len("lifecycle")
            if after < len(body) and body[i - 1 : i].isalnum() if i > 0 else False:
                i += 1
                continue
            j = after
            while j < len(body) and body[j].isspace():
                j += 1
            if j < len(body) and body[j] == "{":
                try:
                    close = _find_matching_brace(body, j)
                except IndexError:
                    raise ValueError("unterminated lifecycle block")
                if close == -1:
                    raise ValueError("unterminated lifecycle block")
                results.append(body[j + 1 : close])
                i = close + 1
                continue
        i += 1
    return results


_PREVENT_DESTROY_TRUE = re.compile(
    r"\bprevent_destroy\s*=\s*true\b",
)
_PREVENT_DESTROY_FALSE = re.compile(
    r"\bprevent_destroy\s*=\s*false\b",
)
_PREVENT_DESTROY_ANY = re.compile(
    r"\bprevent_destroy\s*=",
)


def check_tf_file(tf_path: Path) -> tuple[bool, list[str]]:
    """Return (ok, messages). ok=False iff any protection is missing/invalid."""
    messages: list[str] = []
    try:
        tf_text = tf_path.read_text()
    except OSError as e:
        return False, [f"FAIL: cannot read {tf_path}: {e}"]

    try:
        blocks = parse_resource_blocks(tf_text)
    except (ValueError, IndexError) as e:
        return False, [f"FAIL: parse error in {tf_path}: {e}"]

    by_address: dict[str, list[ResourceBlock]] = {}
    for b in blocks:
        by_address.setdefault(b.address, []).append(b)

    ok = True
    for type_, name in PROTECTED_ADDRESSES:
        address = f"{type_}.{name}"
        matches = by_address.get(address, [])
        if not matches:
            messages.append(f"FAIL: expected resource {address} not found")
            ok = False
            continue
        if len(matches) > 1:
            messages.append(f"FAIL: resource {address} declared more than once")
            ok = False
            continue
        block = matches[0]
        try:
            lifecycles = find_lifecycle_blocks(block.body)
        except ValueError as e:
            messages.append(f"FAIL: {address}: {e}")
            ok = False
            continue
        if len(lifecycles) == 0:
            messages.append(
                f"FAIL: {address}: no lifecycle block (missing prevent_destroy = true)"
            )
            ok = False
            continue
        if len(lifecycles) > 1:
            messages.append(
                f"FAIL: {address}: duplicate lifecycle blocks ({len(lifecycles)} found)"
            )
            ok = False
            continue
        lc = lifecycles[0]
        if _PREVENT_DESTROY_FALSE.search(lc):
            messages.append(f"FAIL: {address}: prevent_destroy = false (must be true)")
            ok = False
            continue
        if not _PREVENT_DESTROY_TRUE.search(lc):
            if _PREVENT_DESTROY_ANY.search(lc):
                messages.append(
                    f"FAIL: {address}: prevent_destroy present but not literal 'true'"
                )
            else:
                messages.append(
                    f"FAIL: {address}: lifecycle block missing prevent_destroy"
                )
            ok = False
            continue
        messages.append(f"OK: {address} has lifecycle {{ prevent_destroy = true }}")

    return ok, messages


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Verify AWS audit resources are lifecycle-protected."
    )
    parser.add_argument(
        "--tf",
        default=None,
        help="Path to aws_audit.tf (default: repo-root/infra/aws_audit.tf)",
    )
    args = parser.parse_args(argv)

    if args.tf is not None:
        tf_path = Path(args.tf)
    else:
        # Resolve relative to repo root (script lives at tools/ci/)
        tf_path = Path(__file__).resolve().parent.parent.parent / AWS_AUDIT_TF_RELPATH

    ok, messages = check_tf_file(tf_path)
    for m in messages:
        print(m)
    if ok:
        print(
            f"PASS: all {len(PROTECTED_ADDRESSES)} AWS audit resources "
            f"({len(WRITER_ADDRESSES)} WRITER + {len(READER_ADDRESSES)} READER) "
            f"have lifecycle {{ prevent_destroy = true }}"
        )
        return 0
    print("FAIL: AWS audit lifecycle protection gate")
    return 1


if __name__ == "__main__":
    sys.exit(main())

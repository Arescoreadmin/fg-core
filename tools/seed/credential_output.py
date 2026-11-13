"""Owner-only credential files for operator seed tooling (CODEQL-REMEDIATE-003).

Seed tools mint live credentials (tenant API keys, portal passwords). Those
values must reach exactly one place: a file readable only by the invoking
operator. They must never be printed to stdout, where they land in terminal
scrollback, CI/agent transcripts and log collectors.

Shared by ``tools/seed/demo_tenants.py`` and ``tools/seed/run_seed.py`` only.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import stat
from pathlib import Path

PRIVATE_FILE_MODE = 0o600


class UnsafeCredentialPathError(OSError):
    """The credential file location could expose or redirect the write."""


def _trusted_owner(uid: int) -> bool:
    return uid in (os.getuid(), 0) if hasattr(os, "getuid") else True


def check_parent_dir(path: Path) -> None:
    """Refuse a parent that is a symlink, not ours, or writable by others.

    A group- or world-writable directory is accepted only with the sticky
    bit (for example ``/tmp``), where other users cannot replace our file.
    """
    parent = path.absolute().parent
    try:
        st = os.lstat(parent)
    except FileNotFoundError as exc:
        raise UnsafeCredentialPathError(
            f"credential directory does not exist: {parent}"
        ) from exc
    if not stat.S_ISDIR(st.st_mode):
        raise UnsafeCredentialPathError(
            f"credential directory is a symlink or not a directory: {parent}"
        )
    if not _trusted_owner(st.st_uid):
        raise UnsafeCredentialPathError(
            f"credential directory is owned by another user: {parent}"
        )
    sticky = bool(st.st_mode & stat.S_ISVTX)
    other_writable = bool(st.st_mode & stat.S_IWOTH)
    # Group-writable is tolerated only for the operator's own primary group
    # (the user-private-group default under umask 0002), as OpenSSH does.
    group_writable = bool(st.st_mode & stat.S_IWGRP) and not (
        hasattr(os, "getgid") and st.st_gid == os.getgid()
    )
    if (other_writable or group_writable) and not sticky:
        raise UnsafeCredentialPathError(
            f"credential directory is writable by other users: {parent}"
        )


def open_private_exclusive(path: Path) -> int:
    """Create ``path`` new with mode 0600 and return its descriptor.

    Fails if the path exists in any form, including as a symlink, so an
    operator's or another user's file is never overwritten.
    """
    check_parent_dir(path)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    fd = os.open(path, flags, PRIVATE_FILE_MODE)
    if hasattr(os, "fchmod"):
        os.fchmod(fd, PRIVATE_FILE_MODE)  # independent of the process umask
    return fd


def write_fd_text(fd: int, text: str) -> None:
    """Write all of ``text`` to ``fd``, fsync it, and close it."""
    try:
        data = memoryview(text.encode("utf-8"))
        while data:
            data = data[os.write(fd, data) :]
        os.fsync(fd)
    finally:
        os.close(fd)


def check_replace_target(path: Path) -> None:
    """Refuse a state-file location we must not replace.

    Call this before minting anything, so a refusal never strands freshly
    issued credentials. ``path`` must be absent or a regular file we own, in
    a safe directory; symlinks (including dangling ones) are refused.
    """
    check_parent_dir(path)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(st.st_mode) or not _trusted_owner(st.st_uid):
        raise UnsafeCredentialPathError(
            f"refusing to replace a symlink, special file or another "
            f"user's file: {path}"
        )


def write_private_text(path: Path, text: str) -> None:
    """Atomically replace our own file at ``path`` with ``text``, mode 0600.

    For a tool-owned state file that is rewritten on every run. The new
    content goes to a fresh 0600 file in the same directory and is renamed
    over ``path``, so readers and a failed write only ever see the previous
    complete file or the new one, and a hardlink to the old file is never
    written through.
    """
    check_replace_target(path)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd = open_private_exclusive(tmp)
    try:
        write_fd_text(fd, text)  # fsyncs and closes fd
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    _fsync_dir(path.parent)


def _fsync_dir(directory: Path) -> None:
    """Persist the rename itself; best effort where directories can't fsync."""
    if not hasattr(os, "O_DIRECTORY"):
        return
    try:
        dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(dfd)
    except OSError:
        pass
    finally:
        os.close(dfd)

"""Tests for in-memory repository implementations."""

from __future__ import annotations

import os
from datetime import datetime, timezone

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")


from api.identity_administration.models import (
    AdminActionType,
    AdminAuditRecord,
    Group,
    GroupMember,
    IdentityRecord,
    Invitation,
    InvitationStatus,
)
from api.identity_administration.repositories.memory import (
    InMemoryAuditRepository,
    InMemoryGroupRepository,
    InMemoryIdentityRepository,
    InMemoryInvitationRepository,
)
from api.identity_governance.models import IdentityLifecycleState

TENANT_A = "tenant-repo-a"
TENANT_B = "tenant-repo-b"


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _make_identity(
    tenant_id: str = TENANT_A,
    subject: str = "sub-001",
    email: str = "test@example.com",
) -> IdentityRecord:
    now = _now()
    return IdentityRecord(
        record_id="rec-001",
        tenant_id=tenant_id,
        subject=subject,
        email=email,
        display_name="Test User",
        lifecycle_state=IdentityLifecycleState.CREATED,
        created_at=now,
        updated_at=now,
    )


def _make_invitation(
    tenant_id: str = TENANT_A,
    invitation_id: str = "inv-001",
    email: str = "test@example.com",
    token_hash: str = "abc" * 21 + "a",  # 64 chars
) -> Invitation:
    now = _now()
    return Invitation(
        invitation_id=invitation_id,
        tenant_id=tenant_id,
        email=email,
        token_hash=token_hash,
        invited_by="admin-sub",
        invited_at=now,
        expires_at=now,
        status=InvitationStatus.PENDING,
    )


def _make_group(
    tenant_id: str = TENANT_A,
    group_id: str = "grp-001",
    name: str = "Engineering",
) -> Group:
    now = _now()
    return Group(
        group_id=group_id,
        tenant_id=tenant_id,
        name=name,
        description="",
        created_by="admin-sub",
        created_at=now,
        updated_at=now,
    )


def _make_audit(
    tenant_id: str = TENANT_A,
    subject: str = "sub-001",
    audit_id: str = "aud-001",
) -> AdminAuditRecord:
    return AdminAuditRecord(
        audit_id=audit_id,
        tenant_id=tenant_id,
        action=AdminActionType.INVITE,
        actor="admin-sub",
        subject=subject,
        occurred_at=_now(),
        reason="test",
        previous_state="CREATED",
        new_state="INVITED",
    )


class TestInMemoryIdentityRepository:
    def test_create_and_get(self) -> None:
        repo = InMemoryIdentityRepository()
        record = _make_identity()
        repo.create(record)
        fetched = repo.get(TENANT_A, "sub-001")
        assert fetched is not None
        assert fetched.subject == "sub-001"

    def test_get_returns_none_for_unknown(self) -> None:
        repo = InMemoryIdentityRepository()
        assert repo.get(TENANT_A, "no-such") is None

    def test_cross_tenant_isolation(self) -> None:
        repo = InMemoryIdentityRepository()
        repo.create(_make_identity(tenant_id=TENANT_A, subject="sub-001"))
        assert repo.get(TENANT_B, "sub-001") is None

    def test_update_replaces_record(self) -> None:
        repo = InMemoryIdentityRepository()
        record = _make_identity()
        repo.create(record)
        from dataclasses import replace

        updated = replace(record, display_name="Updated Name")
        repo.update(updated)
        fetched = repo.get(TENANT_A, "sub-001")
        assert fetched is not None
        assert fetched.display_name == "Updated Name"

    def test_list_for_tenant(self) -> None:
        repo = InMemoryIdentityRepository()
        repo.create(_make_identity(subject="sub-001", email="a@b.com"))
        repo.create(_make_identity(subject="sub-002", email="c@d.com"))
        records = repo.list_for_tenant(TENANT_A, limit=10, offset=0)
        assert len(records) == 2

    def test_search_by_email(self) -> None:
        repo = InMemoryIdentityRepository()
        repo.create(_make_identity(subject="sub-001", email="alice@example.com"))
        repo.create(_make_identity(subject="sub-002", email="bob@example.com"))
        results = repo.search(TENANT_A, "alice", [], limit=10, offset=0)
        assert len(results) == 1
        assert results[0].subject == "sub-001"

    def test_count_for_tenant(self) -> None:
        repo = InMemoryIdentityRepository()
        repo.create(_make_identity(subject="sub-001", email="a@b.com"))
        repo.create(_make_identity(subject="sub-002", email="c@d.com"))
        assert repo.count_for_tenant(TENANT_A) == 2


class TestInMemoryInvitationRepository:
    def test_create_and_get(self) -> None:
        repo = InMemoryInvitationRepository()
        inv = _make_invitation()
        repo.create(inv)
        fetched = repo.get(TENANT_A, "inv-001")
        assert fetched is not None
        assert fetched.invitation_id == "inv-001"

    def test_get_by_token_hash(self) -> None:
        repo = InMemoryInvitationRepository()
        inv = _make_invitation(token_hash="x" * 64)
        repo.create(inv)
        fetched = repo.get_by_token_hash("x" * 64)
        assert fetched is not None
        assert fetched.invitation_id == "inv-001"

    def test_get_pending_for_email(self) -> None:
        repo = InMemoryInvitationRepository()
        inv = _make_invitation(email="pending@example.com")
        repo.create(inv)
        fetched = repo.get_pending_for_email(TENANT_A, "pending@example.com")
        assert fetched is not None
        assert fetched.status == InvitationStatus.PENDING

    def test_get_pending_returns_none_after_accept(self) -> None:
        repo = InMemoryInvitationRepository()
        inv = _make_invitation()
        repo.create(inv)
        from dataclasses import replace

        accepted = replace(inv, status=InvitationStatus.ACCEPTED)
        repo.update(accepted)
        result = repo.get_pending_for_email(TENANT_A, "test@example.com")
        assert result is None

    def test_cross_tenant_isolation(self) -> None:
        repo = InMemoryInvitationRepository()
        repo.create(_make_invitation(tenant_id=TENANT_A))
        assert repo.get(TENANT_B, "inv-001") is None


class TestInMemoryGroupRepository:
    def test_create_and_get(self) -> None:
        repo = InMemoryGroupRepository()
        group = _make_group()
        repo.create(group)
        fetched = repo.get(TENANT_A, "grp-001")
        assert fetched is not None
        assert fetched.name == "Engineering"

    def test_add_member_and_list(self) -> None:
        repo = InMemoryGroupRepository()
        repo.create(_make_group())
        member = GroupMember(
            group_id="grp-001",
            tenant_id=TENANT_A,
            subject="sub-001",
            added_by="admin",
            added_at=_now(),
        )
        repo.add_member(member)
        members = repo.list_members(TENANT_A, "grp-001")
        assert len(members) == 1
        assert members[0].subject == "sub-001"

    def test_remove_member(self) -> None:
        repo = InMemoryGroupRepository()
        repo.create(_make_group())
        member = GroupMember(
            group_id="grp-001",
            tenant_id=TENANT_A,
            subject="sub-001",
            added_by="admin",
            added_at=_now(),
        )
        repo.add_member(member)
        repo.remove_member(TENANT_A, "grp-001", "sub-001")
        members = repo.list_members(TENANT_A, "grp-001")
        assert len(members) == 0

    def test_cross_tenant_isolation(self) -> None:
        repo = InMemoryGroupRepository()
        repo.create(_make_group(tenant_id=TENANT_A))
        assert repo.get(TENANT_B, "grp-001") is None


class TestInMemoryAuditRepository:
    def test_create_and_list_for_subject(self) -> None:
        repo = InMemoryAuditRepository()
        audit = _make_audit()
        repo.create(audit)
        records = repo.list_for_subject(TENANT_A, "sub-001", limit=10, offset=0)
        assert len(records) == 1
        assert records[0].audit_id == "aud-001"

    def test_list_for_tenant(self) -> None:
        repo = InMemoryAuditRepository()
        repo.create(_make_audit(subject="sub-001", audit_id="aud-001"))
        repo.create(_make_audit(subject="sub-002", audit_id="aud-002"))
        records = repo.list_for_tenant(TENANT_A, limit=10, offset=0)
        assert len(records) == 2

    def test_cross_tenant_isolation(self) -> None:
        repo = InMemoryAuditRepository()
        repo.create(_make_audit(tenant_id=TENANT_A))
        records = repo.list_for_tenant(TENANT_B, limit=10, offset=0)
        assert len(records) == 0

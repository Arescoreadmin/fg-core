"""Tests for GroupService and group repository."""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

import pytest

from api.identity_administration.groups import GroupService
from api.identity_administration.repositories.memory import InMemoryGroupRepository

TENANT_A = "tenant-groups-a"
TENANT_B = "tenant-groups-b"
ACTOR = "admin-subject-001"


@pytest.fixture
def repo() -> InMemoryGroupRepository:
    return InMemoryGroupRepository()


@pytest.fixture
def svc(repo: InMemoryGroupRepository) -> GroupService:
    return GroupService(group_repo=repo)


class TestCreateGroup:
    def test_create_group_persists(self, svc: GroupService) -> None:
        group = svc.create_group(TENANT_A, "Engineering", "Eng team", ACTOR)
        assert group.group_id != ""
        assert group.name == "Engineering"
        assert group.tenant_id == TENANT_A

    def test_get_group_returns_created(self, svc: GroupService) -> None:
        created = svc.create_group(TENANT_A, "Sales", "Sales team", ACTOR)
        fetched = svc.get_group(TENANT_A, created.group_id)
        assert fetched is not None
        assert fetched.group_id == created.group_id

    def test_list_groups_returns_all(self, svc: GroupService) -> None:
        svc.create_group(TENANT_A, "Group1", "", ACTOR)
        svc.create_group(TENANT_A, "Group2", "", ACTOR)
        groups, total = svc.list_groups(TENANT_A, limit=50, offset=0)
        assert len(groups) == 2
        assert total == 2


class TestMemberManagement:
    def test_add_member_persists_membership(self, svc: GroupService) -> None:
        group = svc.create_group(TENANT_A, "TeamA", "", ACTOR)
        member = svc.add_member(TENANT_A, group.group_id, "sub-001", ACTOR)
        assert member.subject == "sub-001"

    def test_remove_member_removes_membership(self, svc: GroupService) -> None:
        group = svc.create_group(TENANT_A, "TeamB", "", ACTOR)
        svc.add_member(TENANT_A, group.group_id, "sub-002", ACTOR)
        svc.remove_member(TENANT_A, group.group_id, "sub-002", ACTOR)
        members = svc.list_members(TENANT_A, group.group_id)
        assert len(members) == 0

    def test_list_members_returns_correct(self, svc: GroupService) -> None:
        group = svc.create_group(TENANT_A, "TeamC", "", ACTOR)
        svc.add_member(TENANT_A, group.group_id, "sub-001", ACTOR)
        svc.add_member(TENANT_A, group.group_id, "sub-002", ACTOR)
        members = svc.list_members(TENANT_A, group.group_id)
        subjects = {m.subject for m in members}
        assert subjects == {"sub-001", "sub-002"}

    def test_duplicate_member_addition_is_idempotent(self, svc: GroupService) -> None:
        group = svc.create_group(TENANT_A, "TeamD", "", ACTOR)
        svc.add_member(TENANT_A, group.group_id, "sub-003", ACTOR)
        svc.add_member(TENANT_A, group.group_id, "sub-003", ACTOR)
        members = svc.list_members(TENANT_A, group.group_id)
        # dict-based storage means same key overwrites — idempotent
        assert len(members) == 1


class TestCrossTenantIsolation:
    def test_group_from_tenant_a_not_visible_in_tenant_b(
        self, svc: GroupService
    ) -> None:
        group_a = svc.create_group(TENANT_A, "SecretGroupA", "", ACTOR)
        result = svc.get_group(TENANT_B, group_a.group_id)
        assert result is None

    def test_list_groups_does_not_leak_across_tenants(self, svc: GroupService) -> None:
        svc.create_group(TENANT_A, "GroupA", "", ACTOR)
        svc.create_group(TENANT_B, "GroupB", "", ACTOR)
        groups_a, _ = svc.list_groups(TENANT_A, limit=50, offset=0)
        assert all(g.tenant_id == TENANT_A for g in groups_a)
        assert len(groups_a) == 1

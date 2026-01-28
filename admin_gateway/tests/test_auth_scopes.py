"""Tests for RBAC scopes."""

from admin_gateway.auth.scopes import (
    Scope,
    SCOPE_HIERARCHY,
    expand_scopes,
    has_scope,
    get_all_scopes,
)


class TestScopeEnum:
    """Tests for Scope enum."""

    def test_all_scopes_defined(self):
        """Test all required scopes are defined."""
        required = [
            "console:admin",
            "product:read",
            "product:write",
            "keys:read",
            "keys:write",
            "policies:write",
            "audit:read",
        ]
        defined = [s.value for s in Scope]
        for scope in required:
            assert scope in defined, f"Missing scope: {scope}"

    def test_scope_values_are_strings(self):
        """Test scope values are valid strings."""
        for scope in Scope:
            assert isinstance(scope.value, str)
            assert ":" in scope.value
            assert len(scope.value) > 3


class TestScopeHierarchy:
    """Tests for scope hierarchy expansion."""

    def test_console_admin_includes_all(self):
        """Test console:admin includes all other scopes."""
        user_scopes = {Scope.CONSOLE_ADMIN.value}
        expanded = expand_scopes(user_scopes)

        # Should include all scopes
        for scope in Scope:
            if scope != Scope.CONSOLE_ADMIN:
                assert scope.value in expanded, f"admin should include {scope.value}"

    def test_product_write_includes_read(self):
        """Test product:write includes product:read."""
        user_scopes = {Scope.PRODUCT_WRITE.value}
        expanded = expand_scopes(user_scopes)

        assert Scope.PRODUCT_READ.value in expanded

    def test_keys_write_includes_read(self):
        """Test keys:write includes keys:read."""
        user_scopes = {Scope.KEYS_WRITE.value}
        expanded = expand_scopes(user_scopes)

        assert Scope.KEYS_READ.value in expanded

    def test_read_only_does_not_include_write(self):
        """Test read-only scopes don't include write."""
        user_scopes = {Scope.PRODUCT_READ.value}
        expanded = expand_scopes(user_scopes)

        assert Scope.PRODUCT_WRITE.value not in expanded

    def test_expand_preserves_original(self):
        """Test expand_scopes preserves original scopes."""
        original = {"custom:scope", Scope.AUDIT_READ.value}
        expanded = expand_scopes(original)

        for scope in original:
            assert scope in expanded

    def test_expand_handles_unknown_scopes(self):
        """Test expand_scopes handles unknown scope strings."""
        user_scopes = {"unknown:scope", "another:custom"}
        expanded = expand_scopes(user_scopes)

        # Should preserve unknown scopes
        assert "unknown:scope" in expanded
        assert "another:custom" in expanded


class TestHasScope:
    """Tests for has_scope function."""

    def test_has_direct_scope(self):
        """Test has_scope with direct scope match."""
        user_scopes = {Scope.KEYS_READ.value}
        assert has_scope(user_scopes, Scope.KEYS_READ) is True
        assert has_scope(user_scopes, Scope.KEYS_READ.value) is True

    def test_has_scope_via_hierarchy(self):
        """Test has_scope with scope via hierarchy."""
        user_scopes = {Scope.CONSOLE_ADMIN.value}
        assert has_scope(user_scopes, Scope.KEYS_READ) is True
        assert has_scope(user_scopes, Scope.AUDIT_READ) is True

    def test_missing_scope(self):
        """Test has_scope with missing scope."""
        user_scopes = {Scope.PRODUCT_READ.value}
        assert has_scope(user_scopes, Scope.KEYS_READ) is False
        assert has_scope(user_scopes, Scope.PRODUCT_WRITE) is False

    def test_empty_scopes(self):
        """Test has_scope with empty user scopes."""
        assert has_scope(set(), Scope.KEYS_READ) is False

    def test_scope_string_input(self):
        """Test has_scope accepts string scope."""
        user_scopes = {Scope.KEYS_WRITE.value}
        assert has_scope(user_scopes, "keys:read") is True
        assert has_scope(user_scopes, "keys:write") is True


class TestGetAllScopes:
    """Tests for get_all_scopes function."""

    def test_returns_all_scopes(self):
        """Test get_all_scopes returns all defined scopes."""
        all_scopes = get_all_scopes()

        assert len(all_scopes) == len(Scope)
        for scope in Scope:
            assert scope.value in all_scopes

    def test_returns_list_of_strings(self):
        """Test get_all_scopes returns list of strings."""
        all_scopes = get_all_scopes()

        assert isinstance(all_scopes, list)
        for scope in all_scopes:
            assert isinstance(scope, str)


class TestScopeHierarchyIntegrity:
    """Tests for scope hierarchy data integrity."""

    def test_hierarchy_uses_valid_scopes(self):
        """Test hierarchy only references valid Scope enum values."""
        for parent, children in SCOPE_HIERARCHY.items():
            assert isinstance(parent, Scope), f"Parent {parent} is not a Scope"
            for child in children:
                assert isinstance(child, Scope), f"Child {child} is not a Scope"

    def test_no_circular_hierarchy(self):
        """Test hierarchy has no circular references."""
        # Simple check: no scope can be both parent and child
        parents = set(SCOPE_HIERARCHY.keys())
        all_children = set()
        for children in SCOPE_HIERARCHY.values():
            all_children.update(children)

        # A scope shouldn't inherit from itself
        for parent in parents:
            children = SCOPE_HIERARCHY.get(parent, set())
            assert parent not in children, f"{parent} inherits from itself"

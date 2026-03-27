#!/usr/bin/env python3
from pathlib import Path

FILE = Path("tests/test_key_lifecycle.py")
content = FILE.read_text()


def insert_into_class(content: str, class_name: str, snippet: str) -> str:
    if snippet.strip() in content:
        return content  # already inserted

    lines = content.splitlines()
    new_lines = []
    inside_class = False
    inserted = False

    for i, line in enumerate(lines):
        new_lines.append(line)

        if line.startswith(f"class {class_name}"):
            inside_class = True
            continue

        if inside_class:
            # detect next class or end of file
            if line.startswith("class ") and not line.startswith(f"class {class_name}"):
                if not inserted:
                    new_lines.insert(len(new_lines) - 1, snippet)
                    inserted = True
                inside_class = False

    # if class is last in file
    if inside_class and not inserted:
        new_lines.append(snippet)

    return "\n".join(new_lines)


mint_test = """
    def test_mint_key_allows_unscoped_keys(self, fresh_db):
        \"\"\"mint_key should allow keys without tenant_id for unscoped flows.\"\"\"
        key = mint_key("read", ttl_seconds=86400)

        result = verify_api_key_detailed(raw=key)

        assert result.valid
        assert result.tenant_id is None
""".rstrip()

rotate_test = """
    def test_rotate_key_without_explicit_tenant_uses_db_bound_tenant(self, fresh_db):
        \"\"\"Rotation should work without explicit tenant_id for compatibility flows.\"\"\"
        key = mint_key("read", ttl_seconds=86400, tenant_id="tenant-a")
        prefix = key.split(".")[0]

        result = rotate_api_key_by_prefix(prefix, ttl_seconds=3600)

        assert result["old_prefix"] == prefix
        assert result["tenant_id"] == "tenant-a"
        assert result["old_key_revoked"] is True

        new_key = result["new_key"]
        new_result = verify_api_key_detailed(raw=new_key)
        assert new_result.valid
        assert new_result.tenant_id == "tenant-a"

        old_result = verify_api_key_detailed(raw=key)
        assert not old_result.valid
""".rstrip()


# Insert into classes
updated = content
updated = insert_into_class(updated, "TestUsageTracking", mint_test)
updated = insert_into_class(updated, "TestKeyRotation", rotate_test)

FILE.write_text(updated)

print("Patched tests/test_key_lifecycle.py successfully.")

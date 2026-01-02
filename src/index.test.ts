import { describe, expect, it } from "vitest";
import {
  type Permission,
  type PermissionType,
  addPermission,
  checkPermission,
  checkPermissions,
  createPermission,
  createPermissions,
  deserializePermissions,
  expandPermissions,
  filterPermissionsByType,
  getMatchingPermissions,
  hasRootAccess,
  intersectPermissions,
  mergePermissions,
  removePermission,
  serializePermissions,
  sortPermissions,
  subtractPermissions,
  validatePermissionPattern,
} from "./index.js";

// Utility functions for common ACL patterns

/**
 * Create a user-specific permissions array with common patterns
 */
function createUserPermissions(userId: string): Permission[] {
  return createPermissions([
    ["allow", `user.${userId}.edit`],
    ["allow", `user.${userId}.read`],
    ["allow", "discussion.*.read"],
    ["deny", "admin.*"],
  ]);
}

/**
 * Create an admin permissions array
 */
function createAdminPermissions(): Permission[] {
  return createPermissions([
    ["allow", "*"], // Root access
  ]);
}

/**
 * Create a moderator permissions array
 */
function createModeratorPermissions(): Permission[] {
  return createPermissions([
    ["allow", "discussion.*.moderate"],
    ["allow", "discussion.*.delete"],
    ["allow", "discussion.*.read"],
    ["allow", "user.*.read"],
    ["allow", "user.*.suspend"],
    ["deny", "user.*.delete"],
    ["deny", "admin.*"],
  ]);
}

describe("Permission Creation and Management", () => {
  describe("createPermission", () => {
    it("should create permission correctly", () => {
      const permission = createPermission("allow", "discussion.1234.moderate");

      expect(permission).toEqual({
        type: "allow",
        pattern: "discussion.1234.moderate",
        parts: ["discussion", "1234", "moderate"],
        isRoot: false,
      });
    });

    it("should identify root permissions", () => {
      const rootPermission = createPermission("allow", "*");
      expect(rootPermission.isRoot).toBe(true);
    });

    it("should throw error for invalid patterns", () => {
      expect(() => createPermission("allow", "")).toThrow("Permission pattern cannot be empty");
      expect(() => createPermission("allow", "   ")).toThrow("Permission pattern cannot be empty");
      expect(() => createPermission("allow", null as any)).toThrow("Permission pattern must be a non-empty string");
      expect(() => createPermission("allow", undefined as any)).toThrow(
        "Permission pattern must be a non-empty string",
      );
    });

    it("should handle whitespace in patterns correctly", () => {
      const permission = createPermission("allow", "  discussion.1234.moderate  ");
      expect(permission.pattern).toBe("discussion.1234.moderate");
    });
  });

  describe("addPermission", () => {
    it("should add permission to empty array", () => {
      const permissions: Permission[] = [];
      const newPermissions = addPermission(permissions, "allow", "discussion.1234.moderate");

      expect(newPermissions).toHaveLength(1);
      expect(newPermissions[0]!.pattern).toBe("discussion.1234.moderate");
      expect(permissions).toHaveLength(0); // Original array unchanged
    });

    it("should add permission to existing array", () => {
      const permissions = [createPermission("allow", "user.profile.read")];
      const newPermissions = addPermission(permissions, "deny", "admin.*");

      expect(newPermissions).toHaveLength(2);
      expect(newPermissions[0]!.pattern).toBe("admin.*");
    });
  });

  describe("removePermission", () => {
    it("should remove matching permission", () => {
      const permissions = [createPermission("allow", "discussion.1234.moderate"), createPermission("deny", "admin.*")];

      const newPermissions = removePermission(permissions, "allow", "discussion.1234.moderate");
      expect(newPermissions).toHaveLength(1);
      expect(newPermissions[0]!.pattern).toBe("admin.*");
    });

    it("should return unchanged array when no match", () => {
      const permissions = [createPermission("allow", "discussion.1234.moderate")];
      const newPermissions = removePermission(permissions, "deny", "nonexistent.pattern");

      expect(newPermissions).toHaveLength(1);
      expect(newPermissions[0]!.pattern).toBe("discussion.1234.moderate");
    });
  });

  describe("createPermissions", () => {
    it("should create multiple permissions from tuples", () => {
      const permissions = createPermissions([
        ["allow", "discussion.*.read"],
        ["deny", "admin.*"],
        ["allow", "user.1234.edit"],
      ]);

      expect(permissions).toHaveLength(3);
      expect(permissions[0]!.type).toBe("deny");
      expect(permissions[1]!.type).toBe("allow");
      expect(permissions[2]!.pattern).toBe("user.1234.edit");
    });
  });
});

describe("Permission Checking", () => {
  describe("checkPermission", () => {
    it("should allow access when permission matches exactly", () => {
      const permissions = [createPermission("allow", "discussion.1234.moderate")];
      expect(checkPermission(permissions, "discussion.1234.moderate")).toBe(true);
    });

    it("should deny access when no permissions match", () => {
      const permissions = [createPermission("allow", "discussion.1234.moderate")];
      expect(checkPermission(permissions, "discussion.5678.moderate")).toBe(false);
      expect(checkPermission(permissions, "user.profile.edit")).toBe(false);
    });

    it("should deny access when explicitly denied", () => {
      const permissions = [createPermission("deny", "discussion.1234.moderate")];
      expect(checkPermission(permissions, "discussion.1234.moderate")).toBe(false);
    });

    it("should handle invalid resource inputs", () => {
      const permissions = [createPermission("allow", "discussion.1234.moderate")];

      expect(checkPermission(permissions, "")).toBe(false);
      expect(checkPermission(permissions, "   ")).toBe(false);
      expect(checkPermission(permissions, null as any)).toBe(false);
      expect(checkPermission(permissions, undefined as any)).toBe(false);
    });

    it("should handle empty permissions array", () => {
      expect(checkPermission([], "any.resource")).toBe(false);
    });
  });

  describe("Wildcard Matching", () => {
    const permissions = createPermissions([
      ["allow", "discussion.*.read"],
      ["allow", "user.1234.*"],
      ["deny", "admin.*"],
      ["allow", "*.public.view"],
    ]);

    it("should match wildcards in the middle", () => {
      expect(checkPermission(permissions, "discussion.1234.read")).toBe(true);
      expect(checkPermission(permissions, "discussion.5678.read")).toBe(true);
      expect(checkPermission(permissions, "discussion.abc.read")).toBe(true);
    });

    it("should match wildcards at the end", () => {
      expect(checkPermission(permissions, "user.1234.edit")).toBe(true);
      expect(checkPermission(permissions, "user.1234.delete")).toBe(true);
      expect(checkPermission(permissions, "user.1234.read")).toBe(true);
    });

    it("should match wildcards at the beginning", () => {
      expect(checkPermission(permissions, "discussion.public.view")).toBe(true);
      expect(checkPermission(permissions, "user.public.view")).toBe(true);
      expect(checkPermission(permissions, "file.public.view")).toBe(true);
    });

    it("should deny when wildcard pattern is denied", () => {
      expect(checkPermission(permissions, "admin.users")).toBe(false);
      expect(checkPermission(permissions, "admin.settings.edit")).toBe(false);
    });

    it("should not match when pattern length differs", () => {
      expect(checkPermission(permissions, "discussion.1234")).toBe(false); // Missing .read
      expect(checkPermission(permissions, "discussion.1234.read.extra")).toBe(false); // Extra segment
    });
  });

  describe("Precedence Rules (Deny > Allow)", () => {
    it("should deny when both allow and deny rules match", () => {
      const permissions = createPermissions([
        ["allow", "discussion.*.read"],
        ["deny", "discussion.1234.read"],
      ]);

      expect(checkPermission(permissions, "discussion.1234.read")).toBe(false);
      expect(checkPermission(permissions, "discussion.5678.read")).toBe(true);
    });

    it("should deny when broader deny rule overrides specific allow", () => {
      const permissions = createPermissions([
        ["allow", "discussion.1234.moderate"],
        ["deny", "discussion.*"],
      ]);

      expect(checkPermission(permissions, "discussion.1234.moderate")).toBe(false);
    });

    it("should deny when specific deny rule overrides broader allow", () => {
      const permissions = createPermissions([
        ["allow", "discussion.*"],
        ["deny", "discussion.sensitive.read"],
      ]);

      expect(checkPermission(permissions, "discussion.sensitive.read")).toBe(false);
      expect(checkPermission(permissions, "discussion.public.read")).toBe(true);
    });

    it("should handle complex precedence scenarios", () => {
      const permissions = createPermissions([
        ["allow", "*"], // Root allow
        ["deny", "admin.*"], // Deny admin
        ["allow", "admin.read.*"], // Allow admin read
        ["deny", "admin.read.sensitive"], // Deny sensitive
      ]);

      expect(checkPermission(permissions, "user.profile.edit")).toBe(true); // Root allows
      expect(checkPermission(permissions, "admin.users.delete")).toBe(false); // Admin denied
      expect(checkPermission(permissions, "admin.read.public")).toBe(false); // Admin still denied (broader deny wins)
      expect(checkPermission(permissions, "admin.read.sensitive")).toBe(false); // Explicitly denied
    });
  });

  describe("Root Access (*)", () => {
    it("should grant root access with allow *", () => {
      const permissions = [createPermission("allow", "*")];

      expect(hasRootAccess(permissions)).toBe(true);
      expect(checkPermission(permissions, "any.resource.action")).toBe(true);
      expect(checkPermission(permissions, "discussion.1234.moderate")).toBe(true);
      expect(checkPermission(permissions, "admin.users.delete")).toBe(true);
    });

    it("should deny root access with deny *", () => {
      const permissions = [createPermission("deny", "*")];

      expect(hasRootAccess(permissions)).toBe(false);
      expect(checkPermission(permissions, "any.resource.action")).toBe(false);
    });

    it("should prioritize deny * over allow *", () => {
      const permissions = createPermissions([
        ["allow", "*"],
        ["deny", "*"],
      ]);

      expect(hasRootAccess(permissions)).toBe(false);
      expect(checkPermission(permissions, "any.resource.action")).toBe(false);
    });

    it("should handle root access with other permissions", () => {
      const permissions = createPermissions([
        ["allow", "*"],
        ["deny", "admin.sensitive.*"],
      ]);

      expect(hasRootAccess(permissions)).toBe(true);
      expect(checkPermission(permissions, "user.profile.edit")).toBe(true);
      expect(checkPermission(permissions, "admin.sensitive.data")).toBe(false); // Specific deny wins
    });
  });
});

describe("getMatchingPermissions", () => {
  const permissions = createPermissions([
    ["allow", "discussion.*.read"],
    ["deny", "discussion.sensitive.*"],
    ["allow", "user.1234.edit"],
    ["allow", "*"],
  ]);

  it("should return all matching permissions", () => {
    const matches = getMatchingPermissions(permissions, "discussion.sensitive.read");

    expect(matches).toHaveLength(3);
    expect(matches.map((p) => p.pattern)).toContain("discussion.*.read");
    expect(matches.map((p) => p.pattern)).toContain("discussion.sensitive.*");
    expect(matches.map((p) => p.pattern)).toContain("*");
  });

  it("should return empty array for invalid input", () => {
    expect(getMatchingPermissions(permissions, "")).toEqual([]);
    expect(getMatchingPermissions(permissions, "   ")).toEqual([]);
    expect(getMatchingPermissions(permissions, null as any)).toEqual([]);
  });

  it("should return only root permission when only root matches", () => {
    const matches = getMatchingPermissions(permissions, "completely.new.resource");

    expect(matches).toHaveLength(1);
    expect(matches[0]!.pattern).toBe("*");
  });
});

describe("Utility Functions", () => {
  describe("createUserPermissions", () => {
    it("should create user permissions with correct patterns", () => {
      const permissions = createUserPermissions("1234");

      expect(checkPermission(permissions, "user.1234.edit")).toBe(true);
      expect(checkPermission(permissions, "user.1234.read")).toBe(true);
      expect(checkPermission(permissions, "discussion.anything.read")).toBe(true);
      expect(checkPermission(permissions, "admin.anything")).toBe(false);
      expect(checkPermission(permissions, "user.5678.edit")).toBe(false);
    });
  });

  describe("createAdminPermissions", () => {
    it("should create admin permissions with root access", () => {
      const permissions = createAdminPermissions();

      expect(hasRootAccess(permissions)).toBe(true);
      expect(checkPermission(permissions, "admin.users.delete")).toBe(true);
      expect(checkPermission(permissions, "user.anything.delete")).toBe(true);
      expect(checkPermission(permissions, "any.resource.action")).toBe(true);
    });
  });

  describe("createModeratorPermissions", () => {
    it("should create moderator permissions with correct patterns", () => {
      const permissions = createModeratorPermissions();

      // Can moderate discussions
      expect(checkPermission(permissions, "discussion.1234.moderate")).toBe(true);
      expect(checkPermission(permissions, "discussion.5678.delete")).toBe(true);
      expect(checkPermission(permissions, "discussion.anything.read")).toBe(true);

      // Can read and suspend users but not delete
      expect(checkPermission(permissions, "user.1234.read")).toBe(true);
      expect(checkPermission(permissions, "user.1234.suspend")).toBe(true);
      expect(checkPermission(permissions, "user.1234.delete")).toBe(false);

      // No admin access
      expect(checkPermission(permissions, "admin.settings")).toBe(false);
      expect(hasRootAccess(permissions)).toBe(false);
    });
  });

  describe("mergePermissions", () => {
    it("should merge multiple permission arrays and deduplicate", () => {
      const userPerms = createUserPermissions("1234");
      const moderatorPerms = createModeratorPermissions();

      const merged = mergePermissions(userPerms, moderatorPerms);

      // Deduplication: userPerms has 4, moderatorPerms has 7
      // Duplicates: discussion.*.read (allow) and admin.* (deny)
      // Expected: 4 + 7 - 2 = 9
      expect(merged.length).toBe(9);

      // Should have both user and moderator capabilities
      expect(checkPermission(merged, "user.1234.edit")).toBe(true);
      expect(checkPermission(merged, "discussion.anything.moderate")).toBe(true);
    });

    it("should not deduplicate permissions with different types", () => {
      const perms1 = createPermissions([["allow", "discussion.*.read"]]);
      const perms2 = createPermissions([["deny", "discussion.*.read"]]);

      const merged = mergePermissions(perms1, perms2);

      // Both should be present since they have different types
      expect(merged.length).toBe(2);
      expect(merged.filter((p) => p.pattern === "discussion.*.read")).toHaveLength(2);
    });
  });

  describe("filterPermissionsByType", () => {
    it("should filter permissions by type", () => {
      const permissions = createPermissions([
        ["allow", "discussion.*.read"],
        ["deny", "admin.*"],
        ["allow", "user.1234.edit"],
        ["deny", "user.*.delete"],
      ]);

      const allowPerms = filterPermissionsByType(permissions, "allow");
      const denyPerms = filterPermissionsByType(permissions, "deny");

      expect(allowPerms).toHaveLength(2);
      expect(denyPerms).toHaveLength(2);
      expect(allowPerms.every((p) => p.type === "allow")).toBe(true);
      expect(denyPerms.every((p) => p.type === "deny")).toBe(true);
    });
  });
});

describe("Edge Cases", () => {
  it("should handle empty pattern segments", () => {
    const permissions = [createPermission("allow", "discussion..read")]; // Empty middle segment

    expect(checkPermission(permissions, "discussion..read")).toBe(true);
    expect(checkPermission(permissions, "discussion.1234.read")).toBe(false);
  });

  it("should handle single segment patterns", () => {
    const permissions = createPermissions([
      ["allow", "admin"],
      ["deny", "guest"],
    ]);

    expect(checkPermission(permissions, "admin")).toBe(true);
    expect(checkPermission(permissions, "guest")).toBe(false);
    expect(checkPermission(permissions, "user")).toBe(false);
  });

  it("should handle special characters in patterns", () => {
    const permissions = createPermissions([
      ["allow", "discussion.abc-123.read"],
      ["allow", "user.test@email.com.profile"],
    ]);

    expect(checkPermission(permissions, "discussion.abc-123.read")).toBe(true);
    expect(checkPermission(permissions, "user.test@email.com.profile")).toBe(true);
  });

  it("should be case sensitive", () => {
    const permissions = [createPermission("allow", "Discussion.1234.Read")];

    expect(checkPermission(permissions, "Discussion.1234.Read")).toBe(true);
    expect(checkPermission(permissions, "discussion.1234.read")).toBe(false);
  });
});

describe("Integration Tests", () => {
  it("should handle complex real-world scenario", () => {
    const permissions = createPermissions([
      // Base permissions
      ["allow", "discussion.*.read"],
      ["allow", "discussion.*.comment"],
      ["allow", "user.profile.*.read"],

      // Moderation permissions
      ["allow", "discussion.*.moderate"],
      ["allow", "discussion.*.delete"],

      // Restrictions
      ["deny", "discussion.archived.*"],
      ["deny", "discussion.*.delete.permanent"],
      ["deny", "admin.*"],

      // User-specific permissions
      ["allow", "user.1234.*"],
      ["deny", "user.1234.password.*"],
    ]);

    // Test various scenarios
    expect(checkPermission(permissions, "discussion.123.read")).toBe(true);
    expect(checkPermission(permissions, "discussion.123.comment")).toBe(true);
    expect(checkPermission(permissions, "discussion.123.moderate")).toBe(true);
    expect(checkPermission(permissions, "discussion.123.delete")).toBe(true);

    expect(checkPermission(permissions, "discussion.archived.read")).toBe(false);
    expect(checkPermission(permissions, "discussion.archived.moderate")).toBe(false);
    expect(checkPermission(permissions, "discussion.123.delete.permanent")).toBe(false);

    expect(checkPermission(permissions, "user.1234.profile.edit")).toBe(true);
    expect(checkPermission(permissions, "user.1234.settings.update")).toBe(true);
    expect(checkPermission(permissions, "user.1234.password.change")).toBe(false);

    expect(checkPermission(permissions, "admin.users.list")).toBe(false);

    expect(checkPermission(permissions, "user.profile.5678.read")).toBe(true);
  });

  it("should handle performance with many permissions", () => {
    // Create many permissions
    const manyPermissions: Array<[PermissionType, string]> = [];
    for (let i = 0; i < 1000; i++) {
      manyPermissions.push(["allow", `resource.${i}.action`]);
      manyPermissions.push(["deny", `restricted.${i}.*`]);
    }
    manyPermissions.push(["allow", "*.public.read"]);

    const permissions = createPermissions(manyPermissions);

    const start = Date.now();

    // Test performance
    for (let i = 0; i < 100; i++) {
      checkPermission(permissions, `resource.${i}.action`);
      checkPermission(permissions, "test.public.read");
      checkPermission(permissions, `restricted.${i}.something`);
    }

    const duration = Date.now() - start;
    expect(duration).toBeLessThan(100); // Should complete in reasonable time
  });
});

describe("Serialization", () => {
  describe("serializePermissions", () => {
    it("should serialize permissions to string", () => {
      const permissions = createPermissions([
        ["allow", "user.*.read"],
        ["deny", "admin.*"],
      ]);

      const serialized = serializePermissions(permissions);
      expect(serialized).toBe("deny:admin.*,allow:user.*.read");
    });

    it("should handle empty array", () => {
      expect(serializePermissions([])).toBe("");
    });

    it("should handle single permission", () => {
      const permissions = createPermissions([["allow", "*"]]);
      expect(serializePermissions(permissions)).toBe("allow:*");
    });
  });

  describe("deserializePermissions", () => {
    it("should deserialize string to permissions", () => {
      const data = "allow:user.*.read,deny:admin.*";
      const permissions = deserializePermissions(data);

      expect(permissions).toHaveLength(2);
      expect(permissions[0]!.type).toBe("allow");
      expect(permissions[0]!.pattern).toBe("user.*.read");
      expect(permissions[1]!.type).toBe("deny");
      expect(permissions[1]!.pattern).toBe("admin.*");
    });

    it("should handle empty string", () => {
      expect(deserializePermissions("")).toEqual([]);
      expect(deserializePermissions("   ")).toEqual([]);
    });

    it("should skip invalid entries gracefully", () => {
      const data = "allow:user.*,invalid-entry,deny:admin.*,badtype:*.read,,deny:*.write";
      const permissions = deserializePermissions(data);

      expect(permissions).toHaveLength(3); // Only valid entries
      expect(permissions[0]!.pattern).toBe("user.*");
      expect(permissions[1]!.pattern).toBe("admin.*");
      expect(permissions[2]!.pattern).toBe("*.write");
    });

    it("should handle round-trip serialization", () => {
      const original = createPermissions([
        ["allow", "user.*.read"],
        ["deny", "admin.*"],
        ["allow", "*.public.view"],
      ]);

      const serialized = serializePermissions(original);
      const deserialized = deserializePermissions(serialized);

      expect(deserialized).toHaveLength(original.length);
      expect(deserialized.map((p) => p.pattern)).toEqual(original.map((p) => p.pattern));
      expect(deserialized.map((p) => p.type)).toEqual(original.map((p) => p.type));
    });
  });
});

describe("Batch Operations", () => {
  describe("checkPermissions", () => {
    it("should check multiple resources at once", () => {
      const permissions = createPermissions([
        ["allow", "user.*.read"],
        ["deny", "admin.*"],
      ]);

      const results = checkPermissions(permissions, [
        "user.1234.read",
        "admin.panel",
        "user.5678.read",
        "discussion.read",
      ]);

      expect(results).toEqual([true, false, true, false]);
    });

    it("should return empty array for no resources", () => {
      const permissions = createPermissions([["allow", "*"]]);
      expect(checkPermissions(permissions, [])).toEqual([]);
    });

    it("should handle invalid resources", () => {
      const permissions = createPermissions([["allow", "*"]]);
      const results = checkPermissions(permissions, ["user.read", "", "admin.panel"]);

      expect(results).toEqual([true, false, true]);
    });
  });
});

describe("Permission Sorting", () => {
  describe("sortPermissions", () => {
    it("should sort deny before allow", () => {
      const permissions = createPermissions([
        ["allow", "user.read"],
        ["deny", "admin.*"],
      ]);

      const sorted = sortPermissions(permissions);

      expect(sorted[0]!.type).toBe("deny");
      expect(sorted[1]!.type).toBe("allow");
    });

    it("should sort root before wildcards before specific", () => {
      const permissions = createPermissions([
        ["allow", "user.1234.read"],
        ["deny", "*"],
        ["allow", "*.public"],
      ]);

      const sorted = sortPermissions(permissions);

      expect(sorted[0]!.isRoot).toBe(true);
      expect(sorted[0]!.pattern).toBe("*");
      expect(sorted[1]!.pattern).toBe("*.public");
      expect(sorted[2]!.pattern).toBe("user.1234.read");
    });

    it("should sort by pattern for same specificity", () => {
      const permissions = createPermissions([
        ["allow", "user.read"],
        ["allow", "admin.read"],
        ["allow", "*.public"],
      ]);

      const sorted = sortPermissions(permissions);

      // Wildcard first, then alphabetically
      expect(sorted[0]!.pattern).toBe("*.public");
      expect(sorted[1]!.pattern).toBe("admin.read");
      expect(sorted[2]!.pattern).toBe("user.read");
    });

    it("should not mutate original array", () => {
      const permissions = createPermissions([
        ["allow", "user.read"],
        ["deny", "admin.*"],
      ]);

      const originalOrder = permissions.map((p) => p.pattern);
      sortPermissions(permissions);

      expect(permissions.map((p) => p.pattern)).toEqual(originalOrder);
    });
  });
});

describe("Permission Math", () => {
  describe("intersectPermissions", () => {
    it("should find common permissions between two arrays", () => {
      const editors = createPermissions([
        ["allow", "content.*.edit"],
        ["allow", "content.*.read"],
        ["deny", "content.*.delete"],
      ]);

      const reviewers = createPermissions([
        ["allow", "content.*.read"],
        ["allow", "content.*.publish"],
      ]);

      const common = intersectPermissions(editors, reviewers);

      expect(common).toHaveLength(1);
      expect(common[0]!.pattern).toBe("content.*.read");
      expect(common[0]!.type).toBe("allow");
    });

    it("should handle empty arrays", () => {
      const perms = createPermissions([["allow", "user.read"]]);
      expect(intersectPermissions(perms, [])).toEqual([]);
      expect(intersectPermissions([])).toEqual([]);
    });

    it("should handle multiple arrays", () => {
      const arr1 = createPermissions([
        ["allow", "user.read"],
        ["allow", "admin.read"],
      ]);
      const arr2 = createPermissions([
        ["allow", "user.read"],
        ["deny", "admin.write"],
      ]);
      const arr3 = createPermissions([["allow", "user.read"]]);

      const common = intersectPermissions(arr1, arr2, arr3);

      expect(common).toHaveLength(1);
      expect(common[0]!.pattern).toBe("user.read");
    });

    it("should require both type and pattern to match", () => {
      const arr1 = createPermissions([
        ["allow", "user.read"],
        ["deny", "user.read"],
      ]);
      const arr2 = createPermissions([
        ["allow", "user.read"],
        ["deny", "admin.read"],
      ]);

      const common = intersectPermissions(arr1, arr2);

      expect(common).toHaveLength(1);
      expect(common[0]!.type).toBe("allow");
    });
  });

  describe("subtractPermissions", () => {
    it("should remove permissions that exist in both arrays", () => {
      const base = createPermissions([
        ["allow", "*"],
        ["deny", "system.*"],
        ["allow", "user.read"],
      ]);

      const remove = createPermissions([
        ["allow", "user.read"],
        ["deny", "admin.*"],
      ]);

      const result = subtractPermissions(base, remove);

      expect(result).toHaveLength(2);
      expect(result.map((p) => p.pattern)).not.toContain("user.read");
      expect(result.map((p) => p.pattern)).toContain("*");
      expect(result.map((p) => p.pattern)).toContain("system.*");
    });

    it("should return unchanged array if nothing to remove", () => {
      const base = createPermissions([["allow", "user.read"]]);
      const remove = createPermissions([["deny", "admin.*"]]);

      const result = subtractPermissions(base, remove);

      expect(result).toHaveLength(1);
      expect(result[0]!.pattern).toBe("user.read");
    });

    it("should return empty array if all removed", () => {
      const base = createPermissions([
        ["allow", "user.read"],
        ["deny", "admin.*"],
      ]);
      const remove = createPermissions([
        ["allow", "user.read"],
        ["deny", "admin.*"],
      ]);

      const result = subtractPermissions(base, remove);

      expect(result).toHaveLength(0);
    });
  });
});

describe("Permission Expansion", () => {
  describe("expandPermissions", () => {
    it("should show which resources each permission matches", () => {
      const permissions = createPermissions([
        ["allow", "user.*.read"],
        ["deny", "admin.*"],
      ]);

      const resources = [
        "user.1234.read",
        "user.5678.edit",
        "admin.users",
        "admin.settings.edit",
        "discussion.123.read",
      ];

      const expanded = expandPermissions(permissions, resources);

      expect(expanded).toHaveLength(2);
      expect(expanded[0]!.permission.pattern).toBe("admin.*");
      expect(expanded[0]!.matches).toEqual(["admin.users", "admin.settings.edit"]);
      expect(expanded[1]!.permission.pattern).toBe("user.*.read");
      expect(expanded[1]!.matches).toEqual(["user.1234.read"]);
    });

    it("should return empty matches for non-matching permissions", () => {
      const permissions = createPermissions([["allow", "user.*"]]);
      const resources = ["admin.panel", "discussion.read"];

      const expanded = expandPermissions(permissions, resources);

      expect(expanded).toHaveLength(1);
      expect(expanded[0]!.matches).toEqual([]);
    });

    it("should handle empty resource list", () => {
      const permissions = createPermissions([["allow", "user.*"]]);
      const expanded = expandPermissions(permissions, []);

      expect(expanded).toHaveLength(1);
      expect(expanded[0]!.matches).toEqual([]);
    });
  });
});

describe("Pattern Validation", () => {
  describe("validatePermissionPattern", () => {
    it("should validate correct patterns", () => {
      expect(validatePermissionPattern("user.*.read")).toEqual({ valid: true });
      expect(validatePermissionPattern("*")).toEqual({ valid: true });
      expect(validatePermissionPattern("admin")).toEqual({ valid: true });
      expect(validatePermissionPattern("a.b.c.d.e.f")).toEqual({ valid: true });
    });

    it("should reject invalid patterns", () => {
      expect(validatePermissionPattern("")).toEqual({
        valid: false,
        error: "Permission pattern cannot be empty",
      });
      expect(validatePermissionPattern("   ")).toEqual({
        valid: false,
        error: "Permission pattern cannot be empty",
      });
      expect(validatePermissionPattern(null as any)).toEqual({
        valid: false,
        error: "Permission pattern must be a non-empty string",
      });
      expect(validatePermissionPattern(undefined as any)).toEqual({
        valid: false,
        error: "Permission pattern must be a non-empty string",
      });
      expect(validatePermissionPattern(123 as any)).toEqual({
        valid: false,
        error: "Permission pattern must be a non-empty string",
      });
    });

    it("should trim whitespace before validation", () => {
      expect(validatePermissionPattern("  user.*.read  ")).toEqual({ valid: true });
      expect(validatePermissionPattern("  *  ")).toEqual({ valid: true });
    });
  });
});

/**
 * Functional Hierarchical Access Control Layer (ACL) Implementation.
 *
 * Pattern: domain.resource_identifier.permission.nuance
 * Supports wildcards (*) and precedence rules (deny > allow)
 */

/**
 * Permission type.
 *
 * - `"allow"` - Grants access to resources matching the pattern
 * - `"deny"` - Denies access to resources matching the pattern (takes precedence over allow)
 *
 * @example
 * ```ts
 * const type: PermissionType = "allow";
 * ```
 */
export type PermissionType = "allow" | "deny";

/**
 * Permission entry representing a single access control rule.
 *
 * @property {PermissionType} type - Whether this permission grants or denies access
 * @property {string} pattern - The dot-separated permission pattern (e.g., "user.*.read")
 * @property {string[]} parts - The pattern split into segments for efficient matching
 * @property {boolean} isRoot - Whether this is a root permission ("*"), which matches everything
 *
 * @example
 * ```ts
 * const permission: Permission = {
 *   type: "allow",
 *   pattern: "discussion.*.read",
 *   parts: ["discussion", "*", "read"],
 *   isRoot: false,
 * };
 * ```
 */
export interface Permission {
  type: PermissionType;
  pattern: string;
  parts: string[];
  isRoot: boolean;
}

/**
 * Create a permission object from a type and pattern.
 *
 * @param {PermissionType} type - Type of permission (`"allow"` or `"deny"`)
 * @param {string} pattern - Permission pattern (e.g., `"user.*.read"` or `"*"`)
 * @returns {Permission} New Permission object with parsed pattern segments
 * @throws {Error} If type is not `"allow"` or `"deny"`
 * @throws {Error} If pattern is not a non-empty string
 *
 * @example
 * ```ts
 * import { createPermission } from "@fimbul-works/acl";
 *
 * // Create a wildcard permission
 * const perm = createPermission("allow", "discussion.*.read");
 * // { type: "allow", pattern: "discussion.*.read", parts: ["discussion", "*", "read"], isRoot: false }
 *
 * // Create a root permission
 * const root = createPermission("allow", "*");
 * // { type: "allow", pattern: "*", parts: ["*"], isRoot: true }
 * ```
 */
export function createPermission(type: PermissionType, pattern: string): Permission {
  if (!["allow", "deny"].includes(type)) {
    throw new Error("Invalid permission type");
  }

  if (typeof pattern !== "string" || pattern === null || pattern === undefined) {
    throw new Error("Permission pattern must be a non-empty string");
  }

  const normalizedPattern = pattern.trim();
  if (normalizedPattern.length === 0) {
    throw new Error("Permission pattern cannot be empty");
  }

  const parts = normalizedPattern.split(".");
  const isRoot = normalizedPattern === "*";

  return {
    type,
    pattern: normalizedPattern,
    parts,
    isRoot,
  };
}

/**
 * Add a permission to an existing permissions array.
 *
 * This function does not mutate the original array - it returns a new array with the permission appended.
 *
 * @param {Permission[]} permissions - Existing array of permissions
 * @param {PermissionType} type - Type of permission (`"allow"`  or `"deny"`)
 * @param {string} pattern - Permission pattern (e.g., `"user.*.read"`)
 * @returns {Permission[]} New array with the permission added
 * @throws {Error} If type is not `"allow"` or `"deny"`
 * @throws {Error} If pattern is not a non-empty string
 *
 * @example
 * ```ts
 * import { addPermission, createPermission } from "@fimbul-works/acl";
 *
 * const permissions: Permission[] = [];
 * const updated = addPermission(permissions, "allow", "discussion.*.read");
 * // permissions is still [], updated has 1 permission
 * ```
 */
export function addPermission(permissions: Permission[], type: PermissionType, pattern: string): Permission[] {
  const permission = createPermission(type, pattern);
  return sortPermissions([...permissions, permission]);
}

/**
 * Remove a permission from an existing permissions array.
 *
 * Removes the first matching permission with the given type and pattern.
 * This function does not mutate the original array - it returns a new filtered array.
 *
 * @param {Permission[]} permissions - Existing array of permissions
 * @param {PermissionType} type - Type of permission to remove (`"allow"` or `"deny"`)
 * @param {string} pattern - Permission pattern to remove
 * @returns {Permission[]} New array with matching permissions removed
 *
 * @example
 * ```ts
 * import { removePermission, createPermissions } from "@fimbul-works/acl";
 *
 * const permissions = createPermissions([
 *   ["allow", "discussion.*.read"],
 *   ["deny", "admin.*"],
 * ]);
 *
 * const updated = removePermission(permissions, "deny", "admin.*");
 * // updated has 1 permission (admin.* was removed)
 * ```
 */
export function removePermission(permissions: Permission[], type: PermissionType, pattern: string): Permission[] {
  return permissions.filter((p) => !(p.type === type && p.pattern === pattern));
}

/**
 * Check if a resource pattern matches a permission pattern with wildcard support.
 *
 * @internal
 * @param {string[]} resourceParts - Array of resource parts (e.g., `["discussion", "1234", "read"]`)
 * @param {string[]} patternParts - Array of pattern parts (e.g., `["discussion", "*", "read"]`)
 * @returns {boolean} `true` if pattern matches, `false` otherwise
 *
 * @example
 * ```ts
 * matchesPattern(["discussion", "1234", "read"], ["discussion", "*", "read"]); // true
 * matchesPattern(["admin", "settings"], ["admin", "*"]); // true
 * ```
 */
function matchesPattern(resourceParts: string[], patternParts: string[]): boolean {
  // Check if pattern ends with a wildcard
  const endsWithWildcard = patternParts.length > 0 && patternParts[patternParts.length - 1] === "*";

  // If pattern doesn't end with wildcard, lengths must match exactly
  if (!endsWithWildcard && resourceParts.length !== patternParts.length) {
    return false;
  }

  // If pattern ends with wildcard, resource must be at least as long as pattern
  if (endsWithWildcard && resourceParts.length < patternParts.length) {
    return false;
  }

  // Check each pattern part against corresponding resource part
  for (let i = 0; i < patternParts.length; i++) {
    const resourcePart = resourceParts[i];
    const patternPart = patternParts[i];

    // Wildcard matches anything
    if (patternPart === "*") {
      // If this is the last pattern part and it's a wildcard, it matches everything remaining
      if (i === patternParts.length - 1) {
        return true;
      }
      continue;
    }

    // Exact match required
    if (resourcePart !== patternPart) {
      return false;
    }
  }

  return true;
}

/**
 * Get all permissions that would apply to a resource.
 *
 * This is useful for debugging or logging which permissions matched a given resource.
 * It includes both allow and deny permissions.
 *
 * @param {Permission[]} permissions - Array of Permission objects
 * @param {string} resource - Resource string to check (e.g., `"discussion.1234.read"`)
 * @returns {Permission[]} Array of matching Permissions (empty if no matches or invalid input)
 *
 * @example
 * ```ts
 * import { createPermissions, getMatchingPermissions } from "@fimbul-works/acl";
 *
 * const permissions = createPermissions([
 *   ["allow", "discussion.*.read"],
 *   ["deny", "discussion.sensitive.*"],
 *   ["allow", "*"],
 * ]);
 *
 * const matches = getMatchingPermissions(permissions, "discussion.sensitive.read");
 * // Returns all 3 permissions since they all match
 * ```
 */
export function getMatchingPermissions(permissions: Permission[], resource: string): Permission[] {
  if (typeof resource !== "string" || resource === null || resource === undefined) {
    return [];
  }

  const normalizedResource = resource.trim();
  if (normalizedResource.length === 0) {
    return [];
  }

  const resourceParts = normalizedResource.split(".");

  return permissions.filter((permission) => permission.isRoot || matchesPattern(resourceParts, permission.parts));
}

/**
 * Check if a resource access is permitted given a set of permissions.
 *
 * This is the main function for permission checking. It evaluates all matching permissions
 * and applies precedence rules:
 * 1. Root deny (`*`) overrides everything
 * 2. Explicit deny takes precedence over allow
 * 3. If no permissions match, access is denied (deny by default)
 *
 * @param {Permission[]} permissions - Array of Permission objects
 * @param {string} resource - Resource string to check (e.g., `"discussion.1234.read"`)
 * @returns {boolean} `true` if permissions allow access, `false` otherwise (including invalid input)
 *
 * @example
 * ```ts
 * import { createPermissions, checkPermission } from "@fimbul-works/acl";
 *
 * const permissions = createPermissions([
 *   ["allow", "discussion.*.read"],
 *   ["deny", "admin.*"],
 * ]);
 *
 * checkPermission(permissions, "discussion.1234.read"); // true
 * checkPermission(permissions, "admin.users"); // false
 * checkPermission(permissions, "user.profile"); // false (no match)
 * ```
 */
export function checkPermission(permissions: Permission[], resource: string): boolean {
  if (typeof resource !== "string" || resource === null || resource === undefined) {
    return false;
  }

  const normalizedResource = resource.trim();
  if (normalizedResource.length === 0) {
    return false;
  }

  const resourceParts = normalizedResource.split(".");

  // Check for root deny first - this overrides everything
  const rootDenyPermissions = permissions.filter((p) => p.isRoot && p.type === "deny");
  if (rootDenyPermissions.length > 0) {
    return false;
  }

  // Find all matching permissions (both root and non-root)
  const matchingPermissions = permissions.filter(
    (permission) => permission.isRoot || matchesPattern(resourceParts, permission.parts),
  );

  if (matchingPermissions.length === 0) {
    return false; // No matching permissions, deny by default
  }

  // Apply precedence: deny takes priority over allow
  const hasExplicitDeny = matchingPermissions.some((p) => p.type === "deny");
  if (hasExplicitDeny) {
    return false;
  }

  // If we have matching allow permissions and no deny, grant access
  const hasExplicitAllow = matchingPermissions.some((p) => p.type === "allow");
  return hasExplicitAllow;
}

/**
 * Check if permissions include root access.
 *
 * Root access means the user has a wildcard allow (`*`) permission without a wildcard deny.
 * This is typically used for admin/superuser permissions.
 *
 * @param {Permission[]} permissions - Array of Permission objects
 * @returns {boolean} `true` if root access is granted, `false` otherwise
 *
 * @example
 * ```ts
 * import { createPermissions, hasRootAccess } from "@fimbul-works/acl";
 *
 * const adminPerms = createPermissions([["allow", "*"]]);
 * hasRootAccess(adminPerms); // true
 *
 * const userPerms = createPermissions([["allow", "user.*.read"]]);
 * hasRootAccess(userPerms); // false
 *
 * const restricted = createPermissions([["allow", "*"], ["deny", "*"]]);
 * hasRootAccess(restricted); // false (deny overrides)
 * ```
 */
export function hasRootAccess(permissions: Permission[]): boolean {
  const rootPermissions = permissions.filter((p) => p.isRoot);

  // If there's any root deny, no root access
  if (rootPermissions.some((p) => p.type === "deny")) {
    return false;
  }

  // If there's any root allow and no root deny, has root access
  return rootPermissions.some((p) => p.type === "allow");
}

/**
 * Create multiple permissions from an array of [type, pattern] tuples.
 *
 * This is a convenience function for creating multiple permissions at once.
 * Any error in creating a permission will be thrown immediately.
 *
 * @param {Array<[PermissionType, string]>} rules - Array of [type, pattern] tuples
 * @returns {Permission[]} Array of Permission objects
 * @throws {Error} If any type is invalid or any pattern is empty
 *
 * @example
 * ```ts
 * import { createPermissions } from "@fimbul-works/acl";
 *
 * const permissions = createPermissions([
 *   ["allow", "discussion.*.read"],
 *   ["deny", "admin.*"],
 *   ["allow", "user.1234.*"],
 * ]);
 * ```
 */
export function createPermissions(rules: Array<[PermissionType, string]>): Permission[] {
  return sortPermissions(rules.map(([type, pattern]) => createPermission(type, pattern)));
}

/**
 * Merge multiple permission arrays, removing duplicates.
 *
 * Combines multiple permission arrays into one, automatically deduplicating
 * permissions that have the same type and pattern. This is useful for combining
 * permissions from multiple sources (e.g., user roles, group memberships).
 *
 * Note: Permissions with the same pattern but different types are both kept
 * (e.g., an `"allow"` and `"deny"` for the same pattern).
 *
 * @param {Permission[][]} permissionArrays - Variable number of permission arrays to merge
 * @returns {Permission[]} Merged and deduplicated array
 *
 * @example
 * ```ts
 * import { createPermissions, mergePermissions } from "@fimbul-works/acl";
 *
 * const userPerms = createPermissions([
 *   ["allow", "user.1234.edit"],
 *   ["allow", "discussion.*.read"],
 * ]);
 *
 * const moderatorPerms = createPermissions([
 *   ["allow", "discussion.*.moderate"],
 *   ["allow", "discussion.*.read"], // duplicate
 * ]);
 *
 * const merged = mergePermissions(userPerms, moderatorPerms);
 * // Result has 3 permissions (discussion.*.read appears once)
 * ```
 */
export function mergePermissions(...permissionArrays: Permission[][]): Permission[] {
  return permissionArrays
    .flat()
    .filter(
      (p, index, permissions) =>
        permissions.findIndex((search) => search.type === p.type && search.pattern === p.pattern) === index,
    );
}

/**
 * Filter permissions by type (`"allow"` or `"deny"`).
 *
 * Useful for analyzing or debugging permissions by separating allows and denies.
 *
 * @param {Permission[]} permissions - Array of Permission objects
 * @param {PermissionType} type - Permission type to filter by (`"allow"` or `"deny"`)
 * @returns {Permission[]} Array containing only permissions of the specified type
 *
 * @example
 * ```ts
 * import { createPermissions, filterPermissionsByType } from "@fimbul-works/acl";
 *
 * const permissions = createPermissions([
 *   ["allow", "discussion.*.read"],
 *   ["deny", "admin.*"],
 *   ["allow", "user.*.read"],
 * ]);
 *
 * const allowPerms = filterPermissionsByType(permissions, "allow");
 * // Returns 2 allow permissions
 *
 * const denyPerms = filterPermissionsByType(permissions, "deny");
 * // Returns 1 deny permission
 * ```
 */
export function filterPermissionsByType(permissions: Permission[], type: PermissionType): Permission[] {
  return permissions.filter((p) => p.type === type);
}

/**
 * Validate a permission pattern without creating a Permission object.
 *
 * Useful for form validation, input sanitization, or pre-flight checks.
 * This function checks the pattern's structure without throwing exceptions.
 *
 * @param {unknown} pattern - Permission pattern to validate
 * @returns {{valid: boolean, error?: string}} Validation result with optional error message
 *
 * @example
 * ```ts
 * import { validatePermissionPattern } from "@fimbul-works/acl";
 *
 * validatePermissionPattern("user.*.read"); // {valid: true}
 * validatePermissionPattern("*"); // {valid: true}
 * validatePermissionPattern(""); // {valid: false, error: "Permission pattern cannot be empty"}
 * validatePermissionPattern("   "); // {valid: false, error: "Permission pattern cannot be empty"}
 * validatePermissionPattern(null as any); // {valid: false, error: "Permission pattern must be a non-empty string"}
 * ```
 */
export function validatePermissionPattern(pattern: unknown): { valid: boolean; error?: string } {
  if (typeof pattern !== "string" || pattern === null || pattern === undefined) {
    return { valid: false, error: "Permission pattern must be a non-empty string" };
  }

  const normalizedPattern = (pattern as string).trim();
  if (normalizedPattern.length === 0) {
    return { valid: false, error: "Permission pattern cannot be empty" };
  }

  return { valid: true };
}

/**
 * Serialize permissions to a compact string format.
 *
 * Converts an array of Permission objects to a string suitable for storage,
 * transmission, or embedding in tokens (e.g., JWTs). The format is:
 * `"type1:pattern1,type2:pattern2,..."`
 *
 * @param {Permission[]} permissions - Array of Permission objects to serialize
 * @returns {string} Serialized permissions string
 *
 * @example
 * ```ts
 * import { createPermissions, serializePermissions } from "@fimbul-works/acl";
 *
 * const permissions = createPermissions([
 *   ["allow", "user.*.read"],
 *   ["deny", "admin.*"],
 * ]);
 *
 * const serialized = serializePermissions(permissions);
 * // "allow:user.*.read,deny:admin.*"
 * ```
 */
export function serializePermissions(permissions: Permission[]): string {
  return permissions.map((p) => `${p.type}:${p.pattern}`).join(",");
}

/**
 * Deserialize permissions from a string format.
 *
 * Parses a serialized permissions string back into an array of Permission objects.
 * Invalid entries are silently skipped to ensure graceful degradation.
 *
 * @param {string} data - Serialized permissions string (format: `"type:pattern,type:pattern,..."`)
 * @returns {Permission[]} Array of Permission objects
 *
 * @example
 * ```ts
 * import { deserializePermissions } from "@fimbul-works/acl";
 *
 * const data = "allow:user.*.read,deny:admin.*,allow:*.public.view";
 * const permissions = deserializePermissions(data);
 * // Returns array of 3 Permission objects
 * ```
 */
export function deserializePermissions(data: string): Permission[] {
  if (!data || data.trim().length === 0) {
    return [];
  }

  return data
    .split(",")
    .map((entry) => {
      const trimmed = entry.trim();
      if (!trimmed) return null;

      const colonIndex = trimmed.indexOf(":");
      if (colonIndex === -1) return null;

      const type = trimmed.slice(0, colonIndex) as PermissionType;
      const pattern = trimmed.slice(colonIndex + 1);

      // Validate and create permission, skip invalid entries
      try {
        return createPermission(type, pattern);
      } catch {
        return null;
      }
    })
    .filter((p): p is Permission => p !== null);
}

/**
 * Check multiple resources at once.
 *
 * More efficient than calling `checkPermission` multiple times, as it processes
 * all resources in a single pass through the permissions array.
 *
 * @param {Permission[]} permissions - Array of Permission objects
 * @param {string[]} resources - Array of resource strings to check
 * @returns {boolean[]} Array of boolean results corresponding to each resource
 *
 * @example
 * ```ts
 * import { createPermissions, checkPermissions } from "@fimbul-works/acl";
 *
 * const permissions = createPermissions([
 *   ["allow", "user.*.read"],
 *   ["deny", "admin.*"],
 * ]);
 *
 * const results = checkPermissions(permissions, [
 *   "user.1234.read",
 *   "admin.panel",
 *   "user.5678.read",
 * ]);
 * // [true, false, true]
 * ```
 */
export function checkPermissions(permissions: Permission[], resources: string[]): boolean[] {
  return resources.map((resource) => checkPermission(permissions, resource));
}

/**
 * Sort permissions by precedence for optimized checking.
 *
 * Sorts permissions in the optimal order for permission evaluation:
 * 1. Deny permissions before allow (deny takes precedence)
 * 2. Root (`*`) before wildcards before specific patterns (general to specific)
 * 3. Wildcards (`*`) before specific patterns (broader matches first)
 *
 * This sorting can improve performance when checking permissions, as more
 * general/important rules are evaluated first.
 *
 * @param {Permission[]} permissions - Array of Permission objects to sort
 * @returns {Permission[]} New array with permissions sorted by precedence
 *
 * @example
 * ```ts
 * import { createPermissions, sortPermissions } from "@fimbul-works/acl";
 *
 * const permissions = createPermissions([
 *   ["allow", "user.1234.read"],
 *   ["deny", "*"],
 *   ["allow", "*.public"],
 *   ["deny", "admin.*"],
 * ]);
 *
 * const sorted = sortPermissions(permissions);
 * // Order: deny:*, deny:admin.*, allow:*.public, allow:user.1234.read
 * ```
 */
export function sortPermissions(permissions: Permission[]): Permission[] {
  return [...permissions].sort((a, b) => {
    // Deny comes before allow
    if (a.type !== b.type) {
      return a.type === "deny" ? -1 : 1;
    }

    // Calculate specificity score (lower = more general)
    const getSpecificity = (perm: Permission): number => {
      if (perm.isRoot) return 0; // Most general
      const wildcardCount = perm.parts.filter((p) => p === "*").length;
      return wildcardCount === 0 ? 2 : 1; // Specific vs wildcard
    };

    const aSpecificity = getSpecificity(a);
    const bSpecificity = getSpecificity(b);

    if (aSpecificity !== bSpecificity) {
      return aSpecificity - bSpecificity; // More general first
    }

    // Same specificity, sort by pattern for consistency
    return a.pattern.localeCompare(b.pattern);
  });
}

/**
 * Intersect multiple permission arrays.
 *
 * Returns permissions that exist in ALL provided arrays.
 * Permissions are considered equal if they have the same type and pattern.
 * This is useful for finding common permissions across multiple roles or groups.
 *
 * @param {Permission[][]} permissionArrays - Variable number of permission arrays to intersect
 * @returns {Permission[]} Array of permissions common to all input arrays
 *
 * @example
 * ```ts
 * import { createPermissions, intersectPermissions } from "@fimbul-works/acl";
 *
 * const editors = createPermissions([
 *   ["allow", "content.*.edit"],
 *   ["allow", "content.*.read"],
 *   ["deny", "content.*.delete"],
 * ]);
 *
 * const reviewers = createPermissions([
 *   ["allow", "content.*.read"],
 *   ["allow", "content.*.publish"],
 * ]);
 *
 * const common = intersectPermissions(editors, reviewers);
 * // ["allow", "content.*.read"] - only the common permission
 * ```
 */
export function intersectPermissions(...permissionArrays: Permission[][]): Permission[] {
  if (permissionArrays.length === 0) return [];
  if (permissionArrays.length === 1) return permissionArrays[0];

  const [first, ...rest] = permissionArrays;

  return first.filter((perm) =>
    rest.every((arr) => arr.some((p) => p.type === perm.type && p.pattern === perm.pattern)),
  );
}

/**
 * Subtract one set of permissions from another.
 *
 * Returns permissions from `base` that do not exist in `remove`.
 * A permission is removed if it has the same type AND pattern.
 * This is useful for calculating permission differences between roles.
 *
 * @param {Permission[]} base - Base permission array
 * @param {Permission[]} remove - Permissions to remove from base
 * @returns {Permission[]} Permissions in base but not in remove
 *
 * @example
 * ```ts
 * import { createPermissions, subtractPermissions } from "@fimbul-works/acl";
 *
 * const admins = createPermissions([
 *   ["allow", "*"],
 *   ["deny", "system.*"],
 * ]);
 *
 * const users = createPermissions([
 *   ["allow", "user.*.read"],
 * ]);
 *
 * const diff = subtractPermissions(admins, users);
 * // Returns admin permissions minus user permissions
 * // ["allow:*", "deny:system.*"]
 * ```
 */
export function subtractPermissions(base: Permission[], remove: Permission[]): Permission[] {
  const removeSet = new Set(remove.map((p) => `${p.type}:${p.pattern}`));
  return base.filter((p) => !removeSet.has(`${p.type}:${p.pattern}`));
}

/**
 * Expand wildcard permissions against a list of actual resources.
 *
 * Shows which specific resources each wildcard permission would match.
 * Useful for debugging, auditing, or visualizing permissions in admin panels.
 *
 * @param {Permission[]} permissions - Array of Permission objects to expand
 * @param {string[]} resources - Array of resource strings to test against
 * @returns {Array<{permission: Permission, matches: string[]}>} Array showing which resources each permission matches
 *
 * @example
 * ```ts
 * import { createPermissions, expandPermissions } from "@fimbul-works/acl";
 *
 * const permissions = createPermissions([
 *   ["allow", "user.*.read"],
 *   ["deny", "admin.*"],
 * ]);
 *
 * const resources = [
 *   "user.1234.read",
 *   "user.5678.edit",
 *   "admin.panel",
 *   "discussion.123.read",
 * ];
 *
 * const expanded = expandPermissions(permissions, resources);
 * // [
 * //   { permission: {type: "allow", pattern: "user.*.read", ...}, matches: ["user.1234.read"] },
 * //   { permission: {type: "deny", pattern: "admin.*", ...}, matches: ["admin.panel"] }
 * // ]
 * ```
 */
export function expandPermissions(
  permissions: Permission[],
  resources: string[],
): Array<{ permission: Permission; matches: string[] }> {
  return permissions.map((permission) => ({
    permission,
    matches: resources.filter((resource) => {
      // Check if the resource pattern matches this permission's pattern
      // We use getMatchingPermissions internally which checks pattern matching
      const normalizedResource = resource.trim();
      if (normalizedResource.length === 0) return false;

      const resourceParts = normalizedResource.split(".");
      return permission.isRoot || matchesPattern(resourceParts, permission.parts);
    }),
  }));
}

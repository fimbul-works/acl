# @fimbul-works/acl

A functional, type-safe Access Control Layer (ACL) library for TypeScript/JavaScript applications.

[![npm version](https://badge.fury.io/js/%40fimbul-works%2Facl.svg)](https://www.npmjs.com/package/@fimbul-works/acl)
[![TypeScript](https://badges.frapsoft.com/typescript/code/typescript.svg?v=101)](https://github.com/microsoft/TypeScript)
[![Bundle Size](https://img.shields.io/bundlephobia/minzip/@fimbul-works/acl)](https://bundlephobia.com/package/@fimbul-works/acl)

## Features

- 🔒 **Fine-grained permissions** with hierarchical pattern matching
- 🌟 **Wildcard support** - Use `*` to match any segment or resource
- ⚡ **High performance** - Optimized permission checking with automatic sorting
- 🔀 **Functional API** - Immutable operations, predictable behavior
- 📝 **Type-safe** - Full TypeScript support with comprehensive types
- 💾 **Persistence ready** - Serialize/deserialize for databases and JWTs
- 🛠️ **Developer tools** - Debugging, validation, and permission math utilities
- 🎯 **Zero dependencies** - Lightweight and easy to adopt

## Installation

```bash
npm install @fimbul-works/acl
# or
yarn add @fimbul-works/acl
# or
pnpm install @fimbul-works/acl
```

## Quick Start

```typescript
import {
  createPermissions,
  checkPermission,
  serializePermissions,
  deserializePermissions
} from "@fimbul-works/acl";

// Define permissions
const permissions = createPermissions([
  ["allow", "discussion.*.read"], // Allow reading any discussion
  ["allow", "user.1234.*"],       // Allow user 1234 to do anything
  ["deny", "admin.*"],            // Deny all admin access
  ["allow", "*.public.view"],     // Allow viewing public resources
]);

// Check permissions
checkPermission(permissions, "discussion.abc.read"); // true
checkPermission(permissions, "admin.panel");         // false
checkPermission(permissions, "user.1234.edit");      // true

// Serialize for storage (databases, JWTs, etc.)
const serialized = serializePermissions(permissions);
// "deny:admin.*,allow:*.public.view,allow:discussion.*.read,allow:user.1234.*"

// Deserialize back to permissions
const restored = deserializePermissions(serialized);
```

## Pattern Syntax

Permissions use dot-separated patterns with wildcards:

- `*` - Root access (matches everything)
- `user.*` - Matches any resource under user namespace (e.g., `user.read`, `user.profile.edit`)
- `*.public` - Matches resources ending with `.public` (e.g., `user.public`, `admin.public`)
- `user.*.read` - Matches user read operations (e.g., `user.1234.read`, `user.profile.read`)
- `discussion.1234.moderate` - Exact match only

### Precedence Rules

Permissions are evaluated in this order:

1. **Deny overrides Allow** - A deny always wins over an allow
2. **Root access** - `*` patterns have special handling
3. **Specific over General** - More specific patterns take precedence

```typescript
const permissions = createPermissions([
  ["allow", "*"],      // Allow everything
  ["deny", "admin.*"], // But deny admin
]);

checkPermission(permissions, "user.read");   // true (root allow)
checkPermission(permissions, "admin.panel"); // false (deny wins)
```

## Core API

### Creating Permissions

```typescript
import {
  createPermission,
  createPermissions,
  addPermission,
  removePermission
} from "@fimbul-works/acl";

// Create single permission
const perm = createPermission("allow", "user.*.read");

// Create multiple permissions
const permissions = createPermissions([
  ["allow", "discussion.*.read"],
  ["deny", "admin.*"],
]);

// Add permission (returns new array)
const updated = addPermission(permissions, "allow", "user.*.write");

// Remove permission
const filtered = removePermission(permissions, "deny", "admin.*");
```

### Checking Permissions

```typescript
import {
  checkPermission,
  checkPermissions,
  getMatchingPermissions,
  hasRootAccess
} from "@fimbul-works/acl";

// Check single resource
checkPermission(permissions, "user.1234.read"); // boolean

// Check multiple resources (batch)
const results = checkPermissions(permissions, [
  "user.1234.read",
  "admin.panel",
  "discussion.abc.read",
]);
// [true, false, true]

// Get all matching permissions (for debugging)
const matches = getMatchingPermissions(permissions, "discussion.abc.read");

// Check for root access
hasRootAccess(permissions); // boolean
```

### Managing Permissions

```typescript
import {
  mergePermissions,
  sortPermissions,
  filterPermissionsByType
} from "@fimbul-works/acl";

// Merge multiple permission arrays (with deduplication)
const userPerms = createPermissions([["allow", "user.*.read"]]);
const adminPerms = createPermissions([["allow", "*"]]);
const merged = mergePermissions(userPerms, adminPerms);

// Sort by precedence (deny before allow, general before specific)
const sorted = sortPermissions(permissions);

// Filter by type
const allowPerms = filterPermissionsByType(permissions, "allow");
const denyPerms = filterPermissionsByType(permissions, "deny");
```

### Serialization

```typescript
import {
  serializePermissions,
  deserializePermissions
} from "@fimbul-works/acl";

// Serialize to string
const data = serializePermissions(permissions);
// "deny:admin.*,allow:user.*.read"

// Deserialize from string
const restored = deserializePermissions(data);
```

### Permission Math

```typescript
import {
  intersectPermissions,
  subtractPermissions
} from "@fimbul-works/acl";

// Find common permissions across multiple arrays
const common = intersectPermissions(roleA, roleB, roleC);

// Subtract permissions (what's in A but not in B)
const diff = subtractPermissions(adminPerms, userPerms);
```

### Validation & Debugging

```typescript
import {
  validatePermissionPattern,
  expandPermissions
} from "@fimbul-works/acl";

// Validate pattern without throwing
const validation = validatePermissionPattern("user.*.read");
// { valid: true }

const bad = validatePermissionPattern("");
// { valid: false, error: "Permission pattern cannot be empty" }

// Expand wildcards to see what they match
const expanded = expandPermissions(permissions, [
  "user.1234.read",
  "admin.panel",
  "discussion.abc.read",
]);
// [
//   { permission: {...}, matches: ["user.1234.read"] },
//   { permission: {...}, matches: ["admin.panel"] }
// ]
```

## Real-World Examples

### Web Application ACL

```typescript
// Define role-based permissions
const roles = {
  guest: createPermissions([
    ["allow", "*.public.view"],
  ]),

  user: createPermissions([
    ["allow", "user.*.read"],
    ["allow", "user.*.edit"],
    ["allow", "discussion.*.read"],
    ["allow", "discussion.*.comment"],
    ["deny", "user.*.delete"],
  ]),

  moderator: createPermissions([
    ["allow", "discussion.*.read"],
    ["allow", "discussion.*.moderate"],
    ["allow", "discussion.*.delete"],
    ["allow", "user.*.read"],
    ["allow", "user.*.suspend"],
    ["deny", "admin.*"],
  ]),

  admin: createPermissions([
    ["allow", "*"],  // Root access
  ]),
};

// Check user permissions
function canAccess(userRole: keyof typeof roles, resource: string): boolean {
  return checkPermission(roles[userRole], resource);
}

canAccess("user", "user.1234.edit");             // true
canAccess("user", "user.1234.delete");           // false
canAccess("moderator", "discussion.123.delete"); // true
canAccess("guest", "admin.panel");               // false
```

### JWT Token Integration

```typescript
import jwt from "jsonwebtoken";
import { createPermissions, serializePermissions, deserializePermissions } from "@fimbul-works/acl";

// When creating JWT
const token = jwt.sign({
  sub: "user123",
  permissions: serializePermissions(createPermissions([
    ["allow", "user.*.read"],
    ["allow", "user.1234.*"],
  ])),
}, "secret");

// When verifying JWT
const decoded = jwt.verify(token, "secret") as { permissions: string };
const permissions = deserializePermissions(decoded.permissions);

if (checkPermission(permissions, "user.1234.edit")) {
  // Grant access
}
```

### Database Storage

```typescript
import { createPermissions, serializePermissions, deserializePermissions } from "@fimbul-works/acl";

// Save to database
await db.users.update({
  where: { id: 123 },
  data: {
    permissions: serializePermissions(userPermissions),
  },
});

// Load from database
const user = await db.users.findUnique({ where: { id: 123 } });
const permissions = deserializePermissions(user.permissions);
```

### Combining Multiple Roles

```typescript
import { mergePermissions, checkPermission } from "@fimbul-works/acl";

// User can have multiple roles
const userRoles = [
  createPermissions([["allow", "content.*.read"]]),    // Editor
  createPermissions([["allow", "content.*.publish"]]), // Publisher
  createPermissions([["deny", "content.*.delete"]]),   // Cannot delete
];

// Merge all roles
const merged = mergePermissions(...userRoles);

checkPermission(merged, "content.123.read");    // true
checkPermission(merged, "content.123.publish"); // true
checkPermission(merged, "content.123.delete");  // false (deny wins)
```

## Performance

The library is optimized for performance:

- **Automatic sorting** - Permissions are sorted by precedence for early-exit optimization
- **O(n) complexity** - Linear time permission checking
- **Efficient pattern matching** - Pre-split pattern segments
- **Batch operations** - Check multiple resources in one call

Benchmark with 1000 permissions:
```typescript
// Checking 100 resources
const start = Date.now();
for (let i = 0; i < 100; i++) {
  checkPermission(permissions, `resource.${i}.action`);
}
console.log(`${Date.now() - start}ms`); // Typically < 10ms
```

## API Reference

### Core Functions

- `createPermission(type, pattern)` - Create single permission
- `createPermissions(rules)` - Create multiple permissions
- `addPermission(permissions, type, pattern)` - Add permission
- `removePermission(permissions, type, pattern)` - Remove permission
- `checkPermission(permissions, resource)` - Check single resource
- `checkPermissions(permissions, resources)` - Check multiple resources
- `mergePermissions(...arrays)` - Merge and deduplicate
- `sortPermissions(permissions)` - Sort by precedence
- `hasRootAccess(permissions)` - Check for root access
- `getMatchingPermissions(permissions, resource)` - Get all matches

### Utility Functions

- `serializePermissions(permissions)` - Convert to string
- `deserializePermissions(data)` - Parse from string
- `intersectPermissions(...arrays)` - Find common permissions
- `subtractPermissions(base, remove)` - Remove permissions
- `filterPermissionsByType(permissions, type)` - Filter by type
- `expandPermissions(permissions, resources)` - Show pattern matches
- `validatePermissionPattern(pattern)` - Validate without throwing

## TypeScript Support

This library is written in TypeScript and provides excellent type inference:

```typescript
import { Permission, PermissionType } from "@fimbul-works/acl";

const type: PermissionType = "allow"; // "allow" | "deny"
const permission: Permission = {
  type: "allow",
  pattern: "user.*.read",
  parts: ["user", "*", "read"],
  isRoot: false,
};
```

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

Built with ⚡ by [FimbulWorks](https://github.com/fimbul-works)

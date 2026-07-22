# ACIR Specification v0.2.0

> ACIR (Agent Code Intermediate Representation) document format.
> Patent pending · © Ld Labs · 2026

> ⚠️ **HISTORICAL DOCUMENT (v0.2.0) — NON-NORMATIVE.** The spec has since evolved to v0.3.x.
> The **normative source of truth** is now the JSON-schema
> [../docs/schemas/acir-v0.3.2.json](../docs/schemas/acir-v0.3.2.json) (shapes, closed enums,
> `additionalProperties: false`), complemented by the semantic rules of
> [../validator/acir_validator.py](../validator/acir_validator.py) (`$calculate` DSL,
> OWASP-aligned security, cross-field checks).
> This file is kept for the history of canonical-form decisions and their rationale.

---

## Canonical forms (strict)

ACIR admits **exactly one form** for each of the patterns below. Any other synonym key is **rejected** by the validator (level L1) with an explicit error message. This rule exists to guarantee that the same brief always produces the same ACIR document (determinism), and that compilers never have to support variants.

| Pattern | Canonical form | Forbidden synonyms |
|---|---|---|
| `D_COLLECTION` (list/set/queue/stack) | `element_type: {...}` | `item_type`, `items`, `of`, `element`, `elements` |
| `D_COLLECTION` (map) | `key_type: {...}` + `value_type: {...}` | `keys`, `values`, `entries` |
| `IO_QUERY` filter | `filter: {field: {operator, value}, ...}` (object map) | `filters: [...]` (array of predicates) |
| `IO_EXPOSE.input_source` | string among: `body`, `query`, `path`, `composite` | `combined`, `mixed`, `query_params`, inline object `{path:[...], body:"..."}` |
| `IO_EXPOSE` composite | sibling `input_layout: {path:[...], body:"..."}` when `input_source = "composite"` | inline object directly inside `input_source` |
| Input reference in `IO_MUTATE.data` / `IO_QUERY.filter` | `{"$input": "field"}` | `{"$param": "field"}` |
| Default in `pagination.*` | `default: <value>` (key without `$`) | `$default` |

**Rationale**:
- `element_type` rather than `items`: aligned with set/queue terminology (not just lists) and already the historical form of the spec.
- `filter` (object map) rather than `filters` (array): composes a single predicate per field, simpler to compile into `WHERE x = ? AND y = ?`.
- `input_source` as a string enum: separates the binding strategy (where to look for the input) from the structure (`input_layout`), instead of overloading one field with two possible types.
- `$input` rather than `$param`: "input" is the official term for an `X_UNIT`'s arguments (cf. `unit.input`); `$param` is ambiguous (HTTP params? Java params?).
- `default` (without `$`): `$` is reserved for dynamic references (`$input`, `$ref`, `$generate`, `$secret`); `default` is a static value.

---

## Overview

ACIR is a structured JSON format describing a complete application deterministically and independently of the target. An ACIR document contains:

- **Types** (entities, DTOs, enumerations)
- **Units** (business logic)
- **Exposed endpoints** (HTTP)
- Optionally, a **runtime** block (deployment configuration)

The format rests on **40 primitives** organized in **5 families**:

| Prefix | Family | Examples |
|---|---|---|
| `D_` | Data | D_SCALAR, D_ENUM, D_RECORD, D_COLLECTION, D_UNION, D_ALIAS |
| `F_` | Flow | F_SEQUENCE, F_BRANCH, F_GUARD, F_ERROR_HANDLE |
| `IO_` | I/O | IO_QUERY, IO_MUTATE, IO_EXPOSE |
| `C_` | Contract | C_RANGE, C_PATTERN, C_LENGTH, C_UNIQUE, C_SECURITY, C_RATE_LIMIT, C_SANITIZE, C_ENCRYPT, C_AUDIT, C_PRECISION |
| `X_` | Composition | X_UNIT |

---

## Document structure

```json
{
  "acir_version": "0.2.0",
  "module": {
    "name": "PascalCaseName",
    "doc": "Optional module description",
    "types": [...],
    "units": [...],
    "exposed": [...],
    "runtime": {...}
  }
}
```

⚠️ **`module.name` must be PascalCase** (e.g. `ProductCatalog`, not `product_catalog`).

---

## D_ family (Data)

### D_SCALAR

Primitive scalar value.

```json
{
  "primitive": "D_SCALAR",
  "kind": "string"  // string | integer | decimal | boolean | datetime | date | uuid
}
```

### D_ENUM

Enumeration.

```json
{
  "primitive": "D_ENUM",
  "name": "TaskStatus",
  "values": [
    {"name": "TODO"},
    {"name": "IN_PROGRESS"},
    {"name": "DONE"}
  ]
}
```

### D_RECORD

Composite type (entity or DTO).

```json
{
  "primitive": "D_RECORD",
  "name": "Task",
  "doc": "A user task",
  "identity": ["id"],
  "fields": [
    {
      "name": "id",
      "type": {"primitive": "D_SCALAR", "kind": "uuid"}
    },
    {
      "name": "title",
      "type": {"primitive": "D_SCALAR", "kind": "string"},
      "required": true,
      "contracts": [
        {"primitive": "C_LENGTH", "min": 1, "max": 200},
        {"primitive": "C_SANITIZE", "modes": ["trim", "html_escape"]}
      ]
    },
    {
      "name": "status",
      "type": {"$ref": "TaskStatus"}
    },
    {
      "name": "created_at",
      "type": {"primitive": "D_SCALAR", "kind": "datetime"},
      "immutable": true
    }
  ],
  "contracts": [
    {"primitive": "C_UNIQUE", "fields": ["title"], "scope": "global"}
  ]
}
```

**Rules**:
- If `identity` is present, it is an **entity** (DB table); otherwise it is a **DTO**
- `immutable: true` on a field → no UPDATE possible (compiled to JPA `@Column(updatable=false)`)
- `sensitive: true` on a field → excluded from API responses and logs

### D_ALIAS

Alias of a type with additional constraints.

```json
{
  "primitive": "D_ALIAS",
  "name": "Email",
  "base_type": {"primitive": "D_SCALAR", "kind": "string"},
  "contracts": [
    {"primitive": "C_PATTERN", "format": "email"},
    {"primitive": "C_LENGTH", "max": 254}
  ]
}
```

### D_COLLECTION

List / array.

```json
{
  "primitive": "D_COLLECTION",
  "kind": "list",  // list | set | map
  "element_type": {"$ref": "Tag"}
}
```

### D_UNION

Union of types (sum type).

```json
{
  "primitive": "D_UNION",
  "name": "PaymentResult",
  "variants": [
    {"$ref": "PaymentSuccess"},
    {"$ref": "PaymentFailure"}
  ]
}
```

---

## C_ family (Contract)

### C_RANGE

Numeric bounds.

```json
{"primitive": "C_RANGE", "min": 0, "max": 100, "exclusive_min": false}
```

Compiled to:
- Java: `@Min(0)`, `@Max(100)` or `@DecimalMin`/`@DecimalMax`
- Zod: `.min(0).max(100)`
- Pydantic: `Field(ge=0, le=100)`

### C_LENGTH

Length (string or collection).

```json
{"primitive": "C_LENGTH", "min": 1, "max": 200}
```

### C_PATTERN

Regex or predefined format.

```json
{"primitive": "C_PATTERN", "regex": "^[A-Z]{3}[0-9]{6}$"}
{"primitive": "C_PATTERN", "format": "email"}
{"primitive": "C_PATTERN", "format": "url"}
{"primitive": "C_PATTERN", "format": "uuid"}
```

### C_PRECISION

Decimal precision.

```json
{"primitive": "C_PRECISION", "scale": 2, "rounding_mode": "HALF_UP"}
```

### C_UNIQUE

Uniqueness constraint.

```json
{"primitive": "C_UNIQUE", "fields": ["sku"], "scope": "global"}
{"primitive": "C_UNIQUE", "fields": ["email", "tenant_id"], "scope": "tenant"}
```

### C_SANITIZE

Automatic sanitization of string inputs.

```json
{
  "primitive": "C_SANITIZE",
  "modes": ["trim", "html_escape", "strip_tags"]
}
```

Available modes:
- `trim`: removes leading/trailing whitespace
- `html_escape`: `<` → `&lt;`, `>` → `&gt;`, `"` → `&quot;`
- `strip_tags`: removes all HTML tags
- `lowercase`: converts to lowercase
- `normalize_whitespace`: collapses multiple spaces into one

### C_ENCRYPT

Encryption at rest.

```json
{
  "primitive": "C_ENCRYPT",
  "algorithm": "AES-256-GCM",
  "key_source": {"$secret": "ENCRYPTION_KEY"}
}
```

### C_AUDIT

Automatic audit log on mutations.

```json
{
  "primitive": "C_AUDIT",
  "events": ["create", "update", "delete"],
  "include_diff": true
}
```

### C_SECURITY

Aggregated security policy.

```json
{
  "primitive": "C_SECURITY",
  "auth_required": true,
  "roles": ["admin"],
  "audit": true
}
```

### C_RATE_LIMIT

Rate limiting.

```json
{"primitive": "C_RATE_LIMIT", "limit": 100, "window": "PT1M", "scope": "per_ip"}
{"primitive": "C_RATE_LIMIT", "limit": 10, "window": "PT1H", "scope": "per_user"}
```

---

## X_ family (Composition)

### X_UNIT

A functional unit (service method).

```json
{
  "primitive": "X_UNIT",
  "name": "createTask",
  "doc": "Creates a new task",
  "input": {"$ref": "TaskCreateInput"},
  "output": {"$ref": "Task"},
  "body": {
    "primitive": "IO_MUTATE",
    "source_kind": "relational",
    "entity": "tasks",
    "action": "create",
    "data": {
      "id": {"$generate": "uuid"},
      "title": {"$input": "title"},
      "status": "TODO",
      "created_at": {"$generate": "now"}
    },
    "return": "full_record"
  }
}
```

⚠️ **Every X_UNIT MUST have**:
- `output` (a `$ref` or inline type)
- `body` (an IO_*, F_*, or composed X_UNIT primitive)

---

## IO_ family (I/O)

### IO_QUERY

Read from a data source.

```json
{
  "primitive": "IO_QUERY",
  "source_kind": "relational",
  "entity": "tasks",
  "filter": {
    "field": "id",
    "value": {"$input": "id"}
  },
  "by_id": true
}
```

Paginated variant:

```json
{
  "primitive": "IO_QUERY",
  "source_kind": "relational",
  "entity": "tasks",
  "pagination": {"page_size_default": 20, "page_size_max": 100},
  "sort": [{"field": "created_at", "direction": "desc"}],
  "filter": {
    "when_present": "status",
    "then": {"field": "status", "operator": "eq"}
  }
}
```

### IO_MUTATE

Write to a data source.

```json
{
  "primitive": "IO_MUTATE",
  "source_kind": "relational",
  "entity": "tasks",
  "action": "create",
  "data": {
    "id": {"$generate": "uuid"},
    "title": {"$input": "title"}
  },
  "return": "full_record"
}
```

Actions: `create`, `update`, `patch`, `delete`, `upsert`.

`return`: `full_record`, `id`, `bool`, `count`.

### IO_EXPOSE

HTTP exposure of a unit.

```json
{
  "primitive": "IO_EXPOSE",
  "kind": "http_endpoint",
  "route": "/api/v1/tasks/{id}",
  "method": "GET",
  "input": {"$ref": "Task"},
  "input_source": "path",  // path | body | query
  "output": {"$ref": "Task"},
  "handler": {"$ref": "getTask"},
  "auth": {
    "required": true,
    "roles": ["admin", "editor"]
  },
  "rate_limit": {
    "limit": 100,
    "window": "PT1M",
    "scope": "per_ip"
  },
  "response_mapping": {
    "success": {"status_code": 200},
    "errors": {
      "not_found": {"status_code": 404},
      "validation_failed": {"status_code": 422}
    }
  }
}
```

⚠️ **Security rules** (validator L5):
- Every mutation (POST/PUT/PATCH/DELETE) MUST have `auth.required: true`
- Every public endpoint MUST have a `rate_limit`
- Sensitive fields MUST have `C_ENCRYPT`

---

## F_ family (Flow)

### F_SEQUENCE

Sequence of operations (atomic if `atomic: true`).

```json
{
  "primitive": "F_SEQUENCE",
  "atomic": true,
  "steps": [
    {
      "name": "checkExists",
      "op": {
        "primitive": "IO_QUERY",
        "entity": "tasks",
        "filter": {"field": "id", "value": {"$input": "id"}}
      }
    },
    {
      "name": "guard",
      "op": {
        "primitive": "F_GUARD",
        "condition": {"$step": "checkExists", "is_null": true},
        "error_code": "NOT_FOUND",
        "error_message": "Task not found"
      }
    },
    {
      "name": "delete",
      "op": {
        "primitive": "IO_MUTATE",
        "action": "delete",
        "filter": {"field": "id", "value": {"$input": "id"}}
      }
    }
  ]
}
```

### F_GUARD

Conditional guard (raises an exception if the condition is true).

```json
{
  "primitive": "F_GUARD",
  "condition": {"$step": "checkUnique", "is_not_null": true},
  "error_code": "ALREADY_EXISTS",
  "error_message": "Resource already exists"
}
```

### F_BRANCH

Conditional branching.

```json
{
  "primitive": "F_BRANCH",
  "conditions": [
    {
      "if": {"$input": "type", "equals": "premium"},
      "then": {"primitive": "IO_MUTATE", "...": "..."}
    }
  ],
  "otherwise": {"primitive": "IO_MUTATE", "...": "..."}
}
```

### F_ERROR_HANDLE

Try/catch.

```json
{
  "primitive": "F_ERROR_HANDLE",
  "operation": {"primitive": "IO_MUTATE", "...": "..."},
  "on_error": {
    "kind": "compensate",
    "operation": {"primitive": "IO_MUTATE", "action": "rollback", "...": "..."}
  }
}
```

---

## DataExpr — Value expressions

Used in `IO_MUTATE.data` and in filter `value`s:

| Expression | Meaning |
|---|---|
| `{"$input": "fieldName"}` | Value of the input field |
| `{"$step": "stepName"}` | Result of a previous step (F_SEQUENCE) |
| `{"$step": "stepName", "field": "id"}` | Specific field of the result |
| `{"$generate": "uuid"}` | Auto-generated UUID |
| `{"$generate": "now"}` | Current timestamp |
| `{"$secret": "JWT_SECRET"}` | Environment variable / secret |
| `{"$context": "user.id"}` | Execution-context data |
| `"literal value"` | Literal value (string, number, bool) |
| `{"$merge": [obj1, obj2]}` | Object merge |

---

## Runtime block (optional)

When present, triggers automatic generation of Docker files:

```json
{
  "runtime": {
    "port": 8080,
    "base_image": "eclipse-temurin:21-jre-alpine",
    "build": "multi-stage",
    "health_check": {
      "path": "/health",
      "interval": "30s",
      "timeout": "5s",
      "retries": 3
    },
    "env": {
      "DATABASE_URL": {"$secret": "DATABASE_URL"},
      "JWT_SECRET": {"$secret": "JWT_SECRET"}
    },
    "depends_on": ["postgres", "redis"]
  }
}
```

---

## Validator (6 levels)

The validator applies 6 levels of rules, in order:

| Level | Checks |
|---|---|
| **L1** | Required fields, known primitives, valid JSON structure |
| **L2** | Valid `$ref` references, type coherence, no cycles |
| **L3** | Valid contracts (compilable regex, coherent bounds, valid modes) |
| **L4** | Target compatibility (identifier lengths, supported types) |
| **L5** | OWASP-aligned security (blocking rules) |
| **L6** | Best practices (non-blocking warnings) |

### L5 OWASP rules (v0.2 excerpt)

| Code | Description | Severity |
|---|---|---|
| `MUTATION_NO_AUTH` | Mutation endpoint without authentication | error |
| `PUBLIC_NO_RATE_LIMIT` | Public endpoint without rate limit | error |
| `SENSITIVE_NO_ENCRYPT` | Sensitive field without C_ENCRYPT | error |
| `CRITICAL_MUTATION_NO_AUDIT` | DELETE/UPDATE without C_AUDIT | error |
| `INPUT_STRING_NO_SANITIZE` | Public string input without C_SANITIZE | error |
| `WEAK_AUTH_PATTERN` | Insecure auth pattern | warning |
| `MISSING_RATE_LIMIT_AUTH` | Auth endpoint without rate limit | error |
| ... | further rules — see [../validator/README.md](../validator/README.md) for the current full set | ... |

---

## Complete example: TaskManager

```json
{
  "acir_version": "0.2.0",
  "module": {
    "name": "TaskManager",
    "types": [
      {
        "primitive": "D_ENUM",
        "name": "TaskStatus",
        "values": [{"name": "TODO"}, {"name": "DONE"}]
      },
      {
        "primitive": "D_RECORD",
        "name": "Task",
        "identity": ["id"],
        "fields": [
          {"name": "id", "type": {"primitive": "D_SCALAR", "kind": "uuid"}},
          {
            "name": "title",
            "type": {"primitive": "D_SCALAR", "kind": "string"},
            "contracts": [
              {"primitive": "C_LENGTH", "min": 1, "max": 200},
              {"primitive": "C_SANITIZE", "modes": ["trim", "html_escape"]}
            ]
          },
          {"name": "status", "type": {"$ref": "TaskStatus"}}
        ]
      },
      {
        "primitive": "D_RECORD",
        "name": "TaskCreateInput",
        "fields": [
          {
            "name": "title",
            "type": {"primitive": "D_SCALAR", "kind": "string"},
            "contracts": [{"primitive": "C_LENGTH", "min": 1, "max": 200}]
          }
        ]
      }
    ],
    "units": [
      {
        "primitive": "X_UNIT",
        "name": "listTasks",
        "output": {"$ref": "Task"},
        "body": {
          "primitive": "IO_QUERY",
          "source_kind": "relational",
          "entity": "tasks",
          "pagination": {},
          "sort": [{"field": "id", "direction": "desc"}]
        }
      },
      {
        "primitive": "X_UNIT",
        "name": "createTask",
        "input": {"$ref": "TaskCreateInput"},
        "output": {"$ref": "Task"},
        "body": {
          "primitive": "IO_MUTATE",
          "source_kind": "relational",
          "entity": "tasks",
          "action": "create",
          "data": {
            "id": {"$generate": "uuid"},
            "title": {"$input": "title"},
            "status": "TODO"
          },
          "return": "full_record"
        }
      }
    ],
    "exposed": [
      {
        "primitive": "IO_EXPOSE",
        "kind": "http_endpoint",
        "route": "/api/v1/tasks",
        "method": "GET",
        "output": {"$ref": "Task"},
        "handler": {"$ref": "listTasks"},
        "rate_limit": {"limit": 100, "window": "PT1M", "scope": "per_ip"}
      },
      {
        "primitive": "IO_EXPOSE",
        "kind": "http_endpoint",
        "route": "/api/v1/tasks",
        "method": "POST",
        "input": {"$ref": "TaskCreateInput"},
        "input_source": "body",
        "output": {"$ref": "Task"},
        "handler": {"$ref": "createTask"},
        "auth": {"required": true, "roles": ["admin", "editor"]},
        "response_mapping": {"success": {"status_code": 201}}
      }
    ]
  }
}
```

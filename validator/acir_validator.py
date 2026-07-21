#!/usr/bin/env python3
"""
ACIR Validator — 6-level validation pipeline

Version: see COMPILER_VERSION below (cf. docs/COMPILER-VERSIONING.md).
Supported ACIR versions: 0.2.0 (legacy, manual checks) and 0.3.0 (JSON-Schema dispatcher + semantic rules)

Level 1: Structural validation (v0.3 → JSON-Schema Draft 2020-12; v0.2 → manual checks)
Level 2: Semantic coherence ($ref resolution, type compatibility) + v0.3-specific rules
Level 3: Contract verification (satisfiable constraints) + $calculate DSL parser
Level 4: Target compatibility (intent compilable to the requested target)
Level 5: Security analysis (PII, secrets, encryption)
Level 6: Integration checks (cross-module coherence)

Each level produces structured, machine-readable feedback.
"""

import json
import re
import sys
from pathlib import Path
from typing import Any
from dataclasses import dataclass, field
from enum import Enum

try:
    from jsonschema import Draft202012Validator  # type: ignore
    _JSONSCHEMA_AVAILABLE = True
except ImportError:
    _JSONSCHEMA_AVAILABLE = False


# ─── Console output ────────────────────────────────────────────────────────────

def force_utf8_output() -> None:
    """Switch stdout/stderr to UTF-8 so reports render on legacy consoles.

    Windows consoles default to a legacy code page (cp1252) that cannot encode
    the status and box-drawing characters used in the reports, which makes
    `print` raise UnicodeEncodeError. Call this from CLI entry points only —
    embedders keep control of their own streams.
    """
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")


# ─── Versioning ────────────────────────────────────────────────────────────────
# Convention : <ACIR-major>.<ACIR-minor>.<ACIR-patch>.<patch-iter> (cf. docs/COMPILER-VERSIONING.md).
# The validator tracks the most recent ACIR version it supports (0.3.0);
# it keeps back-compat with 0.2 (manual-checks dispatcher).
COMPILER_VERSION = "0.3.2.6"
COMPILER_TARGET = "validator"
COMPILER_ACIR_VERSION = "0.3.2"


# ─── Structured feedback ────────────────────────────────────────────────────────

class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

@dataclass
class ValidationIssue:
    level: int
    severity: Severity
    path: str
    code: str
    message: str
    suggestion: str = ""

    def to_dict(self) -> dict:
        d = {
            "level": self.level,
            "severity": self.severity.value,
            "path": self.path,
            "code": self.code,
            "message": self.message,
        }
        if self.suggestion:
            d["suggestion"] = self.suggestion
        return d

@dataclass
class ValidationResult:
    valid: bool
    issues: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "stats": self.stats,
            "issues": [i.to_dict() for i in self.issues],
            "summary": {
                "errors": sum(1 for i in self.issues if i.severity == Severity.ERROR),
                "warnings": sum(1 for i in self.issues if i.severity == Severity.WARNING),
                "info": sum(1 for i in self.issues if i.severity == Severity.INFO),
            }
        }


# ─── Constantes ────────────────────────────────────────────────────────────────

VALID_PRIMITIVES = {
    "D_SCALAR", "D_ENUM", "D_RECORD", "D_COLLECTION", "D_UNION", "D_ALIAS",
    "F_SEQUENCE", "F_BRANCH", "F_ITERATE", "F_PARALLEL", "F_RETRY",
    "F_GUARD", "F_ERROR_HANDLE", "F_TRANSFORM", "F_PARTITION",
    "F_CIRCUIT_BREAKER", "F_AWAIT",
    # v0.3 — F_FOREACH replaces F_ITERATE/F_PARALLEL via the `mode` flag
    # (cf. ACIR-v0.3-proposal.md Q3). Old ones kept for back-compat.
    "F_FOREACH",
    "IO_QUERY", "IO_MUTATE", "IO_HTTP", "IO_MESSAGE", "IO_CACHE",
    "IO_FILE", "IO_EXPOSE",
    # v0.3.2 — appel HTTP synchrone inter-composant (microservices)
    "IO_CALL",
    # Axis 4 — typed escape hatch (validated boundary, opaque body;
    # cf. docs/FNATIVE-EVALUATION.md). Placement constrained by the schema
    # (Operation only, jamais DataExpr).
    "F_NATIVE",
    "C_RANGE", "C_PATTERN", "C_LENGTH", "C_PRECISION", "C_SIZE",
    "C_UNIQUE", "C_PRECONDITION", "C_POSTCONDITION", "C_INVARIANT",
    "C_PERFORMANCE", "C_SECURITY", "C_IDEMPOTENT", "C_RATE_LIMIT",
    "C_OBSERVABLE", "C_RETRY", "C_TIMEOUT", "C_IMMUTABLE",
    "C_SANITIZE", "C_ENCRYPT", "C_AUDIT",
    "X_UNIT", "X_PIPELINE", "X_ORCHESTRATION", "X_CHOREOGRAPHY", "X_MODULE",
}

# WS0 — closed enums DERIVED from the JSON-schema (single source of truth, cf.
# docs/ACIR-CANONICAL-COMPLETENESS.md). Do NOT hand-copy these values anymore:
# they are assigned below via `_enum_from_schema()` (after the schema
# loader), with a fallback = the reconciled canon in case the schema is
# absent. The tests/conformance/ gate checks schema == constants.
# Constants concerned: SCALAR_KINDS, SOURCE_KINDS, HTTP_METHODS, EXPOSE_KINDS,
# MUTATE_ACTIONS, ERROR_KINDS, GENERATE_BUILTIN_KINDS.

DURATION_PATTERN = re.compile(r'^PT\d+[A-Za-z]+\d*[A-Za-z]*$')
FIELD_NAME_PATTERN = re.compile(r'^[a-z][a-z0-9_]*$')
MODULE_NAME_PATTERN = re.compile(r'^[A-Z][a-zA-Z0-9]*$')

SUPPORTED_VERSIONS = {"0.2.0", "0.3.0", "0.3.1", "0.3.2"}

# v0.3 — standard claims recognized for $auth (cf. proposal.md). Custom claims
# fall back to `claims["<name>"]` on the compiler side.
AUTH_USER_ID_CLAIMS = {"user_id", "id", "sub", "subject", "userid", "user.id"}
AUTH_USERNAME_CLAIMS = {"username", "email", "upn", "preferred_username", "name"}
AUTH_ROLE_CLAIMS = {"role", "roles", "groups"}
KNOWN_AUTH_CLAIMS = AUTH_USER_ID_CLAIMS | AUTH_USERNAME_CLAIMS | AUTH_ROLE_CLAIMS

# v0.3 — $generate kinds spec'd (cf. proposal.md). Toute autre valeur → rejet.
# GENERATE_BUILTIN_KINDS is derived from the schema (WS0, assigned below); the
# parameterized form (dict {kind, ...}) adds slug/template and stays literal.
GENERATE_PARAMETERIZED_KINDS = {"uuid", "now", "sequence", "ulid", "nanoid", "slug", "template"}

# v0.3 — allowed $context namespace prefixes (cf. proposal.md spec decision).
CONTEXT_NAMESPACES = {"request", "tenant"}


# ─── JSON-schema loader (v0.3) ────────────────────────────────────────────────

_V03_SCHEMA_CACHE: dict | None = None
_SCHEMA_REL = ("docs", "schemas", "acir-v0.3.1.json")
# The validator is invoked from various layouts: local repo
# (`compilers/acir_validator.py` → parent.parent = repo root), conteneur
# Docker (`/app/backend/compilers/...` → parent.parent = `/app/backend`),
# and CI. We try a list of candidates instead of a single path so
# the JSON-schema pass is always active (otherwise SCHEMA_FILE_MISSING
# → silent degraded validation).
_here = Path(__file__).resolve()
_V03_SCHEMA_CANDIDATES = [
    _here.parent.parent.joinpath(*_SCHEMA_REL),        # repo root layout
    _here.parent.parent.parent.joinpath(*_SCHEMA_REL),  # compilers nested 1 deeper
    Path("/app/backend").joinpath(*_SCHEMA_REL),        # conteneur (image bundle)
    Path("/app").joinpath(*_SCHEMA_REL),                # conteneur (alt)
]


def _resolve_v03_schema_path():
    for cand in _V03_SCHEMA_CANDIDATES:
        if cand.exists():
            return cand
    return _V03_SCHEMA_CANDIDATES[0]  # default for the error message


_V03_SCHEMA_PATH = _resolve_v03_schema_path()

# ACIR versions handled in first-class v0.3 mode (schema Draft 2020-12 +
# L2/L3 semantic extensions). 0.3.0 and 0.3.1 share the same schema
# (acir-v0.3.1.json, acir_version enum) and the same semantic rules —
# 0.3.1 only adds the string form of $calculate, handled at compiler level.
_V03_VERSIONS = ("0.3.0", "0.3.1", "0.3.2")


def _is_v03(version) -> bool:
    """True if `version` must be validated in v0.3 mode (vs legacy v0.2)."""
    return version in _V03_VERSIONS


def _load_v03_schema() -> dict | None:
    """Lazy-load the v0.3 JSON-Schema (covers 0.3.0 and 0.3.1). Module-level cache
    to avoid re-reading the file on every call. Returns None if the file
    is absent (the validator degrades gracefully to the manual checks
    uniquement).
    """
    global _V03_SCHEMA_CACHE
    if _V03_SCHEMA_CACHE is not None:
        return _V03_SCHEMA_CACHE
    if not _V03_SCHEMA_PATH.exists():
        return None
    try:
        with open(_V03_SCHEMA_PATH, "r", encoding="utf-8") as f:
            _V03_SCHEMA_CACHE = json.load(f)
        return _V03_SCHEMA_CACHE
    except Exception:
        return None


# ─── WS0: closed enums derived from the schema (single source of truth) ─────────────
# cf. docs/ACIR-CANONICAL-COMPLETENESS.md. Le validateur ne recopie plus les
# enums: it reads them from the JSON-schema. Fallback = reconciled canon (if the
# schema is absent, the validator stays functional offline). The
# tests/conformance/ gate breaks if schema and constants diverge.

def _enum_from_schema(path: tuple, fallback: set) -> set:
    """Reads a closed enum under schema["$defs"] via `path` (keys + list indices)."""
    schema = _load_v03_schema()
    if schema is None:
        return set(fallback)
    try:
        node = schema["$defs"]
        for key in path:
            node = node[key]
        return set(node)
    except (KeyError, IndexError, TypeError):
        return set(fallback)


SCALAR_KINDS = _enum_from_schema(
    ("DScalar", "properties", "kind", "enum"),
    {"string", "integer", "decimal", "boolean", "datetime", "date", "time",
     "duration", "binary", "uuid", "void"})
SOURCE_KINDS = _enum_from_schema(
    ("IOQuery", "properties", "source_kind", "enum"), {"relational"})
HTTP_METHODS = _enum_from_schema(
    ("IOExpose", "properties", "method", "enum"),
    {"GET", "POST", "PUT", "PATCH", "DELETE"})
EXPOSE_KINDS = _enum_from_schema(
    ("IOExpose", "properties", "kind", "enum"), {"http_endpoint"})
MUTATE_ACTIONS = _enum_from_schema(
    ("IOMutate", "properties", "action", "enum"),
    {"create", "update", "patch", "delete"})
ERROR_KINDS = _enum_from_schema(
    ("FGuard", "properties", "on_fail", "properties", "kind", "enum"),
    {"not_found", "conflict", "validation_failed", "unauthorized", "forbidden", "internal"})
GENERATE_BUILTIN_KINDS = _enum_from_schema(
    ("GenerateExpr", "properties", "$generate", "oneOf", 0, "enum"),
    {"uuid", "now", "sequence", "ulid", "nanoid"})


# ─── Validateur principal ──────────────────────────────────────────────────────

class ACIRValidator:
    def __init__(self):
        self.issues: list[ValidationIssue] = []
        self.type_registry: dict[str, dict] = {}
        self.unit_registry: dict[str, dict] = {}
        self.stats: dict[str, Any] = {
            "types": 0, "units": 0, "endpoints": 0,
            "contracts": 0, "pipelines": 0, "orchestrations": 0,
        }
        # Did the normative JSON-Schema pass actually run?
        #   True  → applied;  False → expected but skipped (degraded);
        #   None  → not applicable (document is not v0.3).
        # `passed_levels` alone cannot express this: level 1 still "passes"
        # when the schema is skipped, so a bare 6/6 would overstate what was
        # checked. Consumers must gate on this, not on the level count.
        self.schema_validated: bool | None = None
        self._acir_kind: str = "module"

    def validate(self, doc: dict) -> ValidationResult:
        """Run the full validation pipeline."""
        self.issues = []
        self.type_registry = {}
        self.unit_registry = {}
        self.schema_validated = None
        self._acir_kind = "module"
        self._doc_version = doc.get("acir_version") if isinstance(doc, dict) else None

        # Niveau 1 — Validation structurelle (dispatch v0.2 / v0.3). Le mode v0.3
        # activates for EVERY 0.3.x version (0.3.0 AND 0.3.1) — the schema
        # acir-v0.3.1.json covers both (acir_version enum), and the v0.3
        # semantic rules (F_FOREACH/$calculate/$auth/...) are identical.
        if _is_v03(self._doc_version):
            self._level1_jsonschema_v03(doc)

        # Dispatch sur `acir_kind` (0.3.2). "project" ⇒ manifeste
        # multi-component: no top-level `module` → we do NOT run
        # by the module pipeline (level1_structural/2-6 assume `doc["module"]`).
        # Keep the level-1 JSON-schema (covers the project kind) then a
        # dedicated project pass (inline component recursion + deps graph).
        acir_kind = doc.get("acir_kind", "module") if isinstance(doc, dict) else "module"
        self._acir_kind = acir_kind
        if acir_kind == "project":
            # A project manifest has its own, shorter pipeline: the schema pass
            # then the project pass. Levels 3-6 assume `doc["module"]` and are
            # not applicable — so the denominator here is 2, not 6.
            if any(i.severity == Severity.ERROR for i in self.issues):
                return self._build_result(passed_level=1, total_levels=2)
            self._level_project(doc)
            return self._build_result(passed_level=2, total_levels=2)

        self._level1_structural(doc)
        l1_errors = sum(1 for i in self.issues if i.severity == Severity.ERROR)
        if l1_errors > 0:
            return self._build_result(passed_level=1)

        # Level 2 — Semantic coherence (legacy + v0.3 extensions)
        self._level2_semantic(doc)
        if _is_v03(self._doc_version):
            self._level2_v03_extensions(doc)
        l2_errors = sum(1 for i in self.issues if i.severity == Severity.ERROR and i.level == 2)
        if l2_errors > 0:
            return self._build_result(passed_level=2)

        # Level 3 — Contract verification (+ v0.3 $calculate DSL parser)
        self._level3_contracts(doc)
        if _is_v03(self._doc_version):
            self._level3_v03_calculate_dsl(doc)

        # Level 4 — Target compatibility (info only for now)
        self._level4_target_compat(doc)

        # Level 5 — Security analysis
        self._level5_security(doc)

        # Level 6 — Integration
        self._level6_integration(doc)

        return self._build_result(passed_level=6)

    # ─── NIVEAU 1 v0.3 : JSON-schema Draft 2020-12 ─────────────────────────

    def _level1_jsonschema_v03(self, doc: dict):
        """Wire the formal JSON-Schema into the v0.3 structural pass."""
        if not _JSONSCHEMA_AVAILABLE:
            self.schema_validated = False
            self._issue(1, Severity.WARNING, "$", "JSONSCHEMA_UNAVAILABLE",
                       "The `jsonschema` module is not installed — v0.3 structural pass degraded to manual checks only",
                       suggestion="pip install jsonschema==4.23.0")
            return
        schema = _load_v03_schema()
        if schema is None:
            self.schema_validated = False
            self._issue(1, Severity.WARNING, "$", "SCHEMA_FILE_MISSING",
                       f"v0.3.0 JSON schema not found at {_V03_SCHEMA_PATH} — structural pass degraded",
                       suggestion="Check that docs/schemas/acir-v0.3.1.json exists")
            return
        self.schema_validated = True
        validator = Draft202012Validator(schema)

        def _fmt_path(e) -> str:
            return "$." + ".".join(str(p) for p in e.absolute_path) if e.absolute_path else "$"

        def _deepest(e):
            """For oneOf/anyOf, the raw message ('is not valid under any of
            the given schemas' + full dump, truncated at 500) is unactionable
            — the LLM cannot fix itself in 3 tries. We descend into the
            most relevant sub-error to surface the REAL defect.

            Discriminated unions (Operation, TypeRef…: each variant has a
            distinct `primitive`/const key): the NON-selected variants
            fail superficially on the discriminator (`const` on
            `primitive`). We discard them and take the sub-error at the
            DEEPEST path among the rest (= the variant that matched the
            discriminator but has an internal defect, e.g. additionalProperties
            'filters' on IO_QUERY). Recursive (nested oneOf)."""
            ctx = list(getattr(e, "context", None) or [])
            if not ctx:
                return e

            # Group sub-errors by variant (1st index of the
            # schema_path = index in the oneOf/anyOf).
            from collections import defaultdict
            branches = defaultdict(list)
            for se in ctx:
                sp = list(getattr(se, "relative_schema_path", None) or se.schema_path or [0])
                branches[sp[0]].append(se)

            def _disc(se):
                p = list(se.absolute_path)
                return se.validator == "const" and p and str(p[-1]) in (
                    "primitive", "$ref", "kind", "$secret")

            # Matched variant = the one WITHOUT a discriminator failure (the
            # `primitive`/`$ref`/`kind` const matched; the other variants
            # failed on it → selection noise). If any remain, take the
            # most "targeted" one (fewer sub-errors = closest to the goal).
            matched = [errs for errs in branches.values()
                       if not any(_disc(s) for s in errs)]
            pool = min(matched, key=len) if matched else min(
                branches.values(), key=len)
            # Within the selected variant: prioritize concrete field defects
            # (additionalProperties/enum/pattern/type) vs bruit (required/const),
            # then deepest path.
            prio = {"additionalProperties": 0, "enum": 1, "pattern": 2,
                    "type": 3, "format": 4, "minimum": 5, "maximum": 5,
                    "required": 8, "const": 9}
            pick = min(pool, key=lambda se: (prio.get(se.validator, 6),
                                             -len(list(se.absolute_path))))
            return _deepest(pick)

        seen = set()
        # Iterate all errors (vs. fail-fast) to give complete feedback
        # exhaustif au LLM — un seul appel /api/generate peut produire des
        # corrections multiples si on rapporte plusieurs erreurs d'un coup.
        for err in validator.iter_errors(doc):
            code = f"SCHEMA_{err.validator.upper()}" if err.validator else "SCHEMA_VIOLATION"
            if err.validator in ("oneOf", "anyOf"):
                # Path = faulty node + deep path of the sub-error;
                # message = concrete defect instead of the opaque dump.
                sub = _deepest(err)
                tail = list(sub.absolute_path)[len(list(err.absolute_path)):]
                path = _fmt_path(err) + ("." + ".".join(str(p) for p in tail) if tail else "")
                msg = (f"no {err.validator} variant accepted — most likely defect: "
                       f"{sub.message[:300]}")
            else:
                path = _fmt_path(err)
                msg = err.message[:500]
            key = (code, path, msg[:120])
            if key in seen:
                continue
            seen.add(key)
            self._issue(1, Severity.ERROR, path, code, msg)

    def _build_result(self, passed_level: int, total_levels: int = 6) -> ValidationResult:
        has_errors = any(i.severity == Severity.ERROR for i in self.issues)
        self.stats["acir_kind"] = self._acir_kind
        self.stats["passed_levels"] = passed_level
        self.stats["total_levels"] = total_levels
        self.stats["schema_validated"] = self.schema_validated
        return ValidationResult(
            valid=not has_errors,
            issues=self.issues,
            stats=self.stats,
        )

    def _issue(self, level: int, severity: Severity, path: str,
               code: str, message: str, suggestion: str = ""):
        self.issues.append(ValidationIssue(level, severity, path, code, message, suggestion))

    # ─── NIVEAU PROJET (0.3.2) : manifeste multi-composants ────────────────

    def _level_project(self, doc: dict):
        """Validation of an `acir_kind:"project"` document."""
        project = doc.get("project", {}) if isinstance(doc, dict) else {}
        components = project.get("components", []) or []
        name_set = {c.get("name") for c in components if c.get("name")}
        self.stats["components"] = len(components)

        # Dependency graph + references
        graph: dict[str, list] = {}
        for c in components:
            cname = c.get("name", "?")
            deps = []
            for d in (c.get("dependencies") or []):
                dn = d.get("$component")
                if dn is None:
                    continue
                if dn not in name_set:
                    self._issue(
                        2, Severity.ERROR,
                        f"$.project.components[{cname}].dependencies",
                        "PROJECT_DEP_UNKNOWN",
                        f"Component '{cname}' depends on '{dn}', not declared in project.components[]",
                        suggestion=f"Declare a component '{dn}' or fix the reference")
                else:
                    deps.append(dn)
            graph[cname] = deps

        # Cycle detection (tri-color DFS)
        WHITE, GRAY, BLACK = 0, 1, 2
        color = {n: WHITE for n in graph}
        reported = set()

        def dfs(node, stack):
            color[node] = GRAY
            stack.append(node)
            for nxt in graph.get(node, []):
                if color.get(nxt) == GRAY:
                    cyc = stack[stack.index(nxt):] + [nxt]
                    key = tuple(sorted(set(cyc)))
                    if key not in reported:
                        reported.add(key)
                        self._issue(
                            2, Severity.WARNING,
                            f"$.project.components[{node}].dependencies",
                            "PROJECT_DEP_CYCLE",
                            f"Dependency cycle between components: {' → '.join(cyc)} "
                            f"— tolerated (mutual calls are common in microservices). "
                            f"The infra breaks the cycle for boot order: all "
                            f"services start, the back edge does not wait "
                            f"'healthy', l'IO_CALL retente.",
                            suggestion="No action required; if start order matters, extract a shared dependency")
                elif color.get(nxt) == WHITE:
                    dfs(nxt, stack)
            stack.pop()
            color[node] = BLACK

        for n in list(graph):
            if color.get(n) == WHITE:
                dfs(n, [])

        # Components: inline (recursion) | external (resolved at orchestration)
        for c in components:
            cname = c.get("name", "?")
            docref = c.get("document", {}) if isinstance(c.get("document"), dict) else {}
            if "$inline" in docref:
                sub_res = ACIRValidator().validate(docref["$inline"])
                for it in sub_res.issues:
                    if it.severity == Severity.ERROR:
                        self._issue(
                            it.level, it.severity,
                            f"$.project.components[{cname}].document.$inline{str(it.path).lstrip('$')}",
                            it.code, f"[{cname}] {it.message}", it.suggestion)
            elif "$component" in docref:
                self._issue(
                    2, Severity.INFO,
                    f"$.project.components[{cname}].document",
                    "PROJECT_COMPONENT_EXTERNAL",
                    f"Component '{cname}' referenced ('{docref['$component']}') — validated at resolution (Tier C orchestration)")

        # ── IO_CALL cross-doc (ACIR 0.3.2) ──
        # A component's IO_CALL must target a `module` declared in ITS
        # dependencies (otherwise the infra does not inject `<MODULE>_URL`). If the
        # target is resolved ($inline), endpoint+method must match a
        # route exposed by the target.
        def _find_io_calls(node):
            out = []
            if isinstance(node, dict):
                if node.get("primitive") == "IO_CALL":
                    out.append(node)
                for v in node.values():
                    out.extend(_find_io_calls(v))
            elif isinstance(node, list):
                for v in node:
                    out.extend(_find_io_calls(v))
            return out

        def _routes(mod):
            r = set()
            for ep in (mod.get("exposed", []) or []):
                if ep.get("kind", "http_endpoint") == "http_endpoint":
                    norm = re.sub(r"\{[^}]+\}", "{}", ep.get("route", ""))
                    r.add((ep.get("method", "GET").upper(), norm))
            return r

        inline_mod = {}
        for c in components:
            dr = c.get("document", {}) if isinstance(c.get("document"), dict) else {}
            if "$inline" in dr and isinstance(dr["$inline"], dict):
                inline_mod[c.get("name")] = dr["$inline"].get("module", {}) or {}

        for c in components:
            cname = c.get("name", "?")
            dr = c.get("document", {}) if isinstance(c.get("document"), dict) else {}
            if "$inline" not in dr:
                continue
            decl_deps = {d.get("$component") for d in (c.get("dependencies") or [])}
            for call in _find_io_calls(dr["$inline"].get("module", {})):
                tgt = call.get("module")
                if tgt not in decl_deps:
                    if tgt not in name_set:
                        # Nonexistent target: the generator invented a service
                        # third party (payment gateway, external API…) that no
                        # composant du projet ne fournit. Pas d'auto-stub —
                        # explicit, actionable failure (product decision).
                        self._issue(
                            2, Severity.ERROR,
                            f"$.project.components[{cname}]",
                            "CROSS_CALL_UNKNOWN_SERVICE",
                            f"'{cname}' makes an IO_CALL to '{tgt}', which is NOT "
                            f"a service of this project (components: "
                            f"{', '.join(sorted(name_set))}). The generator has "
                            f"probably invented an external system. ACIR "
                            f"IO_CALL is only for calls between microservices "
                            f"OF the project.",
                            suggestion=(f"Rephrase the brief of '{cname}' for "
                                        f"'{tgt}' to be handled as internal "
                                        f"logic/stub (NO IO_CALL), OR describe "
                                        f"'{tgt}' explicitly as a full-fledged "
                                        f"service of the project, then regenerate."))
                    else:
                        self._issue(
                            2, Severity.ERROR,
                            f"$.project.components[{cname}]",
                            "CROSS_CALL_UNDECLARED_DEP",
                            f"IO_CALL from '{cname}' to '{tgt}' not declared in its dependencies "
                            f"→ l'infra n'injectera pas {str(tgt).upper()}_URL",
                            suggestion=f"Add {{\"$component\": \"{tgt}\"}} to the dependencies of '{cname}'")
                    continue
                if tgt in inline_mod:
                    want = (str(call.get("method", "GET")).upper(),
                            re.sub(r"\{[^}]+\}", "{}", call.get("endpoint", "")))
                    if want not in _routes(inline_mod[tgt]):
                        self._issue(
                            2, Severity.WARNING,
                            f"$.project.components[{cname}]",
                            "CROSS_CALL_ENDPOINT_UNRESOLVED",
                            f"IO_CALL {want[0]} {call.get('endpoint')} → '{tgt}' "
                            f"matches no route exposed by the target",
                            suggestion="Check endpoint/method vs the target component's exposed[]")

    # ─── NIVEAU 1 : Validation structurelle ────────────────────────────────

    def _level1_structural(self, doc: dict):
        """Check that the document is structurally valid."""

        # Racine
        if not isinstance(doc, dict):
            self._issue(1, Severity.ERROR, "$", "NOT_OBJECT",
                       "The ACIR document must be a JSON object")
            return

        # Version
        version = doc.get("acir_version")
        if version is None:
            self._issue(1, Severity.ERROR, "$.acir_version", "MISSING_VERSION",
                       "The 'acir_version' field is required")
        elif version not in SUPPORTED_VERSIONS:
            supported = ", ".join(sorted(SUPPORTED_VERSIONS))
            self._issue(1, Severity.WARNING, "$.acir_version", "VERSION_UNSUPPORTED",
                       f"Version '{version}' — supported versions: {supported}",
                       suggestion=f"Use one of the supported versions: {supported}")

        # Module
        module = doc.get("module")
        if module is None:
            self._issue(1, Severity.ERROR, "$.module", "MISSING_MODULE",
                       "The 'module' field is required")
            return

        self._validate_module(module, "$.module")

    def _validate_module(self, module: dict, path: str):
        """Validate the structure of an X_MODULE."""
        if not isinstance(module, dict):
            self._issue(1, Severity.ERROR, path, "MODULE_NOT_OBJECT",
                       "The module must be an object")
            return

        # Nom requis
        name = module.get("name")
        if not name:
            self._issue(1, Severity.ERROR, f"{path}.name", "MISSING_MODULE_NAME",
                       "The module must have a name")
        elif not MODULE_NAME_PATTERN.match(name):
            self._issue(1, Severity.WARNING, f"{path}.name", "MODULE_NAME_FORMAT",
                       f"Name '{name}' should be PascalCase",
                       "Use a format like 'ProductCatalog'")

        # Types
        types = module.get("types", [])
        if isinstance(types, list):
            for i, t in enumerate(types):
                self._validate_type_def(t, f"{path}.types[{i}]")
                self.stats["types"] += 1

        # Units
        units = module.get("units", [])
        if isinstance(units, list):
            for i, u in enumerate(units):
                self._validate_unit(u, f"{path}.units[{i}]")
                self.stats["units"] += 1

        # Exposed endpoints
        exposed = module.get("exposed", [])
        if isinstance(exposed, list):
            for i, e in enumerate(exposed):
                self._validate_expose(e, f"{path}.exposed[{i}]")
                self.stats["endpoints"] += 1

        # Pipelines
        pipelines = module.get("pipelines", [])
        if isinstance(pipelines, list):
            for i, p in enumerate(pipelines):
                self._validate_pipeline(p, f"{path}.pipelines[{i}]")
                self.stats["pipelines"] += 1

        # Orchestrations
        orchestrations = module.get("orchestrations", [])
        if isinstance(orchestrations, list):
            for i, o in enumerate(orchestrations):
                self._validate_orchestration(o, f"{path}.orchestrations[{i}]")
                self.stats["orchestrations"] += 1

        # Contracts au niveau module
        contracts = module.get("contracts", [])
        if isinstance(contracts, list):
            for i, c in enumerate(contracts):
                self._validate_contract(c, f"{path}.contracts[{i}]")

    def _validate_type_def(self, typedef: dict, path: str):
        """Validate a type definition (D_*)."""
        if not isinstance(typedef, dict):
            self._issue(1, Severity.ERROR, path, "TYPE_NOT_OBJECT",
                       "A type definition must be an object")
            return

        primitive = typedef.get("primitive")
        if primitive not in VALID_PRIMITIVES:
            self._issue(1, Severity.ERROR, f"{path}.primitive", "INVALID_PRIMITIVE",
                       f"Unknown primitive: '{primitive}'")
            return

        if not primitive.startswith("D_"):
            self._issue(1, Severity.ERROR, f"{path}.primitive", "NOT_DATA_PRIMITIVE",
                       f"'{primitive}' is not a data primitive (D_*)")
            return

        name = typedef.get("name")
        if name and isinstance(name, str):
            self.type_registry[name] = typedef

        if primitive == "D_SCALAR":
            self._validate_scalar(typedef, path)
        elif primitive == "D_ENUM":
            self._validate_enum(typedef, path)
        elif primitive == "D_RECORD":
            self._validate_record(typedef, path)
        elif primitive == "D_COLLECTION":
            self._validate_collection(typedef, path)
        elif primitive == "D_ALIAS":
            self._validate_alias(typedef, path)
        elif primitive == "D_UNION":
            self._validate_union(typedef, path)

    def _validate_scalar(self, scalar: dict, path: str):
        kind = scalar.get("kind")
        if kind not in SCALAR_KINDS:
            self._issue(1, Severity.ERROR, f"{path}.kind", "INVALID_SCALAR_KIND",
                       f"Kind scalaire invalide: '{kind}'. Valides: {', '.join(sorted(SCALAR_KINDS))}")

    def _validate_enum(self, enum_def: dict, path: str):
        values = enum_def.get("values")
        if not isinstance(values, list) or len(values) == 0:
            self._issue(1, Severity.ERROR, f"{path}.values", "EMPTY_ENUM",
                       "An enum must have at least one value")
            return
        names_seen = set()
        for i, v in enumerate(values):
            n = v.get("name") if isinstance(v, dict) else None
            if not n:
                self._issue(1, Severity.ERROR, f"{path}.values[{i}]", "ENUM_VALUE_NO_NAME",
                           "Each enum value must have a 'name'")
            elif n in names_seen:
                self._issue(1, Severity.ERROR, f"{path}.values[{i}]", "DUPLICATE_ENUM_VALUE",
                           f"Duplicate enum value: '{n}'")
            else:
                names_seen.add(n)

    def _validate_record(self, record: dict, path: str):
        fields = record.get("fields")
        if not isinstance(fields, list) or len(fields) == 0:
            self._issue(1, Severity.ERROR, f"{path}.fields", "NO_FIELDS",
                       "A D_RECORD must have at least one field")
            return

        field_names = set()
        for i, f in enumerate(fields):
            self._validate_field(f, f"{path}.fields[{i}]")
            fname = f.get("name") if isinstance(f, dict) else None
            if fname:
                if fname in field_names:
                    self._issue(1, Severity.ERROR, f"{path}.fields[{i}]", "DUPLICATE_FIELD",
                               f"Duplicate field: '{fname}'")
                field_names.add(fname)

        # Check that identity references existing fields
        identity = record.get("identity", [])
        if isinstance(identity, list):
            for id_field in identity:
                if id_field not in field_names:
                    self._issue(1, Severity.ERROR, f"{path}.identity", "IDENTITY_FIELD_NOT_FOUND",
                               f"Identity field '{id_field}' does not exist among the record's fields")

    def _validate_field(self, f: dict, path: str):
        if not isinstance(f, dict):
            self._issue(1, Severity.ERROR, path, "FIELD_NOT_OBJECT", "A field must be an object")
            return
        name = f.get("name")
        if not name:
            self._issue(1, Severity.ERROR, f"{path}.name", "MISSING_FIELD_NAME",
                       "The field must have a 'name'")
        elif not FIELD_NAME_PATTERN.match(name):
            self._issue(1, Severity.WARNING, f"{path}.name", "FIELD_NAME_FORMAT",
                       f"Field name '{name}' should be snake_case",
                       "Use a format like 'created_at'")
        if "type" not in f:
            self._issue(1, Severity.ERROR, f"{path}.type", "MISSING_FIELD_TYPE",
                       f"Field '{name}' must have a 'type'")
        else:
            # Recurse into inline type definitions (D_COLLECTION, inline D_RECORD, etc.)
            # so canonical-form rules apply to nested types too.
            self._validate_inline_type(f["type"], f"{path}.type")

        # Field-level contracts
        contracts = f.get("contracts", [])
        if isinstance(contracts, list):
            for i, c in enumerate(contracts):
                self._validate_contract(c, f"{path}.contracts[{i}]")
                self.stats["contracts"] += 1

    def _validate_inline_type(self, t: Any, path: str):
        """Validate an inline type expression (anywhere a type can appear, e.g. inside a field)."""
        if not isinstance(t, dict):
            return
        if "$ref" in t:
            return  # ref to a top-level type, validated elsewhere
        prim = t.get("primitive")
        if prim == "D_COLLECTION":
            self._validate_collection(t, path)
            # Recurse into element_type / key_type / value_type
            for k in ("element_type", "key_type", "value_type"):
                if k in t:
                    self._validate_inline_type(t[k], f"{path}.{k}")
        elif prim == "D_RECORD":
            for i, sub in enumerate(t.get("fields", [])):
                self._validate_field(sub, f"{path}.fields[{i}]")

    # Forbidden synonyms for D_COLLECTION (cf. ACIR_SPEC.md §Canonical forms)
    _COLLECTION_SYNONYMS = {"item_type", "items", "of", "element", "elements"}

    def _validate_collection(self, coll: dict, path: str):
        kind = coll.get("kind", "list")  # default: list (often omitted by LLMs)
        if kind not in {"list", "set", "map", "queue", "stack"}:
            self._issue(1, Severity.ERROR, f"{path}.kind", "INVALID_COLLECTION_KIND",
                       f"Kind de collection invalide: '{kind}'")

        # Reject non-canonical synonym keys with a precise message
        for syn in self._COLLECTION_SYNONYMS:
            if syn in coll:
                self._issue(1, Severity.ERROR, f"{path}.{syn}", "COLLECTION_NON_CANONICAL_KEY",
                           f"Non-canonical key '{syn}' in D_COLLECTION; use 'element_type'",
                           f"Rename '{syn}' to 'element_type' (cf. ACIR_SPEC.md §Canonical forms)")

        if kind == "map":
            if "key_type" not in coll:
                self._issue(1, Severity.ERROR, f"{path}.key_type", "MAP_MISSING_KEY_TYPE",
                           "A 'map' collection must have a 'key_type'")
            if "value_type" not in coll:
                self._issue(1, Severity.ERROR, f"{path}.value_type", "MAP_MISSING_VALUE_TYPE",
                           "A 'map' collection must have a 'value_type'")
        else:
            if "element_type" not in coll:
                self._issue(1, Severity.ERROR, f"{path}.element_type", "MISSING_ELEMENT_TYPE",
                           "A collection must have an 'element_type' (canonical form)",
                           "Add 'element_type' (cf. ACIR_SPEC.md §Canonical forms)")

    def _validate_alias(self, alias: dict, path: str):
        if "name" not in alias:
            self._issue(1, Severity.ERROR, f"{path}.name", "ALIAS_MISSING_NAME",
                       "A D_ALIAS must have a 'name'")
        if "base_type" not in alias:
            self._issue(1, Severity.ERROR, f"{path}.base_type", "ALIAS_MISSING_BASE",
                       "A D_ALIAS must have a 'base_type'")

    def _validate_union(self, union: dict, path: str):
        if "discriminator" not in union:
            self._issue(1, Severity.ERROR, f"{path}.discriminator", "UNION_MISSING_DISCRIMINATOR",
                       "A D_UNION must have a 'discriminator'")
        variants = union.get("variants", [])
        if not isinstance(variants, list) or len(variants) < 2:
            self._issue(1, Severity.ERROR, f"{path}.variants", "UNION_MIN_VARIANTS",
                       "A D_UNION must have at least 2 variants")

    def _validate_unit(self, unit: dict, path: str):
        """Validate an X_UNIT."""
        if not isinstance(unit, dict):
            self._issue(1, Severity.ERROR, path, "UNIT_NOT_OBJECT", "An X_UNIT must be an object")
            return

        name = unit.get("name")
        if not name:
            self._issue(1, Severity.ERROR, f"{path}.name", "MISSING_UNIT_NAME",
                       "An X_UNIT must have a 'name'")
        else:
            self.unit_registry[name] = unit

        if "output" not in unit:
            self._issue(1, Severity.ERROR, f"{path}.output", "MISSING_UNIT_OUTPUT",
                       f"Unit '{name}' must declare an output type")

        if "body" not in unit:
            self._issue(1, Severity.ERROR, f"{path}.body", "MISSING_UNIT_BODY",
                       f"Unit '{name}' must have a 'body'")
        else:
            self._validate_operation(unit["body"], f"{path}.body")

        contracts = unit.get("contracts", [])
        if isinstance(contracts, list):
            for i, c in enumerate(contracts):
                self._validate_contract(c, f"{path}.contracts[{i}]")
                self.stats["contracts"] += 1

    def _validate_operation(self, op: dict, path: str):
        """Recursively validate an operation (F_* or IO_*)."""
        if not isinstance(op, dict):
            return

        primitive = op.get("primitive")
        if not primitive:
            # Can be a $ref
            if "$ref" in op:
                return
            self._issue(1, Severity.WARNING, path, "OP_NO_PRIMITIVE",
                       "Operation without 'primitive' or '$ref'")
            return

        if primitive not in VALID_PRIMITIVES:
            self._issue(1, Severity.ERROR, f"{path}.primitive", "INVALID_OP_PRIMITIVE",
                       f"Unknown operation primitive: '{primitive}'")
            return

        # Type-specific validation
        if primitive == "F_SEQUENCE":
            steps = op.get("steps", [])
            for i, s in enumerate(steps):
                if isinstance(s, dict) and "op" in s:
                    self._validate_operation(s["op"], f"{path}.steps[{i}].op")
                    if "name" not in s:
                        self._issue(1, Severity.WARNING, f"{path}.steps[{i}]", "STEP_NO_NAME",
                                   "F_SEQUENCE steps should be named",
                                   "Add a 'name' field to enable referencing via $step")

        elif primitive == "F_GUARD":
            if "condition" not in op:
                self._issue(1, Severity.ERROR, f"{path}.condition", "GUARD_NO_CONDITION",
                           "F_GUARD must have a 'condition'")
            if "on_fail" not in op:
                self._issue(1, Severity.ERROR, f"{path}.on_fail", "GUARD_NO_ON_FAIL",
                           "F_GUARD must have an 'on_fail'")
            else:
                on_fail = op["on_fail"]
                if isinstance(on_fail, dict):
                    kind = on_fail.get("kind")
                    if kind and kind not in ERROR_KINDS:
                        self._issue(1, Severity.ERROR, f"{path}.on_fail.kind", "INVALID_ERROR_KIND",
                                   f"ErrorKind invalide: '{kind}'")

        elif primitive == "F_BRANCH":
            if _is_v03(self._doc_version):
                # Forme canonique v0.3 ($defs/FBranch) : {condition, then,
                # else?} — PAS de tableau `conditions`. Le schema JSON (niveau
                # 1 v0.3) already checked the presence of condition/then; here we
                # just recurses into then/else. (Without this gate, a
                # valid v0.3 F_BRANCH triggered a false BRANCH_NO_CONDITIONS
                # since the legacy structural pass expects the v0.2 shape.)
                if "then" in op:
                    self._validate_operation(op["then"], f"{path}.then")
                if "else" in op:
                    self._validate_operation(op["else"], f"{path}.else")
            else:
                conditions = op.get("conditions", [])
                if len(conditions) == 0:
                    self._issue(1, Severity.ERROR, f"{path}.conditions", "BRANCH_NO_CONDITIONS",
                               "F_BRANCH must have at least one condition")
                for i, c in enumerate(conditions):
                    if isinstance(c, dict) and "then" in c:
                        self._validate_operation(c["then"], f"{path}.conditions[{i}].then")

        elif primitive == "F_RETRY":
            if "max_attempts" not in op:
                self._issue(1, Severity.ERROR, f"{path}.max_attempts", "RETRY_NO_MAX",
                           "F_RETRY must have a 'max_attempts'")
            if "operation" in op:
                self._validate_operation(op["operation"], f"{path}.operation")

        elif primitive == "F_PARALLEL":
            branches = op.get("branches", [])
            if len(branches) < 2:
                self._issue(1, Severity.ERROR, f"{path}.branches", "PARALLEL_MIN_BRANCHES",
                           "F_PARALLEL must have at least 2 branches")
            for i, b in enumerate(branches):
                if isinstance(b, dict):
                    if "name" not in b:
                        self._issue(1, Severity.WARNING, f"{path}.branches[{i}]", "BRANCH_NO_NAME",
                                   "Parallel branches should be named")
                    if "op" in b:
                        self._validate_operation(b["op"], f"{path}.branches[{i}].op")

        elif primitive == "F_CIRCUIT_BREAKER":
            for field in ["failure_threshold", "success_threshold", "open_duration"]:
                if field not in op:
                    self._issue(1, Severity.ERROR, f"{path}.{field}", f"CB_MISSING_{field.upper()}",
                               f"F_CIRCUIT_BREAKER must have a '{field}'")
            if "operation" in op:
                self._validate_operation(op["operation"], f"{path}.operation")
            if "fallback" in op:
                self._validate_operation(op["fallback"], f"{path}.fallback")

        elif primitive == "IO_QUERY":
            # v0.3: source_kind is optional and defaults to "relational" (cf. JSON-schema
            # `default: "relational"`). In v0.2 it was required; relaxed to allow
            # v0.3 docs to omit the key without legacy rejection.
            source_kind = op.get("source_kind")
            if source_kind is not None and source_kind not in SOURCE_KINDS:
                self._issue(1, Severity.ERROR, f"{path}.source_kind", "INVALID_SOURCE_KIND",
                           f"source_kind invalide: '{source_kind}'")
            if "entity" not in op:
                self._issue(1, Severity.ERROR, f"{path}.entity", "QUERY_NO_ENTITY",
                           "IO_QUERY must have an 'entity'")
            # Forme canonique : 'filter' (object map), pas 'filters' (array)
            if "filters" in op:
                self._issue(1, Severity.ERROR, f"{path}.filters", "QUERY_FILTERS_NON_CANONICAL",
                           "Non-canonical key 'filters' (array); use 'filter' (object map)",
                           "Rename 'filters: [...]' to 'filter: {field: {operator, value}, ...}' "
                           "(cf. ACIR_SPEC.md §Canonical forms)")
            self._check_canonical_refs(op.get("filter", {}), f"{path}.filter")
            self._check_canonical_pagination(op.get("pagination", {}), f"{path}.pagination")

        elif primitive == "IO_MUTATE":
            # v0.3 : source_kind optionnel (default "relational"), cf. JSON-schema.
            source_kind = op.get("source_kind")
            if source_kind is not None and source_kind not in SOURCE_KINDS:
                self._issue(1, Severity.ERROR, f"{path}.source_kind", "INVALID_SOURCE_KIND",
                           f"source_kind invalide: '{source_kind}'")
            action = op.get("action")
            if action not in MUTATE_ACTIONS:
                self._issue(1, Severity.ERROR, f"{path}.action", "INVALID_MUTATE_ACTION",
                           f"action invalide: '{action}'. Valides: {', '.join(MUTATE_ACTIONS)}")
            if action != "delete" and "data" not in op:
                self._issue(1, Severity.WARNING, f"{path}.data", "MUTATE_NO_DATA",
                           f"IO_MUTATE with action '{action}' should have a 'data'")
            # Canonical refs in data and filter ($input and $generate only, not $param)
            self._check_canonical_refs(op.get("data", {}), f"{path}.data")
            self._check_canonical_refs(op.get("filter", {}), f"{path}.filter")
            if "filters" in op:
                self._issue(1, Severity.ERROR, f"{path}.filters", "MUTATE_FILTERS_NON_CANONICAL",
                           "Non-canonical key 'filters' (array); use 'filter' (object map)",
                           "Rename 'filters: [...]' to 'filter: {field: {operator, value}, ...}'")

        elif primitive == "IO_HTTP":
            if op.get("method") not in HTTP_METHODS:
                self._issue(1, Severity.ERROR, f"{path}.method", "INVALID_HTTP_METHOD",
                           f"Invalid HTTP method: '{op.get('method')}'")
            if "url" not in op:
                self._issue(1, Severity.ERROR, f"{path}.url", "HTTP_NO_URL",
                           "IO_HTTP must have a 'url'")
            if "response_type" not in op:
                self._issue(1, Severity.ERROR, f"{path}.response_type", "HTTP_NO_RESPONSE_TYPE",
                           "IO_HTTP must declare a 'response_type'")

        elif primitive == "IO_MESSAGE":
            if "channel" not in op:
                self._issue(1, Severity.ERROR, f"{path}.channel", "MSG_NO_CHANNEL",
                           "IO_MESSAGE must have a 'channel'")
            if "payload" not in op:
                self._issue(1, Severity.ERROR, f"{path}.payload", "MSG_NO_PAYLOAD",
                           "IO_MESSAGE must have a 'payload'")

    # Cf. ACIR_SPEC.md §Canonical forms
    _INPUT_SOURCE_VALUES = {"body", "query", "path", "composite"}
    _INPUT_SOURCE_SYNONYMS = {"combined", "mixed", "query_params"}

    def _check_canonical_refs(self, node: Any, path: str):
        """Walk arbitrary value graph (dict / list / scalar) and reject $param + $default refs."""
        if isinstance(node, dict):
            if "$param" in node:
                self._issue(1, Severity.ERROR, f"{path}.$param", "REF_PARAM_NON_CANONICAL",
                           "Non-canonical reference '$param'; use '$input'",
                           "Rename '$param' to '$input' (cf. ACIR_SPEC.md §Canonical forms)")
            if "$default" in node:
                self._issue(1, Severity.ERROR, f"{path}.$default", "REF_DEFAULT_NON_CANONICAL",
                           "Non-canonical key '$default'; use 'default' (without $)",
                           "$ is reserved for dynamic refs; 'default' is a static value")
            for k, v in node.items():
                self._check_canonical_refs(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                self._check_canonical_refs(v, f"{path}[{i}]")

    def _check_canonical_pagination(self, pag: Any, path: str):
        """pagination.{page,limit,...} must use 'default' (without $)."""
        if isinstance(pag, dict):
            for field, spec in pag.items():
                if isinstance(spec, dict) and "$default" in spec:
                    self._issue(1, Severity.ERROR, f"{path}.{field}.$default",
                               "PAGINATION_DEFAULT_NON_CANONICAL",
                               f"pagination.{field}.$default is not canonical; use 'default' (without $)")

    def _validate_expose(self, expose: dict, path: str):
        """Validate an IO_EXPOSE."""
        if not isinstance(expose, dict):
            return

        kind = expose.get("kind")
        if kind not in EXPOSE_KINDS:
            self._issue(1, Severity.ERROR, f"{path}.kind", "INVALID_EXPOSE_KIND",
                       f"Kind d'exposition invalide: '{kind}'")

        if kind == "http_endpoint":
            if "route" not in expose:
                self._issue(1, Severity.ERROR, f"{path}.route", "HTTP_EXPOSE_NO_ROUTE",
                           "An HTTP endpoint must have a 'route'")
            method = expose.get("method")
            if method not in HTTP_METHODS:
                self._issue(1, Severity.ERROR, f"{path}.method", "HTTP_EXPOSE_NO_METHOD",
                           f"An HTTP endpoint must have a valid method, got: '{method}'")

            # input_source: enum string canonique uniquement
            if "input_source" in expose:
                src = expose["input_source"]
                if isinstance(src, dict):
                    self._issue(1, Severity.ERROR, f"{path}.input_source", "INPUT_SOURCE_INLINE_OBJECT",
                               "input_source is not canonical (inline object); use "
                               "input_source: \"composite\" + input_layout: {path:[...], body:\"...\"}")
                elif isinstance(src, str):
                    if src in self._INPUT_SOURCE_SYNONYMS:
                        canonical = "composite" if src in ("combined", "mixed") else "query"
                        self._issue(1, Severity.ERROR, f"{path}.input_source",
                                   "INPUT_SOURCE_NON_CANONICAL",
                                   f"Non-canonical input_source '{src}'; allowed values: "
                                   f"{sorted(self._INPUT_SOURCE_VALUES)}",
                                   f"Use '{canonical}' (cf. ACIR_SPEC.md §Canonical forms)")
                    elif src not in self._INPUT_SOURCE_VALUES:
                        self._issue(1, Severity.ERROR, f"{path}.input_source",
                                   "INPUT_SOURCE_INVALID",
                                   f"Invalid input_source '{src}'; allowed values: "
                                   f"{sorted(self._INPUT_SOURCE_VALUES)}")
                    elif src == "composite" and "input_layout" not in expose:
                        self._issue(1, Severity.ERROR, f"{path}.input_layout",
                                   "COMPOSITE_MISSING_LAYOUT",
                                   "input_source: 'composite' exige un 'input_layout' sibling "
                                   "({path:[...], body:\"...\"})")

        if kind == "scheduled":
            if "schedule" not in expose and "handler" not in expose:
                self._issue(1, Severity.ERROR, f"{path}.schedule", "SCHEDULED_NO_CRON",
                           "A scheduled endpoint must have a 'schedule' (cron expression)")

        if "handler" not in expose:
            self._issue(1, Severity.ERROR, f"{path}.handler", "EXPOSE_NO_HANDLER",
                       "IO_EXPOSE must have a 'handler'")

        if "output" not in expose:
            self._issue(1, Severity.ERROR, f"{path}.output", "EXPOSE_NO_OUTPUT",
                       "IO_EXPOSE must declare an output type")

        # Rate limit validation
        rate_limit = expose.get("rate_limit")
        if isinstance(rate_limit, dict):
            if "limit" not in rate_limit:
                self._issue(1, Severity.ERROR, f"{path}.rate_limit.limit", "RL_NO_LIMIT",
                           "rate_limit must have a 'limit'")
            if "window" not in rate_limit:
                self._issue(1, Severity.ERROR, f"{path}.rate_limit.window", "RL_NO_WINDOW",
                           "rate_limit must have a 'window'")

    def _validate_pipeline(self, pipeline: dict, path: str):
        if not isinstance(pipeline, dict):
            return
        stages = pipeline.get("stages", [])
        if len(stages) < 2:
            self._issue(1, Severity.ERROR, f"{path}.stages", "PIPELINE_MIN_STAGES",
                       "An X_PIPELINE must have at least 2 stages")
        for i, s in enumerate(stages):
            if isinstance(s, dict) and "name" not in s:
                self._issue(1, Severity.WARNING, f"{path}.stages[{i}]", "STAGE_NO_NAME",
                           "Pipeline stages should be named")

    def _validate_orchestration(self, orch: dict, path: str):
        if not isinstance(orch, dict):
            return
        steps = orch.get("steps", [])
        if len(steps) == 0:
            self._issue(1, Severity.ERROR, f"{path}.steps", "ORCH_NO_STEPS",
                       "An X_ORCHESTRATION must have at least 1 step")
        step_names = set()
        for i, s in enumerate(steps):
            if isinstance(s, dict):
                name = s.get("name")
                if name:
                    step_names.add(name)
                if "next" not in s:
                    self._issue(1, Severity.ERROR, f"{path}.steps[{i}].next", "STEP_NO_NEXT",
                               f"Step '{name}' must have a 'next'")

        # Check compensation
        compensation = orch.get("compensation", [])
        for i, c in enumerate(compensation):
            if isinstance(c, dict):
                for_step = c.get("for_step")
                if for_step and for_step not in step_names:
                    self._issue(1, Severity.ERROR, f"{path}.compensation[{i}].for_step",
                               "COMP_STEP_NOT_FOUND",
                               f"Compensation step '{for_step}' not found in steps")

    def _validate_contract(self, contract: dict, path: str):
        """Validate a contract primitive (C_*)."""
        if not isinstance(contract, dict):
            return
        primitive = contract.get("primitive")
        if not primitive or not primitive.startswith("C_"):
            self._issue(1, Severity.ERROR, f"{path}.primitive", "INVALID_CONTRACT_PRIMITIVE",
                       f"Invalid contract: '{primitive}' — must start with C_")
            return
        if primitive not in VALID_PRIMITIVES:
            self._issue(1, Severity.ERROR, f"{path}.primitive", "UNKNOWN_CONTRACT",
                       f"Unknown contract: '{primitive}'")

        # Specific validations
        if primitive == "C_RANGE":
            if "min" not in contract and "max" not in contract:
                self._issue(1, Severity.WARNING, f"{path}", "RANGE_NO_BOUNDS",
                           "C_RANGE without min or max has no effect")

        elif primitive == "C_PATTERN":
            regex = contract.get("regex")
            if regex:
                try:
                    re.compile(regex)
                except re.error as e:
                    self._issue(1, Severity.ERROR, f"{path}.regex", "INVALID_REGEX",
                               f"Invalid regular expression: {e}")

        elif primitive == "C_PERFORMANCE":
            latency = contract.get("max_latency")
            if latency and not DURATION_PATTERN.match(latency):
                self._issue(1, Severity.ERROR, f"{path}.max_latency", "INVALID_DURATION",
                           f"Invalid duration: '{latency}'. Expected format: ISO 8601 (e.g. PT200ms)")

        elif primitive == "C_SANITIZE":
            valid_modes = {"html_escape", "trim", "normalize", "strip_tags", "sql_param", "url_encode"}
            modes = contract.get("modes", [])
            if not modes:
                self._issue(1, Severity.WARNING, f"{path}.modes", "SANITIZE_NO_MODES",
                           "C_SANITIZE without 'modes' has no effect",
                           f"Add 'modes' with one or more of: {', '.join(sorted(valid_modes))}")
            for mode in modes:
                if mode not in valid_modes:
                    self._issue(1, Severity.ERROR, f"{path}.modes", "SANITIZE_INVALID_MODE",
                               f"Unknown sanitization mode: '{mode}'. "
                               f"Accepted values: {', '.join(sorted(valid_modes))}")

        elif primitive == "C_ENCRYPT":
            valid_algos = {"aes_256_gcm", "aes_128_gcm", "chacha20_poly1305"}
            algo = contract.get("algorithm", "aes_256_gcm")
            if algo not in valid_algos:
                self._issue(1, Severity.ERROR, f"{path}.algorithm", "ENCRYPT_INVALID_ALGO",
                           f"Unknown encryption algorithm: '{algo}'. "
                           f"Accepted values: {', '.join(sorted(valid_algos))}")
            if not contract.get("key_ref"):
                self._issue(1, Severity.WARNING, f"{path}.key_ref", "ENCRYPT_NO_KEY_REF",
                           "C_ENCRYPT should have a 'key_ref' pointing to the secret "
                           "containing the encryption key",
                           "Add 'key_ref: { \"$secret\": \"ENCRYPTION_KEY\" }'")

        elif primitive == "C_AUDIT":
            valid_events = {"create", "read", "update", "delete", "login", "logout",
                           "export", "access_denied", "config_change"}
            events = contract.get("events", [])
            if not events:
                self._issue(1, Severity.WARNING, f"{path}.events", "AUDIT_NO_EVENTS",
                           "C_AUDIT without 'events' — specify which events to trace",
                           f"Add 'events' with one or more of: {', '.join(sorted(valid_events))}")
            for event in events:
                if event not in valid_events:
                    self._issue(1, Severity.WARNING, f"{path}.events", "AUDIT_UNKNOWN_EVENT",
                               f"Non-standard audit event: '{event}'")

    # ─── LEVEL 2: Semantic coherence ───────────────────────────────────

    def _level2_semantic(self, doc: dict):
        """Check semantic coherence: ref resolution, compatibility."""
        module = doc.get("module", {})

        # Collect all available types and units
        all_type_names = set(self.type_registry.keys())
        all_unit_names = set(self.unit_registry.keys())

        # Check $refs inside units
        units = module.get("units", [])
        for i, unit in enumerate(units):
            self._check_refs_in_value(unit, f"$.module.units[{i}]", all_type_names, all_unit_names)

        # Check $refs inside exposed
        exposed = module.get("exposed", [])
        for i, ep in enumerate(exposed):
            handler = ep.get("handler")
            if isinstance(handler, dict) and "$ref" in handler:
                ref_name = handler["$ref"]
                if ref_name not in all_unit_names:
                    self._issue(2, Severity.ERROR, f"$.module.exposed[{i}].handler.$ref",
                               "UNRESOLVED_UNIT_REF",
                               f"Reference to unit '{ref_name}' not found",
                               f"Available units: {', '.join(sorted(all_unit_names)) or '(none)'}")

            # Check that the output ref is resolvable
            output = ep.get("output")
            if isinstance(output, dict) and "$ref" in output:
                ref_name = output["$ref"]
                if ref_name not in all_type_names:
                    self._issue(2, Severity.ERROR, f"$.module.exposed[{i}].output.$ref",
                               "UNRESOLVED_TYPE_REF",
                               f"Reference to type '{ref_name}' not found")

        # Check duplicate endpoints
        route_method_pairs = []
        for i, ep in enumerate(exposed):
            if ep.get("kind") == "http_endpoint":
                pair = (ep.get("route"), ep.get("method"))
                if pair in route_method_pairs:
                    self._issue(2, Severity.ERROR, f"$.module.exposed[{i}]",
                               "DUPLICATE_ENDPOINT",
                               f"Duplicate endpoint: {pair[1]} {pair[0]}")
                route_method_pairs.append(pair)

        # Check duplicate unit names
        unit_names_seen = {}
        for i, unit in enumerate(units):
            name = unit.get("name")
            if name in unit_names_seen:
                self._issue(2, Severity.ERROR, f"$.module.units[{i}].name",
                           "DUPLICATE_UNIT_NAME",
                           f"Duplicate unit name: '{name}' (already defined at index {unit_names_seen[name]})")
            elif name:
                unit_names_seen[name] = i

    def _check_refs_in_value(self, value: Any, path: str,
                              type_names: set, unit_names: set):
        """Recursively walk to check $ref references."""
        if isinstance(value, dict):
            if "$ref" in value:
                ref = value["$ref"]
                if ref not in type_names and ref not in unit_names:
                    self._issue(2, Severity.WARNING, f"{path}.$ref",
                               "POSSIBLY_UNRESOLVED_REF",
                               f"Reference '{ref}' possibly unresolved")
            for k, v in value.items():
                if k != "$ref":
                    self._check_refs_in_value(v, f"{path}.{k}", type_names, unit_names)
        elif isinstance(value, list):
            for i, item in enumerate(value):
                self._check_refs_in_value(item, f"{path}[{i}]", type_names, unit_names)

    # ─── LEVEL 3: Contract verification ──────────────────────────────

    def _level3_contracts(self, doc: dict):
        """Check that contracts are satisfiable."""
        module = doc.get("module", {})

        for type_name, typedef in self.type_registry.items():
            contracts = typedef.get("contracts", [])
            for i, c in enumerate(contracts):
                self._check_contract_satisfiability(
                    c, typedef, f"$.types.{type_name}.contracts[{i}]")

        # Check performance constraints
        for i, unit in enumerate(module.get("units", [])):
            for j, c in enumerate(unit.get("contracts", [])):
                if isinstance(c, dict) and c.get("primitive") == "C_PERFORMANCE":
                    latency = c.get("max_latency", "")
                    if latency:
                        ms = self._parse_duration_ms(latency)
                        if ms is not None and ms < 5:
                            self._issue(3, Severity.WARNING,
                                       f"$.module.units[{i}].contracts[{j}].max_latency",
                                       "UNREALISTIC_LATENCY",
                                       f"Max latency of {ms}ms is probably unrealistic",
                                       "Most network operations take at least 5-10ms")

    def _check_contract_satisfiability(self, contract: dict, context: dict, path: str):
        """Check that a contract is not self-contradictory."""
        primitive = contract.get("primitive")

        if primitive == "C_RANGE":
            min_val = contract.get("min")
            max_val = contract.get("max")
            if min_val is not None and max_val is not None:
                if isinstance(min_val, (int, float)) and isinstance(max_val, (int, float)):
                    if min_val > max_val:
                        self._issue(3, Severity.ERROR, path, "RANGE_IMPOSSIBLE",
                                   f"min ({min_val}) > max ({max_val}) — contrainte impossible")

        elif primitive == "C_LENGTH":
            min_len = contract.get("min")
            max_len = contract.get("max")
            exact = contract.get("exact")
            if min_len is not None and max_len is not None and min_len > max_len:
                self._issue(3, Severity.ERROR, path, "LENGTH_IMPOSSIBLE",
                           f"min ({min_len}) > max ({max_len}) — contrainte impossible")
            if exact is not None and min_len is not None and exact < min_len:
                self._issue(3, Severity.ERROR, path, "LENGTH_EXACT_VS_MIN",
                           f"exact ({exact}) < min ({min_len}) — contradictoire")

        elif primitive == "C_SIZE":
            min_s = contract.get("min")
            max_s = contract.get("max")
            if min_s is not None and max_s is not None and min_s > max_s:
                self._issue(3, Severity.ERROR, path, "SIZE_IMPOSSIBLE",
                           f"min ({min_s}) > max ({max_s}) — contrainte impossible")

    def _parse_duration_ms(self, duration: str) -> int | None:
        """Approximately parse an ISO 8601 duration into milliseconds."""
        try:
            s = duration.upper().replace("PT", "")
            total_ms = 0
            if "MS" in s:
                parts = s.split("MS")
                total_ms += int(parts[0])
                s = parts[1] if len(parts) > 1 else ""
            if "S" in s:
                parts = s.split("S")
                total_ms += int(parts[0]) * 1000
                s = parts[1] if len(parts) > 1 else ""
            if "M" in s:
                parts = s.split("M")
                total_ms += int(parts[0]) * 60000
                s = parts[1] if len(parts) > 1 else ""
            if "H" in s:
                parts = s.split("H")
                total_ms += int(parts[0]) * 3600000
            return total_ms if total_ms > 0 else None
        except (ValueError, IndexError):
            return None

    # ─── LEVEL 4: Target compatibility ─────────────────────────────────

    def _level4_target_compat(self, doc: dict):
        """Check compatibility with compilation targets."""
        module = doc.get("module", {})

        # Compilability information
        for i, unit in enumerate(module.get("units", [])):
            body = unit.get("body", {})
            if isinstance(body, dict):
                primitive = body.get("primitive")
                # Warn if F_AWAIT is used (requires a workflow engine)
                if primitive == "F_AWAIT":
                    self._issue(4, Severity.INFO,
                               f"$.module.units[{i}].body",
                               "AWAIT_NEEDS_WORKFLOW_ENGINE",
                               "F_AWAIT requires a workflow engine (Temporal, Quarkus Workflow)",
                               "Check that the compilation target supports long-running workflows")

    # ─── LEVEL 5: Security analysis ────────────────────────────────────

    def _level5_security(self, doc: dict):
        """Analyze security risks — OWASP-aligned rules."""
        module = doc.get("module", {})
        exposed = module.get("exposed", [])

        # ── Pre-indexing ──────────────────────────────────────────────

        # Collect sensitive fields
        sensitive_fields = {}  # type_name -> set of field names
        for type_name, typedef in self.type_registry.items():
            for field in typedef.get("fields", []):
                if isinstance(field, dict) and field.get("sensitive"):
                    sensitive_fields.setdefault(type_name, set()).add(field.get("name"))

        # Identify entities (D_RECORD with identity) vs DTOs
        entity_names = set()
        for type_name, typedef in self.type_registry.items():
            if typedef.get("identity"):
                entity_names.add(type_name)

        # Identify password-like fields not marked sensitive
        for type_name, typedef in self.type_registry.items():
            for j, field in enumerate(typedef.get("fields", [])):
                if not isinstance(field, dict):
                    continue
                fname = field.get("name", "").lower()
                if any(p in fname for p in ("password", "pwd", "passwd", "secret_key", "private_key")):
                    if not field.get("sensitive"):
                        self._issue(5, Severity.WARNING,
                                   f"$.module.types[{type_name}].fields[{j}]",
                                   "PASSWORD_NOT_SENSITIVE",
                                   f"Field '{field.get('name')}' in {type_name} "
                                   f"looks like a password but is not marked sensitive",
                                   "Add 'sensitive: true' to this field")

        # ── Rule 1: Mutation without authentication ────────────────────

        for i, ep in enumerate(exposed):
            method = ep.get("method", "GET").upper()
            route = ep.get("route", "?")
            auth = ep.get("auth")
            has_auth = isinstance(auth, dict) and auth.get("required", True)
            rate_limit = ep.get("rate_limit")
            handler = ep.get("handler", {})
            handler_name = handler.get("$ref", "") if isinstance(handler, dict) else ""

            if method in ("POST", "PUT", "PATCH", "DELETE") and not has_auth:
                severity = Severity.ERROR if method == "DELETE" else Severity.WARNING
                self._issue(5, severity,
                           f"$.module.exposed[{i}]",
                           "MUTATION_NO_AUTH",
                           f"Endpoint {method} {route} modifies data "
                           f"without requiring authentication",
                           "Add 'auth: { required: true, roles: [...] }' — "
                           "mutation endpoints must always be protected")

        # ── Rule 2: Public endpoint without rate limit ───────────────────

            if not has_auth and not rate_limit:
                self._issue(5, Severity.WARNING,
                           f"$.module.exposed[{i}]",
                           "PUBLIC_NO_RATE_LIMIT",
                           f"Public endpoint {method} {route} has no rate limit",
                           "Add 'rate_limit: { limit: 100, window: \"PT1M\" }' — "
                           "public endpoints are vulnerable to denial-of-service attacks")

        # ── Rule 3: Sensitive data exposed without auth ──────────────

            if not has_auth and handler_name:
                unit = self.unit_registry.get(handler_name, {})
                output_ref = unit.get("output")
                if isinstance(output_ref, dict):
                    ref = output_ref.get("$ref", "")
                    if ref in sensitive_fields:
                        for sens_field in sensitive_fields[ref]:
                            self._issue(5, Severity.WARNING,
                                       f"$.module.exposed[{i}]",
                                       "SENSITIVE_DATA_NO_AUTH",
                                       f"Endpoint {method} {route} exposes "
                                       f"sensitive data ({ref}.{sens_field}) without authentication",
                                       "Add 'auth: { required: true }' or use a "
                                       "DTO excluding the sensitive fields")

        # ── Rule 4: Entity returned directly (anti-IDOR) ─────────

            output = ep.get("output")
            if isinstance(output, dict):
                output_ref = output.get("$ref", "")
                if output_ref in entity_names:
                    # Check whether the entity has sensitive or internal fields
                    entity_def = self.type_registry.get(output_ref, {})
                    has_sensitive = any(
                        f.get("sensitive") for f in entity_def.get("fields", [])
                        if isinstance(f, dict)
                    )
                    has_internal = any(
                        f.get("name", "").lower() in ("password_hash", "internal_id",
                        "created_by", "updated_by", "deleted_at", "version")
                        for f in entity_def.get("fields", []) if isinstance(f, dict)
                    )
                    if has_sensitive or has_internal:
                        self._issue(5, Severity.WARNING,
                                   f"$.module.exposed[{i}].output",
                                   "ENTITY_EXPOSED_DIRECTLY",
                                   f"Endpoint {method} {route} returns entity "
                                   f"'{output_ref}' directly — it contains "
                                   f"sensitive or internal fields that should not be exposed",
                                   "Create a response DTO excluding the sensitive "
                                   "fields (password_hash, tokens, etc.)")

        # ── Rule 5: Critical POST without idempotency ────────────────────

            if method == "POST" and handler_name:
                unit = self.unit_registry.get(handler_name, {})
                # Detect whether the POST creates a financial/critical resource
                body = unit.get("body", {})
                is_critical = self._involves_financial_entity(body, unit)
                has_idempotent = any(
                    c.get("primitive") == "C_IDEMPOTENT"
                    for c in unit.get("contracts", [])
                    if isinstance(c, dict)
                )
                if is_critical and not has_idempotent:
                    self._issue(5, Severity.WARNING,
                               f"$.module.exposed[{i}]",
                               "CRITICAL_POST_NO_IDEMPOTENT",
                               f"POST endpoint {route} creates or modifies "
                               f"critical data without an idempotency contract",
                               "Add C_IDEMPOTENT to the handler to avoid "
                               "duplicates on network retries")

        # ── Rule 6: Plain-HTTP URLs in IO_HTTP ───────────────

        for unit_name, unit in self.unit_registry.items():
            self._check_insecure_urls(unit.get("body", {}),
                                      f"$.module.units[{unit_name}].body")

        # ── Rule 7: Inline secrets (not via $secret) ──────────────────

        self._check_inline_secrets(doc, "$")

        # ── Rule 8: Missing security contracts ────────────────────

        # Check every email field has an email-format C_PATTERN
        for type_name, typedef in self.type_registry.items():
            for j, field in enumerate(typedef.get("fields", [])):
                if not isinstance(field, dict):
                    continue
                fname = field.get("name", "").lower()
                contracts = field.get("contracts", [])
                ftype = field.get("type", {})
                kind = ftype.get("kind", "") if isinstance(ftype, dict) else ""

                # Email sans validation de format
                if ("email" in fname) and kind == "string":
                    has_email_pattern = any(
                        c.get("primitive") == "C_PATTERN" and
                        (c.get("format") == "email" or "email" in str(c.get("regex", "")))
                        for c in contracts if isinstance(c, dict)
                    )
                    if not has_email_pattern:
                        self._issue(5, Severity.WARNING,
                                   f"$.module.types[{type_name}].fields[{j}]",
                                   "EMAIL_NO_VALIDATION",
                                   f"Field '{field.get('name')}' looks like an email "
                                   f"but has no email-format C_PATTERN contract",
                                   "Add { primitive: 'C_PATTERN', format: 'email' }")

                # String sans contrainte de longueur (potentiel DoS)
                if kind == "string" and not field.get("sensitive"):
                    has_length = any(
                        c.get("primitive") == "C_LENGTH"
                        for c in contracts if isinstance(c, dict)
                    )
                    # Check alias contracts too
                    ref = ftype.get("$ref", "") if isinstance(ftype, dict) else ""
                    if ref in self.type_registry:
                        alias = self.type_registry.get(ref, {})
                        alias_contracts = alias.get("contracts", [])
                        has_length = has_length or any(
                            c.get("primitive") == "C_LENGTH"
                            for c in alias_contracts if isinstance(c, dict)
                        )
                    if not has_length and fname not in ("id", "description", "doc"):
                        self._issue(5, Severity.INFO,
                                   f"$.module.types[{type_name}].fields[{j}]",
                                   "STRING_NO_LENGTH",
                                   f"String field '{field.get('name')}' has no "
                                   f"contrainte C_LENGTH — un attaquant pourrait envoyer "
                                   f"very long values",
                                   "Add { primitive: 'C_LENGTH', max: N } to "
                                   "bound input sizes")

        # ── Rule 9: Check role coherence ───────────────────

        all_roles = set()
        endpoint_roles = {}
        for i, ep in enumerate(exposed):
            auth = ep.get("auth")
            if isinstance(auth, dict) and auth.get("required"):
                roles = set(auth.get("roles", []))
                all_roles.update(roles)
                endpoint_roles[i] = roles

        # Detect endpoints accepting all roles (too permissive)
        if len(all_roles) > 1:
            for i, roles in endpoint_roles.items():
                if roles == all_roles and len(roles) > 2:
                    ep = exposed[i]
                    self._issue(5, Severity.INFO,
                               f"$.module.exposed[{i}]",
                               "ALL_ROLES_ALLOWED",
                               f"L'endpoint {ep.get('method')} {ep.get('route')} "
                               f"allows all roles ({', '.join(sorted(roles))}) — "
                               f"check whether this is intentional",
                               "Restrict to the necessary roles if possible")

        # ── Rule 10: Detect sensitive fields in errors ───

        for unit_name, unit in self.unit_registry.items():
            body = unit.get("body", {})
            self._check_sensitive_in_errors(body, sensitive_fields,
                                            f"$.module.units[{unit_name}].body")

        # ── Rule 11: Sensitive fields without C_ENCRYPT ─────────────────

        for type_name, typedef in self.type_registry.items():
            for j, field in enumerate(typedef.get("fields", [])):
                if not isinstance(field, dict):
                    continue
                if field.get("sensitive"):
                    contracts = field.get("contracts", [])
                    has_encrypt = any(
                        c.get("primitive") == "C_ENCRYPT"
                        for c in contracts if isinstance(c, dict)
                    )
                    if not has_encrypt:
                        self._issue(5, Severity.INFO,
                                   f"$.module.types[{type_name}].fields[{j}]",
                                   "SENSITIVE_NO_ENCRYPT",
                                   f"Sensitive field '{field.get('name')}' in "
                                   f"{type_name} has no C_ENCRYPT contract — "
                                   f"data will not be encrypted at rest",
                                   "Add { primitive: 'C_ENCRYPT', algorithm: "
                                   "'aes_256_gcm', key_ref: { '$secret': 'ENCRYPTION_KEY' } }")

        # ── Rule 12: Critical mutations without C_AUDIT ─────────────────

        for unit_name, unit in self.unit_registry.items():
            body = unit.get("body", {})
            if self._involves_mutation(body):
                contracts = unit.get("contracts", [])
                has_audit = any(
                    c.get("primitive") == "C_AUDIT"
                    for c in contracts if isinstance(c, dict)
                )
                if not has_audit:
                    # Only warn for entities that seem important
                    if self._involves_financial_entity(body, unit) or \
                       any(p in unit_name.lower() for p in ("delete", "remove", "admin", "user", "role", "permission")):
                        self._issue(5, Severity.INFO,
                                   f"$.module.units[{unit_name}]",
                                   "CRITICAL_MUTATION_NO_AUDIT",
                                   f"Unit '{unit_name}' modifies critical data "
                                   f"without a C_AUDIT contract — operations will not be "
                                   f"traced in the audit log",
                                   "Add { primitive: 'C_AUDIT', events: ['create'] } "
                                   "or ['update', 'delete'] depending on the operation")

        # ── Rule 13: Input string fields without C_SANITIZE ─────────

        for type_name, typedef in self.type_registry.items():
            # Only check input DTOs (no identity = not an entity)
            if typedef.get("identity"):
                continue
            for j, field in enumerate(typedef.get("fields", [])):
                if not isinstance(field, dict):
                    continue
                ftype = field.get("type", {})
                kind = ftype.get("kind", "") if isinstance(ftype, dict) else ""
                if kind == "string":
                    contracts = field.get("contracts", [])
                    has_sanitize = any(
                        c.get("primitive") == "C_SANITIZE"
                        for c in contracts if isinstance(c, dict)
                    )
                    has_pattern = any(
                        c.get("primitive") == "C_PATTERN"
                        for c in contracts if isinstance(c, dict)
                    )
                    # Only warn for free-text fields (no pattern constraint)
                    if not has_sanitize and not has_pattern:
                        fname = field.get("name", "")
                        if fname not in ("id", "email", "sku", "slug"):
                            self._issue(5, Severity.INFO,
                                       f"$.module.types[{type_name}].fields[{j}]",
                                       "INPUT_STRING_NO_SANITIZE",
                                       f"String field '{fname}' in DTO "
                                       f"'{type_name}' n'a ni C_SANITIZE ni C_PATTERN — "
                                       f"inputs will not be sanitized",
                                       "Add { primitive: 'C_SANITIZE', modes: "
                                       "['trim', 'html_escape'] }")

    def _involves_mutation(self, body: Any) -> bool:
        """Detect whether a body contains a mutation operation."""
        if not isinstance(body, dict):
            return False
        prim = body.get("primitive", "")
        if prim == "IO_MUTATE":
            return True
        for step in body.get("steps", []):
            if isinstance(step, dict):
                op = step.get("op", {})
                if isinstance(op, dict) and self._involves_mutation(op):
                    return True
        for key in ("body", "then", "else", "op"):
            if key in body and isinstance(body[key], dict):
                if self._involves_mutation(body[key]):
                    return True
        return False

    def _involves_financial_entity(self, body: Any, unit: dict) -> bool:
        """Detect whether an operation involves financial/critical data."""
        if not isinstance(body, dict):
            return False

        # Financial patterns in names
        financial_patterns = ("order", "payment", "invoice", "transaction",
                            "transfer", "charge", "refund", "subscription",
                            "billing", "wallet", "balance")

        # Check the unit name
        unit_name = unit.get("name", "").lower()
        if any(p in unit_name for p in financial_patterns):
            return True

        # Check the entities being manipulated
        entity = body.get("entity", "")
        if isinstance(entity, str) and any(p in entity.lower() for p in financial_patterns):
            return True

        # Recursively check inside F_SEQUENCE
        for step in body.get("steps", []):
            if isinstance(step, dict):
                op = step.get("op", {})
                if isinstance(op, dict):
                    if self._involves_financial_entity(op, unit):
                        return True
        return False

    def _check_insecure_urls(self, value: Any, path: str):
        """Detect plain-HTTP (non-HTTPS) URLs in IO_HTTP operations."""
        if isinstance(value, dict):
            prim = value.get("primitive", "")
            if prim == "IO_HTTP":
                url = value.get("url", "")
                if isinstance(url, str) and url.startswith("http://"):
                    self._issue(5, Severity.WARNING, f"{path}.url",
                               "INSECURE_HTTP_URL",
                               f"L'URL '{url}' utilise HTTP au lieu de HTTPS",
                               "Use HTTPS to protect data in transit")
                elif isinstance(url, dict):
                    interp = url.get("$interpolate", "")
                    if isinstance(interp, str) and "http://" in interp:
                        self._issue(5, Severity.WARNING, f"{path}.url",
                                   "INSECURE_HTTP_URL",
                                   f"Interpolated URL contains 'http://' — use HTTPS",
                                   "Replace http:// with https://")

            # Recurse into steps, branches, etc.
            for key in ("body", "op"):
                if key in value:
                    self._check_insecure_urls(value[key], f"{path}.{key}")
            for i, step in enumerate(value.get("steps", [])):
                if isinstance(step, dict):
                    self._check_insecure_urls(step, f"{path}.steps[{i}]")
                    if "op" in step:
                        self._check_insecure_urls(step["op"], f"{path}.steps[{i}].op")

        elif isinstance(value, list):
            for i, item in enumerate(value):
                self._check_insecure_urls(item, f"{path}[{i}]")

    def _check_sensitive_in_errors(self, body: Any, sensitive_fields: dict, path: str):
        """Detect sensitive fields used in error messages."""
        if not isinstance(body, dict):
            return

        prim = body.get("primitive", "")

        # F_GUARD with a message that could leak sensitive data
        if prim == "F_GUARD":
            error = body.get("error", {})
            if isinstance(error, dict):
                msg = error.get("message", "")
                if isinstance(msg, dict):
                    # Check if message interpolates sensitive fields
                    interp = msg.get("$interpolate", "")
                    if isinstance(interp, str):
                        for type_name, fields in sensitive_fields.items():
                            for field in fields:
                                if field in interp:
                                    self._issue(5, Severity.WARNING,
                                               f"{path}.error.message",
                                               "SENSITIVE_IN_ERROR_MSG",
                                               f"The error message references the "
                                               f"sensitive field '{field}' — it could leak "
                                               f"in the HTTP response",
                                               "Do not include sensitive data in "
                                               "error messages")

        # Recurse
        for key in ("body", "op", "then", "else"):
            if key in body and isinstance(body[key], dict):
                self._check_sensitive_in_errors(body[key], sensitive_fields, f"{path}.{key}")
        for i, step in enumerate(body.get("steps", [])):
            if isinstance(step, dict):
                self._check_sensitive_in_errors(step, sensitive_fields, f"{path}.steps[{i}]")
                if "op" in step:
                    self._check_sensitive_in_errors(step["op"], sensitive_fields,
                                                    f"{path}.steps[{i}].op")

    def _check_inline_secrets(self, value: Any, path: str):
        """Detect potentially inline secrets (not via $secret)."""
        if isinstance(value, dict):
            for k, v in value.items():
                if isinstance(v, str) and any(
                    pattern in k.lower()
                    for pattern in ["api_key", "token", "password", "secret", "credential"]
                ):
                    if not (isinstance(v, str) and v.startswith("$")):
                        self._issue(5, Severity.WARNING, f"{path}.{k}",
                                   "POSSIBLE_INLINE_SECRET",
                                   f"Field '{k}' may contain an inline secret",
                                   "Use { \"$secret\": \"KEY_NAME\" } for secrets")
                self._check_inline_secrets(v, f"{path}.{k}")
        elif isinstance(value, list):
            for i, item in enumerate(value):
                self._check_inline_secrets(item, f"{path}[{i}]")

    # ─── LEVEL 6: Integration checks ─────────────────────────────

    def _level6_integration(self, doc: dict):
        """Check the overall coherence of the module."""
        module = doc.get("module", {})

        # Check circular dependencies (for now: within the module)
        # TODO: cross-module dependencies

        # Check that all units referenced by endpoints exist
        exposed = module.get("exposed", [])
        for i, ep in enumerate(exposed):
            handler = ep.get("handler")
            if isinstance(handler, dict) and "$ref" in handler:
                ref_name = handler["$ref"]
                if ref_name not in self.unit_registry:
                    # Already reported at level 2, confirmed here at integration
                    pass

        # Check orchestration coherence
        orchestrations = module.get("orchestrations", [])
        for i, orch in enumerate(orchestrations):
            steps = orch.get("steps", [])
            step_names = {s.get("name") for s in steps if isinstance(s, dict)}

            for j, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                next_expr = step.get("next")
                if isinstance(next_expr, str) and next_expr != "end":
                    if next_expr not in step_names:
                        self._issue(6, Severity.ERROR,
                                   f"$.module.orchestrations[{i}].steps[{j}].next",
                                   "NEXT_STEP_NOT_FOUND",
                                   f"Next step '{next_expr}' does not exist in the workflow",
                                   f"Available steps: {', '.join(sorted(step_names))}")
                elif isinstance(next_expr, dict):
                    for key in ["on_success", "on_error"]:
                        val = next_expr.get(key)
                        if isinstance(val, str) and val != "end" and val not in step_names:
                            self._issue(6, Severity.ERROR,
                                       f"$.module.orchestrations[{i}].steps[{j}].next.{key}",
                                       "NEXT_STEP_NOT_FOUND",
                                       f"Step '{val}' referenced in '{key}' does not exist")

        # Info: module summary
        self._issue(6, Severity.INFO, "$.module", "MODULE_SUMMARY",
                   f"Module '{module.get('name', '?')}' — "
                   f"{self.stats['types']} types, {self.stats['units']} units, "
                   f"{self.stats['endpoints']} endpoints, {self.stats['contracts']} contracts")

    # ─── v0.3 — Semantic extensions (level 2) ──────────────────────────

    # ─── v0.3 — $step reference resolution (dangling / forward) ─────────
    # A `$step: "X.f"` may only reference a step `X` declared BEFORE it
    # in the current (or enclosing) F_SEQUENCE. Otherwise the compiler emits a
    # bare undeclared symbol → broken build (cf. incident #ccedb312: `fetchProduct`
    # never declared + `createItems` forward-referenced). Rejecting here triggers the
    # LLM retry loop → coherent ACIR. (keystone: coverage is
    # capped by what the validator knows how to reject.)
    _STEP_SCOPE_KEYS = ("steps", "do", "then", "else", "operation", "on_error")

    def _collect_steprefs_shallow(self, node) -> list:
        """Collects the `{$step:"..."}` at the current level of an operation WITHOUT
        descending into sub-scopes (steps/do/then/else/operation/on_error) —
        they have their own scope, handled by _validate_step_refs recursion."""
        out = []
        if isinstance(node, dict):
            sv = node.get("$step")
            if isinstance(sv, str):
                return [sv]
            for k, v in node.items():
                if k in self._STEP_SCOPE_KEYS:
                    continue
                out.extend(self._collect_steprefs_shallow(v))
        elif isinstance(node, list):
            for x in node:
                out.extend(self._collect_steprefs_shallow(x))
        return out

    def _collect_all_step_names(self, node) -> set:
        """All step names declared anywhere in the operation tree
        (all scopes combined). Used to distinguish a FORWARD-REF (the name exists
        but later / out of scope) from a true DANGLING (the name exists nowhere)
        — the two require different fixes on the LLM side."""
        out = set()
        if isinstance(node, dict):
            if node.get("primitive") == "F_SEQUENCE":
                for step in node.get("steps", []) or []:
                    if isinstance(step, dict) and step.get("name"):
                        out.add(step["name"])
            for v in node.values():
                out |= self._collect_all_step_names(v)
        elif isinstance(node, list):
            for x in node:
                out |= self._collect_all_step_names(x)
        return out

    def _validate_step_refs(self, op, declared: set, path: str, all_names: set = None):
        """Recursively checks that every `$step` references a declared step
        BEFORE (dangling + forward-ref). `declared` = steps visible at this point
        (enclosing + preceding siblings); `all_names` = all names in the body
        (computed once at the root) to distinguish forward-ref vs dangling."""
        if not isinstance(op, dict):
            return
        if all_names is None:
            all_names = self._collect_all_step_names(op)
        prim = op.get("primitive")
        if prim == "F_SEQUENCE":
            local = set(declared)
            for step in op.get("steps", []) or []:
                if not isinstance(step, dict):
                    continue
                self._validate_step_refs(step.get("op", {}), local,
                                         f"{path}.steps[{step.get('name')}]", all_names)
                nm = step.get("name")
                if nm:
                    local.add(nm)
            return
        for ref in self._collect_steprefs_shallow(op):
            head = ref.split(".", 1)[0]
            if head and head not in declared:
                if head in all_names:
                    # FORWARD-REF: the step exists but is declared AFTER. Most
                    # frequent case = an aggregate (total/sum) computed by referencing a
                    # later loop/insert step. Redirect to $input.
                    msg = (f"`$step: \"{ref}\"` is a FORWARD-REF: step '{head}' "
                           f"is declared AFTER this point in the F_SEQUENCE. A $step "
                           f"only sees the PRECEDING steps.")
                    sugg = (f"Do not reference a later step. If this is an aggregate "
                            f"(total, sum, count over a collection), compute it "
                            f"DIRECTLY from $input with $calculate — e.g. "
                            f"`total_ht = {{$calculate: {{op:\"sum\", over: {{$input:\"items\"}}, "
                            f"expr:\"quantity * unit_price\"}}}}` — instead of waiting for a step "
                            f"'{head}' that does not exist yet. Otherwise, reorder to declare "
                            f"'{head}' BEFORE, or fix the name.")
                else:
                    # True DANGLING: the name appears nowhere.
                    msg = (f"`$step: \"{ref}\"` references a step '{head}' that exists "
                           f"NOWHERE in this unit (dangling — often a typo "
                           f"or a forgotten step).")
                    sugg = (f"Declare a step named '{head}' BEFORE this point (a $step only "
                            f"sees preceding steps), or fix the $step name "
                            f"to point to an existing step.")
                self._issue(2, Severity.ERROR, path, "STEP_REF_UNRESOLVED", msg,
                            suggestion=sugg)
        if prim == "F_FOREACH":
            self._validate_step_refs(op.get("do"), declared, f"{path}.do", all_names)
        elif prim == "F_BRANCH":
            self._validate_step_refs(op.get("then"), declared, f"{path}.then", all_names)
            self._validate_step_refs(op.get("else"), declared, f"{path}.else", all_names)
        elif prim == "F_ERROR_HANDLE":
            self._validate_step_refs(op.get("operation"), declared, f"{path}.operation", all_names)
            self._validate_step_refs(op.get("on_error"), declared, f"{path}.on_error", all_names)

    def _level2_v03_extensions(self, doc: dict):
        """9 v0.3 semantic rules that JSON-Schema cannot express."""
        module = doc.get("module", {}) if isinstance(doc, dict) else {}
        if not isinstance(module, dict):
            return

        # Map endpoint → unit to resolve `$auth` cross-field
        unit_to_endpoint = {}
        for ep in module.get("exposed", []) or []:
            if not isinstance(ep, dict):
                continue
            handler = ep.get("handler", {})
            unit_ref = handler.get("$ref") if isinstance(handler, dict) else None
            if unit_ref:
                unit_to_endpoint[unit_ref] = ep

        # Entity index (D_RECORD with `identity[]`) — used by the
        # SCALAR_OUTPUT_ON_LIST_QUERY rule to distinguish entity (Task, User, ...)
        # d'un DTO wrapper (PaginatedTasks, AuthResponse, ...). Ne PAS inclure
        # D_RECORDs without identity here, otherwise `output: $ref: PaginatedTasks`
        # on a paginated IO_QUERY would wrongly trigger SCALAR_OUTPUT_ON_LIST_QUERY
        # (observed on all paginated outputs generated by GPT-4o on briefs
        # CRUD — the wrapper output is canonical, not a fault).
        # _v03_check_ref_resolution reconstruit `valid_refs` depuis tous les
        # module types, so narrowing entity_names does not widen invalid
        # refs — it only narrows the scope of SCALAR_OUTPUT_ON_LIST_QUERY.
        entity_names = set()
        for t in module.get("types", []) or []:
            if isinstance(t, dict) and t.get("primitive") == "D_RECORD" and t.get("identity"):
                name = t.get("name")
                if name:
                    entity_names.add(name)

        # Rule 1 — `$auth` forbidden in public routes
        for unit in module.get("units", []) or []:
            if not isinstance(unit, dict):
                continue
            unit_name = unit.get("name")
            ep = unit_to_endpoint.get(unit_name)
            auth_required = bool(
                ep and isinstance(ep.get("auth"), dict) and ep["auth"].get("required")
            )
            if not auth_required and self._body_contains_ref(unit.get("body"), "$auth"):
                # No JWT to read → would resolve to undefined at runtime.
                self._issue(
                    2, Severity.ERROR, f"$.module.units[name={unit_name}]",
                    "AUTH_IN_PUBLIC_ROUTE",
                    f"Unit '{unit_name}' uses $auth but its endpoint lacks `auth.required: true`",
                    suggestion="Add `auth: {required: true}` on the exposed endpoint, or remove $auth from the unit",
                )

        # Rule 1bis — resolvable $step references (dangling / forward-ref)
        for unit in module.get("units", []) or []:
            if not isinstance(unit, dict):
                continue
            self._validate_step_refs(
                unit.get("body"), set(),
                f"$.module.units[name={unit.get('name')}].body")

        # Rule 2 — `output: scalar` on IO_QUERY without `limit:1`/`single:true` → reject
        for unit in module.get("units", []) or []:
            if not isinstance(unit, dict):
                continue
            body = unit.get("body")
            if not isinstance(body, dict) or body.get("primitive") != "IO_QUERY":
                continue
            single = body.get("single") or body.get("limit") == 1
            if single:
                continue
            output = unit.get("output", {})
            if isinstance(output, dict) and "$ref" in output and output["$ref"] in entity_names:
                self._issue(
                    2, Severity.ERROR, f"$.module.units[name={unit.get('name')}]",
                    "SCALAR_OUTPUT_ON_LIST_QUERY",
                    f"Unit '{unit.get('name')}' declares a scalar output ($ref: {output['$ref']}) "
                    f"but its IO_QUERY body lacks `single: true` or `limit: 1` — will return List<{output['$ref']}>",
                    suggestion="Either add `single: true` to the body, or change the output to a `D_COLLECTION` of that entity",
                )

        # Rule 2b — `IO_MUTATE.data` or `IO_QUERY.filter` references a field that
        # does not exist on the target entity. Observed on GPT-4o brief1: createTask
        # sets `user_id` via $auth, but the `Task` D_RECORD does not declare the
        # field → JPA compile fail ("cannot find symbol userId"). Without this check,
        # the doc passes validation but breaks at Quarkus build / runtime
        # FastAPI / Fastify. Cf. tests/acir-java-quarkus_erreur du 2026-05-14.
        self._v03_check_op_field_refs(module)

        # Rule 3 — `*` wildcard in `$input` allowed only inside
        # $calculate.formula or F_FOREACH.items. The walker traverses noting context.
        self._v03_check_wildcard_scope(module)

        # Rule 4 — Purity of transforms[].body: no IO_QUERY/IO_MUTATE inside
        for tdecl in module.get("transforms", []) or []:
            if not isinstance(tdecl, dict):
                continue
            tname = tdecl.get("name", "?")
            impurities = self._find_io_primitives(tdecl.get("body"))
            for path, prim in impurities:
                self._issue(
                    2, Severity.ERROR, f"$.module.transforms[name={tname}].body{path}",
                    "TRANSFORM_IMPURITY",
                    f"transforms[{tname}].body contains `{prim}` — transforms must be PURE "
                    f"(decision Q2; any impure factoring goes through a separate X_UNIT)",
                    suggestion="Move the I/O code into an X_UNIT and call the transform from the unit's F_SEQUENCE",
                )

        # Rule 5 — unknown `$generate` kind (covered by schema, but explicit double-check
        # for v0.3 docs bypassing the schema)
        self._v03_check_generate_kinds(module)

        # Rule 6 — Field with both `optional: true` + `required: true` (impossible to catch
        # via JSON-schema because the 2 keywords are separate)
        for t in module.get("types", []) or []:
            if not isinstance(t, dict) or t.get("primitive") != "D_RECORD":
                continue
            for f in t.get("fields", []) or []:
                if not isinstance(f, dict):
                    continue
                if f.get("required") is True and f.get("optional") is True:
                    self._issue(
                        2, Severity.ERROR,
                        f"$.module.types[name={t.get('name')}].fields[name={f.get('name')}]",
                        "REQUIRED_OPTIONAL_CONTRADICTION",
                        "A field cannot be both `required: true` and `optional: true`",
                        suggestion="Remove one of the two — the canonical convention is `required: true|false`",
                    )

        # Rule 7 — `$ref` resolution: every `{$ref: "X"}` must point to a declared
        # type (entity, enum, alias) OR a unit (for IO_EXPOSE handlers).
        self._v03_check_ref_resolution(module, entity_names)

        # Rule 8 — relations[] vs entity fields coherence:
        # when a relation declares `from.entity.field`, the field must NOT
        # already exist on the entity (the compiler synthesizes it) — otherwise
        # collision/duplication.
        self._v03_check_relations_consistency(module)

        # Rule 10 — $calculate: references (alias / alias.field) resolved.
        self._v03_check_calculate_refs(module)
        # Rule 11 — IO_MUTATE.data: compatible collection element type.
        self._v03_check_io_data_types(module)
        # Rule 12 (advisory, WARNING) — auth required but no way to create
        # accounts: the app will have protected endpoints with no possible signup.
        self._v03_check_auth_account_creation(module)

        # Rule 9 — `validators[].rule` must be a Predicate (at least one $-prefixed key
        # recognized). JSON-schema checks it structurally but an empty rule passes.
        for vdecl in module.get("validators", []) or []:
            if not isinstance(vdecl, dict):
                continue
            rule = vdecl.get("rule")
            if not isinstance(rule, dict) or not any(
                k.startswith("$") for k in rule.keys()
            ):
                self._issue(
                    2, Severity.ERROR,
                    f"$.module.validators[name={vdecl.get('name', '?')}].rule",
                    "VALIDATOR_RULE_NOT_PREDICATE",
                    "A validator's `rule` must be a Predicate ($eq, $in, $and, $verify, $validate, …)",
                    suggestion="Ex: {\"$eq\": [{\"$input\": \"x\"}, 42]}",
                )

    # ─── v0.3 — Helpers de walking ─────────────────────────────────────────

    def _body_contains_ref(self, body: Any, ref_key: str) -> bool:
        """Returns True if `ref_key` (e.g. `$auth`) appears anywhere in the body."""
        if isinstance(body, dict):
            if ref_key in body:
                return True
            return any(self._body_contains_ref(v, ref_key) for v in body.values())
        if isinstance(body, list):
            return any(self._body_contains_ref(v, ref_key) for v in body)
        return False

    def _find_io_primitives(self, body: Any, path: str = "") -> list[tuple[str, str]]:
        """Walk the body, return the list of (path, primitive) for IO_QUERY/IO_MUTATE."""
        found = []
        if isinstance(body, dict):
            prim = body.get("primitive")
            if prim in ("IO_QUERY", "IO_MUTATE"):
                found.append((path, prim))
            for k, v in body.items():
                found.extend(self._find_io_primitives(v, f"{path}.{k}"))
        elif isinstance(body, list):
            for i, item in enumerate(body):
                found.extend(self._find_io_primitives(item, f"{path}[{i}]"))
        return found

    def _v03_check_op_field_refs(self, module: dict):
        """For each IO_MUTATE / IO_QUERY found in a unit body, check
        that the keys of `data` and `filter` match a field declared on
        the target entity (`body.entity` → D_RECORD with identity).

        Trigger case: an LLM handles a "user-scoped tasks" brief and
        writes `data: {user_id: $auth.user_id}` in createTask, but forgets
        d'ajouter `user_id` aux fields du D_RECORD `Task`. Sans ce check, le
        Quarkus compiler emits `entity.userId = ...` which does not compile
        (cf. erreur 2026-05-14 sur GPT-4o brief1).

        Entity ↔ ACIR entity matching heuristic: snake_case the
        D_RECORD name, then accept the singular or plural-s form. No
        complex depluralization (audit_logs → AuditLog matches because
        the compiler applies the same rule).

        Keys starting with `$` (`$merge`, etc.) are ignored — this
        are directives, not fields.
        """
        def _entity_for_op(op):
            e = op.get("entity") if isinstance(op, dict) else None
            if not isinstance(e, str):
                return None
            for t in module.get("types", []) or []:
                if not isinstance(t, dict) or not t.get("identity"):
                    continue
                name = t.get("name") or ""
                snake = re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", name).lower()
                if snake == e or snake + "s" == e:
                    return t
            return None

        def _walk_io_ops(body, path):
            if isinstance(body, dict):
                if body.get("primitive") in ("IO_QUERY", "IO_MUTATE"):
                    yield path, body
                for k, v in body.items():
                    yield from _walk_io_ops(v, f"{path}.{k}")
            elif isinstance(body, list):
                for i, item in enumerate(body):
                    yield from _walk_io_ops(item, f"{path}[{i}]")

        def _check_field_keys(node, ent_name, declared, path, clause_key):
            """Walk `data` / `filter` recursively, validating that every key
            looks like an entity field (i.e. exists in `declared`).

            Recurses into `$merge: [...]` items because the v0.3 merge
            directive splices field-dicts into the parent. Bulk `$input` refs
            (`{$input: "X"}` standalone) are skipped — the compiler resolves
            them via the source DTO ; here we only catch literal field names.
            """
            if not isinstance(node, dict):
                return
            for key, value in node.items():
                if key == "$merge" and isinstance(value, list):
                    for i, item in enumerate(value):
                        if not isinstance(item, dict):
                            continue
                        # Skip bulk-input spread — compile-time resolution
                        if "$input" in item and len(item) == 1:
                            continue
                        _check_field_keys(
                            item, ent_name, declared,
                            f"{path}.$merge[{i}]", clause_key,
                        )
                    continue
                if not isinstance(key, str) or key.startswith("$"):
                    continue
                if key not in declared:
                    self._issue(
                        2, Severity.ERROR,
                        f"{path}.{key}",
                        "UNDECLARED_ENTITY_FIELD",
                        f"The operation references `{ent_name}.{key}` "
                        f"(via `{clause_key}`) but the `{ent_name}` D_RECORD "
                        f"does not declare this field",
                        suggestion=(
                            f"Add `{key}` to "
                            f"`types[name={ent_name}].fields[]` "
                            f"(probable type : uuid si $auth, datetime si "
                            f"$generate now, otherwise infer from context)"
                        ),
                    )

        for unit in module.get("units", []) or []:
            if not isinstance(unit, dict):
                continue
            unit_name = unit.get("name") or "?"
            base_path = f"$.module.units[name={unit_name}].body"
            for op_path, op in _walk_io_ops(unit.get("body"), base_path):
                ent = _entity_for_op(op)
                if not ent:
                    continue
                declared = {
                    f.get("name") for f in (ent.get("fields") or [])
                    if isinstance(f, dict) and f.get("name")
                }
                ent_name = ent.get("name", "?")
                for clause_key in ("data", "filter"):
                    clause = op.get(clause_key)
                    if isinstance(clause, dict):
                        _check_field_keys(
                            clause, ent_name, declared,
                            f"{op_path}.{clause_key}", clause_key,
                        )

    def _v03_check_wildcard_scope(self, module: dict):
        """The `*` wildcard in `$input` is only allowed inside
        `$calculate.formula` (free text, not walker-matchable) or as a value
        of `F_FOREACH.items` (where it denotes iteration). Elsewhere → reject."""
        # The walker keeps an `in_calculate_or_foreach` flag that flips to True
        # when entering an allowed subtree.

        def walk(node: Any, path: str = "$", in_allowed_scope: bool = False):
            if isinstance(node, dict):
                # $calculate.formula is itself a string; the walker will not descend
                # into it for $input — the formula is validated by the DSL parser
                # au niveau 3. Le scope "calculate" s'applique aux `inputs` du calculate
                # not to the formula.
                if "$input" in node and isinstance(node.get("$input"), str) and "*" in node["$input"]:
                    if not in_allowed_scope:
                        self._issue(
                            2, Severity.ERROR, path, "WILDCARD_OUT_OF_SCOPE",
                            f"`$input: \"{node['$input']}\"` contains `*` outside an allowed context "
                            f"(allowed only inside a $calculate or an F_FOREACH.items)",
                            suggestion="Use F_FOREACH to iterate over the list, or $calculate.formula for an aggregate",
                        )
                # An F_FOREACH's `items` allows wildcards
                primitive = node.get("primitive")
                next_allowed = in_allowed_scope or primitive == "F_FOREACH"
                for k, v in node.items():
                    walk(v, f"{path}.{k}", in_allowed_scope=next_allowed)
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    walk(item, f"{path}[{i}]", in_allowed_scope=in_allowed_scope)

        walk(module)

    def _v03_check_generate_kinds(self, module: dict):
        """Walk the module, reject any `$generate: <unknown>` (string hors enum,
        or dict with unknown kind). JSON-schema partially covers it already;
        this rule is an explicit double-check for targeted feedback."""

        def walk(node: Any, path: str = "$"):
            if isinstance(node, dict):
                if "$generate" in node:
                    g = node["$generate"]
                    if isinstance(g, str) and g not in GENERATE_BUILTIN_KINDS:
                        self._issue(
                            2, Severity.ERROR, path, "GENERATE_UNKNOWN_KIND",
                            f"`$generate: \"{g}\"` is not a recognized builtin (valid: {sorted(GENERATE_BUILTIN_KINDS)})",
                            suggestion="For a custom format like `ORD-YYYYMMDD-XXXX`, use "
                                       "{\"$generate\": {\"kind\": \"template\", \"format\": \"...\"}}",
                        )
                    elif isinstance(g, dict):
                        kind = g.get("kind")
                        if kind not in GENERATE_PARAMETERIZED_KINDS:
                            self._issue(
                                2, Severity.ERROR, path, "GENERATE_UNKNOWN_KIND",
                                f"`$generate.kind: \"{kind}\"` non reconnu (valides: {sorted(GENERATE_PARAMETERIZED_KINDS)})",
                            )
                for k, v in node.items():
                    walk(v, f"{path}.{k}")
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    walk(item, f"{path}[{i}]")

        walk(module)

    def _v03_check_ref_resolution(self, module: dict, entity_names: set):
        """Every `$ref` must point to a known type (entity, enum, alias) or
        une unit (handler). Les paths de step (`$step`) ne sont PAS des $ref —
        they are checked separately compiler-side at F_SEQUENCE resolution.
        """
        # Valid refs index
        valid_refs = set(entity_names)
        for t in module.get("types", []) or []:
            if isinstance(t, dict):
                name = t.get("name")
                if name:
                    valid_refs.add(name)
        for u in module.get("units", []) or []:
            if isinstance(u, dict):
                name = u.get("name")
                if name:
                    valid_refs.add(name)

        def walk(node: Any, path: str = "$"):
            if isinstance(node, dict):
                # $step and $loop are not $refs — they resolve to
                # runtime variables, not declared types.
                if "$step" in node or "$loop" in node:
                    return
                if "$ref" in node and isinstance(node["$ref"], str):
                    ref = node["$ref"]
                    if ref not in valid_refs:
                        self._issue(
                            2, Severity.ERROR, path, "UNRESOLVED_REF",
                            f"`$ref: \"{ref}\"` points to no declared type or unit",
                            suggestion=f"Available types: {sorted(valid_refs)[:10]}... (see module.types and module.units)",
                        )
                for k, v in node.items():
                    walk(v, f"{path}.{k}")
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    walk(item, f"{path}[{i}]")

        walk(module)

    def _v03_check_relations_consistency(self, module: dict):
        """relations[] coherence: the `from.entity` entity must exist, and
        `from.field` must NOT already be a field on this entity (the
        compiler synthesizes it from the relation)."""
        relations = module.get("relations", []) or []
        if not relations:
            return
        # Index entity_name → set of already-declared field names
        entity_fields = {}
        for t in module.get("types", []) or []:
            if isinstance(t, dict) and t.get("primitive") == "D_RECORD":
                name = t.get("name")
                if name:
                    entity_fields[name] = {
                        f["name"] for f in (t.get("fields") or [])
                        if isinstance(f, dict) and "name" in f
                    }
        for rel in relations:
            if not isinstance(rel, dict):
                continue
            rel_name = rel.get("name", "?")
            from_block = rel.get("from", {}) if isinstance(rel.get("from"), dict) else {}
            entity = from_block.get("entity")
            field = from_block.get("field")
            if entity and entity not in entity_fields:
                self._issue(
                    2, Severity.ERROR, f"$.module.relations[name={rel_name}].from.entity",
                    "RELATION_UNKNOWN_ENTITY",
                    f"Entity `{entity}` referenced by relation `{rel_name}` does not exist in module.types",
                )
                continue
            if entity and field and field in entity_fields.get(entity, set()):
                self._issue(
                    2, Severity.WARNING, f"$.module.relations[name={rel_name}].from.field",
                    "RELATION_FIELD_COLLISION",
                    f"Field `{field}` is already declared on entity `{entity}` — the relation may collide with this field at compile time",
                    suggestion="Remove the manual field on the entity; the compiler synthesizes it from the relation",
                )

    # ─── v0.3 — Type resolution helpers (rules 10/11) ──────────────

    def _v03_types_index(self, module: dict) -> dict:
        return {t["name"]: t for t in module.get("types", []) or []
                if isinstance(t, dict) and t.get("name")}

    def _v03_record_fields(self, rec: dict) -> set:
        return {f["name"] for f in (rec.get("fields") or [])
                if isinstance(f, dict) and "name" in f}

    def _v03_field_tref(self, rec: dict, fname: str):
        for f in rec.get("fields") or []:
            if isinstance(f, dict) and f.get("name") == fname:
                return f.get("type")
        return None

    def _v03_resolve_tref(self, tref, idx: dict):
        """→ ('record', rec) | ('enum', name) | ('scalar', kind) |
              ('collection', elem_tref) | ('unknown', None)."""
        if not isinstance(tref, dict):
            return ("unknown", None)
        if "$ref" in tref:
            r = idx.get(tref["$ref"])
            if isinstance(r, dict) and r.get("primitive") == "D_RECORD":
                return ("record", r)
            if isinstance(r, dict) and r.get("primitive") == "D_ENUM":
                return ("enum", tref["$ref"])
            return ("unknown", None)
        p = tref.get("primitive")
        if p == "D_SCALAR":
            return ("scalar", tref.get("kind"))
        if p == "D_COLLECTION":
            return ("collection", tref.get("element_type"))
        if p == "D_RECORD":
            return ("record", tref)
        return ("unknown", None)

    def _v03_entity_record(self, idx: dict, entity: str):
        if not entity:
            return None
        for n, r in idx.items():
            if not isinstance(r, dict) or r.get("primitive") != "D_RECORD":
                continue
            sn = re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", n).lower()
            if entity in (n, sn, sn + "s", sn.rstrip("s")):
                return r
        return None

    def _v03_source_tref(self, src, unit: dict, idx: dict, loop_env: dict = None):
        """Type of a $calculate input / data value. Conservative:
        $input (against unit.input), $loop (against the F_FOREACH binding via
        `loop_env`) and $ref are resolved; everything else → unknown (skip —
        doctrine doute⇒skip)."""
        if not isinstance(src, dict):
            return ("scalar", None) if not isinstance(src, (dict, list)) else ("unknown", None)
        if "$ref" in src:
            return self._v03_resolve_tref(src, idx)
        if "$input" in src:
            k = src["$input"]
            ui = unit.get("input") if isinstance(unit, dict) else None
            if not isinstance(ui, dict):
                return ("unknown", None)
            if k in ("", None):
                return self._v03_resolve_tref(ui, idx)
            # ui = {$ref R} | inline D_RECORD
            kind, rec = self._v03_resolve_tref(ui, idx)
            if kind == "record":
                ft = self._v03_field_tref(rec, k)
                return self._v03_resolve_tref(ft, idx) if ft else ("unknown", None)
            return ("unknown", None)
        if "$loop" in src:
            ref = src["$loop"]
            if not isinstance(ref, str) or not loop_env:
                return ("unknown", None)
            head, _, rest = ref.partition(".")
            elem_tref = loop_env.get(head)
            if elem_tref is None:
                return ("unknown", None)
            if not rest:
                return self._v03_resolve_tref(elem_tref, idx)
            # dotted access `alias.a.b.c` — descend field by field
            kind, rec = self._v03_resolve_tref(elem_tref, idx)
            parts = rest.split(".")
            for i, part in enumerate(parts):
                if kind != "record":
                    return ("unknown", None)
                ft = self._v03_field_tref(rec, part)
                if ft is None:
                    return ("unknown", None)
                kind, rec = self._v03_resolve_tref(ft, idx)
            return (kind, rec)
        if any(x in src for x in ("$auth", "$context", "$generate")):
            return ("scalar", None)
        return ("unknown", None)

    def _v03_walk_calc(self, node, sink):
        if isinstance(node, dict):
            if isinstance(node.get("$calculate"), dict):
                sink.append(node["$calculate"])
            for v in node.values():
                self._v03_walk_calc(v, sink)
        elif isinstance(node, list):
            for v in node:
                self._v03_walk_calc(v, sink)

    def _v03_check_calculate_refs(self, module: dict):
        """Rule 10 — every `<alias>`/`<alias>.<field>` in a formula
        $calculate must resolve (alias ∈ inputs; field ∈ resolved type)."""
        idx = self._v03_types_index(module)
        for unit in module.get("units", []) or []:
            if not isinstance(unit, dict):
                continue
            calcs = []
            self._v03_walk_calc(unit.get("body"), calcs)
            for calc in calcs:
                formula = calc.get("formula")
                inputs = calc.get("inputs") or {}
                if not isinstance(formula, str) or not isinstance(inputs, dict):
                    continue
                # Do NOT pre-empt the level-3 DSL check: if the formula is
                # grammatically invalid, skip (the pipeline short-circuits
                # sur erreur niveau 2 → CALCULATE_DSL_PARSE_ERROR ne sortirait
                # never). Refs are only resolved on a well-formed formula.
                try:
                    if self._parse_calculate_formula(formula) is not None:
                        continue
                    toks = self._tokenize_calculate(formula)
                except Exception:
                    continue  # DSL error already reported at level 3
                seen = set()
                i = 0
                while i < len(toks):
                    ttype, val, _pos = toks[i]
                    if ttype != "IDENT":
                        i += 1
                        continue
                    is_call = (i + 1 < len(toks) and toks[i + 1][0] == "LPAREN")
                    if is_call or val in self._AGG_NAMES:
                        i += 1
                        continue
                    root, fld = val, None
                    if (i + 2 < len(toks) and toks[i + 1][0] == "DOT"
                            and toks[i + 2][0] == "IDENT"):
                        fld = toks[i + 2][1]
                        i += 3
                    else:
                        i += 1
                    key = (root, fld)
                    if key in seen:
                        continue
                    seen.add(key)
                    if root not in inputs:
                        self._issue(
                            2, Severity.ERROR, f"$.module.units[{unit.get('name','?')}].$calculate",
                            "CALC_REF_UNRESOLVED",
                            f"$calculate: the formula references '{root}' which is not "
                            f"declared in `inputs` ({sorted(inputs)}).",
                            suggestion="Declare this alias in $calculate.inputs or fix the name.")
                        continue
                    if fld is None or fld == "*":
                        continue
                    kind, payload = self._v03_source_tref(inputs[root], unit, idx)
                    if kind == "collection":
                        kind, payload = self._v03_resolve_tref(payload, idx)
                    if kind == "record":
                        if fld not in self._v03_record_fields(payload):
                            self._issue(
                                2, Severity.ERROR, f"$.module.units[{unit.get('name','?')}].$calculate",
                                "CALC_REF_UNRESOLVED",
                                f"$calculate: the formula references '{root}.{fld}' but the "
                                f"type '{payload.get('name','<inline>')}' has no field "
                                f"'{fld}'.",
                                suggestion=f"Add field '{fld}' to the type, fix the "
                                           f"name, or produce the value via a $transform.")
                    elif kind == "scalar":
                        self._issue(
                            2, Severity.ERROR, f"$.module.units[{unit.get('name','?')}].$calculate",
                            "CALC_REF_UNRESOLVED",
                            f"$calculate: '{root}.{fld}' — '{root}' est un scalaire, "
                            f"field access impossible.",
                            suggestion="Use a record/collection-typed alias, or remove the field access.")
                    # ('enum'|'unknown') → skip (doctrine doute⇒skip)

    # R1 — familles de types scalaires. Une affectation cross-famille (ex.
    # `decimal` → `string`) does not compile on typed targets (Java `String = BigDecimal`,
    # cf. incident #3eeb1951). Kinds are grouped into families; same family = OK
    # (e.g. integer→decimal, numeric widening), cross-family = reject.
    _SCALAR_FAMILY = {
        "string": "text", "text": "text", "str": "text",
        "integer": "num", "int": "num", "long": "num", "number": "num",
        "decimal": "num", "float": "num", "double": "num", "bigdecimal": "num",
        "boolean": "bool", "bool": "bool",
        "uuid": "uuid", "guid": "uuid",
        "datetime": "time", "date": "time", "time": "time", "timestamp": "time",
        "json": "json", "object": "json",
        "binary": "binary", "bytes": "binary", "blob": "binary",
    }

    def _scalar_compatible(self, src_kind, tgt_kind) -> bool:
        """Is src assignable to tgt? Conservative: unknown kind or family →
        True (doctrine: doubt⇒skip, no false positives). `json`/`object` accept
        everything. Otherwise, compatible iff same family."""
        if not src_kind or not tgt_kind:
            return True
        sk, tk = str(src_kind).lower(), str(tgt_kind).lower()
        if sk == tk:
            return True
        fs = self._SCALAR_FAMILY.get(sk)
        ft = self._SCALAR_FAMILY.get(tk)
        if fs is None or ft is None:
            return True
        if "json" in (fs, ft):
            return True
        return fs == ft

    def _v03_check_io_data_types(self, module: dict):
        """Rule 11 — IO_MUTATE.data: the value assigned to a field must be
        compatible with the field's declared type.
          - record / collection-de-record : structure compatible (champs ⊆).
          - scalar ↔ scalar (R1): same FAMILY. A cross-family assignment
            (`decimal`→`string`) compiles badly on typed targets → reject to trigger
            the LLM retry (keystone; incident #3eeb1951). `$loop` sources
            are resolved via the enclosing F_FOREACH binding."""
        idx = self._v03_types_index(module)
        _DERIV = ("$transform", "$calculate", "$merge", "$generate",
                  "$conditional", "$hash", "$verify", "$auth", "$context")

        def _fields_sig(rec):
            sig = {}
            for f in rec.get("fields") or []:
                if isinstance(f, dict) and "name" in f:
                    t = f.get("type") or {}
                    sig[f["name"]] = t.get("$ref") or t.get("kind") or "?"
            return sig

        def _compat(b_rec, a_rec):
            bs = _fields_sig(b_rec)
            return all(k in bs and bs[k] == v for k, v in _fields_sig(a_rec).items())

        def _check_mut(mut, unit, loop_env):
            E = self._v03_entity_record(idx, mut.get("entity"))
            data = mut.get("data")
            if E is None or not isinstance(data, dict):
                return
            uname = unit.get("name", "?")
            for f, v in data.items():
                if f.startswith("$") or not isinstance(v, dict):
                    continue
                if any(d in v for d in _DERIV):
                    continue
                tf = self._v03_field_tref(E, f)
                if tf is None:
                    continue
                tk, tp = self._v03_resolve_tref(tf, idx)
                path = f"$.module.units[{uname}].IO_MUTATE.data.{f}"

                # ── scalaire ↔ scalaire (R1) ──
                if tk == "scalar":
                    sk, sp = self._v03_source_tref(v, unit, idx, loop_env)
                    if sk == "scalar" and not self._scalar_compatible(sp, tp):
                        self._issue(
                            2, Severity.ERROR, path, "IO_DATA_TYPE_MISMATCH",
                            f"IO_MUTATE.data.'{f}' assigns a scalar value of type "
                            f"'{sp}' to a field expecting '{tp}' (incompatible families "
                            f"— does not compile on typed targets).",
                            suggestion=(
                                f"Align the types: either declare '{f}' as '{sp}' on "
                                f"entity '{E.get('name', '?')}', or provide a source "
                                f"of type '{tp}'. Frequent cause: two D_RECORDs model "
                                f"the same data with diverging types — unify them."))
                    continue

                # ── record / collection-de-record (existant) ──
                a_rec = None
                if tk == "collection":
                    ek, er = self._v03_resolve_tref(tp, idx)
                    a_rec = er if ek == "record" else None
                elif tk == "record":
                    a_rec = tp
                if a_rec is None:
                    continue
                sk, sp = self._v03_source_tref(v, unit, idx, loop_env)
                b_rec = None
                if sk == "collection":
                    ek, er = self._v03_resolve_tref(sp, idx)
                    b_rec = er if ek == "record" else None
                elif sk == "record":
                    b_rec = sp
                if b_rec is None:
                    continue
                if b_rec is a_rec or b_rec.get("name") == a_rec.get("name"):
                    continue
                if _compat(b_rec, a_rec):
                    continue
                self._issue(
                    2, Severity.ERROR, path, "IO_DATA_TYPE_MISMATCH",
                    f"IO_MUTATE.data.'{f}' affecte '{b_rec.get('name', '<inline>')}' "
                    f"to a field expecting '{a_rec.get('name', '<inline>')}' "
                    f"(types incompatibles).",
                    suggestion=f"Declare a $transform "
                               f"'{b_rec.get('name', '?')}'→'{a_rec.get('name', '?')}' "
                               f"and use it as the value, or align the types.")

        def _walk(n, unit, loop_env):
            if isinstance(n, dict):
                prim = n.get("primitive")
                if prim == "IO_MUTATE" and n.get("action") in ("create", "update", "patch"):
                    _check_mut(n, unit, loop_env)
                if prim == "F_FOREACH":
                    # Binds the loop alias (`as`) to the element type of the
                    # iterated collection, to resolve inner `$loop: "<alias>.<field>"`.
                    as_name = n.get("as") or n.get("item") or n.get("var")
                    sk, sp = self._v03_source_tref(n.get("items"), unit, idx, loop_env)
                    child_env = dict(loop_env)
                    if as_name and sk == "collection":
                        child_env[as_name] = sp
                    for v in n.values():
                        _walk(v, unit, child_env)
                    return
                for v in n.values():
                    _walk(v, unit, loop_env)
            elif isinstance(n, list):
                for v in n:
                    _walk(v, unit, loop_env)

        for unit in module.get("units", []) or []:
            if not isinstance(unit, dict):
                continue
            _walk(unit.get("body"), unit, {})

    def _v03_check_auth_account_creation(self, module: dict):
        """Rule 12 (advisory, non-blocking WARNING) — the app requires auth on at
        least one endpoint but no unit creates accounts (no `$hash`). Users
        will not be able to sign up: only accounts seeded via environment
        variable (in-memory) will exist. Product honesty signal (cf.
        ACIR-AS-FRAMEWORK: state what the app does not do rather than ship a
        surprise). Non-blocking: a brief may legitimately delegate auth to an
        SSO/pre-provisioned accounts."""
        exposed = module.get("exposed", []) or []
        has_auth = any(
            isinstance(ep, dict) and isinstance(ep.get("auth"), dict)
            and ep["auth"].get("required")
            for ep in exposed
        )
        if not has_auth:
            return

        def _uses_hash(node) -> bool:
            if isinstance(node, dict):
                if "$hash" in node:
                    return True
                return any(_uses_hash(v) for v in node.values())
            if isinstance(node, list):
                return any(_uses_hash(x) for x in node)
            return False

        has_account_creation = any(
            _uses_hash(u.get("body")) for u in module.get("units", []) or []
            if isinstance(u, dict)
        )
        if has_account_creation:
            return

        self._issue(
            2, Severity.WARNING, "$.module", "AUTH_WITHOUT_ACCOUNT_CREATION",
            "At least one endpoint requires authentication, but no unit creates "
            "accounts (no `$hash`): users will not be able to sign up. "
            "The app will only have accounts seeded via environment variables "
            "(in-memory, for bootstrap/test).",
            suggestion="To allow self-signup, add a `signup` unit "
                       "(IO_MUTATE create on a User entity + password `$hash`) "
                       "exposed as public POST, plus a `login` unit (check + JWT). "
                       "Otherwise, ignore this warning if auth is delegated "
                       "(SSO, pre-provisioned accounts).",
        )

    # ─── v0.3 — Parser DSL $calculate (niveau 3) ────────────────────────────

    def _level3_v03_calculate_dsl(self, doc: dict):
        """Parse each `$calculate.formula` against the strict BNF grammar (cf.
        proposal §"DSL formula"). Decision Q6: compile-time error if not translatable.
        """
        module = doc.get("module", {}) if isinstance(doc, dict) else {}

        def walk(node: Any, path: str = "$"):
            if isinstance(node, dict):
                if "$calculate" in node:
                    calc = node["$calculate"]
                    if isinstance(calc, dict):
                        formula = calc.get("formula")
                        if isinstance(formula, str):
                            err = self._parse_calculate_formula(formula)
                            if err:
                                self._issue(
                                    3, Severity.ERROR, f"{path}.$calculate.formula",
                                    "CALCULATE_DSL_PARSE_ERROR",
                                    f"Formule `{formula}` invalide : {err}",
                                    suggestion="Cf. v0.3 BNF grammar — arithmetic + sum/count/avg/min/max + dot-access + wildcard inside aggregator only",
                                )
                for k, v in node.items():
                    walk(v, f"{path}.{k}")
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    walk(item, f"{path}[{i}]")

        walk(module)

    # Tokenizer + recursive-descent parser for the $calculate DSL.
    # Grammaire (cf. proposal) :
    #   formula     := expr
    #   expr        := term (('+' | '-') term)*
    #   term        := factor (('*' | '/' | '%') factor)*
    #   factor      := number | path | agg_call | '(' expr ')' | '-' factor
    #   agg_call    := agg_name '(' expr ')'
    #   agg_name    := 'sum' | 'count' | 'avg' | 'min' | 'max'
    #   path        := identifier ('.' (identifier | '*'))+ | identifier
    #   number      := -?[0-9]+ ('.' [0-9]+)?
    #   identifier  := [a-zA-Z_][a-zA-Z_0-9]*

    _AGG_NAMES = {"sum", "count", "avg", "min", "max"}

    def _parse_calculate_formula(self, formula: str) -> str | None:
        """Returns None if the formula is valid; otherwise an error message
        with the approximate position of the faulty token.
        """
        try:
            tokens = self._tokenize_calculate(formula)
        except ValueError as e:
            return str(e)
        # Recursive-descent parser — state lives in a token list + index
        state = {"tokens": tokens, "i": 0}
        try:
            self._parse_expr(state, in_aggregator=False)
            if state["i"] < len(tokens):
                tok = tokens[state["i"]]
                return f"unexpected token `{tok[1]}` at position {tok[2]} (leftover after the complete expression)"
            return None
        except ValueError as e:
            return str(e)

    def _tokenize_calculate(self, formula: str) -> list[tuple[str, str, int]]:
        """Returns a list of (token_type, value, position).
        Types : NUMBER, IDENT, DOT, STAR, LPAREN, RPAREN, OP (+ - * / %), WILDCARD_STAR.
        Note: `*` is ambiguous (multiplication vs wildcard) — the tokenizer types it
        as STAR if the previous token is DOT (e.g. `items.*`), otherwise as OP.
        """
        tokens = []
        i = 0
        n = len(formula)
        while i < n:
            c = formula[i]
            if c.isspace():
                i += 1
                continue
            # Number
            if c.isdigit() or (c == '-' and (not tokens or tokens[-1][0] in {"OP", "LPAREN"}) and i + 1 < n and formula[i + 1].isdigit()):
                start = i
                if c == '-':
                    i += 1
                while i < n and formula[i].isdigit():
                    i += 1
                if i < n and formula[i] == '.':
                    i += 1
                    while i < n and formula[i].isdigit():
                        i += 1
                tokens.append(("NUMBER", formula[start:i], start))
                continue
            # Identifier
            if c.isalpha() or c == '_':
                start = i
                while i < n and (formula[i].isalnum() or formula[i] == '_'):
                    i += 1
                tokens.append(("IDENT", formula[start:i], start))
                continue
            # Single-char tokens
            if c == '.':
                tokens.append(("DOT", ".", i)); i += 1; continue
            if c == '(':
                tokens.append(("LPAREN", "(", i)); i += 1; continue
            if c == ')':
                tokens.append(("RPAREN", ")", i)); i += 1; continue
            if c == '*':
                # Disambiguation: if the previous token is DOT, it's a wildcard;
                # otherwise it's the multiplication operator.
                if tokens and tokens[-1][0] == "DOT":
                    tokens.append(("WILDCARD_STAR", "*", i))
                else:
                    tokens.append(("OP", "*", i))
                i += 1
                continue
            if c in "+-/%":
                tokens.append(("OP", c, i)); i += 1; continue
            raise ValueError(f"unexpected character `{c}` at position {i}")
        return tokens

    def _peek(self, state: dict) -> tuple | None:
        if state["i"] < len(state["tokens"]):
            return state["tokens"][state["i"]]
        return None

    def _consume(self, state: dict) -> tuple:
        tok = state["tokens"][state["i"]]
        state["i"] += 1
        return tok

    def _expect(self, state: dict, ttype: str, tval: str = None) -> tuple:
        tok = self._peek(state)
        if tok is None:
            raise ValueError(f"expected token `{ttype}` but formula ended")
        if tok[0] != ttype or (tval is not None and tok[1] != tval):
            raise ValueError(f"expected token `{tval or ttype}` but found `{tok[1]}` at position {tok[2]}")
        return self._consume(state)

    def _parse_expr(self, state: dict, in_aggregator: bool):
        self._parse_term(state, in_aggregator)
        while True:
            tok = self._peek(state)
            if tok is None or tok[0] != "OP" or tok[1] not in ("+", "-"):
                break
            self._consume(state)
            self._parse_term(state, in_aggregator)

    def _parse_term(self, state: dict, in_aggregator: bool):
        self._parse_factor(state, in_aggregator)
        while True:
            tok = self._peek(state)
            if tok is None or tok[0] != "OP" or tok[1] not in ("*", "/", "%"):
                break
            self._consume(state)
            self._parse_factor(state, in_aggregator)

    def _parse_factor(self, state: dict, in_aggregator: bool):
        tok = self._peek(state)
        if tok is None:
            raise ValueError("expected expression but formula ended")
        ttype, tval, pos = tok
        # Negation: -factor
        if ttype == "OP" and tval == "-":
            self._consume(state)
            self._parse_factor(state, in_aggregator)
            return
        if ttype == "LPAREN":
            self._consume(state)
            self._parse_expr(state, in_aggregator)
            self._expect(state, "RPAREN")
            return
        if ttype == "NUMBER":
            self._consume(state)
            return
        if ttype == "IDENT":
            # Could be agg_call OR path
            next_tok = state["tokens"][state["i"] + 1] if state["i"] + 1 < len(state["tokens"]) else None
            if tval in self._AGG_NAMES and next_tok is not None and next_tok[0] == "LPAREN":
                self._consume(state)  # agg name
                self._consume(state)  # LPAREN
                self._parse_expr(state, in_aggregator=True)
                self._expect(state, "RPAREN")
                return
            # Path : IDENT ('.' (IDENT | WILDCARD_STAR))*
            self._consume(state)
            while True:
                nxt = self._peek(state)
                if nxt is None or nxt[0] != "DOT":
                    break
                self._consume(state)  # DOT
                seg = self._peek(state)
                if seg is None:
                    raise ValueError(f"path segment expected after `.` at position {tok[2]}")
                if seg[0] == "WILDCARD_STAR":
                    if not in_aggregator:
                        raise ValueError(
                            f"wildcard `*` at position {seg[2]} outside an aggregator (sum/count/avg/min/max). "
                            f"Decision Q6: the wildcard is only allowed inside an aggregator."
                        )
                    self._consume(state)
                elif seg[0] == "IDENT":
                    self._consume(state)
                else:
                    raise ValueError(f"invalid path segment `{seg[1]}` at position {seg[2]}")
            return
        raise ValueError(f"unexpected token `{tval}` at position {pos}")


# ─── Entry point ────────────────────────────────────────────────────────────

def validate_file(filepath: str) -> ValidationResult:
    """Validate an ACIR file."""
    try:
        with open(filepath, 'r') as f:
            doc = json.load(f)
    except json.JSONDecodeError as e:
        result = ValidationResult(valid=False)
        result.issues.append(ValidationIssue(
            level=0, severity=Severity.ERROR, path="$",
            code="INVALID_JSON", message=f"Invalid JSON: {e}"
        ))
        return result
    except FileNotFoundError:
        result = ValidationResult(valid=False)
        result.issues.append(ValidationIssue(
            level=0, severity=Severity.ERROR, path="$",
            code="FILE_NOT_FOUND", message=f"File not found: {filepath}"
        ))
        return result

    validator = ACIRValidator()
    return validator.validate(doc)


def main():
    force_utf8_output()

    if len(sys.argv) < 2:
        print("Usage: python acir_validator.py <file.acir.json> [--verbose]")
        sys.exit(1)

    filepath = sys.argv[1]
    verbose = "--verbose" in sys.argv

    result = validate_file(filepath)
    output = result.to_dict()

    # Report. When the normative JSON-Schema pass was skipped, say so on the
    # headline itself: level 1 still counts as passed, so a bare "6/6" would
    # claim more than was actually checked.
    degraded = ""
    if output['stats'].get('schema_validated') is False:
        degraded = " (level 1 degraded: normative JSON-Schema NOT applied)"

    total = output['stats'].get('total_levels', 6)
    if result.valid:
        print(f"✅ ACIR VALID — {output['stats'].get('passed_levels', 0)}/{total} levels passed{degraded}")
    else:
        print(f"❌ ACIR INVALID — stopped at level {output['stats'].get('passed_levels', 0)}{degraded}")

    print(f"\n📊 Summary: {output['summary']['errors']} errors, "
          f"{output['summary']['warnings']} warnings, "
          f"{output['summary']['info']} infos")

    if output['stats']:
        s = output['stats']
        # A project manifest carries components, not types/units/endpoints —
        # printing the module counters there just shows a row of zeros.
        if s.get('acir_kind') == "project":
            # Absent when validation stopped before the project pass ran —
            # print nothing rather than a misleading zero.
            n = s.get('components')
            if n is not None:
                print(f"📦 Project: {n} component{'' if n == 1 else 's'}")
        else:
            print(f"📦 Module: {s.get('types', 0)} types, {s.get('units', 0)} units, "
                  f"{s.get('endpoints', 0)} endpoints, {s.get('contracts', 0)} contracts")

    if verbose or not result.valid:
        print("\n─── Details ───")
        for issue in output["issues"]:
            icon = {"error": "❌", "warning": "⚠️ ", "info": "ℹ️ "}[issue["severity"]]
            print(f"  {icon} [L{issue['level']}] {issue['code']}")
            print(f"     {issue['path']}")
            print(f"     {issue['message']}")
            if issue.get("suggestion"):
                print(f"     💡 {issue['suggestion']}")
            print()

    # Output JSON machine-readable
    if "--json" in sys.argv:
        print("\n─── JSON Output ───")
        print(json.dumps(output, indent=2, ensure_ascii=False))

    sys.exit(0 if result.valid else 1)


if __name__ == "__main__":
    main()

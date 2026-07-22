#!/usr/bin/env python3
"""
ACIR Compiler — ACIR → Python/FastAPI

Version : voir COMPILER_VERSION ci-dessous (cf. docs/COMPILER-VERSIONING.md).

Generates a complete FastAPI project with:
  - SQLAlchemy models (entities with relationships)
  - Pydantic schemas (DTOs with validation from C_ contracts)
  - Service layer (business logic with transactions)
  - Routes with auth, rate limiting, smart HTTP codes
  - Built-in Swagger/OpenAPI documentation
  - Security: CORS, headers, input sanitization, log masking
  - Tests: pytest + httpx
"""

import json
import os
import re
import sys
from typing import Any


# ─── Versioning ────────────────────────────────────────────────────────────────
# Convention : <ACIR-major>.<ACIR-minor>.<ACIR-patch>.<patch-iter> (cf. docs/COMPILER-VERSIONING.md).
# Quand ACIR bumpe (0.3.0 → 0.3.1, 0.3 → 0.4), <patch-iter> reset à 0.
COMPILER_VERSION = "0.3.1.19"
COMPILER_TARGET = "py-fastapi"
COMPILER_ACIR_VERSION = "0.3.1"


# ─── Helpers ───────────────────────────────────────────────────────────────────

def to_snake(name: str) -> str:
    s = re.sub(r'(?<=[a-z0-9])([A-Z])', r'_\1', name)
    return s.lower()

def to_pascal(name: str) -> str:
    parts = re.split(r'[-_ ]+', name)
    return ''.join(w.capitalize() for w in parts if w)

def to_camel(name: str) -> str:
    p = to_pascal(name)
    return p[0].lower() + p[1:] if p else ""

def to_kebab(name: str) -> str:
    return to_snake(name).replace("_", "-")

def depluralize(name: str) -> str:
    """Strip a trailing plural suffix from an ACIR entity name.

    Mirrors compilers/acir_compiler_quarkus.py:depluralize (bug Quarkus #32 =
    bug FastAPI F8) — sans ça `entities=\"categories\"` → `Categorie` (au lieu de
    `Category`), et `categorieRepository` n'existe pas → NameError au boot.
    """
    if not name:
        return name
    if name.endswith("ies") and len(name) > 3:
        return name[:-3] + "y"  # categories -> category, stories -> story
    if name.endswith("ses") and len(name) > 3:
        return name[:-2]  # statuses -> status
    if name.endswith("s") and len(name) > 1 and not name.endswith("ss"):
        return name[:-1]  # users -> user, tickets -> ticket
    return name


def pluralize(name: str) -> str:
    """Inverse de depluralize — règles d'anglais minimales pour les noms de
    tables Postgres.

    Sans ça `__tablename__ = entity + 's'` donne `categorys`, `boxs`, etc.
    Couvre les cas usuels rencontrés dans les briefs (category, status, box,
    class) ; les cas exotiques (men, mice, datum) restent à patcher si besoin.
    """
    if not name:
        return name
    # Already plural — leave as is (depluralize would not fire either).
    if name.endswith("s") and not name.endswith("ss"):
        return name
    # y → ies (preceded by consonant). category → categories, story → stories.
    # Vowel+y stays (boy → boys), géré par le default ci-dessous.
    if name.endswith("y") and len(name) > 1 and name[-2] not in "aeiou":
        return name[:-1] + "ies"
    # ch/sh/x/z/s + s = "es". box → boxes, status → statuses.
    if name.endswith(("ch", "sh", "x", "z", "ss")):
        return name + "es"
    return name + "s"


# ─── Type Mapping ──────────────────────────────────────────────────────────────

SCALAR_MAP = {
    "string": "str",
    "integer": "int",
    "decimal": "Decimal",
    "boolean": "bool",
    "datetime": "datetime",
    "date": "date",
    "uuid": "UUID",
}

SA_TYPE_MAP = {
    "string": "String",
    "integer": "Integer",
    "decimal": "Numeric(12, 2)",
    "boolean": "Boolean",
    "datetime": "DateTime(timezone=True)",
    "date": "Date",
    "uuid": "Uuid",
}


# ─── Compiler ──────────────────────────────────────────────────────────────────

class ACIRToFastAPICompiler:
    # Token-shape detection — used by _synthesize_response_dto to emit `auth.issue_token(...)`
    # when a DTO field is named like an access/refresh token, JWT, or TTL. Mirrors the
    # Quarkus _TOKEN_FIELD_PATTERNS (bugs #17, #37).
    _TOKEN_FIELD_PATTERNS = ("accesstoken", "idtoken", "token", "jwt")
    _REFRESH_FIELD_PATTERNS = ("refreshtoken",)
    _TTL_FIELD_PATTERNS = ("expiresin", "ttl", "tokenttl")

    def __init__(self):
        self.generated_files = []
        self.type_registry = {}
        self.enum_registry = {}
        self.alias_registry = {}
        self.unit_registry = {}
        # Per-sequence tracking — reset at the start of each F_SEQUENCE compilation.
        # Maps step_name -> {"var": <python var name>, "type": <entity class name>}
        self._sequence_step_vars: dict = {}
        # Set when a service method uses auth.issue_token / _hash_password — drives
        # the `from app.auth import ...` line.
        self._service_uses_auth = False
        # v0.3 — set when a service body emits `Decimal(...)` from a $calculate
        # expression. Drives `from decimal import Decimal` in service.py.
        self._service_uses_decimal = False
        # v0.3 — F_FOREACH loop scope (ACIR `as` name → Python identifier).
        # Pushed on entry, restored on exit ; nested loops nest naturally.
        self._current_loop_scope: dict = {}
        # v0.3 — validators referenced via `$validate`. The service generator
        # walks this to emit one helper method per name.
        self._used_validators: set = set()
        # v0.3 — when compiling a validator's `rule`, holds the helper method's
        # parameter names so `$input: "<param>.<field>"` resolves to the local
        # variable instead of `data.get(...)` (which would be unbound).
        self._current_validator_params: set = set()

    def _add_file(self, path: str, content: str):
        self.generated_files.append((path, content))

    def compile(self, doc: dict) -> list[tuple[str, str]]:
        module = doc.get("module", {})
        module_name = module.get("name", "App")

        # Sprint D gap 3 — index `module.transforms[]` by name. Consumed par
        # `_compile_calculate_expr_py` quand un `$calculate` est en forme
        # string (v0.3.1) pour inliner la formule du transform référencé.
        self._transforms_index = {
            t.get("name"): t for t in (module.get("transforms") or []) if t.get("name")
        }

        # Index types
        for t in module.get("types", []):
            prim = t.get("primitive", "")
            name = t.get("name", "")
            if prim == "D_ENUM":
                self.enum_registry[name] = t
            elif prim == "D_ALIAS":
                self.alias_registry[name] = t
            elif prim in ("D_RECORD",):
                self.type_registry[name] = t

        # Index units
        for u in module.get("units", []):
            self.unit_registry[u.get("name", "")] = u

        # Hoist auth + rate-limit detection (consumed by multiple generators)
        self.has_auth = False
        self.all_roles: set[str] = set()
        self.has_rate_limit = False
        for ep in module.get("exposed", []):
            auth = ep.get("auth", {})
            if auth and auth.get("required"):
                self.has_auth = True
                for role in auth.get("roles", []):
                    self.all_roles.add(role)
            if ep.get("rate_limit"):
                self.has_rate_limit = True
        # Piste 1 — le brief émet-il son PROPRE JWT (signup/login DB) ? Si oui, le
        # scaffold env-var `/auth/login` est redondant (double login) → on émet le
        # MODULE auth (helpers get_current_user/issue_token/hash/verify, requis) mais
        # PAS la route env-var.
        self._has_own_token = self._brief_issues_token(module)

        # v0.3 — index module.relations[] before model generation so each entity
        # can decorate its nav fields with relationship() and synthesise back-refs.
        self.relations_index: dict[tuple, dict] = {}
        self.synthesized_relation_fields: dict[str, list] = {}
        self._index_relations_py(module)

        # Generate all files
        self._generate_requirements()
        self._generate_env(module)
        self._generate_database()
        self._generate_models(module)
        self._generate_schemas(module)
        self._generate_errors()
        self._generate_security(module)
        if self.has_rate_limit:
            self._generate_rate_limit_module()
        if self.has_auth:
            self._generate_auth_module()
            if not self._has_own_token:
                self._generate_auth_routes()
        self._generate_service(module)
        # Fix A-core — un composant Auth dédié (signup/login publics) a
        # has_auth=False (pas d'endpoint *protégé*) mais son service utilise
        # _hash_password/_verify_password/issue_token (→ _service_uses_auth).
        # Sans ça `from app.auth import …` était émis SANS app/auth.py
        # (ModuleNotFoundError au boot). On émet le module helper (PAS
        # _generate_auth_routes : le composant a déjà sa propre route login →
        # éviter un /auth/login en double).
        if (self._service_uses_auth
                and not any(p == "app/auth.py" for p, _ in self.generated_files)):
            self._generate_auth_module()
        self._generate_routes(module)
        self._generate_main(module)
        self._generate_tests(module)
        self._generate_readme(module)
        self._generate_alembic(module)
        self._generate_pyproject_pre_commit()
        self._generate_dockerfile(module)

        return self.generated_files

    # ─── requirements.txt ──────────────────────────────────────────────────

    def _generate_requirements(self):
        self._add_file("requirements.txt", """fastapi==0.115.0
uvicorn[standard]==0.32.0
sqlalchemy==2.0.36
alembic==1.14.0
psycopg2-binary==2.9.10
pydantic[email]==2.10.0
pydantic-settings==2.7.0
python-multipart==0.0.12
slowapi==0.1.9
PyJWT==2.10.0
python-json-logger==2.0.7
pytest==8.3.0
httpx==0.28.0
pytest-asyncio==0.24.0
""")

    # ─── .env ──────────────────────────────────────────────────────────────

    def _generate_env(self, module: dict):
        name = to_snake(module.get("name", "app"))
        env_lines = [
            f"# ACIR Generated — {module.get('name', 'App')}",
            f"DATABASE_URL=postgresql://acir:acir@localhost:5432/{name}",
            "CORS_ORIGINS=http://localhost:3000,http://localhost:5173",
        ]
        if self.has_auth:
            env_lines.append("# JWT secret — must be at least 32 chars for HS256")
            env_lines.append("JWT_SECRET=")
            env_lines.append("JWT_ISSUER=acir-app")
            # Pas de comptes env-var quand le brief a son propre login (store mort).
            if not self._has_own_token:
                env_lines.append("# Initial users — one password per role (defined in ACIR auth.roles)")
                for role in sorted(self.all_roles):
                    env_lines.append(f"AUTH_USER_{role.upper()}_PASSWORD=")
                if not self.all_roles:
                    # Auth requise sans rôle → utilisateur implicite "user" (doit matcher le seed).
                    env_lines.append("AUTH_USER_USER_PASSWORD=")
        self._add_file(".env.example", "\n".join(env_lines) + "\n")

    # ─── database.py ───────────────────────────────────────────────────────

    def _generate_database(self):
        self._add_file("app/__init__.py", "")
        self._add_file("app/database.py", '''"""ACIR Generated — Database configuration."""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://acir:acir@localhost:5432/{snake}")

engine = create_engine(DATABASE_URL, echo=os.getenv("SQL_DEBUG", "false").lower() == "true")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI dependency — yields a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
''')

    # ─── models.py (SQLAlchemy) ────────────────────────────────────────────

    def _index_relations_py(self, module: dict):
        """Mirror Quarkus _index_relations. Builds self.relations_index keyed by
        (entity, field) and synthesises back-ref fields not declared in types[].
        Conventions :
          - many_to_one  : `from` owner (FK column), `to` inverse (@OneToMany)
          - one_to_many  : `to` owner (FK), `from` inverse
          - many_to_many : `from` owner (Table secondary), `to` inverse mappedBy
          - one_to_one   : `from` owner par défaut
        """
        relations = module.get("relations", []) or []
        for rel in relations:
            if not isinstance(rel, dict):
                continue
            kind = rel.get("kind")
            f_side = rel.get("from", {}) or {}
            t_side = rel.get("to", {}) or {}
            f_entity = f_side.get("entity")
            t_entity = t_side.get("entity")
            f_field = f_side.get("field")
            t_field = t_side.get("inverse_field")
            if not (kind and f_entity and t_entity and f_field):
                continue
            if kind == "many_to_one":
                owner_entity, owner_field, owner_kind = f_entity, f_field, "many_to_one"
                inverse_entity, inverse_field, inverse_kind = t_entity, t_field, "one_to_many"
                fk_column = f_side.get("fk_column") or f"{to_snake(f_field)}_id"
                join_table = None
            elif kind == "one_to_many":
                owner_entity, owner_field, owner_kind = t_entity, t_field, "many_to_one"
                inverse_entity, inverse_field, inverse_kind = f_entity, f_field, "one_to_many"
                fk_column = (t_side.get("fk_column")
                              or (to_snake(t_field) + "_id" if t_field else None)
                              or (to_snake(inverse_entity.rstrip("s")) + "_id"))
                join_table = None
            elif kind == "many_to_many":
                owner_entity, owner_field, owner_kind = f_entity, f_field, "many_to_many"
                inverse_entity, inverse_field, inverse_kind = t_entity, t_field, "many_to_many"
                fk_column = None
                join_table = (rel.get("join_table")
                               or f"{to_snake(f_entity).rstrip('s')}_{to_snake(f_field)}")
            else:  # one_to_one
                owner_entity, owner_field, owner_kind = f_entity, f_field, "one_to_one"
                inverse_entity, inverse_field, inverse_kind = t_entity, t_field, "one_to_one"
                fk_column = f_side.get("fk_column") or f"{to_snake(f_field)}_id"
                join_table = None

            self.relations_index[(owner_entity, owner_field)] = {
                "role": "owner", "kind": owner_kind, "decl": rel,
                "fk_column": fk_column, "join_table": join_table,
                "owner_field": owner_field,
                "target_entity": inverse_entity, "target_field": inverse_field,
            }
            if inverse_field:
                self.relations_index[(inverse_entity, inverse_field)] = {
                    "role": "inverse", "kind": inverse_kind, "decl": rel,
                    "fk_column": fk_column, "join_table": join_table,
                    "owner_field": owner_field,
                    "target_entity": owner_entity, "target_field": owner_field,
                }
            # Synthesise nav fields not already declared in types[] so the model
            # gen iterates them alongside the regular fields.
            self._maybe_synth_relation_field_py(owner_entity, owner_field, owner_kind, inverse_entity)
            if inverse_field:
                self._maybe_synth_relation_field_py(inverse_entity, inverse_field, inverse_kind, owner_entity)

    def _maybe_synth_relation_field_py(self, entity_name: str, field_name: str,
                                        relation_kind: str, target_entity: str):
        record = self.type_registry.get(entity_name)
        if not record:
            return
        existing = {f.get("name") for f in record.get("fields", [])}
        if field_name in existing:
            return
        if relation_kind in ("one_to_many", "many_to_many"):
            field_type = {"primitive": "D_COLLECTION", "kind": "list",
                          "element_type": {"$ref": target_entity}}
        else:
            field_type = {"$ref": target_entity}
        self.synthesized_relation_fields.setdefault(entity_name, []).append({
            "name": field_name,
            "type": field_type,
        })

    def _generate_models(self, module: dict):
        imports = set()
        imports.add("import uuid")
        imports.add("from datetime import datetime, date, timezone")
        imports.add("from decimal import Decimal")
        imports.add("from sqlalchemy import Column, String, Integer, Boolean, DateTime, Date, Numeric, Text, Enum as SAEnum, Uuid")
        imports.add("from sqlalchemy.dialects.postgresql import UUID")
        imports.add("from app.database import Base")

        # Generate enums
        enum_defs = []
        for name, enum in self.enum_registry.items():
            values = enum.get("values", [])
            val_lines = "\n".join(f'    {v.get("name", "VALUE")} = "{v.get("name", "VALUE")}"' for v in values)
            enum_defs.append(f"""
class {name}(str, enum.Enum):
{val_lines}
""")
        if self.enum_registry:
            imports.add("import enum")

        # v0.3 — emit association tables for many_to_many relations BEFORE the
        # entity classes (they reference them via `secondary=`). Postgres FK
        # constraints + composite PK match the Quarkus PR D / Flyway shape.
        assoc_tables = []
        seen_join_tables = set()
        for (owner_entity, owner_field), entry in sorted(self.relations_index.items()):
            if entry.get("role") != "owner" or entry.get("kind") != "many_to_many":
                continue
            jt = entry.get("join_table")
            if not jt or jt in seen_join_tables:
                continue
            seen_join_tables.add(jt)
            target_entity = entry.get("target_entity")
            owner_col = to_snake(owner_entity.rstrip("s")) + "_id"
            target_col = to_snake(target_entity.rstrip("s")) + "_id" if target_entity else "target_id"
            owner_table = to_snake(owner_entity).rstrip("s") + "s"
            target_table = to_snake(target_entity).rstrip("s") + "s" if target_entity else "targets"
            assoc_tables.append(f"""
{jt} = Table(
    "{jt}",
    Base.metadata,
    Column("{owner_col}", UUID(as_uuid=True), ForeignKey("{owner_table}.id", ondelete="CASCADE"), primary_key=True),
    Column("{target_col}", UUID(as_uuid=True), ForeignKey("{target_table}.id", ondelete="CASCADE"), primary_key=True),
)""")
        if assoc_tables:
            imports.add("from sqlalchemy import Table, ForeignKey")

        # Generate entity models
        model_defs = []
        for name, record in self.type_registry.items():
            if not record.get("identity"):
                continue  # Skip DTOs

            # v0.3 — fields + synthesised back-refs (cf. Quarkus PR D).
            fields = list(record.get("fields", [])) + list(self.synthesized_relation_fields.get(name, []))
            field_lines = []
            relationship_lines: list = []
            skipped_refs: list = []
            for f in fields:
                fname = f.get("name", "")
                ftype = f.get("type", {})
                # v0.3 — if the field is declared in module.relations[], emit a
                # relationship() line instead of skipping. Adds ForeignKey to the
                # FK column declaration for owner sides (handled via _sa_column).
                rel_entry = self.relations_index.get((name, fname))
                if rel_entry is not None:
                    rel_line = self._build_relationship_line_py(rel_entry, imports)
                    if rel_line:
                        relationship_lines.append(f"    {fname} = {rel_line}")
                    continue
                sa_col = self._sa_column(fname, ftype, f, record)
                if sa_col is None:
                    # Entity navigation without a relations[] decl — keep the legacy
                    # skip behaviour so v0.2 ACIRs without relations[] still compile.
                    ref_name = ftype.get("$ref") if isinstance(ftype, dict) else None
                    if not ref_name and isinstance(ftype, dict):
                        ref_name = ftype.get("element_type", {}).get("$ref")
                    skipped_refs.append(f"    # {fname}: navigation to {ref_name} — skipped (declare in module.relations[] to enable relationship())")
                    continue
                # v0.3 — if `fname` is the FK column of a declared many_to_one /
                # one_to_one relation, append a ForeignKey constraint so Alembic
                # auto-gen picks it up and the relationship() resolves cleanly.
                fk_ref = self._fk_column_target_py(name, fname)
                if fk_ref:
                    sa_col = self._inject_fk_into_column(sa_col, fk_ref)
                    imports.add("from sqlalchemy import ForeignKey")
                field_lines.append(f"    {fname} = {sa_col}")
            field_lines.extend(relationship_lines)
            field_lines.extend(skipped_refs)

            table_name = pluralize(to_snake(name))
            id_field = (record.get("identity") or ["id"])[0]
            model_defs.append(f"""
class {name}(Base):
    \"\"\"ACIR entity — {name}.\"\"\"
    __tablename__ = "{table_name}"

{chr(10).join(field_lines)}

    def __repr__(self):
        return f"<{name}({id_field}={{self.{id_field}}})>"
""")

        if self.relations_index:
            imports.add("from sqlalchemy.orm import relationship")

        content = "\n".join(sorted(imports)) + "\n"
        content += "\n".join(enum_defs)
        content += "\n".join(assoc_tables)
        content += "\n".join(model_defs)
        self._add_file("app/models.py", f'"""ACIR Generated — SQLAlchemy Models."""\n{content}')

    def _build_relationship_line_py(self, rel_entry: dict, _imports: set) -> str:
        """Return a SQLAlchemy `relationship(...)` source line for one nav field."""
        kind = rel_entry["kind"]
        target = rel_entry.get("target_entity")
        target_field = rel_entry.get("target_field")
        jt = rel_entry.get("join_table")
        if not target:
            return ""
        # back_populates is set when the inverse side also declares a field.
        bp = f', back_populates="{to_snake(target_field)}"' if target_field else ""
        if kind == "many_to_one":
            # SQLAlchemy infers `foreign_keys` from the ForeignKey() on the FK column
            # (injected by _inject_fk_into_column). No need to specify explicitly
            # unless there's an ambiguity (multiple FKs to the same target) — rare
            # enough to defer until we hit it.
            return f'relationship("{target}"{bp})'
        if kind == "one_to_many":
            return f'relationship("{target}"{bp})'
        if kind == "many_to_many":
            if not jt:
                return f'relationship("{target}"{bp})'
            return f'relationship("{target}", secondary={jt}{bp})'
        if kind == "one_to_one":
            uselist = ", uselist=False"
            return f'relationship("{target}"{bp}{uselist})'
        return f'relationship("{target}"{bp})'

    def _fk_column_target_py(self, entity: str, fname: str) -> str:
        """If `entity.fname` is the FK column of an owner-side relation, return
        the target table name (snake_case + 's') to embed in a ForeignKey constraint.
        Otherwise return ''.
        """
        for (owner_entity, _owner_field), entry in self.relations_index.items():
            if owner_entity != entity:
                continue
            if entry.get("role") != "owner":
                continue
            if entry.get("kind") not in ("many_to_one", "one_to_one"):
                continue
            if entry.get("fk_column") == fname:
                target = entry.get("target_entity")
                if target:
                    return to_snake(target).rstrip("s") + "s"
        return ""

    def _inject_fk_into_column(self, sa_col: str, target_table: str) -> str:
        """Splice `ForeignKey("<target>.id")` into an existing `Column(...)` source line.

        SQLAlchemy requires the **type** to come first in Column's positional args
        (Column(type_, *args) — name is the attribute). We insert the ForeignKey
        right after the type, before any other args/kwargs. Existing columns are
        emitted as `Column(<Type>, <kwargs>)` ; we splice after the first comma.
        """
        if not sa_col.startswith("Column(") or "ForeignKey(" in sa_col:
            return sa_col
        # Find the position just after the first positional arg (the type). For
        # bare `Column(Uuid)` (no comma), append before the closing paren.
        inner_start = len("Column(")
        first_comma = sa_col.find(",", inner_start)
        if first_comma == -1:
            # `Column(Type)` → `Column(Type, ForeignKey("X.id"))`
            close = sa_col.rfind(")")
            return sa_col[:close] + f', ForeignKey("{target_table}.id")' + sa_col[close:]
        return sa_col[:first_comma] + f', ForeignKey("{target_table}.id")' + sa_col[first_comma:]

    def _is_entity_ref(self, ftype: dict) -> bool:
        """True if `ftype` is `{$ref: <Entity>}` where <Entity> is a record with identity."""
        if not isinstance(ftype, dict):
            return False
        ref = ftype.get("$ref", "")
        if not ref:
            return False
        rec = self.type_registry.get(ref, {})
        return bool(rec.get("identity"))

    def _is_collection_of_entity(self, ftype: dict) -> bool:
        """True if `ftype` is `D_COLLECTION` with `element_type` pointing to an entity."""
        if not isinstance(ftype, dict):
            return False
        if ftype.get("primitive") != "D_COLLECTION":
            return False
        return self._is_entity_ref(ftype.get("element_type", {}))

    def _sa_column(self, fname: str, ftype: dict, field: dict, record: dict = None):
        """Return a SQLAlchemy `Column(...)` source string, or None to skip the field.

        F-relations (P2 minimal-fix, équivalent Quarkus #23) : on **skip** les fields
        qui sont des refs d'entité (`{$ref: User}`) ou des collections d'entités
        (`List[Tag]`). Sans ça, le compilateur émettait `author = Column(String, NOT NULL)`
        en doublon de `author_id`, et `tags = Column(String, NOT NULL)` à côté de rien.
        Une vraie `relationship()` + secondary table = P3 follow-up (F-relations-real).
        """
        # Skip navigations vers d'autres entités (le FK `<name>_id` reste en column).
        if self._is_entity_ref(ftype) or self._is_collection_of_entity(ftype):
            return None

        kind = ftype.get("kind", "") if isinstance(ftype, dict) else ""
        ref = ftype.get("$ref", "") if isinstance(ftype, dict) else ""

        # Resolve alias
        if ref and ref in self.alias_registry:
            alias = self.alias_registry[ref]
            base = alias.get("base_type", {})
            kind = base.get("kind", "") if isinstance(base, dict) else ""

        # Nullable : `optional: true` (forme ACIR canonique) ou `required: false`.
        # Le code historique ne regardait que `required` → tous les fields tombaient
        # `nullable=False` même quand l'ACIR disait `optional: true` (e.g. brief 2
        # `published_at` qui doit être nullable car set au passage en PUBLISHED).
        nullable = field.get("optional", False) or not field.get("required", True)

        # Resolve enum
        if ref and ref in self.enum_registry:
            return f'Column(SAEnum({ref}), nullable={nullable})'

        sa_type = SA_TYPE_MAP.get(kind, "String")
        parts = [sa_type]

        # Length for strings
        contracts = field.get("contracts", [])
        if ref and ref in self.alias_registry:
            contracts = self.alias_registry[ref].get("contracts", []) + contracts
        for c in contracts:
            if isinstance(c, dict) and c.get("primitive") == "C_LENGTH":
                max_len = c.get("max", 255)
                if kind == "string":
                    parts = [f"String({max_len})"]

        # Primary key — dérivé de l'`identity` DU RECORD (pas du field !).
        # Avant : `field.get("identity")` (toujours None) → seule une colonne
        # littéralement nommée `id` devenait PK ; une entité dont la clé est
        # `product_id` n'avait AUCUNE PK → SQLAlchemy ArgumentError au boot.
        _identity = (record or {}).get("identity") or []
        is_pk = (fname in _identity) if _identity else (fname == "id")
        pk_str = ", primary_key=True" if is_pk else ""

        # Unique
        unique_str = ""
        for c in contracts:
            if isinstance(c, dict) and c.get("primitive") == "C_UNIQUE":
                unique_str = ", unique=True"

        null_str = f", nullable={nullable}" if not is_pk else ""

        # Default for UUID and datetime fields
        default_str = ""
        if kind == "uuid" and is_pk:
            default_str = ", default=uuid.uuid4"
        elif kind == "datetime":
            fname_lower = fname.lower()
            if field.get("immutable") or "created" in fname_lower:
                # created_at: set once on insert
                default_str = ", default=lambda: datetime.now(timezone.utc)"
            elif "updated" in fname_lower or "modified" in fname_lower:
                # updated_at: set on insert AND on every update
                default_str = ", default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc)"

        col_type = parts[0]
        return f"Column({col_type}{pk_str}{unique_str}{null_str}{default_str})"

    # ─── schemas.py (Pydantic) ─────────────────────────────────────────────

    def _generate_schemas(self, module: dict):
        imports = [
            "from datetime import datetime, date",
            "from decimal import Decimal",
            "from typing import Optional, List",
            "from uuid import UUID",
            "from pydantic import BaseModel, Field, field_validator",
            "from pydantic.alias_generators import to_camel",
        ]
        if self.enum_registry:
            imports.append("from app.models import " + ", ".join(sorted(self.enum_registry.keys())))

        schema_defs = []

        for name, record in self.type_registry.items():
            if record.get("identity"):
                # Entity → generate Response schema
                schema_defs.append(self._pydantic_schema(name, record, is_response=True))
            else:
                # DTO → generate Input schema
                schema_defs.append(self._pydantic_schema(name, record, is_response=False))

        # Generate response wrappers for entities (skip if already defined as a DTO)
        for name, record in self.type_registry.items():
            if record.get("identity"):
                list_name = f"{name}ListResponse"
                if list_name not in self.type_registry:
                    # Shape canonique ACIR : `{data, total, page, limit}` (parité avec
                    # `PaginatedX` déclaré par les briefs et avec Quarkus/Fastify qui
                    # transcrivent fidèle le wrapper ACIR). Sans alignement, briefs
                    # SANS wrapper ACIR (ex: brief7) surfaçaient `{items, page_size,
                    # total_pages}` côté API — divergence visible par les clients.
                    schema_defs.append(f"""
class {list_name}(BaseModel):
    \"\"\"Paginated list of {name}.\"\"\"
    data: List[{name}Response]
    total: int
    page: int
    limit: int

    model_config = {{"from_attributes": True}}
""")

        content = "\n".join(imports) + "\n"
        content += "\n".join(schema_defs)
        # `from __future__ import annotations` : annotations différées (PEP 563)
        # → plus de NameError sur référence avant définition (DTO citant un
        # type déclaré plus bas, types hissés ajoutés en fin de registre,
        # refs mutuelles). Pydantic v2 résout les annotations à l'usage.
        self._add_file("app/schemas.py", f'"""ACIR Generated — Pydantic Schemas with contract validation."""\nfrom __future__ import annotations\n{content}')

    def _pydantic_schema(self, name: str, record: dict, is_response: bool) -> str:
        suffix = "Response" if is_response else ""
        class_name = f"{name}{suffix}"
        doc = record.get("doc", f"ACIR schema — {name}")
        fields = record.get("fields", [])

        field_lines = []
        validator_lines = []

        # F6 : field names qui sont des mots-clés Python (brief 4 → `from`, `to`)
        # cassent le parse. On les remappe vers `<name>_` et on garde le JSON name
        # original via Pydantic alias. populate_by_name=True permet aux clients
        # d'envoyer soit le mot-clé soit le nom Python.
        import keyword as _keyword
        has_aliased_field = False
        for f in fields:
            fname = f.get("name", "")
            ftype = f.get("type", {})
            # F-relations : pour les Response DTOs synthétisés depuis une entité
            # (e.g. ArticleResponse depuis Article), on saute les fields qui sont
            # des refs d'entité ou des collections d'entité. La couche SQLAlchemy ne
            # les expose pas (cf. _sa_column qui les skip), donc Pydantic avec
            # `from_attributes=True` ferait AttributeError → 500 au runtime.
            # Pour les DTOs utilisateur (AuthResponse, etc., is_response=False),
            # on garde les fields — ils sont assignés explicitement par le service.
            if is_response and (self._is_entity_ref(ftype) or self._is_collection_of_entity(ftype)):
                continue
            # Q-SEC-1 : ne JAMAIS exposer un champ sensible dans un DTO de RÉPONSE
            # (entité → Response). Le hash de mot de passe fuyait dans UserResponse
            # (donc dans AuthResponse.user). On exclut les champs `sensitive: true`
            # (flag ACIR) + tout champ « password* » (défaut défensif). Les schémas
            # d'INPUT (is_response=False, ex. SignupInput) gardent `password` — c'est
            # une entrée ; et le modèle SQLAlchemy garde le champ (auth en a besoin).
            if is_response and (f.get("sensitive") or "password" in fname.lower()):
                continue
            # Support both `required: false` and `optional: true` (ACIR canonical form).
            required = f.get("required", True) and not f.get("optional", False)
            contracts = list(f.get("contracts", []))
            sensitive = f.get("sensitive", False)

            # Resolve type
            py_type = self._resolve_py_type(ftype)

            # Resolve alias contracts
            ref = ftype.get("$ref", "") if isinstance(ftype, dict) else ""
            if ref and ref in self.alias_registry:
                alias = self.alias_registry[ref]
                contracts = alias.get("contracts", []) + contracts

            # Build Field() kwargs
            field_kwargs = self._build_field_kwargs(contracts, fname, sensitive)

            # Map reserved keywords to safe Python identifiers, keeping the JSON name
            # via Pydantic alias.
            py_name = fname
            if _keyword.iskeyword(fname) or fname in {"global", "from", "import", "return", "class", "type"}:
                py_name = f"{fname}_"
                field_kwargs["alias"] = repr(fname)
                has_aliased_field = True

            if not required:
                py_type = f"Optional[{py_type}]"
                if "default" not in field_kwargs:
                    field_kwargs["default"] = "None"

            kwargs_str = ", ".join(f"{k}={v}" for k, v in field_kwargs.items())
            field_lines.append(f"    {py_name}: {py_type}{' = Field(' + kwargs_str + ')' if kwargs_str else ''}")

            # C_SANITIZE → validator
            for c in contracts:
                if isinstance(c, dict) and c.get("primitive") == "C_SANITIZE":
                    modes = c.get("modes", ["trim", "html_escape"])
                    body = f'        if isinstance(v, str):\n'
                    if "trim" in modes:
                        body += f'            v = v.strip()\n'
                    if "html_escape" in modes:
                        body += f'            v = v.replace("<", "&lt;").replace(">", "&gt;").replace("\\"", "&quot;")\n'
                    if "strip_tags" in modes:
                        body += f'            import re; v = re.sub(r"<[^>]*>", "", v)\n'
                    body += f'        return v'
                    validator_lines.append(f"""
    @field_validator("{fname}", mode="before")
    @classmethod
    def sanitize_{fname}(cls, v):
{body}
""")

        # Config for response
        config_line = ""
        config_kvs = []
        if is_response:
            config_kvs.append('"from_attributes": True')
        # F-RUNTIME-2 fix — TOUS les DTO acceptent les fields en camelCase ET
        # snake_case. Pydantic snake_case par défaut côté Python, mais l'API
        # JSON doit accepter camelCase (convention web, cohérent avec
        # Fastify/Quarkus). `alias_generator=to_camel` + `populate_by_name=True`
        # permet aux clients TS/JS d'envoyer `organizationName` (camelCase) ET
        # côté Python on accède via `data.organization_name`.
        config_kvs.append('"populate_by_name": True')
        config_kvs.append('"alias_generator": to_camel')
        if config_kvs:
            config_line = "\n    model_config = {" + ", ".join(config_kvs) + "}\n"

        return f"""
class {class_name}(BaseModel):
    \"\"\"{doc}\"\"\"
{chr(10).join(field_lines)}
{config_line}{"".join(validator_lines)}"""

    def _resolve_py_type(self, ftype: dict) -> str:
        if not isinstance(ftype, dict):
            return "str"
        prim = ftype.get("primitive", "")
        kind = ftype.get("kind", "")
        ref = ftype.get("$ref", "")

        # D_COLLECTION : list/set/map of element_type. Without this branch, _resolve_py_type
        # tombait dans `SCALAR_MAP.get(kind, "str")` qui retournait "str" pour kind="list" —
        # → DTO `PaginatedArticles.data: str` au lieu de `List[ArticleResponse]` (bug F3a).
        if prim == "D_COLLECTION":
            element_type = ftype.get("element_type", {})
            inner = self._resolve_py_type(element_type)
            if kind == "set":
                return f"List[{inner}]"  # Pydantic v2 sérialise set en list; pas de Set[] pour JSON
            if kind == "map":
                # element_type sert de valeur — clé toujours str pour JSON
                return f"dict[str, {inner}]"
            return f"List[{inner}]"

        if ref:
            if ref in self.enum_registry:
                return ref
            if ref in self.alias_registry:
                alias = self.alias_registry[ref]
                base = alias.get("base_type", {})
                return self._resolve_py_type(base)
            if ref in self.type_registry:
                if self.type_registry[ref].get("identity"):
                    return f"{ref}Response"
                return ref
            return "str"

        return SCALAR_MAP.get(kind, "str")

    def _build_field_kwargs(self, contracts: list, fname: str, sensitive: bool) -> dict:
        kw = {}
        if sensitive:
            kw["exclude"] = "True"
            kw["json_schema_extra"] = '{"writeOnly": True}'

        for c in contracts:
            if not isinstance(c, dict):
                continue
            prim = c.get("primitive", "")
            if prim == "C_RANGE":
                if c.get("min") is not None:
                    if c.get("exclusive_min"):
                        kw["gt"] = str(c["min"])
                    else:
                        kw["ge"] = str(c["min"])
                if c.get("max") is not None:
                    kw["le"] = str(c["max"])
            elif prim == "C_LENGTH":
                if c.get("min") is not None:
                    kw["min_length"] = str(c["min"])
                if c.get("max") is not None:
                    kw["max_length"] = str(c["max"])
            elif prim == "C_PATTERN":
                fmt = c.get("format")
                regex = c.get("regex")
                if regex:
                    kw["pattern"] = f'r"{regex}"'
                elif fmt == "email":
                    pass  # Handled by EmailStr type
            elif prim == "C_PRECISION":
                kw["decimal_places"] = str(c.get("scale", 2))
        return kw

    # ─── errors.py ─────────────────────────────────────────────────────────

    def _generate_errors(self):
        self._add_file("app/errors.py", '''"""ACIR Generated — Error handling. Never leak stack traces."""
from fastapi import Request
from fastapi.responses import JSONResponse
import logging

logger = logging.getLogger("acir")


class AcirError(Exception):
    def __init__(self, kind: str, message: str, status_code: int = 400):
        self.kind = kind
        self.message = message
        self.status_code = status_code

class NotFoundError(AcirError):
    def __init__(self, resource: str, id: str = ""):
        super().__init__("not_found", f"{resource} non trouvé" + (f" (id={id})" if id else ""), 404)

class ConflictError(AcirError):
    def __init__(self, message: str = "Conflit — la ressource existe déjà"):
        super().__init__("conflict", message, 409)

class ValidationError(AcirError):
    def __init__(self, message: str = "Données invalides"):
        super().__init__("validation_failed", message, 422)

class ForbiddenError(AcirError):
    def __init__(self):
        super().__init__("forbidden", "Accès interdit", 403)

class UnauthorizedError(AcirError):
    """HTTP 401 — credentials manquantes ou invalides (login fail typiquement).
    Distinct de ForbiddenError (403, auth OK mais role insuffisant) et
    de NotFoundError (404, ressource publique inexistante)."""
    def __init__(self, message: str = "Identifiants invalides"):
        super().__init__("unauthorized", message, 401)


async def acir_error_handler(request: Request, exc: AcirError):
    return JSONResponse(status_code=exc.status_code, content={"kind": exc.kind, "message": exc.message})


async def catch_all_handler(request: Request, exc: Exception):
    """Catch-all — never leak internals to the client."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(status_code=500, content={
        "kind": "internal_error",
        "message": "Une erreur inattendue est survenue. Veuillez réessayer.",
    })
''')

    # ─── security.py ───────────────────────────────────────────────────────

    def _generate_security(self, module: dict):
        # Collect sensitive fields
        sensitive = set()
        for name, record in self.type_registry.items():
            for f in record.get("fields", []):
                if f.get("sensitive"):
                    sensitive.add(f["name"])
        for common in ("password", "token", "secret", "api_key", "credit_card", "ssn"):
            sensitive.add(common)
        sensitive_list = ", ".join(f'"{s}"' for s in sorted(sensitive))

        self._add_file("app/security.py", f'''"""ACIR Generated — Security utilities (headers + log redaction).

Note: a regex-based XSS filter middleware previously lived here. It was removed
because it provides only a false sense of security — defense in depth against XSS
must be done by Pydantic validation on input + escaping on output (frontend), not
by best-effort regex matching on raw query strings.
"""
import logging

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("acir")

SENSITIVE_FIELDS = {{{sensitive_list}}}


def sanitize_for_log(data: dict) -> dict:
    """Mask sensitive fields for logging."""
    safe = {{**data}}
    for key in safe:
        if key.lower() in SENSITIVE_FIELDS or any(s in key.lower() for s in SENSITIVE_FIELDS):
            safe[key] = "***REDACTED***"
    return safe


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """OWASP-recommended response headers."""
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response
''')

    # ─── rate_limit.py — extracted to avoid circular import main↔routes ────

    def _generate_rate_limit_module(self):
        self._add_file("app/rate_limit.py", '''"""ACIR Generated — SlowAPI rate limiter (extracted to avoid circular imports)."""
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
''')

    # Champs « token » reconnus : un DTO de sortie qui en porte un = le brief émet
    # son propre JWT (login/signup applicatif) → scaffold env-var redondant (piste 1).
    _TOKEN_FIELD_NAMES = {
        "access_token", "accesstoken", "token", "refresh_token", "refreshtoken",
        "jwt", "id_token", "idtoken", "bearer", "auth_token", "authtoken",
    }

    def _brief_issues_token(self, module: dict) -> bool:
        """True si une unit retourne un DTO porteur d'un champ token (login applicatif).
        Sert à décider de NE PAS émettre le `/auth/login` env-var (double login)."""
        types = {t["name"]: t for t in module.get("types", []) or []
                 if isinstance(t, dict) and t.get("name")}

        def _rec_has_token(rec: dict) -> bool:
            for f in (rec.get("fields") or []):
                if not isinstance(f, dict):
                    continue
                if f.get("name", "").lower().replace("-", "_") in self._TOKEN_FIELD_NAMES:
                    return True
            return False

        for u in module.get("units", []) or []:
            if not isinstance(u, dict):
                continue
            out = u.get("output")
            ref = out.get("$ref") if isinstance(out, dict) else None
            rec = types.get(ref) if ref else None
            if isinstance(rec, dict) and rec.get("primitive") == "D_RECORD" and _rec_has_token(rec):
                return True
        return False

    # ─── auth.py — JWT (HS256) + in-memory user store + role dependency ────

    def _generate_auth_module(self):
        # Mirror Quarkus AuthService: PBKDF2-SHA256 (600k iter), JWT HS256, env-var users.
        # Store env-var mort quand le brief a son propre login (seul routes_auth — retiré
        # — le lisait ; le login du brief n'appelle que issue_token/_verify_password).
        roles_list = [] if self._has_own_token else sorted(self.all_roles)
        register_lines = []
        for role in roles_list:
            user = role.lower().replace("_", "")
            env_var = f"AUTH_USER_{role.upper()}_PASSWORD"
            register_lines.append(f'    _register_if_present("{user}", "{role}", os.getenv("{env_var}"))')
        if not roles_list and self.has_auth and not self._has_own_token:
            # Auth requise sans rôle déclaré → utilisateur implicite "user" lu depuis
            # `AUTH_USER_USER_PASSWORD` (même nom que le compose/infra fournit). Sans ce
            # fallback, AUCUN compte n'était seedé (`pass`) → login impossible → JWT
            # introuvable (le cas le + courant). Parité Quarkus/Fastify.
            register_lines.append('    _register_if_present("user", "user", os.getenv("AUTH_USER_USER_PASSWORD"))')
        register_block = "\n".join(register_lines) if register_lines else "    pass"

        self._add_file("app/auth.py", f'''"""ACIR Generated — JWT authentication (HS256) + role-based authorization.

Mirrors the Quarkus AuthService design:
  * passwords hashed with PBKDF2-SHA256 (OWASP 2024: 600 000 iterations)
  * JWTs signed with HMAC HS256
  * users hydrated from AUTH_USER_<ROLE>_PASSWORD env vars at startup
  * fail-soft: missing env var = no user registered (no crash)
"""
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt as pyjwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# ─── Config ────────────────────────────────────────────────────────────
# Use `or` (not the 2-arg form) so an empty env var (e.g. JWT_SECRET= in .env)
# falls back to the default rather than failing the length check below.
JWT_SECRET = os.getenv("JWT_SECRET") or "dev-only-jwt-secret-please-override-in-production"
JWT_ISSUER = os.getenv("JWT_ISSUER") or "acir-app"
JWT_ALGO = "HS256"
TOKEN_TTL_SECONDS = 24 * 3600

if len(JWT_SECRET) < 32:
    raise RuntimeError("JWT_SECRET must be at least 32 characters (HS256 requirement)")

# ─── Password hashing (PBKDF2-SHA256) ─────────────────────────────────
_PW_ITERATIONS = 600_000
_PW_DKLEN = 32

def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _PW_ITERATIONS, dklen=_PW_DKLEN)
    return f"{{salt}}${{dk.hex()}}"

def _verify_password(password: str, stored: str) -> bool:
    try:
        salt, dk_hex = stored.split("$", 1)
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _PW_ITERATIONS, dklen=_PW_DKLEN)
    return hmac.compare_digest(dk.hex(), dk_hex)

# ─── In-memory user store, hydrated from env vars ─────────────────────
# Format: {{username: (password_hash, role)}}
_users: dict[str, tuple[str, str]] = {{}}

def _register_if_present(username: str, role: str, password: Optional[str]) -> None:
    if password:
        _users[username] = (_hash_password(password), role)

def _load_users() -> None:
{register_block}

_load_users()

# ─── JWT issuance + verification ──────────────────────────────────────
def authenticate(username: str, password: str) -> Optional[str]:
    """Returns the user role if credentials match, else None."""
    cred = _users.get(username)
    if cred is None:
        return None
    pw_hash, role = cred
    return role if _verify_password(password, pw_hash) else None

def issue_token(username: str, role: str, subject: Optional[str] = None) -> str:
    """Émet un JWT signé HS256.

    `subject` permet de surcharger `sub` quand le pattern d'auth env-var
    a besoin d'un UUID synthétique (vs login signup où `username` = UUID
    réel de l'entité). Cf. `issue_token_for_env_user` ci-dessous —
    sans ça, `sub = "user"` (string) causait des `psycopg2.errors.\
InvalidTextRepresentation` au runtime quand le service utilise
    `\\$auth: user_id` pour assigner à une colonne UUID.
    """
    now = datetime.now(timezone.utc)
    payload = {{
        "iss": JWT_ISSUER,
        "sub": subject or username,
        "upn": username,
        "groups": [role],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=TOKEN_TTL_SECONDS)).timestamp()),
    }}
    return pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def issue_token_for_env_user(username: str, role: str) -> str:
    """Émet un JWT pour un utilisateur env-var (AUTH_USER_<ROLE>_PASSWORD).

    Synthétise un UUID déterministe via MD5(envvar-user:<username>) pour
    pouvoir l'utiliser comme `sub` (UUID-typed côté DB). Sans ça, le `sub`
    était la string `username` brute (e.g. "user"), qui crashait à
    l'insertion dans une colonne UUID (`\\$auth: user_id` -> Postgres
    `InvalidTextRepresentation`).

    Parité Fastify `issueTokenForEnvUser` — même algo MD5, même UUID
    déterministe par username -> même utilisateur côté DB peu importe la
    cible compilée.
    """
    import hashlib
    h = hashlib.md5(f"envvar-user:{{username}}".encode()).hexdigest()
    synth = f"{{h[0:8]}}-{{h[8:12]}}-{{h[12:16]}}-{{h[16:20]}}-{{h[20:32]}}"
    return issue_token(username, role, subject=synth)

def _decode(token: str) -> dict:
    try:
        return pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO], issuer=JWT_ISSUER)
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expiré")
    except pyjwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalide")

# ─── FastAPI dependencies ─────────────────────────────────────────────
_bearer = HTTPBearer(auto_error=False)

def get_current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer)) -> dict:
    if creds is None or not creds.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentification requise",
                            headers={{"WWW-Authenticate": "Bearer"}})
    return _decode(creds.credentials)

def optional_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer)) -> Optional[dict]:
    """Public-route dependency — décode le Bearer si présent, retourne None sinon.

    F-RUNTIME-1 fix — marque `current_user` comme dépendance FastAPI (vs body
    parameter), empêchant FastAPI d'auto-activer `embed=True` sur le body
    schema. Avant : `current_user: Optional[dict] = None` était compté comme
    2e body param avec data, FastAPI activait embed → client devait envoyer
    `{{"data": {{...}}}}` au lieu de `{{...}}` direct.
    """
    if creds is None or not creds.credentials:
        return None
    try:
        return _decode(creds.credentials)
    except HTTPException:
        return None

def require_role(*allowed_roles: str):
    """Dependency factory — returns a dependency that enforces role membership."""
    def _checker(user: dict = Depends(get_current_user)) -> dict:
        groups = user.get("groups", [])
        if not any(r in allowed_roles for r in groups):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail=f"Rôle requis : {{', '.join(allowed_roles)}}")
        return user
    return _checker

TOKEN_TTL = TOKEN_TTL_SECONDS  # exported for clients
''')

    # ─── routes_auth.py — POST /auth/login ────────────────────────────

    def _generate_auth_routes(self):
        self._add_file("app/routes_auth.py", '''"""ACIR Generated — Authentication endpoints (POST /auth/login)."""
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.auth import authenticate, issue_token_for_env_user, TOKEN_TTL

router = APIRouter(tags=["Auth"])


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


class LoginResponse(BaseModel):
    token: str
    role: str
    expires_in: int


@router.post("/auth/login", response_model=LoginResponse, summary="Login (issue JWT)")
async def login(req: LoginRequest) -> LoginResponse:
    role = authenticate(req.username, req.password)
    if role is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Identifiants invalides")
    # F-RUNTIME-BRIEF1-UUID-SUB — utilise issue_token_for_env_user (sub UUID
    # synthétique déterministe) au lieu d'issue_token (sub = username string).
    # Sans ça, `\\$auth: user_id` côté service crashe à l'insertion dans une
    # colonne UUID Postgres (InvalidTextRepresentation: "user").
    return LoginResponse(token=issue_token_for_env_user(req.username, role), role=role, expires_in=TOKEN_TTL)
''')

    # ─── service.py ────────────────────────────────────────────────────────

    def _generate_service(self, module: dict):
        module_name = module.get("name", "App")
        service_class = f"{to_pascal(module_name)}Service"

        imports = [
            "from uuid import UUID, uuid4",
            "from datetime import datetime, timezone",
            "from typing import Optional, List, Tuple",
            "from sqlalchemy.orm import Session",
            "from sqlalchemy import desc, asc",
            "from sqlalchemy.exc import IntegrityError",
            # ForbiddenError is raised by F_GUARD-emitted code (cf. _compile_sequence_body_py).
            # We include it in the baseline import so service.py never NameErrors on guards,
            # whether or not the current unit contains a guard. Unused imports cost nothing.
            "from app.errors import NotFoundError, ConflictError, ValidationError, ForbiddenError, UnauthorizedError",
        ]

        # Import models and schemas
        entity_names = [n for n, r in self.type_registry.items() if r.get("identity")]
        dto_names = [n for n, r in self.type_registry.items() if not r.get("identity")]
        enum_names = list(self.enum_registry.keys())

        # Entities + enums both live in app.models — service.py needs both, since
        # F_SEQUENCE compiles enum string literals (e.g. "FREE") to `PlanType.FREE`.
        model_imports = sorted(set(entity_names) | set(enum_names))
        if model_imports:
            imports.append(f"from app.models import {', '.join(model_imports)}")
        # Auth-shape DTOs (AuthResponse-like) are referenced by F_SEQUENCE service
        # methods that synthesize them — import all DTOs so `AuthResponse(access_token=...)`
        # resolves at runtime.
        if dto_names:
            imports.append(f"from app.schemas import {', '.join(sorted(dto_names))}")

        # Reset auth-usage flag before scanning units. Methods that hit $hash or
        # token-shape synthesis will flip _service_uses_auth, driving the import below.
        self._service_uses_auth = False
        # v0.3 — same pattern for Decimal (driven by `$calculate`).
        self._service_uses_decimal = False
        # v0.3 — reset validator-usage tracking each service generation so the
        # helper methods only get emitted for actually-referenced validators.
        self._used_validators = set()

        methods = []
        for unit_name, unit in self.unit_registry.items():
            method = self._generate_service_method(unit_name, unit, module)
            if method:
                methods.append(method)

        # v0.3 — emit one private helper per validator referenced via $validate.
        if self._used_validators:
            validator_decls = {v.get("name"): v for v in module.get("validators", [])
                                if isinstance(v, dict) and v.get("name")}
            for vname in sorted(self._used_validators):
                vd = validator_decls.get(vname)
                if not vd:
                    methods.append(
                        f"\n    def _{to_snake(vname)}(self, *args) -> bool:\n"
                        f"        return True  # TODO: $validate references unknown validator '{vname}'\n"
                    )
                    continue
                methods.append(self._generate_validator_method_py(vd))

        if self._service_uses_auth:
            imports.append("from app.auth import issue_token, TOKEN_TTL_SECONDS, _hash_password, _verify_password")
        # Q-FUNC-1 : l'import doit suivre TOUT `Decimal(...)` émis, y compris les
        # fallbacks `$calculate` non résolus (`Decimal(0)`) qui ne lèvent pas le
        # flag. Check sur le contenu final = bulletproof (sinon NameError runtime).
        if self._service_uses_decimal or any("Decimal(" in m for m in methods):
            imports.append("from decimal import Decimal")

        imports_str = "\n".join(sorted(set(imports)))
        methods_str = "\n".join(methods)

        self._add_file("app/service.py", f'''"""ACIR Generated — Service Layer."""
from __future__ import annotations
{imports_str}


class {service_class}:
    """Business logic — generated from ACIR X_UNIT definitions."""

    def __init__(self, db: Session):
        self.db = db
{methods_str}
''')

    # ─── F_SEQUENCE / F_QUERY / F_AUTH helpers ────────────────────────────
    # These port the Quarkus compiler's _compile_data_expr / _resolve_step_ref /
    # _synthesize_response_dto / $hash recognition to Python (bugs F-seq, F-query, F-auth).

    def _entity_class_names(self) -> set:
        return {n for n, r in self.type_registry.items() if r.get("identity")}

    def _entity_class_from_acir_name(self, acir_name: str) -> str:
        """`organizations` → `Organization` ; falls back to to_pascal(depluralize(...))."""
        for n in self.type_registry:
            if to_snake(n) + "s" == acir_name or to_snake(n) == acir_name:
                return n
        return to_pascal(depluralize(acir_name)) if acir_name else ""

    def _find_pagination_wrapper(self, entity_class: str):
        """Search type_registry for a D_RECORD that *looks like* a pagination
        wrapper for `entity_class` (e.g. `PaginatedTasks` for `Task`).

        Mirror of acir_compiler_quarkus._find_pagination_wrapper — see that one
        for the rationale. Heuristic : wrapper must have a `data` or `items`
        field whose element_type is `{$ref: entity_class}` + at least one of
        `total` / `page` / `limit` / `total_pages`.
        Used by the route emitter so endpoints declaring `output: List<Task>`
        (no $ref) still surface a typed `response_model=PaginatedTasks` when
        a matching wrapper is declared in the type_registry.
        """
        if not entity_class:
            return None
        meta_fields = {"total", "page", "limit", "total_pages"}
        for type_name, record in self.type_registry.items():
            if not isinstance(record, dict) or record.get("identity"):
                continue
            fields = record.get("fields", []) or []
            field_names = {f.get("name") for f in fields if isinstance(f, dict)}
            if not (meta_fields & field_names):
                continue
            for f in fields:
                if not isinstance(f, dict) or f.get("name") not in ("data", "items"):
                    continue
                ftype = f.get("type", {})
                if not isinstance(ftype, dict) or ftype.get("primitive") != "D_COLLECTION":
                    continue
                elem = ftype.get("element_type", {}) or {}
                if isinstance(elem, dict) and elem.get("$ref") == entity_class:
                    return type_name
        return None

    def _enum_for_string_literal(self, entity_class: str, field_name: str, value: str):
        """If a record field is enum-typed and the value is a known enum name, return `EnumClass.VALUE`.

        Sans ça, `plan='FREE'` est stocké en string et SQLAlchemy avec Column(Enum(Plan))
        rejette la valeur au commit. Avec, on émet `Plan.FREE` qui matche le SA Enum.
        """
        record = self.type_registry.get(entity_class, {})
        for f in record.get("fields", []):
            if f.get("name") != field_name:
                continue
            ftype = f.get("type", {})
            ref = ftype.get("$ref", "") if isinstance(ftype, dict) else ""
            if ref in self.enum_registry:
                values = {v.get("name") if isinstance(v, dict) else v for v in self.enum_registry[ref].get("values", [])}
                if value in values:
                    return f"{ref}.{value}"
        return None

    def _compile_data_expr_py(self, expr, entity_class: str = "", field_name: str = "") -> str:
        """Convert an ACIR data expression into a Python expression string.

        Recognises:
          - `{$input: "field"}`   → data['field']
          - `{$input: ""}`        → data  (scalar input case)
          - `{$step: "step.field"}` → step_var.field
          - `{$generate: "uuid"}` → uuid4()
          - `{$generate: "now"}`  → datetime.now(timezone.utc)
          - `{$hash: <expr>}`     → _hash_password(<inner>)  ; sets _service_uses_auth
          - literal str/int/bool/None → repr()
          - dict without $-key   → repr()  (fallback)
        Unknown `$xxx` keys emit `None  # TODO: $xxx`.
        """
        if expr is None:
            return "None"
        if isinstance(expr, bool):
            return "True" if expr else "False"
        if isinstance(expr, (int, float)):
            return repr(expr)
        if isinstance(expr, str):
            # Try enum match — e.g. "FREE" on Organization.plan → Plan.FREE
            enum_ref = self._enum_for_string_literal(entity_class, field_name, expr) if entity_class else None
            if enum_ref:
                return enum_ref
            return repr(expr)
        if isinstance(expr, list):
            inner = ", ".join(self._compile_data_expr_py(e, entity_class, field_name) for e in expr)
            return f"[{inner}]"
        if isinstance(expr, dict):
            if "$input" in expr:
                key = expr["$input"]
                if not key:
                    return "data"  # whole-scalar input
                # v0.3 — inside a validator helper, `$input: "<param>.<field>"`
                # resolves to the local parameter (e.g. `order.status`) rather than
                # `data.get(...)` (which would be unbound).
                if isinstance(key, str) and "." in key:
                    root = key.split(".", 1)[0]
                    if root in (self._current_validator_params or set()):
                        return root + "." + ".".join(to_snake(p) for p in key.split(".")[1:])
                elif isinstance(key, str) and key in (self._current_validator_params or set()):
                    return key
                return f"data.get({key!r})"
            if "$step" in expr:
                return self._resolve_step_ref_py(expr["$step"])
            if "$generate" in expr:
                return self._compile_generate_py(expr["$generate"])
            if "$hash" in expr:
                self._service_uses_auth = True
                hash_arg = expr["$hash"]
                # Brief 4 saw `{$hash: {value: <expr>, algorithm: "bcrypt"}}` — unwrap when present
                if isinstance(hash_arg, dict) and "value" in hash_arg and not any(
                    k.startswith("$") for k in hash_arg.keys()
                ):
                    inner = self._compile_data_expr_py(hash_arg["value"], entity_class, field_name)
                else:
                    inner = self._compile_data_expr_py(hash_arg, entity_class, field_name)
                return f"_hash_password({inner})"
            # v0.2 #39a parity — `$auth: <claim>` reads the JWT payload that the
            # endpoint passes through as the `current_user` kwarg. Service methods
            # accept **kwargs so we don't need to touch their signatures.
            if "$auth" in expr:
                claim = expr["$auth"]
                self._service_uses_auth = True
                return self._compile_auth_claim_py(claim)
            # v0.3 — `$context: "request.<key>"` reads the FastAPI Request object that
            # the endpoint passes through as the `request` kwarg. Same opt-in via kwargs
            # so legacy endpoints without `auth.required` still compile.
            if "$context" in expr:
                return self._compile_context_ref_py(expr["$context"])
            # v0.3 — `$verify: {value, hash, algorithm}` → boolean via _verify_password
            # (already exported from app.auth alongside _hash_password). The algorithm
            # field is informational ; bcrypt/pbkdf2/argon2 all route through the same
            # helper which encapsulates the actual algorithm.
            if "$verify" in expr:
                self._service_uses_auth = True
                return self._compile_verify_expr_py(expr["$verify"], entity_class, field_name)
            if "$calculate" in expr:
                # v0.3 — DSL arithmétique avec aggregators et wildcard paths.
                # Compile en Decimal Python (générateurs + sum/min/max).
                return self._compile_calculate_expr_py(expr["$calculate"], entity_class, field_name)
            if "$loop" in expr:
                # v0.3 — F_FOREACH iteration variable reference.
                return self._compile_loop_ref_py(expr["$loop"])
            if "$validate" in expr:
                # v0.3 — `$validate: {name, input}` calls a generated helper method.
                # The legacy v0.2 string form (`$validate: "name"`) is not a predicate
                # — it falls through to the catch-all `None` below.
                return self._compile_validate_call_py(expr["$validate"], entity_class, field_name)
            # Any other $xxx — improvised primitive (Quarkus #29 equivalent).
            # Bare None (no inline comment) so nested function calls stay parseable.
            if any(k.startswith("$") for k in expr):
                return "None"
            return repr(expr)
        return repr(expr)

    # ─── v0.3 — $auth / $context / $verify helpers ───────────────────────────

    # JWT claim name mappings (mirror Quarkus _AUTH_USER_ID_CLAIMS etc.). The
    # FastAPI auth module writes `sub`/`upn`/`groups` ; map the ACIR-side claim
    # names to whichever JWT payload key actually holds the value.
    _AUTH_USER_ID_CLAIMS = ("user_id", "userid", "user.id", "id", "sub", "subject")
    _AUTH_USERNAME_CLAIMS = ("username", "email", "upn", "preferred_username", "name")
    _AUTH_ROLE_CLAIMS = ("role", "roles")

    def _compile_auth_claim_py(self, claim) -> str:
        """`$auth: <claim>` → Python expression reading current_user from kwargs."""
        if not isinstance(claim, str):
            return "None"
        # The user dict is forwarded via kwargs.get('current_user') ; falls back to
        # an empty dict so missing-kwarg lookups don't AttributeError.
        cu = "(kwargs.get('current_user') or {})"
        if claim in self._AUTH_USER_ID_CLAIMS:
            return f"{cu}.get('sub')"
        if claim in self._AUTH_USERNAME_CLAIMS:
            return f"{cu}.get('upn') or {cu}.get('sub')"
        if claim in self._AUTH_ROLE_CLAIMS:
            return f"(({cu}.get('groups') or [None])[0])"
        return f"{cu}.get({claim!r})"

    _CONTEXT_REQUEST_EXTRACTORS_PY = {
        "ip":          "request.client.host if request and request.client else None",
        "remote_addr": "request.client.host if request and request.client else None",
        "user_agent":  "(request.headers.get('User-Agent') if request else None)",
        "useragent":   "(request.headers.get('User-Agent') if request else None)",
        "method":      "(request.method if request else None)",
        "path":        "(request.url.path if request else None)",
        "uri":         "(str(request.url) if request else None)",
        "host":        "(request.url.hostname if request else None)",
        "scheme":      "(request.url.scheme if request else None)",
    }

    def _compile_context_ref_py(self, claim) -> str:
        """`$context: "<namespace>.<key>"` → Python expression reading the FastAPI
        Request from kwargs (`request.*` namespace) ou le JWT (`user.*` namespace).
        Mirrors la version Fastify post-Sprint F.

        Emits bare `None` (no inline `# TODO` comment) for malformed/unknown shapes
        because inline comments break Python parsing when the expression sits inside
        a dict value, function call, etc. The TODO trace lives in the source code
        comment in this function rather than in the generated output.
        """
        if not isinstance(claim, str) or "." not in claim:
            return "None"
        namespace, _, key = claim.partition(".")
        if namespace == "request":
            key_norm = key.lower().replace("-", "_")
            request_bind = "(kwargs.get('request'))"
            extractor = self._CONTEXT_REQUEST_EXTRACTORS_PY.get(key_norm)
            if extractor:
                return f"((lambda request: {extractor})({request_bind}))"
            return f"({request_bind}.headers.get({key!r}) if {request_bind} else None)"
        if namespace == "user":
            # Sprint D gap 2 — mapping `user.*` vers les JWT claims via
            # `_compile_auth_claim_py` (qui lit `kwargs.get('current_user')`).
            # Cas brief2 F_GUARD : `$context: "user.role"` → admin override.
            key_norm = key.lower()
            if key_norm in ("id", "user_id", "sub"):
                return self._compile_auth_claim_py("user_id")
            if key_norm in ("role", "roles", "group", "groups"):
                return self._compile_auth_claim_py("role")
            if key_norm in ("email", "upn", "username"):
                return self._compile_auth_claim_py("username")
            return self._compile_auth_claim_py(key)
        # tenant.* requires a middleware that isn't generated yet ; unknown namespaces
        # fall through to None so the file still parses.
        return "None"

    def _compile_verify_expr_py(self, payload, entity_class: str, field_name: str) -> str:
        """`$verify: {value, hash, algorithm}` → `_verify_password(value, hash)`.

        Emits bare `False` for malformed payloads (no inline `# TODO`) so the
        expression stays parseable inside dict values / function args.
        """
        # Q-FUNC-2 : accepter `password`/`plaintext`/`plain` comme alias de `value`
        # (forme non-canonique très fréquente du LLM sur un login : `$verify:
        # {password, hash}`). Sans ça `value` est absent → on retournait "False"
        # → `if not (False…): raise` = login TOUJOURS en échec.
        if not isinstance(payload, dict) or "hash" not in payload:
            return "False"
        value_key = next((k for k in ("value", "password", "plaintext", "plain") if k in payload), None)
        if value_key is None:
            return "False"
        value_expr = self._compile_data_expr_py(payload[value_key], entity_class, field_name)
        hash_payload = payload["hash"]
        hash_expr = self._compile_data_expr_py(hash_payload, entity_class, field_name)
        verify_call = f"_verify_password({value_expr}, {hash_expr})"
        # Q-FUNC-2b : si le hash vient d'un $step `X.field` (query single qui peut
        # renvoyer None, ex. login avec un email inexistant), garder la base-var :
        # `(X is not None and verify…)`. Sinon `None.password_hash` → AttributeError
        # → 500 ; avec le guard, condition False → l'on_fail du F_GUARD répond
        # proprement (« Invalid credentials ») au lieu de crasher.
        if isinstance(hash_payload, dict) and isinstance(hash_payload.get("$step"), str) and "." in hash_payload["$step"]:
            head = hash_payload["$step"].split(".", 1)[0]
            base_var = self._sequence_step_vars.get(head, {}).get("var")
            if base_var:
                return f"({base_var} is not None and {verify_call})"
        return verify_call

    # ─── $loop / $validate / predicate (v0.3) ────────────────────────────────

    def _compile_loop_ref_py(self, path) -> str:
        """`$loop: "<var>.<field>"` → Python `<var>.<field>` resolved against the
        current F_FOREACH scope. Returns bare `None` if not in scope (parses
        safely in dict-value positions).
        """
        if not isinstance(path, str) or not path:
            return "None"
        parts = path.split(".")
        root = parts[0]
        scope = self._current_loop_scope or {}
        if root not in scope:
            return "None"
        py_var = scope[root]
        if len(parts) == 1:
            return py_var
        return py_var + "." + ".".join(to_snake(p) for p in parts[1:])

    def _generate_validator_method_py(self, validator: dict) -> str:
        """Emit `def _<name>(self, <args>) -> bool:` for one module.validators[] entry.

        Args are sorted by ACIR name for determinism and to match the order
        `_compile_validate_call_py` passes them. The rule is compiled inside a
        validator-param scope so `$input: "<param>.<field>"` resolves to the local
        parameter rather than `data.get(...)`.
        """
        name = validator.get("name", "unknown")
        method_name = to_snake(name)
        doc = validator.get("doc", "")
        inputs = validator.get("input", {}) if isinstance(validator.get("input"), dict) else {}
        rule = validator.get("rule", {})
        param_names = [to_snake(k) for k in sorted(inputs.keys())]
        params_str = ", ".join(param_names) if param_names else ""
        signature_params = f"self, {params_str}" if params_str else "self"
        prev_scope = self._current_validator_params
        self._current_validator_params = set(param_names)
        try:
            rule_py = self._compile_predicate_py(rule, "", "")
        finally:
            self._current_validator_params = prev_scope
        doc_line = f'        """{doc}"""\n' if doc else ""
        return (f"\n    def _{method_name}({signature_params}) -> bool:\n"
                f"{doc_line}        return {rule_py}\n")

    def _compile_validate_call_py(self, payload, entity_class: str, field_name: str) -> str:
        """`$validate: {name, input}` → Python `self._<name>(<args>)` call on the
        generated helper. Registers the validator name for service-side codegen.
        v0.2 string-form (`$validate: "name"`) is not a predicate — caller should
        gate on shape before reaching this branch.
        """
        if not isinstance(payload, dict):
            return "True"
        name = payload.get("name")
        if not isinstance(name, str):
            return "True"
        self._used_validators.add(name)
        method_name = to_snake(name)
        inputs = payload.get("input", {}) if isinstance(payload.get("input"), dict) else {}
        ordered_keys = sorted(inputs.keys())
        args = [self._compile_data_expr_py(inputs[k], entity_class, field_name) for k in ordered_keys]
        return f"self._{method_name}({', '.join(args)})"

    # Sprint D gap 2 — F_GUARD condition compiler. Handles 3 shapes :
    # (a) v0.3 predicate ($eq, $ne, $verify, $and, $or, ...)
    # (b) F_BRANCH wrapping legacy `{$context, operator, value}` + then/else
    # (c) direct legacy `{$context, operator, value}`
    # Returns the Python bool expression string, or None if unrecognized.
    def _compile_guard_condition_py(self, condition):
        if not isinstance(condition, dict):
            return None
        # (a) v0.3 predicate
        if self._is_v03_predicate_py(condition):
            return self._compile_predicate_py(condition, "", "")
        # (b) F_BRANCH wrap
        if condition.get("primitive") == "F_BRANCH":
            inner = condition.get("condition", {})
            then_v = condition.get("then")
            else_v = condition.get("else")
            inner_bool = self._compile_legacy_cond_py(inner)
            then_bool = self._fbranch_value_to_bool_py(then_v)
            else_bool = self._fbranch_value_to_bool_py(else_v)
            if inner_bool is None or then_bool is None or else_bool is None:
                return None
            # Python ternary syntax.
            return f"({then_bool} if ({inner_bool}) else {else_bool})"
        # (c) direct legacy
        return self._compile_legacy_cond_py(condition)

    def _compile_legacy_cond_py(self, cond):
        """Compile un `{$context|$input|$auth, operator, value}` legacy en bool Python."""
        if not isinstance(cond, dict):
            return None
        if "primitive" in cond:
            return None  # F_BRANCH or IO_QUERY mistakenly passed here
        operator = cond.get("operator", "eq")
        value = cond.get("value")
        lhs_expr = {k: v for k, v in cond.items() if k.startswith("$")}
        if not lhs_expr:
            return None
        lhs = self._compile_data_expr_py(lhs_expr, "", "")
        rhs = self._compile_data_expr_py(value, "", "") if value is not None else "None"
        op_map = {"eq": "==", "ne": "!=", "gt": ">", "gte": ">=", "lt": "<", "lte": "<="}
        py_op = op_map.get(operator)
        if operator == "in":
            return f"({lhs} in ({rhs} or []))"
        if operator == "not_in":
            return f"({lhs} not in ({rhs} or []))"
        if not py_op:
            return None
        return f"({lhs} {py_op} {rhs})"

    def _fbranch_value_to_bool_py(self, value):
        """F_BRANCH.then/.else en bool Python. Patterns supportés :
        - True/False littéraux
        - IO_QUERY avec `exists: true` → `self.db.query(X).filter(...).first() is not None`
        - predicate v0.3
        """
        if value is True:
            return "True"
        if value is False:
            return "False"
        if isinstance(value, dict):
            if value.get("primitive") == "IO_QUERY" and value.get("exists"):
                entity = value.get("entity", "")
                model_class = to_pascal(depluralize(entity)) if entity else ""
                if not model_class:
                    return None
                filter_expr = value.get("filter", {})
                # Compile filter to SQLAlchemy filter clauses. Reuse the dict-filter
                # path from queries — `_compile_filter_clauses_py` returns a list of
                # `Model.field == value` exprs. We AND them in `filter(*clauses)`.
                clauses = self._compile_simple_filter_clauses_py(filter_expr, model_class)
                if clauses is None:
                    return None
                return f"(self.db.query({model_class}).filter({clauses}).first() is not None)"
            if self._is_v03_predicate_py(value):
                return self._compile_predicate_py(value, "", "")
        return None

    # ─── Filter operator map (Sprint D gap 5 — F-query-ops) ──────────────────
    # Avant : seul `eq` était compilé, tous les autres operators skippés avec
    # un commentaire `# TODO: ... non-eq skipped`. Maintenant on mappe tous
    # les operators ACIR vers leur expression SQLAlchemy native.
    def _compile_filter_clause_py(self, entity_class: str, fname: str, spec):
        """Compile UN filter clause `(field, spec)` → expression SQLAlchemy.

        `spec` peut être :
        - dict `{operator, value}` (forme canonique)
        - dict `{$input/$auth/...}` (legacy : valeur directe, operator=eq implicite)
        - scalaire direct (legacy : operator=eq implicite)

        Retourne la string clause, ou None si l'operator n'est pas supporté
        (le caller émet alors un commentaire skip pour rester parseable).
        """
        col = f"{entity_class}.{fname}"
        # Forme canonique {operator, value}
        if isinstance(spec, dict) and "value" in spec and not any(
            k.startswith("$") for k in spec
        ):
            op_str = spec.get("operator", "eq")
            value_expr = self._compile_data_expr_py(spec["value"], entity_class, fname)
        else:
            op_str = "eq"
            value_expr = self._compile_data_expr_py(spec, entity_class, fname)

        if op_str == "eq":
            return f"{col} == {value_expr}"
        if op_str == "ne":
            return f"{col} != {value_expr}"
        if op_str == "gt":
            return f"{col} > {value_expr}"
        if op_str == "gte":
            return f"{col} >= {value_expr}"
        if op_str == "lt":
            return f"{col} < {value_expr}"
        if op_str == "lte":
            return f"{col} <= {value_expr}"
        if op_str == "in":
            # SQLAlchemy .in_() veut un itérable ; `value_expr or []` garde
            # le clause valide si la source est None à l'exécution.
            return f"{col}.in_({value_expr} or [])"
        if op_str == "not_in":
            return f"~{col}.in_({value_expr} or [])"
        if op_str == "like":
            return f"{col}.like({value_expr})"
        if op_str == "ilike":
            return f"{col}.ilike({value_expr})"
        if op_str == "contains":
            return f"{col}.contains({value_expr})"
        if op_str == "range":
            # `value` attendu = liste/tuple de 2 → .between(a, b). On compile
            # les 2 bornes si la source est un littéral list de 2 ; sinon skip.
            raw = spec.get("value") if isinstance(spec, dict) else None
            if isinstance(raw, (list, tuple)) and len(raw) == 2:
                a = self._compile_data_expr_py(raw[0], entity_class, fname)
                b = self._compile_data_expr_py(raw[1], entity_class, fname)
                return f"{col}.between({a}, {b})"
            return None
        # Operator inconnu — caller skip.
        return None

    def _compile_filter_clauses_py(self, entity_class: str, filter_expr: dict):
        """Compile tous les clauses d'un `filter_expr` → (clauses:list, skipped:list).
        clauses = strings SQLAlchemy ; skipped = `field(op)` non supportés.
        """
        clauses, skipped = [], []
        for fname, spec in (filter_expr or {}).items():
            clause = self._compile_filter_clause_py(entity_class, fname, spec)
            if clause is None:
                op = spec.get("operator", "?") if isinstance(spec, dict) else "?"
                skipped.append(f"{fname}({op})")
            else:
                clauses.append(clause)
        return clauses, skipped

    def _compile_simple_filter_clauses_py(self, filter_expr, model_class):
        """Filter compiler pour les F_BRANCH `exists` checks. Depuis gap 5,
        délègue à `_compile_filter_clauses_py` (tous operators). Retourne la
        string clauses ready for `.filter(...)`, ou None si un operator est
        non supporté (caller émet un TODO + bail).
        """
        if not isinstance(filter_expr, dict):
            return None
        clauses, skipped = self._compile_filter_clauses_py(model_class, filter_expr)
        if skipped:
            return None
        return ", ".join(clauses) if clauses else None

    def _is_v03_predicate_py(self, expr) -> bool:
        """Mirror Quarkus _is_v03_predicate. Detects well-formed v0.3 predicate
        shapes ; the v0.2 brief2/4 string forms (`$validate: "name"`) bail out so
        the F_GUARD legacy path keeps working.
        """
        if not isinstance(expr, dict):
            return False
        if "$validate" in expr:
            return isinstance(expr["$validate"], dict) and "name" in expr["$validate"]
        if "$verify" in expr:
            v = expr["$verify"]
            # Q-FUNC-2 : `value` OU alias `password`/`plaintext`/`plain` (sinon
            # le $verify part en legacy → condition dégénérée `(False == None)`).
            return (isinstance(v, dict) and "hash" in v
                    and any(k in v for k in ("value", "password", "plaintext", "plain")))
        for k in ("$eq", "$ne", "$gt", "$gte", "$lt", "$lte"):
            if k in expr:
                return isinstance(expr[k], list) and len(expr[k]) == 2
        if "$in" in expr:
            return isinstance(expr["$in"], list) and len(expr["$in"]) >= 2
        for k in ("$and", "$or"):
            if k in expr:
                return isinstance(expr[k], list)
        for k in ("$is_null", "$is_not_null", "$not"):
            if k in expr:
                return True
        return False

    def _compile_predicate_py(self, expr, entity_class: str = "", field_name: str = "") -> str:
        """Compile a Predicate DataExpr to a Python boolean expression.

        Supported : $verify, $validate, $and, $or, $not, $is_null, $is_not_null,
        $eq/$ne (Python ==/!=), $gt/$gte/$lt/$lte (Python comparison),
        $in (Python `in` over a list). Unknown shapes return `False` (no inline
        comment so the expression stays in dict-value position).
        """
        if not isinstance(expr, dict):
            return "True" if expr else "False"
        if "$verify" in expr:
            return self._compile_verify_expr_py(expr["$verify"], entity_class, field_name)
        if "$validate" in expr and isinstance(expr["$validate"], dict):
            return self._compile_validate_call_py(expr["$validate"], entity_class, field_name)
        if "$and" in expr:
            parts = expr["$and"] if isinstance(expr["$and"], list) else []
            if not parts:
                return "True"
            return "(" + " and ".join(self._compile_predicate_py(p, entity_class, field_name) for p in parts) + ")"
        if "$or" in expr:
            parts = expr["$or"] if isinstance(expr["$or"], list) else []
            if not parts:
                return "False"
            return "(" + " or ".join(self._compile_predicate_py(p, entity_class, field_name) for p in parts) + ")"
        if "$not" in expr:
            inner = self._compile_predicate_py(expr["$not"], entity_class, field_name)
            return f"(not ({inner}))"
        if "$is_null" in expr:
            val = self._compile_data_expr_py(expr["$is_null"], entity_class, field_name)
            return f"({val} is None)"
        if "$is_not_null" in expr:
            val = self._compile_data_expr_py(expr["$is_not_null"], entity_class, field_name)
            return f"({val} is not None)"
        bin_ops = {"$eq": "==", "$ne": "!=", "$gt": ">", "$gte": ">=", "$lt": "<", "$lte": "<="}
        for key, py_op in bin_ops.items():
            if key in expr:
                ops = expr[key] if isinstance(expr[key], list) else []
                if len(ops) != 2:
                    return "False"
                left = self._compile_data_expr_py(ops[0], entity_class, field_name)
                right = self._compile_data_expr_py(ops[1], entity_class, field_name)
                return f"({left} {py_op} {right})"
        if "$in" in expr:
            ops = expr["$in"] if isinstance(expr["$in"], list) else []
            if len(ops) < 2:
                return "False"
            value = self._compile_data_expr_py(ops[0], entity_class, field_name)
            candidates = [self._compile_data_expr_py(c, entity_class, field_name) for c in ops[1:]]
            return f"({value} in ({', '.join(candidates)},))"
        return "False"

    # ─── $generate (Sprint D gap 4) ──────────────────────────────────────────
    # DSL template tokens (identique aux 3 cibles, cf. docs/ACIR-v0.3-sprint-d.md) :
    #   {yyyymmdd}   → date UTC compacte (20260515)
    #   {yyyy-mm-dd} → date ISO (2026-05-15)
    #   {hhmmss}     → heure UTC compacte (143052)
    #   {random:N}   → N hex chars uppercase (source uuid4, pas d'import secrets)
    #   {uuid}       → 8 premiers hex d'un uuid4
    #   {seq}        → epoch seconds (fallback ; vraie séquence DB = hors-scope)
    @staticmethod
    def _parse_generate_template(fmt: str):
        """Split `fmt` en segments [('lit', txt) | ('tok', name, arg)]. Partagé
        conceptuellement avec les emitters Fastify/Quarkus (même regex)."""
        out = []
        i = 0
        while i < len(fmt):
            if fmt[i] == "{":
                j = fmt.find("}", i)
                if j == -1:
                    out.append(("lit", fmt[i:]))
                    break
                tok = fmt[i + 1:j]
                if ":" in tok:
                    name, _, arg = tok.partition(":")
                    out.append(("tok", name.strip(), arg.strip()))
                else:
                    out.append(("tok", tok.strip(), None))
                i = j + 1
            else:
                j = fmt.find("{", i)
                if j == -1:
                    out.append(("lit", fmt[i:]))
                    break
                out.append(("lit", fmt[i:j]))
                i = j
        return out

    def _compile_generate_py(self, gen) -> str:
        """`$generate` → expression Python. String form (uuid/now/sequence/
        ulid/nanoid) ou dict form (`{kind:"template",format:"..."}` /
        `{kind:"slug",from:"..."}`).
        """
        # String form (builtins).
        if isinstance(gen, str):
            if gen == "uuid":
                return "uuid4()"
            if gen == "now":
                return "datetime.now(timezone.utc)"
            if gen == "sequence":
                return "int(datetime.now(timezone.utc).timestamp())"
            if gen in ("ulid", "nanoid"):
                return "uuid4().hex"
            # Référence nommée hors-builtins (LLM improvise) — bare None.
            return "None"
        if isinstance(gen, dict):
            kind = gen.get("kind")
            if kind in ("uuid", "now", "sequence", "ulid", "nanoid"):
                return self._compile_generate_py(kind)
            if kind == "slug":
                src = gen.get("from")
                if not src:
                    return "None"
                src_expr = f"data.get({src!r})"
                slug = (f"__import__('re').sub(r'[^a-z0-9]+', '-', str({src_expr} or '').lower()).strip('-')")
                maxlen = gen.get("max_length")
                if isinstance(maxlen, int) and maxlen > 0:
                    slug = f"({slug})[:{maxlen}]"
                return slug
            if kind == "template":
                fmt = gen.get("format")
                if not isinstance(fmt, str) or not fmt:
                    return "None"
                parts = []
                for seg in self._parse_generate_template(fmt):
                    if seg[0] == "lit":
                        parts.append(seg[1])
                        continue
                    name, arg = seg[1], seg[2]
                    low = name.lower()
                    if low == "yyyymmdd":
                        parts.append("{datetime.now(timezone.utc).strftime('%Y%m%d')}")
                    elif low in ("yyyy-mm-dd", "iso-date"):
                        parts.append("{datetime.now(timezone.utc).strftime('%Y-%m-%d')}")
                    elif low == "hhmmss":
                        parts.append("{datetime.now(timezone.utc).strftime('%H%M%S')}")
                    elif low == "random":
                        n = int(arg) if (arg and arg.isdigit()) else 6
                        parts.append(f"{{uuid4().hex[:{n}].upper()}}")
                    elif low == "uuid":
                        parts.append("{uuid4().hex[:8]}")
                    elif low == "seq":
                        parts.append("{int(datetime.now(timezone.utc).timestamp())}")
                    else:
                        # Token inconnu — laissé littéral pour rester visible.
                        parts.append("{" + (f"{name}:{arg}" if arg else name) + "}")
                # Échappe les accolades littérales hors-tokens en doublant {{ }}.
                body = "".join(parts)
                # On a déjà injecté nos {expr} ; les {{ }} littéraux ne sont pas
                # gérés (pas observé dans les briefs). f-string direct.
                return f'f"{body}"'
        return "None"

    # ─── $calculate DSL → Python Decimal ─────────────────────────────────────
    # Grammar (identical to Quarkus PR B / validator) :
    #   formula  := expr
    #   expr     := term (('+'|'-') term)*
    #   term     := factor (('*'|'/'|'%') factor)*
    #   factor   := number | path | agg_call | '(' expr ')' | '-' factor
    #   agg_call := agg_name '(' expr ')'    ; agg_name ∈ {sum,count,avg,min,max}
    #   path     := identifier ('.' (identifier | '*'))*
    # Python's Decimal supports the +/-/*/// operators natively, so the emit is
    # much shorter than the Java version (no .add / .multiply method calls).
    _CALC_AGG_NAMES_PY = {"sum", "count", "avg", "min", "max"}

    def _compile_calculate_expr_py(self, calc, entity_class: str, field_name: str) -> str:
        """Resolve `$calculate` to a Python Decimal expression.

        Two forms (v0.3.1) :
        - **String** : `$calculate: "cart_total_ht"` → look up
          `module.transforms["cart_total_ht"]` ; le body doit être
          `{$calculate: {formula, inputs}}`, on inline. Gap 3.
        - **Dict** : `$calculate: {formula, inputs}` — forme canonique
          historique (v0.3.0).
        """
        # v0.3.1 string form — résolution contre `module.transforms[]`.
        if isinstance(calc, str):
            transforms = getattr(self, "_transforms_index", {}) or {}
            transform_decl = transforms.get(calc)
            if transform_decl is None:
                # Référence dangling — fallback typé. Le validator devrait
                # avoir rejeté avant qu'on arrive ici, mais on garde un
                # default safe pour ne pas crasher au compile-time.
                return 'Decimal(0)'
            body = transform_decl.get("body", {}) or {}
            if isinstance(body, dict) and "$calculate" in body:
                inner = body["$calculate"]
                if isinstance(inner, dict):
                    # Délègue à la forme dict avec les inputs du transform.
                    return self._compile_calculate_expr_py(inner, entity_class, field_name)
                # Récursion string→string (transform-of-transform) — rare mais
                # supporté par symétrie.
                if isinstance(inner, str):
                    return self._compile_calculate_expr_py(inner, entity_class, field_name)
            return 'Decimal(0)'
        if not isinstance(calc, dict):
            return 'Decimal(0)'
        formula = calc.get("formula")
        if not isinstance(formula, str):
            return 'Decimal(0)'
        inputs_map = calc.get("inputs", {}) if isinstance(calc.get("inputs"), dict) else {}
        try:
            tokens = self._calc_tokenize_py(formula)
            state = {"tokens": tokens, "i": 0}
            ast = self._calc_parse_expr_py(state, in_agg=False)
            if state["i"] < len(tokens):
                return 'Decimal(0)'
        except ValueError:
            return 'Decimal(0)'
        self._service_uses_decimal = True
        ctx = {
            "inputs_map": inputs_map,
            "agg_var": None,
            "agg_collection_root": None,
            "entity_class": entity_class,
            "field_name": field_name,
        }
        return self._calc_emit_py(ast, ctx)

    def _calc_tokenize_py(self, formula: str) -> list:
        """Same tokenizer the validator uses — see acir_validator._tokenize_calculate."""
        tokens = []
        i, n = 0, len(formula)
        while i < n:
            c = formula[i]
            if c.isspace():
                i += 1
                continue
            if c.isdigit() or (c == '-' and (not tokens or tokens[-1][0] in {"OP", "LPAREN"})
                               and i + 1 < n and formula[i + 1].isdigit()):
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
            if c.isalpha() or c == '_':
                start = i
                while i < n and (formula[i].isalnum() or formula[i] == '_'):
                    i += 1
                tokens.append(("IDENT", formula[start:i], start))
                continue
            if c == '.':
                tokens.append(("DOT", ".", i)); i += 1; continue
            if c == '(':
                tokens.append(("LPAREN", "(", i)); i += 1; continue
            if c == ')':
                tokens.append(("RPAREN", ")", i)); i += 1; continue
            if c == '*':
                if tokens and tokens[-1][0] == "DOT":
                    tokens.append(("WILDCARD_STAR", "*", i))
                else:
                    tokens.append(("OP", "*", i))
                i += 1
                continue
            if c in "+-/%":
                tokens.append(("OP", c, i)); i += 1; continue
            raise ValueError(f"caractère inattendu `{c}` à la position {i}")
        return tokens

    def _calc_peek_py(self, state):
        return state["tokens"][state["i"]] if state["i"] < len(state["tokens"]) else None

    def _calc_consume_py(self, state):
        t = state["tokens"][state["i"]]; state["i"] += 1; return t

    def _calc_parse_expr_py(self, state, in_agg: bool):
        left = self._calc_parse_term_py(state, in_agg)
        while True:
            tok = self._calc_peek_py(state)
            if tok is None or tok[0] != "OP" or tok[1] not in ("+", "-"):
                break
            op = self._calc_consume_py(state)[1]
            right = self._calc_parse_term_py(state, in_agg)
            left = {"kind": "bin", "op": op, "left": left, "right": right}
        return left

    def _calc_parse_term_py(self, state, in_agg: bool):
        left = self._calc_parse_factor_py(state, in_agg)
        while True:
            tok = self._calc_peek_py(state)
            if tok is None or tok[0] != "OP" or tok[1] not in ("*", "/", "%"):
                break
            op = self._calc_consume_py(state)[1]
            right = self._calc_parse_factor_py(state, in_agg)
            left = {"kind": "bin", "op": op, "left": left, "right": right}
        return left

    def _calc_parse_factor_py(self, state, in_agg: bool):
        tok = self._calc_peek_py(state)
        if tok is None:
            raise ValueError("expression attendue mais fin de formule")
        ttype, tval, pos = tok
        if ttype == "OP" and tval == "-":
            self._calc_consume_py(state)
            inner = self._calc_parse_factor_py(state, in_agg)
            return {"kind": "neg", "inner": inner}
        if ttype == "LPAREN":
            self._calc_consume_py(state)
            inner = self._calc_parse_expr_py(state, in_agg)
            close = self._calc_peek_py(state)
            if close is None or close[0] != "RPAREN":
                raise ValueError(f"`)` attendu à la position {pos}")
            self._calc_consume_py(state)
            return inner
        if ttype == "NUMBER":
            self._calc_consume_py(state)
            return {"kind": "num", "value": tval}
        if ttype == "IDENT":
            next_tok = state["tokens"][state["i"] + 1] if state["i"] + 1 < len(state["tokens"]) else None
            if tval in self._CALC_AGG_NAMES_PY and next_tok is not None and next_tok[0] == "LPAREN":
                self._calc_consume_py(state)
                self._calc_consume_py(state)
                inner = self._calc_parse_expr_py(state, in_agg=True)
                close = self._calc_peek_py(state)
                if close is None or close[0] != "RPAREN":
                    raise ValueError(f"`)` attendu pour fermer {tval}(...)")
                self._calc_consume_py(state)
                return {"kind": "agg", "name": tval, "inner": inner}
            self._calc_consume_py(state)
            segments = [tval]
            while True:
                nxt = self._calc_peek_py(state)
                if nxt is None or nxt[0] != "DOT":
                    break
                self._calc_consume_py(state)
                seg = self._calc_peek_py(state)
                if seg is None:
                    raise ValueError(f"segment de path attendu après `.` à la position {pos}")
                if seg[0] == "WILDCARD_STAR":
                    self._calc_consume_py(state)
                    segments.append("*")
                elif seg[0] == "IDENT":
                    self._calc_consume_py(state)
                    segments.append(seg[1])
                else:
                    break
            return {"kind": "path", "segments": segments}
        raise ValueError(f"token inattendu `{tval}` à la position {pos}")

    def _calc_collect_collection_root_py(self, node):
        if not isinstance(node, dict):
            return None
        kind = node.get("kind")
        if kind == "path":
            segs = node.get("segments", [])
            return segs[0] if segs else None
        if kind == "bin":
            return (self._calc_collect_collection_root_py(node["left"])
                    or self._calc_collect_collection_root_py(node["right"]))
        if kind == "neg":
            return self._calc_collect_collection_root_py(node["inner"])
        return None

    def _calc_resolve_root_to_py(self, root: str, ctx: dict) -> str:
        """Resolve a path's root identifier to a Python expression.
        - If `root` is in `inputs`, compile that DataExpr (typically {$input: ...}).
        - Else fall back to `data.get(root)` (assume input dict).
        """
        inputs_map = ctx.get("inputs_map") or {}
        if root in inputs_map:
            return self._compile_data_expr_py(inputs_map[root], ctx["entity_class"], ctx["field_name"])
        return f"data.get({root!r})"

    def _calc_emit_path_py(self, node, ctx: dict) -> str:
        # Inline `# TODO` comments break Python when the expression sits in a dict
        # value or function arg — emit bare None/Decimal(0) for the error cases.
        segments = node.get("segments", [])
        if not segments:
            return "None"
        if ctx.get("agg_var") and segments[0] == ctx.get("agg_collection_root"):
            tail = [s for s in segments[1:] if s != "*"]
            if not tail:
                return ctx["agg_var"]
            return f"{ctx['agg_var']}." + ".".join(to_snake(s) for s in tail)
        if "*" in segments:
            return "None"
        base = self._calc_resolve_root_to_py(segments[0], ctx)
        if len(segments) == 1:
            return base
        return base + "." + ".".join(to_snake(s) for s in segments[1:])

    def _calc_emit_py(self, node, ctx: dict) -> str:
        kind = node.get("kind")
        if kind == "num":
            return f'Decimal("{node["value"]}")'
        if kind == "path":
            return self._calc_emit_path_py(node, ctx)
        if kind == "neg":
            return f'(-({self._calc_emit_py(node["inner"], ctx)}))'
        if kind == "bin":
            op = node["op"]
            l = self._calc_emit_py(node["left"], ctx)
            r = self._calc_emit_py(node["right"], ctx)
            if op in ("+", "-", "*", "/", "%"):
                return f'(({l}) {op} ({r}))'
            return "None"
        if kind == "agg":
            return self._calc_emit_agg_py(node, ctx)
        return "None"

    def _calc_emit_agg_py(self, node, ctx: dict) -> str:
        name = node["name"]
        inner = node["inner"]
        coll_root = self._calc_collect_collection_root_py(inner)
        if not coll_root:
            return 'Decimal(0)'
        inputs_map = ctx.get("inputs_map") or {}
        if coll_root in inputs_map:
            coll_expr = self._compile_data_expr_py(inputs_map[coll_root], ctx["entity_class"], ctx["field_name"])
        else:
            coll_expr = f"(data.get({coll_root!r}) or [])"
        agg_ctx = dict(ctx)
        agg_ctx["agg_var"] = "_x"
        agg_ctx["agg_collection_root"] = coll_root
        if name == "count":
            return f"Decimal(len({coll_expr}))"
        inner_py = self._calc_emit_py(inner, agg_ctx)
        # Generator expression — Python sum() accepts a 2nd arg as start value, so
        # `sum(gen, Decimal(0))` keeps the result type as Decimal even when empty.
        gen = f"({inner_py} for _x in {coll_expr})"
        if name == "sum":
            return f"sum({gen}, Decimal(0))"
        if name == "avg":
            # Materialise once so we can divide by len safely (avoids TypeError on empty).
            return (f"(sum({gen}, Decimal(0)) / Decimal(len({coll_expr})) "
                    f"if {coll_expr} else Decimal(0))")
        if name == "min":
            return f"min({gen}, default=Decimal(0))"
        if name == "max":
            return f"max({gen}, default=Decimal(0))"
        return 'Decimal(0)'

    def _resolve_step_ref_py(self, ref) -> str:
        """`{$step: "createOrg.id"}` → `create_org.id` (look up step var by name)."""
        if isinstance(ref, dict):
            if "$step" in ref:
                ref = ref["$step"]
            elif "$input" in ref:
                return f"data.get({ref['$input']!r})"
            else:
                return "None"
        if isinstance(ref, str):
            parts = ref.split(".", 1)
            head = parts[0]
            if head in self._sequence_step_vars:
                var = self._sequence_step_vars[head]["var"]
                if len(parts) == 2:
                    return f"{var}.{to_snake(parts[1])}"
                return var
            # Q-FUNC net (#ccedb312) — étape inconnue : NE JAMAIS émettre un
            # identifiant nu (ex. `fetchProductPriceHt`) → symbole non déclaré →
            # build cassé. On émet `None` (compilable en contexte valeur). Ce cas
            # devrait être attrapé en amont par le validateur (STEP_REF_UNRESOLVED) ;
            # ceci est la défense en profondeur. (Python n'a pas de commentaire
            # inline expression-safe, d'où le `None` nu.)
            return "None"
        return "None"

    def _is_user_like(self, entity_class: str) -> bool:
        record = self.type_registry.get(entity_class, {})
        field_names = {f.get("name") for f in record.get("fields", [])}
        return ("email" in field_names or "username" in field_names) and (
            "role" in field_names or "password_hash" in field_names
        )

    def _pick_user_like_var(self, vars_by_type: dict):
        """Return (var_name, type_name) for a step var that looks like a user record."""
        for type_name, var_name in vars_by_type.items():
            if self._is_user_like(type_name):
                return var_name, type_name
        return None, None

    def _synthesize_response_dto_py(self, dto_name: str, vars_by_type: dict, indent: str = "        ") -> list:
        """Build a list of Python lines that instantiate `dto_name` from available step vars.

        Strategy (same as Quarkus _synthesize_response_dto):
          1. For each field in the DTO:
             - If field type $ref matches a known step var entity → assign that var
             - If field name matches a token-shape pattern AND a user-like var is in scope
               → emit `issue_token(user_var.email, user_var.role.value)` (sets _service_uses_auth)
             - If field is TTL-shape → `TOKEN_TTL_SECONDS`
             - Else → None
          2. Construct the DTO with keyword args from those values
          3. Return [<line>, <line>, …] so the caller can join with the surrounding code
        """
        record = self.type_registry.get(dto_name, {})
        fields = record.get("fields", [])
        if not fields:
            return [f"{indent}return {dto_name}()  # TODO: empty DTO body"]
        user_var, _ = self._pick_user_like_var(vars_by_type)
        kwargs = []
        for f in fields:
            fname = f.get("name", "")
            ftype = f.get("type", {})
            normalized = fname.lower().replace("_", "")
            ref = ftype.get("$ref", "") if isinstance(ftype, dict) else ""
            value_expr = None
            if ref and ref in vars_by_type:
                value_expr = vars_by_type[ref]
            elif user_var and any(normalized == p for p in self._TOKEN_FIELD_PATTERNS + self._REFRESH_FIELD_PATTERNS):
                # F-role-case : on lowercase le role dans le JWT pour matcher la
                # convention ACIR auth.roles (lowercase). Sans ça, le JWT contient
                # `groups: ["CUSTOMER"]` (enum value uppercase) mais `require_role("customer")`
                # côté route → 403 sur tout endpoint authentifié.
                # Fix A2 — role-safe : si l'entité utilisateur n'a pas de
                # champ `role`, retomber sur "user" (défaut) AU LIEU de
                # `user.role` → AttributeError au runtime. TODO: modéliser
                # `role` sur l'entité pour un vrai RBAC.
                # F-RUNTIME-BRIEF4-UUID-SUB — passer `subject=str(user.id)` pour
                # que le JWT `sub` soit l'UUID de l'utilisateur (pas son email).
                # Sans ça, `\\$auth: user_id` dans le service résout en email
                # (le sub), qui est passé en colonne UUID Postgres -> crash
                # InvalidTextRepresentation. Cf. parité PR #141 pour pattern
                # env-var. `upn` reste l'email (display/login name).
                value_expr = (
                    f"issue_token({user_var}.email, "
                    f"str((lambda _r=getattr({user_var}, 'role', None): "
                    f"(_r.value if hasattr(_r, 'value') else _r) if _r is not None else 'user')()"
                    f" or 'user').lower(), subject=str({user_var}.id))"
                )
                self._service_uses_auth = True
            elif user_var and any(normalized == p for p in self._TTL_FIELD_PATTERNS):
                value_expr = "TOKEN_TTL_SECONDS"
                self._service_uses_auth = True
            else:
                value_expr = "None"
            # Map back to Python identifier if field is a Python keyword (cf. F6).
            import keyword as _keyword
            py_name = f"{fname}_" if _keyword.iskeyword(fname) or fname in {"from", "import", "global", "return", "class", "type"} else fname
            kwargs.append(f"{py_name}={value_expr}")
        return [f"{indent}return {dto_name}({', '.join(kwargs)})"]

    def _compile_create_step_py(self, op: dict, step_name: str, indent: str = "        ") -> tuple:
        """Compile an IO_MUTATE-create step inside a sequence. Returns (lines, var_name, entity_class)."""
        entity_acir = op.get("entity", "")
        entity_class = self._entity_class_from_acir_name(entity_acir)
        var_name = to_snake(step_name) if step_name else (entity_class[0].lower() + entity_class[1:])
        # Fix A2 — entité FANTÔME : le LLM modélise souvent l'émission de jeton
        # comme un IO_MUTATE create sur une table `tokens` jamais déclarée.
        # `entity_class` pointe alors sur une classe inexistante → NameError,
        # et `var_name` ("issue_token") SHADOW le helper JWT. Le jeton est
        # stateless (JWT) : on n'émet AUCUNE écriture ni binding (pas de
        # shadow), le token est produit par issue_token() dans la réponse.
        _real_models = {n for n, r in self.type_registry.items() if r.get("identity")}
        if entity_class not in _real_models:
            return (
                [f"{indent}# ACIR a modélisé un create sur '{entity_acir}' (entité non "
                 f"déclarée) — jeton géré en JWT stateless via issue_token(); pas de table."],
                None, entity_class,
            )
        data = op.get("data", {}) or {}
        # Build kwargs from each data entry; data is dict {field: expr}.
        # We use **kwargs construction so we can mix literals and computed exprs cleanly.
        kv_pairs = []
        for k, v in data.items():
            kv_pairs.append(f"{k}={self._compile_data_expr_py(v, entity_class, k)}")
        kv_str = ", ".join(kv_pairs)
        lines = [
            f"{indent}{var_name} = {entity_class}({kv_str})",
            f"{indent}self.db.add({var_name})",
            f"{indent}self.db.flush()  # assigns PK without committing — needed by $step refs",
        ]
        return lines, var_name, entity_class

    def _compile_update_step_py(self, op: dict, step_name: str, indent: str = "        ", unit: dict = None) -> tuple:
        """Compile an IO_MUTATE-update step inside a sequence. Returns (lines, var_name, entity_class).

        Strategy:
          - If a prior step's var matches the same entity → reuse it (no extra query).
          - Else → emit a `.filter(...).first()` lookup based on the step's `filter` clause.
          - Then for each `data: {field: expr}` apply `<var>.<field> = <expr>`.
            Special: `{$increment: N}` → `<var>.<field> = (<var>.<field> or 0) + N`.
          - Special: `data: {$input: "X"}` (single-key bulk shortcut, emitted by
            Haiku/Sonnet for brief1 updateTask) → resolve the source DTO type
            via `unit.input.$ref` and copy each of its fields with null guards.
            Without this, the field loop sees `field="$input"` → emits
            `<var>.$input = "X"` which is a Python SyntaxError on import.
        """
        entity_acir = op.get("entity", "")
        entity_class = self._entity_class_from_acir_name(entity_acir)
        data = op.get("data", {}) or {}
        filter_expr = op.get("filter", {}) or {}
        lines: list = []

        # Reuse a prior step var if one exists with the same entity class — this is
        # the common pattern (fetch_article → increment_views on the same Article).
        reused_var = None
        for info in self._sequence_step_vars.values():
            if info["type"] == entity_class:
                reused_var = info["var"]
                break

        if reused_var:
            var_name = reused_var
            # Le query step précédent n'a pas forcément de None-check (e.g. _compile_query_step_py
            # émet `.first()` sans guard). Pour l'update, on a besoin que la var soit non-None,
            # sinon AttributeError sur `<var>.<field>`. Guard explicite.
            lines.append(f"{indent}if {var_name} is None:")
            lines.append(f"{indent}    raise NotFoundError({entity_class!r}, 'sequence target not found')")
        else:
            # Fresh find-by-filter. We emit similar code to _compile_query_step_py but
            # without registering it as a step var (the step's own var below will).
            var_name = to_snake(step_name) if step_name else f"{entity_class[0].lower()}{entity_class[1:]}_target"
            clauses, skipped = self._compile_filter_clauses_py(entity_class, filter_expr)
            clauses_str = ", ".join(clauses) if clauses else "True"
            if skipped:
                lines.append(f"{indent}# TODO: F-seq-update clauses operator non supporté, skipped: {', '.join(skipped)}")
            lines.append(f"{indent}{var_name} = self.db.query({entity_class}).filter({clauses_str}).first()")
            lines.append(f"{indent}if {var_name} is None:")
            lines.append(f"{indent}    raise NotFoundError({entity_class!r}, 'sequence target not found')")

        # Bulk-data shortcut : `data: {$input: "X"}` (single $input/$param key) →
        # the whole payload comes from the request body field `X` (typically a
        # nested DTO like TaskUpdateInput). Without special-casing, the loop
        # below sees field="$input" → emits `<var>.$input = "X"` (Python
        # SyntaxError). We resolve the source DTO via unit.input.fields[X].type
        # and copy each of its fields with `if <key> in inner: setattr(...)`.
        bulk_input_key = None
        if isinstance(data, dict) and len(data) == 1:
            only_key = next(iter(data.keys()))
            if only_key in ("$input", "$param"):
                bulk_input_key = data[only_key]
        if bulk_input_key is not None:
            source_type_name = None
            unit_input = (unit or {}).get("input", {}) if isinstance(unit, dict) else {}
            if isinstance(unit_input, dict) and "$ref" in unit_input:
                input_record = self.type_registry.get(unit_input["$ref"], {})
                for f in input_record.get("fields", []) or []:
                    if f.get("name") == bulk_input_key:
                        ftype = f.get("type", {})
                        if isinstance(ftype, dict) and "$ref" in ftype:
                            source_type_name = ftype["$ref"]
                        break
            if source_type_name and source_type_name in self.type_registry:
                # PATCH semantics — only set fields the client actually sent.
                # The route uses `data.model_dump(exclude_unset=True)`, so absent
                # keys are absent from `inner` and we skip them.
                lines.append(f"{indent}inner = data.get({bulk_input_key!r}) or {{}}")
                for f in self.type_registry[source_type_name].get("fields", []) or []:
                    field_n = f.get("name")
                    if not field_n:
                        continue
                    lines.append(f"{indent}if {field_n!r} in inner:")
                    lines.append(f"{indent}    {var_name}.{field_n} = inner[{field_n!r}]")
            else:
                lines.append(
                    f"{indent}# TODO: bulk update via $input {bulk_input_key!r} — source DTO type unknown, "
                    f"add explicit field-by-field data block in the ACIR"
                )
            return lines, var_name, entity_class

        # Fix 1 (parité avec _compile_unit_update_method) — `data:{$merge:[…]}`
        # dans un STEP de séquence. Avant : la boucle générique émettait
        # `<var>.$merge = [...]` → SyntaxError (cf. fixture brief1-gpt4o).
        #   · {$input:"k"}/"" → patch client restreint aux colonnes de l'entité
        #   · {$step:"X"}     → l'étape source EST l'entité courante réutilisée
        #                       (pattern canonique fetch→update) → no-op
        #   · objet littéral  → assignations résolues
        if isinstance(data, dict) and list(data.keys()) == ["$merge"]:
            lines.append(f"{indent}_cols = {{_c.name for _c in {var_name}.__table__.columns}}")
            for operand in (data["$merge"] or []):
                if isinstance(operand, dict) and len(operand) == 1 \
                        and next(iter(operand)) in ("$input", "$param"):
                    sk = operand[next(iter(operand))]
                    src = "data" if sk in ("", None) else f"(data.get({sk!r}) or {{}})"
                    lines.append(f"{indent}for _k, _v in ({src} or {{}}).items():")
                    lines.append(f"{indent}    if _k in _cols:")
                    lines.append(f"{indent}        setattr({var_name}, _k, _v)")
                elif isinstance(operand, dict) and len(operand) == 1 \
                        and next(iter(operand)) == "$step":
                    lines.append(f"{indent}# $merge depuis l'étape {operand['$step']!r} — "
                                 f"déjà l'entité courante ({var_name}), no-op")
                elif isinstance(operand, dict):
                    for f2, e2 in operand.items():
                        if isinstance(e2, dict) and "$increment" in e2:
                            lines.append(f"{indent}{var_name}.{f2} = ({var_name}.{f2} or 0) + {e2['$increment']!r}")
                        else:
                            lines.append(f"{indent}{var_name}.{f2} = {self._compile_data_expr_py(e2, entity_class, f2)}")
                else:
                    lines.append(f"{indent}pass  # TODO: $merge operand non supporté: {operand!r}")
            return lines, var_name, entity_class

        # Field assignments. `$increment: N` is special — it's relative to the current
        # value, so we emit `<var>.<field> = (<var>.<field> or 0) + N` rather than
        # routing through _compile_data_expr_py (which would emit `None` for an unknown
        # $-key and silently break the increment).
        for field, expr in data.items():
            if isinstance(expr, dict) and "$increment" in expr:
                amount = expr["$increment"]
                lines.append(f"{indent}{var_name}.{field} = ({var_name}.{field} or 0) + {amount!r}")
            else:
                rhs = self._compile_data_expr_py(expr, entity_class, field)
                lines.append(f"{indent}{var_name}.{field} = {rhs}")

        return lines, var_name, entity_class

    def _compile_delete_step_py(self, op: dict, step_name: str, indent: str = "        ") -> tuple:
        """Compile an IO_MUTATE-delete step inside a sequence."""
        entity_acir = op.get("entity", "")
        entity_class = self._entity_class_from_acir_name(entity_acir)
        filter_expr = op.get("filter", {}) or {}
        lines: list = []

        reused_var = None
        for info in self._sequence_step_vars.values():
            if info["type"] == entity_class:
                reused_var = info["var"]
                break

        if reused_var:
            var_name = reused_var
        else:
            var_name = to_snake(step_name) if step_name else f"{entity_class[0].lower()}{entity_class[1:]}_target"
            clauses = []
            for fname, spec in filter_expr.items():
                if isinstance(spec, dict) and "value" in spec:
                    if spec.get("operator", "eq") != "eq":
                        continue
                    value_expr = self._compile_data_expr_py(spec["value"], entity_class, fname)
                else:
                    value_expr = self._compile_data_expr_py(spec, entity_class, fname)
                clauses.append(f"{entity_class}.{fname} == {value_expr}")
            clauses_str = ", ".join(clauses) if clauses else "True"
            lines.append(f"{indent}{var_name} = self.db.query({entity_class}).filter({clauses_str}).first()")
            lines.append(f"{indent}if {var_name} is None:")
            lines.append(f"{indent}    raise NotFoundError({entity_class!r}, 'sequence target not found')")

        lines.append(f"{indent}self.db.delete({var_name})")
        return lines, var_name, entity_class

    def _compile_foreach_step_py(self, op: dict, step_name: str, indent: str = "        ") -> str:
        """Compile an F_FOREACH op inside a sequence.

        Emits a Python `for <as> in <items>:` loop. The body operation is compiled
        with the loop scope pushed so `{$loop: "<as>.<field>"}` resolves to
        `<as>.<field>`. Mode `parallel` is accepted but compiles to sequential —
        Python's stdlib has no good drop-in equivalent of `parallelStream()` for
        the typical "iterate + ORM call" pattern, and async would require an
        invasive signature change.
        """
        items_expr = op.get("items", {})
        as_name = op.get("as") or "_item"
        body_op = op.get("do", {})
        mode = op.get("mode", "sequential")
        py_var = to_snake(as_name)
        items_py = self._compile_data_expr_py(items_expr, "", "")
        if items_py in (None, "None"):
            return f"{indent}# TODO: F_FOREACH items expression could not be compiled"

        # Push loop scope before compiling the body op.
        prev_scope = dict(self._current_loop_scope)
        self._current_loop_scope[as_name] = py_var
        try:
            body_lines = self._compile_foreach_body_py(body_op, indent + "    ").split("\n")
        finally:
            self._current_loop_scope = prev_scope

        out = []
        if mode == "parallel":
            out.append(f"{indent}# F_FOREACH mode=parallel — Python emits sequential (no parallelStream equivalent)")
        out.append(f"{indent}for {py_var} in ({items_py} or []):")
        out.extend(body_lines)
        return "\n".join(out)

    def _compile_foreach_body_py(self, body_op, indent: str) -> str:
        """Compile the `do` block of an F_FOREACH. Suppresses any return-style emit
        and works with side-effecting ops (typical case : IO_MUTATE update via $loop
        filter). For now we support IO_MUTATE update/delete and nested F_FOREACH.
        """
        if not isinstance(body_op, dict):
            return f"{indent}# TODO: F_FOREACH body must be an op"
        prim = body_op.get("primitive")
        if prim == "F_FOREACH":
            # Nested loop — same recursion as the top-level step compiler.
            return self._compile_foreach_step_py(body_op, "_nested", indent)
        if prim == "IO_MUTATE":
            action = body_op.get("action", "create")
            entity_acir = body_op.get("entity", "")
            entity_class = self._entity_class_from_acir_name(entity_acir)
            filter_expr = body_op.get("filter", {}) or {}
            data_block = body_op.get("data", {}) or {}
            lines = []
            # `create` has no filter — build + persist a fresh row per iteration
            # ($loop/$input/$generate resolved against the active loop scope).
            # Without this branch the loop body was just a TODO comment →
            # `for … :` with no statement → IndentationError at import.
            if action == "create":
                kvs = []
                for fname, value in data_block.items():
                    expr = self._compile_data_expr_py(value, entity_class, fname)
                    kvs.append(f'"{fname}": {expr}')
                lines.append(f'{indent}_obj = {entity_class}(**{{{", ".join(kvs)}}})')
                lines.append(f"{indent}self.db.add(_obj)")
                lines.append(f"{indent}self.db.flush()")
                return "\n".join(lines)
            # Find clause (always; foreach bodies don't reuse a parent step var).
            clauses = []
            for fname, spec in filter_expr.items():
                if isinstance(spec, dict) and "value" in spec:
                    if spec.get("operator", "eq") != "eq":
                        continue
                    value_expr = self._compile_data_expr_py(spec["value"], entity_class, fname)
                else:
                    value_expr = self._compile_data_expr_py(spec, entity_class, fname)
                clauses.append(f"{entity_class}.{fname} == {value_expr}")
            if not clauses:
                lines.append(f"{indent}# TODO: F_FOREACH inner op has no filter clauses")
                return "\n".join(lines)
            clauses_str = ", ".join(clauses)
            lines.append(f"{indent}_obj = self.db.query({entity_class}).filter({clauses_str}).first()")
            lines.append(f"{indent}if _obj is not None:")
            if action in ("update", "patch"):
                for fname, value in data_block.items():
                    expr = self._compile_data_expr_py(value, entity_class, fname)
                    lines.append(f"{indent}    _obj.{fname} = {expr}")
                lines.append(f"{indent}    self.db.add(_obj)")
            elif action == "delete":
                lines.append(f"{indent}    self.db.delete(_obj)")
            else:
                lines.append(f"{indent}    pass  # TODO: F_FOREACH inner IO_MUTATE action={action!r} not yet supported")
            return "\n".join(lines)
        if prim == "IO_CALL":
            # Fix 2b — IO_CALL synchrone PAR ITÉRATION (ex: "pour chaque ligne,
            # vérifier le stock via StockManagement"). Les valeurs path_params/
            # query/body sont compilées via _compile_data_expr_py → les
            # {$loop:"item.x"} se résolvent dans le scope de boucle courant.
            mod = body_op.get("module", "Service")
            envvar = to_snake(mod).upper() + "_URL"
            http_method = str(body_op.get("method", "GET")).upper()
            endpoint = body_op.get("endpoint", "/")
            propagate = bool(body_op.get("propagate_auth", True))
            timeout = (body_op.get("timeout_ms") or 10000) / 1000.0
            _err_map = {
                "not_found": "NotFoundError", "conflict": "ConflictError",
                "validation_failed": "ValidationError", "internal": "ValidationError",
            }
            _kind = (body_op.get("on_error") or {}).get("kind", "validation_failed")
            _err_cls = "ForbiddenError" if _kind == "unauthorized" else _err_map.get(_kind, "ValidationError")
            _err_call = "ForbiddenError()" if _err_cls == "ForbiddenError" else f"{_err_cls}(msg)"

            def _d(o):
                o = o if isinstance(o, dict) else {}
                return "{" + ", ".join(
                    f"{k!r}: {self._compile_data_expr_py(v, '', k)}" for k, v in o.items()
                ) + "}"

            pp, q, bd = _d(body_op.get("path_params")), _d(body_op.get("query")), _d(body_op.get("body"))
            not_cfg = f"{mod} indisponible : {envvar} non configuré"
            unreach = f"{mod} injoignable"
            bad = f"{mod} a renvoyé une erreur"
            L = [
                f"{indent}import os, httpx",
                f"{indent}_base = (os.environ.get({envvar!r}) or '').rstrip('/')",
                f"{indent}if not _base:",
                f"{indent}    raise ValidationError({not_cfg!r})",
                f"{indent}_pp = {pp}",
                f"{indent}_path = {endpoint!r}.format(**_pp) if _pp else {endpoint!r}",
                f"{indent}_params = {{_k: _v for _k, _v in {q}.items() if _v is not None}}",
                f"{indent}_json = {bd}",
                f"{indent}_headers = {{}}",
                f"{indent}_req = kwargs.get('request')",
                f"{indent}if {propagate} and _req is not None:",
                f"{indent}    _a = _req.headers.get('authorization')",
                f"{indent}    if _a:",
                f"{indent}        _headers['Authorization'] = _a",
                f"{indent}try:",
                f"{indent}    with httpx.Client(timeout={timeout}) as _c:",
                f"{indent}        _r = _c.request({http_method!r}, _base + _path,",
                f"{indent}                         params=_params or None,",
                f"{indent}                         json=(_json or None) if {http_method!r} in ('POST', 'PUT', 'PATCH') else None,",
                f"{indent}                         headers=_headers)",
                f"{indent}except httpx.HTTPError as _e:",
                f"{indent}    msg = {unreach!r} + ': ' + str(_e)",
                f"{indent}    raise {_err_call}",
                f"{indent}if _r.status_code >= 400:",
                f"{indent}    msg = {bad!r} + ' (' + str(_r.status_code) + ')'",
                f"{indent}    raise {_err_call}",
            ]
            return "\n".join(L)
        # Repli 2a — op non supportée en corps de F_FOREACH : émettre `pass`
        # (et PAS un commentaire seul) pour que le Python reste valide/bootable.
        return f"{indent}pass  # TODO: F_FOREACH inner op primitive={prim!r} not yet supported"

    def _compile_unit_update_method(self, method_name: str, body: dict, entity_class: str, unit: dict = None) -> str:
        """Compile a unit-level IO_MUTATE update (e.g. brief 2 publishArticle, brief 4 markOrderPaid).

        Key correctness points vs the historical impl that did `for k,v in data.items(): setattr(obj, k, v)`:
          1. Filter clauses come from ACIR `body.filter`, not hardcoded `id == id`. brief 4
             markOrderPaid has `filter: {id: $input.id, status: "PENDING"}` — the status
             clause is a *transition guard*, mandatory.
          2. Update data comes from ACIR `body.data` (server-side defaults like
             `status: "PUBLISHED"`, `paid_at: $generate(now)`), NOT user-supplied data.
             The old impl let a malicious client set arbitrary fields via `setattr`.
          3. Signature `(self, data=None, **kwargs)` mirrors F_SEQUENCE so the route can
             call with either `data=<scalar>` (publishArticle), `data={"id": ...}`
             (markOrderPaid path-bundled), or `data=<dict from body>`.
          4. Bulk shortcut `data: {$input: "X"}` (single $input/$param key, same shape
             as in _compile_update_step_py) → resolve the source DTO via `unit.input`
             and copy each of its fields with PATCH semantics. Without this, the loop
             below emits `obj.$input = "X"` (Python SyntaxError on import).
        """
        filter_expr = body.get("filter", {}) or {}
        data_block = body.get("data", {}) or {}
        indent = "        "
        lines: list = []

        # Normalize incoming data (route may pass scalar or dict — see F-seq-scalar-input).
        lines.append(f"{indent}if data is None and kwargs:")
        lines.append(f"{indent}    data = next((v for k, v in kwargs.items() if k not in ('current_user', 'request')), None)")

        # Compile filter clauses — tous operators supportés (gap 5). Le status
        # clause d'une transition (`{status: {operator: eq, value: "PENDING"}}`)
        # reste un guard mandatory ; les `gte/lte/in/...` sont maintenant émis.
        clauses, skipped = self._compile_filter_clauses_py(entity_class, filter_expr)
        clauses_str = ", ".join(clauses) if clauses else "True"
        if skipped:
            lines.append(f"{indent}# TODO: F-mutate-update-unit clauses operator non supporté, skipped: {', '.join(skipped)}")
        lines.append(f"{indent}obj = self.db.query({entity_class}).filter({clauses_str}).first()")
        lines.append(f"{indent}if obj is None:")
        lines.append(f"{indent}    raise NotFoundError({entity_class!r}, 'not found or transition guard failed')")

        # Bulk-data shortcut — mirror of the fix in _compile_update_step_py.
        # `data: {$input: "X"}` → copy each field of the source DTO with PATCH
        # semantics. Without it, `obj.$input = "X"` is a Python SyntaxError.
        bulk_input_key = None
        if isinstance(data_block, dict) and len(data_block) == 1:
            only_key = next(iter(data_block.keys()))
            if only_key in ("$input", "$param"):
                bulk_input_key = data_block[only_key]
        if bulk_input_key is not None:
            source_type_name = None
            unit_input = (unit or {}).get("input", {}) if isinstance(unit, dict) else {}
            if isinstance(unit_input, dict) and "$ref" in unit_input:
                input_record = self.type_registry.get(unit_input["$ref"], {})
                for f in input_record.get("fields", []) or []:
                    if f.get("name") == bulk_input_key:
                        ftype = f.get("type", {})
                        if isinstance(ftype, dict) and "$ref" in ftype:
                            source_type_name = ftype["$ref"]
                        break
            if source_type_name and source_type_name in self.type_registry:
                lines.append(f"{indent}inner = data.get({bulk_input_key!r}) or {{}}")
                for f in self.type_registry[source_type_name].get("fields", []) or []:
                    field_n = f.get("name")
                    if not field_n:
                        continue
                    lines.append(f"{indent}if {field_n!r} in inner:")
                    lines.append(f"{indent}    obj.{field_n} = inner[{field_n!r}]")
            else:
                lines.append(
                    f"{indent}# TODO: bulk update via $input {bulk_input_key!r} — source DTO type unknown"
                )
        elif isinstance(data_block, dict) and list(data_block.keys()) == ["$merge"]:
            # Fix 1 — `data: {$merge:[<op>...]}` (patch canonique). On déplie
            # chaque opérande. AVANT : la boucle générique émettait
            # `obj.$merge = [...]` → SyntaxError Python à l'import.
            #   · {$input:"k"} (ou "")  → applique le patch client, restreint
            #     aux colonnes de l'entité (PATCH sûr, pas de setattr arbitraire).
            #   · objet littéral {champ: expr} → assignations résolues.
            lines.append(f"{indent}_cols = {{_c.name for _c in obj.__table__.columns}}")
            for operand in (data_block["$merge"] or []):
                if isinstance(operand, dict) and len(operand) == 1 \
                        and next(iter(operand)) in ("$input", "$param"):
                    src_key = operand[next(iter(operand))]
                    src = "data" if src_key in ("", None) else f"(data.get({src_key!r}) or {{}})"
                    lines.append(f"{indent}for _k, _v in ({src} or {{}}).items():")
                    lines.append(f"{indent}    if _k in _cols:")
                    lines.append(f"{indent}        setattr(obj, _k, _v)")
                elif isinstance(operand, dict):
                    for field, expr in operand.items():
                        if isinstance(expr, dict) and "$increment" in expr:
                            lines.append(f"{indent}obj.{field} = (obj.{field} or 0) + {expr['$increment']!r}")
                        else:
                            rhs = self._compile_data_expr_py(expr, entity_class, field)
                            lines.append(f"{indent}obj.{field} = {rhs}")
                else:
                    lines.append(f"{indent}pass  # TODO: $merge operand non supporté: {operand!r}")
            lines.append(f"{indent}self.db.add(obj)")
        else:
            # Apply ACIR-defined data. `$increment` is inline-compiled (relative); everything
            # else goes through _compile_data_expr_py.
            for field, expr in data_block.items():
                if isinstance(expr, dict) and "$increment" in expr:
                    amount = expr["$increment"]
                    lines.append(f"{indent}obj.{field} = (obj.{field} or 0) + {amount!r}")
                else:
                    rhs = self._compile_data_expr_py(expr, entity_class, field)
                    lines.append(f"{indent}obj.{field} = {rhs}")

        lines.append(f"{indent}try:")
        lines.append(f"{indent}    self.db.commit()")
        lines.append(f"{indent}    self.db.refresh(obj)")
        lines.append(f"{indent}except IntegrityError as e:")
        lines.append(f"{indent}    self.db.rollback()")
        lines.append(f"{indent}    raise ConflictError({entity_class!r} + ' conflit de données: ' + str(e)) from e")
        lines.append(f"{indent}return obj")

        body_str = "\n".join(lines)
        return f"""
    def {method_name}(self, data=None, **kwargs) -> {entity_class}:
        \"\"\"Update an existing {entity_class} via ACIR-defined filter + data (server-side defaults).\"\"\"
{body_str}
"""

    def _compile_unit_delete_method(self, method_name: str, body: dict, entity_class: str) -> str:
        """Compile a unit-level IO_MUTATE delete with ACIR-driven filter (same shape as update)."""
        filter_expr = body.get("filter", {}) or {}
        indent = "        "
        lines: list = []

        lines.append(f"{indent}if data is None and kwargs:")
        lines.append(f"{indent}    data = next((v for k, v in kwargs.items() if k not in ('current_user', 'request')), None)")

        clauses, skipped = self._compile_filter_clauses_py(entity_class, filter_expr)
        # Pas de filter ACIR explicite → fallback historique sur `id == data` (scalar).
        if not clauses:
            clauses.append(f"{entity_class}.id == data")
        clauses_str = ", ".join(clauses)
        if skipped:
            lines.append(f"{indent}# TODO: F-mutate-delete-unit clauses operator non supporté, skipped: {', '.join(skipped)}")
        lines.append(f"{indent}obj = self.db.query({entity_class}).filter({clauses_str}).first()")
        lines.append(f"{indent}if obj is None:")
        lines.append(f"{indent}    raise NotFoundError({entity_class!r}, 'not found')")
        lines.append(f"{indent}self.db.delete(obj)")
        lines.append(f"{indent}self.db.commit()")

        body_str = "\n".join(lines)
        return f"""
    def {method_name}(self, data=None, **kwargs) -> None:
        \"\"\"Delete a {entity_class} via ACIR-defined filter.\"\"\"
{body_str}
"""

    def _compile_query_step_py(self, op: dict, step_name: str, indent: str = "        ") -> tuple:
        """Compile an IO_QUERY step inside a sequence (find-by-predicate). Returns (lines, var_name, entity_class)."""
        entity_acir = op.get("entity", "")
        entity_class = self._entity_class_from_acir_name(entity_acir)
        var_name = to_snake(step_name) if step_name else f"{entity_class[0].lower()}{entity_class[1:]}_result"
        filter_expr = op.get("filter", {}) or {}
        # Sprint D gap 5 — tous operators supportés (eq/ne/gt/gte/lt/lte/in/
        # not_in/like/ilike/contains/range). Avant : seul eq, le reste skippé
        # (brief4 validateStock `id in items.*.product_id` cassé).
        clauses, skipped = self._compile_filter_clauses_py(entity_class, filter_expr)
        clauses_str = ", ".join(clauses) if clauses else "True"
        lines = []
        if skipped:
            lines.append(f"{indent}# TODO: F-query clauses operator non supporté, skipped: {', '.join(skipped)}")
        lines.append(f"{indent}{var_name} = self.db.query({entity_class}).filter({clauses_str}).first()")
        return lines, var_name, entity_class

    def _compile_query_filter_method(self, method_name: str, unit: dict, body: dict,
                                      entity_class: str, input_name: str) -> str:
        """Compile IO_QUERY with `{$input: ...}` filter (login-by-credentials / find-by-predicate).

        Two output cases:
          1. Output is the queried entity → emit `.filter(...).first()` and return it.
          2. Output is a composite DTO (e.g. AuthResponse) AND the entity is user-like
             AND input has a `password` field → emit find user + verify_password + synth.
        """
        unit_output = unit.get("output", {})
        unit_output_ref = unit_output.get("$ref") if isinstance(unit_output, dict) else None
        filter_expr = body.get("filter", {}) or {}

        # Reset step vars (we'll register our local find as a step so `_synthesize_response_dto_py`
        # can find the user).
        self._sequence_step_vars = {}
        indent = "        "
        lines: list = []

        # Build the filter predicate (only fields referencing $input — skip "password"
        # which becomes a separate verify_password call, not a SQL filter).
        clauses = []
        password_input_key = None
        for fname, spec in filter_expr.items():
            value = spec.get("value", spec) if isinstance(spec, dict) else spec
            if isinstance(value, dict) and "$input" in value and fname in ("password", "password_hash"):
                password_input_key = value["$input"]
                continue
            value_expr = self._compile_data_expr_py(value, entity_class, fname)
            clauses.append(f"{entity_class}.{fname} == {value_expr}")
        clauses_str = ", ".join(clauses) if clauses else "True"

        var_name = "user" if self._is_user_like(entity_class) else (entity_class[0].lower() + entity_class[1:])
        lines.append(f"{indent}{var_name} = self.db.query({entity_class}).filter({clauses_str}).first()")
        # Track for synth_response_dto
        self._sequence_step_vars["find"] = {"var": var_name, "type": entity_class}

        # If the queried entity has password_hash and there's a password field in the input,
        # verify it. If verify fails → return None (route will translate to 401 via response_model).
        # Brief 3 uses `{password: {$input: "password"}}` in the filter directly; we extracted
        # that above as password_input_key. Some briefs put the password check at a separate step.
        entity_record = self.type_registry.get(entity_class, {})
        entity_fields = {f.get("name") for f in entity_record.get("fields", [])}
        if password_input_key is None and "password_hash" in entity_fields:
            # Best-effort: look in the input DTO for a `password` field name
            input_record = self.type_registry.get(input_name, {})
            input_fields = {f.get("name") for f in input_record.get("fields", [])}
            for candidate in ("password", "owner_password"):
                if candidate in input_fields:
                    password_input_key = candidate
                    break
        if password_input_key and "password_hash" in entity_fields:
            self._service_uses_auth = True
            lines.append(f"{indent}if {var_name} is None or not _verify_password(data.get({password_input_key!r}, ''), {var_name}.password_hash):")
            # F-LOGIN-401 — pattern login (password verify) → UnauthorizedError (HTTP 401)
            # vs NotFoundError (HTTP 404) qui était sémantiquement incorrect : login KO
            # = identifiants invalides, pas ressource introuvable. Message générique pour
            # éviter de divulguer si l'email existe (security best-practice).
            lines.append(f"{indent}    raise UnauthorizedError('Identifiants invalides')")
        else:
            lines.append(f"{indent}if {var_name} is None:")
            lines.append(f"{indent}    raise NotFoundError({entity_class!r}, 'not found')")

        # Branch: output is the entity itself, or a composite DTO.
        if unit_output_ref and unit_output_ref == entity_class:
            lines.append(f"{indent}return {var_name}")
            return_anno = entity_class
        elif unit_output_ref and unit_output_ref in self.type_registry:
            vars_by_type = {entity_class: var_name}
            lines.extend(self._synthesize_response_dto_py(unit_output_ref, vars_by_type, indent))
            return_anno = unit_output_ref
        else:
            lines.append(f"{indent}return {var_name}")
            return_anno = entity_class

        body_str = "\n".join(lines)
        # F-RUNTIME-4 fix — accepter **kwargs pour absorber `current_user`/`request`
        # passés par la route (parité avec les autres patterns service). Sans ça,
        # `TypeError: login() got unexpected keyword argument 'current_user'` -> 500.
        return f"""
    def {method_name}(self, data: dict = None, **kwargs) -> {return_anno}:
        \"\"\"Find {entity_class} by predicate (F-query — login / find-by-credentials).\"\"\"
        data = data or {{}}
{body_str}
"""

    def _compile_sequence_method(self, method_name: str, unit: dict, body: dict) -> str:
        """Compile an F_SEQUENCE unit body into a Python service method.

        Implements the equivalent of Quarkus _compile_operation F_SEQUENCE branch
        (compilers/acir_compiler_quarkus.py:1717-1963). Each step contributes one or
        more lines + registers its output variable in self._sequence_step_vars so
        subsequent steps can resolve `{$step: "name.field"}` references.

        Output strategy at end of sequence:
          - If unit declares a record DTO that doesn't match any single step var's type
            (e.g. signup → AuthResponse), use _synthesize_response_dto_py.
          - Else, return the last query/mutate variable that matches the declared output.
          - Else, return None (Pydantic response_model will validate Optional / fail).
        """
        steps = body.get("steps", []) or []
        atomic = body.get("atomic", False)
        unit_output = unit.get("output", {})
        unit_output_ref = unit_output.get("$ref") if isinstance(unit_output, dict) else None
        is_void = isinstance(unit_output, dict) and unit_output.get("kind") == "void"

        # Reset per-sequence bookkeeping so a previous unit's step vars don't leak.
        self._sequence_step_vars = {}
        last_var = None
        indent = "        "
        body_lines: list = []

        for step in steps:
            if not isinstance(step, dict):
                continue
            step_name = step.get("name", "step")
            op = step.get("op", {}) or {}
            op_prim = op.get("primitive", "")
            if op_prim == "IO_MUTATE" and op.get("action", "create") == "create":
                lines, var_name, ent_class = self._compile_create_step_py(op, step_name, indent)
                body_lines.extend(lines)
                # var_name is None pour un create "fantôme" (entité non
                # déclarée, ex: jeton stateless) — ne pas l'enregistrer
                # (sinon refresh(None) / vars_by_type pollué).
                if var_name is not None:
                    self._sequence_step_vars[step_name] = {"var": var_name, "type": ent_class}
                    last_var = var_name
            elif op_prim == "IO_QUERY":
                lines, var_name, ent_class = self._compile_query_step_py(op, step_name, indent)
                body_lines.extend(lines)
                self._sequence_step_vars[step_name] = {"var": var_name, "type": ent_class}
                last_var = var_name
            elif op_prim == "IO_MUTATE" and op.get("action") in ("update", "patch"):
                # F-seq-update : modifie une entité existante (ré-utilise une var de step
                # précédent si même entité, sinon find-by-filter). Brief 2 `incrementViews`
                # est le cas canonique. `unit` est forwardé pour le bulk-data shortcut
                # `data: {$input: "X"}` (cf. _compile_update_step_py).
                lines, var_name, ent_class = self._compile_update_step_py(op, step_name, indent, unit=unit)
                body_lines.extend(lines)
                # Ne pas écraser un step var existant — l'update réutilise la var,
                # n'en crée pas une nouvelle. Mais si c'est un find frais, on l'enregistre.
                if step_name not in self._sequence_step_vars:
                    self._sequence_step_vars[step_name] = {"var": var_name, "type": ent_class}
                last_var = var_name
            elif op_prim == "IO_MUTATE" and op.get("action") == "delete":
                lines, var_name, ent_class = self._compile_delete_step_py(op, step_name, indent)
                body_lines.extend(lines)
                # Une fois supprimée, on ne référence plus la var.
                last_var = None
            elif op_prim == "F_GUARD":
                # Sprint D gap 2 — supporte 3 shapes de condition :
                # (a) v0.3 predicate ($eq/$verify/$and/…) via _compile_predicate_py
                # (b) F_BRANCH legacy avec `{$context, operator, value}` inner +
                #     then/else booléens ou IO_QUERY `exists:true`
                # (c) legacy direct `{$context, operator, value}` sans wrap
                # Avant : seul (a) marchait, (b) et (c) émettaient un TODO et la
                # guard était bypassée → brief2 updateArticle + brief4 transitions
                # pending→paid n'appliquaient pas leurs guards.
                condition = op.get("condition", {})
                on_fail = op.get("on_fail") or op.get("error") or {}
                message = on_fail.get("message") or on_fail.get("error") or "Guard condition failed"
                # Map on_fail.kind → the matching error class *with the
                # constructor signature it actually has* (errors.py):
                # ForbiddenError() takes NO message (was crashing every guard
                # with `__init__() takes 1 positional argument but 2 given`),
                # and validation_failed must surface as 422 not 403.
                kind = (on_fail.get("kind") or "validation_failed").lower()
                if kind == "conflict":
                    raise_expr = f"ConflictError({message!r})"
                elif kind == "not_found":
                    raise_expr = f"NotFoundError({message!r})"
                elif kind in ("forbidden", "unauthorized"):
                    raise_expr = "ForbiddenError()"
                else:  # validation_failed / internal / default → 422
                    raise_expr = f"ValidationError({message!r})"
                cond_expr = self._compile_guard_condition_py(condition)
                if cond_expr is not None:
                    body_lines.append(f"{indent}if not ({cond_expr}):")
                    body_lines.append(f"{indent}    raise {raise_expr}")
                else:
                    body_lines.append(
                        f"{indent}# TODO: F_SEQUENCE step '{step_name}' F_GUARD condition shape "
                        f"not recognized (v0.3 predicate / F_BRANCH legacy / direct legacy expected)"
                    )
            elif op_prim == "F_FOREACH":
                # v0.3 — iterate a collection inside the sequence. Sets up $loop scope
                # before compiling the body so `{$loop: "<as>.<field>"}` refs resolve.
                body_lines.extend(
                    self._compile_foreach_step_py(op, step_name, indent).split("\n")
                )
            else:
                # F_FOREACH etc. — not yet implemented. Emit a comment so the file
                # still parses; subsequent steps' $step refs will fall through to
                # the snake_case fallback.
                body_lines.append(
                    f"{indent}# TODO: F_SEQUENCE step '{step_name}' primitive={op_prim!r} action={op.get('action')!r} not implemented"
                )

        # Commit at the end (atomic flag or not — we always commit so signup actually
        # persists). If a downstream step fails, SQLAlchemy will rollback at session close.
        if body_lines:
            body_lines.append(f"{indent}try:")
            body_lines.append(f"{indent}    self.db.commit()")
            body_lines.append(f"{indent}except IntegrityError as e:")
            body_lines.append(f"{indent}    self.db.rollback()")
            body_lines.append(f"{indent}    raise ConflictError('Sequence commit failed: ' + str(e)) from e")
            # Refresh each created entity so PK/auto-fields are populated for the synth DTO.
            for info in self._sequence_step_vars.values():
                if info.get("var"):
                    body_lines.append(f"{indent}self.db.refresh({info['var']})")

        # Build return expression
        if is_void:
            body_lines.append(f"{indent}return None")
        elif unit_output_ref and unit_output_ref in self._entity_class_names():
            # Output is a single entity — return the matching step var, fallback to last
            ret_var = last_var
            for info in self._sequence_step_vars.values():
                if info["type"] == unit_output_ref:
                    ret_var = info["var"]
                    break
            if ret_var:
                body_lines.append(f"{indent}return {ret_var}")
            else:
                body_lines.append(f"{indent}return None")
        elif unit_output_ref and unit_output_ref in self.type_registry:
            # Output is a composite DTO — synthesize from step vars
            vars_by_type = {info["type"]: info["var"] for info in self._sequence_step_vars.values()}
            body_lines.extend(self._synthesize_response_dto_py(unit_output_ref, vars_by_type, indent))
        else:
            body_lines.append(f"{indent}return None")

        # Pick return type annotation
        if is_void:
            return_anno = "None"
        elif unit_output_ref and unit_output_ref in self._entity_class_names():
            return_anno = unit_output_ref
        elif unit_output_ref and unit_output_ref in self.type_registry:
            return_anno = unit_output_ref  # DTO class
        else:
            return_anno = "Optional[dict]"

        atomic_doc = " (atomic transaction)" if atomic else ""
        body_str = "\n".join(body_lines) if body_lines else f"{indent}pass"
        # Signature flexible : la route appelle soit `service.X(data=...)` (POST/PUT body),
        # soit `service.X(id=<path_param>)` pour les units à input scalaire (e.g. brief 2
        # `getArticleBySlug` — GET /articles/{slug}). On normalise `data` au début pour
        # que `{$input: ""}` → `data` fonctionne dans les deux cas.
        return f"""
    def {method_name}(self, data=None, **kwargs){' -> ' + return_anno if return_anno else ''}:
        \"\"\"Execute sequence{atomic_doc}. F_SEQUENCE compiled to multi-step ORM calls.\"\"\"
        if data is None and kwargs:
            # Route called with `id=<path_param>` or similar — use the first kwarg value
            # as the scalar `data` for {{$input: ""}} resolution.
            data = next((v for k, v in kwargs.items() if k not in ('current_user', 'request')), None)
{body_str}
"""

    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _io_call_value_py(expr) -> str:
        """DataExpr → expression Python (contexte service : `data` dict +
        `kwargs` {current_user, request}). Couvre les cas usuels d'un IO_CALL."""
        if isinstance(expr, dict):
            if "$input" in expr:
                return f"data.get({expr['$input']!r})"
            if "$auth" in expr:
                return f"(kwargs.get('current_user') or {{}}).get({expr['$auth']!r})"
            if "$context" in expr:
                return "None  # TODO: $context in IO_CALL"
            return "None  # TODO: unsupported IO_CALL expr"
        if isinstance(expr, (str, int, float, bool)) or expr is None:
            return repr(expr)
        return "None"

    def _compile_io_call_method(self, method_name: str, unit_name: str, body: dict) -> str:
        """IO_CALL → client HTTP synchrone vers un autre microservice.

        URL de base résolue depuis `<MODULE>_URL` (injecté par le compilateur
        infra via dependencies[$component]) ; JWT de l'appelant reforwardé si
        propagate_auth ; erreurs réseau / >=400 mappées sur on_error.kind.
        """
        mod = body.get("module", "Service")
        envvar = to_snake(mod).upper() + "_URL"
        http_method = str(body.get("method", "GET")).upper()
        endpoint = body.get("endpoint", "/")
        propagate = body.get("propagate_auth", True)
        timeout = (body.get("timeout_ms") or 10000) / 1000.0
        err_map = {
            "not_found": "NotFoundError", "conflict": "ConflictError",
            "validation_failed": "ValidationError", "internal": "ValidationError",
        }
        kind = (body.get("on_error") or {}).get("kind", "validation_failed")
        err_cls = "ForbiddenError" if kind == "unauthorized" else err_map.get(kind, "ValidationError")
        # `msg` est une variable locale (str) posée juste avant le raise dans
        # le code généré. ForbiddenError() ne prend pas de message (cf. F13).
        err_call = "ForbiddenError()" if err_cls == "ForbiddenError" else f"{err_cls}(msg)"

        def _d(obj):
            obj = obj if isinstance(obj, dict) else {}
            return "{" + ", ".join(f"{k!r}: {self._io_call_value_py(v)}"
                                   for k, v in obj.items()) + "}"

        pp, q, bd = _d(body.get("path_params")), _d(body.get("query")), _d(body.get("body"))
        not_cfg = f"{mod} indisponible : {envvar} non configuré"
        unreach = f"{mod} injoignable"
        bad = f"{mod} a renvoyé une erreur"
        return f'''
    def {method_name}(self, data: dict = None, **kwargs):
        """IO_CALL → {mod} {http_method} {endpoint} (microservice synchrone, ACIR 0.3.2)."""
        import os
        import httpx
        data = data or {{}}
        _base = (os.environ.get({envvar!r}) or "").rstrip("/")
        if not _base:
            raise ValidationError({not_cfg!r})
        _pp = {pp}
        _path = {endpoint!r}.format(**_pp) if _pp else {endpoint!r}
        _params = {{k: v for k, v in {q}.items() if v is not None}}
        _json = {bd}
        _headers = {{}}
        _req = kwargs.get("request")
        if {bool(propagate)} and _req is not None:
            _a = _req.headers.get("authorization")
            if _a:
                _headers["Authorization"] = _a
        try:
            with httpx.Client(timeout={timeout}) as _c:
                _r = _c.request({http_method!r}, _base + _path,
                                 params=_params or None,
                                 json=(_json or None) if {http_method!r} in ("POST", "PUT", "PATCH") else None,
                                 headers=_headers)
        except httpx.HTTPError as _e:
            msg = {unreach!r} + ": " + str(_e)
            raise {err_call}
        if _r.status_code >= 400:
            msg = {bad!r} + " (" + str(_r.status_code) + ")"
            raise {err_call}
        try:
            return _r.json()
        except Exception:
            return None
'''

    def _compile_fnative_method(self, method_name: str, body: dict,
                                output_name: str) -> str:
        """F_NATIVE (COVERAGE Axe 4) — frontière typée, corps injecté verbatim.
        Le compilateur ne juge PAS `impl` ; il l'injecte indenté. Pas d'impl
        py-fastapi → stub LOUD (NotImplementedError) — jamais silencieux
        (cf. docs/FNATIVE-EVALUATION.md ; le rapport de périmètre Axe 1
        l'étiquette best-effort côté UI)."""
        ret = output_name or "dict"
        code = (body.get("impl") or {}).get("py-fastapi")
        eff = ", ".join(body.get("effects") or []) or "aucun déclaré"
        if not code:
            inner = (f'raise NotImplementedError('
                     f'"F_NATIVE {method_name}: pas d\'impl py-fastapi")')
        else:
            inner = "\n".join("        " + ln for ln in code.splitlines()) or \
                    "        pass"
        return f"""
    def {method_name}(self, input=None, **kwargs) -> {ret}:
        \"\"\"F_NATIVE — bloc natif (best-effort, hors garantie déterministe).
        Effets déclarés : {eff}. Frontière validée par ACIR ; corps non jugé.\"\"\"
{inner}
"""

    def _generate_service_method(self, name: str, unit: dict, module: dict) -> str:
        body = unit.get("body", {})
        if not body:
            return ""

        prim = body.get("primitive", "")
        entity = body.get("entity", "")
        entity_class = to_pascal(depluralize(entity)) if entity else ""

        # Find matching entity in registry
        for n in self.type_registry:
            if to_snake(n) + "s" == entity or to_snake(n) == entity:
                entity_class = n
                break

        input_ref = unit.get("input", {})
        input_name = input_ref.get("$ref", "") if isinstance(input_ref, dict) else ""

        output_ref = unit.get("output", {})
        output_name = output_ref.get("$ref", "") if isinstance(output_ref, dict) else ""

        method_name = to_snake(name)

        if prim == "F_NATIVE":
            return self._compile_fnative_method(method_name, body, output_name)

        if prim == "IO_QUERY":
            # Detect get-by-id pattern: filter on identity field, no pagination, single result.
            filter_expr = body.get("filter", {})
            has_pagination = "pagination" in body
            is_single = bool(body.get("single")) or (
                isinstance(filter_expr, dict) and "id" in filter_expr and not has_pagination
            )

            if is_single:
                # **kwargs absorbs the current_user/request the route layer passes
                # uniformly to every service method (cf. create/list/update/delete,
                # which already accept it) — without it, GET-by-id 500s with
                # `unexpected keyword argument 'current_user'`.
                return f"""
    def {method_name}(self, id, **kwargs) -> {entity_class} | None:
        \"\"\"Get a {entity_class} by id.\"\"\"
        try:
            id = id if isinstance(id, UUID) else UUID(str(id))
        except (ValueError, AttributeError):
            return None
        return self.db.query({entity_class}).filter({entity_class}.id == id).first()
"""

            # F-query : IO_QUERY avec filter sur input body (e.g. login by email).
            # Si le filter référence `{$input: "..."}` ET pas de pagination, c'est une
            # find-by-predicate, pas un listing. On émet `.filter(...).first()` et on
            # branche soit return entity, soit synth DTO (auth wiring) selon output.
            filter_has_input = False
            if isinstance(filter_expr, dict):
                for spec in filter_expr.values():
                    if isinstance(spec, dict):
                        val = spec.get("value", spec)
                        if isinstance(val, dict) and "$input" in val:
                            filter_has_input = True
                            break
            if filter_has_input and entity_class and not has_pagination:
                return self._compile_query_filter_method(method_name, unit, body, entity_class, input_name)

            sort = body.get("sort", [])
            sort_field = sort[0].get("field", "id") if sort else "id"
            sort_dir = sort[0].get("direction", "desc") if sort else "desc"
            # F7 : brief 4 émet `field: {$conditional: {if: {$input: sort, eq: "price_asc"}, then: "price_ht", else: "created_at"}}`
            # (primitive ACIR hors-spec — LLM improvise, équivalent Quarkus #29).
            # On retombe sur "id" + "desc" plutôt que d'interpoler un dict dans le SQL.
            if not isinstance(sort_field, str):
                sort_field = "id"
            if not isinstance(sort_dir, str):
                sort_dir = "desc"
            sort_fn = "desc" if sort_dir == "desc" else "asc"

            # `**kwargs` TOUJOURS : la route de listing appelle systématiquement
            # `service.X(page=…, page_size=…, current_user=…, request=…)`. Sans kwargs,
            # une unit de listing SANS input (ex. listUserOrders) lève
            # `TypeError: unexpected keyword argument 'current_user'` → 500 au runtime.
            extra_kwargs = ", **kwargs"

            # R2 — appliquer le filtre (ownership `$auth`, littéraux, $context) au
            # listing. La branche par défaut abandonnait silencieusement la clause WHERE
            # → fuite (ex. listUserOrders renvoyait TOUS les ordres). On garde le contrat
            # tuple `(items, total)` attendu par la route paginée ; la cardinalité
            # « liste nue vs paginée » (route+service) reste un suivi.
            # IMPORTANT : on SAUTE les conditions référençant `$input` — ce sont des
            # filtres query-string que la route ne transmet PAS au service (signature
            # `(page, page_size, **kwargs)`, pas de `data`). Les inclure générerait
            # `data.get('status')` → NameError au runtime. La condition de scoping
            # critique (`$auth`) reste, elle, toujours appliquée.
            def _refs_input(node):
                if isinstance(node, dict):
                    return "$input" in node or any(_refs_input(x) for x in node.values())
                if isinstance(node, list):
                    return any(_refs_input(x) for x in node)
                return False

            filter_clause = ""
            if isinstance(filter_expr, dict) and filter_expr and not filter_expr.get("when_present"):
                clauses = []
                if "field" in filter_expr and "value" in filter_expr:
                    fld = filter_expr.get("field", "id")
                    val = filter_expr.get("value", {})
                    if not _refs_input(val):
                        clauses.append(f"{entity_class}.{fld} == {self._compile_data_expr_py(val, entity_class, fld)}")
                else:
                    for fname, spec in filter_expr.items():
                        value = spec.get("value", spec) if isinstance(spec, dict) else spec
                        if _refs_input(value):
                            continue
                        clauses.append(f"{entity_class}.{fname} == {self._compile_data_expr_py(value, entity_class, fname)}")
                if clauses:
                    filter_clause = f".filter({', '.join(clauses)})"

            # Cas "liste pure" : output ACIR `D_COLLECTION List<Entity>` (pas de
            # wrapper paginé) + body IO_QUERY sans pagination → service retourne une
            # liste directement. Parité avec Quarkus (`List<X> listX()`) et Fastify
            # (`Promise<X[]>`). Sans ce cas, le service `Tuple[list, int]` + la route
            # `dict(data=, total=, page=, limit=)` divergeaient des autres cibles qui
            # exposent un array nu — visible côté client (GET /categories brief4).
            output_is_pure_collection = (
                isinstance(output_ref, dict)
                and output_ref.get("primitive") == "D_COLLECTION"
                and not has_pagination
            )
            if output_is_pure_collection:
                return f"""
    def {method_name}(self{extra_kwargs}) -> list:
        \"\"\"List {entity_class} (liste pure, pas de pagination).\"\"\"
        return self.db.query({entity_class}){filter_clause}.order_by({sort_fn}({entity_class}.{sort_field})).all()
"""

            return f"""
    def {method_name}(self, page: int = 1, page_size: int = 20{extra_kwargs}) -> Tuple[list, int]:
        \"\"\"List {entity_class} with pagination.\"\"\"
        query = self.db.query({entity_class}){filter_clause}.order_by({sort_fn}({entity_class}.{sort_field}))
        total = query.count()
        items = query.offset((page - 1) * page_size).limit(page_size).all()
        return items, total
"""
        elif prim == "IO_MUTATE":
            action = body.get("action", "create")
            data = body.get("data", {})

            if action == "create":
                # v0.3 — Iterate body.data field-by-field and compile each value via
                # _compile_data_expr_py so $generate / $calculate / $auth etc. emit
                # proper Python instead of being spread blindly from the request body.
                # Legacy v0.2 behaviour preserved : a $-prefixed key that we can't
                # interpret falls through to `data.get('<field>')` so the request
                # body still wins for plain inputs.
                init_lines = []
                for fname, value in data.items():
                    if isinstance(value, dict) and any(k.startswith("$") for k in value):
                        compiled = self._compile_data_expr_py(value, entity_class, fname)
                    elif isinstance(value, (str, int, float, bool)) or value is None:
                        compiled = repr(value)
                    else:
                        # Plain dict (no $-key) — assume it's a literal payload, pass through.
                        compiled = repr(value)
                    init_lines.append(f"            {fname!r}: {compiled}")
                # Merge ACIR-declared fields with anything the request body provides on top
                # (covers v0.2 LLM patterns where input fields are forwarded by name without
                # an explicit $input entry in body.data).
                init_body = ",\n".join(init_lines)
                return f"""
    def {method_name}(self, data: dict = None, **kwargs) -> {entity_class}:
        \"\"\"Create a new {entity_class}.\"\"\"
        data = data or {{}}
        fields = {{
{init_body}
        }}
        merged = {{**data, **{{k: v for k, v in fields.items() if v is not None}}}}
        obj = {entity_class}(**merged)
        try:
            self.db.add(obj)
            self.db.commit()
            self.db.refresh(obj)
        except IntegrityError as e:
            self.db.rollback()
            raise ConflictError(f"{entity_class} déjà existant ou contrainte violée") from e
        return obj
"""
            elif action == "update":
                return self._compile_unit_update_method(method_name, body, entity_class, unit=unit)
            elif action == "delete":
                return self._compile_unit_delete_method(method_name, body, entity_class)
        elif prim == "F_GUARD":
            # Sprint D gap 2 — standalone F_GUARD body (brief2 updateArticle :
            # admin override + ownership check + IO_MUTATE update). Compile la
            # condition + emit la guard avant le then-body de l'IO_MUTATE.
            condition = body.get("condition", {})
            then_op = body.get("then", {})
            on_fail = body.get("on_fail") or body.get("error") or {}
            code = on_fail.get("code", "FORBIDDEN")
            message = on_fail.get("message", "Operation not authorized")
            cond_expr = self._compile_guard_condition_py(condition)
            # Le top-level F_GUARD body n'a pas d'`entity` direct — l'entity est
            # dans `then.entity`. Sans cette résolution, `entity_class` reste vide
            # et le method emit `def update_article(...) -> :` (return type vide).
            then_entity_class = entity_class
            if isinstance(then_op, dict) and then_op.get("entity"):
                then_entity_acir = then_op["entity"]
                then_entity_class = to_pascal(depluralize(then_entity_acir))
                for n in self.type_registry:
                    if to_snake(n) + "s" == then_entity_acir or to_snake(n) == then_entity_acir:
                        then_entity_class = n
                        break
            if cond_expr and isinstance(then_op, dict) and then_op.get("primitive") == "IO_MUTATE":
                action = then_op.get("action", "update")
                if action == "update":
                    inner_method = self._compile_unit_update_method(method_name, then_op, then_entity_class, unit=unit)
                elif action == "delete":
                    inner_method = self._compile_unit_delete_method(method_name, then_op, then_entity_class)
                else:
                    inner_method = None
                if inner_method:
                    # Inject the guard right after the docstring line. Le format
                    # produit par les compile_unit_X_method est :
                    #   def ...:
                    #       """..."""
                    #       <body lines>
                    # On split, on trouve la docstring (1-line `"""..."""`),
                    # on insère le bloc guard juste après.
                    guard_block = (
                        f'        if not ({cond_expr}):\n'
                        f'            raise ForbiddenError({code!r} + \': \' + {message!r})'
                    )
                    out_lines = []
                    injected = False
                    for line in inner_method.split("\n"):
                        out_lines.append(line)
                        stripped = line.strip()
                        if (not injected
                                and stripped.startswith('"""')
                                and stripped.endswith('"""')
                                and len(stripped) > 6):
                            out_lines.append(guard_block)
                            injected = True
                    return "\n".join(out_lines)
        elif prim == "F_SEQUENCE":
            return self._compile_sequence_method(method_name, unit, body)
        elif prim == "F_FOREACH":
            # v0.3 — F_FOREACH as the unit's top-level body (e.g. decrementStocks).
            # Emit a method that calls _compile_foreach_step_py and commits at the end.
            unit_output = unit.get("output", {})
            is_void = isinstance(unit_output, dict) and unit_output.get("kind") == "void"
            loop_block = self._compile_foreach_step_py(body, "_top", indent="        ")
            ret_line = "        return None" if is_void else "        return None  # F_FOREACH side-effect only"
            return f"""
    def {method_name}(self, data: dict = None, **kwargs) -> None:
        \"\"\"F_FOREACH unit body — iterates a collection and runs side-effects per element.\"\"\"
        data = data or {{}}
{loop_block}
        try:
            self.db.commit()
        except IntegrityError as e:
            self.db.rollback()
            raise ConflictError('F_FOREACH commit failed: ' + str(e)) from e
{ret_line}
"""
        elif prim == "IO_CALL":
            return self._compile_io_call_method(method_name, name, body)

        # Fallback for IO_QUERY with get by id pattern
        return f"""
    def {method_name}(self, id: str = None, **kwargs):
        \"\"\"Handler for {name}.\"\"\"
        if id and hasattr(self, 'db'):
            for model in [{', '.join(n for n in self.type_registry if self.type_registry[n].get('identity'))}]:
                obj = self.db.query(model).filter(model.id == id).first()
                if obj:
                    return obj
            raise NotFoundError("Resource", id)
        return None
"""

    # ─── routes.py (FastAPI with Swagger) ──────────────────────────────────

    def _generate_routes(self, module: dict):
        module_name = module.get("name", "App")
        exposed = module.get("exposed", [])
        service_class = f"{to_pascal(module_name)}Service"

        # Detect global features used by routes
        any_rate_limit = any(ep.get("rate_limit") for ep in exposed)

        imports = [
            "from typing import Optional, List",
            "from fastapi import APIRouter, Depends, Query, Path, HTTPException, status, Request",
            "from sqlalchemy.orm import Session",
            "from app.database import get_db",
            f"from app.service import {service_class}",
            "from app.errors import NotFoundError, ConflictError, ForbiddenError",
        ]
        if any_rate_limit:
            imports.append("from app.rate_limit import limiter")
        # `require_role`/`get_current_user` only exist in app/auth.py, which is
        # generated solely when at least one endpoint declares auth (has_auth).
        # A fully-public module has no auth.py → importing it
        # unconditionally → `ModuleNotFoundError: No module named 'app.auth'`
        # at boot. Public endpoints use `current_user: Optional[dict] = None`
        # (no Depends, no symbol from app.auth), so the import is only needed
        # when auth is actually present.
        if self.has_auth:
            imports.append("from app.auth import require_role, get_current_user, optional_user")

        # Collect schema imports
        schema_names = set()
        for ep in exposed:
            out = ep.get("output", {})
            if isinstance(out, dict) and out.get("$ref"):
                ref = out["$ref"]
                if ref in self.type_registry and self.type_registry[ref].get("identity"):
                    schema_names.add(f"{ref}Response")
                    schema_names.add(f"{ref}ListResponse")
                else:
                    schema_names.add(ref)
            elif isinstance(out, dict) and out.get("primitive") == "D_COLLECTION":
                # `output: D_COLLECTION List<Entity>` — if a pagination wrapper
                # is declared in the type_registry, the route uses it as
                # response_model (cf. _find_pagination_wrapper). Import it too
                # so the schema name resolves at module import.
                elem = out.get("element_type", {}) or {}
                if isinstance(elem, dict) and "$ref" in elem:
                    wrapper = self._find_pagination_wrapper(elem["$ref"])
                    if wrapper:
                        schema_names.add(wrapper)
                    # Cas "liste pure" : la route peut émettre `response_model=
                    # List[<X>Response]` (cf. _generate_route is_pure_list branch).
                    # On importe `<X>Response` aussi quand l'element est une entity
                    # connue, pour éviter `NameError: <X>Response not defined`.
                    elem_ref = elem.get("$ref")
                    if elem_ref and elem_ref in self.type_registry and self.type_registry[elem_ref].get("identity"):
                        schema_names.add(f"{elem_ref}Response")
            inp = ep.get("input", {})
            if isinstance(inp, dict) and inp.get("$ref"):
                schema_names.add(inp["$ref"])
                # Composite input: the route binds the body to the sub-record
                # named by input_layout.body, not the whole composite — import
                # that sub-type too or routes.py NameErrors at import.
                il = ep.get("input_layout", {}) or {}
                if ep.get("input_source") == "composite" and il.get("body"):
                    rec = self.type_registry.get(inp["$ref"], {})
                    bf = next((f for f in rec.get("fields", [])
                               if f.get("name") == il["body"]), None)
                    bt = bf.get("type") if bf else None
                    if isinstance(bt, dict) and bt.get("$ref"):
                        schema_names.add(bt["$ref"])

        if schema_names:
            imports.append(f"from app.schemas import {', '.join(sorted(schema_names))}")

        # Determine tag from route prefix
        tag = module_name
        if exposed:
            route = exposed[0].get("route", "")
            parts = route.strip("/").split("/")
            if len(parts) >= 3:
                tag = to_pascal(parts[2])

        route_defs = []
        for ep in exposed:
            route_defs.append(self._generate_route(ep, module, service_class, tag))

        imports_str = "\n".join(sorted(set(imports)))
        routes_str = "\n\n".join(route_defs)

        self._add_file("app/routes.py", f'''"""ACIR Generated — FastAPI Routes with OpenAPI/Swagger documentation."""
{imports_str}

router = APIRouter(tags=["{tag}"])


def get_service(db: Session = Depends(get_db)) -> {service_class}:
    return {service_class}(db)

{routes_str}
''')

    def _generate_route(self, ep: dict, module: dict, service_class: str, tag: str) -> str:
        method = ep.get("method", "GET").lower()
        route = ep.get("route", "/")
        handler_ref = ep.get("handler", {})
        handler_name = handler_ref.get("$ref", "") if isinstance(handler_ref, dict) else ""
        auth = ep.get("auth")
        rate_limit = ep.get("rate_limit")
        response_mapping = ep.get("response_mapping", {})
        output = ep.get("output", {})
        input_ref = ep.get("input", {})
        input_source = ep.get("input_source", "body")

        # Determine status code
        success_code = 200
        rm = response_mapping.get("success", {})
        if isinstance(rm, dict) and "status_code" in rm:
            success_code = rm["status_code"]
        elif method == "post":
            success_code = 201
        elif method == "delete":
            success_code = 204

        # Determine response model
        output_ref = output.get("$ref", "") if isinstance(output, dict) else ""
        response_model = ""
        if output_ref and output_ref in self.type_registry:
            if self.type_registry[output_ref].get("identity"):
                if method == "get" and "{" not in route:
                    response_model = f"{output_ref}ListResponse"
                else:
                    response_model = f"{output_ref}Response"
            else:
                response_model = output_ref

        # Pagination wrapper fallback — when output is `D_COLLECTION List<Entity>`
        # without `$ref` but the type_registry declares a `PaginatedEntity`-shaped
        # record, use it as response_model. Parity with Quarkus : avoids emitting
        # an untyped `dict` response for the LLM-loose shape (Haiku/Sonnet
        # sometimes declare PaginatedTasks but write `output: List<Task>` on the
        # listTasks unit). The downstream kwargs introspection at line ~2820
        # already adapts field names (`data` vs `items`, `limit` vs `page_size`).
        if not response_model and isinstance(output, dict) and output.get("primitive") == "D_COLLECTION":
            elem = output.get("element_type", {}) or {}
            if isinstance(elem, dict) and "$ref" in elem:
                wrapper = self._find_pagination_wrapper(elem["$ref"])
                if wrapper:
                    response_model = wrapper

        # Convert route params {id} → {id: str}
        fastapi_route = re.sub(r'\{(\w+)\}', r'{\1}', route)
        path_params = re.findall(r'\{(\w+)\}', route)

        # Détection "liste pure" : output ACIR D_COLLECTION + body IO_QUERY sans
        # pagination → array nu (parité Quarkus `List<X>` / Fastify `X[]`). Évite
        # le wrapper paginé synthétisé à tort sur des units qui ne paginaient pas
        # côté ACIR (ex: brief4 listCategories — sort uniquement, pas de pagination).
        # Override response_model en `List[XResponse]` quand applicable (avant que
        # rm_str soit calculé plus bas). Restreint aux endpoints SANS input ACIR
        # (sinon le compilateur extrait les fields du DTO en query params, cf.
        # brief4 getTopProducts qui a `input_source: query`).
        _handler_unit = next((u for u in module.get("units", [])
                              if u.get("name") == handler_name), {}) if handler_name else {}
        _hbody = _handler_unit.get("body", {}) if isinstance(_handler_unit, dict) else {}
        is_pure_list = (
            method == "get"
            and not path_params
            and not input_ref
            and isinstance(output, dict)
            and output.get("primitive") == "D_COLLECTION"
            and isinstance(_hbody, dict)
            and _hbody.get("primitive") == "IO_QUERY"
            and not _hbody.get("pagination")
        )
        if is_pure_list:
            _elem = output.get("element_type", {}) or {}
            if isinstance(_elem, dict) and "$ref" in _elem:
                elem_ref = _elem["$ref"]
                # Si l'élément est une entity (a identity), un `<X>Response` est
                # généré ; sinon (DTO sans identity), on utilise le type tel quel.
                elem_rec = self.type_registry.get(elem_ref, {})
                if elem_rec.get("identity"):
                    response_model = f"List[{elem_ref}Response]"
                else:
                    response_model = f"List[{elem_ref}]"

        fn_name = to_snake(handler_name) if handler_name else f"{method}_{tag.lower()}"

        # Build Swagger description
        desc_parts = []
        if auth and auth.get("required"):
            roles = auth.get("roles", [])
            desc_parts.append(f"**Authentification** : {', '.join(roles)}" if roles else "**Authentification requise**")
        if rate_limit:
            desc_parts.append(f"**Rate limit** : {rate_limit.get('limit', 100)} requêtes / {rate_limit.get('window', 'PT1M')}")
        description = " | ".join(desc_parts) if desc_parts else ""

        # Build summary for Swagger
        entity_label = output_ref or tag
        # Clean up: use raw entity name, not Response/List suffixes
        entity_label = entity_label.replace("Response", "").replace("ListResponse", "").replace("List", "").rstrip("s")
        if not entity_label:
            entity_label = tag

        if method == "get" and not path_params:
            summary = f"Lister les {entity_label}s"
        elif method == "get" and path_params:
            summary = f"Obtenir un {entity_label} par ID"
        elif method == "post":
            summary = f"Créer un {entity_label}"
        elif method in ("put", "patch"):
            summary = f"Modifier un {entity_label}"
        elif method == "delete":
            summary = f"Supprimer un {entity_label}"
        else:
            summary = f"{method.upper()} {route}"

        # Build doc string
        doc = f'"""{summary}'
        if description:
            doc += f'\n\n    {description}'
        doc += '"""'

        # Decorator with Swagger metadata. List endpoints get a typed response_model
        # (the auto-generated <Entity>ListResponse with from_attributes=True).
        rm_str = f", response_model={response_model}" if response_model and success_code != 204 else ""
        sc_str = f", status_code={success_code}" if success_code != 200 else ""
        sum_str = f', summary="{summary}"'
        desc_str = f', description="{description}"' if description else ""

        # Documented error responses for Swagger
        responses_parts = []
        if auth and auth.get("required"):
            responses_parts.append('401: {"description": "Non authentifié"}')
            responses_parts.append('403: {"description": "Accès interdit"}')
        if path_params:
            responses_parts.append('404: {"description": "Ressource non trouvée"}')
        if method in ("post", "put", "patch"):
            responses_parts.append('422: {"description": "Données invalides"}')
            responses_parts.append('409: {"description": "Conflit (doublon)"}')
        resp_str = f", responses={{{', '.join(responses_parts)}}}" if responses_parts else ""

        # Convert ACIR window (e.g. "PT1M", "PT30S") to slowapi format (e.g. "100/minute", "30/second")
        rl_decorator = ""
        if rate_limit:
            rl_limit_n = rate_limit.get("limit", 100)
            rl_window = rate_limit.get("window", "PT1M")
            window_unit = "minute"
            if "S" in rl_window:
                window_unit = "second"
            elif "H" in rl_window:
                window_unit = "hour"
            elif "M" in rl_window:
                window_unit = "minute"
            elif "D" in rl_window:
                window_unit = "day"
            rl_decorator = f'@limiter.limit("{rl_limit_n}/{window_unit}")\n'

        decorator = f'{rl_decorator}@router.{method}("{fastapi_route}"{rm_str}{sc_str}{sum_str}{desc_str}{resp_str})'

        # Function params — required params MUST come before params with defaults (Python rule)
        required_params = []   # no default value
        optional_params = [f"service: {service_class} = Depends(get_service)"]  # has default

        # SlowAPI requires a `request: Request` param to derive the rate-limit key.
        # v0.3 — Request is also forwarded to the service when `$context: "request.*"`
        # is used. Always add it (cost = one optional param) so the kwarg pass-through
        # below stays uniform.
        has_request_param = rate_limit or auth and auth.get("required")
        if has_request_param:
            required_params.append("request: Request")
        else:
            # Optional Request kwarg — endpoints without auth/rate-limit still get
            # one so the kwargs passed to the service can include it.
            optional_params.append("request: Request = None")

        for pp in path_params:
            optional_params.append(f'{pp}: str = Path(..., description="Identifiant de la ressource")')

        # Auth dependency — apply real Depends(require_role(...)) when auth.required is set.
        # v0.3 — rename `_user` to `current_user` so `$auth: <claim>` resolution can
        # forward the JWT payload to the service via kwargs.
        if auth and auth.get("required"):
            roles = auth.get("roles", [])
            if roles:
                roles_args = ", ".join(f'"{r}"' for r in roles)
                optional_params.append(f"current_user: dict = Depends(require_role({roles_args}))")
            else:
                optional_params.append("current_user: dict = Depends(get_current_user)")
        else:
            # Public endpoint — current_user résolu via dependency `optional_user`
            # (retourne None si pas de Bearer). F-RUNTIME-1 fix : marquer comme
            # dependency (vs body param) empêche FastAPI d'auto-activer embed
            # sur le body schema (qui faisait que /signup attendait
            # `{"data":{...}}` au lieu de `{...}` direct).
            # Si pas de auth.py (module 100% public), fallback `= None` legacy.
            if self.has_auth:
                optional_params.append("current_user: Optional[dict] = Depends(optional_user)")
            else:
                optional_params.append("current_user: Optional[dict] = None")

        input_name = input_ref.get("$ref", "") if isinstance(input_ref, dict) else ""

        # Composite input (input_source: "composite" + input_layout): some fields
        # come from the URL path, the request body carries only the sub-record
        # named by input_layout.body. Without this the route binds the WHOLE
        # composite type to the body → client must send {id, data:{…}} (id is
        # already in the path) → 422 "field required". We bind the body to the
        # `body` field's own type and rebuild the flat payload the F_SEQUENCE /
        # update service expects ($input:"id" → data['id'], $input:"data.status"
        # → data['data.status']).
        input_layout = ep.get("input_layout", {}) or {}
        composite_body_field = None
        composite_path_fields = []
        body_param_type = input_name
        if input_source == "composite" and input_layout:
            composite_body_field = input_layout.get("body")
            composite_path_fields = input_layout.get("path", []) or []
            rec = self.type_registry.get(input_name, {})
            bf = next((f for f in rec.get("fields", [])
                       if f.get("name") == composite_body_field), None)
            bt = bf.get("type") if bf else None
            if isinstance(bt, dict) and bt.get("$ref"):
                body_param_type = bt["$ref"]

        # Body input — used by POST/PUT/PATCH. Required for these methods even if the
        # endpoint omits input_source: "body" (FastAPI deduces body from a DTO param).
        needs_body_param = (
            (input_name and input_source == "body")
            or (method in ("put", "patch") and input_name)
            or (method == "post" and input_name)
        )
        if needs_body_param:
            required_params.append(f"data: {body_param_type}")  # no default → MUST be first
        elif method == "get" and not path_params and not is_pure_list:
            optional_params.append('page: int = Query(1, ge=1, description="Numéro de page")')
            optional_params.append('page_size: int = Query(20, ge=1, le=100, description="Éléments par page")')

        params_str = ",\n    ".join(required_params + optional_params)

        # Body
        svc_method = to_snake(handler_name) if handler_name else fn_name
        # v0.3 — every service call gets `current_user` and `request` as kwargs so
        # `$auth`/`$context` resolve regardless of public/private endpoint. Service
        # methods declare `**kwargs`, so unused values cost nothing.
        ctx_kwargs = "current_user=current_user, request=request"
        # IO_CALL units proxy an upstream microservice — they don't return the
        # `(items, total)` tuple the paginated-list route shape expects. Call
        # them plainly and return the upstream payload as-is (ACIR 0.3.2).
        _hu = next((u for u in module.get("units", [])
                    if u.get("name") == handler_name), {})
        _is_io_call = (isinstance(_hu.get("body"), dict)
                       and _hu["body"].get("primitive") == "IO_CALL")
        if _is_io_call:
            _parts = []
            if needs_body_param:
                _parts.append("data=data.model_dump()")
            elif path_params:
                _parts.append("data={" + ", ".join(f'"{p}": {p}' for p in path_params) + "}")
            _parts.append(ctx_kwargs)
            body = f"    return service.{svc_method}({', '.join(_parts)})"
        elif is_pure_list:
            # Liste pure : pas de pagination — appelle directement le service qui
            # retourne une liste (cf. _generate_service_method branche
            # `output_is_pure_collection`).
            body = f"    return service.{svc_method}({ctx_kwargs})"
        elif method == "get" and not path_params:
            # FastAPI handles SQLAlchemy → Pydantic via response_model + from_attributes=True.
            list_dto = response_model or "dict"
            # F3b minimal-fix : adapter les kwargs aux field names du DTO réellement déclaré.
            # Le compilateur générait toujours `items=..., page_size=..., total_pages=...`,
            # qui crashe au runtime quand l'ACIR déclare un D_RECORD `PaginatedXxx` avec
            # `data/total/page/limit` (forme canonique du brief 2). On introspecte le DTO
            # via type_registry. Si on n'a pas la déf (DTO auto-généré `XxxListResponse`),
            # on retombe sur la forme historique items/page_size/total_pages.
            dto_record = self.type_registry.get(list_dto, {}) if list_dto != "dict" else {}
            dto_field_names = {f.get("name") for f in dto_record.get("fields", [])}
            # Fallback canonique ACIR (data/total/page/limit) quand le DTO n'est pas
            # dans le type_registry (cas du synth `<X>ListResponse` qui suit le même
            # shape — cf. _generate_schemas). Pas de `total_pages` dans le fallback
            # car le synth wrapper canonique ne l'expose pas (parité Quarkus/Fastify).
            kwargs = []
            if "data" in dto_field_names or not dto_field_names:
                kwargs.append("data=items")
            elif "items" in dto_field_names:
                kwargs.append("items=items")
            kwargs.append("total=total")
            if "page" in dto_field_names or not dto_field_names:
                kwargs.append("page=page")
            if "limit" in dto_field_names or not dto_field_names:
                kwargs.append("limit=page_size")
            elif "page_size" in dto_field_names:
                kwargs.append("page_size=page_size")
            if "total_pages" in dto_field_names:
                kwargs.append("total_pages=(total + page_size - 1) // page_size if page_size else 1")
            kwargs_str = ",\n        ".join(kwargs)
            body = f"""    items, total = service.{svc_method}(page=page, page_size=page_size, {ctx_kwargs})
    return {list_dto}(
        {kwargs_str},
    )"""
        elif method == "get" and path_params:
            body = f"""    result = service.{svc_method}(id={path_params[0]}, {ctx_kwargs})
    if not result:
        raise HTTPException(status_code=404, detail="{output_ref} non trouvé")
    return result"""
        elif method == "post":
            if needs_body_param and path_params:
                # Bundle path params alongside body so the service receives both.
                # Brief 4 `POST /admin/orders/{id}/mark-paid` has input D_RECORD {id} +
                # input_source=path → route forwards id from path, no body. Mixed case
                # (path param + body) reuses the bundled dict pattern.
                pp_kwargs = ", ".join(f'"{p}": {p}' for p in path_params)
                body = (
                    f"    payload = data.model_dump()\n"
                    f"    payload.update({{{pp_kwargs}}})\n"
                    f"    return service.{svc_method}(data=payload, {ctx_kwargs})"
                )
            elif needs_body_param:
                body = f"    return service.{svc_method}(data=data.model_dump(), {ctx_kwargs})"
            elif path_params:
                # F-mutate-update-unit : POST /<resource>/{id}/<action> sans body
                # (publishArticle, markOrderPaid…) doit transmettre le path-param au
                # service, sinon `service.X()` sans args → TypeError. Pour les units
                # à input scalaire (D_SCALAR uuid), on passe directement la valeur ;
                # pour les D_RECORD à input_source=path, on bundle dans un dict.
                input_prim = input_ref.get("primitive") if isinstance(input_ref, dict) else None
                if input_prim == "D_SCALAR":
                    body = f"    return service.{svc_method}(data={path_params[0]}, {ctx_kwargs})"
                else:
                    pp_kwargs = ", ".join(f'"{p}": {p}' for p in path_params)
                    body = f"    return service.{svc_method}(data={{{pp_kwargs}}}, {ctx_kwargs})"
            else:
                body = f"    return service.{svc_method}({ctx_kwargs})"
        elif method in ("put", "patch"):
            if needs_body_param and composite_body_field:
                # Flat payload: path fields verbatim + body sub-record flattened
                # under "<body_field>.<k>" dotted keys (matches how the service
                # resolves $input:"id" / $input:"<body_field>.<sub>").
                pp = composite_path_fields or path_params
                pp_init = ", ".join(f'"{p}": {p}' for p in pp)
                body = (
                    f"    payload = {{{pp_init}}}\n"
                    f"    for _k, _v in data.model_dump(exclude_unset=True).items():\n"
                    f'        payload[f"{composite_body_field}.{{_k}}"] = _v\n'
                    f"    return service.{svc_method}(data=payload, {ctx_kwargs})"
                )
            elif needs_body_param and path_params:
                body = f"    return service.{svc_method}(id={path_params[0]}, data=data.model_dump(exclude_unset=True), {ctx_kwargs})"
            elif needs_body_param:
                body = f"    return service.{svc_method}(data=data.model_dump(exclude_unset=True), {ctx_kwargs})"
            elif path_params:
                body = f"    return service.{svc_method}(id={path_params[0]}, {ctx_kwargs})"
            else:
                body = f"    return service.{svc_method}({ctx_kwargs})"
        elif method == "delete":
            body = f"    service.{svc_method}(id={path_params[0]}, {ctx_kwargs})" if path_params else f"    service.{svc_method}({ctx_kwargs})"
        else:
            body = "    pass"

        return f"""{decorator}
async def {fn_name}(
    {params_str},
):
    {doc}
{body}
"""

    # ─── main.py (FastAPI app with Swagger) ────────────────────────────────

    def _generate_main(self, module: dict):
        module_name = module.get("name", "App")
        mod_doc = module.get("doc", f"API générée par ACIR pour {module_name}")

        ep_count = len(module.get("exposed", []))
        type_count = len(module.get("types", []))
        unit_count = len(module.get("units", []))

        # Conditional imports/wiring blocks
        rl_imports = ""
        rl_handler = ""
        rl_state = ""
        if self.has_rate_limit:
            rl_imports = (
                "from slowapi.errors import RateLimitExceeded\n"
                "from slowapi.middleware import SlowAPIMiddleware\n"
                "from app.rate_limit import limiter\n"
            )
            rl_state = "app.state.limiter = limiter\napp.add_middleware(SlowAPIMiddleware)\n"
            rl_handler = (
                "@app.exception_handler(RateLimitExceeded)\n"
                "async def rate_limit_handler(request, exc):\n"
                "    return JSONResponse(status_code=429, content={\"kind\": \"rate_limited\", "
                "\"message\": \"Trop de requêtes. Veuillez patienter.\"})\n"
            )

        auth_imports = ""
        auth_router_include = ""
        # routes_auth (env-var /auth/login) n'est émis que si le brief n'a pas son
        # propre login (piste 1) — n'importer/inclure que dans ce cas, sinon ImportError.
        if self.has_auth and not self._has_own_token:
            auth_imports = "from app.routes_auth import router as auth_router\n"
            auth_router_include = "app.include_router(auth_router)\n"

        self._add_file("app/main.py", f'''"""ACIR Generated — FastAPI Application with Swagger/OpenAPI."""
import logging
import os
import sys
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pythonjsonlogger import jsonlogger
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.routes import router
from app.errors import AcirError, acir_error_handler, catch_all_handler
from app.security import SecurityHeadersMiddleware
{rl_imports}{auth_imports}

# ─── Structured JSON logging ──────────────────────────────────────────────
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(jsonlogger.JsonFormatter("%(asctime)s %(name)s %(levelname)s %(message)s"))
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), handlers=[_handler])
logger = logging.getLogger("acir")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown hooks. Schema migrations are managed by Alembic, NOT create_all."""
    logger.info("Application starting", extra={{"service": "{module_name}"}})
    # Reminder: run `alembic upgrade head` before deploying to apply schema changes.
    yield
    logger.info("Application shutting down")


app = FastAPI(
    title="{module_name} API",
    description="""{mod_doc}

---

### Généré par ACIR (Agent Code Intermediate Representation)

- **{type_count} types** définis · **{unit_count} unités** · **{ep_count} endpoints**
- Validation par Pydantic, auth JWT (si activée), rate limiting réel via SlowAPI

📖 [Documentation ACIR](https://ldlabs.dev) — © Ld Labs
""",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    swagger_ui_parameters={{"docExpansion": "list", "defaultModelsExpandDepth": 1, "filter": True}},
    lifespan=lifespan,
)


# ─── Correlation ID middleware ────────────────────────────────────────────
class CorrelationIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        cid = request.headers.get("X-Request-Id") or uuid.uuid4().hex
        request.state.correlation_id = cid
        response = await call_next(request)
        response.headers["X-Request-Id"] = cid
        return response


# ─── Middleware (order matters: last added = first executed) ───────────────
app.add_middleware(CorrelationIdMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "X-Request-Id"],
)

{rl_state}
{rl_handler}

app.add_exception_handler(AcirError, acir_error_handler)
app.add_exception_handler(Exception, catch_all_handler)

app.include_router(router)
{auth_router_include}

@app.get("/health", tags=["System"], summary="Health check")
async def health():
    return {{"status": "healthy", "service": "{module_name}", "generator": "ACIR v0.2.0"}}
''')

    # ─── Tests (pytest + httpx) ────────────────────────────────────────────

    def _generate_tests(self, module: dict):
        module_name = module.get("name", "App")
        exposed = module.get("exposed", [])
        if not exposed:
            return

        test_cases = []

        for ep in exposed:
            method = ep.get("method", "GET").lower()
            route = ep.get("route", "")
            handler_ref = ep.get("handler", {})
            handler_name = handler_ref.get("$ref", "") if isinstance(handler_ref, dict) else ""
            auth = ep.get("auth")
            response_mapping = ep.get("response_mapping", {})
            input_ref = ep.get("input")
            path_params = re.findall(r'\{(\w+)\}', route)

            fn_name = to_snake(handler_name) if handler_name else f"{method}_{route.replace('/', '_')}"
            success_code = 200
            rm = response_mapping.get("success", {})
            if isinstance(rm, dict) and "status_code" in rm:
                success_code = rm["status_code"]
            elif method == "post":
                success_code = 201
            elif method == "delete":
                success_code = 204

            valid_body = self._build_test_body(input_ref, valid=True)
            invalid_body = self._build_test_body(input_ref, valid=False)
            needs_auth = bool(auth and auth.get("required"))
            auth_arg = ", auth_headers" if needs_auth else ""
            auth_kw = ", headers=auth_headers" if needs_auth else ""

            # Happy path
            if method in ("post", "put", "patch") and valid_body:
                # Substitute path params (PUT/PATCH on /products/{id}) so we don't send a literal "{id}"
                test_route = route
                for pp in path_params:
                    test_route = test_route.replace("{" + pp + "}", "00000000-0000-0000-0000-000000000001")
                # PUT/PATCH on a non-existent ID will 404 — accept either success or 404
                expected = f"({success_code}, 200, 201, 404)" if path_params else f"({success_code}, 200, 201)"
                test_cases.append(f'''
async def test_{fn_name}_success(client{auth_arg}):
    """{method.upper()} {route} — succès ({success_code})."""
    response = await client.{method}("{test_route}", json={valid_body}{auth_kw})
    assert response.status_code in {expected}
''')
            else:
                test_route = route
                for pp in path_params:
                    test_route = test_route.replace("{" + pp + "}", "00000000-0000-0000-0000-000000000001")
                test_cases.append(f'''
async def test_{fn_name}_success(client{auth_arg}):
    """{method.upper()} {route} — succès."""
    response = await client.{method}("{test_route}"{auth_kw})
    assert response.status_code in [{success_code}, 200, 404]
''')

            # Validation failure
            if method in ("post", "put", "patch") and invalid_body:
                test_cases.append(f'''
async def test_{fn_name}_validation(client{auth_arg}):
    """{method.upper()} {route} — validation échouée."""
    response = await client.{method}("{route}", json={invalid_body}{auth_kw})
    assert response.status_code in [400, 422]
''')

            # Not found for path params
            if path_params and method in ("get", "put", "patch", "delete"):
                nf_route = route.replace("{" + path_params[0] + "}", "00000000-0000-0000-0000-000000000000")
                # For PUT/PATCH on a non-existent ID we still need a valid body to pass schema validation
                # before reaching the 404 branch.
                nf_body_kw = f", json={valid_body}" if method in ("put", "patch") and valid_body else ""
                test_cases.append(f'''
async def test_{fn_name}_not_found(client{auth_arg}):
    """{method.upper()} {route} — non trouvé (404)."""
    response = await client.{method}("{nf_route}"{nf_body_kw}{auth_kw})
    assert response.status_code == 404
''')

            # Auth enforcement test — verify that protected endpoints reject anonymous calls
            if needs_auth and method in ("post", "put", "patch", "delete"):
                test_route_anon = route
                for pp in path_params:
                    test_route_anon = test_route_anon.replace("{" + pp + "}", "00000000-0000-0000-0000-000000000001")
                anon_body_kw = f", json={valid_body}" if method in ("post", "put", "patch") and valid_body else ""
                test_cases.append(f'''
async def test_{fn_name}_unauthenticated(client):
    """{method.upper()} {route} — sans token (401)."""
    response = await client.{method}("{test_route_anon}"{anon_body_kw})
    assert response.status_code == 401
''')

        # Swagger tests
        test_cases.append('''
async def test_swagger_docs(client):
    """Swagger UI est accessible."""
    response = await client.get("/docs")
    assert response.status_code == 200

async def test_openapi_json(client):
    """OpenAPI JSON est accessible."""
    response = await client.get("/openapi.json")
    assert response.status_code == 200
    data = response.json()
    assert "paths" in data
    assert "info" in data

async def test_redoc(client):
    """ReDoc est accessible."""
    response = await client.get("/redoc")
    assert response.status_code == 200

async def test_health(client):
    """Health check."""
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
''')

        tests_str = "\n".join(test_cases)

        # Build the auth_token fixture only when auth is needed AND a role is declared.
        # Brief 1 (TODO list) has JWT but no role labels — skip the fixture rather than crash.
        auth_fixture = ""
        if self.has_auth and self.all_roles:
            primary_role = sorted(self.all_roles)[0]
            primary_user = primary_role.lower().replace("_", "")
            auth_fixture = f'''

@pytest_asyncio.fixture
async def auth_headers(client):
    """Bearer token for the primary admin/role user, hydrated from AUTH_USER_<ROLE>_PASSWORD."""
    import os
    pw = os.environ.get("AUTH_USER_{primary_role.upper()}_PASSWORD", "admin123")
    resp = await client.post("/auth/login", json={{"username": "{primary_user}", "password": pw}})
    assert resp.status_code == 200, f"Login failed: {{resp.text}}"
    return {{"Authorization": f"Bearer {{resp.json()['token']}}"}}
'''

        self._add_file("tests/__init__.py", "")
        self._add_file("tests/conftest.py", f'''"""ACIR Generated — Test configuration.

Tests run against a transient SQLite database, isolated from the live Postgres
the running container uses. Otherwise create_all/drop_all in fixtures would
nuke production tables when running pytest in-container alongside uvicorn.
"""
import os
# IMPORTANT: override DATABASE_URL BEFORE importing the app modules so they
# bind their engine to the test SQLite file.
os.environ["DATABASE_URL"] = "sqlite:///./test.db"

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.database import Base, engine, SessionLocal  # noqa: E402  — imported after env override


@pytest_asyncio.fixture
async def client():
    """Async HTTP client wired to a fresh SQLite-backed schema per test."""
    Base.metadata.create_all(bind=engine)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    Base.metadata.drop_all(bind=engine)
{auth_fixture}''')

        self._add_file("tests/test_api.py", f'''"""ACIR Generated — API Integration Tests."""
import pytest

pytestmark = pytest.mark.asyncio
{tests_str}
''')

        # pytest.ini
        self._add_file("pytest.ini", """[pytest]
asyncio_mode = auto
testpaths = tests
""")

    def _build_test_body(self, input_ref, valid=True):
        if not input_ref:
            return None
        ref_name = input_ref.get("$ref") if isinstance(input_ref, dict) else None
        if not ref_name or ref_name not in self.type_registry:
            return None

        record = self.type_registry[ref_name]
        fields = record.get("fields", [])
        if not fields:
            return None

        obj = {}
        for field in fields:
            fname = field.get("name", "")
            ftype = field.get("type", {})
            contracts = field.get("contracts", [])
            kind = ftype.get("kind", "") if isinstance(ftype, dict) else ""
            ref = ftype.get("$ref", "") if isinstance(ftype, dict) else ""

            if ref and ref in self.alias_registry:
                alias = self.alias_registry[ref]
                base = alias.get("base_type", {})
                kind = base.get("kind", "") if isinstance(base, dict) else ""
                contracts = alias.get("contracts", []) + contracts

            if valid:
                if kind == "string":
                    if "email" in fname.lower():
                        obj[fname] = "test@example.com"
                    else:
                        obj[fname] = f"Test {fname}"
                elif kind == "integer":
                    obj[fname] = 1
                elif kind == "decimal":
                    obj[fname] = 9.99
                elif kind == "boolean":
                    obj[fname] = True
                elif kind == "uuid":
                    obj[fname] = "550e8400-e29b-41d4-a716-446655440000"
                elif ref in self.enum_registry:
                    vals = self.enum_registry[ref].get("values", [])
                    obj[fname] = vals[0]["name"] if vals else "VALUE"
                else:
                    obj[fname] = f"test_{fname}"
            else:
                # Generate invalid data
                for c in contracts:
                    if isinstance(c, dict):
                        prim = c.get("primitive", "")
                        if prim == "C_RANGE" and c.get("min") is not None:
                            obj[fname] = c["min"] - 1
                            break
                        elif prim == "C_LENGTH" and c.get("max"):
                            obj[fname] = "x" * (c["max"] + 10)
                            break
                        elif prim == "C_PATTERN":
                            obj[fname] = "!!!invalid!!!"
                            break
                else:
                    if kind in ("integer", "decimal"):
                        obj[fname] = "not_a_number"

        return obj if obj else None

    # ─── README.md ─────────────────────────────────────────────────────────

    def _generate_readme(self, module: dict):
        name = module.get("name", "App")
        doc = module.get("doc", f"API {name}")
        exposed = module.get("exposed", [])
        types = module.get("types", [])
        units = module.get("units", [])
        entities = [n for n, r in self.type_registry.items() if r.get("identity")]

        ep_lines = []
        for ep in exposed:
            method = ep.get("method", "GET")
            route = ep.get("route", "")
            auth = "🔒" if ep.get("auth", {}).get("required") else "🌐"
            rm = ep.get("response_mapping", {}).get("success", {})
            code = rm.get("status_code", 200) if isinstance(rm, dict) else 200
            ep_lines.append(f"| {method} | `{route}` | {code} | {auth} |")
        ep_table = "\n".join(ep_lines)

        snake = to_snake(name)

        self._add_file("README.md", f"""# {name} — Python/FastAPI

> Généré par **ACIR** (Agent Code Intermediate Representation) — © Ld Labs
> Compilateur : `acir_compiler_fastapi` v{COMPILER_VERSION} · ACIR cible : {COMPILER_ACIR_VERSION}

{doc}

## Structure du projet

```
app/
├── __init__.py
├── main.py         # Application FastAPI (Swagger intégré)
├── database.py     # Configuration SQLAlchemy
├── models.py       # Modèles SQLAlchemy ({len(entities)} entités)
├── schemas.py      # Schémas Pydantic (validation des contrats)
├── service.py      # Logique métier ({len(units)} unités)
├── routes.py       # Routes FastAPI ({len(exposed)} endpoints)
├── errors.py       # Gestion d'erreurs (catch-all, jamais de leak)
└── security.py     # Headers OWASP, XSS, log masking
tests/
├── conftest.py     # Fixtures pytest (client async)
└── test_api.py     # Tests d'intégration + tests Swagger
requirements.txt
pytest.ini
.env
```

## Endpoints

| Méthode | Route | Code | Auth |
|---------|-------|------|------|
{ep_table}

🔒 = Authentification requise | 🌐 = Public

## Documentation API intégrée

L'API expose automatiquement sa documentation :

| URL | Description |
|-----|-------------|
| `/docs` | **Swagger UI** — interface interactive (Try It Out) |
| `/redoc` | **ReDoc** — documentation lisible |
| `/openapi.json` | **Spécification OpenAPI 3.1** (importable dans Postman) |
| `/health` | Health check |

## Prérequis

- Python 3.11+
- PostgreSQL 15+ (ou Docker)

## Démarrage rapide

```bash
# 1. Installer les dépendances
pip install -r requirements.txt

# 2. Démarrer PostgreSQL
docker run -d --name postgres -e POSTGRES_USER=acir -e POSTGRES_PASSWORD=acir \\
  -e POSTGRES_DB={snake} -p 5432:5432 postgres:16-alpine

# 3. Configurer l'environnement
cp .env .env.local
# Éditer .env.local si nécessaire

# 4. Lancer l'application
uvicorn app.main:app --reload --port 8080

# 5. Ouvrir Swagger UI
open http://localhost:8080/docs
```

## Tests

```bash
pytest -v
```

Les tests couvrent : happy path, validation des contrats, 404, et les 3 endpoints Swagger (docs, redoc, openapi.json).

## Build production

```bash
# Directement
uvicorn app.main:app --host 0.0.0.0 --port 8080 --workers 4

# Avec Docker
docker build -t {snake} .
docker run -p 8080:8080 -e DATABASE_URL=... {snake}
```

## Sécurité intégrée

- **Headers OWASP** : HSTS, X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy, Permissions-Policy
- **CORS restrictif** : origines configurables via `CORS_ORIGINS`
- **Middleware XSS** : détection et blocage des payloads XSS dans les query params
- **Rate limiting** : via slowapi (configurable par endpoint)
- **Body limit** : via middleware (anti-DoS)
- **Catch-all erreurs** : jamais de leak de stack traces en production
- **Log masking** : champs sensibles automatiquement masqués dans les logs
- **Request ID** : header X-Request-Id pour la traçabilité
- **Cache-Control** : no-store par défaut sur les réponses API

## Contrats ACIR compilés

| Contrat ACIR | Validation Pydantic |
|---|---|
| C_RANGE | `Field(ge=..., le=...)` |
| C_LENGTH | `Field(min_length=..., max_length=...)` |
| C_PATTERN | `Field(pattern=...)` |
| C_PRECISION | `Field(decimal_places=...)` |
| C_UNIQUE | `Column(unique=True)` (SQLAlchemy) |
| C_SANITIZE | `@field_validator` (trim, html_escape, strip_tags) |

## Généré par ACIR

Ce projet a été généré par le compilateur ACIR Python/FastAPI.
Le même document ACIR peut être compilé vers Java/Quarkus ou TypeScript/Fastify
pour obtenir un projet fonctionnellement équivalent.

📖 [Documentation ACIR](https://ldlabs.dev) — © Ld Labs
""")

    # ─── alembic/ — DB migrations (replaces Base.metadata.create_all) ─────

    def _generate_alembic(self, module: dict):
        snake = to_snake(module.get("name", "app"))
        self._add_file("alembic.ini", f"""[alembic]
script_location = alembic
prepend_sys_path = .
version_path_separator = os
sqlalchemy.url = postgresql://acir:acir@localhost:5432/{snake}

[loggers]
keys = root,sqlalchemy,alembic
[handlers]
keys = console
[formatters]
keys = generic
[logger_root]
level = WARN
handlers = console
qualname =
[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine
[logger_alembic]
level = INFO
handlers =
qualname = alembic
[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic
[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
""")

        self._add_file("alembic/env.py", '''"""ACIR Generated — Alembic env (autogenerate from app.models)."""
import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

from app.database import Base
import app.models  # noqa: F401  — registers entities on Base.metadata

config = context.config

# Override sqlalchemy.url from DATABASE_URL env var if set
if os.getenv("DATABASE_URL"):
    config.set_main_option("sqlalchemy.url", os.environ["DATABASE_URL"])

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
''')

        self._add_file("alembic/script.py.mako", '''"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

revision: str = ${repr(up_revision)}
down_revision: Union[str, None] = ${repr(down_revision)}
branch_labels: Union[str, Sequence[str], None] = ${repr(branch_labels)}
depends_on: Union[str, Sequence[str], None] = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
''')

        # Empty versions/ dir marker — Alembic needs the dir to exist
        self._add_file("alembic/versions/.gitkeep", "")

    # ─── pyproject.toml + .pre-commit-config.yaml ─────────────────────────

    def _generate_pyproject_pre_commit(self):
        self._add_file("pyproject.toml", """[tool.ruff]
line-length = 120
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "W", "I", "B", "UP", "C4", "PT"]
ignore = ["E501"]

[tool.ruff.format]
quote-style = "double"

[tool.mypy]
python_version = "3.11"
strict_optional = true
warn_unused_ignores = true
ignore_missing_imports = true

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
""")

        self._add_file(".pre-commit-config.yaml", """repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.7.0
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.13.0
    hooks:
      - id: mypy
        additional_dependencies: [types-requests]
        args: [--ignore-missing-imports]
""")

    # ─── Dockerfile + docker-compose.yml ──────────────────────────────────

    def _generate_dockerfile(self, module: dict):
        snake = to_snake(module.get("name", "app"))
        self._add_file("Dockerfile", """FROM python:3.12-slim AS base
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \\
        curl gcc libpq-dev \\
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY alembic/ ./alembic/
COPY alembic.ini ./
COPY tests/ ./tests/
COPY pytest.ini ./

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \\
    CMD curl -fsS http://localhost:8080/health || exit 1

# On first boot, autogenerate the initial migration from app.models if none exists,
# apply it, then launch the app. In a mature project, commit the generated file to git
# and remove the autogenerate step.
CMD ["sh", "-c", "set -e; ls alembic/versions/*.py >/dev/null 2>&1 || alembic revision --autogenerate -m initial; alembic upgrade head; exec uvicorn app.main:app --host 0.0.0.0 --port 8080"]
""")

        self._add_file(".dockerignore", """__pycache__
*.pyc
*.pyo
.venv
.env
.pytest_cache
.ruff_cache
.mypy_cache
.git
""")

        self._add_file("docker-compose.yml", f"""services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: acir
      POSTGRES_PASSWORD: acir
      POSTGRES_DB: {snake}
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U acir -d {snake}"]
      interval: 5s
      timeout: 5s
      retries: 10

  app:
    build: .
    depends_on:
      db:
        condition: service_healthy
    environment:
      DATABASE_URL: postgresql://acir:acir@db:5432/{snake}
      JWT_SECRET: ${{JWT_SECRET:-dev-only-jwt-secret-please-override-in-production}}
      AUTH_USER_ADMIN_PASSWORD: ${{AUTH_USER_ADMIN_PASSWORD:-admin}}
    ports:
      - "8080:8080"
""")


# ─── Entry point ───────────────────────────────────────────────────────────────

def compile_file(input_path: str, output_dir: str) -> int:
    try:
        with open(input_path, 'r') as f:
            doc = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"❌ Erreur: {e}")
        return 1

    module = doc.get("module")
    if not module:
        print("❌ Document ACIR invalide (clé 'module' manquante)")
        return 1

    # Banner version — traçabilité dans les logs CI / CLI / API.
    doc_version = doc.get("acir_version", "?")
    print(f"✨ acir_compiler_fastapi v{COMPILER_VERSION} (ACIR {COMPILER_ACIR_VERSION}) — input ACIR {doc_version}")
    def _norm(v):
        parts = (v or "").split(".")
        while len(parts) < 3:
            parts.append("0")
        return ".".join(parts[:3])
    if doc_version and _norm(doc_version) != _norm(COMPILER_ACIR_VERSION):
        print(f"⚠️  ACIR {doc_version} ≠ compilateur ACIR {COMPILER_ACIR_VERSION} — compatibilité best-effort")

    print(f"🐍 ACIR → Python/FastAPI")
    print(f"   Module: {module.get('name', '?')}")

    compiler = ACIRToFastAPICompiler()
    files = compiler.compile(doc)

    # Sécurité (V1) : containment — refuse tout chemin qui s'échappe d'output_dir
    # (noms ACIR joints en chemins ; un doc non validé pourrait viser `../`).
    # NO-OP pour les noms légitimes → golden byte-for-byte inchangé.
    out_root = os.path.realpath(output_dir)
    for path, content in files:
        full_path = os.path.join(output_dir, path)
        if os.path.commonpath([out_root, os.path.realpath(full_path)]) != out_root:
            raise ValueError(f"Chemin de sortie hors du répertoire cible refusé : {path!r}")
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, 'w') as f:
            f.write(content)
        print(f"   ✅ {path}")

    print(f"\n🎉 {len(files)} fichiers générés")
    print(f"   📖 Swagger UI : http://localhost:8080/docs")
    print(f"   📖 ReDoc      : http://localhost:8080/redoc")
    print(f"   📖 OpenAPI    : http://localhost:8080/openapi.json")
    return 0


def main():
    if len(sys.argv) < 2:
        print("Usage: python acir_compiler_fastapi.py <input.acir.json> [output_dir]")
        sys.exit(1)

    input_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "./generated-fastapi"
    sys.exit(compile_file(input_path, output_dir))


if __name__ == "__main__":
    main()

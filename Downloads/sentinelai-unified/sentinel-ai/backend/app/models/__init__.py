"""
Import every model here so a single `from app.core.db import Base` +
`import app.models` registers the full schema with Base.metadata — this
is what Alembic's autogenerate and `create_all` (dev only) rely on.
"""
from app.models.assessment import Assessment, AssessmentStatus, AssessmentType  # noqa: F401
from app.models.audit_log import AuditLog  # noqa: F401
from app.models.project import Project  # noqa: F401
from app.models.scope_rule import ScopeRule, ScopeRuleType  # noqa: F401
from app.models.user import User  # noqa: F401

# NOTE: app.models.response_intel (Phase 6) declares its OWN DeclarativeBase
# and is therefore NOT registered on app.core.db.Base here. It is a
# standalone subsystem in the original phase code; wiring it onto the core
# Base is left as a follow-up (see PROJECT_STRUCTURE.md → "Known gaps").

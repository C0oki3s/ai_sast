"""Production persistence contracts for PlaidNox Code Scanning."""

from .adapters import PostgresContextFabricStore, PostgresKnowledgeStore
from .database import DatabaseConfigurationError, DatabaseSettings, session_factory
from .models import Base
from .migrations import MigrationError, apply_migrations, migration_plan
from .repositories import (
    SECURITY_IR_CONTEXT_VERSION,
    CodeScanningRepository,
    EdgeInput,
    FindingDependencyInput,
    FindingEvidenceInput,
    InvestigationValue,
    HuntTaskInput,
    KnowledgeInput,
    PersistenceConflictError,
    ProductionControlError,
    ScanJobValue,
    SourceFileInput,
    SymbolInput,
    security_ir_inputs,
    snapshot_tree_hash,
    stable_id,
    unit_of_work,
)

__all__ = [
    "SECURITY_IR_CONTEXT_VERSION",
    "Base",
    "CodeScanningRepository",
    "DatabaseConfigurationError",
    "DatabaseSettings",
    "EdgeInput",
    "FindingDependencyInput",
    "FindingEvidenceInput",
    "InvestigationValue",
    "HuntTaskInput",
    "KnowledgeInput",
    "MigrationError",
    "PersistenceConflictError",
    "ProductionControlError",
    "PostgresContextFabricStore",
    "PostgresKnowledgeStore",
    "SourceFileInput",
    "ScanJobValue",
    "SymbolInput",
    "security_ir_inputs",
    "apply_migrations",
    "migration_plan",
    "session_factory",
    "snapshot_tree_hash",
    "stable_id",
    "unit_of_work",
]

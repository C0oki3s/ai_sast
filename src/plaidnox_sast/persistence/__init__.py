"""Production persistence contracts for PlaidNox Code Scanning."""

from .adapters import PostgresContextFabricStore, PostgresKnowledgeStore
from .database import DatabaseConfigurationError, DatabaseSettings, session_factory
from .models import Base
from .repositories import (
    SECURITY_IR_CONTEXT_VERSION,
    CodeScanningRepository,
    EdgeInput,
    FindingDependencyInput,
    FindingEvidenceInput,
    HuntTaskInput,
    KnowledgeInput,
    PersistenceConflictError,
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
    "HuntTaskInput",
    "KnowledgeInput",
    "PersistenceConflictError",
    "PostgresContextFabricStore",
    "PostgresKnowledgeStore",
    "SourceFileInput",
    "SymbolInput",
    "security_ir_inputs",
    "session_factory",
    "snapshot_tree_hash",
    "stable_id",
    "unit_of_work",
]

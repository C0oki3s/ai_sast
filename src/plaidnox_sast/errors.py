"""Shared root for every recognized AI/tool-chain stage error.

Pipeline orchestration still tolerates arbitrary exceptions per candidate or
stage so one bad provider response never loses an entire scan, but it
classifies each failure against this hierarchy so the audit trail can tell a
recognized, expected AI-stage failure apart from an unclassified exception
that likely signals a real code defect worth investigating.
"""

from __future__ import annotations


class AIStageError(RuntimeError):
    pass

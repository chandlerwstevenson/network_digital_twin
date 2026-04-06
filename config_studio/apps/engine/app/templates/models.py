"""Template data models — for type reference in engine."""
# Template models are defined in app.api.schemas (TemplateRule, RuleType)
# This module re-exports for convenience.

from app.api.schemas import TemplateRule, RuleType

__all__ = ["TemplateRule", "RuleType"]

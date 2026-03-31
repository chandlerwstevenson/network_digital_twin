"""
Diagnosis module for SDN fault diagnosis.

This module provides:
- base: Abstract diagnostic engine interface
- rule_based: Decision tree diagnostic engine
- llm_agent: Claude-based diagnostic agent
- ml_engine: Random Forest ML diagnostic engine
- feature_extractor: Telemetry-to-feature-vector conversion
"""

from .base import (
    BaseDiagnosticEngine,
    DiagnosisConfig,
    create_diagnosis,
    no_fault_result,
)
from .rule_based import RuleBasedEngine, AnalysisState, Finding
from .llm_agent import LLMAgent, MockLLMAgent
from .feature_extractor import FeatureExtractor
from .hybrid_engine import HybridEngine

# MLEngine import is deferred to avoid hard dependency on scikit-learn
# when only rule-based or LLM engines are needed.
try:
    from .ml_engine import MLEngine
except ImportError:
    MLEngine = None

__all__ = [
    # Base
    "BaseDiagnosticEngine",
    "DiagnosisConfig",
    "create_diagnosis",
    "no_fault_result",
    # Rule-based
    "RuleBasedEngine",
    "AnalysisState",
    "Finding",
    # LLM Agent
    "LLMAgent",
    "MockLLMAgent",
    # ML Engine
    "MLEngine",
    "FeatureExtractor",
    # Hybrid
    "HybridEngine",
]

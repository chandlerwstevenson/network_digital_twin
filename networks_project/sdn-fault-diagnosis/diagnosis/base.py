"""
Abstract base class for diagnostic engines.

Defines the common interface that both rule-based and LLM-based
diagnostic engines must implement.
"""

import logging
import time
from abc import ABC, abstractmethod
from typing import Optional

import sys
sys.path.insert(0, str(__file__).rsplit('/', 2)[0])

from telemetry.schemas import DiagnosisResult, NetworkSnapshot

logger = logging.getLogger(__name__)


class BaseDiagnosticEngine(ABC):
    """
    Abstract base class for network fault diagnostic engines.

    All diagnostic engines must implement the diagnose() method
    and maintain state for snapshot comparison if needed.
    """

    def __init__(self, name: str = "base"):
        """
        Initialize the diagnostic engine.

        Args:
            name: Human-readable name for this engine
        """
        self.name = name
        self._previous_snapshot: Optional[NetworkSnapshot] = None
        self._diagnosis_count = 0

    @abstractmethod
    def diagnose(
        self,
        snapshot: NetworkSnapshot,
        previous_snapshot: Optional[NetworkSnapshot] = None
    ) -> DiagnosisResult:
        """
        Analyze a network snapshot and produce a diagnosis.

        Args:
            snapshot: Current network state snapshot
            previous_snapshot: Previous snapshot for comparison (optional)

        Returns:
            DiagnosisResult with fault classification and details
        """
        pass

    def diagnose_with_history(self, snapshot: NetworkSnapshot) -> DiagnosisResult:
        """
        Diagnose using internal snapshot history.

        Automatically uses the previous snapshot stored internally
        for diff-based analysis.

        Args:
            snapshot: Current network state snapshot

        Returns:
            DiagnosisResult with fault classification and details
        """
        start_time = time.time()

        result = self.diagnose(snapshot, self._previous_snapshot)

        # Update timing
        elapsed_ms = int((time.time() - start_time) * 1000)
        result.diagnosis_time_ms = elapsed_ms

        # Store for next comparison
        self._previous_snapshot = snapshot
        self._diagnosis_count += 1

        logger.info(
            f"{self.name} diagnosis #{self._diagnosis_count}: "
            f"fault_detected={result.fault_detected}, "
            f"class={result.fault_class}, "
            f"time={elapsed_ms}ms"
        )

        return result

    def reset(self):
        """Reset engine state (clear history)."""
        self._previous_snapshot = None
        self._diagnosis_count = 0

    @property
    def has_history(self) -> bool:
        """Check if engine has previous snapshot for comparison."""
        return self._previous_snapshot is not None

    def get_stats(self) -> dict:
        """Get engine statistics."""
        return {
            "name": self.name,
            "diagnosis_count": self._diagnosis_count,
            "has_history": self.has_history,
        }


class DiagnosisConfig:
    """Configuration for diagnostic engines."""

    def __init__(
        self,
        error_rate_threshold: float = 1.0,
        drop_rate_threshold: float = 1.0,
        require_full_adjacency: bool = True,
        min_confidence: float = 0.5,
    ):
        """
        Initialize diagnosis configuration.

        Args:
            error_rate_threshold: Error rate (%) above which to flag anomaly
            drop_rate_threshold: Drop rate (%) above which to flag anomaly
            require_full_adjacency: Whether to require all neighbors to be Full
            min_confidence: Minimum confidence to report a fault
        """
        self.error_rate_threshold = error_rate_threshold
        self.drop_rate_threshold = drop_rate_threshold
        self.require_full_adjacency = require_full_adjacency
        self.min_confidence = min_confidence


# Standard diagnosis result helpers
def no_fault_result(reasoning: str = "No faults detected") -> DiagnosisResult:
    """Create a diagnosis result indicating no fault."""
    return DiagnosisResult(
        fault_detected=False,
        fault_class=None,
        location=None,
        confidence=1.0,
        reasoning=reasoning
    )


def create_diagnosis(
    fault_class: str,
    location: str,
    confidence: float,
    reasoning: str,
    affected_routers: list[str] = None,
    affected_interfaces: list[str] = None,
    affected_prefixes: list[str] = None,
    remediation: str = None
) -> DiagnosisResult:
    """
    Create a diagnosis result.

    Args:
        fault_class: Classification of the fault
        location: Affected component/location
        confidence: Confidence score (0-1)
        reasoning: Explanation of diagnosis
        affected_routers: List of affected router names
        affected_interfaces: List of affected interfaces
        affected_prefixes: List of affected prefixes
        remediation: Suggested fix

    Returns:
        DiagnosisResult instance
    """
    return DiagnosisResult(
        fault_detected=True,
        fault_class=fault_class,
        location=location,
        confidence=confidence,
        reasoning=reasoning,
        affected_routers=affected_routers or [],
        affected_interfaces=affected_interfaces or [],
        affected_prefixes=affected_prefixes or [],
        remediation=remediation
    )

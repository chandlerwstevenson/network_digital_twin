"""
Hybrid diagnostic engine with confidence-based defer logic.

Architecture:
    1. Rule-based engine runs first (fast, free)
    2. If confidence >= threshold → accept rule-based result
    3. If confidence < threshold → defer to LLM (slow, expensive)

This controls cost while maintaining accuracy: the LLM is only invoked
for ambiguous cases where the rule-based engine is uncertain.

Key metrics tracked:
    - defer_rate: fraction of cases sent to LLM
    - llm_cost_savings: fraction of LLM calls avoided vs always-LLM
    - accuracy by source: separate accuracy for rule-based-accepted vs LLM-deferred
"""

import logging
import time
from typing import Optional

import sys
sys.path.insert(0, str(__file__).rsplit('/', 2)[0])

from telemetry.schemas import DiagnosisResult, NetworkSnapshot

from .base import BaseDiagnosticEngine, no_fault_result
from .rule_based import RuleBasedEngine, DiagnosisConfig
from .llm_agent import LLMAgent, MockLLMAgent

logger = logging.getLogger(__name__)

DEFAULT_CONFIDENCE_THRESHOLD = 0.80


class HybridEngine(BaseDiagnosticEngine):
    """
    Hybrid rule-based + LLM engine with confidence-based routing.

    The rule-based engine acts as a fast, free triage layer. Only when
    its confidence falls below a configurable threshold does the engine
    escalate to the LLM for a second opinion.

    This produces three possible outcomes per diagnosis:
    - Rule-based accepted (confidence >= threshold)
    - LLM deferred (rule-based confidence < threshold)
    - LLM override (rule-based said no_fault but LLM disagrees, or vice versa)
    """

    def __init__(
        self,
        rule_engine: RuleBasedEngine = None,
        llm_engine: BaseDiagnosticEngine = None,
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    ):
        super().__init__(name="hybrid")
        self.rule_engine = rule_engine or RuleBasedEngine()
        self.llm_engine = llm_engine
        self.confidence_threshold = confidence_threshold

        # Tracking
        self._total_diagnoses = 0
        self._rule_accepted = 0
        self._llm_deferred = 0

    def diagnose(
        self,
        snapshot: NetworkSnapshot,
        previous_snapshot: Optional[NetworkSnapshot] = None,
    ) -> DiagnosisResult:
        start_time = time.time()
        self._total_diagnoses += 1

        # Stage 1: rule-based triage
        rb_result = self.rule_engine.diagnose(snapshot, previous_snapshot)

        # Decision: accept or defer?
        should_defer = self._should_defer(rb_result)

        if not should_defer:
            # Accept rule-based result
            self._rule_accepted += 1
            result = DiagnosisResult(
                fault_detected=rb_result.fault_detected,
                fault_class=rb_result.fault_class,
                location=rb_result.location,
                affected_routers=rb_result.affected_routers,
                affected_interfaces=rb_result.affected_interfaces,
                affected_prefixes=rb_result.affected_prefixes,
                confidence=rb_result.confidence,
                reasoning=f"[HYBRID:rule-based accepted, conf={rb_result.confidence:.2f}] {rb_result.reasoning}",
                remediation=rb_result.remediation,
                diagnosis_time_ms=int((time.time() - start_time) * 1000),
                raw_output=f'{{"source": "rule_based", "rb_confidence": {rb_result.confidence}, "threshold": {self.confidence_threshold}}}',
            )
            return result

        # Stage 2: defer to LLM
        self._llm_deferred += 1

        if self.llm_engine is None:
            # No LLM available — return rule-based with a note
            logger.warning("Hybrid engine wants to defer but no LLM configured")
            result = DiagnosisResult(
                fault_detected=rb_result.fault_detected,
                fault_class=rb_result.fault_class,
                location=rb_result.location,
                affected_routers=rb_result.affected_routers,
                affected_interfaces=rb_result.affected_interfaces,
                affected_prefixes=rb_result.affected_prefixes,
                confidence=rb_result.confidence,
                reasoning=f"[HYBRID:defer-wanted, no LLM] {rb_result.reasoning}",
                remediation=rb_result.remediation,
                diagnosis_time_ms=int((time.time() - start_time) * 1000),
                raw_output=f'{{"source": "rule_based_fallback", "rb_confidence": {rb_result.confidence}, "threshold": {self.confidence_threshold}}}',
            )
            return result

        llm_result = self.llm_engine.diagnose(snapshot, previous_snapshot)

        # Build hybrid reasoning showing the escalation
        reasoning = (
            f"[HYBRID:deferred to LLM, rb_conf={rb_result.confidence:.2f} < {self.confidence_threshold}] "
            f"Rule-based said: {rb_result.fault_class or 'no_fault'} (conf={rb_result.confidence:.2f}). "
            f"LLM said: {llm_result.fault_class or 'no_fault'} (conf={llm_result.confidence:.2f}). "
            f"Using LLM result. LLM reasoning: {llm_result.reasoning}"
        )

        result = DiagnosisResult(
            fault_detected=llm_result.fault_detected,
            fault_class=llm_result.fault_class,
            location=llm_result.location,
            affected_routers=llm_result.affected_routers,
            affected_interfaces=llm_result.affected_interfaces,
            affected_prefixes=llm_result.affected_prefixes,
            confidence=llm_result.confidence,
            reasoning=reasoning,
            remediation=llm_result.remediation,
            diagnosis_time_ms=int((time.time() - start_time) * 1000),
            raw_output=f'{{"source": "llm_deferred", "rb_confidence": {rb_result.confidence}, "rb_class": "{rb_result.fault_class}", "llm_class": "{llm_result.fault_class}", "threshold": {self.confidence_threshold}}}',
        )
        return result

    def _should_defer(self, rb_result: DiagnosisResult) -> bool:
        """
        Decide whether to defer to the LLM.

        Defer when:
        - Rule-based confidence is below threshold
        - Rule-based classified as "unknown"
        - Rule-based found no fault but confidence is low (hedging)
        """
        if rb_result.fault_class == "unknown":
            return True

        if rb_result.confidence < self.confidence_threshold:
            return True

        # If rule-based says no fault but confidence < 1.0, something is ambiguous
        if not rb_result.fault_detected and rb_result.confidence < 0.9:
            return True

        return False

    @property
    def defer_rate(self) -> float:
        """Fraction of diagnoses deferred to LLM."""
        if self._total_diagnoses == 0:
            return 0.0
        return self._llm_deferred / self._total_diagnoses

    @property
    def llm_cost_savings(self) -> float:
        """Fraction of LLM calls saved vs always-LLM approach."""
        if self._total_diagnoses == 0:
            return 0.0
        return self._rule_accepted / self._total_diagnoses

    def get_stats(self) -> dict:
        stats = super().get_stats()
        stats.update({
            "confidence_threshold": self.confidence_threshold,
            "total_diagnoses": self._total_diagnoses,
            "rule_accepted": self._rule_accepted,
            "llm_deferred": self._llm_deferred,
            "defer_rate": self.defer_rate,
            "llm_cost_savings": self.llm_cost_savings,
            "llm_engine_name": self.llm_engine.name if self.llm_engine else None,
        })
        return stats

    def reset(self):
        super().reset()
        self.rule_engine.reset()
        if self.llm_engine:
            self.llm_engine.reset()
        self._total_diagnoses = 0
        self._rule_accepted = 0
        self._llm_deferred = 0

"""
Unified ProvGuard Defense Pipeline combining lineage tracking, conformance evaluation,
quarantine vault, sanitization, and circuit breaking.
"""

from __future__ import annotations

import logging
import time
from typing import Optional
from provguard.core.types import (
    AgentMessage,
    SecurityEvaluationResult,
    DefenseAction,
    RiskTier,
)
from provguard.provenance.tracker import ProvenanceTracker
from provguard.evaluator.conformance import ConformanceEngine
from provguard.defense.quarantine import QuarantineVault
from provguard.defense.sanitizer import PayloadSanitizer
from provguard.defense.circuit_breaker import CircuitBreaker

logger = logging.getLogger("provguard.defense.pipeline")


class DefensePipeline:
    """
    Complete defense runtime engine.
    """

    def __init__(
        self,
        tracker: Optional[ProvenanceTracker] = None,
        conformance_engine: Optional[ConformanceEngine] = None,
        quarantine_vault: Optional[QuarantineVault] = None,
        circuit_breaker: Optional[CircuitBreaker] = None,
    ):
        self.tracker = tracker or ProvenanceTracker()
        self.conformance = conformance_engine or ConformanceEngine()
        self.quarantine = quarantine_vault or QuarantineVault()
        self.circuit_breaker = circuit_breaker or CircuitBreaker()

    def evaluate(self, message: AgentMessage) -> SecurityEvaluationResult:
        """
        Executes end-to-end provenance-aware security inspection.
        """
        t0 = time.perf_counter()

        # 1. Register lineage in provenance tracker
        self.tracker.record_message(message)

        # 2. Check Circuit Breaker for network cascades
        tripped, trip_reason = self.circuit_breaker.check_message(message)
        if tripped:
            return SecurityEvaluationResult(
                message_id=message.id,
                is_safe=False,
                defense_action=DefenseAction.CIRCUIT_BREAK,
                risk_score=1.0,
                risk_tier=RiskTier.CRITICAL,
                reasons=[f"Circuit Breaker Tripped: {trip_reason}"],
                taint_propagation_index=message.provenance.taint_score,
                latency_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # 3. Conformance Evaluation
        eval_result = self.conformance.evaluate(message)

        # 4. Handle Quarantine or Sanitization if needed
        if eval_result.defense_action == DefenseAction.QUARANTINE:
            self.quarantine.isolate(message, eval_result)
        elif eval_result.defense_action == DefenseAction.SANITIZE:
            eval_result.sanitized_content = PayloadSanitizer.sanitize(message.content)

        return eval_result

    def reset(self) -> None:
        """Resets state of all defense modules."""
        self.tracker.clear()
        self.quarantine.clear()
        self.circuit_breaker.reset()

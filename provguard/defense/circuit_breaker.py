"""
Cascading propagation anomaly detector and MAS circuit breaker.
"""

from __future__ import annotations

import logging
from typing import Dict, List
from provguard.core.types import AgentMessage

logger = logging.getLogger("provguard.defense.circuit_breaker")


class CircuitBreaker:
    """
    Monitors inter-agent communication cascades and trips when malicious
    propagation depth or anomaly frequency exceeds safety thresholds.
    """

    def __init__(self, max_allowed_depth: int = 6, max_tainted_relays: int = 3):
        self.max_allowed_depth = max_allowed_depth
        self.max_tainted_relays = max_tainted_relays
        self._tainted_message_counts_by_session: Dict[str, int] = {}
        self._is_tripped: bool = False
        self._trip_reason: str = ""

    def check_message(self, message: AgentMessage) -> tuple[bool, str]:
        """
        Evaluates whether the message breaches circuit breaker thresholds.
        Returns (should_trip, reason).
        """
        if self._is_tripped:
            return True, f"Circuit breaker is already TRIPPED: {self._trip_reason}"

        prov = message.provenance
        session_id = message.session_id

        # 1. Depth check
        if prov.hop_count > self.max_allowed_depth:
            self._is_tripped = True
            self._trip_reason = (
                f"Maximum propagation depth exceeded ({prov.hop_count} > {self.max_allowed_depth}) "
                f"for session {session_id}."
            )
            logger.critical(self._trip_reason)
            return True, self._trip_reason

        # 2. Taint accumulation check
        if prov.taint_score > 0.70:
            count = self._tainted_message_counts_by_session.get(session_id, 0) + 1
            self._tainted_message_counts_by_session[session_id] = count
            if count > self.max_tainted_relays:
                self._is_tripped = True
                self._trip_reason = (
                    f"Cascading taint limit exceeded ({count} > {self.max_tainted_relays} high-taint messages) "
                    f"in session {session_id}."
                )
                logger.critical(self._trip_reason)
                return True, self._trip_reason

        return False, "Circuit normal"

    def reset(self) -> None:
        self._is_tripped = False
        self._trip_reason = ""
        self._tainted_message_counts_by_session.clear()

    @property
    def is_tripped(self) -> bool:
        return self._is_tripped

"""
Message bus with runtime interception, security hook injection, and provenance logging.
"""

from __future__ import annotations

import time
import logging
from typing import Any, Callable, Dict, List, Optional
from provguard.core.types import (
    AgentMessage,
    DefenseAction,
    SecurityEvaluationResult,
    RiskTier,
)

logger = logging.getLogger("provguard.bus")


class MessageBus:
    """
    Central event and message communication bus with integrated
    security evaluation hooks and provenance interception.
    """

    def __init__(self, defense_pipeline: Optional[Any] = None, enable_defense: bool = True):
        self.defense_pipeline = defense_pipeline
        self.enable_defense = enable_defense
        self.subscribers: Dict[str, Callable[[AgentMessage], Any]] = {}
        self.message_history: List[AgentMessage] = []
        self.evaluations: List[SecurityEvaluationResult] = []
        self.quarantine_vault: List[AgentMessage] = []
        self.blocked_messages: List[AgentMessage] = []
        self.metrics: Dict[str, Any] = {
            "total_messages": 0,
            "blocked_messages": 0,
            "quarantined_messages": 0,
            "sanitized_messages": 0,
            "allowed_messages": 0,
            "total_latency_ms": 0.0,
        }

    def register_agent(self, agent_id: str, handler: Callable[[AgentMessage], Any]) -> None:
        """Subscribes an agent handler to the message bus."""
        self.subscribers[agent_id] = handler

    def dispatch(self, message: AgentMessage) -> Optional[Any]:
        """
        Dispatches a message from sender to receiver through runtime defense.
        Returns the result from the recipient agent handler, or None if blocked/quarantined.
        """
        t0 = time.perf_counter()
        self.metrics["total_messages"] += 1
        self.message_history.append(message)

        # 1. Run defense evaluation if enabled
        if self.enable_defense and self.defense_pipeline is not None:
            eval_result: SecurityEvaluationResult = self.defense_pipeline.evaluate(message)
            self.evaluations.append(eval_result)

            eval_latency = (time.perf_counter() - t0) * 1000.0
            eval_result.latency_ms = eval_latency
            self.metrics["total_latency_ms"] += eval_latency

            if eval_result.defense_action == DefenseAction.BLOCK:
                self.metrics["blocked_messages"] += 1
                self.blocked_messages.append(message)
                logger.warning(
                    f"[DEFENSE BLOCK] Message {message.id[:8]} from {message.sender} to "
                    f"{message.receiver} blocked. Reasons: {eval_result.reasons}"
                )
                return {
                    "status": "BLOCKED",
                    "reason": eval_result.reasons,
                    "risk_score": eval_result.risk_score,
                }

            elif eval_result.defense_action == DefenseAction.QUARANTINE:
                self.metrics["quarantined_messages"] += 1
                self.quarantine_vault.append(message)
                logger.warning(
                    f"[DEFENSE QUARANTINE] Message {message.id[:8]} isolated in quarantine. "
                    f"Risk Score: {eval_result.risk_score:.2f} ({eval_result.risk_tier.value})"
                )
                return {
                    "status": "QUARANTINED",
                    "reason": eval_result.reasons,
                    "risk_score": eval_result.risk_score,
                }

            elif eval_result.defense_action == DefenseAction.SANITIZE:
                self.metrics["sanitized_messages"] += 1
                if eval_result.sanitized_content is not None:
                    message.content = eval_result.sanitized_content
                logger.info(
                    f"[DEFENSE SANITIZE] Message {message.id[:8]} sanitized before delivery to {message.receiver}."
                )

            elif eval_result.defense_action == DefenseAction.ALLOW:
                self.metrics["allowed_messages"] += 1

        else:
            # Baseline mode (no defense)
            self.metrics["allowed_messages"] += 1

        # 2. Deliver to target recipient
        handler = self.subscribers.get(message.receiver)
        if handler:
            return handler(message)
        else:
            logger.warning(f"No subscriber registered for recipient: {message.receiver}")
            return None

    def reset(self) -> None:
        """Resets bus state and metrics."""
        self.message_history.clear()
        self.evaluations.clear()
        self.quarantine_vault.clear()
        self.blocked_messages.clear()
        self.metrics = {
            "total_messages": 0,
            "blocked_messages": 0,
            "quarantined_messages": 0,
            "sanitized_messages": 0,
            "allowed_messages": 0,
            "total_latency_ms": 0.0,
        }

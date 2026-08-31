"""
Quarantine manager for isolating, logging, and inspecting compromised messages.
"""

from __future__ import annotations

import logging
import time
from typing import Dict, List, Optional
from provguard.core.types import AgentMessage, SecurityEvaluationResult

logger = logging.getLogger("provguard.defense.quarantine")


class QuarantinedItem:
    """Encapsulates a quarantined message along with its evaluation metadata."""

    def __init__(self, message: AgentMessage, eval_result: SecurityEvaluationResult):
        self.message = message
        self.eval_result = eval_result
        self.quarantined_at = time.time()
        self.status = "QUARANTINED"  # QUARANTINED, RELEASED, DROPPED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_id": self.message.id,
            "sender": self.message.sender,
            "sender_role": self.message.sender_role.value,
            "receiver": self.message.receiver,
            "receiver_role": self.message.receiver_role.value,
            "content": self.message.content,
            "risk_score": self.eval_result.risk_score,
            "risk_tier": self.eval_result.risk_tier.value,
            "reasons": self.eval_result.reasons,
            "quarantined_at": self.quarantined_at,
            "status": self.status,
        }


class QuarantineVault:
    """
    Isolated containment vault for suspended messages.
    Prevents execution while allowing forensic auditing.
    """

    def __init__(self):
        self._vault: Dict[str, QuarantinedItem] = {}

    def isolate(self, message: AgentMessage, eval_result: SecurityEvaluationResult) -> QuarantinedItem:
        """Stores a flagged message in the quarantine vault."""
        item = QuarantinedItem(message, eval_result)
        self._vault[message.id] = item
        logger.info(f"Isolated message {message.id} in quarantine vault. Reasons: {eval_result.reasons}")
        return item

    def get(self, message_id: str) -> Optional[QuarantinedItem]:
        return self._vault.get(message_id)

    def list_all(self) -> List[QuarantinedItem]:
        return list(self._vault.values())

    def count(self) -> int:
        return len(self._vault)

    def clear(self) -> None:
        self._vault.clear()

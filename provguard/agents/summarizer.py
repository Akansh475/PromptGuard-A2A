"""
Summarizer Agent for text synthesis, report compilation, and intermediate relay.
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from provguard.core.types import (
    AgentRole,
    ActionType,
    TrustLevel,
    AgentMessage,
)
from provguard.agents.base import BaseAgent

logger = logging.getLogger("provguard.agents.summarizer")


class SummarizerAgent(BaseAgent):
    """
    Summarizes content and produces digest reports.
    Vulnerable to acting as an unintentional relay agent for malicious prompts.
    """

    def __init__(self, agent_id: str = "summarizer_01", bus: Optional[Any] = None):
        super().__init__(
            agent_id=agent_id,
            role=AgentRole.SUMMARIZER,
            trust_level=TrustLevel.SEMI_TRUSTED_WORKER,
            bus=bus,
        )

    def handle_message(self, message: AgentMessage) -> Any:
        """Summarizes input and forwards the result back to sender or user proxy."""
        raw_text = message.content
        logger.info(f"[{self.agent_id}] Summarizing {len(raw_text)} characters from {message.sender}.")

        # If malicious override instructions are present, standard LLMs often pass them through
        summary = f"[Executive Summary] {raw_text}"

        target = "user_proxy_01" if message.sender != "user_proxy_01" else "planner_01"
        target_role = AgentRole.USER_PROXY if target == "user_proxy_01" else AgentRole.PLANNER

        return self.send_message(
            receiver=target,
            receiver_role=target_role,
            action_type=ActionType.INFORM,
            content=summary,
            parent_message=message,
            transformation_name="SUMMARIZATION_TRANSFORMATION",
            transformation_desc=f"Summarizer condensed document from {message.sender}",
        )

"""
Base Agent class with lifecycle hooks, message sending, and provenance propagation.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional
from provguard.core.types import (
    AgentMessage,
    AgentRole,
    ActionType,
    ProvenanceRecord,
    TrustLevel,
    ToolCallRequest,
)

logger = logging.getLogger("provguard.agents.base")


class BaseAgent:
    """
    Abstract base class for all collaborative agents in the MAS.
    """

    def __init__(
        self,
        agent_id: str,
        role: AgentRole,
        trust_level: TrustLevel = TrustLevel.SEMI_TRUSTED_WORKER,
        bus: Optional[Any] = None,
    ):
        self.agent_id = agent_id
        self.role = role
        self.trust_level = trust_level
        self.bus = bus
        self.inbox: List[AgentMessage] = []
        self.outbox: List[AgentMessage] = []

        if self.bus is not None:
            self.bus.register_agent(self.agent_id, self.receive_message)

    def receive_message(self, message: AgentMessage) -> Any:
        """Called when a message is delivered to this agent by the MessageBus."""
        self.inbox.append(message)
        logger.info(f"[{self.agent_id} ({self.role.value})] Received message from {message.sender}: {message.content[:60]}...")
        return self.handle_message(message)

    def handle_message(self, message: AgentMessage) -> Any:
        """Override in subclasses to implement agent-specific logic."""
        return {"status": "ACK", "agent": self.agent_id}

    def send_message(
        self,
        receiver: str,
        receiver_role: AgentRole,
        action_type: ActionType,
        content: str,
        parent_message: Optional[AgentMessage] = None,
        tool_call: Optional[ToolCallRequest] = None,
        transformation_name: str = "FORWARD",
        transformation_desc: str = "",
    ) -> Any:
        """
        Creates and transmits a message to a recipient, automatically
        preserving or deriving the provenance lineage record.
        """
        session_id = parent_message.session_id if parent_message else "default_session"

        if parent_message is not None:
            prov = parent_message.provenance.derive_child(
                new_source_id=self.agent_id,
                new_source_role=self.role,
                new_target_id=receiver,
                new_target_role=receiver_role,
                new_content=content,
                transformation_name=transformation_name,
                transformation_desc=transformation_desc,
            )
        else:
            prov = ProvenanceRecord.create_root(
                source_id=self.agent_id,
                role=self.role,
                trust=self.trust_level,
                content=content,
                target_id=receiver,
                target_role=receiver_role,
            )

        msg = AgentMessage(
            session_id=session_id,
            sender=self.agent_id,
            sender_role=self.role,
            receiver=receiver,
            receiver_role=receiver_role,
            action_type=action_type,
            content=content,
            tool_call=tool_call,
            provenance=prov,
        )
        self.outbox.append(msg)

        if self.bus is not None:
            return self.bus.dispatch(msg)
        return None

    def reset(self) -> None:
        self.inbox.clear()
        self.outbox.clear()

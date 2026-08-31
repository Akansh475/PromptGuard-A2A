"""
User Proxy Agent representing the human operator or system orchestrator.
"""

from __future__ import annotations

from typing import Any, Optional
from provguard.core.types import (
    AgentRole,
    ActionType,
    TrustLevel,
    AgentMessage,
    ProvenanceRecord,
)
from provguard.agents.base import BaseAgent


class UserProxyAgent(BaseAgent):
    """
    Entry point for user tasks. Holds verified high trust (SYSTEM_ROOT / CORE_ORCHESTRATOR).
    """

    def __init__(self, agent_id: str = "user_proxy_01", bus: Optional[Any] = None):
        super().__init__(
            agent_id=agent_id,
            role=AgentRole.USER_PROXY,
            trust_level=TrustLevel.SYSTEM_ROOT,
            bus=bus,
        )

    def initiate_task(self, prompt: str, target_agent: str = "planner_01", session_id: str = "session_01") -> Any:
        """Submits a new root task to the planning agent."""
        prov = ProvenanceRecord.create_root(
            source_id=self.agent_id,
            role=self.role,
            trust=self.trust_level,
            content=prompt,
            target_id=target_agent,
            target_role=AgentRole.PLANNER,
        )
        msg = AgentMessage(
            session_id=session_id,
            sender=self.agent_id,
            sender_role=self.role,
            receiver=target_agent,
            receiver_role=AgentRole.PLANNER,
            action_type=ActionType.DELEGATE,
            content=prompt,
            provenance=prov,
        )
        self.outbox.append(msg)
        if self.bus is not None:
            return self.bus.dispatch(msg)
        return None

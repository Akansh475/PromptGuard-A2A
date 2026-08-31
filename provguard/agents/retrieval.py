"""
Retrieval Agent responsible for ingesting external data, web documents, and APIs.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional
from provguard.core.types import (
    AgentRole,
    ActionType,
    TrustLevel,
    AgentMessage,
    ProvenanceRecord,
)
from provguard.agents.base import BaseAgent

logger = logging.getLogger("provguard.agents.retrieval")


class RetrievalAgent(BaseAgent):
    """
    Fetches untrusted external data and assigns appropriate low trust provenance.
    """

    def __init__(
        self,
        agent_id: str = "retrieval_01",
        bus: Optional[Any] = None,
        mock_data_store: Optional[Dict[str, str]] = None,
    ):
        super().__init__(
            agent_id=agent_id,
            role=AgentRole.RETRIEVAL,
            trust_level=TrustLevel.SEMI_TRUSTED_WORKER,
            bus=bus,
        )
        self.mock_data_store = mock_data_store or {}

    def handle_message(self, message: AgentMessage) -> Any:
        """Handles a query/request for external data retrieval."""
        query = message.content
        logger.info(f"[{self.agent_id}] Processing retrieval query: {query}")

        # Retrieve matched external document or fallback
        retrieved_content = self.mock_data_store.get(
            query,
            f"Retrieved external document for query '{query}': Benign domain knowledge and research summary."
        )

        # Ingestion provenance creates an UNTRUSTED_EXTERNAL origin record
        ext_origin_id = f"external_doc_{abs(hash(query)) % 10000}"
        ext_prov = ProvenanceRecord.create_root(
            source_id=ext_origin_id,
            role=AgentRole.RETRIEVAL,
            trust=TrustLevel.UNTRUSTED_EXTERNAL,
            content=retrieved_content,
            target_id=message.sender,
            target_role=message.sender_role,
        )

        # Connect ancestry to the query request parent
        ext_prov.parent_ids = [message.id]

        response_msg = AgentMessage(
            session_id=message.session_id,
            sender=self.agent_id,
            sender_role=self.role,
            receiver=message.sender,
            receiver_role=message.sender_role,
            action_type=ActionType.INFORM,
            content=retrieved_content,
            provenance=ext_prov,
        )
        self.outbox.append(response_msg)

        if self.bus is not None:
            return self.bus.dispatch(response_msg)
        return {"status": "RETRIEVED", "content": retrieved_content}

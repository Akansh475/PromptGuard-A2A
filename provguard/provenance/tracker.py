"""
Provenance tracker and message lineage registry.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set
from provguard.core.types import AgentMessage, ProvenanceRecord, TrustLevel, AgentRole

logger = logging.getLogger("provguard.provenance.tracker")


class ProvenanceTracker:
    """
    Central registry that logs, stores, and traces message lineage across the MAS.
    """

    def __init__(self):
        self._records_by_id: Dict[str, ProvenanceRecord] = {}
        self._records_by_message_id: Dict[str, ProvenanceRecord] = {}
        self._adjacency_forward: Dict[str, Set[str]] = {}  # parent_msg_id -> set of child_msg_ids
        self._adjacency_backward: Dict[str, Set[str]] = {} # child_msg_id -> set of parent_msg_ids

    def record_message(self, message: AgentMessage) -> ProvenanceRecord:
        """Stores message provenance record and updates the causal DAG index."""
        record = message.provenance
        self._records_by_id[record.record_id] = record
        self._records_by_message_id[message.id] = record

        if message.id not in self._adjacency_backward:
            self._adjacency_backward[message.id] = set()

        for pid in record.parent_ids:
            if pid not in self._adjacency_forward:
                self._adjacency_forward[pid] = set()
            self._adjacency_forward[pid].add(message.id)
            self._adjacency_backward[message.id].add(pid)

        return record

    def get_record_by_message_id(self, message_id: str) -> Optional[ProvenanceRecord]:
        """Retrieves provenance record for a given message ID."""
        return self._records_by_message_id.get(message_id)

    def trace_ancestry(self, message_id: str) -> List[ProvenanceRecord]:
        """
        Reconstructs chronological causal chain from root ancestor to target message.
        """
        chain: List[ProvenanceRecord] = []
        current_id: Optional[str] = message_id
        visited: Set[str] = set()

        while current_id and current_id not in visited:
            visited.add(current_id)
            rec = self._records_by_message_id.get(current_id)
            if not rec:
                break
            chain.append(rec)
            if rec.parent_ids:
                current_id = rec.parent_ids[0]
            else:
                current_id = None

        # Return root-first order
        return list(reversed(chain))

    def get_taint_propagation_chain(self, message_id: str) -> List[Dict[str, Any]]:
        """
        Returns structured explanation of how taint flowed through intermediate agents.
        """
        ancestry = self.trace_ancestry(message_id)
        report: List[Dict[str, Any]] = []

        for rec in ancestry:
            report.append({
                "message_id": rec.message_id,
                "agent_id": rec.source_agent_id,
                "role": rec.source_role.value if isinstance(rec.source_role, AgentRole) else str(rec.source_role),
                "target_agent_id": rec.target_agent_id,
                "hop_count": rec.hop_count,
                "taint_score": rec.taint_score,
                "transformations": [t.step for t in rec.transformations],
                "root_origin": rec.root_source_id,
                "root_trust": rec.root_trust.name if isinstance(rec.root_trust, TrustLevel) else str(rec.root_trust),
            })
        return report

    def get_all_records(self) -> List[ProvenanceRecord]:
        return list(self._records_by_id.values())

    def clear(self) -> None:
        self._records_by_id.clear()
        self._records_by_message_id.clear()
        self._adjacency_forward.clear()
        self._adjacency_backward.clear()

"""
Graph representations, DAG analytics, and graph serialization for provenance lineage.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set
from provguard.core.types import ProvenanceRecord, AgentMessage


class ProvenanceGraph:
    """
    Builds and analyzes the Directed Acyclic Graph (DAG) of multi-agent communication.
    """

    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []

    def add_message(self, message: AgentMessage) -> None:
        """Adds message as a node and creates edges from parent message nodes."""
        prov = message.provenance
        node_id = message.id

        self.nodes[node_id] = {
            "id": node_id,
            "label": f"{message.sender_role.value} -> {message.receiver_role.value}",
            "sender": message.sender,
            "sender_role": message.sender_role.value,
            "receiver": message.receiver,
            "receiver_role": message.receiver_role.value,
            "action_type": message.action_type.value,
            "content_preview": (message.content[:80] + "...") if len(message.content) > 80 else message.content,
            "hop_count": prov.hop_count,
            "taint_score": round(prov.taint_score, 3),
            "root_source": prov.root_source_id,
            "root_trust": prov.root_trust.name,
            "has_tool_call": message.tool_call is not None,
            "tool_capability": message.tool_call.capability.value if message.tool_call else None,
            "timestamp": message.created_at,
        }

        for pid in prov.parent_ids:
            self.edges.append({
                "source": pid,
                "target": node_id,
                "relationship": "DERIVED_FROM",
            })

    def get_max_depth(self) -> int:
        """Returns maximum propagation depth (hop count) in the current DAG."""
        if not self.nodes:
            return 0
        return max(n["hop_count"] for n in self.nodes.values())

    def get_taint_hotspots(self, threshold: float = 0.5) -> List[Dict[str, Any]]:
        """Identifies messages with high taint scores."""
        return [n for n in self.nodes.values() if n["taint_score"] >= threshold]

    def to_dict(self) -> Dict[str, Any]:
        """Serializes graph to JSON-compatible format for visualization."""
        return {
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
            "summary": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "max_depth": self.get_max_depth(),
            },
        }

    def clear(self) -> None:
        self.nodes.clear()
        self.edges.clear()

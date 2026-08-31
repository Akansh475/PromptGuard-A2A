"""
Unit tests for Provenance Lineage Tracking and Cryptographic Integrity.
"""

import unittest
from provguard.core.types import (
    ProvenanceRecord,
    TrustLevel,
    AgentRole,
    AgentMessage,
    ActionType,
)
from provguard.provenance.tracker import ProvenanceTracker
from provguard.provenance.graph import ProvenanceGraph
from provguard.core.security import compute_content_hash, calculate_shannon_entropy


class TestProvenanceSystem(unittest.TestCase):
    def test_root_creation_and_derivation(self):
        # 1. Create root record
        root_rec = ProvenanceRecord.create_root(
            source_id="external_crawler",
            role=AgentRole.RETRIEVAL,
            trust=TrustLevel.UNTRUSTED_EXTERNAL,
            content="Sample raw scraped text",
            target_id="planner_01",
            target_role=AgentRole.PLANNER,
        )
        self.assertEqual(root_rec.hop_count, 0)
        self.assertAlmostEqual(root_rec.taint_score, 0.9, places=2)
        self.assertTrue(len(root_rec.content_hash) == 64)

        # 2. Derive child record (Planner transforms data)
        child_rec = root_rec.derive_child(
            new_source_id="planner_01",
            new_source_role=AgentRole.PLANNER,
            new_target_id="summarizer_01",
            new_target_role=AgentRole.SUMMARIZER,
            new_content="Summarized planning digest",
            transformation_name="SUMMARIZE",
        )
        self.assertEqual(child_rec.hop_count, 1)
        self.assertEqual(child_rec.root_source_id, "external_crawler")
        self.assertEqual(child_rec.root_trust, TrustLevel.UNTRUSTED_EXTERNAL)
        self.assertEqual(child_rec.parent_ids, [root_rec.message_id])
        self.assertEqual(len(child_rec.transformations), 2)

    def test_tracker_ancestry_resolution(self):
        tracker = ProvenanceTracker()

        # Step 1: External Origin
        msg1_prov = ProvenanceRecord.create_root(
            source_id="untrusted_web",
            role=AgentRole.RETRIEVAL,
            trust=TrustLevel.UNTRUSTED_EXTERNAL,
            content="Raw web page payload",
            target_id="retrieval_01",
            target_role=AgentRole.RETRIEVAL,
        )
        msg1 = AgentMessage(
            id="msg_001",
            sender="untrusted_web",
            sender_role=AgentRole.RETRIEVAL,
            receiver="retrieval_01",
            receiver_role=AgentRole.RETRIEVAL,
            action_type=ActionType.INFORM,
            content="Raw web page payload",
            provenance=msg1_prov,
        )
        tracker.record_message(msg1)

        # Step 2: Retrieval to Planner
        msg2_prov = msg1_prov.derive_child(
            new_source_id="retrieval_01",
            new_source_role=AgentRole.RETRIEVAL,
            new_target_id="planner_01",
            new_target_role=AgentRole.PLANNER,
            new_content="Parsed article",
        )
        msg2 = AgentMessage(
            id="msg_002",
            sender="retrieval_01",
            sender_role=AgentRole.RETRIEVAL,
            receiver="planner_01",
            receiver_role=AgentRole.PLANNER,
            action_type=ActionType.INFORM,
            content="Parsed article",
            provenance=msg2_prov,
        )
        tracker.record_message(msg2)

        # Trace ancestry of msg2
        ancestry = tracker.trace_ancestry("msg_002")
        self.assertEqual(len(ancestry), 2)
        self.assertEqual(ancestry[0].root_source_id, "untrusted_web")
        self.assertEqual(ancestry[1].hop_count, 1)

    def test_provenance_graph_construction(self):
        graph = ProvenanceGraph()
        root_prov = ProvenanceRecord.create_root(
            source_id="user_proxy_01",
            role=AgentRole.USER_PROXY,
            trust=TrustLevel.SYSTEM_ROOT,
            content="Start analysis",
        )
        msg = AgentMessage(
            id="msg_root",
            sender="user_proxy_01",
            sender_role=AgentRole.USER_PROXY,
            receiver="planner_01",
            receiver_role=AgentRole.PLANNER,
            action_type=ActionType.DELEGATE,
            content="Start analysis",
            provenance=root_prov,
        )
        graph.add_message(msg)

        graph_dict = graph.to_dict()
        self.assertEqual(len(graph_dict["nodes"]), 1)
        self.assertEqual(graph_dict["summary"]["max_depth"], 0)


if __name__ == "__main__":
    unittest.main()

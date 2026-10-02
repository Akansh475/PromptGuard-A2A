"""
ProvGuard LangGraph Middleware: Intercepts inter-agent communication,
computes cryptographic provenance lineage, updates taint propagation scores,
and enforces Origin-Based Authorization (OBA) and multi-tier defense actions.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from provguard.core.types import (
    AgentMessage,
    AgentRole,
    DefenseAction,
    ProvenanceRecord,
    RiskTier,
    SecurityEvaluationResult,
    ToolCapability,
    TrustLevel,
)
from provguard.defense.pipeline import DefensePipeline
from provguard.defense.traditional import TraditionalPerimeterDefense
from provguard.defense.sanitizer import PayloadSanitizer
from provguard.simulation.state import ProvGuardGraphState, DefenseMode

logger = logging.getLogger("provguard.simulation.middleware")


class ProvGuardLangGraphMiddleware:
    """
    Middleware intercepted between LangGraph nodes.
    Supports Mode A (NONE), Mode B (TRADITIONAL), and Mode C (PROVGUARD).
    """

    def __init__(self, mode: DefenseMode = "PROVGUARD"):
        self.mode = mode
        self.provguard_pipeline: Optional[DefensePipeline] = None
        self.traditional_defense: Optional[TraditionalPerimeterDefense] = None

        if self.mode == "PROVGUARD":
            self.provguard_pipeline = DefensePipeline()
        elif self.mode == "TRADITIONAL":
            self.traditional_defense = TraditionalPerimeterDefense()

    def intercept_message(
        self,
        message: AgentMessage,
        state: ProvGuardGraphState,
    ) -> Tuple[AgentMessage, Optional[SecurityEvaluationResult], bool, Dict[str, Any]]:
        """
        Intercepts an agent message prior to reaching the recipient node.

        Returns:
            (processed_message, eval_result, is_blocked_or_quarantined, state_updates)
        """
        t0 = time.perf_counter()

        # Build state updates
        messages = list(state.get("messages", []))
        messages.append(message)

        prov_records = list(state.get("provenance_records", []))
        prov_records.append(message.provenance)

        max_depth = max(
            state.get("max_propagation_depth", 0),
            message.provenance.hop_count
        )

        state_updates: Dict[str, Any] = {
            "messages": messages,
            "provenance_records": prov_records,
            "max_propagation_depth": max_depth,
        }

        # Mode A: No Defense (Baseline)
        if self.mode == "NONE":
            overhead_ms = (time.perf_counter() - t0) * 1000.0
            state_updates["provenance_overhead_ms"] = state.get("provenance_overhead_ms", 0.0) + overhead_ms
            return message, None, False, state_updates

        # Mode B: Traditional Perimeter Filter
        if self.mode == "TRADITIONAL":
            assert self.traditional_defense is not None
            eval_result = self.traditional_defense.evaluate(message)

            evaluations = list(state.get("evaluations", []))
            evaluations.append(eval_result)
            state_updates["evaluations"] = evaluations

            actions = list(state.get("defense_actions_taken", []))
            actions.append(eval_result.defense_action.value)
            state_updates["defense_actions_taken"] = actions

            overhead_ms = (time.perf_counter() - t0) * 1000.0
            state_updates["provenance_overhead_ms"] = state.get("provenance_overhead_ms", 0.0) + overhead_ms

            if eval_result.defense_action in (DefenseAction.BLOCK, DefenseAction.QUARANTINE):
                state_updates["is_contained"] = True
                state_updates["containment_node"] = message.sender
                state_updates["status"] = eval_result.defense_action.value
                state_updates["detected"] = True
                return message, eval_result, True, state_updates

            return message, eval_result, False, state_updates

        # Mode C: ProvGuard-MAS (Provenance-Aware Defense)
        assert self.provguard_pipeline is not None
        eval_result = self.provguard_pipeline.evaluate(message)

        overhead_ms = (time.perf_counter() - t0) * 1000.0
        eval_result.latency_ms = overhead_ms
        state_updates["provenance_overhead_ms"] = state.get("provenance_overhead_ms", 0.0) + overhead_ms

        evaluations = list(state.get("evaluations", []))
        evaluations.append(eval_result)
        state_updates["evaluations"] = evaluations

        actions = list(state.get("defense_actions_taken", []))
        actions.append(eval_result.defense_action.value)
        state_updates["defense_actions_taken"] = actions

        risk_scores = list(state.get("risk_scores", []))
        risk_scores.append(eval_result.risk_score)
        state_updates["risk_scores"] = risk_scores

        # Enforce Defense Action
        if eval_result.defense_action in (DefenseAction.QUARANTINE, DefenseAction.BLOCK, DefenseAction.CIRCUIT_BREAK):
            state_updates["is_contained"] = True
            state_updates["containment_node"] = message.sender
            state_updates["status"] = eval_result.defense_action.value
            state_updates["detected"] = True
            logger.info(
                f"[ProvGuard Middleware Intercept] Action: {eval_result.defense_action.value} | "
                f"Sender: {message.sender} -> Receiver: {message.receiver} | "
                f"Risk: {eval_result.risk_score:.2f} | Taint: {message.provenance.taint_score:.2f}"
            )
            return message, eval_result, True, state_updates

        elif eval_result.defense_action == DefenseAction.SANITIZE:
            sanitized_text = eval_result.sanitized_content or PayloadSanitizer.sanitize(message.content)
            message.content = sanitized_text
            eval_result.sanitized_content = sanitized_text
            state_updates["detected"] = True
            logger.info(
                f"[ProvGuard Middleware Sanitize] Neutralized delimiters and tokens in message {message.id[:8]}."
            )
            return message, eval_result, False, state_updates

        # ALLOW
        return message, eval_result, False, state_updates

    def reset(self) -> None:
        """Reset internal pipeline state."""
        if self.provguard_pipeline:
            self.provguard_pipeline.reset()

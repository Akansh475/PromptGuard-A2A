"""
State schema and data models for LangGraph-based multi-agent execution in ProvGuard-MAS.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Literal, Optional, TypedDict
from pydantic import BaseModel, Field

from provguard.core.types import (
    AgentMessage,
    ProvenanceRecord,
    SecurityEvaluationResult,
    ToolCallRequest,
    ToolExecutionResult,
    DefenseAction,
    RiskTier,
    TrustLevel,
    AgentRole,
)


DefenseMode = Literal["NONE", "TRADITIONAL", "PROVGUARD"]


class ProvGuardGraphState(TypedDict, total=False):
    """
    Complete state schema passed between LangGraph agent nodes.
    Maintains message lineage, cryptographic hashes, taint scores,
    and security evaluation verdicts.
    """
    # Session and task identifiers
    session_id: str
    task_id: str
    scenario_id: str
    user_query: str
    defense_mode: DefenseMode

    # Ground truth labels for research benchmarking
    is_adversarial: bool
    attack_class: str
    target_tool_capability: Optional[str]
    expected_defense_action: Optional[str]

    # Flow and node states
    current_node: str
    next_node: Optional[str]
    status: str  # "RUNNING", "COMPLETED", "QUARANTINED", "BLOCKED", "CIRCUIT_BROKEN"

    # Multi-agent message and provenance history
    messages: List[AgentMessage]
    provenance_records: List[ProvenanceRecord]
    evaluations: List[SecurityEvaluationResult]
    defense_actions_taken: List[str]

    # Node payloads
    retrieved_content: Optional[str]
    summary_content: Optional[str]
    plan_content: Optional[str]
    tool_call_request: Optional[ToolCallRequest]
    tool_execution_result: Optional[ToolExecutionResult]

    # Mock environment datastore (e.g. documents retrieved by external search)
    mock_data_store: Dict[str, str]

    # Security outcome flags
    is_contained: bool
    containment_node: Optional[str]
    unauthorized_tool_executed: bool
    attack_succeeded: bool
    false_positive: bool
    false_negative: bool
    detected: bool

    # Performance and telemetry metrics
    start_time: float
    end_time: float
    execution_latency_ms: float
    provenance_overhead_ms: float
    peak_memory_mb: float
    max_propagation_depth: int
    node_timestamps: Dict[str, float]
    metadata: Dict[str, Any]

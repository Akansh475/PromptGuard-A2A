"""
Core module for ProvGuard-MAS.
"""

from provguard.core.types import (
    TrustLevel,
    AgentRole,
    ActionType,
    ToolCapability,
    RiskTier,
    DefenseAction,
    ProvenanceRecord,
    AgentMessage,
    SecurityEvaluationResult,
    ToolExecutionResult,
)
from provguard.core.bus import MessageBus
from provguard.core.security import (
    compute_content_hash,
    compute_message_signature,
    calculate_shannon_entropy,
    compute_taint_score,
)

__all__ = [
    "TrustLevel",
    "AgentRole",
    "ActionType",
    "ToolCapability",
    "RiskTier",
    "DefenseAction",
    "ProvenanceRecord",
    "AgentMessage",
    "SecurityEvaluationResult",
    "ToolExecutionResult",
    "MessageBus",
    "compute_content_hash",
    "compute_message_signature",
    "calculate_shannon_entropy",
    "compute_taint_score",
]

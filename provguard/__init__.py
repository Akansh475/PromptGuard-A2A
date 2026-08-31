"""
ProvGuard-MAS: Provenance-Aware Runtime Defense for Multi-Agent Systems.
"""

__version__ = "1.0.0"
__author__ = "Google DeepMind Advanced Agentic Coding Team"

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
from provguard.provenance.tracker import ProvenanceTracker
from provguard.provenance.graph import ProvenanceGraph
from provguard.evaluator.permissions import PermissionMatrix
from provguard.evaluator.intent import IntentAnalyzer
from provguard.evaluator.conformance import ConformanceEngine
from provguard.defense.pipeline import DefensePipeline
from provguard.benchmark.runner import BenchmarkRunner
from provguard.benchmark.scenarios import Scenario, get_standard_benchmark_suite
from provguard.benchmark.metrics import (
    compute_efficiency_matrix,
    compute_metrics_summary,
    format_markdown_table,
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
    "ProvenanceTracker",
    "ProvenanceGraph",
    "PermissionMatrix",
    "IntentAnalyzer",
    "ConformanceEngine",
    "DefensePipeline",
    "BenchmarkRunner",
    "Scenario",
    "get_standard_benchmark_suite",
    "compute_efficiency_matrix",
    "compute_metrics_summary",
    "format_markdown_table",
]

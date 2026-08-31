"""
Benchmark package for ProvGuard-MAS.
"""

from provguard.benchmark.scenarios import Scenario, get_standard_benchmark_suite
from provguard.benchmark.runner import BenchmarkRunner, ScenarioExecutionResult
from provguard.benchmark.metrics import (
    MetricsSummary,
    EfficiencyMatrix,
    compute_metrics_summary,
    compute_efficiency_matrix,
    format_markdown_table,
)

__all__ = [
    "Scenario",
    "get_standard_benchmark_suite",
    "BenchmarkRunner",
    "ScenarioExecutionResult",
    "MetricsSummary",
    "EfficiencyMatrix",
    "compute_metrics_summary",
    "compute_efficiency_matrix",
    "format_markdown_table",
]

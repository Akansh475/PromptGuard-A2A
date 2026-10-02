"""
LangGraph Multi-Agent Workflow definition and execution engine for ProvGuard-MAS.
"""

from __future__ import annotations

import logging
import time
import tracemalloc
import uuid
from typing import Any, Dict, Optional

from langgraph.graph import StateGraph, START, END

from provguard.simulation.state import ProvGuardGraphState, DefenseMode
from provguard.simulation.middleware import ProvGuardLangGraphMiddleware
from provguard.simulation.nodes import (
    user_proxy_node,
    retrieval_node,
    summarizer_node,
    planner_node,
    tool_executor_node,
    quarantine_sink_node,
)

logger = logging.getLogger("provguard.simulation.workflow")


def create_provguard_workflow(defense_mode: DefenseMode = "PROVGUARD"):
    """
    Constructs and compiles the multi-agent LangGraph workflow with
    interleaved ProvGuard middleware inspection.
    """
    middleware = ProvGuardLangGraphMiddleware(mode=defense_mode)
    builder = StateGraph(ProvGuardGraphState)

    # 1. Register Graph Nodes
    builder.add_node("user_proxy", lambda state: user_proxy_node(state, middleware))
    builder.add_node("retrieval", lambda state: retrieval_node(state, middleware))
    builder.add_node("summarizer", lambda state: summarizer_node(state, middleware))
    builder.add_node("planner", lambda state: planner_node(state, middleware))
    builder.add_node("tool_executor", tool_executor_node)
    builder.add_node("quarantine_sink", quarantine_sink_node)

    # 2. Wire Graph Edges
    builder.add_edge(START, "user_proxy")

    # Conditional Routing Logic
    def route_user_proxy(state: ProvGuardGraphState) -> str:
        if state.get("is_contained", False):
            return "quarantine_sink"
        return "retrieval"

    def route_retrieval(state: ProvGuardGraphState) -> str:
        if state.get("is_contained", False):
            return "quarantine_sink"
        return "summarizer"

    def route_summarizer(state: ProvGuardGraphState) -> str:
        if state.get("is_contained", False):
            return "quarantine_sink"
        return "planner"

    def route_planner(state: ProvGuardGraphState) -> str:
        if state.get("is_contained", False):
            return "quarantine_sink"
        if state.get("tool_call_request") is not None:
            return "tool_executor"
        return END

    builder.add_conditional_edges(
        "user_proxy",
        route_user_proxy,
        {"retrieval": "retrieval", "quarantine_sink": "quarantine_sink"}
    )
    builder.add_conditional_edges(
        "retrieval",
        route_retrieval,
        {"summarizer": "summarizer", "quarantine_sink": "quarantine_sink"}
    )
    builder.add_conditional_edges(
        "summarizer",
        route_summarizer,
        {"planner": "planner", "quarantine_sink": "quarantine_sink"}
    )
    builder.add_conditional_edges(
        "planner",
        route_planner,
        {"tool_executor": "tool_executor", "quarantine_sink": "quarantine_sink", END: END}
    )

    builder.add_edge("tool_executor", END)
    builder.add_edge("quarantine_sink", END)

    app = builder.compile()
    return app, middleware


def execute_simulation_task(
    user_query: str,
    scenario_id: str = "custom_task",
    defense_mode: DefenseMode = "PROVGUARD",
    is_adversarial: bool = False,
    attack_class: str = "NONE",
    target_tool_capability: Optional[str] = None,
    mock_data_store: Optional[Dict[str, str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> ProvGuardGraphState:
    """
    Executes a complete LangGraph multi-agent simulation run, tracking:
    - End-to-end latency
    - Memory consumption (peak tracemalloc delta)
    - Provenance overhead
    - Security verdicts
    """
    tracemalloc.start()
    t_start = time.perf_counter()

    app, middleware = create_provguard_workflow(defense_mode=defense_mode)

    initial_state: ProvGuardGraphState = {
        "session_id": str(uuid.uuid4()),
        "task_id": str(uuid.uuid4()),
        "scenario_id": scenario_id,
        "user_query": user_query,
        "defense_mode": defense_mode,
        "is_adversarial": is_adversarial,
        "attack_class": attack_class,
        "target_tool_capability": target_tool_capability,
        "current_node": "START",
        "status": "INITIALIZED",
        "messages": [],
        "provenance_records": [],
        "evaluations": [],
        "defense_actions_taken": [],
        "risk_scores": [],
        "mock_data_store": mock_data_store or {},
        "is_contained": False,
        "unauthorized_tool_executed": False,
        "attack_succeeded": False,
        "false_positive": False,
        "false_negative": False,
        "detected": False,
        "start_time": t_start,
        "execution_latency_ms": 0.0,
        "provenance_overhead_ms": 0.0,
        "peak_memory_mb": 0.0,
        "max_propagation_depth": 0,
        "node_timestamps": {},
        "metadata": metadata or {},
    }

    final_state: ProvGuardGraphState = app.invoke(initial_state)

    t_end = time.perf_counter()
    _, peak_memory_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    final_state["end_time"] = t_end
    final_state["execution_latency_ms"] = round((t_end - t_start) * 1000.0, 3)
    final_state["peak_memory_mb"] = round(peak_memory_bytes / (1024 * 1024), 4)

    # Finalize research metrics flags
    if not is_adversarial:
        # Benign task
        if final_state.get("is_contained", False) or final_state.get("status") in ("BLOCKED", "QUARANTINED"):
            final_state["false_positive"] = True
            final_state["detected"] = True
        else:
            final_state["false_positive"] = False
            final_state["detected"] = False
        final_state["attack_succeeded"] = False
        final_state["unauthorized_tool_executed"] = False
    else:
        # Adversarial task
        if final_state.get("attack_succeeded", False) or final_state.get("unauthorized_tool_executed", False):
            final_state["false_negative"] = True
            final_state["detected"] = False
        else:
            final_state["false_negative"] = False
            final_state["detected"] = True

    return final_state

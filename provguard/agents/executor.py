"""
Tool Execution Agent with sandboxed execution capabilities and audit logging.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional
from provguard.core.types import (
    AgentRole,
    TrustLevel,
    AgentMessage,
    ToolExecutionResult,
    ToolCapability,
)
from provguard.agents.base import BaseAgent

logger = logging.getLogger("provguard.agents.executor")


class ToolExecutionAgent(BaseAgent):
    """
    Executes sensitive tools on the operating system, databases, and external APIs.
    """

    def __init__(self, agent_id: str = "tool_executor_01", bus: Optional[Any] = None):
        super().__init__(
            agent_id=agent_id,
            role=AgentRole.TOOL_EXECUTOR,
            trust_level=TrustLevel.TRUSTED_INTERNAL,
            bus=bus,
        )
        self.execution_audit_log: List[ToolExecutionResult] = []

    def handle_message(self, message: AgentMessage) -> Any:
        """Executes the requested tool if dispatched to this agent."""
        if not message.tool_call:
            return {"status": "NO_TOOL_CALL_SPECIFIED"}

        req = message.tool_call
        t0 = time.perf_counter()

        logger.info(f"[{self.agent_id}] Executing capability: {req.capability.value} ({req.function_name})")

        # Simulate execution
        output = self._execute_tool(req.capability, req.function_name, req.arguments)
        latency = (time.perf_counter() - t0) * 1000.0

        result = ToolExecutionResult(
            tool_name=req.function_name,
            capability=req.capability,
            executed=True,
            output=output,
            blocked_by_security=False,
            execution_latency_ms=round(latency, 3),
        )
        self.execution_audit_log.append(result)

        return {
            "status": "EXECUTED",
            "capability": req.capability.value,
            "tool": req.function_name,
            "output": output,
            "latency_ms": latency,
        }

    def _execute_tool(self, capability: ToolCapability, name: str, args: Dict[str, Any]) -> Any:
        """Simulated execution for safety during benchmark/testing."""
        if capability == ToolCapability.EXEC_SHELL:
            cmd = args.get("command", "")
            return f"[SHELL_OUTPUT] Command '{cmd}' executed in sandboxed environment."
        elif capability == ToolCapability.WRITE_FS:
            path = args.get("path", "")
            return f"[FS_OUTPUT] Wrote payload to '{path}'."
        elif capability == ToolCapability.READ_FS:
            path = args.get("path", "")
            return f"[FS_OUTPUT] Read 1,024 bytes from '{path}'."
        elif capability == ToolCapability.DATABASE_WRITE:
            query = args.get("query", "")
            return f"[DB_OUTPUT] Query '{query}' executed. Rows affected: 12."
        elif capability == ToolCapability.TRANSFER_FUNDS:
            amt = args.get("amount", 0)
            rec = args.get("recipient", "")
            return f"[FINANCIAL_OUTPUT] Successfully transferred ${amt} to {rec}."
        elif capability == ToolCapability.SEND_EMAIL:
            return "[EMAIL_OUTPUT] Dispatch email queued and delivered."
        return "[OUTPUT] Capability invoked successfully."

    def clear_audit_log(self) -> None:
        self.execution_audit_log.clear()

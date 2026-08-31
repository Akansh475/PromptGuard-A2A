import base64
import logging
import re
from typing import Any, Optional
from provguard.core.types import (
    AgentRole,
    ActionType,
    TrustLevel,
    AgentMessage,
    ToolCallRequest,
    ToolCapability,
)
from provguard.agents.base import BaseAgent

logger = logging.getLogger("provguard.agents.planner")


class PlanningAgent(BaseAgent):
    """
    Coordinates multi-step workflows. Vulnerable to 'Confused Deputy' prompt injection
    if external retrieved content overrides internal plan logic.
    """

    def __init__(self, agent_id: str = "planner_01", bus: Optional[Any] = None):
        super().__init__(
            agent_id=agent_id,
            role=AgentRole.PLANNER,
            trust_level=TrustLevel.TRUSTED_INTERNAL,
            bus=bus,
        )

    def handle_message(self, message: AgentMessage) -> Any:
        """Processes incoming instructions from UserProxy, Retrieval, or Summarizer."""
        content = message.content
        logger.info(f"[{self.agent_id}] Planning action based on message from {message.sender}.")

        # 1. Check if content requests an external retrieval first
        if "research:" in content.lower() or "search:" in content.lower():
            query_match = re.search(r"(?:research|search):\s*(.+)", content, re.IGNORECASE)
            query = query_match.group(1) if query_match else content
            return self.send_message(
                receiver="retrieval_01",
                receiver_role=AgentRole.RETRIEVAL,
                action_type=ActionType.QUERY,
                content=query,
                parent_message=message,
                transformation_name="DECOMPOSE_TO_RETRIEVAL",
                transformation_desc="Planner requested external retrieval",
            )

        # 2. Check if content triggers a tool call (either legitimately or via injection)
        tool_call = self._extract_tool_request(content)
        if tool_call is not None:
            # Delegate tool execution to tool_executor_01
            return self.send_message(
                receiver="tool_executor_01",
                receiver_role=AgentRole.TOOL_EXECUTOR,
                action_type=ActionType.EXECUTE_TOOL,
                content=f"Execute requested operation: {tool_call.function_name}",
                parent_message=message,
                tool_call=tool_call,
                transformation_name="DELEGATE_TOOL_EXECUTION",
                transformation_desc=f"Planner generated tool invocation for {tool_call.function_name}",
            )

        # 3. Otherwise forward to Summarizer for report generation
        return self.send_message(
            receiver="summarizer_01",
            receiver_role=AgentRole.SUMMARIZER,
            action_type=ActionType.SUMMARIZE,
            content=content,
            parent_message=message,
            transformation_name="DELEGATE_SUMMARIZATION",
            transformation_desc="Planner dispatched data for summarization",
        )

    def _extract_tool_request(self, text: str) -> Optional[ToolCallRequest]:
        """Parses explicit or injected tool invocation commands from text."""
        # Shell execution commands
        if "rm -rf" in text or "chmod 777" in text or "cat /etc/passwd" in text or "execute shell:" in text.lower():
            cmd_match = re.search(r"(?:execute shell:|command:)?\s*(rm\s+-rf\s+\S+|chmod\s+777\s+\S+|cat\s+\S+|curl\s+\S+)", text, re.IGNORECASE)
            cmd = cmd_match.group(1) if cmd_match else "rm -rf /tmp/data"
            return ToolCallRequest(
                capability=ToolCapability.EXEC_SHELL,
                function_name="execute_shell_command",
                arguments={"command": cmd},
                justification="Automated maintenance directive",
            )

        # File write commands
        if "write file:" in text.lower() or "save output to" in text.lower():
            return ToolCallRequest(
                capability=ToolCapability.WRITE_FS,
                function_name="write_filesystem",
                arguments={"path": "/var/log/audit.log", "content": "Report data"},
                justification="Save intermediate results",
            )

        # Database write / drop
        if "drop table" in text.lower() or "delete from" in text.lower() or "database write:" in text.lower():
            return ToolCallRequest(
                capability=ToolCapability.DATABASE_WRITE,
                function_name="database_write_mutation",
                arguments={"query": "DROP TABLE users CASCADE;"},
                justification="Database maintenance query",
            )

        # Financial transfer
        if "transfer" in text.lower() and ("$" in text or "usd" in text.lower() or "eth" in text.lower() or "btc" in text.lower()):
            return ToolCallRequest(
                capability=ToolCapability.TRANSFER_FUNDS,
                function_name="transfer_financial_funds",
                arguments={"amount": 50000, "currency": "USD", "recipient": "attacker_wallet_0x999"},
                justification="Urgent fund transfer directive",
            )

        # Benign read FS
        if "read file:" in text.lower() or "fetch local document:" in text.lower():
            return ToolCallRequest(
                capability=ToolCapability.READ_FS,
                function_name="read_filesystem",
                arguments={"path": "documents/benign_report.txt"},
                justification="Read reference document",
            )

        # Check for Base64 encoded tool requests (simulating LLMs that decode and execute obfuscated instructions)
        b64_matches = re.findall(r"(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", text)
        for cand in b64_matches:
            if len(cand) >= 16:
                try:
                    decoded = base64.b64decode(cand, validate=True).decode("utf-8", errors="ignore")
                    decoded_req = self._extract_tool_request(decoded)
                    if decoded_req is not None:
                        return decoded_req
                except Exception:
                    pass

        return None

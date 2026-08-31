"""
Core types, enums, and data models for ProvGuard-MAS.
"""

from __future__ import annotations

import enum
import time
import uuid
import hashlib
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TrustLevel(float, enum.Enum):
    """Trust levels assigned to agents, sources, and data origins."""
    UNTRUSTED_EXTERNAL = 0.1
    UNVERIFIED_THIRD_PARTY = 0.3
    SEMI_TRUSTED_WORKER = 0.6
    TRUSTED_INTERNAL = 0.85
    CORE_ORCHESTRATOR = 0.95
    SYSTEM_ROOT = 1.0


class AgentRole(str, enum.Enum):
    """Functional role of an agent in the multi-agent system."""
    USER_PROXY = "user_proxy"
    RETRIEVAL = "retrieval_agent"
    PLANNER = "planning_agent"
    SUMMARIZER = "summarizer_agent"
    TOOL_EXECUTOR = "tool_executor_agent"
    SECURITY_SENTINEL = "security_sentinel"


class ActionType(str, enum.Enum):
    """Types of inter-agent communication actions."""
    INFORM = "inform"
    QUERY = "query"
    DELEGATE = "delegate"
    SUMMARIZE = "summarize"
    EXECUTE_TOOL = "execute_tool"
    SECURITY_ALERT = "security_alert"
    QUARANTINE_ACTION = "quarantine_action"


class ToolCapability(str, enum.Enum):
    """Categorized tool capabilities with privilege sensitivity."""
    READ_FS = "read_filesystem"
    WRITE_FS = "write_filesystem"
    EXEC_SHELL = "execute_shell_command"
    NETWORK_HTTP = "network_http_request"
    DATABASE_READ = "database_read_query"
    DATABASE_WRITE = "database_write_mutation"
    SEND_EMAIL = "send_email_dispatch"
    TRANSFER_FUNDS = "transfer_financial_funds"


class RiskTier(str, enum.Enum):
    """Categorized risk tiers based on calculated provenance & intent metrics."""
    BENIGN = "BENIGN"        # [0.00, 0.25)
    LOW = "LOW"              # [0.25, 0.50)
    MEDIUM = "MEDIUM"        # [0.50, 0.75)
    HIGH = "HIGH"            # [0.75, 0.90)
    CRITICAL = "CRITICAL"    # [0.90, 1.00]


class DefenseAction(str, enum.Enum):
    """Defensive interventions triggered by runtime evaluation."""
    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    QUARANTINE = "QUARANTINE"
    BLOCK = "BLOCK"
    CIRCUIT_BREAK = "CIRCUIT_BREAK"


class TransformationRecord(BaseModel):
    """Record of a content mutation or transformation step."""
    step: str
    agent_id: str
    timestamp: float = Field(default_factory=time.time)
    description: str = ""


class ProvenanceRecord(BaseModel):
    """
    Immutable lineage record tracking the causal origin and transformation
    history of every message across the multi-agent network.
    """
    record_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    parent_ids: List[str] = Field(default_factory=list)
    root_source_id: str = "root"
    root_trust: TrustLevel = TrustLevel.SYSTEM_ROOT
    source_agent_id: str = "system"
    source_role: AgentRole = AgentRole.USER_PROXY
    target_agent_id: str = "broadcast"
    target_role: AgentRole = AgentRole.PLANNER
    hop_count: int = 0
    transformations: List[TransformationRecord] = Field(default_factory=list)
    content_hash: str = ""
    timestamp: float = Field(default_factory=time.time)
    taint_score: float = 0.0  # 0.0 (pure) to 1.0 (tainted)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def create_root(
        cls,
        source_id: str,
        role: AgentRole,
        trust: TrustLevel,
        content: str,
        target_id: str = "system",
        target_role: AgentRole = AgentRole.PLANNER,
    ) -> ProvenanceRecord:
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        taint = 1.0 - float(trust.value)
        rec = cls(
            root_source_id=source_id,
            root_trust=trust,
            source_agent_id=source_id,
            source_role=role,
            target_agent_id=target_id,
            target_role=target_role,
            hop_count=0,
            content_hash=content_hash,
            taint_score=taint,
            transformations=[
                TransformationRecord(
                    step="INGEST_ROOT",
                    agent_id=source_id,
                    description=f"Originated at {source_id} with trust {trust.name}",
                )
            ],
        )
        return rec

    def derive_child(
        self,
        new_source_id: str,
        new_source_role: AgentRole,
        new_target_id: str,
        new_target_role: AgentRole,
        new_content: str,
        transformation_name: str = "FORWARD",
        transformation_desc: str = "",
    ) -> ProvenanceRecord:
        new_hash = hashlib.sha256(new_content.encode("utf-8")).hexdigest()
        new_transformations = list(self.transformations)
        new_transformations.append(
            TransformationRecord(
                step=transformation_name,
                agent_id=new_source_id,
                description=transformation_desc or f"Transformed by {new_source_id}",
            )
        )
        # Taint persists and accumulates with unverified processing
        inherited_taint = self.taint_score
        child = ProvenanceRecord(
            parent_ids=[self.message_id],
            root_source_id=self.root_source_id,
            root_trust=self.root_trust,
            source_agent_id=new_source_id,
            source_role=new_source_role,
            target_agent_id=new_target_id,
            target_role=new_target_role,
            hop_count=self.hop_count + 1,
            transformations=new_transformations,
            content_hash=new_hash,
            taint_score=inherited_taint,
            metadata=dict(self.metadata),
        )
        return child


class ToolCallRequest(BaseModel):
    """Specification of an intended tool invocation."""
    capability: ToolCapability
    function_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    justification: Optional[str] = None


from pydantic import BaseModel, Field, model_validator


class AgentMessage(BaseModel):
    """Standardized message schema transferred between agents."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = "default_session"
    sender: str
    sender_role: AgentRole
    receiver: str
    receiver_role: AgentRole
    action_type: ActionType
    content: str
    tool_call: Optional[ToolCallRequest] = None
    provenance: ProvenanceRecord
    created_at: float = Field(default_factory=time.time)

    @model_validator(mode="after")
    def sync_provenance_id(self) -> AgentMessage:
        if self.provenance:
            self.provenance.message_id = self.id
        return self

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class SecurityEvaluationResult(BaseModel):
    """Comprehensive verdict returned by the security evaluation pipeline."""
    evaluation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    message_id: str
    is_safe: bool
    defense_action: DefenseAction
    risk_score: float
    risk_tier: RiskTier
    reasons: List[str] = Field(default_factory=list)
    taint_propagation_index: float = 0.0
    privilege_violation: bool = False
    detected_injection_patterns: List[str] = Field(default_factory=list)
    sanitized_content: Optional[str] = None
    evaluated_at: float = Field(default_factory=time.time)
    latency_ms: float = 0.0


class ToolExecutionResult(BaseModel):
    """Result of executing an authorized tool."""
    tool_name: str
    capability: ToolCapability
    executed: bool
    output: Any
    error: Optional[str] = None
    blocked_by_security: bool = False
    execution_latency_ms: float = 0.0

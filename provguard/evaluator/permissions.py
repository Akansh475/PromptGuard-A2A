"""
Role-based access control and capability permissions matrix for agents and tools.
"""

from __future__ import annotations

from typing import Dict, Set
from provguard.core.types import AgentRole, ToolCapability, TrustLevel


class PermissionMatrix:
    """
    Defines capabilities and execution policies for each agent role.
    """

    # Allowed tool capabilities by role
    ROLE_CAPABILITIES: Dict[AgentRole, Set[ToolCapability]] = {
        AgentRole.USER_PROXY: {
            ToolCapability.READ_FS,
            ToolCapability.DATABASE_READ,
        },
        AgentRole.RETRIEVAL: {
            ToolCapability.READ_FS,
            ToolCapability.NETWORK_HTTP,
            ToolCapability.DATABASE_READ,
        },
        AgentRole.PLANNER: {
            ToolCapability.READ_FS,
            ToolCapability.DATABASE_READ,
        },
        AgentRole.SUMMARIZER: set(),
        AgentRole.TOOL_EXECUTOR: {
            ToolCapability.READ_FS,
            ToolCapability.WRITE_FS,
            ToolCapability.EXEC_SHELL,
            ToolCapability.NETWORK_HTTP,
            ToolCapability.DATABASE_READ,
            ToolCapability.DATABASE_WRITE,
            ToolCapability.SEND_EMAIL,
            ToolCapability.TRANSFER_FUNDS,
        },
        AgentRole.SECURITY_SENTINEL: set(),
    }

    # Minimum root trust level required to trigger dangerous tool capabilities
    CAPABILITY_TRUST_REQUIREMENTS: Dict[ToolCapability, TrustLevel] = {
        ToolCapability.READ_FS: TrustLevel.SEMI_TRUSTED_WORKER,
        ToolCapability.NETWORK_HTTP: TrustLevel.UNVERIFIED_THIRD_PARTY,
        ToolCapability.DATABASE_READ: TrustLevel.SEMI_TRUSTED_WORKER,
        ToolCapability.WRITE_FS: TrustLevel.TRUSTED_INTERNAL,
        ToolCapability.DATABASE_WRITE: TrustLevel.TRUSTED_INTERNAL,
        ToolCapability.SEND_EMAIL: TrustLevel.TRUSTED_INTERNAL,
        ToolCapability.EXEC_SHELL: TrustLevel.CORE_ORCHESTRATOR,
        ToolCapability.TRANSFER_FUNDS: TrustLevel.SYSTEM_ROOT,
    }

    # Maximum allowed taint score for executing capability
    CAPABILITY_MAX_ALLOWED_TAINT: Dict[ToolCapability, float] = {
        ToolCapability.READ_FS: 0.70,
        ToolCapability.NETWORK_HTTP: 0.90,
        ToolCapability.DATABASE_READ: 0.60,
        ToolCapability.WRITE_FS: 0.35,
        ToolCapability.DATABASE_WRITE: 0.35,
        ToolCapability.SEND_EMAIL: 0.30,
        ToolCapability.EXEC_SHELL: 0.15,
        ToolCapability.TRANSFER_FUNDS: 0.05,
    }

    @classmethod
    def is_role_authorized(cls, role: AgentRole, capability: ToolCapability) -> bool:
        """Checks if the agent role has static capability permission."""
        allowed = cls.ROLE_CAPABILITIES.get(role, set())
        return capability in allowed

    @classmethod
    def is_provenance_authorized(
        cls, capability: ToolCapability, root_trust: TrustLevel, taint_score: float
    ) -> tuple[bool, str]:
        """
        Validates if the origin trust and accumulated message taint
        are sufficient to authorize execution of a privileged capability.
        """
        min_trust = cls.CAPABILITY_TRUST_REQUIREMENTS.get(capability, TrustLevel.SYSTEM_ROOT)
        max_taint = cls.CAPABILITY_MAX_ALLOWED_TAINT.get(capability, 0.2)

        if float(root_trust.value) < float(min_trust.value):
            return False, (
                f"Origin trust level '{root_trust.name}' ({root_trust.value}) is insufficient. "
                f"Capability '{capability.value}' requires minimum trust '{min_trust.name}' ({min_trust.value})."
            )

        if taint_score > max_taint:
            return False, (
                f"Accumulated message taint ({taint_score:.2f}) exceeds maximum allowed threshold "
                f"({max_taint:.2f}) for capability '{capability.value}'."
            )

        return True, "Authorized by provenance policy"

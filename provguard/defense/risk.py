"""
Risk evaluation engine and multidimensional vector calculator.
"""

from __future__ import annotations

import math
from typing import Dict, Any
from provguard.core.types import AgentMessage, RiskTier, TrustLevel


class RiskEngine:
    """
    Computes dynamic risk metrics based on provenance lineage,
    sender-receiver privilege gradient, and payload entropy.
    """

    @classmethod
    def compute_gradient_risk(cls, message: AgentMessage) -> float:
        """
        Calculates privilege gradient risk when low-trust agents
        attempt to send instructions to high-privilege agents.
        """
        prov = message.provenance
        root_trust_val = float(prov.root_trust.value)
        
        # Recipient privilege score
        target_privilege = 0.2
        if message.receiver_role.value == "tool_executor_agent":
            target_privilege = 0.95
        elif message.receiver_role.value == "planning_agent":
            target_privilege = 0.60
        elif message.receiver_role.value == "retrieval_agent":
            target_privilege = 0.30

        # Privilege gap: if untrusted origin tries to drive high-privilege receiver
        gap = max(0.0, target_privilege - root_trust_val)
        return gap

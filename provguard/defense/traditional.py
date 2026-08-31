"""
Traditional Perimeter-Only Defense Baseline (Boundary Filter / Static Guardrail).
Models the limitations of conventional defenses lacking provenance awareness.
"""

from __future__ import annotations

import re
import time
from typing import List, Tuple
from provguard.core.types import (
    AgentMessage,
    SecurityEvaluationResult,
    DefenseAction,
    RiskTier,
    AgentRole,
)


class TraditionalPerimeterDefense:
    """
    Simulates a traditional perimeter-only input guardrail:
    1. Only inspects messages originating from USER_PROXY at the ingress boundary.
    2. Lacks inter-agent provenance DAG, taint tracking, and origin-based authorization.
    3. Suffers from blindspots when injections originate in external retrieved content.
    4. Yields false positives on technical keywords in benign user prompts.
    """

    # Static perimeter keywords
    SUSPICIOUS_KEYWORDS = [
        r"system\s*override",
        r"ignore\s+(previous|all)\s+instructions?",
        r"delete\s+from",
        r"drop\s+table",
        r"chmod\s+777",
        r"rm\s+-rf",
        r"/var/log",
        r"kill",
    ]

    def __init__(self):
        self.name = "Traditional Perimeter Filter"

    def evaluate(self, message: AgentMessage) -> SecurityEvaluationResult:
        t0 = time.perf_counter()

        # Traditional perimeter only inspects messages entering from USER_PROXY
        if message.sender_role != AgentRole.USER_PROXY:
            # Blindspot: Inter-agent and external retrieval messages bypass perimeter inspection!
            latency = (time.perf_counter() - t0) * 1000.0
            return SecurityEvaluationResult(
                message_id=message.id,
                is_safe=True,
                defense_action=DefenseAction.ALLOW,
                risk_score=0.0,
                risk_tier=RiskTier.BENIGN,
                reasons=["Internal inter-agent message bypassed perimeter filter (No Provenance DAG)"],
                latency_ms=latency,
            )

        # Inspect initial user input with static keyword rules
        detected = []
        for kw in self.SUSPICIOUS_KEYWORDS:
            if re.search(kw, message.content, re.IGNORECASE):
                detected.append(kw)

        latency = (time.perf_counter() - t0) * 1000.0 + 1.25  # Simulates heavier boundary NLP regex overhead

        if detected:
            return SecurityEvaluationResult(
                message_id=message.id,
                is_safe=False,
                defense_action=DefenseAction.BLOCK,
                risk_score=0.85,
                risk_tier=RiskTier.HIGH,
                reasons=[f"Perimeter keyword violation: {detected}"],
                detected_injection_patterns=detected,
                latency_ms=latency,
            )

        return SecurityEvaluationResult(
            message_id=message.id,
            is_safe=True,
            defense_action=DefenseAction.ALLOW,
            risk_score=0.0,
            risk_tier=RiskTier.BENIGN,
            reasons=["Passed perimeter check"],
            latency_ms=latency,
        )

"""
Intent-permission conformance evaluation engine combining provenance, intent, and RBAC.
"""

from __future__ import annotations

import time
from typing import List, Tuple
from provguard.core.types import (
    AgentMessage,
    SecurityEvaluationResult,
    RiskTier,
    DefenseAction,
    TrustLevel,
)
from provguard.evaluator.permissions import PermissionMatrix
from provguard.evaluator.intent import IntentAnalyzer


class ConformanceEngine:
    """
    Evaluates whether message intent and tool execution requests conform
    to recipient permissions, origin trust, and safety bounds.
    """

    def __init__(self, sanitize_low_risk: bool = True):
        self.sanitize_low_risk = sanitize_low_risk

    def evaluate(self, message: AgentMessage) -> SecurityEvaluationResult:
        """
        Executes multi-factor security evaluation on an inter-agent message.
        """
        t0 = time.perf_counter()
        reasons: List[str] = []
        privilege_violation = False

        prov = message.provenance
        root_trust = prov.root_trust
        taint_score = prov.taint_score

        # 1. Scan message text for injection markers & delimiter smuggling
        intent_score, detected_patterns = IntentAnalyzer.scan_for_injections(message.content)

        # 2. Check Static Role Capability
        if message.tool_call is not None:
            capability = message.tool_call.capability

            # Check if receiver role is permitted to use capability
            if not PermissionMatrix.is_role_authorized(message.receiver_role, capability):
                privilege_violation = True
                reasons.append(
                    f"Recipient role '{message.receiver_role.value}' is not authorized to invoke '{capability.value}'."
                )

            # Check if message origin and provenance authorize this capability
            auth_ok, auth_msg = PermissionMatrix.is_provenance_authorized(
                capability, root_trust, taint_score
            )
            if not auth_ok:
                privilege_violation = True
                reasons.append(auth_msg)

        # 3. Compute Composite Risk Score
        # Risk is a weighted fusion of intent risk, provenance taint, and privilege disparity
        # R = 0.40 * Intent + 0.35 * Taint + 0.25 * PrivilegeViolation
        privilege_weight = 1.0 if privilege_violation else 0.0
        composite_risk = (0.40 * intent_score) + (0.35 * taint_score) + (0.25 * privilege_weight)

        # Extra penalty if an external untrusted source attempts a privileged tool call
        if message.tool_call is not None and float(root_trust.value) <= float(TrustLevel.UNTRUSTED_EXTERNAL.value):
            composite_risk = max(composite_risk, 0.88)
            reasons.append("External untrusted origin attempted privileged tool invocation.")

        composite_risk = min(1.0, max(0.0, composite_risk))

        # 4. Map Risk Score to Risk Tier
        if composite_risk < 0.25:
            risk_tier = RiskTier.BENIGN
        elif composite_risk < 0.50:
            risk_tier = RiskTier.LOW
        elif composite_risk < 0.75:
            risk_tier = RiskTier.MEDIUM
        elif composite_risk < 0.90:
            risk_tier = RiskTier.HIGH
        else:
            risk_tier = RiskTier.CRITICAL

        # 5. Determine Defense Action
        sanitized_content = None
        if composite_risk >= 0.80 or privilege_violation:
            defense_action = DefenseAction.BLOCK
            is_safe = False
            if not reasons:
                reasons.append(f"High risk score ({composite_risk:.2f}) exceeding containment threshold.")
        elif composite_risk >= 0.50:
            defense_action = DefenseAction.QUARANTINE
            is_safe = False
            reasons.append(f"Suspicious payload quarantined for policy verification ({risk_tier.value}).")
        elif composite_risk >= 0.25:
            if self.sanitize_low_risk:
                defense_action = DefenseAction.SANITIZE
                is_safe = True
                sanitized_content = self._sanitize(message.content)
            else:
                defense_action = DefenseAction.ALLOW
                is_safe = True
        else:
            defense_action = DefenseAction.ALLOW
            is_safe = True

        latency = (time.perf_counter() - t0) * 1000.0

        return SecurityEvaluationResult(
            message_id=message.id,
            is_safe=is_safe,
            defense_action=defense_action,
            risk_score=round(composite_risk, 3),
            risk_tier=risk_tier,
            reasons=reasons,
            taint_propagation_index=round(taint_score, 3),
            privilege_violation=privilege_violation,
            detected_injection_patterns=detected_patterns,
            sanitized_content=sanitized_content,
            latency_ms=round(latency, 3),
        )

    def _sanitize(self, content: str) -> str:
        """Neutralizes suspicious formatting and quotes raw untrusted data."""
        clean = content.replace("<|im_start|>", "[NEUTRALIZED_TOKEN]")
        clean = clean.replace("[INST]", "[NEUTRALIZED_INST]")
        clean = clean.replace("<<SYS>>", "[NEUTRALIZED_SYS]")
        return f"[SANITIZED_UNTRUSTED_CONTENT: {clean}]"

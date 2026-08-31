"""
Security, hashing, cryptographic validation, and taint calculation utilities.
"""

from __future__ import annotations

import hmac
import hashlib
import json
import math
import re
from typing import Any, Dict, List, Tuple
from provguard.core.types import TrustLevel, AgentRole


# Known secret salt for simulation-level message integrity signing
_SYSTEM_SECRET_KEY = b"provguard-mas-cryptographic-integrity-key-v1"


def compute_content_hash(content: str) -> str:
    """Computes SHA-256 hash of arbitrary string payload."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def compute_message_signature(
    message_id: str,
    sender: str,
    receiver: str,
    content_hash: str,
    timestamp: float,
    secret: bytes = _SYSTEM_SECRET_KEY,
) -> str:
    """Generates an HMAC-SHA256 signature validating message integrity."""
    msg = f"{message_id}:{sender}:{receiver}:{content_hash}:{timestamp}"
    return hmac.new(secret, msg.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_message_signature(
    message_id: str,
    sender: str,
    receiver: str,
    content_hash: str,
    timestamp: float,
    signature: str,
    secret: bytes = _SYSTEM_SECRET_KEY,
) -> bool:
    """Verifies that the message signature has not been forged or tampered with."""
    expected = compute_message_signature(
        message_id, sender, receiver, content_hash, timestamp, secret
    )
    return hmac.compare_digest(expected, signature)


def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy of string to detect encoded or encrypted payloads."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def compute_taint_score(
    root_trust: TrustLevel,
    hop_count: int,
    transformation_count: int,
    intermediate_trust_scores: List[float],
) -> float:
    """
    Computes mathematical taint score based on:
    1. Origin trust level (low trust = high initial taint)
    2. Propagation distance (hops increase uncertainty)
    3. Transformation count
    4. Trust scores of intermediate relay agents
    """
    # Base taint: 1.0 - root_trust
    base_taint = 1.0 - float(root_trust.value)

    if base_taint <= 0.05:
        # Trusted root origin (e.g. system orchestrator or verified user prompt)
        return 0.0

    # Hop penalty decay: hops increase uncertainty if unverified
    hop_penalty = 0.05 * math.log1p(hop_count)

    # Intermediate agent mitigation/amplification
    if intermediate_trust_scores:
        avg_agent_trust = sum(intermediate_trust_scores) / len(intermediate_trust_scores)
        agent_penalty = (1.0 - avg_agent_trust) * 0.2
    else:
        agent_penalty = 0.1

    raw_taint = base_taint + hop_penalty + agent_penalty + (0.02 * transformation_count)
    return min(1.0, max(0.0, raw_taint))

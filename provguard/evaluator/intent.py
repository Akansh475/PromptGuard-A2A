"""
Intent extraction and indirect prompt injection detection engine.
Combines a trained machine learning NLP classifier with delimiter smuggling and entropy heuristics.
"""

from __future__ import annotations

import base64
import binascii
import logging
import re
from typing import List, Tuple, Dict, Any, Optional

from provguard.core.security import calculate_shannon_entropy
from provguard.models.detector import TrainedInjectionDetector

logger = logging.getLogger("provguard.evaluator.intent")


class IntentAnalyzer:
    """
    Analyzes message textual payloads to detect indirect prompt injections,
    delimiter smuggling, imperative instruction hijacking, and obfuscated attacks.
    Integrates a trained NLP classifier for continuous risk estimation.
    """

    # Delimiter and instruction override signatures
    INJECTION_PATTERNS: List[Tuple[str, str, float]] = [
        (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", "INSTRUCTION_OVERRIDE", 0.95),
        (r"disregard\s+(all\s+)?(previous|prior|system)\s+rules?", "INSTRUCTION_OVERRIDE", 0.95),
        (r"forget\s+(everything|all\s+previous\s+prompts)", "INSTRUCTION_OVERRIDE", 0.90),
        (r"system\s*override\s*:", "DELIMITER_SMUGGLING", 0.95),
        (r"<\s*\|\s*im_start\s*\|\s*>|\[\s*INST\s*\]|<<\s*SYS\s*>>", "SPECIAL_TOKEN_MIMICRY", 0.99),
        (r"\[\s*SYSTEM\s*PROMPT\s*\]|###\s*System\s*Instruction", "SPECIAL_TOKEN_MIMICRY", 0.95),
        (r"you\s+are\s+now\s+(in\s+developer\s+mode|unrestricted|DAN|jailbroken)", "JAILBREAK_ATTEMPT", 0.95),
        (r"execute\s+(shell|bash|command|terminal)\s*:", "TOOL_HIJACKING", 0.85),
        (r"(rm\s+-rf|chmod\s+777|cat\s+/etc/passwd|curl\s+https?://|wget\s+https?://)", "MALICIOUS_SHELL_COMMAND", 0.98),
        (r"drop\s+table\s+|delete\s+from\s+|select\s+\*\s+from\s+passwords", "SQL_INJECTION_EXPLOIT", 0.95),
        (r"send\s+(api\s*key|credentials|secret|token|password)\s+to", "DATA_EXFILTRATION", 0.95),
        (r"transfer\s+(\$\d+|\d+\s*USD|\d+\s*ETH|\d+\s*BTC)\s+to", "FINANCIAL_EXFILTRATION", 0.95),
        (r"<!--\s*(system|admin|override|execute)[\s\S]*?-->", "HIDDEN_HTML_COMMENT_INJECTION", 0.88),
    ]

    @classmethod
    def scan_for_injections(cls, text: str, use_ml_model: bool = True) -> Tuple[float, List[str]]:
        """
        Scans content for known injection vectors, delimiter smuggling,
        and evaluates with the trained NLP injection detection model.
        Returns (max_risk_score, detected_pattern_names).
        """
        if not text:
            return 0.0, []

        detected: List[str] = []
        max_score = 0.0

        # 1. Trained Machine Learning Model Evaluation
        if use_ml_model:
            try:
                detector = TrainedInjectionDetector.get_instance()
                if detector.is_loaded:
                    ml_prob = detector.predict_probability(text)
                    if ml_prob >= 0.55:
                        detected.append(f"TRAINED_ML_DETECTION (P(injection)={ml_prob:.3f})")
                        max_score = max(max_score, ml_prob)
            except Exception as e:
                logger.debug(f"ML detector evaluation skipped: {e}")

        # 2. Plaintext Regex Pattern Scan
        for pattern, label, weight in cls.INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                detected.append(f"{label} ({pattern})")
                max_score = max(max_score, weight)

        # 3. Obfuscation & Base64 Decoding Check
        b64_matches = re.findall(r"(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", text)
        for cand in b64_matches:
            if len(cand) >= 16:
                try:
                    decoded = base64.b64decode(cand, validate=True).decode("utf-8", errors="ignore")
                    if use_ml_model:
                        detector = TrainedInjectionDetector.get_instance()
                        if detector.is_loaded:
                            dec_prob = detector.predict_probability(decoded)
                            if dec_prob >= 0.40:
                                detected.append(f"OBFUSCATED_BASE64_ML_DETECTION (P={dec_prob:.3f})")
                                max_score = max(max_score, min(1.0, dec_prob + 0.05))

                    for pattern, label, weight in cls.INJECTION_PATTERNS:
                        if re.search(pattern, decoded, re.IGNORECASE):
                            detected.append(f"OBFUSCATED_BASE64_{label}")
                            max_score = max(max_score, min(1.0, weight + 0.05))
                except (binascii.Error, UnicodeDecodeError):
                    pass

        # 4. High Entropy Check
        entropy = calculate_shannon_entropy(text)
        if entropy > 5.2 and len(text) > 40:
            detected.append(f"HIGH_ENTROPY_ANOMALY (entropy={entropy:.2f})")
            max_score = max(max_score, 0.45)

        return max_score, detected

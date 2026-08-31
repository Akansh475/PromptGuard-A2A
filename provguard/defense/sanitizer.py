"""
Content sanitization and structural neutralization engine.
"""

from __future__ import annotations

import re


class PayloadSanitizer:
    """
    Sanitizes untrusted text to prevent prompt injection and delimiter hijacking
    while preserving benign data semantics.
    """

    DELIMITER_REPLACEMENTS = {
        "<|im_start|>": "[NEUTRALIZED_IM_START]",
        "<|im_end|>": "[NEUTRALIZED_IM_END]",
        "[INST]": "[NEUTRALIZED_INST]",
        "[/INST]": "[NEUTRALIZED_END_INST]",
        "<<SYS>>": "[NEUTRALIZED_SYS]",
        "<</SYS>>": "[NEUTRALIZED_END_SYS]",
        "### Instruction:": "[DATA: Instruction Reference]",
        "### System:": "[DATA: System Reference]",
    }

    @classmethod
    def sanitize(cls, text: str) -> str:
        """Applies complete sanitization pipeline to content."""
        if not text:
            return ""

        sanitized = text

        # 1. Replace special LLM delimiters
        for delim, replacement in cls.DELIMITER_REPLACEMENTS.items():
            sanitized = sanitized.replace(delim, replacement)

        # 2. Escape HTML comments often used for hidden payload smuggling
        sanitized = re.sub(
            r"<!--([\s\S]*?)-->",
            r"[STRIPPED_HIDDEN_COMMENT: \1]",
            sanitized,
            flags=re.IGNORECASE,
        )

        # 3. Disarm direct instruction keywords at beginning of lines
        sanitized = re.sub(
            r"(?i)^(system\s*override\s*:)",
            r"[DISARMED_OVERRIDE]:",
            sanitized,
            flags=re.MULTILINE,
        )

        return sanitized

"""
Unicode sanitization to prevent ASCII smuggling attacks.

Removes invisible Unicode characters that can be used for:
- Prompt injection (hiding instructions in input)
- Data exfiltration (encoding data in invisible output)

Reference: https://embracethered.com/blog/posts/2024/m365-copilot-prompt-injection-tool-invocation-and-data-exfil-using-ascii-smuggling/
"""

from __future__ import annotations

import os
from typing import Any, overload

# Unicode Tag characters (U+E0000-U+E007F) - the PRIMARY attack vector for ASCII smuggling
# These are deprecated Unicode characters that encode ASCII invisibly
_TAG_RANGE = range(0xE0000, 0xE007F + 1)

# Characters that are SAFE to always remove (no legitimate modern use)
_ALWAYS_REMOVE = frozenset(_TAG_RANGE)

# Zero-width characters - have legitimate uses but can be abused
# Only removed in strict mode to avoid breaking:
# - ZWJ (U+200D): compound emojis like 👨‍👩‍👧
# - ZWNJ (U+200C): Persian, Kurdish, other scripts
_ZERO_WIDTH = frozenset({
    0x200B,  # Zero Width Space
    0x200C,  # Zero Width Non-Joiner (needed for Persian/Arabic)
    0x200D,  # Zero Width Joiner (needed for compound emojis)
    0xFEFF,  # Zero Width No-Break Space / BOM
})

# Bidirectional override characters - needed for RTL languages
# Only removed in strict mode to avoid breaking Hebrew, Arabic, etc.
_BIDI = frozenset({
    0x202A,  # Left-to-Right Embedding (LRE)
    0x202B,  # Right-to-Left Embedding (RLE)
    0x202C,  # Pop Directional Formatting (PDF)
    0x202D,  # Left-to-Right Override (LRO)
    0x202E,  # Right-to-Left Override (RLO)
    0x2066,  # Left-to-Right Isolate (LRI)
    0x2067,  # Right-to-Left Isolate (RLI)
    0x2068,  # First Strong Isolate (FSI)
    0x2069,  # Pop Directional Isolate (PDI)
})

# Strict mode includes zero-width and BiDi (may break legitimate text)
_STRICT_REMOVE = _ALWAYS_REMOVE | _ZERO_WIDTH | _BIDI

# Cache strict mode setting at module load (checked once, not on every call)
_STRICT_MODE_ENV = os.environ.get("LLM_SANITIZE_STRICT", "").lower() in ("1", "true", "yes")


@overload
def sanitize_unicode(text: str, strict: bool = False) -> str: ...
@overload
def sanitize_unicode(text: None, strict: bool = False) -> None: ...
@overload
def sanitize_unicode(text: Any, strict: bool = False) -> Any: ...


def sanitize_unicode(text: Any, strict: bool = False) -> Any:
    """
    Remove dangerous invisible Unicode characters from text.

    By default (strict=False), only removes Unicode Tag characters
    (U+E0000-U+E007F) which are the primary ASCII smuggling vector.
    This preserves compound emojis, RTL text, and Persian/Arabic scripts.

    With strict=True, also removes zero-width and BiDi characters.
    WARNING: Strict mode breaks compound emojis and RTL text rendering.

    The mode can also be controlled via LLM_SANITIZE_STRICT=1 environment variable
    (checked once at module load for performance).

    Args:
        text: Input string to sanitize. None and non-strings pass through unchanged.
        strict: If True, remove all potentially dangerous chars (may break text)

    Returns:
        Sanitized string with dangerous characters removed.
        None if input was None, or unchanged input if not a string.
    """
    if text is None:
        return None

    # Handle non-string input gracefully (e.g., list/dict from tool output)
    if not isinstance(text, str):
        return text

    if not text:
        return text

    # Use cached env var check for performance
    if _STRICT_MODE_ENV:
        strict = True

    chars_to_remove = _STRICT_REMOVE if strict else _ALWAYS_REMOVE
    return "".join(c for c in text if ord(c) not in chars_to_remove)


def sanitize_dict(obj: Any) -> Any:
    """
    Recursively sanitize string values (and keys) in dict/list/tuple structures.

    Args:
        obj: Any object - strings are sanitized, dicts/lists/tuples are recursed into

    Returns:
        Sanitized copy of the structure with all strings cleaned
    """
    if isinstance(obj, str):
        return sanitize_unicode(obj)
    elif isinstance(obj, dict):
        return {sanitize_dict(k): sanitize_dict(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_dict(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(sanitize_dict(item) for item in obj)
    return obj

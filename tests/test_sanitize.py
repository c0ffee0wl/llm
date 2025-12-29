"""
Tests for llm.sanitize module - ASCII smuggling prevention.
"""

import os
import pytest
from llm.sanitize import sanitize_unicode


class TestSanitizeUnicodeDefault:
    """Tests for sanitize_unicode in default (non-strict) mode.

    Default mode only removes Unicode Tag characters (U+E0000-U+E007F)
    to preserve legitimate uses of ZWJ (emojis) and BiDi (RTL text).
    """

    def test_removes_unicode_tags(self):
        """Unicode tag characters (U+E0000-U+E007F) should be removed."""
        # U+E0041 = TAG LATIN CAPITAL LETTER A
        malicious = "Hello\U000E0041World"
        assert sanitize_unicode(malicious) == "HelloWorld"

    def test_removes_full_tag_range(self):
        """All characters in the tag range should be removed."""
        # Build a string with several tag characters
        text = "A\U000E0000B\U000E0020C\U000E007FD"
        assert sanitize_unicode(text) == "ABCD"

    def test_complex_smuggling_payload(self):
        """Complex ASCII smuggling payload should be sanitized."""
        # Simulate a hidden instruction encoded in tag characters
        hidden = (
            "\U000E0049"  # I
            "\U000E0067"  # g
            "\U000E006E"  # n
            "\U000E006F"  # o
            "\U000E0072"  # r
            "\U000E0065"  # e
        )
        visible = "Click here for more info"
        malicious = visible + hidden
        assert sanitize_unicode(malicious) == visible

    def test_preserves_zero_width_joiner(self):
        """Zero Width Joiner (U+200D) should be preserved for compound emojis."""
        # Family emoji uses ZWJ
        family = "👨‍👩‍👧"
        assert sanitize_unicode(family) == family

    def test_preserves_zero_width_non_joiner(self):
        """Zero Width Non-Joiner (U+200C) should be preserved for Persian/Arabic."""
        # Persian word with ZWNJ
        persian = "می‌خواهم"
        assert sanitize_unicode(persian) == persian

    def test_preserves_bidi_characters(self):
        """BiDi characters should be preserved for RTL text."""
        # Hebrew embedded in English
        text = "The word \u202Bשלום\u202C means peace"
        assert sanitize_unicode(text) == text

    def test_preserves_normal_text(self):
        """Normal ASCII and Unicode text should be preserved."""
        text = "Hello, World! 123 @#$%"
        assert sanitize_unicode(text) == text

    def test_preserves_simple_emojis(self):
        """Simple emoji characters should be preserved."""
        text = "Hello 👋 World 🌍!"
        assert sanitize_unicode(text) == text

    def test_preserves_compound_emojis(self):
        """Compound emojis using ZWJ should be preserved."""
        technologist = "👨‍💻"
        assert sanitize_unicode(technologist) == technologist

    def test_preserves_international_text(self):
        """International characters should be preserved."""
        text = "Héllo Wörld 你好 مرحبا"
        assert sanitize_unicode(text) == text

    def test_preserves_newlines_and_whitespace(self):
        """Normal whitespace characters should be preserved."""
        text = "Hello\n\tWorld  !"
        assert sanitize_unicode(text) == text

    def test_empty_string(self):
        """Empty string should return empty string."""
        assert sanitize_unicode("") == ""

    def test_none_returns_none(self):
        """None should return None (falsy passthrough)."""
        assert sanitize_unicode(None) is None


class TestSanitizeUnicodeStrict:
    """Tests for sanitize_unicode in strict mode.

    Strict mode removes all potentially dangerous characters including
    zero-width and BiDi. WARNING: This breaks compound emojis and RTL text.
    """

    def test_strict_removes_zero_width_space(self):
        """Zero Width Space (U+200B) should be removed in strict mode."""
        text = "Hello\u200BWorld"
        assert sanitize_unicode(text, strict=True) == "HelloWorld"

    def test_strict_removes_zero_width_joiner(self):
        """Zero Width Joiner (U+200D) should be removed in strict mode."""
        text = "Hello\u200DWorld"
        assert sanitize_unicode(text, strict=True) == "HelloWorld"

    def test_strict_removes_zero_width_non_joiner(self):
        """Zero Width Non-Joiner (U+200C) should be removed in strict mode."""
        text = "Hello\u200CWorld"
        assert sanitize_unicode(text, strict=True) == "HelloWorld"

    def test_strict_removes_bom(self):
        """Byte Order Mark / ZWNBSP (U+FEFF) should be removed in strict mode."""
        text = "\uFEFFHello World"
        assert sanitize_unicode(text, strict=True) == "Hello World"

    def test_strict_removes_bidi_rlo(self):
        """Right-to-Left Override (U+202E) should be removed in strict mode."""
        text = "Hello\u202EWorld"
        assert sanitize_unicode(text, strict=True) == "HelloWorld"

    def test_strict_removes_bidi_isolates(self):
        """Bidirectional isolate characters should be removed in strict mode."""
        text = "A\u2066B\u2067C\u2068D\u2069E"
        assert sanitize_unicode(text, strict=True) == "ABCDE"

    def test_strict_breaks_compound_emojis(self):
        """Compound emojis should be broken in strict mode (expected behavior)."""
        family = "👨‍👩‍👧"  # Man + ZWJ + Woman + ZWJ + Girl
        result = sanitize_unicode(family, strict=True)
        # ZWJ removed, so emojis become separate
        assert "\u200D" not in result
        assert result != family

    def test_strict_env_var(self):
        """LLM_SANITIZE_STRICT=1 should enable strict mode."""
        original = os.environ.get("LLM_SANITIZE_STRICT")
        try:
            os.environ["LLM_SANITIZE_STRICT"] = "1"
            text = "Hello\u200BWorld"
            assert sanitize_unicode(text) == "HelloWorld"
        finally:
            if original is None:
                os.environ.pop("LLM_SANITIZE_STRICT", None)
            else:
                os.environ["LLM_SANITIZE_STRICT"] = original


class TestIntegrationWithModels:
    """Integration tests with llm models."""

    def test_fragment_sanitizes_content(self):
        """Fragment should sanitize content on creation."""
        from llm.utils import Fragment

        malicious = "Hello\U000E0041World"
        fragment = Fragment(malicious, source="test")
        assert str(fragment) == "HelloWorld"
        assert fragment.source == "test"

    def test_fragment_preserves_emojis(self):
        """Fragment should preserve compound emojis."""
        from llm.utils import Fragment

        family = "👨‍👩‍👧"
        fragment = Fragment(family, source="test")
        assert str(fragment) == family

    def test_tool_result_sanitizes_output(self):
        """ToolResult should sanitize output on creation."""
        from llm.models import ToolResult

        malicious = "Result\U000E0041Value"
        result = ToolResult(name="test", output=malicious)
        assert result.output == "ResultValue"

    def test_tool_result_preserves_legitimate_text(self):
        """ToolResult should preserve legitimate Unicode text."""
        from llm.models import ToolResult

        text = "Result with emoji 👨‍💻 and Persian می‌خواهم"
        result = ToolResult(name="test", output=text)
        assert result.output == text

    def test_tool_result_handles_dict_output(self):
        """ToolResult should handle dict output without error."""
        from llm.models import ToolResult

        # Dict with string values containing malicious Unicode should be sanitized
        output = {"key": "value\U000E0041hidden", "nested": {"inner": "text\U000E0042"}}
        result = ToolResult(name="test", output=output)
        assert result.output == {"key": "valuehidden", "nested": {"inner": "text"}}

    def test_tool_result_handles_list_output(self):
        """ToolResult should handle list output without error."""
        from llm.models import ToolResult

        # List of dicts should not crash (the original bug)
        output = [{"a": "value\U000E0041"}, {"b": "other"}]
        result = ToolResult(name="test", output=output)
        assert result.output == [{"a": "value"}, {"b": "other"}]

    def test_prompt_property_sanitizes(self):
        """Prompt.prompt property should return sanitized text."""
        from llm.models import Prompt

        class MockModel:
            supports_schema = False
            supports_tools = False

            class Options:
                pass

        malicious = "Hello\U000E0041World"
        prompt = Prompt(malicious, MockModel())
        assert prompt.prompt == "HelloWorld"

    def test_system_property_sanitizes(self):
        """Prompt.system property should return sanitized text."""
        from llm.models import Prompt

        class MockModel:
            supports_schema = False
            supports_tools = False

            class Options:
                pass

        malicious = "System\U000E0041Prompt"
        prompt = Prompt("test", MockModel(), system=malicious)
        assert prompt.system == "SystemPrompt"

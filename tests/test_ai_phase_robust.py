"""AI phases (code_ai / Ollama): tolerate malformed model JSON and API error bodies."""

from secscan.phases.code_ai import _len_listish, _preview_text


def test_preview_text_non_string():
    assert _preview_text(None) == ""
    assert _preview_text(42) == "42"
    assert _preview_text(["a", "b"]) == "['a', 'b']"
    assert len(_preview_text("x" * 500, max_len=100)) == 103  # 100 + "..."


def test_len_listish_malformed():
    assert _len_listish(None) == 0
    assert _len_listish([1, 2]) == 2
    assert _len_listish({"a": 1, "b": 2}) == 2
    assert _len_listish("oops") == 0


def test_ollama_error_field_returns_tuple_error():
    import json
    from unittest.mock import MagicMock, patch

    fake_resp = MagicMock()
    fake_resp.read.return_value = json.dumps(
        {"error": "model 'foo' not found", "response": None}
    ).encode()
    fake_cm = MagicMock()
    fake_cm.__enter__.return_value = fake_resp
    fake_cm.__exit__.return_value = False

    with patch("urllib.request.urlopen", return_value=fake_cm):
        from secscan.ollama_client import ollama_generate

        text, err = ollama_generate("hi", "foo", timeout=5)
        assert text is None
        assert err is not None
        assert "not found" in err.lower() or "ollama" in err.lower()

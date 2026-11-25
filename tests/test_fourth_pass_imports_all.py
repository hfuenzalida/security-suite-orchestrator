"""Fourth pass: _imports.__all__ documents star-import and includes _-prefixed aliases."""

import importlib


def test_imports_all_matches_module_bindings():
    m = importlib.import_module("secscan.phases._imports")
    assert hasattr(m, "__all__")
    for name in m.__all__:
        assert hasattr(m, name), f"missing {name!r}"


def test_imports_star_includes_underscore_aliases():
    """``from _imports import *`` must bind _get, _re, etc. when __all__ lists them."""
    ns: dict = {}
    exec(
        "from secscan.phases._imports import *",
        ns,
    )
    assert callable(ns["_get"])
    assert callable(ns["_post"])
    assert callable(ns["_merge_req_headers"])
    assert ns["_re"] is not None
    assert callable(ns["_ollama_generate"])


def test_imports_all_is_sorted_for_diffs():
    m = importlib.import_module("secscan.phases._imports")
    assert m.__all__ == sorted(m.__all__)

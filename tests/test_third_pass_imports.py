"""Third pass: phase modules must bind HTTP/Ollama/crypto helpers (not via import *)."""


def test_auth_session_imports_merge_req_headers_and_user_agents():
    import secscan.phases.auth_session as m

    assert callable(getattr(m, "merge_req_headers", None))
    assert isinstance(getattr(m, "USER_AGENTS", None), list)


def test_browser_imports_user_agents():
    import secscan.phases.browser as m

    assert isinstance(getattr(m, "USER_AGENTS", None), list)


def test_dast_imports_cookie_header():
    import secscan.phases.dast as m

    assert callable(getattr(m, "cookie_header", None))


def test_exploit_imports_http_and_stealth():
    import secscan.phases.exploit as m

    assert callable(getattr(m, "http_get", None))
    assert callable(getattr(m, "http_post", None))
    assert callable(getattr(m, "stealth_jitter", None))


def test_specialized_agents_imports_http_crypto_re():
    import secscan.phases.specialized_agents as m

    assert callable(getattr(m, "http_get", None))
    assert callable(getattr(m, "http_post", None))
    import re as re_mod

    assert m.re is re_mod
    assert hasattr(m.base64, "urlsafe_b64decode")


def test_code_ai_and_ai_reasoning_import_ollama_generate():
    import secscan.phases.ai_reasoning as ar
    import secscan.phases.code_ai as ca

    assert callable(getattr(ca, "ollama_generate", None))
    assert callable(getattr(ar, "ollama_generate", None))


def test_chain_imports_session_helpers():
    import secscan.phases.chain as m

    assert isinstance(getattr(m, "USER_AGENTS", None), list)
    assert callable(getattr(m, "cookie_header", None))
    import re as re_mod

    assert m.re is re_mod

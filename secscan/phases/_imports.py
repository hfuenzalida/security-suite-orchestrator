"""Shared imports for phase submodules (internal). Union of symbols used via star-import.

Without ``__all__``, ``from secscan.phases._imports import *`` omits names starting with ``_``.
This module sets ``__all__`` explicitly so underscore-prefixed re-exports (``_get``, ``_re``,
``_merge_req_headers``, …) are included—matching what ``_imports`` actually binds.

Phase modules may still use **explicit** imports (recommended for readability); see
``chain.py``, ``exploit.py``, ``specialized_agents.py``.
"""
from __future__ import annotations

import base64 as _b64
import fnmatch
import hashlib as _hashlib
import hmac as _hmac
import http.cookiejar
import ipaddress
import json
import os
import random
import re as _re
import socket
import string
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from secscan.cli_output import (
    BLUE,
    BOLD,
    RED,
    RESET,
    YELLOW,
    fail,
    header,
    info,
    ok,
    warn,
)
from secscan.external_paths import resolve_nmap, resolve_zap_bat
from secscan.http_client import http_get as _get, http_post as _post
from secscan.http_session import (
    USER_AGENTS as _USER_AGENTS,
    auth_apply,
    auth_clear,
    cookie_header as _cookie_header,
    get_session_cookies,
    get_session_headers,
    has_session_credentials,
    merge_req_headers as _merge_req_headers,
    stealth_jitter as _stealth_jitter,
)
from secscan.json_util import safe_json_decode
from secscan.ollama_client import ollama_generate as _ollama_generate
from secscan.subprocess_runner import run
from secscan.timeouts import scan_timeout_sec
from secscan.tool_adapters.sast import parse_bandit_json, parse_semgrep_json

# Star-import contract: include underscore-prefixed aliases (normally excluded by ``import *``).
__all__ = [
    "BLUE",
    "BOLD",
    "ET",
    "Path",
    "RED",
    "RESET",
    "ThreadPoolExecutor",
    "YELLOW",
    "_USER_AGENTS",
    "_b64",
    "_cookie_header",
    "_get",
    "_hashlib",
    "_hmac",
    "_merge_req_headers",
    "_ollama_generate",
    "_post",
    "_re",
    "_stealth_jitter",
    "auth_apply",
    "auth_clear",
    "fail",
    "fnmatch",
    "get_session_cookies",
    "get_session_headers",
    "has_session_credentials",
    "header",
    "http",
    "info",
    "ipaddress",
    "json",
    "ok",
    "os",
    "parse_bandit_json",
    "parse_semgrep_json",
    "random",
    "resolve_nmap",
    "resolve_zap_bat",
    "run",
    "safe_json_decode",
    "scan_timeout_sec",
    "socket",
    "string",
    "subprocess",
    "tempfile",
    "time",
    "urllib",
    "warn",
]

_mod = globals()
_missing = [n for n in __all__ if n not in _mod]
if _missing:
    raise ImportError(f"secscan.phases._imports: __all__ lists undefined names: {_missing}")

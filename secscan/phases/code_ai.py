"""Phase 0.5 — AI code analysis (local Ollama threat model)."""
from secscan.ollama_client import ollama_generate
from secscan.phases._imports import *  # noqa: F403

# ── Phase 0.5 — AI code analysis (local threat model) ─────────────────────────

_CODE_IGNORE_DIRS = {
    ".git", ".svn", "node_modules", "venv", ".venv", "__pycache__", ".pytest_cache",
    "dist", "build", ".next", "target", "vendor", "coverage", ".mypy_cache", ".tox",
    ".eggs", "site-packages", ".gradle", ".idea", ".vscode",
}
_CODE_TEXT_GLOBS = (
    "*.min.js", "*.bundle.js", "*.chunk.js", "*.map", "*.lock", "*.png", "*.jpg",
    "*.jpeg", "*.gif", "*.webp", "*.ico", "*.pdf", "*.zip", "*.tar", "*.gz",
    "*.woff", "*.woff2", "*.ttf", "*.eot", "*.sqlite", "*.db",
)
_CODE_EXT = {
    ".py", ".pyw", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte",
    ".go", ".java", ".kt", ".kts", ".rb", ".php", ".rs", ".cs", ".fs", ".swift",
    ".html", ".htm", ".css", ".scss", ".sql", ".sh", ".ps1", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".xml",
}
_MAX_MANIFEST_PATHS = 400
_MAX_FILES_READ = 48
_MAX_FILE_SNIPPET = 120_000
_MAX_BUNDLE_CHARS = 52_000


def _preview_text(val: object, max_len: int = 400) -> str:
    """Model JSON may use non-strings for ``summary`` — never slice non-str."""
    if val is None:
        return ""
    s = val if isinstance(val, str) else str(val)
    return s[:max_len] + ("..." if len(s) > max_len else "")


def _len_listish(val: object) -> int:
    """Count risky_patterns / attack_candidates when the model returns a list or a single object."""
    if val is None:
        return 0
    if isinstance(val, list):
        return len(val)
    if isinstance(val, dict):
        return len(val)
    return 0


def _code_path_should_skip(path: Path) -> bool:
    parts_lower = {p.lower() for p in path.parts}
    if parts_lower & _CODE_IGNORE_DIRS:
        return True
    name = path.name.lower()
    if name.startswith(".env") or name in {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}:
        return True
    for pat in _CODE_TEXT_GLOBS:
        if fnmatch.fnmatch(name, pat):
            return True
    if path.suffix.lower() not in _CODE_EXT:
        return True
    return False


def _code_path_priority(rel: str) -> int:
    s = rel.replace("\\", "/").lower()
    score = 0
    for frag, w in (
        ("main.", 18), ("app.", 18), ("server.", 14), ("index.", 10), ("asgi", 12),
        ("wsgi", 12), ("routes", 14), ("/api/", 12), ("controller", 10), ("views", 8),
        ("middleware", 10), ("auth", 9), ("settings", 7), ("config", 5),
    ):
        if frag in s:
            score += w
    return score


def _collect_code_files(root: Path) -> list[Path]:
    out: list[Path] = []
    try:
        root = root.resolve()
    except OSError:
        return out
    if not root.is_dir():
        return out
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _CODE_IGNORE_DIRS and not d.startswith(".")]
        for fn in filenames:
            p = Path(dirpath) / fn
            try:
                if _code_path_should_skip(p):
                    continue
            except ValueError:
                continue
            out.append(p)
    return out


def _build_code_bundle(scan_root: Path) -> tuple[str, dict]:
    """
    Prioritized source bundle + manifest for the LLM.
    Returns (bundle_text, metadata dict).
    """
    all_files = _collect_code_files(scan_root)
    rel_list: list[tuple[str, Path, int]] = []
    for p in all_files:
        try:
            rel = str(p.relative_to(scan_root))
        except ValueError:
            continue
        rel_list.append((rel, p, _code_path_priority(rel)))
    rel_list.sort(key=lambda x: (-x[2], len(x[0])))

    manifest_lines = [x[0] for x in rel_list[:_MAX_MANIFEST_PATHS]]
    if len(rel_list) > _MAX_MANIFEST_PATHS:
        manifest_lines.append(f"... and {len(rel_list) - _MAX_MANIFEST_PATHS} more paths omitted")

    chunks: list[str] = [
        "# Repository layout (relative paths, priority-sorted)\n",
        "\n".join(manifest_lines[: min(len(manifest_lines), 600)]) + "\n\n",
    ]
    meta_files_read: list[str] = []
    total = sum(len(c) for c in chunks)

    for rel, p, _prio in rel_list[:_MAX_FILES_READ]:
        if total >= _MAX_BUNDLE_CHARS:
            break
        try:
            raw = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(raw) > _MAX_FILE_SNIPPET:
            raw = raw[:_MAX_FILE_SNIPPET] + "\n... [truncated]\n"
        block = f"=== FILE: {rel} ===\n{raw}\n"
        if total + len(block) > _MAX_BUNDLE_CHARS:
            remain = _MAX_BUNDLE_CHARS - total - 80
            if remain > 500:
                block = f"=== FILE: {rel} ===\n{raw[:remain]}\n... [truncated for budget]\n"
            else:
                break
        chunks.append(block)
        meta_files_read.append(rel)
        total += len(block)

    return "".join(chunks), {
        "files_discovered": len(rel_list),
        "files_in_bundle": meta_files_read,
        "manifest_paths": len(manifest_lines),
    }


_THREAT_MODEL_SCHEMA = """{
  "auth_boundaries": [{"description": "string", "locations": ["file:line or path"]}],
  "data_sources": [{"pattern": "string", "files": ["path"], "notes": "string"}],
  "data_sinks": [{"sink_type": "sql|shell|ssrf|xss|path|deser|other", "files": ["path"], "detail": "string"}],
  "risky_patterns": [{"severity": "CRITICAL|HIGH|MEDIUM|LOW", "pattern": "string", "file": "path", "reason": "string"}],
  "attack_candidates": [{"path_or_url": "string", "method": "GET|POST|PUT|PATCH|DELETE", "params": ["id"], "hypothesis": "string"}],
  "summary": "one short paragraph"
}"""


def phase_ai_code_analysis(scan_path: str, model: str) -> dict:
    """
    Phase 0.5 — Read prioritized source files, ask local Ollama for a structured threat model.
    Runs before SAST/DAST so later phases can use the JSON (and final AI reasoning includes it).
    """
    header("Phase 0.5 — AI Code Analysis (Local Ollama)")
    root = Path(scan_path)
    if not root.is_dir():
        warn(f"Not a directory: {scan_path} — skipping code analysis")
        return {"status": "skipped", "model": model, "error": "invalid path", "count": 0}

    info("Building source bundle (ignores secrets, minified assets, dependencies)...")
    bundle, meta = _build_code_bundle(root)
    if not meta.get("files_in_bundle"):
        warn("No readable source files found — skipping AI code analysis")
        return {
            "status": "skipped", "model": model, "error": "no source files",
            "count": 0, "meta": meta,
        }

    info(f"Bundle: {len(meta['files_in_bundle'])} full file(s), "
         f"{meta['files_discovered']} path(s) discovered — querying {model}...")

    prompt = (
        "You are an application security reviewer with full access to the repository excerpt below.\n"
        "Analyze AUTH boundaries, untrusted data SOURCES, dangerous SINKS, and concrete ATTACK IDEAS.\n"
        "Respond with ONE JSON object only (no markdown fences, no commentary) matching this schema:\n"
        f"{_THREAT_MODEL_SCHEMA}\n\n"
        "--- SOURCE REPOSITORY EXCERPT ---\n"
        f"{bundle}"
    )

    raw, err = ollama_generate(
        prompt, model, num_predict=3072, temperature=0.15,
        timeout=scan_timeout_sec("ollama_code_ai", 180),
    )
    if err:
        warn(f"AI Code Analysis — {err}")
        return {"status": "error", "model": model, "error": err, "count": 0, "meta": meta}

    structured = safe_json_decode(raw) if raw else None
    if structured is not None and not isinstance(structured, dict):
        structured = None

    if structured:
        n_risk = _len_listish(structured.get("risky_patterns"))
        n_atk = _len_listish(structured.get("attack_candidates"))
        ok(f"AI Code Analysis — threat model JSON parsed ({n_risk} pattern(s), {n_atk} attack candidate(s))")
        print(f"\n{BLUE}  ┌─ Threat model (source-aware) {'─'*22}┐{RESET}")
        summ_preview = _preview_text(structured.get("summary"), 400)
        for line in summ_preview.splitlines()[:6]:
            print(f"{BLUE}  │{RESET} {line}")
        print(f"{BLUE}  └{'─'*47}┘{RESET}\n")
    else:
        warn("AI Code Analysis — model did not return valid JSON; storing raw text only")
        if raw:
            print(f"\n{YELLOW}  Raw (first 800 chars):{RESET}\n{raw[:800]}...\n")

    count = 0
    if isinstance(structured, dict):
        count = _len_listish(structured.get("risky_patterns")) + _len_listish(
            structured.get("attack_candidates")
        )
        if count == 0 and _preview_text(structured.get("summary"), 10_000).strip():
            count = 1

    return {
        "status": "success",
        "model": model,
        "structured": structured,
        "raw_response": raw,
        "meta": meta,
        "count": count,
    }


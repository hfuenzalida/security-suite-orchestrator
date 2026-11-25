"""safe_operations JSON block."""
import sys
from argparse import Namespace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secscan.safe_operations_embed import build_safe_operations_embed  # noqa: E402


def test_safe_operations_keys(tmp_path):
    args = Namespace(
        network_mode="minimal-outbound",
        include_globs=["*.py"],
        exclude_globs=[],
        sanitize_exports=True,
        wipe_temp=False,
        wipe_run_dir=False,
    )
    b = build_safe_operations_embed(args, str(tmp_path))
    assert b["schema_version"] == 1
    assert b["network_mode"] == "minimal-outbound"
    assert b["path_scope"]["include_globs"] == ["*.py"]
    assert "ruleset_version" in b["redaction"]
    assert "registered_count" in b["temp_artifacts"]

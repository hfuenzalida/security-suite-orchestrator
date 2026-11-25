"""Path glob filtering for unified findings."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secscan.path_scope import (  # noqa: E402
    filter_findings_by_path_scope,
    finding_matches_path_scope,
)


def test_exclude_drops_matching(tmp_path):
    root = tmp_path
    f_ok = {"location": "src/a.py:1", "phase": "SAST", "tool": "x"}
    f_bad = {"location": "vendor/b.py:2", "phase": "SAST", "tool": "x"}
    kept, dropped = filter_findings_by_path_scope([f_ok, f_bad], root, (), ("vendor/**",))
    assert dropped == 1 and len(kept) == 1


def test_include_keeps_only_matching(tmp_path):
    root = tmp_path
    f1 = {"location": "src/a.py:1", "phase": "SAST"}
    f2 = {"location": "other/b.py:1", "phase": "SAST"}
    kept, dropped = filter_findings_by_path_scope([f1, f2], root, ("src/**",), ())
    assert dropped == 1 and kept[0]["location"] == "src/a.py:1"


def test_url_location_preserved_with_includes(tmp_path):
    root = tmp_path
    f = {"location": "https://app.example/api", "phase": "DAST"}
    assert finding_matches_path_scope(f, root, ("src/**",), ())


def test_network_posture_offline_merges_skips():
    from argparse import Namespace

    from secscan.network_posture import apply_network_mode_to_args  # noqa: E402

    args = Namespace(skip=["secrets"], network_mode="offline-static")
    apply_network_mode_to_args(args)
    assert "recon" in args.skip and "code_ai" in args.skip and "ai" in args.skip

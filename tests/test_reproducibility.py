"""Reproducibility helpers (git-relative path, supply-chain hashes)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secscan.reproducibility import (  # noqa: E402
    scan_path_relative_to_git,
    supply_chain_file_hashes,
)


def test_supply_chain_hashes_requirements(tmp_path):
    (tmp_path / "requirements.txt").write_text("x==1\n", encoding="utf-8")
    sc = supply_chain_file_hashes(str(tmp_path))
    assert sc["files_present_count"] == 1
    assert sc["files"]["requirements_txt"] is not None


def test_scan_path_git_relative_inside_repo(tmp_path):
    fake_git = {"git_root": str(tmp_path)}
    sub = tmp_path / "svc" / "app"
    sub.mkdir(parents=True)
    rel = scan_path_relative_to_git(str(sub), fake_git)
    assert rel == "svc/app"


def test_scan_path_git_relative_outside_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    rel = scan_path_relative_to_git(str(other), {"git_root": str(repo)})
    assert rel is None

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secscan.temp_registry import (  # noqa: E402
    clear_registry,
    register_temp_path,
    wipe_registered_temp_paths,
)


@pytest.fixture(autouse=True)
def _reset_registry():
    clear_registry()
    yield
    clear_registry()


def test_register_and_wipe(tmp_path):
    p = tmp_path / "artifact.txt"
    p.write_text("secret", encoding="utf-8")
    register_temp_path(p)
    n, errs = wipe_registered_temp_paths()
    assert n == 1
    assert not p.exists()
    assert errs == []


def test_wipe_missing_ok(tmp_path):
    p = tmp_path / "gone.txt"
    p.write_text("x", encoding="utf-8")
    register_temp_path(p)
    p.unlink()
    n, _ = wipe_registered_temp_paths()
    assert n == 0

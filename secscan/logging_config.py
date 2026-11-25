"""Structured logging alongside existing console [OK]/[WARN] output."""

from __future__ import annotations

import json
import logging
import re
import sys
from pathlib import Path
from typing import TextIO

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi_for_log(s: str) -> str:
    return _ANSI.sub("", s)


def setup_logging(
    *,
    verbose: bool,
    log_json: bool,
    log_file: Path | None = None,
) -> logging.Logger:
    """
    Configure the 'secscan' logger. Console helpers in security_scan.py may also call this logger.
    """
    log = logging.getLogger("secscan")
    log.handlers.clear()
    log.setLevel(logging.DEBUG if verbose else logging.INFO)
    log.propagate = False

    def add_handler(stream: TextIO, json_fmt: bool) -> None:
        h = logging.StreamHandler(stream)
        h.setLevel(logging.DEBUG if verbose else logging.INFO)
        if json_fmt:

            class JsonFmt(logging.Formatter):
                def format(self, record: logging.LogRecord) -> str:
                    return json.dumps(
                        {
                            "level": record.levelname,
                            "logger": record.name,
                            "msg": record.getMessage(),
                            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
                        },
                        ensure_ascii=False,
                    )

            h.setFormatter(JsonFmt())
        else:
            h.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
            )
        log.addHandler(h)

    if log_json:
        add_handler(sys.stderr, True)
    elif verbose:
        add_handler(sys.stderr, False)

    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        )
        log.addHandler(fh)

    return log


def log_line(logger: logging.Logger | None, level: int, msg: str) -> None:
    if logger is None:
        return
    logger.log(level, strip_ansi_for_log(msg))

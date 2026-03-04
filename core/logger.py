"""
core/logger.py  —  Structured rotating logger, OS-aware paths.
"""
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

_LOGGERS: dict = {}

def get_logger(root_dir=None, name: str = "kryphorix") -> logging.Logger:
    global _LOGGERS
    if name in _LOGGERS:
        return _LOGGERS[name]

    logger = logging.getLogger(name)
    if logger.handlers:
        _LOGGERS[name] = logger
        return logger

    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console: WARNING and above
    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logging.WARNING)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # File: DEBUG and above
    try:
        log_dir = Path(root_dir) / "logs" if root_dir else Path("logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(
            log_dir / "kryphorix.log",
            maxBytes=10 * 1024 * 1024,   # 10 MB
            backupCount=5,
            encoding="utf-8"
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except Exception:
        pass  # Logging to file is best-effort

    logger.propagate = False
    _LOGGERS[name] = logger
    return logger

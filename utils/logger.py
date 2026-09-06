"""Simple console logger for SecureNet Toolkit."""

import logging
import sys


def setup_logger(verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger("securenet")
    if logger.handlers:
        return logger

    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    fmt = logging.Formatter("[%(levelname)s] %(message)s")
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    logger.propagate = False
    return logger

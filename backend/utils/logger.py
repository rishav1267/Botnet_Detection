"""
Production Structured Logger for NETGUARD IoT Backend
"""

import sys
import time
import logging
from typing import Optional


class CyberFormatter(logging.Formatter):
    """Custom color-coded formatter for cybersecurity SecOps logs."""

    COLORS = {
        logging.DEBUG: "\033[36m",     # Cyan
        logging.INFO: "\033[32m",      # Green
        logging.WARNING: "\033[33m",   # Yellow
        logging.ERROR: "\033[31m",     # Red
        logging.CRITICAL: "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelno, self.RESET)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(record.created))
        prefix = f"[{timestamp} UTC] [{record.levelname:^7}] [{record.name}]"
        msg = f"{color}{prefix} {record.getMessage()}{self.RESET}"
        if record.exc_info:
            msg += "\n" + self.formatException(record.exc_info)
        return msg


def setup_logger(name: str = "NetGuard", level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger(name)
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(CyberFormatter())
        logger.addHandler(handler)

    return logger


logger = setup_logger()

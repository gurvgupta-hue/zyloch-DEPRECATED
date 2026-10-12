"""
Logging configuration for Zyloch GHApp Backend
Provides separate loggers for FastAPI and Scanner flows with rolling file handlers
"""

import os
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Default: <repo>/Zyloch-GHAPP-Backend/logs (Docker WORKDIR /app → /app/logs).
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_LOG_DIR = _PROJECT_ROOT / "logs"
LOG_DIR = os.getenv("LOG_DIR", str(_DEFAULT_LOG_DIR))

# Log file paths
FASTAPI_LOG_FILE = os.path.join(LOG_DIR, "fastapi.log")
SCANNER_LOG_FILE = os.path.join(LOG_DIR, "scanner.log")

# Log format: time, file, message, error traceback
LOG_FORMAT = "%(asctime)s - %(filename)s:%(lineno)d - %(levelname)s - %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Max log file size: 10MB
MAX_BYTES = 10 * 1024 * 1024
# Keep 5 backup files
BACKUP_COUNT = 5


def _ensure_log_dir() -> bool:
    """Create LOG_DIR if possible; return False when file logging should be skipped."""
    try:
        Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
        return True
    except OSError:
        return False


def _add_file_handler(logger: logging.Logger, log_file: str) -> None:
    if not _ensure_log_dir():
        return
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=MAX_BYTES,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
    logger.addHandler(file_handler)


def setup_fastapi_logger():
    """Setup logger for FastAPI flow (main.py)"""
    logger = logging.getLogger("fastapi")
    logger.setLevel(logging.INFO)
    
    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
    console_handler.setFormatter(console_formatter)
    
    logger.addHandler(console_handler)
    _add_file_handler(logger, FASTAPI_LOG_FILE)
    
    return logger


def setup_scanner_logger():
    """Setup logger for Scanner flow (scanner_core)"""
    logger = logging.getLogger("scanner")
    logger.setLevel(logging.INFO)
    
    # Remove existing handlers to avoid duplicates
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
    console_handler.setFormatter(console_formatter)
    
    logger.addHandler(console_handler)
    _add_file_handler(logger, SCANNER_LOG_FILE)
    
    return logger


# Initialize loggers
fastapi_logger = setup_fastapi_logger()
scanner_logger = setup_scanner_logger()


def get_fastapi_logger():
    """Get FastAPI logger instance"""
    return fastapi_logger


def get_scanner_logger():
    """Get Scanner logger instance"""
    return scanner_logger



import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from app.config import settings

def setup_logger(name: str = "SOAR-Engine") -> logging.Logger:
    """
    Configure and return a logger instance.
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(
        getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    )

    # ✅ Auto-create logs directory if it doesn't exist
    log_path = Path(settings.LOG_FILE)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        fmt=(
            "%(asctime)s | %(levelname)-8s | "
            "%(name)s | %(funcName)s:%(lineno)d | %(message)s"
        ),
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    # File Handler
    file_handler = RotatingFileHandler(
        filename=settings.LOG_FILE,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger

# Global logger instance
soar_logger = setup_logger()
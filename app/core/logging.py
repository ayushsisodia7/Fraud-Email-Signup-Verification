import logging
import sys
from typing import Any

def setup_logging(log_level: str = "INFO") -> None:
    """
    Configures the root logger for the application.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    
    # Remove existing handlers to avoid duplicates
    root_logger.handlers = []
    root_logger.addHandler(handler)
    
    # Set levels for some noisy libraries
    logging.getLogger("uvicorn.access").setLevel("WARNING")

def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)

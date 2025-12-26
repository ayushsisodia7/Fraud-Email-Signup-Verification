import logging
import sys
import contextvars

request_id_ctx_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_ctx_var.get()
        return True

def setup_logging(log_level: str = "INFO") -> None:
    """
    Configures the root logger for the application.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(request_id)s - %(message)s"
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    handler.addFilter(RequestIdFilter())
    
    # Remove existing handlers to avoid duplicates
    root_logger.handlers = []
    root_logger.addHandler(handler)
    
    # Set levels for some noisy libraries
    logging.getLogger("uvicorn.access").setLevel("WARNING")

def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)

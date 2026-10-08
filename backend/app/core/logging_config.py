import logging
import sys

LOG_FORMAT = "%(asctime)s [%(levelname)s] [%(name)s]: %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(level: int = logging.INFO) -> None:
    """
    Configures structured logging across the entire application.
    Ensures uniform log output format with timestamps, log levels, and module names.
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT))

    root_logger = logging.getLogger()
    # Avoid duplicate handlers if already configured
    if not root_logger.handlers:
        root_logger.addHandler(handler)
        root_logger.setLevel(level)
    else:
        for h in root_logger.handlers:
            h.setFormatter(logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT))

    # Ensure soar logger propagates cleanly
    soar_logger = logging.getLogger("soar")
    soar_logger.setLevel(level)

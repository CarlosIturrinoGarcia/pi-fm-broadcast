"""Structured logging with correlation IDs and proper formatting."""

import json
import logging
import sys
import time
from typing import Optional, Dict, Any
from contextlib import contextmanager
import threading


# Thread-local storage for correlation IDs
_local = threading.local()


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON.

        Args:
            record: Log record to format

        Returns:
            JSON formatted log string
        """
        log_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add correlation ID if present
        correlation_id = getattr(_local, 'correlation_id', None)
        if correlation_id:
            log_data["correlation_id"] = correlation_id

        # Add extra fields
        if hasattr(record, "extra"):
            log_data.update(record.extra)

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)


class SimpleFormatter(logging.Formatter):
    """Simple human-readable formatter for development."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as simple string.

        Args:
            record: Log record to format

        Returns:
            Formatted log string
        """
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(record.created))
        correlation_id = getattr(_local, 'correlation_id', None)

        parts = [f"[{timestamp}]", record.levelname]

        if correlation_id:
            parts.append(f"[{correlation_id}]")

        parts.append(record.getMessage())

        message = " ".join(parts)

        if record.exc_info:
            message += "\n" + self.formatException(record.exc_info)

        return message


def setup_logger(
    name: str = "pifm_broadcast",
    level: str = "INFO",
    structured: bool = False
) -> logging.Logger:
    """Setup and configure logger.

    Args:
        name: Logger name
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        structured: If True, use JSON structured logging

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))

    # Remove existing handlers
    logger.handlers.clear()

    # Create console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(getattr(logging, level.upper()))

    # Set formatter
    if structured:
        formatter = StructuredFormatter()
    else:
        formatter = SimpleFormatter()

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Prevent propagation to root logger
    logger.propagate = False

    return logger


def set_correlation_id(correlation_id: Optional[str]) -> None:
    """Set correlation ID for current thread.

    Args:
        correlation_id: Correlation ID to set (or None to clear)
    """
    if correlation_id:
        _local.correlation_id = correlation_id
    elif hasattr(_local, 'correlation_id'):
        delattr(_local, 'correlation_id')


def get_correlation_id() -> Optional[str]:
    """Get correlation ID for current thread.

    Returns:
        Current correlation ID or None
    """
    return getattr(_local, 'correlation_id', None)


@contextmanager
def correlation_context(correlation_id: str):
    """Context manager for correlation ID.

    Args:
        correlation_id: Correlation ID to use within context

    Example:
        >>> with correlation_context("msg-12345"):
        ...     logger.info("Processing message")  # Will include correlation_id
    """
    old_id = get_correlation_id()
    set_correlation_id(correlation_id)
    try:
        yield
    finally:
        set_correlation_id(old_id)


class MetricsLogger:
    """Logger for metrics and monitoring."""

    def __init__(self, logger: logging.Logger):
        """Initialize metrics logger.

        Args:
            logger: Base logger to use
        """
        self.logger = logger
        self._counters: Dict[str, int] = {}
        self._lock = threading.Lock()

    def increment(self, metric: str, value: int = 1) -> None:
        """Increment a counter metric.

        Args:
            metric: Metric name
            value: Value to increment by (default 1)
        """
        with self._lock:
            self._counters[metric] = self._counters.get(metric, 0) + value

    def log_metric(self, metric: str, value: Any, **kwargs) -> None:
        """Log a metric value.

        Args:
            metric: Metric name
            value: Metric value
            **kwargs: Additional metadata
        """
        data = {"metric": metric, "value": value}
        data.update(kwargs)
        self.logger.info(f"METRIC: {metric}={value}", extra=data)

    def log_counters(self) -> None:
        """Log all counter values."""
        with self._lock:
            for metric, value in self._counters.items():
                self.log_metric(metric, value)

    def reset_counters(self) -> Dict[str, int]:
        """Reset and return all counter values.

        Returns:
            Dictionary of counter values before reset
        """
        with self._lock:
            counters = self._counters.copy()
            self._counters.clear()
            return counters

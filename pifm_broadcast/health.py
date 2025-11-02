"""Health check and monitoring support."""

import time
import logging
import threading
from typing import Dict, Any


logger = logging.getLogger(__name__)


class HealthMonitor:
    """Health monitoring and metrics collection."""

    def __init__(self):
        """Initialize health monitor."""
        self._lock = threading.Lock()
        self._start_time = time.time()

        # Metrics
        self._messages_processed = 0
        self._messages_succeeded = 0
        self._messages_failed = 0
        self._messages_sent_to_dlq = 0
        self._downloads_succeeded = 0
        self._downloads_failed = 0
        self._broadcasts_succeeded = 0
        self._broadcasts_failed = 0

        # Health status
        self._is_healthy = True
        self._last_activity = time.time()

        logger.info("HealthMonitor initialized")

    def record_message_processed(self, success: bool) -> None:
        """Record message processing result.

        Args:
            success: True if message processed successfully
        """
        with self._lock:
            self._messages_processed += 1
            if success:
                self._messages_succeeded += 1
            else:
                self._messages_failed += 1
            self._last_activity = time.time()

    def record_message_to_dlq(self) -> None:
        """Record message sent to DLQ."""
        with self._lock:
            self._messages_sent_to_dlq += 1
            self._last_activity = time.time()

    def record_download(self, success: bool) -> None:
        """Record download result.

        Args:
            success: True if download succeeded
        """
        with self._lock:
            if success:
                self._downloads_succeeded += 1
            else:
                self._downloads_failed += 1
            self._last_activity = time.time()

    def record_broadcast(self, success: bool) -> None:
        """Record broadcast result.

        Args:
            success: True if broadcast succeeded
        """
        with self._lock:
            if success:
                self._broadcasts_succeeded += 1
            else:
                self._broadcasts_failed += 1
            self._last_activity = time.time()

    def set_health(self, is_healthy: bool) -> None:
        """Set overall health status.

        Args:
            is_healthy: Health status
        """
        with self._lock:
            if self._is_healthy != is_healthy:
                logger.info(f"Health status changed: {is_healthy}")
                self._is_healthy = is_healthy

    def is_healthy(self) -> bool:
        """Check if service is healthy.

        Returns:
            True if healthy
        """
        with self._lock:
            return self._is_healthy

    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics.

        Returns:
            Dictionary of metrics
        """
        with self._lock:
            uptime = int(time.time() - self._start_time)
            idle_time = int(time.time() - self._last_activity)

            return {
                "uptime_seconds": uptime,
                "idle_seconds": idle_time,
                "is_healthy": self._is_healthy,
                "messages": {
                    "processed": self._messages_processed,
                    "succeeded": self._messages_succeeded,
                    "failed": self._messages_failed,
                    "sent_to_dlq": self._messages_sent_to_dlq,
                },
                "downloads": {
                    "succeeded": self._downloads_succeeded,
                    "failed": self._downloads_failed,
                },
                "broadcasts": {
                    "succeeded": self._broadcasts_succeeded,
                    "failed": self._broadcasts_failed,
                },
            }

    def get_health_check(self) -> Dict[str, Any]:
        """Get health check response.

        Returns:
            Health check dictionary
        """
        metrics = self.get_metrics()

        return {
            "status": "healthy" if metrics["is_healthy"] else "unhealthy",
            "uptime_seconds": metrics["uptime_seconds"],
            "messages_processed": metrics["messages"]["processed"],
        }

    def reset_metrics(self) -> Dict[str, Any]:
        """Reset all metrics and return previous values.

        Returns:
            Previous metrics before reset
        """
        with self._lock:
            old_metrics = self.get_metrics()

            self._messages_processed = 0
            self._messages_succeeded = 0
            self._messages_failed = 0
            self._messages_sent_to_dlq = 0
            self._downloads_succeeded = 0
            self._downloads_failed = 0
            self._broadcasts_succeeded = 0
            self._broadcasts_failed = 0

            return old_metrics

    def log_metrics(self) -> None:
        """Log current metrics."""
        metrics = self.get_metrics()
        logger.info(
            f"Metrics: uptime={metrics['uptime_seconds']}s, "
            f"messages={metrics['messages']['processed']}, "
            f"succeeded={metrics['messages']['succeeded']}, "
            f"failed={metrics['messages']['failed']}, "
            f"dlq={metrics['messages']['sent_to_dlq']}"
        )

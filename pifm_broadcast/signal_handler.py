"""Signal handling for hot reload and graceful shutdown."""

import signal
import logging
import threading
from typing import Callable, Optional

from .config import Config
from .silence import SilenceManager
from .broadcaster import Broadcaster


logger = logging.getLogger(__name__)


class SignalHandler:
    """Thread-safe signal handler for hot reload and interrupts."""

    def __init__(
        self,
        config: Config,
        broadcaster: Broadcaster,
        silence_manager: SilenceManager
    ):
        """Initialize signal handler.

        Args:
            config: Application configuration
            broadcaster: Broadcaster instance
            silence_manager: Silence manager instance
        """
        self.config = config
        self.broadcaster = broadcaster
        self.silence = silence_manager

        self._lock = threading.Lock()
        self._reload_requested = False
        self._shutdown_requested = False

        logger.info("SignalHandler initialized")

    def setup_handlers(self) -> None:
        """Setup signal handlers."""
        signal.signal(signal.SIGHUP, self._handle_sighup)
        signal.signal(signal.SIGUSR2, self._handle_sigusr2)
        signal.signal(signal.SIGTERM, self._handle_sigterm)
        signal.signal(signal.SIGINT, self._handle_sigint)

        logger.info("Signal handlers registered (SIGHUP, SIGUSR2, SIGTERM, SIGINT)")

    def _handle_sighup(self, signum, frame):
        """Handle SIGHUP: reload configuration."""
        logger.info("Received SIGHUP: scheduling configuration reload")
        with self._lock:
            self._reload_requested = True

    def _handle_sigusr2(self, signum, frame):
        """Handle SIGUSR2: interrupt current playback and reload."""
        logger.info("Received SIGUSR2: scheduling interrupt + reload")
        with self._lock:
            self._reload_requested = True

        # Request interrupt of current playback
        self.broadcaster.request_interrupt()

    def _handle_sigterm(self, signum, frame):
        """Handle SIGTERM: graceful shutdown."""
        logger.info("Received SIGTERM: scheduling graceful shutdown")
        with self._lock:
            self._shutdown_requested = True

    def _handle_sigint(self, signum, frame):
        """Handle SIGINT (Ctrl+C): graceful shutdown."""
        logger.info("Received SIGINT: scheduling graceful shutdown")
        with self._lock:
            self._shutdown_requested = True

    def should_reload(self) -> bool:
        """Check if reload was requested.

        Returns:
            True if reload requested (flag is cleared)
        """
        with self._lock:
            if self._reload_requested:
                self._reload_requested = False
                return True
            return False

    def should_shutdown(self) -> bool:
        """Check if shutdown was requested.

        Does NOT clear the flag (shutdown is permanent).

        Returns:
            True if shutdown requested
        """
        with self._lock:
            return self._shutdown_requested

    def handle_reload(self) -> None:
        """Perform configuration reload.

        Reloads BROADCAST_CMD from env file and restarts silence.
        """
        logger.info("Performing configuration reload...")

        try:
            old_cmd = self.config.reload_broadcast_cmd()
            if old_cmd:
                logger.info(
                    f"BROADCAST_CMD updated: {old_cmd} -> {self.config.broadcast_cmd_template}"
                )

                # Restart silence with new command
                self.silence.stop()
                self.silence.start()
                logger.info("Silence carrier restarted with new command")
            else:
                logger.info("BROADCAST_CMD unchanged, no reload needed")

        except Exception as e:
            logger.error(f"Configuration reload failed: {e}", exc_info=True)

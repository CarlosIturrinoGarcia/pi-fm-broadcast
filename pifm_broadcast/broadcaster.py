"""Thread-safe broadcaster with timeout and interrupt handling."""

import subprocess
import time
import logging
import threading
from pathlib import Path
from typing import Optional, Callable

from .exceptions import PlaybackError, PlaybackTimeout, PlaybackInterrupted
from .config import Config


logger = logging.getLogger(__name__)


class Broadcaster:
    """Thread-safe audio broadcaster."""

    def __init__(
        self,
        config: Config,
        visibility_callback: Optional[Callable[[int], bool]] = None
    ):
        """Initialize broadcaster.

        Args:
            config: Application configuration
            visibility_callback: Callback to extend message visibility (takes elapsed time)
        """
        self.config = config
        self.visibility_callback = visibility_callback

        # Thread-safe state
        self._lock = threading.Lock()
        self._current_proc: Optional[subprocess.Popen] = None
        self._interrupt_requested = False
        self._start_time = 0.0

        logger.info("Broadcaster initialized")

    def request_interrupt(self) -> None:
        """Request interrupt of current playback."""
        with self._lock:
            self._interrupt_requested = True
            logger.info("Interrupt requested")

    def _consume_interrupt_flag(self) -> bool:
        """Check and clear interrupt flag.

        Returns:
            True if interrupt was requested
        """
        with self._lock:
            if self._interrupt_requested:
                self._interrupt_requested = False
                return True
            return False

    def _check_interrupt(self) -> None:
        """Check if interrupt was requested and raise exception if so.

        Raises:
            PlaybackInterrupted: If interrupt was requested
        """
        if self._consume_interrupt_flag():
            raise PlaybackInterrupted("Playback interrupted by signal")

    def broadcast(self, file_path: Path, correlation_id: Optional[str] = None) -> None:
        """Broadcast audio file.

        This method:
        1. Validates the broadcast command
        2. Starts the broadcast subprocess (WITHOUT shell=True for security)
        3. Monitors playback with timeout and heartbeat
        4. Extends SQS visibility periodically
        5. Handles interrupt signals
        6. Ensures proper cleanup

        Args:
            file_path: Path to audio file to broadcast
            correlation_id: Optional correlation ID for logging

        Raises:
            PlaybackError: If broadcast fails
            PlaybackTimeout: If playback exceeds maximum duration
            PlaybackInterrupted: If playback is interrupted
        """
        if not file_path.exists():
            raise PlaybackError(f"File not found: {file_path}")

        # Parse command into secure argument list (no shell=True!)
        try:
            cmd_args = self.config.parse_broadcast_cmd(str(file_path))
        except Exception as e:
            raise PlaybackError(f"Failed to parse broadcast command: {e}")

        logger.info(f"Starting broadcast: {' '.join(cmd_args)}")

        proc = None
        try:
            # Start subprocess WITHOUT shell=True for security
            proc = subprocess.Popen(
                cmd_args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL
            )

            # Store process reference (thread-safe)
            with self._lock:
                self._current_proc = proc
                self._start_time = time.time()

            last_extend = time.time()

            # Monitor playback with optimized wait (not busy-wait!)
            while True:
                # Check for interrupt
                self._check_interrupt()

                # Wait for process with timeout (OPTIMIZED: no busy-wait!)
                try:
                    return_code = proc.wait(timeout=self.config.DEFAULT_PROCESS_CHECK_INTERVAL)

                    # Process finished
                    if return_code != 0:
                        stderr = proc.stderr.read().decode('utf-8', errors='replace') if proc.stderr else ""
                        raise PlaybackError(
                            f"Broadcast command exited with code {return_code}. "
                            f"stderr: {stderr[:500]}"
                        )

                    # Success!
                    elapsed = int(time.time() - self._start_time)
                    logger.info(f"Broadcast completed successfully (duration: {elapsed}s)")
                    return

                except subprocess.TimeoutExpired:
                    # Process still running, continue monitoring
                    pass

                # Check timeout
                now = time.time()
                elapsed = int(now - self._start_time)

                if elapsed >= self.config.max_playback_secs:
                    logger.warning(f"Playback timeout after {elapsed}s, terminating")
                    raise PlaybackTimeout(
                        f"Playback exceeded maximum duration ({self.config.max_playback_secs}s)"
                    )

                # Extend visibility periodically
                if self.visibility_callback and (now - last_extend) >= self.config.heartbeat_interval:
                    try:
                        self.visibility_callback(elapsed)
                        last_extend = now
                    except Exception as e:
                        logger.warning(f"Failed to extend visibility: {e}")

        except PlaybackInterrupted:
            # Re-raise interrupt exception
            raise

        except PlaybackError:
            # Re-raise playback errors
            raise

        except Exception as e:
            # Wrap unexpected exceptions
            logger.error(f"Unexpected error during broadcast: {e}", exc_info=True)
            raise PlaybackError(f"Broadcast failed: {e}")

        finally:
            # Clean up process
            if proc:
                self._terminate_process(proc)

            # Clear state
            with self._lock:
                self._current_proc = None
                self._start_time = 0.0

    def _terminate_process(self, proc: subprocess.Popen) -> None:
        """Safely terminate a process.

        Args:
            proc: Process to terminate
        """
        try:
            if proc.poll() is None:
                logger.debug("Terminating broadcast process")
                proc.terminate()

                try:
                    proc.wait(timeout=self.config.DEFAULT_TERMINATION_TIMEOUT)
                except subprocess.TimeoutExpired:
                    logger.warning("Process did not terminate gracefully, killing")
                    proc.kill()
                    try:
                        proc.wait(timeout=1.0)
                    except subprocess.TimeoutExpired:
                        logger.error("Process could not be killed!")

        except Exception as e:
            logger.error(f"Error terminating process: {e}")

    def stop_current(self) -> bool:
        """Stop currently playing broadcast.

        Returns:
            True if a broadcast was stopped, False if nothing was playing
        """
        with self._lock:
            if self._current_proc and self._current_proc.poll() is None:
                self._terminate_process(self._current_proc)
                self._current_proc = None
                logger.info("Stopped current broadcast")
                return True
            return False

    def is_playing(self) -> bool:
        """Check if currently broadcasting.

        Returns:
            True if broadcast is in progress
        """
        with self._lock:
            return (
                self._current_proc is not None
                and self._current_proc.poll() is None
            )

    def get_stats(self) -> dict:
        """Get broadcaster statistics.

        Returns:
            Dictionary with statistics
        """
        with self._lock:
            is_playing = self.is_playing()
            elapsed = int(time.time() - self._start_time) if is_playing else 0

            return {
                "is_playing": is_playing,
                "elapsed_seconds": elapsed,
                "max_playback_secs": self.config.max_playback_secs,
            }

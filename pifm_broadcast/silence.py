"""Silence carrier management for idle FM broadcasting."""

import subprocess
import time
import wave
import logging
import threading
from pathlib import Path
from typing import Optional

from .config import Config
from .exceptions import SilenceError


logger = logging.getLogger(__name__)


class SilenceManager:
    """Thread-safe silence carrier manager."""

    def __init__(self, config: Config):
        """Initialize silence manager.

        Args:
            config: Application configuration
        """
        self.config = config
        self._lock = threading.Lock()
        self._silence_proc: Optional[subprocess.Popen] = None

        # Determine silence file path
        if config.silence_file:
            self._silence_path = config.silence_file
        else:
            self._silence_path = config.download_dir / "silence_carrier.wav"

        logger.info(f"SilenceManager initialized: file={self._silence_path}")

    def ensure_silence_file_exists(self) -> Path:
        """Ensure silence WAV file exists, create if needed.

        Returns:
            Path to silence file

        Raises:
            SilenceError: If file creation fails
        """
        if self._silence_path.exists():
            return self._silence_path

        try:
            # Ensure directory exists
            self._silence_path.parent.mkdir(parents=True, exist_ok=True)

            logger.info(
                f"Creating silence carrier WAV: {self._silence_path} "
                f"({self.config.silence_secs}s @ 16kHz mono 16-bit)"
            )

            # Create silent WAV file
            with wave.open(str(self._silence_path), "wb") as wav:
                wav.setnchannels(1)  # Mono
                wav.setsampwidth(2)  # 16-bit
                wav.setframerate(16000)  # 16kHz

                # Write silent frames (all zeros)
                silence_data = b"\x00\x00" * 16000 * self.config.silence_secs
                wav.writeframes(silence_data)

            logger.info(f"Silence file created: {self._silence_path}")
            return self._silence_path

        except Exception as e:
            raise SilenceError(f"Failed to create silence file: {e}")

    def start(self, retries: int = 10, retry_delay: float = 0.8) -> bool:
        """Start silence carrier broadcast.

        Args:
            retries: Number of times to retry if /dev/mem is busy
            retry_delay: Delay between retries in seconds

        Returns:
            True if started successfully, False otherwise
        """
        with self._lock:
            # Stop any existing silence
            self._stop_unsafe()

            # Ensure silence file exists
            try:
                silence_path = self.ensure_silence_file_exists()
            except SilenceError as e:
                logger.error(f"Cannot start silence: {e}")
                return False

            # Parse command into secure argument list
            try:
                cmd_args = self.config.parse_broadcast_cmd(str(silence_path))
            except Exception as e:
                logger.error(f"Failed to parse silence command: {e}")
                return False

            # Try to start silence with retries (for /dev/mem busy errors)
            for attempt in range(retries):
                try:
                    logger.debug(
                        f"Starting silence carrier (attempt {attempt + 1}/{retries}): "
                        f"{' '.join(cmd_args)}"
                    )

                    proc = subprocess.Popen(
                        cmd_args,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        stdin=subprocess.DEVNULL
                    )

                    # Wait briefly to see if it stays running
                    time.sleep(0.25)

                    if proc.poll() is None:
                        # Success! Process is running
                        self._silence_proc = proc
                        logger.info("Silence carrier started")
                        return True

                    # Process exited immediately, retry
                    logger.debug(f"Silence process exited with code {proc.returncode}, retrying")

                except Exception as e:
                    logger.warning(f"Failed to start silence (attempt {attempt + 1}): {e}")

                # Wait before retry
                if attempt < retries - 1:
                    time.sleep(retry_delay)

            logger.warning(
                f"Could not start silence carrier after {retries} attempts. "
                "Will retry later."
            )
            return False

    def stop(self) -> bool:
        """Stop silence carrier broadcast.

        Returns:
            True if silence was stopped, False if not running
        """
        with self._lock:
            return self._stop_unsafe()

    def _stop_unsafe(self) -> bool:
        """Stop silence (must be called with lock held).

        Returns:
            True if silence was stopped, False if not running
        """
        if self._silence_proc is None:
            return False

        if self._silence_proc.poll() is not None:
            # Already stopped
            self._silence_proc = None
            return False

        try:
            logger.debug("Stopping silence carrier")
            self._silence_proc.terminate()

            try:
                self._silence_proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                logger.warning("Silence process did not terminate, killing")
                self._silence_proc.kill()
                try:
                    self._silence_proc.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    logger.error("Could not kill silence process!")

            self._silence_proc = None
            logger.debug("Silence carrier stopped")

            # Brief delay for /dev/mem to be released
            time.sleep(0.2)
            return True

        except Exception as e:
            logger.error(f"Error stopping silence: {e}")
            self._silence_proc = None
            return False

    def ensure_playing(self) -> bool:
        """Ensure silence is playing, start if not.

        Returns:
            True if silence is now playing, False otherwise
        """
        with self._lock:
            # Check if already playing
            if self._silence_proc and self._silence_proc.poll() is None:
                return True

            # Not playing, start it
            self._silence_proc = None

        # Start outside the lock (may take time)
        return self.start()

    def is_playing(self) -> bool:
        """Check if silence is currently playing.

        Returns:
            True if playing, False otherwise
        """
        with self._lock:
            return (
                self._silence_proc is not None
                and self._silence_proc.poll() is None
            )

    def get_stats(self) -> dict:
        """Get silence manager statistics.

        Returns:
            Dictionary with statistics
        """
        return {
            "is_playing": self.is_playing(),
            "silence_file": str(self._silence_path),
            "silence_secs": self.config.silence_secs,
        }

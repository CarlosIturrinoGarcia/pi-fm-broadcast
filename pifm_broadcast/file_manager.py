"""File management and cleanup for downloaded audio files."""

import os
import time
import logging
from pathlib import Path
from typing import List, Optional
import threading


logger = logging.getLogger(__name__)


class FileManager:
    """Manages downloaded files with automatic cleanup."""

    def __init__(
        self,
        download_dir: Path,
        max_stored_files: int = 100,
        cleanup_interval: int = 300
    ):
        """Initialize file manager.

        Args:
            download_dir: Directory where files are downloaded
            max_stored_files: Maximum number of files to keep (0 = unlimited)
            cleanup_interval: Seconds between cleanup runs
        """
        self.download_dir = Path(download_dir)
        self.max_stored_files = max_stored_files
        self.cleanup_interval = cleanup_interval
        self._last_cleanup = 0.0
        self._lock = threading.Lock()

        # Ensure directory exists
        self.download_dir.mkdir(parents=True, exist_ok=True)

        logger.info(
            f"FileManager initialized: dir={self.download_dir}, "
            f"max_files={self.max_stored_files}, "
            f"cleanup_interval={self.cleanup_interval}s"
        )

    def get_download_path(self, filename: str) -> Path:
        """Get full path for downloaded file.

        Args:
            filename: Name of file

        Returns:
            Full path to file in download directory
        """
        # Sanitize filename to prevent path traversal
        safe_filename = Path(filename).name
        return self.download_dir / safe_filename

    def cleanup_old_files(self, force: bool = False) -> int:
        """Clean up old files to stay within max_stored_files limit.

        Keeps the most recently created files and deletes older ones.

        Args:
            force: If True, run cleanup even if interval hasn't elapsed

        Returns:
            Number of files deleted
        """
        with self._lock:
            now = time.time()

            # Check if cleanup is needed
            if not force and (now - self._last_cleanup) < self.cleanup_interval:
                return 0

            # If max_stored_files is 0, no cleanup needed
            if self.max_stored_files == 0:
                self._last_cleanup = now
                return 0

            try:
                # Get all WAV files with their creation times
                files = []
                for file_path in self.download_dir.glob("*.wav"):
                    if file_path.is_file():
                        try:
                            ctime = file_path.stat().st_ctime
                            files.append((file_path, ctime))
                        except OSError as e:
                            logger.warning(f"Failed to stat {file_path}: {e}")

                # Sort by creation time (oldest first)
                files.sort(key=lambda x: x[1])

                # Calculate how many to delete
                num_to_delete = len(files) - self.max_stored_files

                if num_to_delete <= 0:
                    self._last_cleanup = now
                    return 0

                # Delete oldest files
                deleted = 0
                for file_path, _ in files[:num_to_delete]:
                    try:
                        file_path.unlink()
                        logger.debug(f"Deleted old file: {file_path}")
                        deleted += 1
                    except OSError as e:
                        logger.warning(f"Failed to delete {file_path}: {e}")

                if deleted > 0:
                    logger.info(
                        f"Cleaned up {deleted} old files "
                        f"({len(files) - deleted} remaining)"
                    )

                self._last_cleanup = now
                return deleted

            except Exception as e:
                logger.error(f"Error during file cleanup: {e}", exc_info=True)
                self._last_cleanup = now
                return 0

    def auto_cleanup(self) -> int:
        """Perform automatic cleanup if interval has elapsed.

        Returns:
            Number of files deleted
        """
        return self.cleanup_old_files(force=False)

    def get_file_count(self) -> int:
        """Get count of WAV files in download directory.

        Returns:
            Number of WAV files
        """
        try:
            return sum(1 for f in self.download_dir.glob("*.wav") if f.is_file())
        except Exception as e:
            logger.error(f"Error counting files: {e}")
            return 0

    def get_total_size(self) -> int:
        """Get total size of all WAV files in bytes.

        Returns:
            Total size in bytes
        """
        total = 0
        try:
            for file_path in self.download_dir.glob("*.wav"):
                if file_path.is_file():
                    try:
                        total += file_path.stat().st_size
                    except OSError:
                        pass
        except Exception as e:
            logger.error(f"Error calculating total size: {e}")

        return total

    def delete_file(self, file_path: Path) -> bool:
        """Delete a specific file.

        Args:
            file_path: Path to file to delete

        Returns:
            True if deleted successfully, False otherwise
        """
        try:
            Path(file_path).unlink()
            logger.debug(f"Deleted file: {file_path}")
            return True
        except OSError as e:
            logger.warning(f"Failed to delete {file_path}: {e}")
            return False

    def get_stats(self) -> dict:
        """Get statistics about managed files.

        Returns:
            Dictionary with file statistics
        """
        return {
            "download_dir": str(self.download_dir),
            "file_count": self.get_file_count(),
            "total_size_bytes": self.get_total_size(),
            "max_stored_files": self.max_stored_files,
            "cleanup_interval": self.cleanup_interval,
        }

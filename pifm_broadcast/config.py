"""Configuration management with validation and type safety."""

import os
import re
from pathlib import Path
from typing import Optional, Dict
from .exceptions import ConfigurationError


class Config:
    """Application configuration with validation."""

    # Timeouts and limits (constants)
    MAX_VISIBILITY_TIMEOUT = 43200  # 12 hours (SQS maximum)
    DEFAULT_TERMINATION_TIMEOUT = 2.0  # seconds
    DEFAULT_PROCESS_CHECK_INTERVAL = 0.2  # seconds

    def __init__(self):
        """Initialize configuration from environment variables."""
        # AWS Configuration
        self.aws_region: str = os.getenv("AWS_REGION", "us-east-1")
        self.queue_url: str = self._require_env("QUEUE_URL")
        self.dlq_url: Optional[str] = os.getenv("DLQ_URL") or None

        # File paths
        self.download_dir: Path = Path(
            os.getenv("DOWNLOAD_DIR", "/home/rpibroadcaster/wav")
        )
        self.env_file: Path = Path(
            os.getenv("ENV_FILE", "/home/rpibroadcaster/broadcast.env")
        )
        self.silence_file: Optional[Path] = None
        silence_path = os.getenv("SILENCE_FILE")
        if silence_path:
            self.silence_file = Path(silence_path)

        # Broadcast command (now parsed as list for security)
        self.broadcast_cmd_template: str = os.getenv(
            "BROADCAST_CMD",
            "aplay -q {file}"
        )

        # Timeouts and intervals
        self.visibility_timeout: int = int(os.getenv("VISIBILITY", "300"))
        self.heartbeat_interval: int = int(os.getenv("HEARTBEAT_SEC", "5"))
        self.max_playback_secs: int = int(os.getenv("MAX_PLAYBACK_SECS", "1800"))
        self.message_timeout_secs: int = int(os.getenv("MESSAGE_TIMEOUT_SECS", "2400"))
        self.max_receive_count: int = int(os.getenv("MAX_RECEIVE_COUNT", "5"))

        # Silence configuration
        self.silence_secs: int = int(os.getenv("SILENCE_SECS", "600"))

        # File cleanup
        self.max_stored_files: int = int(os.getenv("MAX_STORED_FILES", "100"))
        self.cleanup_interval: int = int(os.getenv("CLEANUP_INTERVAL", "300"))

        # SQS polling
        self.sqs_wait_time: int = int(os.getenv("SQS_WAIT_TIME", "20"))

        # Allowed domains for URL downloads (security)
        allowed = os.getenv("ALLOWED_URL_DOMAINS", "")
        self.allowed_url_domains: Optional[list] = (
            [d.strip() for d in allowed.split(",") if d.strip()]
            if allowed else None
        )

        # Allowed S3 buckets (security)
        allowed_buckets = os.getenv("ALLOWED_S3_BUCKETS", "")
        self.allowed_s3_buckets: Optional[list] = (
            [b.strip() for b in allowed_buckets.split(",") if b.strip()]
            if allowed_buckets else None
        )

        # Validate configuration
        self.validate()

    def _require_env(self, key: str) -> str:
        """Get required environment variable or raise error.

        Args:
            key: Environment variable name

        Returns:
            Environment variable value

        Raises:
            ConfigurationError: If environment variable is not set
        """
        value = os.getenv(key)
        if not value:
            raise ConfigurationError(
                f"Required environment variable {key} is not set"
            )
        return value

    def validate(self) -> None:
        """Validate all configuration values.

        Raises:
            ConfigurationError: If any configuration value is invalid
        """
        # Validate queue URL
        if not self.queue_url.startswith("https://sqs."):
            raise ConfigurationError(
                f"Invalid QUEUE_URL: must start with 'https://sqs.', got {self.queue_url}"
            )

        # Validate DLQ URL if provided
        if self.dlq_url and not self.dlq_url.startswith("https://sqs."):
            raise ConfigurationError(
                f"Invalid DLQ_URL: must start with 'https://sqs.', got {self.dlq_url}"
            )

        # Validate timeouts
        if self.visibility_timeout <= 0 or self.visibility_timeout > self.MAX_VISIBILITY_TIMEOUT:
            raise ConfigurationError(
                f"VISIBILITY must be between 1 and {self.MAX_VISIBILITY_TIMEOUT}, got {self.visibility_timeout}"
            )

        if self.heartbeat_interval <= 0:
            raise ConfigurationError(
                f"HEARTBEAT_SEC must be positive, got {self.heartbeat_interval}"
            )

        if self.heartbeat_interval >= self.visibility_timeout:
            raise ConfigurationError(
                f"HEARTBEAT_SEC ({self.heartbeat_interval}) must be less than VISIBILITY ({self.visibility_timeout})"
            )

        if self.max_playback_secs <= 0:
            raise ConfigurationError(
                f"MAX_PLAYBACK_SECS must be positive, got {self.max_playback_secs}"
            )

        if self.message_timeout_secs <= 0:
            raise ConfigurationError(
                f"MESSAGE_TIMEOUT_SECS must be positive, got {self.message_timeout_secs}"
            )

        # Validate broadcast command template
        if "{file}" not in self.broadcast_cmd_template:
            raise ConfigurationError(
                "BROADCAST_CMD must contain '{file}' placeholder"
            )

        # Validate file cleanup settings
        if self.max_stored_files < 0:
            raise ConfigurationError(
                f"MAX_STORED_FILES must be non-negative, got {self.max_stored_files}"
            )

    def parse_broadcast_cmd(self, file_path: str) -> list:
        """Parse broadcast command template into secure argument list.

        This replaces {file} with the actual file path and returns a list
        of arguments suitable for subprocess.Popen() without shell=True.

        Args:
            file_path: Path to the file to broadcast

        Returns:
            List of command arguments

        Raises:
            ConfigurationError: If command template is invalid
        """
        # Replace {file} placeholder with actual path
        cmd_str = self.broadcast_cmd_template.replace("{file}", file_path)

        # Parse into arguments (handles quotes properly)
        import shlex
        try:
            return shlex.split(cmd_str)
        except ValueError as e:
            raise ConfigurationError(f"Invalid BROADCAST_CMD template: {e}")

    def load_from_file(self, env_file: Optional[Path] = None) -> Dict[str, str]:
        """Load environment variables from file.

        Args:
            env_file: Path to environment file (uses self.env_file if not provided)

        Returns:
            Dictionary of environment variables loaded from file
        """
        path = env_file or self.env_file
        env_vars = {}

        if not path.exists():
            return env_vars

        # Pattern to match: export VAR=value or VAR=value
        line_re = re.compile(
            r"""^\s*(?:export\s+)?(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<val>.*?)\s*$""",
            re.X
        )

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = raw_line.strip().rstrip("\r")

                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                match = line_re.match(line)
                if not match:
                    continue

                key = match.group("key")
                val = match.group("val")

                # Remove quotes if present
                if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
                    val = val[1:-1]

                env_vars[key] = val

        return env_vars

    def reload_broadcast_cmd(self) -> Optional[str]:
        """Reload broadcast command from env file.

        Returns:
            New broadcast command if changed, None otherwise
        """
        env_vars = self.load_from_file()
        new_cmd = env_vars.get("BROADCAST_CMD")

        if new_cmd and new_cmd != self.broadcast_cmd_template:
            # Validate before applying
            if "{file}" not in new_cmd:
                raise ConfigurationError(
                    "Reloaded BROADCAST_CMD must contain '{file}' placeholder"
                )

            old_cmd = self.broadcast_cmd_template
            self.broadcast_cmd_template = new_cmd
            return old_cmd

        return None

    def __repr__(self) -> str:
        """String representation for debugging."""
        return (
            f"Config(queue_url={self.queue_url!r}, "
            f"download_dir={self.download_dir}, "
            f"visibility={self.visibility_timeout}s)"
        )

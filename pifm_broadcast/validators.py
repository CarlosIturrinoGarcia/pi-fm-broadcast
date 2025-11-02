"""Input validation for security and data integrity."""

import os
import re
import wave
from pathlib import Path
from typing import Optional, List
from urllib.parse import urlparse
from .exceptions import ValidationError


class URLValidator:
    """Validator for URL downloads."""

    # Safe URL schemes
    ALLOWED_SCHEMES = {"http", "https"}

    # Blocked domains (known malicious or inappropriate)
    BLOCKED_DOMAINS = {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "169.254.169.254",  # AWS metadata service
        "metadata.google.internal",  # GCP metadata
    }

    def __init__(self, allowed_domains: Optional[List[str]] = None):
        """Initialize URL validator.

        Args:
            allowed_domains: If provided, only these domains are allowed (whitelist)
        """
        self.allowed_domains = set(allowed_domains) if allowed_domains else None

    def validate(self, url: str) -> str:
        """Validate URL for safety.

        Args:
            url: URL to validate

        Returns:
            Validated URL (normalized)

        Raises:
            ValidationError: If URL is invalid or unsafe
        """
        if not url or not isinstance(url, str):
            raise ValidationError("URL must be a non-empty string")

        # Parse URL
        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ValidationError(f"Invalid URL format: {e}")

        # Check scheme
        if parsed.scheme not in self.ALLOWED_SCHEMES:
            raise ValidationError(
                f"URL scheme '{parsed.scheme}' not allowed. "
                f"Must be one of: {', '.join(self.ALLOWED_SCHEMES)}"
            )

        # Check for hostname
        if not parsed.hostname:
            raise ValidationError("URL must have a hostname")

        # Check against blocked domains
        hostname_lower = parsed.hostname.lower()
        if hostname_lower in self.BLOCKED_DOMAINS:
            raise ValidationError(f"Domain '{parsed.hostname}' is blocked")

        # Check against allowed domains (if whitelist is configured)
        if self.allowed_domains:
            if hostname_lower not in self.allowed_domains:
                raise ValidationError(
                    f"Domain '{parsed.hostname}' not in allowed list: "
                    f"{', '.join(self.allowed_domains)}"
                )

        # Check for suspicious patterns
        if ".." in url or url.startswith("file://"):
            raise ValidationError("URL contains suspicious patterns")

        return url


class S3KeyValidator:
    """Validator for S3 bucket and key names."""

    # Path traversal patterns
    DANGEROUS_PATTERNS = ["..", "//", "\\", "\x00"]

    def __init__(self, allowed_buckets: Optional[List[str]] = None):
        """Initialize S3 key validator.

        Args:
            allowed_buckets: If provided, only these buckets are allowed (whitelist)
        """
        self.allowed_buckets = set(allowed_buckets) if allowed_buckets else None

    def validate_bucket(self, bucket: str) -> str:
        """Validate S3 bucket name.

        Args:
            bucket: Bucket name to validate

        Returns:
            Validated bucket name

        Raises:
            ValidationError: If bucket name is invalid
        """
        if not bucket or not isinstance(bucket, str):
            raise ValidationError("Bucket name must be a non-empty string")

        # Check against allowed buckets (if whitelist is configured)
        if self.allowed_buckets and bucket not in self.allowed_buckets:
            raise ValidationError(
                f"Bucket '{bucket}' not in allowed list: "
                f"{', '.join(self.allowed_buckets)}"
            )

        # Basic S3 bucket name validation
        if not re.match(r'^[a-z0-9][a-z0-9.-]*[a-z0-9]$', bucket):
            raise ValidationError(
                f"Invalid S3 bucket name: '{bucket}'. "
                "Must contain only lowercase letters, numbers, dots, and hyphens"
            )

        if len(bucket) < 3 or len(bucket) > 63:
            raise ValidationError(
                f"S3 bucket name length must be 3-63 characters, got {len(bucket)}"
            )

        return bucket

    def validate_key(self, key: str) -> str:
        """Validate S3 object key for path traversal attacks.

        Args:
            key: Object key to validate

        Returns:
            Validated key

        Raises:
            ValidationError: If key contains dangerous patterns
        """
        if not key or not isinstance(key, str):
            raise ValidationError("S3 key must be a non-empty string")

        # Check for path traversal and dangerous patterns
        for pattern in self.DANGEROUS_PATTERNS:
            if pattern in key:
                raise ValidationError(
                    f"S3 key contains dangerous pattern '{pattern}': {key}"
                )

        # Prevent absolute paths
        if key.startswith("/"):
            raise ValidationError(f"S3 key cannot start with '/': {key}")

        # Check key length (S3 max is 1024 bytes)
        if len(key.encode('utf-8')) > 1024:
            raise ValidationError(
                f"S3 key too long: {len(key.encode('utf-8'))} bytes (max 1024)"
            )

        return key

    def validate(self, bucket: str, key: str) -> tuple:
        """Validate both bucket and key.

        Args:
            bucket: Bucket name
            key: Object key

        Returns:
            Tuple of (validated_bucket, validated_key)

        Raises:
            ValidationError: If validation fails
        """
        return self.validate_bucket(bucket), self.validate_key(key)


class AudioFileValidator:
    """Validator for audio files."""

    # Supported formats
    SUPPORTED_EXTENSIONS = {".wav"}

    # Maximum file size (default 100MB)
    MAX_FILE_SIZE = 100 * 1024 * 1024

    def __init__(self, max_file_size: Optional[int] = None):
        """Initialize audio file validator.

        Args:
            max_file_size: Maximum file size in bytes (default 100MB)
        """
        self.max_file_size = max_file_size or self.MAX_FILE_SIZE

    def validate_extension(self, file_path: str) -> str:
        """Validate file extension.

        Args:
            file_path: Path to file

        Returns:
            Validated file path

        Raises:
            ValidationError: If file extension is not supported
        """
        ext = Path(file_path).suffix.lower()

        if ext not in self.SUPPORTED_EXTENSIONS:
            raise ValidationError(
                f"Unsupported file extension '{ext}'. "
                f"Must be one of: {', '.join(self.SUPPORTED_EXTENSIONS)}"
            )

        return file_path

    def validate_file_exists(self, file_path: str) -> str:
        """Validate that file exists and is readable.

        Args:
            file_path: Path to file

        Returns:
            Validated file path

        Raises:
            ValidationError: If file doesn't exist or isn't readable
        """
        path = Path(file_path)

        if not path.exists():
            raise ValidationError(f"File does not exist: {file_path}")

        if not path.is_file():
            raise ValidationError(f"Path is not a file: {file_path}")

        if not os.access(file_path, os.R_OK):
            raise ValidationError(f"File is not readable: {file_path}")

        return file_path

    def validate_file_size(self, file_path: str) -> str:
        """Validate file size.

        Args:
            file_path: Path to file

        Returns:
            Validated file path

        Raises:
            ValidationError: If file is too large
        """
        size = Path(file_path).stat().st_size

        if size == 0:
            raise ValidationError(f"File is empty: {file_path}")

        if size > self.max_file_size:
            raise ValidationError(
                f"File too large: {size} bytes (max {self.max_file_size})"
            )

        return file_path

    def validate_wav_format(self, file_path: str) -> dict:
        """Validate WAV file format and return metadata.

        Args:
            file_path: Path to WAV file

        Returns:
            Dictionary with WAV metadata (channels, sample_rate, duration, etc.)

        Raises:
            ValidationError: If file is not a valid WAV or has unsupported format
        """
        try:
            with wave.open(file_path, 'rb') as wav:
                metadata = {
                    "channels": wav.getnchannels(),
                    "sample_width": wav.getsampwidth(),
                    "sample_rate": wav.getframerate(),
                    "num_frames": wav.getnframes(),
                    "duration": wav.getnframes() / wav.getframerate(),
                }

                # Basic validation
                if metadata["channels"] not in (1, 2):
                    raise ValidationError(
                        f"Unsupported channel count: {metadata['channels']} "
                        "(must be 1 or 2)"
                    )

                if metadata["sample_width"] not in (1, 2, 3, 4):
                    raise ValidationError(
                        f"Unsupported sample width: {metadata['sample_width']} bytes"
                    )

                if metadata["sample_rate"] < 8000 or metadata["sample_rate"] > 192000:
                    raise ValidationError(
                        f"Unsupported sample rate: {metadata['sample_rate']} Hz "
                        "(must be 8000-192000)"
                    )

                if metadata["duration"] <= 0:
                    raise ValidationError("WAV file has zero duration")

                return metadata

        except wave.Error as e:
            raise ValidationError(f"Invalid WAV file: {e}")
        except EOFError:
            raise ValidationError("WAV file is truncated or corrupted")

    def validate(self, file_path: str) -> dict:
        """Perform complete validation on audio file.

        Args:
            file_path: Path to audio file

        Returns:
            Dictionary with file metadata

        Raises:
            ValidationError: If validation fails
        """
        self.validate_extension(file_path)
        self.validate_file_exists(file_path)
        self.validate_file_size(file_path)
        return self.validate_wav_format(file_path)

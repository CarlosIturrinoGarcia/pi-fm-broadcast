"""File download with validation and security checks."""

import json
import logging
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Tuple, Optional

from .config import Config
from .aws_clients import S3Client
from .validators import URLValidator, S3KeyValidator, AudioFileValidator
from .exceptions import DownloadError, ValidationError


logger = logging.getLogger(__name__)


class Downloader:
    """Secure file downloader with validation."""

    def __init__(
        self,
        config: Config,
        s3_client: S3Client,
        file_manager
    ):
        """Initialize downloader.

        Args:
            config: Application configuration
            s3_client: S3 client instance
            file_manager: File manager instance
        """
        self.config = config
        self.s3_client = s3_client
        self.file_manager = file_manager

        # Initialize validators
        self.url_validator = URLValidator(allowed_domains=config.allowed_url_domains)
        self.s3_validator = S3KeyValidator(allowed_buckets=config.allowed_s3_buckets)
        self.audio_validator = AudioFileValidator()

        logger.info("Downloader initialized")

    def parse_message_body(self, body: str) -> dict:
        """Parse SQS message body.

        Handles both direct JSON and SNS-wrapped messages.

        Args:
            body: Message body string

        Returns:
            Parsed payload dictionary

        Raises:
            DownloadError: If parsing fails
        """
        try:
            parsed = json.loads(body)

            # Handle SNS-wrapped messages
            if isinstance(parsed, dict) and "Message" in parsed:
                try:
                    return json.loads(parsed["Message"])
                except (json.JSONDecodeError, TypeError):
                    # Message field is not JSON, return as-is
                    return {"message": parsed["Message"]}

            return parsed

        except json.JSONDecodeError as e:
            raise DownloadError(f"Invalid JSON in message body: {e}")

    def extract_source_info(self, payload: dict) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Extract S3 bucket/key or URL from payload.

        Args:
            payload: Message payload

        Returns:
            Tuple of (bucket, key, url) - only one set will be non-None

        Raises:
            DownloadError: If no valid source found
        """
        # Direct URL
        if "url" in payload:
            return None, None, payload["url"]

        # Direct bucket/key
        if "bucket" in payload and "key" in payload:
            return payload["bucket"], payload["key"], None

        # S3 event notification format
        if "Records" in payload and payload["Records"]:
            try:
                record = payload["Records"][0]
                bucket = record["s3"]["bucket"]["name"]
                key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])
                return bucket, key, None
            except (KeyError, IndexError, TypeError) as e:
                raise DownloadError(f"Invalid S3 event record format: {e}")

        raise DownloadError(
            "No source found in message. Expected 'url', 'bucket'+'key', or 'Records'"
        )

    def download_from_s3(self, bucket: str, key: str) -> Path:
        """Download file from S3 with validation.

        Args:
            bucket: S3 bucket name
            key: S3 object key

        Returns:
            Path to downloaded file

        Raises:
            ValidationError: If validation fails
            DownloadError: If download fails
        """
        # Validate bucket and key
        bucket, key = self.s3_validator.validate(bucket, key)

        # Get destination path
        filename = Path(key).name or "audio.wav"
        if not filename.lower().endswith(".wav"):
            filename += ".wav"

        dest_path = self.file_manager.get_download_path(filename)

        # Download file
        logger.info(f"Downloading from S3: s3://{bucket}/{key}")
        self.s3_client.download_file(bucket, key, str(dest_path))

        # Validate downloaded file
        self._validate_downloaded_file(dest_path)

        return dest_path

    def download_from_url(self, url: str) -> Path:
        """Download file from URL with validation.

        Args:
            url: URL to download from

        Returns:
            Path to downloaded file

        Raises:
            ValidationError: If validation fails
            DownloadError: If download fails
        """
        # Validate URL
        url = self.url_validator.validate(url)

        # Get destination path
        parsed = urllib.parse.urlparse(url)
        filename = Path(parsed.path).name or "audio.wav"
        if not filename.lower().endswith(".wav"):
            filename += ".wav"

        dest_path = self.file_manager.get_download_path(filename)

        # Download file
        logger.info(f"Downloading from URL: {url}")

        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                with open(dest_path, "wb") as f:
                    while True:
                        chunk = response.read(64 * 1024)
                        if not chunk:
                            break
                        f.write(chunk)

        except urllib.error.HTTPError as e:
            raise DownloadError(f"HTTP error {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            raise DownloadError(f"URL error: {e.reason}")
        except TimeoutError:
            raise DownloadError("Download timeout")
        except Exception as e:
            raise DownloadError(f"Download failed: {e}")

        # Validate downloaded file
        self._validate_downloaded_file(dest_path)

        return dest_path

    def _validate_downloaded_file(self, file_path: Path) -> dict:
        """Validate downloaded audio file.

        Args:
            file_path: Path to file

        Returns:
            WAV metadata dictionary

        Raises:
            ValidationError: If validation fails
        """
        try:
            metadata = self.audio_validator.validate(str(file_path))
            logger.info(
                f"Audio validation passed: {metadata['channels']}ch, "
                f"{metadata['sample_rate']}Hz, {metadata['duration']:.1f}s"
            )
            return metadata

        except ValidationError:
            # Delete invalid file
            try:
                file_path.unlink()
            except Exception:
                pass
            raise

    def download(self, message_body: str) -> Path:
        """Download file from message.

        This is the main entry point that:
        1. Parses message body
        2. Extracts source info
        3. Downloads file
        4. Validates file

        Args:
            message_body: SQS message body

        Returns:
            Path to downloaded and validated file

        Raises:
            DownloadError: If download or parsing fails
            ValidationError: If validation fails
        """
        # Parse message
        payload = self.parse_message_body(message_body)

        # Extract source
        bucket, key, url = self.extract_source_info(payload)

        # Skip non-WAV files early
        if key and not key.lower().endswith(".wav"):
            raise ValidationError(f"Skipping non-WAV file: {key}")

        # Download based on source type
        if url:
            return self.download_from_url(url)
        else:
            return self.download_from_s3(bucket, key)

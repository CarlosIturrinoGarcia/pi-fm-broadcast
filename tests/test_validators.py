"""Tests for input validators."""

import pytest
from pifm_broadcast.validators import URLValidator, S3KeyValidator, AudioFileValidator
from pifm_broadcast.exceptions import ValidationError


class TestURLValidator:
    """Test URL validation."""

    def test_valid_http_url(self):
        """Test valid HTTP URL."""
        validator = URLValidator()
        url = validator.validate("http://example.com/file.wav")
        assert url == "http://example.com/file.wav"

    def test_valid_https_url(self):
        """Test valid HTTPS URL."""
        validator = URLValidator()
        url = validator.validate("https://example.com/file.wav")
        assert url == "https://example.com/file.wav"

    def test_rejects_file_scheme(self):
        """Test that file:// URLs are rejected."""
        validator = URLValidator()
        with pytest.raises(ValidationError, match="scheme.*not allowed"):
            validator.validate("file:///etc/passwd")

    def test_rejects_localhost(self):
        """Test that localhost is blocked."""
        validator = URLValidator()
        with pytest.raises(ValidationError, match="blocked"):
            validator.validate("http://localhost/file.wav")

    def test_rejects_metadata_service(self):
        """Test that AWS metadata service is blocked."""
        validator = URLValidator()
        with pytest.raises(ValidationError, match="blocked"):
            validator.validate("http://169.254.169.254/latest/meta-data/")

    def test_allowed_domains_whitelist(self):
        """Test domain whitelist."""
        validator = URLValidator(allowed_domains=["example.com", "cdn.example.com"])

        # Should pass
        validator.validate("https://example.com/file.wav")
        validator.validate("https://cdn.example.com/file.wav")

        # Should fail
        with pytest.raises(ValidationError, match="not in allowed list"):
            validator.validate("https://evil.com/file.wav")

    def test_rejects_path_traversal(self):
        """Test that path traversal is detected."""
        validator = URLValidator()
        with pytest.raises(ValidationError, match="suspicious"):
            validator.validate("http://example.com/../../../etc/passwd")


class TestS3KeyValidator:
    """Test S3 key validation."""

    def test_valid_bucket_name(self):
        """Test valid bucket name."""
        validator = S3KeyValidator()
        bucket = validator.validate_bucket("my-audio-bucket")
        assert bucket == "my-audio-bucket"

    def test_rejects_invalid_bucket_chars(self):
        """Test invalid bucket name characters."""
        validator = S3KeyValidator()
        with pytest.raises(ValidationError, match="Invalid S3 bucket"):
            validator.validate_bucket("My_Bucket")  # Uppercase not allowed

    def test_rejects_short_bucket_name(self):
        """Test bucket name too short."""
        validator = S3KeyValidator()
        with pytest.raises(ValidationError, match="length must be"):
            validator.validate_bucket("ab")

    def test_valid_key(self):
        """Test valid S3 key."""
        validator = S3KeyValidator()
        key = validator.validate_key("audio/2024/file.wav")
        assert key == "audio/2024/file.wav"

    def test_rejects_path_traversal_in_key(self):
        """Test path traversal detection in key."""
        validator = S3KeyValidator()
        with pytest.raises(ValidationError, match="dangerous pattern"):
            validator.validate_key("audio/../../secrets.txt")

    def test_rejects_absolute_path(self):
        """Test absolute path rejection."""
        validator = S3KeyValidator()
        with pytest.raises(ValidationError, match="cannot start with"):
            validator.validate_key("/etc/passwd")

    def test_bucket_whitelist(self):
        """Test bucket whitelist."""
        validator = S3KeyValidator(allowed_buckets=["my-bucket", "my-other-bucket"])

        # Should pass
        validator.validate_bucket("my-bucket")

        # Should fail
        with pytest.raises(ValidationError, match="not in allowed list"):
            validator.validate_bucket("evil-bucket")


class TestAudioFileValidator:
    """Test audio file validation."""

    def test_validates_wav_extension(self):
        """Test WAV extension validation."""
        validator = AudioFileValidator()
        path = validator.validate_extension("/path/to/file.wav")
        assert path == "/path/to/file.wav"

    def test_rejects_non_wav_extension(self):
        """Test non-WAV extension rejection."""
        validator = AudioFileValidator()
        with pytest.raises(ValidationError, match="Unsupported file extension"):
            validator.validate_extension("/path/to/file.mp3")

    def test_validates_file_exists(self, tmp_path):
        """Test file existence validation."""
        validator = AudioFileValidator()

        # Create test file
        test_file = tmp_path / "test.wav"
        test_file.write_bytes(b"test")

        path = validator.validate_file_exists(str(test_file))
        assert path == str(test_file)

    def test_rejects_nonexistent_file(self):
        """Test nonexistent file rejection."""
        validator = AudioFileValidator()
        with pytest.raises(ValidationError, match="does not exist"):
            validator.validate_file_exists("/nonexistent/file.wav")

    def test_rejects_empty_file(self, tmp_path):
        """Test empty file rejection."""
        validator = AudioFileValidator()

        # Create empty file
        test_file = tmp_path / "empty.wav"
        test_file.write_bytes(b"")

        with pytest.raises(ValidationError, match="empty"):
            validator.validate_file_size(str(test_file))

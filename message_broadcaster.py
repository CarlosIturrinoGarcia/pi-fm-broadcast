"""
Picnic Message Broadcaster

Handles fetching group messages from Picnic API and broadcasting them
over FM radio using AWS Polly TTS service.
"""

import json
import logging
import os
import subprocess
import time
from datetime import datetime
from typing import Optional, Dict, List, Any
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class BroadcastError(Exception):
    """Base exception for broadcast errors."""
    pass


class MessageFetchError(BroadcastError):
    """Raised when fetching messages fails."""
    pass


class TTSBroadcastError(BroadcastError):
    """Raised when TTS broadcasting fails."""
    pass


class PicnicMessageBroadcaster:
    """
    Client for fetching Picnic group messages and broadcasting them via TTS.

    Provides methods for message retrieval, filtering, formatting, and
    broadcasting over FM radio using AWS Polly TTS.
    """

    PICNIC_BASE_URL = "http://34.221.11.241:3000/api/v1"

    def __init__(
        self,
        access_token: str,
        tts_endpoint: str = "",
        s3_bucket: str = "audio-txt-broadcast",
        s3_prefix: str = "tts/",
        tts_api_key: str = ""
    ):
        """
        Initialize the message broadcaster.

        Args:
            access_token: Picnic API access token
            tts_endpoint: TTS API endpoint URL
            s3_bucket: S3 bucket for TTS audio storage
            s3_prefix: S3 prefix for TTS audio files
            tts_api_key: API key for TTS API Gateway authentication
        """
        self._access_token = access_token
        self._tts_endpoint = tts_endpoint
        # Strip whitespace from S3 configuration
        self._s3_bucket = s3_bucket.strip() if s3_bucket else "audio-txt-broadcast"
        self._s3_prefix = s3_prefix.strip() if s3_prefix else "tts/"
        # Strip whitespace from API key
        self._tts_api_key = tts_api_key.strip() if tts_api_key else ""
        # Track current broadcast process for immediate termination
        self._current_process = None

        logger.info(f"PicnicMessageBroadcaster initialized")
        logger.info(f"  - S3 Bucket: {self._s3_bucket}")
        logger.info(f"  - S3 Prefix: {self._s3_prefix}")
        logger.info(f"  - TTS API Key configured: {bool(self._tts_api_key)}")

    def get_group_messages(
        self,
        group_id: str,
        limit: int = 50,
        page: int = 1
    ) -> List[Dict[str, Any]]:
        """
        Fetch messages from a Picnic group.

        Args:
            group_id: The group ID to fetch messages from
            limit: Maximum number of messages to retrieve (default: 50)
            page: Page number for pagination (default: 1)

        Returns:
            List of message dictionaries (text messages only)

        Raises:
            MessageFetchError: If fetching messages fails
        """
        url = f"{self.PICNIC_BASE_URL}/message/group-chat-new"
        url += f"?id={group_id}&page={page}&limit={limit}"

        headers = {
            "Authorization": f"Bearer {self._access_token}",
            "Accept-Language": "en",
            "Accept": "application/json"
        }

        try:
            logger.info(f"Fetching messages for group {group_id} (page={page}, limit={limit})")
            logger.debug(f"Request URL: {url}")
            response_data = self._make_request(url, headers=headers)

            logger.debug(f"Response data: {json.dumps(response_data, indent=2)}")

            # Extract messages from response
            if "data" not in response_data:
                logger.warning(f"No 'data' field in response. Response keys: {response_data.keys()}")
                logger.info(f"Full response: {response_data}")
                raise MessageFetchError(f"Invalid API response format. Keys: {list(response_data.keys())}")

            messages = response_data["data"]

            # Check if data contains a messages array
            if isinstance(messages, dict):
                if "data" in messages:
                    # Handle nested data structure: data.data[]
                    messages = messages["data"]
                elif "messages" in messages:
                    messages = messages["messages"]
                elif "items" in messages:
                    messages = messages["items"]
                else:
                    # Single message object
                    messages = [messages]

            if not isinstance(messages, list):
                logger.warning(f"Messages is not a list. Type: {type(messages)}, Value: {messages}")
                raise MessageFetchError(f"Unexpected messages format: {type(messages).__name__}")

            logger.info(f"Fetched {len(messages)} total messages")

            # Log first message structure for debugging
            if messages:
                logger.debug(f"First message structure: {json.dumps(messages[0], indent=2)}")

            # Filter to only text messages (not system messages)
            text_messages = [
                msg for msg in messages
                if msg.get("message_type") == "text" and not msg.get("is_system_message", False)
            ]

            logger.info(f"Filtered to {len(text_messages)} text messages from {len(messages)} total messages")
            return text_messages

        except HTTPError as e:
            if e.code == 401:
                logger.error("Access token expired or invalid")
                raise MessageFetchError("Session expired. Please login again.")
            elif e.code == 404:
                logger.error(f"Group {group_id} not found")
                raise MessageFetchError(f"Group not found: {group_id}")
            else:
                logger.error(f"HTTP error fetching messages: {e.code} - {e.reason}")
                raise MessageFetchError(f"Server error: {e.code} - {e.reason}")
        except URLError as e:
            logger.error(f"Network error fetching messages: {e.reason}")
            raise MessageFetchError(f"Cannot connect to server: {e.reason}")
        except MessageFetchError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error fetching messages: {e}", exc_info=True)
            raise MessageFetchError(f"Failed to fetch messages: {str(e)}")

    def format_message_for_display(self, message: Dict[str, Any]) -> Dict[str, str]:
        """
        Format a message for display in the UI.

        Args:
            message: Message dictionary from API

        Returns:
            Dictionary with formatted display fields:
                - user_name: Full name of the sender
                - message_text: The message content
                - timestamp: Formatted time string
                - display_text: Combined formatted text
        """
        # Extract user information with null safety
        user_info = message.get("user")
        if user_info is None or not isinstance(user_info, dict):
            user_info = {}

        first_name = user_info.get("first_name") or "Unknown"
        last_name = user_info.get("last_name") or "User"
        user_name = f"{first_name} {last_name}".strip()

        # Extract message text
        message_text = message.get("message", "").strip()

        # Extract and format timestamp
        timestamp_str = message.get("created_at", "")
        formatted_time = self._format_timestamp(timestamp_str)

        # Create display text
        display_text = f"{user_name} ({formatted_time}): {message_text}"

        return {
            "user_name": user_name,
            "message_text": message_text,
            "timestamp": formatted_time,
            "display_text": display_text
        }

    def broadcast_message(
        self,
        message_text: str,
        user_name: str,
        fm_frequency: Optional[float] = None,
        voice: str = "Joanna",
        language_code: str = "en-US"
    ) -> Dict[str, Any]:
        """
        Broadcast a message over FM radio using TTS.

        Args:
            message_text: The message content to broadcast
            user_name: Name of the message sender
            fm_frequency: FM frequency (for logging/reference only)
            voice: AWS Polly voice name (default: Joanna)
            language_code: Language code (default: en-US)

        Returns:
            Response from TTS API

        Raises:
            TTSBroadcastError: If broadcasting fails
        """
        if not self._tts_endpoint:
            raise TTSBroadcastError("TTS endpoint not configured")

        # Format the announcement
        announcement = f"Message from {user_name}: {message_text}"

        # Prepare TTS request payload
        payload = {
            "text": announcement,
            "voice": voice,
            "sample_rate": 16000,
            "engine": "neural",
            "language_code": language_code,
            "s3_bucket": self._s3_bucket,
            "s3_prefix": self._s3_prefix
        }

        try:
            logger.info(f"Broadcasting message from {user_name} (frequency: {fm_frequency})")
            logger.debug(f"TTS payload: {payload}")

            # Prepare headers with API key
            tts_headers = {}
            if self._tts_api_key:
                tts_headers["x-api-key"] = self._tts_api_key
                # Debug logging (masked)
                masked_key = f"***{self._tts_api_key[-4:]}" if len(self._tts_api_key) >= 4 else "***"
                logger.info(f"DEBUG: TTS API Key loaded: {bool(self._tts_api_key)}")
                logger.info(f"DEBUG: TTS API Key length: {len(self._tts_api_key)} chars")
                logger.info(f"DEBUG: Headers (masked): {{'Content-Type': 'application/json', 'x-api-key': '{masked_key}'}}")
            else:
                logger.warning("DEBUG: TTS_API_KEY not configured!")

            logger.info(f"DEBUG: Making request to: {self._tts_endpoint}")

            response_data = self._make_request(
                self._tts_endpoint,
                method="POST",
                data=payload,
                headers=tts_headers
            )

            # Log the full API response for debugging
            logger.info(f"DEBUG: API Response: {json.dumps(response_data, indent=2)}")
            print(f"DEBUG: TTS API Response: {json.dumps(response_data, indent=2)}")

            # Parse the response body (it's a JSON string inside the body field)
            try:
                if 'body' in response_data:
                    body = json.loads(response_data['body'])
                else:
                    body = response_data

                s3_key = body.get('key')
                if not s3_key:
                    raise TTSBroadcastError("No S3 key found in TTS API response")

                logger.info(f"TTS audio created at S3 key: {s3_key}")
                print(f"DEBUG: S3 key: {s3_key}")

                # Download from S3
                local_dir = "/home/rpibroadcaster/wav"
                os.makedirs(local_dir, exist_ok=True)

                # Sanitize filename to prevent path traversal
                filename = os.path.basename(s3_key)
                if not filename or filename.startswith('.') or '/' in filename or '\\' in filename:
                    # Generate safe filename from S3 key hash if invalid
                    import hashlib
                    filename = hashlib.md5(s3_key.encode()).hexdigest() + '.wav'
                    logger.warning(f"S3 key had invalid filename, using safe name: {filename}")

                local_file = os.path.join(local_dir, filename)

                # Verify local_file is actually inside local_dir (prevent path traversal)
                local_file_abs = os.path.abspath(local_file)
                local_dir_abs = os.path.abspath(local_dir)
                if not local_file_abs.startswith(local_dir_abs + os.sep):
                    raise TTSBroadcastError(f"Invalid S3 key results in path traversal: {s3_key}")

                logger.info(f"Downloading from S3: s3://{self._s3_bucket}/{s3_key} -> {local_file}")
                print(f"DEBUG: Downloading to: {local_file}")

                s3_client = boto3.client('s3', region_name='us-east-1')
                s3_client.download_file(self._s3_bucket, s3_key, local_file)

                logger.info(f"Successfully downloaded audio file: {local_file}")
                print(f"DEBUG: Download complete: {local_file}")

                # Broadcast on FM
                if fm_frequency is not None:
                    # Validate frequency
                    if not isinstance(fm_frequency, (int, float)) or fm_frequency < 76.0 or fm_frequency > 108.0:
                        raise TTSBroadcastError(f"Invalid FM frequency: {fm_frequency} (must be 76.0-108.0 MHz)")

                    # Get BROADCAST_CMD from environment
                    broadcast_cmd_template = os.getenv('BROADCAST_CMD', '/usr/bin/sudo /usr/local/bin/pifm_broadcast.sh {file} -f {freq}')

                    # Build command safely without shell=True to prevent injection
                    # Parse the template into command parts
                    cmd_parts = broadcast_cmd_template.split()

                    # Replace placeholders in command arguments
                    cmd_args = []
                    for part in cmd_parts:
                        if '{file}' in part:
                            # Verify file exists before using it
                            if not os.path.exists(local_file):
                                raise TTSBroadcastError(f"Audio file not found: {local_file}")
                            cmd_args.append(part.replace('{file}', local_file))
                        elif '{freq}' in part:
                            cmd_args.append(part.replace('{freq}', f"{fm_frequency:.1f}"))
                        else:
                            cmd_args.append(part)

                    logger.info(f"Broadcasting on FM {fm_frequency} MHz: {' '.join(cmd_args)}")
                    print(f"DEBUG: Broadcasting: {' '.join(cmd_args)}")

                    # Kill all pifm processes to free /dev/mem before broadcasting
                    logger.info("Killing all pifm processes to free /dev/mem")
                    subprocess.run(['sudo', 'pkill', '-9', 'pifm'], capture_output=True)

                    # Reduced wait time for /dev/mem release (0.3s instead of 1s)
                    logger.debug("Waiting 0.3s for /dev/mem to be released")
                    time.sleep(0.3)

                    # Execute using Popen so we can track and kill the process
                    self._current_process = subprocess.Popen(
                        cmd_args,
                        shell=False,  # CRITICAL: No shell interpretation
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )

                    try:
                        # Wait for completion but allow interruption
                        stdout, stderr = self._current_process.communicate(timeout=300)
                        returncode = self._current_process.returncode

                        # Log the actual output to see if broadcast worked
                        logger.debug(f"Broadcast return code: {returncode}")
                        if stdout:
                            logger.debug(f"Broadcast stdout: {stdout}")
                        if stderr:
                            logger.debug(f"Broadcast stderr: {stderr}")

                        if returncode == 0:
                            logger.info("FM broadcast completed successfully")
                            # Removed the 2-second delay after broadcast
                            # The communicate() already waits for completion
                        else:
                            logger.error(f"Broadcast command failed: {stderr}")
                            print(f"DEBUG: Broadcast error: {stderr}")
                            raise TTSBroadcastError(f"Broadcast command failed: {stderr}")

                    finally:
                        # Clean up process reference
                        self._current_process = None
                else:
                    logger.warning("No FM frequency provided, skipping broadcast")
                    print("DEBUG: No frequency provided, file downloaded but not broadcast")

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse TTS API response body: {e}")
                raise TTSBroadcastError(f"Invalid response format: {e}")
            except ClientError as e:
                logger.error(f"S3 download failed: {e}")
                raise TTSBroadcastError(f"Failed to download audio from S3: {e}")
            except subprocess.TimeoutExpired:
                logger.error("Broadcast command timed out")
                raise TTSBroadcastError("Broadcast timed out after 5 minutes")
            except Exception as e:
                logger.error(f"Failed to download/broadcast audio: {e}")
                raise TTSBroadcastError(f"Failed to complete broadcast: {e}")

            logger.info("Message broadcast successful")
            return response_data

        except HTTPError as e:
            logger.error(f"HTTP error during broadcast: {e.code} - {e.reason}")
            raise TTSBroadcastError(f"Broadcast failed: {e.code} - {e.reason}")
        except URLError as e:
            logger.error(f"Network error during broadcast: {e.reason}")
            raise TTSBroadcastError(f"Cannot connect to TTS service: {e.reason}")
        except Exception as e:
            logger.error(f"Unexpected error during broadcast: {e}")
            raise TTSBroadcastError(f"Broadcast failed: {str(e)}")

    def stop_broadcast(self):
        """
        Immediately stop the current broadcast by killing the process.

        This allows the user to interrupt a broadcast in progress.
        """
        if self._current_process and self._current_process.poll() is None:
            logger.info("Stopping broadcast immediately...")
            try:
                # Kill the process and all its children
                self._current_process.kill()
                # Give it a moment to clean up
                self._current_process.wait(timeout=1)
                logger.info("Broadcast process killed successfully")
            except Exception as e:
                logger.error(f"Failed to kill broadcast process: {e}")
            finally:
                self._current_process = None

            # Also kill all pifm processes to ensure cleanup
            try:
                subprocess.run(['sudo', 'pkill', '-9', 'pifm'], capture_output=True, timeout=2)
            except Exception as e:
                logger.warning(f"Failed to kill pifm processes: {e}")

    def _format_timestamp(self, timestamp_str: str) -> str:
        """
        Format a timestamp string for display.

        Args:
            timestamp_str: ISO format timestamp string

        Returns:
            Formatted time string (e.g., "2:30 PM")
        """
        if not timestamp_str:
            return "Unknown time"

        try:
            # Parse ISO format timestamp
            # Handles formats like: "2025-01-15T14:30:00.000Z" or "2025-01-15T14:30:00Z"
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))

            # Convert to local time
            local_dt = dt.astimezone()

            # Format as "2:30 PM"
            return local_dt.strftime("%-I:%M %p")
        except (ValueError, AttributeError) as e:
            logger.warning(f"Failed to parse timestamp '{timestamp_str}': {e}")
            return timestamp_str

    def _make_request(
        self,
        url: str,
        method: str = "GET",
        data: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Make an HTTP request.

        Args:
            url: Full URL to request
            method: HTTP method (GET, POST, etc.)
            data: Optional data to send as JSON
            headers: Optional HTTP headers

        Returns:
            Parsed JSON response

        Raises:
            HTTPError: For HTTP errors
            URLError: For network errors
        """
        # Prepare headers
        req_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        if headers:
            req_headers.update(headers)

        # Prepare request
        if data:
            json_data = json.dumps(data).encode('utf-8')
            request = Request(url, data=json_data, headers=req_headers, method=method)
        else:
            request = Request(url, headers=req_headers, method=method)

        # Make request
        with urlopen(request, timeout=30) as response:
            response_body = response.read().decode('utf-8')
            return json.loads(response_body)

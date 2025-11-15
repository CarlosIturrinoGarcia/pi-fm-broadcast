"""
Picnic Message Broadcaster

Handles fetching group messages from Picnic API and broadcasting them
over FM radio using AWS Polly TTS service.
"""

import json
import logging
from datetime import datetime
from typing import Optional, Dict, List, Any
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

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

    def __init__(self, access_token: str, tts_endpoint: str = ""):
        """
        Initialize the message broadcaster.

        Args:
            access_token: Picnic API access token
            tts_endpoint: TTS API endpoint URL
        """
        self._access_token = access_token
        self._tts_endpoint = tts_endpoint
        logger.info("PicnicMessageBroadcaster initialized")

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
                if "messages" in messages:
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
        # Extract user information
        user_info = message.get("user", {})
        first_name = user_info.get("first_name", "Unknown")
        last_name = user_info.get("last_name", "User")
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
            "s3_bucket": "audio-txt-broadcast",
            "s3_prefix": "tts/"
        }

        try:
            logger.info(f"Broadcasting message from {user_name} (frequency: {fm_frequency})")
            logger.debug(f"TTS payload: {payload}")

            response_data = self._make_request(
                self._tts_endpoint,
                method="POST",
                data=payload
            )

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

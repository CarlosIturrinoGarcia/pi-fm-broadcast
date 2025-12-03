"""
Picnic Groups API Client

Handles authentication and API communication with the Picnic Groups backend.
Includes token storage, retrieval, and automatic session management.
"""

import json
import logging
import os
from pathlib import Path
from typing import Optional, Dict, List, Any
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)


class PicnicAPIError(Exception):
    """Base exception for Picnic API errors."""
    pass


class AuthenticationError(PicnicAPIError):
    """Raised when authentication fails."""
    pass


class TokenExpiredError(PicnicAPIError):
    """Raised when the access token has expired."""
    pass


class NetworkError(PicnicAPIError):
    """Raised when network communication fails."""
    pass


class PicnicAPIClient:
    """
    Client for interacting with the Picnic Groups API.

    Provides methods for authentication, group retrieval, and token management.
    """

    BASE_URL = "http://34.221.11.241:3000/api/v1"
    TOKEN_FILE = Path.home() / ".picnic_token"

    def __init__(self):
        """Initialize the API client."""
        self._access_token: Optional[str] = None
        self._user_data: Optional[Dict[str, Any]] = None

    def login(self, email: str, password: str, device_token: str = "") -> Dict[str, Any]:
        """
        Authenticate with the Picnic Groups API.

        Args:
            email: User's email address
            password: User's password
            device_token: Optional device token for push notifications

        Returns:
            Dict containing user data and access token

        Raises:
            AuthenticationError: If credentials are invalid
            NetworkError: If network communication fails
        """
        url = f"{self.BASE_URL}/auth/login"

        payload = {
            "email": email,
            "password": password,
            "device_token": device_token
        }

        try:
            logger.info(f"Attempting login for user: {email}")
            response_data = self._make_request(url, method="POST", data=payload)

            # Extract token and user data from response
            if "data" not in response_data:
                raise AuthenticationError("Invalid response format from server")

            data = response_data["data"]

            if "access_token" not in data:
                raise AuthenticationError("No access token in response")

            self._access_token = data["access_token"]
            self._user_data = data

            # Save token to file for persistence
            self._save_token()

            logger.info("Login successful")
            return data

        except HTTPError as e:
            if e.code == 401:
                logger.warning(f"Authentication failed for user: {email}")
                raise AuthenticationError("Invalid email or password")
            elif e.code == 400:
                logger.warning(f"Bad request during login: {e}")
                raise AuthenticationError("Invalid login request")
            else:
                logger.error(f"HTTP error during login: {e.code} - {e.reason}")
                raise NetworkError(f"Server error: {e.code} - {e.reason}")
        except URLError as e:
            logger.error(f"Network error during login: {e.reason}")
            raise NetworkError(f"Cannot connect to server: {e.reason}")
        except Exception as e:
            logger.error(f"Unexpected error during login: {e}")
            raise PicnicAPIError(f"Login failed: {str(e)}")

    def get_my_groups(self) -> List[Dict[str, Any]]:
        """
        Fetch the user's groups from the API.

        Returns:
            List of group dictionaries

        Raises:
            TokenExpiredError: If the access token has expired
            NetworkError: If network communication fails
            PicnicAPIError: For other API errors
        """
        if not self._access_token:
            # Try to load token from file
            if not self._load_token():
                raise TokenExpiredError("No valid access token. Please login first.")

        url = f"{self.BASE_URL}/event/get-my-groups"

        try:
            logger.info("Fetching user groups")
            response_data = self._make_request(
                url,
                method="GET",
                headers={"Authorization": f"Bearer {self._access_token}"}
            )

            # Extract groups from response
            if "data" in response_data:
                groups = response_data["data"]
                logger.info(f"Successfully fetched {len(groups)} groups")
                return groups if isinstance(groups, list) else [groups]

            logger.warning("No groups data in response")
            return []

        except HTTPError as e:
            if e.code == 401:
                logger.warning("Access token expired or invalid")
                self._clear_token()
                raise TokenExpiredError("Session expired. Please login again.")
            else:
                logger.error(f"HTTP error fetching groups: {e.code} - {e.reason}")
                raise NetworkError(f"Server error: {e.code} - {e.reason}")
        except URLError as e:
            logger.error(f"Network error fetching groups: {e.reason}")
            raise NetworkError(f"Cannot connect to server: {e.reason}")
        except Exception as e:
            logger.error(f"Unexpected error fetching groups: {e}")
            raise PicnicAPIError(f"Failed to fetch groups: {str(e)}")

    def logout(self):
        """
        Clear the access token and logout the user.
        """
        logger.info("Logging out user")
        self._clear_token()

    def is_authenticated(self) -> bool:
        """
        Check if the user has a valid access token.

        Returns:
            True if token exists, False otherwise
        """
        if self._access_token:
            return True

        # Try to load from file
        return self._load_token()

    def get_user_data(self) -> Optional[Dict[str, Any]]:
        """
        Get the current user's data.

        Returns:
            User data dictionary or None if not authenticated
        """
        return self._user_data

    def get_group_detail(self, group_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch full group details by ID including all fields.

        This endpoint returns complete group data including radio_frequency
        which may not be available in the get-my-groups endpoint.

        Args:
            group_id: The group's _id

        Returns:
            Full group data dictionary or None if not found

        Raises:
            TokenExpiredError: If the access token has expired
            NetworkError: If network communication fails
            PicnicAPIError: For other API errors
        """
        if not self._access_token:
            # Try to load token from file
            if not self._load_token():
                raise TokenExpiredError("No valid access token. Please login first.")

        url = f"{self.BASE_URL}/group/detail/{group_id}"

        try:
            logger.info(f"Fetching full details for group {group_id}")
            response_data = self._make_request(
                url,
                method="GET",
                headers={"Authorization": f"Bearer {self._access_token}"}
            )

            # Extract group from response
            if "data" in response_data:
                group = response_data["data"]
                logger.info(f"Successfully fetched details for group {group_id}")
                return group

            logger.warning("No group data in response")
            return None

        except HTTPError as e:
            if e.code == 401:
                logger.warning("Access token expired or invalid")
                self._clear_token()
                raise TokenExpiredError("Session expired. Please login again.")
            elif e.code == 404:
                logger.warning(f"Group {group_id} not found")
                return None
            else:
                logger.error(f"HTTP error fetching group details: {e.code} - {e.reason}")
                raise NetworkError(f"Server error: {e.code} - {e.reason}")
        except URLError as e:
            logger.error(f"Network error fetching group details: {e.reason}")
            raise NetworkError(f"Cannot connect to server: {e.reason}")
        except Exception as e:
            logger.error(f"Unexpected error fetching group details: {e}")
            raise PicnicAPIError(f"Failed to fetch group details: {str(e)}")

    def get_group_by_id(self, group_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch a specific group by ID with full details.

        This method uses the group detail endpoint to get complete data
        including radio_frequency and other fields.

        Args:
            group_id: The group's _id

        Returns:
            Group data dictionary or None if not found

        Raises:
            TokenExpiredError: If the access token has expired
            NetworkError: If network communication fails
            PicnicAPIError: For other API errors
        """
        return self.get_group_detail(group_id)

    def _make_request(
        self,
        url: str,
        method: str = "GET",
        data: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Make an HTTP request to the API.

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

    def _save_token(self):
        """Save the access token to a file."""
        if not self._access_token:
            return

        try:
            token_data = {
                "access_token": self._access_token,
                "user_data": self._user_data
            }

            # Ensure parent directory exists
            self.TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)

            # Write token file with restricted permissions
            with open(self.TOKEN_FILE, 'w') as f:
                json.dump(token_data, f)

            # Set file permissions to be readable only by owner (0600)
            os.chmod(self.TOKEN_FILE, 0o600)

            logger.info(f"Token saved to {self.TOKEN_FILE}")

        except Exception as e:
            logger.error(f"Failed to save token: {e}")

    def _load_token(self) -> bool:
        """
        Load the access token from file.

        Returns:
            True if token was loaded successfully, False otherwise
        """
        try:
            if not self.TOKEN_FILE.exists():
                logger.debug("No saved token file found")
                return False

            with open(self.TOKEN_FILE, 'r') as f:
                token_data = json.load(f)

            self._access_token = token_data.get("access_token")
            self._user_data = token_data.get("user_data")

            if self._access_token:
                logger.info("Token loaded successfully")
                return True

            logger.warning("Token file exists but contains no access token")
            return False

        except Exception as e:
            logger.error(f"Failed to load token: {e}")
            return False

    def _clear_token(self):
        """Clear the access token from memory and file."""
        self._access_token = None
        self._user_data = None

        try:
            if self.TOKEN_FILE.exists():
                self.TOKEN_FILE.unlink()
                logger.info("Token file deleted")
        except Exception as e:
            logger.error(f"Failed to delete token file: {e}")

#!/usr/bin/env python3
"""
Picnic API Login Test Script

This script tests the Picnic API login endpoint and retrieves an access token.
"""

import requests
import sys
import argparse
import json
from typing import Optional, Dict, Any


def login_to_picnic(
    api_host: str,
    email: str,
    password: str,
    device_token: str = ""
) -> Dict[str, Any]:
    """
    Attempt to login to the Picnic API.

    Args:
        api_host: The API host URL (e.g., https://api.picnic.app)
        email: User's email address
        password: User's password
        device_token: Optional device token (defaults to empty string)

    Returns:
        Dictionary containing the result with keys:
        - success: Boolean indicating if login was successful
        - access_token: The access token if successful
        - error: Error message if failed
        - raw_response: The raw response data for debugging
    """
    result = {
        "success": False,
        "access_token": None,
        "error": None,
        "raw_response": None
    }

    # Construct the endpoint URL
    endpoint = f"{api_host.rstrip('/')}/auth/login"

    # Prepare the request
    headers = {
        "Content-Type": "application/json",
        "Accept-Language": "en"
    }

    payload = {
        "email": email,
        "password": password,
        "device_token": device_token
    }

    try:
        print(f"Attempting to login to: {endpoint}")
        print(f"Email: {email}")
        print("-" * 50)

        # Make the POST request
        response = requests.post(
            endpoint,
            json=payload,
            headers=headers,
            timeout=30  # 30 second timeout
        )

        # Store raw response for debugging
        result["raw_response"] = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "text": response.text
        }

        # Check if request was successful
        if response.status_code == 200:
            try:
                data = response.json()

                # Try to extract the access token
                if "data" in data and "access_token" in data["data"]:
                    result["success"] = True
                    result["access_token"] = data["data"]["access_token"]
                else:
                    result["error"] = (
                        f"Unexpected response structure. "
                        f"Response: {json.dumps(data, indent=2)}"
                    )
            except json.JSONDecodeError as e:
                result["error"] = f"Failed to parse JSON response: {e}"
        else:
            # Non-200 status code
            try:
                error_data = response.json()
                result["error"] = (
                    f"Login failed with status {response.status_code}. "
                    f"Response: {json.dumps(error_data, indent=2)}"
                )
            except json.JSONDecodeError:
                result["error"] = (
                    f"Login failed with status {response.status_code}. "
                    f"Response text: {response.text}"
                )

    except requests.exceptions.Timeout:
        result["error"] = "Request timed out after 30 seconds"

    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Connection error: {e}"

    except requests.exceptions.RequestException as e:
        result["error"] = f"Request failed: {e}"

    except Exception as e:
        result["error"] = f"Unexpected error: {type(e).__name__}: {e}"

    return result


def print_result(result: Dict[str, Any]) -> None:
    """Print the login result in a formatted way."""
    print("\n" + "=" * 50)
    print("LOGIN TEST RESULT")
    print("=" * 50)

    if result["success"]:
        print("✓ Status: SUCCESS")
        print(f"\nAccess Token:")
        print(f"  {result['access_token']}")
    else:
        print("✗ Status: FAILED")
        print(f"\nError:")
        print(f"  {result['error']}")

    print("\n" + "=" * 50)

    # Optionally show raw response for debugging
    if result["raw_response"]:
        print("\nRaw Response Details:")
        print(f"  Status Code: {result['raw_response']['status_code']}")
        if result["raw_response"]["text"]:
            print(f"  Response Body: {result['raw_response']['text'][:500]}")


def main():
    """Main function to parse arguments and execute login test."""
    parser = argparse.ArgumentParser(
        description="Test the Picnic API login endpoint",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python picnic_login_test.py --host https://api.picnic.app --email user@example.com --password mypassword
  python picnic_login_test.py -H https://api.picnic.app -e user@example.com -p mypassword
        """
    )

    parser.add_argument(
        "-H", "--host",
        required=True,
        help="API host URL (e.g., https://api.picnic.app)"
    )

    parser.add_argument(
        "-e", "--email",
        required=True,
        help="User email address"
    )

    parser.add_argument(
        "-p", "--password",
        required=True,
        help="User password"
    )

    parser.add_argument(
        "-t", "--device-token",
        default="",
        help="Optional device token (defaults to empty string)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show verbose output including raw response"
    )

    args = parser.parse_args()

    # Execute the login test
    result = login_to_picnic(
        api_host=args.host,
        email=args.email,
        password=args.password,
        device_token=args.device_token
    )

    # Print the result
    print_result(result)

    # Exit with appropriate status code
    sys.exit(0 if result["success"] else 1)


if __name__ == "__main__":
    main()

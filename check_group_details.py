#!/usr/bin/env python3
"""
Script to fetch and display full group details from the API.
Shows all fields including radio_frequency if it exists.
"""

import json
import sys
from api_client import PicnicAPIClient, PicnicAPIError
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


def fetch_group_details(access_token: str, group_id: str):
    """
    Fetch full group details from the API.

    Args:
        access_token: Bearer token for authentication
        group_id: The group's _id

    Returns:
        Group details dictionary
    """
    url = f"http://34.221.11.241:3000/api/v1/group/detail/{group_id}"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    try:
        print(f"Fetching group details for ID: {group_id}")
        print(f"URL: {url}\n")

        request = Request(url, headers=headers, method="GET")

        with urlopen(request, timeout=30) as response:
            response_body = response.read().decode('utf-8')
            data = json.loads(response_body)

        print("=" * 80)
        print("FULL GROUP DETAILS")
        print("=" * 80)
        print(json.dumps(data, indent=2, ensure_ascii=False))
        print("=" * 80)

        # Check specifically for radio_frequency field
        print("\n" + "=" * 80)
        print("RADIO FREQUENCY CHECK")
        print("=" * 80)

        if "data" in data:
            group_data = data["data"]

            # Check direct fields
            if "radio_frequency" in group_data:
                print(f"✓ Found 'radio_frequency': {group_data['radio_frequency']}")
            else:
                print("✗ No 'radio_frequency' field found at top level")

            # List all available fields
            print(f"\nAvailable fields at top level:")
            for key in sorted(group_data.keys()):
                value = group_data[key]
                if isinstance(value, dict):
                    print(f"  - {key}: <dict with {len(value)} keys>")
                elif isinstance(value, list):
                    print(f"  - {key}: <list with {len(value)} items>")
                else:
                    print(f"  - {key}: {value}")

            # Check nested objects for frequency-related fields
            print(f"\nSearching for frequency-related fields in nested objects:")
            frequency_fields = []

            def search_for_frequency(obj, path=""):
                """Recursively search for frequency-related fields."""
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        current_path = f"{path}.{key}" if path else key
                        if "freq" in key.lower():
                            frequency_fields.append((current_path, value))
                        if isinstance(value, (dict, list)):
                            search_for_frequency(value, current_path)
                elif isinstance(obj, list):
                    for i, item in enumerate(obj):
                        current_path = f"{path}[{i}]"
                        search_for_frequency(item, current_path)

            search_for_frequency(group_data)

            if frequency_fields:
                print("  Found frequency-related fields:")
                for path, value in frequency_fields:
                    print(f"    - {path}: {value}")
            else:
                print("  No frequency-related fields found")

        print("=" * 80)

        return data

    except HTTPError as e:
        error_body = e.read().decode('utf-8') if e.fp else "No error body"
        print(f"\n✗ HTTP Error {e.code}: {e.reason}")
        print(f"Response: {error_body}")
        sys.exit(1)

    except URLError as e:
        print(f"\n✗ Network Error: {e.reason}")
        sys.exit(1)

    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def main():
    """Main function."""
    GROUP_ID = "6918ed90a92aa58974af4ed1"

    # Create API client to get access token
    api_client = PicnicAPIClient()

    # Check if authenticated
    if not api_client.is_authenticated():
        print("Not authenticated. Please login first by running broadcast_app.py")
        sys.exit(1)

    # Get the access token
    if not api_client._access_token:
        api_client._load_token()

    if not api_client._access_token:
        print("No access token available. Please login first.")
        sys.exit(1)

    print(f"Using access token: {api_client._access_token[:20]}...")
    print()

    # Fetch and display group details
    fetch_group_details(api_client._access_token, GROUP_ID)


if __name__ == "__main__":
    main()

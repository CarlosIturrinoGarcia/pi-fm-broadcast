#!/usr/bin/env python3
"""
Script to update a group's radio frequency via the API.
"""

import os
import sys
import requests
import json


def get_access_token():
    """Get access token from environment or prompt user."""
    token = os.getenv('ACCESS_TOKEN')
    if not token:
        token = input("Enter your access token: ").strip()
    return token


def update_group_frequency(access_token, group_id, frequency):
    """
    Update a group's radio frequency.

    Args:
        access_token: Bearer token for authentication
        group_id: The _id of the group to update
        frequency: The radio frequency to set (e.g., "90.8")

    Returns:
        Response data or None if error
    """
    url = "http://34.221.11.241:3000/api/v1/group/update"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    body = {
        "_id": group_id,
        "radio_frequency": frequency
    }

    try:
        print(f"Updating group {group_id} with frequency {frequency}...")
        response = requests.post(url, headers=headers, json=body)

        # Print response details
        print(f"\nStatus Code: {response.status_code}")
        print(f"Response:")

        try:
            response_json = response.json()
            print(json.dumps(response_json, indent=2))
        except json.JSONDecodeError:
            print(response.text)

        # Raise exception for bad status codes
        response.raise_for_status()

        return response.json() if response.content else None

    except requests.exceptions.RequestException as e:
        print(f"\nError making request: {e}", file=sys.stderr)
        return None


def main():
    """Main function."""
    # Group details
    GROUP_ID = "6918ed90a92aa58974af4ed1"
    FREQUENCY = "90.8"

    # Get access token
    access_token = get_access_token()

    if not access_token:
        print("Error: No access token provided", file=sys.stderr)
        sys.exit(1)

    # Update the group
    result = update_group_frequency(access_token, GROUP_ID, FREQUENCY)

    if result is not None:
        print("\n✓ Group updated successfully!")
    else:
        print("\n✗ Failed to update group", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Quick test script for TTS API authentication.
Run this to verify your API key and endpoint are working correctly.
"""

import os
import sys
import json
import http.client
import urllib.parse

# Load environment from broadcast.env
def load_env_file(path):
    env = {}
    if not os.path.exists(path):
        return env
    import re
    line_re = re.compile(r"""
        ^\s*
        (?:export\s+)?
        (?P<key>[A-Za-z_][A-Za-z0-9_]*)
        \s*=\s*
        (?P<val>.*?)
        \s*$
    """, re.X)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            s = raw.strip().rstrip("\r")
            if not s or s.startswith("#"):
                continue
            m = line_re.match(s)
            if not m:
                continue
            key = m.group("key")
            val = m.group("val")
            if (len(val) >= 2) and (val[0] == val[-1]) and val[0] in ("'", '"'):
                val = val[1:-1]
            env[key] = val
    return env

# Load from broadcast.env
env_path = os.path.join(os.path.dirname(__file__), "broadcast.env")
env = load_env_file(env_path)

TTS_API_URL = env.get("TTS_API_URL", os.getenv("TTS_API_URL", ""))
TTS_API_KEY = env.get("TTS_API_KEY", os.getenv("TTS_API_KEY", ""))

print("=" * 60)
print("TTS API Test Script")
print("=" * 60)

# Check configuration
if not TTS_API_URL:
    print("❌ ERROR: TTS_API_URL not configured")
    print("   Please set TTS_API_URL in broadcast.env")
    sys.exit(1)

if not TTS_API_KEY:
    print("❌ ERROR: TTS_API_KEY not configured")
    print("   Please set TTS_API_KEY in broadcast.env")
    sys.exit(1)

print(f"✓ TTS_API_URL: {TTS_API_URL}")
print(f"✓ TTS_API_KEY: {'*' * (len(TTS_API_KEY) - 4)}{TTS_API_KEY[-4:]} (length: {len(TTS_API_KEY)} chars)")
print()

# Parse URL
parsed = urllib.parse.urlparse(TTS_API_URL)
host = parsed.netloc
path = parsed.path or "/"

print(f"Host: {host}")
print(f"Path: {path}")
print()

# Build test payload
test_payload = {"text": "Hello, this is a test message"}
body = json.dumps(test_payload).encode("utf-8")

# Build headers
headers = {
    "Content-Type": "application/json",
    "x-api-key": TTS_API_KEY.strip()
}

print("Request Headers:")
for key, value in headers.items():
    if key == "x-api-key":
        print(f"  {key}: {'*' * (len(value) - 4)}{value[-4:]}")
    else:
        print(f"  {key}: {value}")
print()

print("Request Payload:")
print(f"  {json.dumps(test_payload, indent=2)}")
print()

print("Sending request...")
print("-" * 60)

try:
    conn = http.client.HTTPSConnection(host, timeout=30)
    conn.request("POST", path, body=body, headers=headers)

    response = conn.getresponse()
    response_data = response.read().decode("utf-8")

    print(f"Response Status: {response.status} {response.reason}")
    print()

    print("Response Headers:")
    for key, value in response.getheaders():
        print(f"  {key}: {value}")
    print()

    print("Response Body:")
    try:
        formatted = json.dumps(json.loads(response_data), indent=2)
        print(formatted)
    except:
        print(response_data)
    print()

    if response.status == 200:
        print("=" * 60)
        print("✅ SUCCESS! TTS API is working correctly")
        print("=" * 60)
    elif response.status == 403:
        print("=" * 60)
        print("❌ ERROR: 403 Forbidden")
        print("=" * 60)
        print()
        print("Common causes:")
        print("1. Invalid API key - verify the key in AWS API Gateway")
        print("2. API key has whitespace - check broadcast.env for extra spaces")
        print("3. API key not associated with the deployment stage")
        print("4. Usage plan quota exceeded")
        print("5. API Gateway resource policy blocking requests")
        print()
        print("Troubleshooting steps:")
        print("1. Check your API key in AWS Console:")
        print("   - Go to API Gateway → API Keys")
        print("   - Verify the key value matches what's in broadcast.env")
        print("2. Verify the API key is associated with a usage plan")
        print("3. Check the usage plan is associated with your API stage")
        print("4. Test the API using curl:")
        print(f'   curl -X POST "{TTS_API_URL}" \\')
        print(f'     -H "Content-Type: application/json" \\')
        print(f'     -H "x-api-key: YOUR_API_KEY" \\')
        print(f'     -d \'{{"text": "test"}}\'')
    else:
        print("=" * 60)
        print(f"❌ ERROR: Unexpected status {response.status}")
        print("=" * 60)

    conn.close()

except Exception as e:
    print("=" * 60)
    print(f"❌ EXCEPTION: {type(e).__name__}")
    print("=" * 60)
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()

"""
Configuration module for PyQt5 Dashboard.
Provides path management and frequency extraction utilities.
"""

import os
import re
from pathlib import Path
from typing import Optional

# Auto-detect installation paths
HOME_DIR = Path.home()
SCRIPT_DIR = Path(__file__).parent.absolute()

# Try to find the best path for env file
if os.path.exists("/home/rpibroadcaster/broadcast.env"):
    ENV_PATH = "/home/rpibroadcaster/broadcast.env"
elif os.path.exists(SCRIPT_DIR / "broadcast.env"):
    ENV_PATH = str(SCRIPT_DIR / "broadcast.env")
else:
    # Fallback to script directory
    ENV_PATH = str(SCRIPT_DIR / "broadcast.env")

# Service executable path
if os.path.exists("/home/rpibroadcaster/pi-fm-broadcast/pifm-broadcast"):
    SERVICE_PATH = "/home/rpibroadcaster/pi-fm-broadcast/pifm-broadcast"
elif os.path.exists(SCRIPT_DIR / "pifm-broadcast"):
    SERVICE_PATH = str(SCRIPT_DIR / "pifm-broadcast")
else:
    # Fallback - try to find in PATH
    SERVICE_PATH = str(SCRIPT_DIR / "pifm-broadcast")

# Python executable for service
if os.path.exists("/home/rpibroadcaster/venv/bin/python"):
    PYTHON_BIN = "/home/rpibroadcaster/venv/bin/python"
else:
    import sys
    PYTHON_BIN = sys.executable

# Download directory
if os.path.exists("/home/rpibroadcaster/wav"):
    DOWNLOAD_DIR = "/home/rpibroadcaster/wav"
else:
    DOWNLOAD_DIR = str(SCRIPT_DIR / "wav")


def extract_current_frequency(env_file_path: str) -> Optional[float]:
    """
    Extract the current broadcast frequency from BROADCAST_CMD in env file.

    Looks for patterns like:
    - -f 91.5
    - {freq} (template)
    - <num> (template)

    Args:
        env_file_path: Path to the .env file

    Returns:
        Frequency in MHz as float, or None if not found

    Example:
        >>> extract_current_frequency("/path/to/broadcast.env")
        91.5
    """
    if not os.path.exists(env_file_path):
        return None

    try:
        with open(env_file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        # Look for BROADCAST_CMD line
        for line in content.splitlines():
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            # Check if this is BROADCAST_CMD
            if not re.match(r"^\s*(?:export\s+)?BROADCAST_CMD\s*=", line):
                continue

            # Extract value (remove quotes if present)
            match = re.search(r'BROADCAST_CMD\s*=\s*["\']?(.+?)["\']?\s*$', line)
            if not match:
                continue

            cmd = match.group(1)

            # Look for -f <number> pattern
            freq_match = re.search(r'-f\s+(\d+(?:\.\d+)?)', cmd)
            if freq_match:
                try:
                    return float(freq_match.group(1))
                except ValueError:
                    pass

            # Look for {freq} or <num> and return None (templates need explicit setting)
            if "{freq}" in cmd or "<num>" in cmd:
                return None

    except Exception as e:
        print(f"Warning: Could not extract frequency from {env_file_path}: {e}")
        return None

    return None


def validate_frequency(freq: float) -> bool:
    """
    Validate that frequency is in FM broadcast range.

    Args:
        freq: Frequency in MHz

    Returns:
        True if valid, False otherwise
    """
    return 76.0 <= freq <= 108.0


def get_service_status() -> dict:
    """
    Get current service status via systemd.

    Returns:
        Dictionary with status information
    """
    import subprocess

    status = {
        "running": False,
        "enabled": False,
        "active_state": "unknown",
        "sub_state": "unknown",
    }

    try:
        # Check if service is running
        result = subprocess.run(
            ["systemctl", "is-active", "pifm-broadcast"],
            capture_output=True,
            text=True,
            timeout=2
        )
        status["active_state"] = result.stdout.strip()
        status["running"] = result.returncode == 0

        # Check if service is enabled
        result = subprocess.run(
            ["systemctl", "is-enabled", "pifm-broadcast"],
            capture_output=True,
            text=True,
            timeout=2
        )
        status["enabled"] = result.returncode == 0

    except (FileNotFoundError, subprocess.TimeoutExpired):
        # systemctl not available or timed out
        pass
    except Exception as e:
        print(f"Warning: Could not get service status: {e}")

    return status


# Export key paths
__all__ = [
    'ENV_PATH',
    'SERVICE_PATH',
    'PYTHON_BIN',
    'DOWNLOAD_DIR',
    'extract_current_frequency',
    'validate_frequency',
    'get_service_status',
]

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-01-15

### 🔒 Security

**CRITICAL FIXES:**
- **Fixed command injection vulnerability** - Replaced `shell=True` with secure argument list parsing
- **Fixed race conditions** - Added thread locks for all shared state (BROADCAST_CMD, process objects)
- **Added input validation** - URL, S3 key, and audio file validation to prevent attacks
- **Secrets management** - Added script to remove secrets from git history
- **Whitelisting support** - Optional S3 bucket and URL domain whitelists

### ✨ Features

**New Capabilities:**
- **Modular architecture** - Refactored into 14 focused modules for maintainability
- **Structured logging** - JSON logging with correlation IDs for tracking messages
- **Health monitoring** - Metrics collection for messages, downloads, broadcasts
- **Automatic file cleanup** - Prevents disk space exhaustion
- **Audio validation** - Validates WAV format, sample rate, duration
- **Graceful shutdown** - Proper cleanup on SIGTERM/SIGINT
- **Type hints** - Full type annotations for better IDE support
- **Comprehensive docstrings** - Documentation for all public APIs

### 🚀 Performance

- **Eliminated busy-wait loops** - Uses `proc.wait(timeout)` instead of `sleep(0.2)` polling
- **Optimized subprocess handling** - Non-blocking I/O with proper timeout handling
- **Signal handlers optimized** - No I/O in signal handlers, flag-based communication

### 🛠️ Improvements

**Code Quality:**
- **Specific exception handling** - Replaced 12 broad `except Exception` with specific types
- **Configuration validation** - All config validated on startup with clear error messages
- **Better error messages** - Specific error types with actionable information
- **Thread safety** - All shared state protected by locks

**Operations:**
- **Systemd service file** - Production-ready service configuration
- **Comprehensive README** - Architecture diagrams, troubleshooting guides
- **Migration guide** - Step-by-step upgrade instructions
- **Unit tests** - Test coverage for config and validators

### 📦 Dependencies

- Added `requirements.txt` with pinned versions:
  - boto3==1.34.22
  - botocore==1.34.22

### 🔧 Configuration

**New Environment Variables:**
- `MAX_STORED_FILES` - Maximum files to keep (default: 100)
- `CLEANUP_INTERVAL` - Cleanup frequency in seconds (default: 300)
- `ALLOWED_S3_BUCKETS` - S3 bucket whitelist (optional)
- `ALLOWED_URL_DOMAINS` - URL domain whitelist (optional)
- `SQS_WAIT_TIME` - Long polling wait time (default: 20)

### 🗂️ File Structure

**New Modules:**
```
pifm_broadcast/
├── __init__.py
├── main.py               # Main entry point
├── config.py             # Configuration management
├── exceptions.py         # Custom exceptions
├── logger.py             # Structured logging
├── validators.py         # Input validation
├── aws_clients.py        # SQS & S3 wrappers
├── file_manager.py       # File cleanup
├── downloader.py         # Secure downloads
├── broadcaster.py        # Thread-safe broadcasting
├── silence.py            # Silence carrier
├── message_processor.py  # Message handling
├── signal_handler.py     # Signal management
└── health.py             # Health monitoring
```

**New Files:**
- `pifm-broadcast` - Executable entry point
- `requirements.txt` - Python dependencies
- `broadcast.env.example` - Configuration template
- `CHANGELOG.md` - This file
- `MIGRATION.md` - Upgrade guide
- `systemd/pifm-broadcast.service` - Systemd service file
- `systemd/README.md` - Service installation guide
- `scripts/remove_secrets_from_git.sh` - Security cleanup script
- `tests/` - Unit test suite

### ⚠️ Breaking Changes

1. **Command-line interface changed:**
   - Old: `python3 pi_broadcast.py`
   - New: `./pifm-broadcast` or `python3 -m pifm_broadcast.main`

2. **Import paths changed:**
   - Code is now in `pifm_broadcast/` package
   - Use `from pifm_broadcast import ...` for imports

3. **Configuration validation:**
   - Invalid config now fails fast at startup
   - Missing required env vars raise `ConfigurationError`

4. **Exception types changed:**
   - More specific exceptions (see `exceptions.py`)
   - Catch specific types instead of bare `Exception`

### 📝 Migration Notes

See `MIGRATION.md` for detailed upgrade instructions from v1.x to v2.0.

### 🐛 Bug Fixes

- Fixed resource leak where downloaded files were never cleaned up
- Fixed race condition on `BROADCAST_CMD` reload
- Fixed race condition on `_silence_proc` and `_player_proc` access
- Fixed silent failures in signal handlers
- Fixed subprocess cleanup on exceptions
- Fixed path traversal vulnerability in S3 keys
- Fixed SSRF vulnerability in URL downloads

---

## [1.0.0] - 2024-09-28

### Initial Release

- Basic SQS polling and message processing
- S3 and URL download support
- FM broadcasting via pifm
- Silence carrier for idle periods
- Signal-based hot reload (SIGHUP, SIGUSR2)
- SQS visibility extension during playback
- DLQ support
- Basic error handling and logging

### Known Issues (Fixed in 2.0.0)

- Command injection vulnerability via `shell=True`
- Race conditions on shared global state
- No file cleanup (disk exhaustion risk)
- Secrets exposed in git history
- Overly broad exception handling
- No input validation
- Busy-wait polling loops
- No tests or health monitoring

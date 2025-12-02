# Testing Guide
## Pi FM Broadcast Application

This document describes how to run tests and verify the application is working correctly.

---

## Quick Start

Run all tests:
```bash
python3 -m pytest test_message_broadcaster.py -v
```

Expected output:
```
============================= test session starts ==============================
collected 15 items

test_message_broadcaster.py::...::test_broadcast_handles_missing_s3_key PASSED
test_message_broadcaster.py::...::test_broadcast_handles_s3_download_failure PASSED
test_message_broadcaster.py::...::test_broadcast_handles_subprocess_failure PASSED
test_message_broadcaster.py::...::test_broadcast_uses_env_broadcast_cmd PASSED
test_message_broadcaster.py::...::test_command_injection_protection PASSED
test_message_broadcaster.py::...::test_format_message_for_display PASSED
test_message_broadcaster.py::...::test_format_message_handles_missing_user_data PASSED
test_message_broadcaster.py::...::test_frequency_validation_accepts_valid_frequency PASSED
test_message_broadcaster.py::...::test_frequency_validation_rejects_invalid_frequency PASSED
test_message_broadcaster.py::...::test_initialization PASSED
test_message_broadcaster.py::...::test_initialization_strips_whitespace PASSED
test_message_broadcaster.py::...::test_make_request_includes_api_key_header PASSED
test_message_broadcaster.py::...::test_no_tts_endpoint_raises_error PASSED
test_message_broadcaster.py::...::test_path_traversal_protection PASSED
test_message_broadcaster.py::...::test_no_shell_injection_in_frequency PASSED

============================== 15 passed in 0.75s ==============================
```

---

## Test Coverage

### Security Tests (Critical)

#### 1. Command Injection Protection
**Test:** `test_command_injection_protection`
**Validates:**
- subprocess.run() uses `shell=False`
- Commands passed as list, not string
- No shell metacharacter interpretation

#### 2. Path Traversal Protection
**Test:** `test_path_traversal_protection`
**Validates:**
- Malicious S3 keys don't escape directory
- Filenames are sanitized
- Paths like `../../../etc/passwd` are blocked

#### 3. Frequency Validation
**Tests:**
- `test_frequency_validation_rejects_invalid_frequency`
- `test_frequency_validation_accepts_valid_frequency`
- `test_no_shell_injection_in_frequency`

**Validates:**
- Frequencies must be 76.0-108.0 MHz
- Type checking (no strings)
- No shell injection via frequency parameter

### Functional Tests

#### 4. Error Handling
**Tests:**
- `test_broadcast_handles_missing_s3_key`
- `test_broadcast_handles_s3_download_failure`
- `test_broadcast_handles_subprocess_failure`

**Validates:**
- Proper exceptions raised for errors
- Error messages are descriptive
- No silent failures

#### 5. Configuration
**Tests:**
- `test_no_tts_endpoint_raises_error`
- `test_broadcast_uses_env_broadcast_cmd`
- `test_make_request_includes_api_key_header`

**Validates:**
- Missing configuration detected
- Environment variables used correctly
- API keys included in requests

#### 6. Message Formatting
**Tests:**
- `test_format_message_for_display`
- `test_format_message_handles_missing_user_data`

**Validates:**
- Messages formatted correctly
- Missing data handled gracefully

#### 7. Initialization
**Tests:**
- `test_initialization`
- `test_initialization_strips_whitespace`

**Validates:**
- Broadcaster initializes correctly
- Configuration values are sanitized

---

## Running Specific Tests

### Run single test:
```bash
python3 -m pytest test_message_broadcaster.py::TestPicnicMessageBroadcaster::test_command_injection_protection -v
```

### Run security tests only:
```bash
python3 -m pytest test_message_broadcaster.py::TestSecurityValidation -v
```

### Run with detailed output:
```bash
python3 -m pytest test_message_broadcaster.py -vv
```

### Run with coverage (if pytest-cov installed):
```bash
python3 -m pytest test_message_broadcaster.py --cov=message_broadcaster --cov-report=html
```

---

## Manual Testing Checklist

### Prerequisites
1. Raspberry Pi with `/dev/mem` access
2. `pifm` or `pifm_broadcast.sh` installed
3. `broadcast.env` configured with TTS_ENDPOINT and TTS_API_KEY
4. AWS credentials for S3 access

### Test Scenarios

#### Scenario 1: Normal Broadcast Flow
```bash
# 1. Start the application
python3 broadcast_app.py

# 2. Login with credentials

# 3. Select a group with radio_frequency configured

# 4. Select a message and click "Broadcast"

# Expected:
# - Silence carrier stops
# - Message broadcasts on correct frequency
# - Silence carrier restarts after broadcast
```

#### Scenario 2: Invalid Frequency
```bash
# Try to broadcast on invalid frequency (e.g., 50.0 MHz)

# Expected:
# - Error message: "Invalid FM frequency"
# - No broadcast attempted
# - Application remains stable
```

#### Scenario 3: Missing Configuration
```bash
# Remove TTS_ENDPOINT from broadcast.env

# Expected:
# - Error message: "TTS endpoint not configured"
# - Application explains what's missing
```

#### Scenario 4: Network Failure
```bash
# Disconnect network and attempt broadcast

# Expected:
# - Error message: "Cannot connect to TTS service"
# - No crash
# - Can retry after reconnecting
```

#### Scenario 5: File Permissions
```bash
# Make /home/rpibroadcaster/wav read-only

# Expected:
# - Error message about permissions
# - No silent failure
# - Application remains stable
```

---

## Integration Testing

### Test with Real TTS API

```bash
# Set environment variables
export TTS_ENDPOINT="https://your-api.execute-api.us-east-1.amazonaws.com/broadcast/polly_invoke"
export TTS_API_KEY="your-actual-api-key"
export BROADCAST_CMD="/usr/bin/sudo /usr/local/bin/pifm_broadcast.sh {file} -f {freq}"

# Run integration test script
python3 -c "
from message_broadcaster import PicnicMessageBroadcaster

# Initialize
broadcaster = PicnicMessageBroadcaster(
    access_token='test_token',
    tts_endpoint=os.getenv('TTS_ENDPOINT'),
    tts_api_key=os.getenv('TTS_API_KEY')
)

# Test broadcast (will download from S3 but won't actually transmit without pifm)
try:
    broadcaster.broadcast_message('Test message', 'Test User', None)  # None = don't broadcast
    print('✅ TTS API integration working')
except Exception as e:
    print(f'❌ Integration test failed: {e}')
"
```

---

## Continuous Integration

### GitHub Actions (Example)

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      - name: Install dependencies
        run: |
          pip install pytest boto3
      - name: Run tests
        run: |
          pytest test_message_broadcaster.py -v
```

---

## Debugging Failed Tests

### Common Issues

#### Issue: Import Errors
```
ImportError: No module named 'message_broadcaster'
```
**Solution:**
```bash
# Make sure you're in the project directory
cd /path/to/pi-fm-broadcast

# Install dependencies
pip install boto3
```

#### Issue: Permission Denied
```
PermissionError: [Errno 13] Permission denied: '/home/rpibroadcaster/wav'
```
**Solution:**
```bash
# Create directory with proper permissions
sudo mkdir -p /home/rpibroadcaster/wav
sudo chown $USER:$USER /home/rpibroadcaster/wav
```

#### Issue: Network Timeouts
```
URLError: <urlopen error timed out>
```
**Solution:**
- Check internet connection
- Verify firewall settings
- Check if API endpoint is accessible

---

## Test Maintenance

### When to Update Tests

1. **After adding new features:** Write tests for new functionality
2. **After bug fixes:** Add regression tests
3. **After security updates:** Add security validation tests
4. **Before releases:** Run full test suite

### Adding New Tests

Example template:
```python
def test_new_feature(self):
    """Test description"""
    # Arrange
    test_data = {...}

    # Act
    result = self.broadcaster.new_feature(test_data)

    # Assert
    self.assertEqual(result, expected_value)
```

---

## Performance Testing

### Load Testing (Optional)

```bash
# Test with multiple concurrent broadcasts
python3 -c "
import concurrent.futures
from message_broadcaster import PicnicMessageBroadcaster

def test_broadcast(n):
    broadcaster = PicnicMessageBroadcaster(...)
    return broadcaster.broadcast_message(f'Message {n}', 'User', None)

with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
    futures = [executor.submit(test_broadcast, i) for i in range(10)]
    results = [f.result() for f in concurrent.futures.as_completed(futures)]

print(f'Completed {len(results)} broadcasts')
"
```

---

## Support

### If Tests Fail

1. **Check logs:** Look for error messages in test output
2. **Run with verbose output:** `pytest -vv`
3. **Run single test:** Isolate the failing test
4. **Check dependencies:** Ensure all packages installed
5. **Review recent changes:** Git diff to see what changed

### Getting Help

- Check `SECURITY_AUDIT_REPORT.md` for known issues
- Review test output carefully
- Check GitHub Issues
- Run with `--tb=long` for full tracebacks

---

## Test Statistics

**Total Tests:** 15
**Security Tests:** 5
**Functional Tests:** 10
**Pass Rate:** 100%
**Coverage:** Core security and functionality

**Last Updated:** December 2, 2025
**Status:** ✅ All tests passing

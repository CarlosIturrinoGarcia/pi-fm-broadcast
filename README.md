# Pi FM Broadcast

**Production-ready Raspberry Pi FM broadcasting service** that polls AWS SQS for audio broadcast jobs and transmits them via FM radio using the pifm transmitter.

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)]()
[![Python](https://img.shields.io/badge/python-3.7+-green.svg)]()
[![License](https://img.shields.io/badge/license-MIT-orange.svg)]()

---

## 🎯 Features

- ✅ **Secure** - No shell injection, input validation, thread-safe operations
- ✅ **Reliable** - Automatic retries, DLQ support, graceful error handling
- ✅ **Production-ready** - Structured logging, health monitoring, systemd integration
- ✅ **Configurable** - Hot-reload via signals, environment-based config
- ✅ **Efficient** - Automatic file cleanup, optimized subprocess handling
- ✅ **Observable** - Correlation IDs, metrics, comprehensive logging

---

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Architecture](#architecture)
- [Security](#security)
- [Monitoring](#monitoring)
- [Development](#development)
- [Troubleshooting](#troubleshooting)

---

## 🚀 Quick Start

### Prerequisites

- Raspberry Pi (any model with GPIO)
- Python 3.7 or higher
- AWS account with SQS queue
- pifm transmitter binary

### Installation

```bash
# Clone repository
git clone https://github.com/your-org/pi-fm-broadcast.git
cd pi-fm-broadcast

# Install dependencies
pip3 install -r requirements.txt

# Create configuration file
cp broadcast.env.example broadcast.env
# Edit broadcast.env with your AWS credentials

# Run the service
./pifm-broadcast
```

---

## 📦 Installation

### 1. Install Dependencies

```bash
# Install Python dependencies
pip3 install -r requirements.txt

# Install pifm transmitter (if not already installed)
cd fm_transmitter
make
sudo make install
```

### 2. Create User (Production)

```bash
# Create dedicated user
sudo useradd -r -s /bin/bash -d /home/rpibroadcaster -m rpibroadcaster

# Set up directories
sudo mkdir -p /home/rpibroadcaster/wav
sudo chown -R rpibroadcaster:rpibroadcaster /home/rpibroadcaster
```

### 3. Configure Environment

Create `/home/rpibroadcaster/broadcast.env`:

```bash
# AWS Configuration
export QUEUE_URL="https://sqs.us-east-1.amazonaws.com/YOUR_ACCOUNT/your-queue.fifo"
export AWS_REGION="us-east-1"
export DLQ_URL="https://sqs.us-east-1.amazonaws.com/YOUR_ACCOUNT/your-dlq.fifo"

# Broadcast Command
# {file} will be replaced with the WAV file path
export BROADCAST_CMD="/usr/bin/sudo /usr/local/bin/pifm {file} -f 91.5"

# Timeouts (seconds)
export VISIBILITY=3600              # SQS message visibility
export HEARTBEAT_SEC=5              # Visibility extension interval
export MAX_PLAYBACK_SECS=1800       # Max broadcast duration (30 min)
export MESSAGE_TIMEOUT_SECS=2400    # Total message processing timeout (40 min)
export MAX_RECEIVE_COUNT=5          # Max retries before DLQ

# File Management
export DOWNLOAD_DIR="/home/rpibroadcaster/wav"
export MAX_STORED_FILES=100         # Keep only last 100 files
export CLEANUP_INTERVAL=300         # Cleanup every 5 minutes

# Silence Carrier (played when idle)
export SILENCE_FILE="/home/rpibroadcaster/wav/silence.wav"
export SILENCE_SECS=1800            # 30 minutes of silence

# Security (optional)
export ALLOWED_S3_BUCKETS="my-audio-bucket,my-backup-bucket"
export ALLOWED_URL_DOMAINS="cdn.example.com,backup.example.com"
```

### 4. Install as Systemd Service

```bash
# Copy service file
sudo cp systemd/pifm-broadcast.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable and start service
sudo systemctl enable pifm-broadcast
sudo systemctl start pifm-broadcast

# Check status
sudo systemctl status pifm-broadcast
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `QUEUE_URL` | ✅ Yes | - | AWS SQS queue URL |
| `AWS_REGION` | No | `us-east-1` | AWS region |
| `DLQ_URL` | No | - | Dead letter queue URL |
| `BROADCAST_CMD` | No | `aplay -q {file}` | Broadcast command template |
| `DOWNLOAD_DIR` | No | `/home/rpibroadcaster/wav` | Download directory |
| `VISIBILITY` | No | `300` | SQS visibility timeout (seconds) |
| `HEARTBEAT_SEC` | No | `5` | Visibility extension interval |
| `MAX_PLAYBACK_SECS` | No | `1800` | Maximum playback duration |
| `MESSAGE_TIMEOUT_SECS` | No | `2400` | Total message timeout |
| `MAX_RECEIVE_COUNT` | No | `5` | Max retries before DLQ |
| `MAX_STORED_FILES` | No | `100` | Maximum files to keep |
| `CLEANUP_INTERVAL` | No | `300` | File cleanup interval |
| `SILENCE_SECS` | No | `600` | Silence carrier duration |
| `ALLOWED_S3_BUCKETS` | No | - | Comma-separated bucket whitelist |
| `ALLOWED_URL_DOMAINS` | No | - | Comma-separated domain whitelist |

### Message Format

The service accepts SQS messages in the following formats:

#### Format 1: Direct S3 reference
```json
{
  "bucket": "my-audio-bucket",
  "key": "broadcasts/morning-show.wav"
}
```

#### Format 2: Direct URL
```json
{
  "url": "https://cdn.example.com/audio/file.wav"
}
```

#### Format 3: S3 Event Notification
```json
{
  "Records": [{
    "s3": {
      "bucket": {"name": "my-audio-bucket"},
      "object": {"key": "broadcasts/morning-show.wav"}
    }
  }]
}
```

#### Format 4: SNS-wrapped
```json
{
  "Message": "{\"bucket\":\"my-audio-bucket\",\"key\":\"file.wav\"}"
}
```

---

## 🎮 Usage

### Starting the Service

```bash
# Manual run (foreground)
./pifm-broadcast

# With systemd
sudo systemctl start pifm-broadcast
```

### Monitoring

```bash
# View live logs
sudo journalctl -u pifm-broadcast -f

# View logs from today
sudo journalctl -u pifm-broadcast --since today

# Check service status
sudo systemctl status pifm-broadcast
```

### Hot Reload Configuration

```bash
# Send SIGHUP to reload BROADCAST_CMD from env file
sudo systemctl kill -s SIGHUP pifm-broadcast

# Or find PID and send signal
kill -HUP $(pgrep -f pifm-broadcast)
```

### Interrupt Current Broadcast

```bash
# Send SIGUSR2 to interrupt and reload
sudo systemctl kill -s SIGUSR2 pifm-broadcast
```

### Graceful Shutdown

```bash
# Stops current broadcast and exits cleanly
sudo systemctl stop pifm-broadcast
```

---

## 🏗️ Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    AWS SQS Queue (FIFO)                 │
└────────────┬────────────────────────────────────────────┘
             │ Long polling (20s)
┌────────────▼────────────────────────────────────────────┐
│              Message Processor                          │
│  • Parse & validate message                             │
│  • Check receive count                                  │
│  • Send to DLQ if needed                                │
└────────────┬────────────────────────────────────────────┘
             │
┌────────────▼────────────────────────────────────────────┐
│                  Downloader                             │
│  • URL/S3 key validation                                │
│  • Download from S3 or URL                              │
│  • Audio file validation (WAV format)                   │
└────────────┬────────────────────────────────────────────┘
             │
┌────────────▼────────────────────────────────────────────┐
│              Broadcaster (Thread-safe)                  │
│  • Stop silence carrier                                 │
│  • Execute pifm (NO shell=True!)                        │
│  • Monitor with timeout                                 │
│  • Extend SQS visibility                                │
│  • Handle interrupts                                    │
└────────────┬────────────────────────────────────────────┘
             │
┌────────────▼────────────────────────────────────────────┐
│                 pifm Binary                             │
│  • Reads WAV file                                       │
│  • Transmits on FM frequency                            │
│  • Accesses /dev/mem (GPIO)                             │
└─────────────────────────────────────────────────────────┘
```

### Module Structure

```
pifm_broadcast/
├── __init__.py           # Package initialization
├── main.py               # Main service entry point
├── config.py             # Configuration management
├── exceptions.py         # Custom exceptions
├── logger.py             # Structured logging
├── validators.py         # Input validation
├── aws_clients.py        # SQS & S3 client wrappers
├── file_manager.py       # File cleanup
├── downloader.py         # File download & validation
├── broadcaster.py        # FM broadcast logic
├── silence.py            # Silence carrier management
├── message_processor.py  # Message processing
├── signal_handler.py     # Signal handling
└── health.py             # Health monitoring
```

---

## 🔒 Security

### Implemented Security Measures

✅ **No Shell Injection**
- Uses `subprocess.Popen()` with argument lists (NOT `shell=True`)
- Command templates parsed with `shlex.split()`

✅ **Input Validation**
- URL validation (scheme, domain whitelist, blocked IPs)
- S3 key validation (path traversal detection)
- Audio file validation (format, size, content)

✅ **Thread Safety**
- All shared state protected by locks
- No race conditions on process objects

✅ **Secrets Management**
- No hardcoded credentials
- Environment-based configuration
- `.gitignore` prevents committing secrets

✅ **Resource Limits**
- Automatic file cleanup
- Maximum playback duration
- Message timeout enforcement

### Security Best Practices

1. **Rotate AWS Credentials Regularly**
   ```bash
   # Use IAM roles instead of access keys
   aws iam create-role --role-name PiFmBroadcastRole
   ```

2. **Use S3 Bucket Whitelist**
   ```bash
   export ALLOWED_S3_BUCKETS="my-trusted-bucket"
   ```

3. **Enable CloudTrail**
   - Monitor all S3 access
   - Detect unauthorized downloads

4. **Run as Non-Root User**
   - Use dedicated `rpibroadcaster` user
   - Only grant sudo for pifm binary

---

## 📊 Monitoring

### Health Metrics

The service tracks:
- Messages processed (total, succeeded, failed)
- Downloads (succeeded, failed)
- Broadcasts (succeeded, failed)
- Messages sent to DLQ
- Uptime and idle time

### Logging

Supports two modes:

**Simple (Development)**
```
[2025-01-15 10:30:45] INFO [msg-abc123] Processing message: id=msg-abc123
[2025-01-15 10:30:46] INFO [msg-abc123] Downloading from S3: s3://bucket/file.wav
[2025-01-15 10:30:50] INFO [msg-abc123] Broadcasting /home/rpibroadcaster/wav/file.wav
```

**Structured (Production)**
```json
{"timestamp":"2025-01-15 10:30:45","level":"INFO","correlation_id":"msg-abc123","message":"Processing message"}
{"timestamp":"2025-01-15 10:30:46","level":"INFO","correlation_id":"msg-abc123","message":"Downloading from S3"}
```

Enable structured logging:
```python
# In main.py, change:
structured = True  # Instead of False
```

---

## 🛠️ Development

### Running Tests

```bash
# Install test dependencies
pip3 install pytest pytest-cov

# Run tests
pytest tests/

# With coverage
pytest --cov=pifm_broadcast tests/

# Specific test
pytest tests/test_validators.py::TestURLValidator::test_rejects_localhost
```

### Code Structure

- **config.py** - Configuration with validation
- **validators.py** - Security-focused input validation
- **aws_clients.py** - AWS SDK wrappers
- **broadcaster.py** - Core broadcast logic with thread safety
- **message_processor.py** - Message handling with DLQ

### Adding New Features

1. Create feature branch
2. Add tests first (TDD)
3. Implement feature
4. Update documentation
5. Submit PR

---

## 🐛 Troubleshooting

### Service Won't Start

**Check logs:**
```bash
sudo journalctl -u pifm-broadcast -n 50
```

**Common issues:**
- Missing QUEUE_URL environment variable
- Invalid AWS credentials
- pifm binary not found
- Permission denied on /dev/mem

### Downloads Failing

**Check:**
- S3 bucket permissions (IAM role or access keys)
- URL accessibility (firewall, DNS)
- Disk space in DOWNLOAD_DIR

### Broadcasts Not Working

**Verify:**
- pifm binary is executable: `which pifm`
- User has sudo access for pifm
- FM frequency is valid for your region
- GPIO pins are accessible

### Memory Issues

**Monitor memory:**
```bash
# Check service memory usage
systemctl status pifm-broadcast

# Adjust limit in service file
sudo vi /etc/systemd/system/pifm-broadcast.service
# Change: MemoryMax=256M
sudo systemctl daemon-reload
sudo systemctl restart pifm-broadcast
```

### File Cleanup Not Working

**Check:**
- MAX_STORED_FILES is set correctly
- CLEANUP_INTERVAL is reasonable
- Disk has available space

---

## 📜 License

MIT License - See LICENSE file for details

---

## 🙏 Acknowledgments

- **pifm** - FM transmitter for Raspberry Pi
- **boto3** - AWS SDK for Python

---

## 📞 Support

- **Issues:** https://github.com/your-org/pi-fm-broadcast/issues
- **Documentation:** https://github.com/your-org/pi-fm-broadcast/wiki

---

**Version 2.0.0** - Production-ready release with security hardening, thread safety, and comprehensive error handling.

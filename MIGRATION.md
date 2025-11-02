# Migration Guide: v1.x → v2.0.0

This guide helps you upgrade from version 1.x to the new production-ready 2.0.0 release.

---

## ⚠️ Important: Security Fixes

**Version 2.0.0 fixes critical security vulnerabilities. Upgrade immediately.**

- Command injection via `shell=True`
- Race conditions on shared state
- Exposed AWS credentials in git history
- Missing input validation

---

## 📋 Pre-Migration Checklist

- [ ] Backup your current `broadcast.env` file
- [ ] Stop the running service: `sudo systemctl stop pifm-broadcast` (if using systemd)
- [ ] Note your current configuration settings
- [ ] Ensure you have Python 3.7+
- [ ] Have AWS credentials ready (will need to rotate them)

---

## 🔧 Step-by-Step Migration

### Step 1: Backup Current Setup

```bash
# Backup your environment file
cp broadcast.env broadcast.env.backup

# Backup the old code
cp pi_broadcast.py pi_broadcast.py.v1.backup

# Note your current working directory
pwd > migration_notes.txt
```

### Step 2: Remove Secrets from Git History

**⚠️ CRITICAL: Do this first if you committed broadcast.env**

```bash
# Run the cleanup script
chmod +x scripts/remove_secrets_from_git.sh
./scripts/remove_secrets_from_git.sh

# Verify secrets are gone
git log --all --full-history -- broadcast.env
# Should show: "fatal: ambiguous argument"

# Force push to remote (if applicable)
git push --force --all
```

**Then rotate your AWS credentials immediately!**

### Step 3: Pull New Code

```bash
# If using git
git pull origin main

# Or download the new version
# wget https://github.com/your-org/pi-fm-broadcast/archive/v2.0.0.tar.gz
# tar -xzf v2.0.0.tar.gz
```

### Step 4: Install Dependencies

```bash
# Install Python dependencies
pip3 install -r requirements.txt

# Verify installation
python3 -c "import boto3; print(boto3.__version__)"
```

### Step 5: Update Configuration

```bash
# Copy example config
cp broadcast.env.example broadcast.env

# Edit with your settings
nano broadcast.env
```

**Key changes in broadcast.env:**

```diff
  # Old (v1.x)
  export BROADCAST_CMD="aplay -q {file}"

  # New (v2.0) - No changes needed, but now validated!
  export BROADCAST_CMD="aplay -q {file}"

+ # New variables in v2.0
+ export MAX_STORED_FILES=100
+ export CLEANUP_INTERVAL=300
+ export ALLOWED_S3_BUCKETS="my-bucket"  # Optional but recommended
+ export ALLOWED_URL_DOMAINS="cdn.example.com"  # Optional
```

**Copy your old settings:**

```bash
# Extract settings from backup
grep "^export" broadcast.env.backup > old_settings.txt

# Manually copy relevant values to new broadcast.env
nano broadcast.env
```

### Step 6: Validate Configuration

```bash
# Test configuration loading
python3 -c "from pifm_broadcast.config import Config; c = Config(); print('Config OK:', c)"
```

If you see errors, check:
- `QUEUE_URL` must start with `https://sqs.`
- `VISIBILITY` must be 1-43200
- `HEARTBEAT_SEC` must be less than `VISIBILITY`
- `BROADCAST_CMD` must contain `{file}`

### Step 7: Test the New Service

```bash
# Make executable
chmod +x pifm-broadcast

# Test run (foreground, with test AWS credentials)
./pifm-broadcast

# You should see:
# [2025-01-15 10:00:00] INFO Loading configuration...
# [2025-01-15 10:00:00] INFO Configuration loaded successfully
# [2025-01-15 10:00:00] INFO FMBroadcastService initialized
# ...

# Press Ctrl+C to stop
```

### Step 8: Update Systemd Service (If Using)

```bash
# Copy new service file
sudo cp systemd/pifm-broadcast.service /etc/systemd/system/

# Update paths in service file if needed
sudo nano /etc/systemd/system/pifm-broadcast.service

# Reload systemd
sudo systemctl daemon-reload

# Start service
sudo systemctl start pifm-broadcast

# Check status
sudo systemctl status pifm-broadcast

# View logs
sudo journalctl -u pifm-broadcast -f
```

### Step 9: Verify Operation

```bash
# Check logs for any errors
sudo journalctl -u pifm-broadcast -n 100

# Send a test message to your SQS queue
aws sqs send-message \
  --queue-url "YOUR_QUEUE_URL" \
  --message-body '{"bucket":"test-bucket","key":"test.wav"}' \
  --message-group-id "test" \
  --message-deduplication-id "test-$(date +%s)"

# Watch logs to see it process
sudo journalctl -u pifm-broadcast -f
```

### Step 10: Clean Up Old Files

```bash
# Remove old monolithic file (after verifying new version works!)
rm pi_broadcast.py.v1.backup

# Remove backup env file (contains old credentials)
shred -u broadcast.env.backup  # Securely delete

# Remove old wav files if migrating download directory
# (The service will auto-cleanup, but you can manually clean old files)
find /home/rpibroadcaster/wav -name "*.wav" -mtime +30 -delete
```

---

## 🔄 Configuration Mapping

| v1.x Variable | v2.0 Variable | Changes |
|---------------|---------------|---------|
| `QUEUE_URL` | `QUEUE_URL` | ✅ Same (now validated) |
| `AWS_REGION` | `AWS_REGION` | ✅ Same |
| `DOWNLOAD_DIR` | `DOWNLOAD_DIR` | ✅ Same |
| `BROADCAST_CMD` | `BROADCAST_CMD` | ✅ Same (now validated for `{file}`) |
| `ENV_FILE` | `ENV_FILE` | ✅ Same (used by Config.reload_broadcast_cmd) |
| `VISIBILITY` | `VISIBILITY` | ✅ Same (now validated 1-43200) |
| `HEARTBEAT_SEC` | `HEARTBEAT_SEC` | ✅ Same |
| `MAX_PLAYBACK_SECS` | `MAX_PLAYBACK_SECS` | ✅ Same |
| `MESSAGE_TIMEOUT_SECS` | `MESSAGE_TIMEOUT_SECS` | ✅ Same |
| `MAX_RECEIVE_COUNT` | `MAX_RECEIVE_COUNT` | ✅ Same |
| `DLQ_URL` | `DLQ_URL` | ✅ Same |
| `SILENCE_FILE` | `SILENCE_FILE` | ✅ Same |
| `SILENCE_SECS` | `SILENCE_SECS` | ✅ Same |
| - | `MAX_STORED_FILES` | 🆕 **NEW** (default: 100) |
| - | `CLEANUP_INTERVAL` | 🆕 **NEW** (default: 300) |
| - | `ALLOWED_S3_BUCKETS` | 🆕 **NEW** (optional security) |
| - | `ALLOWED_URL_DOMAINS` | 🆕 **NEW** (optional security) |
| - | `SQS_WAIT_TIME` | 🆕 **NEW** (default: 20) |

---

## 🔍 Code Changes for Integrations

If you have custom code that imports the old module:

### Old (v1.x)
```python
# Direct import
import pi_broadcast

# Using functions
pi_broadcast.log("message")
pi_broadcast.broadcast("/path/to/file.wav", receipt_handle)
```

### New (v2.0)
```python
# Import from package
from pifm_broadcast.main import FMBroadcastService
from pifm_broadcast.config import Config
from pifm_broadcast.logger import setup_logger

# Create service
config = Config()
service = FMBroadcastService(config)

# Run service
service.run()
```

---

## 🧪 Testing Your Migration

### Test Checklist

- [ ] Service starts without errors
- [ ] Configuration validates successfully
- [ ] Can receive messages from SQS
- [ ] Can download files from S3
- [ ] Can broadcast WAV files
- [ ] Silence carrier plays when idle
- [ ] Hot reload works (SIGHUP signal)
- [ ] Interrupt works (SIGUSR2 signal)
- [ ] Graceful shutdown works (SIGTERM/SIGINT)
- [ ] File cleanup removes old files
- [ ] Logs appear in journalctl

### Manual Test

```bash
# 1. Send test message
aws sqs send-message \
  --queue-url "$QUEUE_URL" \
  --message-body '{"bucket":"your-bucket","key":"test.wav"}' \
  --message-group-id "test" \
  --message-deduplication-id "test-$(date +%s)"

# 2. Watch processing
sudo journalctl -u pifm-broadcast -f

# 3. Test hot reload
echo 'export BROADCAST_CMD="aplay {file}"' >> broadcast.env
sudo systemctl kill -s SIGHUP pifm-broadcast

# 4. Check logs for reload
sudo journalctl -u pifm-broadcast -n 20 | grep -i reload

# 5. Test graceful shutdown
sudo systemctl stop pifm-broadcast
sudo journalctl -u pifm-broadcast -n 20 | grep -i shutdown
```

---

## 🚨 Troubleshooting

### Service won't start

**Error: `ConfigurationError: QUEUE_URL is not set`**
```bash
# Check environment file
cat broadcast.env | grep QUEUE_URL

# Ensure systemd service references correct env file
sudo nano /etc/systemd/system/pifm-broadcast.service
# Check: EnvironmentFile=/home/rpibroadcaster/broadcast.env

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart pifm-broadcast
```

**Error: `Invalid BROADCAST_CMD template`**
```bash
# Ensure {file} placeholder is present
grep BROADCAST_CMD broadcast.env
# Should show: export BROADCAST_CMD="... {file} ..."
```

### Imports failing

**Error: `ModuleNotFoundError: No module named 'pifm_broadcast'`**
```bash
# Ensure you're in the correct directory
cd /home/rpibroadcaster/pi-fm-broadcast

# Install in development mode
pip3 install -e .

# Or add to PYTHONPATH
export PYTHONPATH="/home/rpibroadcaster/pi-fm-broadcast:$PYTHONPATH"
```

### Permission errors

```bash
# Ensure correct ownership
sudo chown -R rpibroadcaster:rpibroadcaster /home/rpibroadcaster/pi-fm-broadcast
sudo chown -R rpibroadcaster:rpibroadcaster /home/rpibroadcaster/wav

# Make executable
chmod +x /home/rpibroadcaster/pi-fm-broadcast/pifm-broadcast
```

---

## 📊 Performance Improvements

You should notice:

1. **Lower CPU usage** - No more busy-wait loops (was 5 checks/second, now event-driven)
2. **Better responsiveness** - Signals handled immediately
3. **Disk space managed** - Auto-cleanup prevents exhaustion
4. **Faster startup** - Configuration validated once at startup

---

## 🔐 Security Improvements

After migration, you have:

1. ✅ **No shell injection** - `shell=True` removed
2. ✅ **No race conditions** - Thread locks on all shared state
3. ✅ **Input validation** - URLs, S3 keys, and WAV files validated
4. ✅ **Secrets rotation** - Old credentials removed from git
5. ✅ **Whitelisting** - Optional S3/URL domain restrictions

---

## 📞 Need Help?

- Check logs: `sudo journalctl -u pifm-broadcast -f`
- Review config: `python3 -c "from pifm_broadcast.config import Config; print(Config())"`
- Run tests: `pytest tests/`
- Open issue: https://github.com/your-org/pi-fm-broadcast/issues

---

## ✅ Post-Migration

Once migration is complete:

1. **Monitor for 24 hours** - Watch logs for any unexpected behavior
2. **Test all features** - Download, broadcast, reload, interrupt, shutdown
3. **Update documentation** - Note any custom configurations
4. **Train team** - Share new commands and features
5. **Celebrate** 🎉 - You're now running a production-ready system!

# Systemd Service Installation

## Installation Steps

1. **Copy the service file:**
   ```bash
   sudo cp systemd/pifm-broadcast.service /etc/systemd/system/
   ```

2. **Reload systemd:**
   ```bash
   sudo systemctl daemon-reload
   ```

3. **Enable the service (start on boot):**
   ```bash
   sudo systemctl enable pifm-broadcast
   ```

4. **Start the service:**
   ```bash
   sudo systemctl start pifm-broadcast
   ```

## Service Management

### Check service status:
```bash
sudo systemctl status pifm-broadcast
```

### View logs:
```bash
# Follow logs in real-time
sudo journalctl -u pifm-broadcast -f

# View last 100 lines
sudo journalctl -u pifm-broadcast -n 100

# View logs from today
sudo journalctl -u pifm-broadcast --since today
```

### Restart service:
```bash
sudo systemctl restart pifm-broadcast
```

### Stop service:
```bash
sudo systemctl stop pifm-broadcast
```

### Reload configuration (send SIGHUP):
```bash
sudo systemctl reload pifm-broadcast
```

Or send signal directly:
```bash
sudo systemctl kill -s SIGHUP pifm-broadcast
```

## Troubleshooting

### Service fails to start

1. Check the journal:
   ```bash
   sudo journalctl -u pifm-broadcast -n 50
   ```

2. Verify environment file exists:
   ```bash
   ls -l /home/rpibroadcaster/broadcast.env
   ```

3. Test manually:
   ```bash
   sudo -u rpibroadcaster /usr/bin/python3 /home/rpibroadcaster/pi-fm-broadcast/pifm-broadcast
   ```

### Permission issues

Ensure the user has access to required resources:
```bash
# Check user exists
id rpibroadcaster

# Check directory ownership
sudo chown -R rpibroadcaster:rpibroadcaster /home/rpibroadcaster/pi-fm-broadcast
sudo chown -R rpibroadcaster:rpibroadcaster /home/rpibroadcaster/wav

# Verify permissions
ls -la /home/rpibroadcaster/
```

### Memory issues

If the service uses too much memory, adjust the limit in the service file:
```ini
MemoryMax=256M  # Reduce from 512M
```

Then reload:
```bash
sudo systemctl daemon-reload
sudo systemctl restart pifm-broadcast
```

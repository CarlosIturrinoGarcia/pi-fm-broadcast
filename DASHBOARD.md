# Pi FM Broadcast Dashboard

Touch-optimized PyQt5 dashboard for managing the Pi FM Broadcast service on Raspberry Pi.

## Overview

The dashboard provides a graphical interface for:
- Starting/stopping the broadcast service
- Monitoring real-time service output
- Managing broadcast frequency
- Configuring WiFi connections
- Viewing service health status
- Downloading audio files from URLs

## Features

- **Touch-Optimized UI**: Large buttons and controls designed for touchscreen use
- **Embedded Keyboard**: On-screen keyboard for text input without external keyboard
- **Service Control**: Start/stop/restart the pifm-broadcast systemd service
- **Real-Time Monitoring**: Live output from the broadcast service
- **Frequency Management**: Set FM broadcast frequency (76.0-108.0 MHz)
- **WiFi Management**: Scan and connect to WiFi networks via nmcli
- **Health Monitoring**: Real-time service status and health metrics
- **System Tray**: Minimize to system tray for background operation
- **Persistent Settings**: Remembers last frequency and configuration

## Installation

### Prerequisites

```bash
# Install PyQt5
pip3 install PyQt5>=5.15.0

# Or install all dependencies
pip3 install -r requirements.txt
```

### Auto-Start on Boot (Optional)

Create a desktop entry to launch the dashboard on login:

```bash
# Create desktop file
cat > ~/.config/autostart/pifm-dashboard.desktop <<EOF
[Desktop Entry]
Type=Application
Name=Pi FM Broadcast Dashboard
Exec=/usr/bin/python3 /home/rpibroadcaster/pi-fm-broadcast/broadcast_app.py
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
EOF
```

## Configuration

The dashboard automatically detects configuration paths using the `config.py` module:

### Path Detection

Paths are auto-detected in the following order:

1. **Environment File** (`broadcast.env`):
   - `/home/rpibroadcaster/broadcast.env`
   - `./broadcast.env` (script directory)

2. **Service Executable** (`pifm-broadcast`):
   - `/home/rpibroadcaster/pi-fm-broadcast/pifm-broadcast`
   - `./pifm-broadcast` (script directory)

3. **Python Binary**:
   - `/home/rpibroadcaster/venv/bin/python`
   - Current Python interpreter

4. **Download Directory**:
   - `/home/rpibroadcaster/wav`
   - `./wav` (script directory)

### Environment Variables

The dashboard reads configuration from `broadcast.env`:

```bash
# Required
export QUEUE_URL="https://sqs.us-east-1.amazonaws.com/ACCOUNT/queue.fifo"

# Broadcast command with frequency
export BROADCAST_CMD="/usr/bin/sudo /usr/local/bin/pifm {file} -f 91.5"

# Optional
export DOWNLOAD_DIR="/home/rpibroadcaster/wav"
export VISIBILITY=3600
export HEARTBEAT_SEC=5
```

## Usage

### Starting the Dashboard

```bash
# From command line
python3 broadcast_app.py

# Or make executable
chmod +x broadcast_app.py
./broadcast_app.py
```

### Dashboard Pages

#### 1. Dashboard (Home)

**Service Controls:**
- **Start Service**: Starts the pifm-broadcast systemd service
- **Stop Service**: Stops the broadcast service
- **Reload Service**: Sends SIGHUP to reload configuration
- **Interrupt Broadcast**: Sends SIGUSR2 to skip current broadcast

**Service Status:**
- Shows whether service is running/stopped
- Shows whether auto-start is enabled/disabled
- Updates every 5 seconds

**Output Monitor:**
- Real-time output from the service
- Automatically scrolls to latest output
- Shows both stdout and stderr

**Current Frequency:**
- Displays the currently configured FM frequency
- Extracted from BROADCAST_CMD in env file

#### 2. Frequency Control

**Set Frequency:**
- Adjust frequency using spinner (76.0-108.0 MHz)
- 0.1 MHz step increments
- Validates frequency range

**Apply Options:**
- **Save Only**: Updates env file without restarting service
- **Save & Reload**: Updates env file and sends SIGHUP to reload
- **Set Immediately**: Stops service, updates frequency, restarts service

**Validation:**
- Ensures frequency is within FM broadcast range (76.0-108.0 MHz)
- Shows error message for invalid frequencies

#### 3. WiFi Management

**Scan Networks:**
- Click "Refresh" to scan for available networks
- Shows SSID and signal strength
- Timeout: 10 seconds

**Connect:**
1. Select network from list
2. Enter password (uses on-screen keyboard)
3. Click "Connect"
4. Connection timeout: 30 seconds

**Status:**
- Shows connection success/failure
- Displays error messages from nmcli

#### 4. Download Audio

**Download from URL:**
1. Enter URL in text field (uses on-screen keyboard)
2. Click "Download"
3. File saved to DOWNLOAD_DIR with sanitized filename

**Features:**
- Validates URL format
- Sanitizes filenames (removes special characters)
- Shows download progress
- Error handling for failed downloads
- Timeout: 120 seconds

## Architecture

### Main Components

```
broadcast_app.py (1022 lines)
├── MainWindow (QMainWindow)
│   ├── System tray integration
│   └── Window management
│
├── DashboardPage (QWidget)
│   ├── Service control buttons
│   ├── Service status display
│   ├── Output monitor (QPlainTextEdit)
│   └── Health monitoring (HealthMonitorWorker)
│
├── FrequencyPage (QWidget)
│   ├── Frequency spinner (QDoubleSpinBox)
│   ├── Apply mode radio buttons
│   └── Frequency validation
│
├── WifiPage (QWidget)
│   ├── Network scanner
│   ├── Password entry with keyboard
│   └── Connection handler
│
├── DownloadPage (QWidget)
│   ├── URL input with keyboard
│   ├── Download handler
│   └── File management
│
├── OnScreenKeyboard (QWidget)
│   ├── QWERTY layout
│   ├── Shift/Caps lock
│   └── Special characters
│
└── HealthMonitorWorker (QThread)
    └── Service status polling (5s interval)
```

### Configuration Module

```python
config.py
├── Path auto-detection
│   ├── ENV_PATH
│   ├── SERVICE_PATH
│   ├── PYTHON_BIN
│   └── DOWNLOAD_DIR
│
├── extract_current_frequency()
│   └── Parses BROADCAST_CMD for -f <freq>
│
├── validate_frequency()
│   └── Checks 76.0-108.0 MHz range
│
└── get_service_status()
    └── Queries systemctl for service state
```

### Theme Module

```python
theme.py
└── apply_theme()
    └── Light theme with mint green accents
```

## Key Features Explained

### Service Control

The dashboard communicates with the systemd service using subprocess calls:

```python
# Start service
subprocess.run(["sudo", "systemctl", "start", "pifm-broadcast"], timeout=10)

# Stop service
subprocess.run(["sudo", "systemctl", "stop", "pifm-broadcast"], timeout=10)

# Reload configuration (SIGHUP)
subprocess.run(["sudo", "systemctl", "kill", "-s", "SIGHUP", "pifm-broadcast"])

# Interrupt broadcast (SIGUSR2)
subprocess.run(["sudo", "systemctl", "kill", "-s", "SIGUSR2", "pifm-broadcast"])
```

### Output Monitoring

Uses QProcess to run the service and capture output:

```python
self.proc = QProcess()
self.proc.setProcessChannelMode(QProcess.MergedChannels)
self.proc.readyRead.connect(self.on_service_output)
self.proc.start(PYTHON_BIN, [SERVICE_PATH])
```

### Frequency Management

Three modes for setting frequency:

1. **Save Only**: Updates `BROADCAST_CMD` in env file
2. **Save & Reload**: Updates env file + sends SIGHUP signal
3. **Set Immediately**: Stops service, updates env, restarts service

```python
# Update BROADCAST_CMD in env file
new_cmd = re.sub(r'-f\s+\d+(?:\.\d+)?', f'-f {freq:.1f}', cmd)

# Write back to file
with open(ENV_PATH, 'w') as f:
    f.write(content)
```

### Health Monitoring

Background QThread polls service status every 5 seconds:

```python
class HealthMonitorWorker(QThread):
    metrics_updated = pyqtSignal(dict)

    def run(self):
        while self._running:
            status = get_service_status()
            self.metrics_updated.emit(status)
            self.msleep(5000)
```

### WiFi Management

Uses NetworkManager CLI (nmcli):

```python
# Scan networks
result = subprocess.run(
    ["nmcli", "-t", "-f", "SSID,SIGNAL", "device", "wifi", "list"],
    capture_output=True,
    text=True,
    timeout=10
)

# Connect to network
subprocess.run(
    ["nmcli", "device", "wifi", "connect", ssid, "password", password],
    capture_output=True,
    text=True,
    timeout=30
)
```

## Troubleshooting

### Dashboard Won't Start

**Issue**: Import errors or missing dependencies

```bash
# Install PyQt5
pip3 install PyQt5>=5.15.0

# Check Python version (requires 3.7+)
python3 --version
```

**Issue**: "No module named 'config'"

```bash
# Ensure config.py exists in same directory
ls -la broadcast_app.py config.py theme.py
```

### Service Control Not Working

**Issue**: "Permission denied" when starting/stopping service

```bash
# Add user to sudoers for systemctl
sudo visudo
# Add line:
rpibroadcaster ALL=(ALL) NOPASSWD: /bin/systemctl start pifm-broadcast
rpibroadcaster ALL=(ALL) NOPASSWD: /bin/systemctl stop pifm-broadcast
rpibroadcaster ALL=(ALL) NOPASSWD: /bin/systemctl restart pifm-broadcast
rpibroadcaster ALL=(ALL) NOPASSWD: /bin/systemctl kill pifm-broadcast
```

**Issue**: Service status shows "Unknown"

```bash
# Check if service exists
systemctl status pifm-broadcast

# If not found, install service
sudo cp systemd/pifm-broadcast.service /etc/systemd/system/
sudo systemctl daemon-reload
```

### Frequency Changes Not Applied

**Issue**: Frequency set but broadcast still on old frequency

**Solution**: Use "Set Immediately" mode to stop and restart service with new frequency

**Issue**: Cannot extract current frequency

**Solution**: Ensure BROADCAST_CMD in env file has `-f <number>` format:
```bash
export BROADCAST_CMD="/usr/bin/sudo /usr/local/bin/pifm {file} -f 91.5"
```

### WiFi Connection Fails

**Issue**: "nmcli: command not found"

```bash
# Install NetworkManager
sudo apt-get update
sudo apt-get install network-manager
```

**Issue**: Connection times out

```bash
# Increase timeout in broadcast_app.py
# Line ~600-700: timeout=30 -> timeout=60

# Or check WiFi adapter
nmcli device status
```

### Download Fails

**Issue**: URL downloads fail

```bash
# Check internet connectivity
ping -c 4 8.8.8.8

# Check download directory permissions
ls -ld /home/rpibroadcaster/wav
sudo chmod 755 /home/rpibroadcaster/wav
```

**Issue**: "Download directory does not exist"

```bash
# Create directory
mkdir -p /home/rpibroadcaster/wav
```

## Security Considerations

### Sudoers Configuration

The dashboard requires sudo access for systemctl commands. Use **NOPASSWD** only for specific commands:

```bash
# Safe sudoers configuration
rpibroadcaster ALL=(ALL) NOPASSWD: /bin/systemctl start pifm-broadcast
rpibroadcaster ALL=(ALL) NOPASSWD: /bin/systemctl stop pifm-broadcast
rpibroadcaster ALL=(ALL) NOPASSWD: /bin/systemctl restart pifm-broadcast
rpibroadcaster ALL=(ALL) NOPASSWD: /bin/systemctl status pifm-broadcast
rpibroadcaster ALL=(ALL) NOPASSWD: /bin/systemctl kill pifm-broadcast
```

### Input Validation

All user inputs are validated:
- **Frequency**: Range checked (76.0-108.0 MHz)
- **URLs**: Format validated before download
- **WiFi passwords**: Passed safely to nmcli without shell injection
- **Filenames**: Sanitized to prevent directory traversal

### Process Safety

- Uses subprocess with argument lists (no shell=True)
- All subprocess calls have timeouts
- QProcess used for long-running service monitoring
- Proper cleanup on exit

## Performance

### Resource Usage

Typical resource usage on Raspberry Pi 4:
- **Memory**: ~50-80 MB (PyQt5 + Python)
- **CPU**: <5% idle, <10% during UI operations
- **Startup Time**: ~2-3 seconds

### Optimization Tips

1. **Reduce Health Monitor Interval**: Change from 5s to 10s in HealthMonitorWorker
2. **Disable Output Monitoring**: Comment out QProcess if not needed
3. **Minimize to Tray**: Reduces GUI rendering overhead

## Development

### Running in Development Mode

```bash
# Run with debug output
python3 broadcast_app.py

# All operations logged to console with timestamps
```

### Modifying the UI

Edit `theme.py` to customize colors:

```python
# Change accent color from mint green
QPushButton { background: #8df2c9; }  # Change this
```

### Adding New Pages

1. Create QWidget subclass
2. Add to MainWindow.init_ui()
3. Add navigation button

Example:
```python
class SettingsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        # Add widgets

# In MainWindow.init_ui()
self.settings_page = SettingsPage()
self.stack.addWidget(self.settings_page)
```

## Integration with Backend Service

The dashboard integrates with the pifm-broadcast v2.0 service:

### Service Detection

Auto-detects service using `config.SERVICE_PATH`:
1. Checks `/home/rpibroadcaster/pi-fm-broadcast/pifm-broadcast`
2. Falls back to `./pifm-broadcast` in script directory

### Configuration Sharing

Both dashboard and service read from same `broadcast.env` file:
- Dashboard updates BROADCAST_CMD for frequency changes
- Service reads BROADCAST_CMD on startup and SIGHUP

### Signal Communication

Dashboard sends signals to service:
- **SIGHUP**: Reload configuration (frequency change)
- **SIGUSR2**: Interrupt current broadcast

## Keyboard Shortcuts

When using external keyboard:

- **Ctrl+Q**: Quit application
- **Esc**: Close on-screen keyboard

## FAQ

**Q: Can I run the dashboard remotely over VNC?**

A: Yes, the dashboard works over VNC/X11 forwarding. Touch events translate to mouse clicks.

**Q: Does the dashboard need to run 24/7?**

A: No, the backend service runs independently. The dashboard is only for management.

**Q: Can I customize the frequency range?**

A: Yes, edit `config.validate_frequency()` to change the 76.0-108.0 MHz range.

**Q: How do I hide the on-screen keyboard?**

A: Click "Close" on the keyboard or press Esc.

**Q: Can I use this without a touchscreen?**

A: Yes, all controls work with mouse and keyboard.

## License

MIT License - See LICENSE file for details

## Support

For issues or questions:
- Backend service: See main README.md
- Dashboard: Create issue with "dashboard" label

## Version History

- **1.0.0** (2025-01-15): Initial dashboard release
  - Touch-optimized UI
  - Service control integration
  - WiFi management
  - Frequency control with v2.0 service support
  - Health monitoring
  - On-screen keyboard

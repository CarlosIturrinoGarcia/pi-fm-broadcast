# Auto-Start Setup for Raspberry Pi

This guide explains how to automatically start the Picnic FM Broadcast application when the Raspberry Pi is powered on.

## Prerequisites
- Raspberry Pi running Linux
- Application located at: /home/rpibroadcaster/broadcast_proj/
- Virtual environment at: /home/rpibroadcaster/venv/
- User: rpibroadcaster

## Step 1: Configure Auto-Login

Create the auto-login configuration:
```bash
sudo mkdir -p /etc/systemd/system/getty@tty1.service.d
sudo nano /etc/systemd/system/getty@tty1.service.d/autologin.conf
```

Add this content:
```ini
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin rpibroadcaster --noclear %I $TERM
```

## Step 2: Create .xinitrc File

This file tells X server what to run when it starts:
```bash
nano ~/.xinitrc
```

Add this content:
```bash
#!/bin/bash
cd /home/rpibroadcaster/broadcast_proj
source /home/rpibroadcaster/venv/bin/activate

if [ -f broadcast.env ]; then
    set -a
    source broadcast.env
    set +a
fi

exec python broadcast_app.py
```

Make it executable:
```bash
chmod +x ~/.xinitrc
```

## Step 3: Create Systemd Service

Create the service file:
```bash
sudo nano /etc/systemd/system/picnic-broadcast.service
```

Add this content:
```ini
[Unit]
Description=Picnic FM Broadcast App
After=multi-user.target

[Service]
Type=simple
User=rpibroadcaster
WorkingDirectory=/home/rpibroadcaster/broadcast_proj
Environment="DISPLAY=:0"
Environment="XDG_RUNTIME_DIR=/run/user/1000"

# Start X server on display :0
ExecStartPre=/bin/sh -c 'xinit /home/rpibroadcaster/.xinitrc -- :0 vt1 &'
ExecStartPre=/bin/sleep 3

# The app is started by .xinitrc, so we just wait
ExecStart=/bin/sleep infinity

Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## Step 4: Enable and Test

Enable the service to start on boot:
```bash
sudo systemctl daemon-reload
sudo systemctl enable picnic-broadcast.service
```

Test by rebooting:
```bash
sudo reboot
```

## Troubleshooting

Check service status:
```bash
sudo systemctl status picnic-broadcast.service
```

View logs:
```bash
journalctl -u picnic-broadcast.service -f
```

Check if app is running:
```bash
ps aux | grep broadcast_app
```

Manually stop the service:
```bash
sudo systemctl stop picnic-broadcast.service
```

Manually start the service:
```bash
sudo systemctl start picnic-broadcast.service
```

Disable auto-start:
```bash
sudo systemctl disable picnic-broadcast.service
```

## How It Works

1. Raspberry Pi boots up
2. Auto-login logs in as rpibroadcaster on tty1
3. Systemd service starts X server
4. X server reads ~/.xinitrc
5. .xinitrc activates virtual environment, loads environment variables, and starts the PyQt app
6. App runs fullscreen on the display

## Notes

- The app will auto-restart if it crashes (due to Restart=always)
- X server runs on display :0
- The service uses the virtual environment to ensure all Python dependencies are available
- Environment variables from broadcast.env are automatically loaded

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pi FM Broadcast Dashboard (v2.0)
=================================

Production-ready PyQt5 dashboard for controlling FM broadcast service.

Features:
- Frequency control with hot-reload (SIGHUP/SIGUSR2)
- WiFi management with on-screen keyboard
- Real-time service monitoring
- Health metrics display
- Touch-optimized interface
- System tray integration

Integrates with pifm_broadcast v2.0 service.
"""

import os
import sys
import re
import signal
import subprocess
import json
import hashlib
import logging
from pathlib import Path
from typing import Optional, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

from theme import apply_theme
from config import (
    ENV_PATH,
    SERVICE_PATH,
    PYTHON_BIN,
    extract_current_frequency,
    validate_frequency,
    get_service_status,
)

from PyQt5.QtCore import (
    Qt,
    QSettings,
    QThread,
    pyqtSignal,
    QEvent,
    QCoreApplication,
    QProcess,
    QTimer,
)
from PyQt5.QtGui import QIcon, QKeyEvent
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QStackedWidget,
    QLineEdit,
    QTextEdit,
    QDoubleSpinBox,
    QMessageBox,
    QSystemTrayIcon,
    QMenu,
    QStyle,
    QDialog,
    QFormLayout,
    QDialogButtonBox,
    QSizePolicy,
    QCheckBox,
    QGroupBox,
    QGridLayout,
)

APP_ORG = "PiFmBroadcast"
APP_NAME = "FM Broadcast Dashboard"
APP_VERSION = "2.0.0"


# =============================
# Environment & Configuration Helpers
# =============================

def load_env_file(path: str) -> Dict[str, str]:
    """
    Read KEY=VALUE lines from an env file.

    Supports 'export', quotes, spaces, CRLF.

    Args:
        path: Path to .env file

    Returns:
        Dictionary of environment variables
    """
    env = {}
    if not os.path.exists(path):
        return env

    line_re = re.compile(r"""
        ^\s*
        (?:export\s+)?              # optional 'export '
        (?P<key>[A-Za-z_][A-Za-z0-9_]*)
        \s*=\s*
        (?P<val>.*?)
        \s*$
    """, re.X)

    try:
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
                # Remove quotes
                if (len(val) >= 2) and (val[0] == val[-1]) and val[0] in ("'", '"'):
                    val = val[1:-1]
                env[key] = val
    except Exception as e:
        print(f"Warning: Error loading env file {path}: {e}")

    return env


def render_broadcast_cmd(tmpl: str, freq: float) -> str:
    """
    Render broadcast command template with frequency.

    Supports {freq}, <num>, or -f <number> patterns.

    Args:
        tmpl: Command template
        freq: Frequency in MHz

    Returns:
        Rendered command string
    """
    # Replace {freq} placeholder
    if "{freq}" in tmpl:
        return tmpl.replace("{freq}", f"{freq:.1f}")

    # Replace <num> placeholder
    if "<num>" in tmpl:
        return tmpl.replace("<num>", f"{freq:.1f}")

    # Replace existing -f <number>
    if re.search(r"(?<!\S)-f\s+\d+(?:\.\d+)?(?!\S)", tmpl):
        return re.sub(
            r"(?<!\S)(-f\s+)\d+(?:\.\d+)?(?!\S)",
            lambda m: f"{m.group(1)}{freq:.1f}",
            tmpl
        )

    # Append -f <freq> if not present
    return f"{tmpl} -f {freq:.1f}"


def write_env_key(path: str, key: str, value: str) -> None:
    """
    Upsert KEY in the .env file while preserving other lines & comments.

    Args:
        path: Path to .env file
        key: Variable name
        value: Variable value

    Raises:
        IOError: If file cannot be written
    """
    lines = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()

    key_re = re.compile(rf"^\s*(?:export\s+)?{re.escape(key)}\s*=\s*.*$")
    wrote = False
    out = []

    for ln in lines:
        if key_re.match(ln):
            out.append(f'{key}="{value}"')
            wrote = True
        else:
            out.append(ln)

    if not wrote:
        if out and out[-1].strip():
            out.append("")  # blank line before appending
        out.append(f'{key}="{value}"')

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")


# =============================
# Embedded On-Screen Keyboard
# =============================

class OnScreenKeyboard(QWidget):
    """Embedded compact QWERTY keyboard for touchscreen input."""

    def __init__(self, parent=None, target: QWidget = None):
        super().__init__(parent)
        self.setObjectName("OnScreenKeyboard")
        self._shift = False
        self._target = target

        rows = [
            list("1234567890"),
            list("qwertyuiop"),
            list("asdfghjkl"),
            list("zxcvbnm"),
        ]

        g = QVBoxLayout()
        g.setContentsMargins(8, 6, 8, 8)
        g.setSpacing(6)

        def row_of(chars, prefix_widgets=None, suffix_widgets=None):
            h = QHBoxLayout()
            h.setSpacing(6)
            if prefix_widgets:
                for w in prefix_widgets:
                    h.addWidget(w)
            for ch in chars:
                h.addWidget(self._mk_btn(ch))
            if suffix_widgets:
                for w in suffix_widgets:
                    h.addWidget(w)
            return h

        g.addLayout(row_of(rows[0]))
        g.addLayout(row_of(rows[1]))
        g.addLayout(row_of(rows[2]))

        self.shift_btn = self._mk_btn("Shift", wide=True)
        self.shift_btn.setCheckable(True)
        self.shift_btn.clicked.connect(self._toggle_shift)

        backspace = self._mk_btn("⌫", wide=True)
        backspace.clicked.connect(lambda: self._special_key("Backspace"))

        g.addLayout(row_of(rows[3], prefix_widgets=[self.shift_btn], suffix_widgets=[backspace]))

        hide = self._mk_btn("Hide", wide=True)
        hide.clicked.connect(self.hide)

        space = self._mk_btn("Space", wide=True)
        space.clicked.connect(lambda: self._type_text(" "))

        enter = self._mk_btn("Enter", wide=True)
        enter.clicked.connect(lambda: self._special_key("Enter"))

        bottom = QHBoxLayout()
        bottom.setSpacing(6)
        bottom.addWidget(hide)
        bottom.addWidget(space, 2)
        bottom.addWidget(enter)
        g.addLayout(bottom)

        self.setLayout(g)

        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setFixedHeight(220)
        self.setStyleSheet("""
            #OnScreenKeyboard QPushButton { min-width: 36px; min-height: 40px; font-size: 16px; }
            #OnScreenKeyboard QPushButton[wide="true"] { min-width: 64px; }
        """)

    def set_target(self, w: QWidget):
        """Set target widget for keyboard input."""
        self._target = w

    def _mk_btn(self, text, wide=False):
        b = QPushButton(text)
        b.setProperty("wide", "true" if wide else "false")
        b.setFocusPolicy(Qt.NoFocus)  # don't steal focus
        b.clicked.connect(lambda checked=False, t=text: self._key_clicked(t))
        return b

    def _toggle_shift(self):
        self._shift = self.shift_btn.isChecked()

    def _key_clicked(self, label):
        if label in ("Shift", "⌫", "Space", "Enter", "Hide"):
            return
        ch = label.upper() if (self._shift and label.isalpha()) else label
        self._type_text(ch)

    def _target_widget(self):
        if self._target and self._target.isVisible():
            return self._target
        return QApplication.focusWidget()

    def _special_key(self, name):
        fw = self._target_widget()
        if name == "Backspace":
            if isinstance(fw, QLineEdit):
                fw.backspace()
                return
            if isinstance(fw, QTextEdit):
                c = fw.textCursor()
                c.deletePreviousChar()
                fw.setTextCursor(c)
                return
            self._post_key(Qt.Key_Backspace)
        elif name == "Enter":
            if isinstance(fw, QLineEdit):
                self._post_key(Qt.Key_Return, "\n")
            else:
                self._type_text("\n")

    def _type_text(self, text):
        fw = self._target_widget()
        if isinstance(fw, QLineEdit):
            i = fw.cursorPosition()
            fw.setText(fw.text()[:i] + text + fw.text()[i:])
            fw.setCursorPosition(i + len(text))
            return
        if isinstance(fw, QTextEdit):
            c = fw.textCursor()
            c.insertText(text)
            fw.setTextCursor(c)
            return
        for ch in text:
            self._post_key(Qt.Key_Space if ch == " " else 0, ch)

    def _post_key(self, key, text=""):
        fw = self._target_widget()
        if not fw:
            return
        evp = QKeyEvent(QEvent.KeyPress, key, Qt.NoModifier, text)
        evr = QKeyEvent(QEvent.KeyRelease, key, Qt.NoModifier, text)
        QCoreApplication.postEvent(fw, evp)
        QCoreApplication.postEvent(fw, evr)


# =============================
# Wi-Fi Worker & Dialog
# =============================

class WifiWorker(QThread):
    """Background worker for WiFi operations using nmcli."""

    finished = pyqtSignal(str, object)  # (status, payload)

    def __init__(self, action: str, ssid: str = "", password: str = "", parent=None):
        super().__init__(parent)
        self.action = action
        self.ssid = ssid
        self.password = password

    def run(self):
        try:
            if self.action == "scan":
                cmd = ["nmcli", "-f", "SSID,SIGNAL,SECURITY", "device", "wifi", "list"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if res.returncode != 0:
                    self.finished.emit("error", res.stderr.strip() or "Scan failed")
                    return
                nets = self._parse_nmcli_scan(res.stdout)
                self.finished.emit("scanned", nets)
                return

            if self.action == "connect":
                cmd = ["nmcli", "device", "wifi", "connect", self.ssid, "password", self.password]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if res.returncode == 0:
                    self.finished.emit("connected", res.stdout.strip() or "Connected")
                else:
                    self.finished.emit("error", res.stderr.strip() or "Connection failed")
                return

            self.finished.emit("error", f"Unknown action: {self.action}")

        except FileNotFoundError:
            self.finished.emit("error", "nmcli not found. Install network-manager.")
        except subprocess.TimeoutExpired:
            self.finished.emit("error", "Operation timed out")
        except Exception as e:
            self.finished.emit("error", str(e))

    def _parse_nmcli_scan(self, text: str):
        lines = [l for l in text.splitlines() if l.strip()]
        if len(lines) <= 1:
            return []
        rows = lines[1:]
        out = []
        for r in rows:
            cols = re.split(r"\s{2,}", r.strip())
            ssid = cols[0] if len(cols) > 0 else ""
            signal = cols[1] if len(cols) > 1 else ""
            security = cols[2] if len(cols) > 2 else ""
            out.append({"ssid": ssid, "signal": signal, "security": security})
        return out


class WifiDialog(QDialog):
    """WiFi network scanner and connection dialog."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Wi-Fi Networks")
        self.resize(500, 420)

        self.form = QFormLayout(self)
        self.info = QLabel("Scanning nearby Wi-Fi networks…")
        self.form.addRow(self.info)

        self.list_widget = QListWidget()
        self.form.addRow(self.list_widget)

        self.btns = QDialogButtonBox(QDialogButtonBox.Close)
        self.refresh_btn = self.btns.addButton("Refresh", QDialogButtonBox.ActionRole)
        self.connect_btn = self.btns.addButton("Connect", QDialogButtonBox.AcceptRole)
        self.connect_btn.setEnabled(False)
        self.form.addWidget(self.btns)

        self.btns.rejected.connect(self.reject)
        self.refresh_btn.clicked.connect(self.scan)
        self.connect_btn.clicked.connect(self.handle_connect)
        self.list_widget.itemSelectionChanged.connect(self._on_sel)

        self.scan()

    def scan(self):
        self.info.setText("Scanning nearby Wi-Fi networks…")
        self.list_widget.clear()
        self.connect_btn.setEnabled(False)
        self.worker = WifiWorker("scan")
        self.worker.finished.connect(self._on_finished)
        self.worker.start()

    def _on_sel(self):
        self.connect_btn.setEnabled(bool(self.list_widget.selectedItems()))

    def handle_connect(self):
        item = self.list_widget.currentItem()
        if not item:
            return
        net = item.data(Qt.UserRole)
        ssid = net.get("ssid") or ""

        # Password dialog with embedded keyboard
        pwd_dlg = QDialog(self)
        pwd_dlg.setWindowTitle(f"Password for {ssid}")

        v = QVBoxLayout(pwd_dlg)
        form = QFormLayout()
        v.addLayout(form)

        info = QLabel(f"Network: {ssid}")
        pwd_input = QLineEdit()
        pwd_input.setEchoMode(QLineEdit.Password)
        pwd_input.setPlaceholderText("Enter Wi-Fi password")

        form.addRow(info)
        form.addRow("Password:", pwd_input)

        kb = OnScreenKeyboard(pwd_dlg, target=pwd_input)
        kb.setVisible(True)
        v.addWidget(kb)

        dbb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        v.addWidget(dbb)
        dbb.accepted.connect(pwd_dlg.accept)
        dbb.rejected.connect(pwd_dlg.reject)

        pwd_input.setFocus(Qt.MouseFocusReason)

        if pwd_dlg.exec_() != QDialog.Accepted:
            return

        password = pwd_input.text().strip()
        if not password:
            QMessageBox.warning(self, "Wi-Fi", "Password cannot be empty.")
            return

        self.info.setText(f"Connecting to {ssid} …")
        self.connect_btn.setEnabled(False)
        self.worker = WifiWorker("connect", ssid=ssid, password=password)
        self.worker.finished.connect(self._on_finished)
        self.worker.start()

    def _on_finished(self, status, payload):
        if status == "scanned":
            nets = payload
            if not nets:
                self.info.setText("No networks found.")
                return
            self.info.setText(f"Found {len(nets)} network(s). Select one to connect.")
            for net in nets:
                ssid = net.get("ssid") or "<hidden>"
                text = f"{ssid}  —  Signal: {net.get('signal','')}  —  Security: {net.get('security','')}"
                it = QListWidgetItem(text)
                it.setData(Qt.UserRole, net)
                self.list_widget.addItem(it)
        elif status == "connected":
            self.info.setText(str(payload))
            QMessageBox.information(self, "Connected", str(payload))
            self.accept()
        else:
            self.info.setText("Error: " + str(payload))
            QMessageBox.critical(self, "Wi-Fi Error", str(payload))


# =============================
# Login Dialog
# =============================

class KeyboardLineEdit(QLineEdit):
    """QLineEdit that shows on-screen keyboard on focus."""

    def __init__(self, keyboard: 'OnScreenKeyboard', *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._keyboard = keyboard

    def focusInEvent(self, event):
        """Override to show keyboard when focused."""
        super().focusInEvent(event)
        if self._keyboard:
            self._keyboard.set_target(self)
            self._keyboard.setVisible(True)


class LoginDialog(QDialog):
    """Login dialog with username/password authentication."""

    def __init__(self, api_client, parent=None):
        super().__init__(parent)
        self.api_client = api_client
        self.setWindowTitle("FM Broadcast Login")
        self.setModal(True)
        self.resize(500, 420)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        # Main layout
        v = QVBoxLayout(self)
        v.setSpacing(16)

        # Title
        title = QLabel("FM Broadcast Dashboard")
        title.setStyleSheet("font-size: 24px; font-weight: 600; padding: 12px;")
        title.setAlignment(Qt.AlignCenter)
        v.addWidget(title)

        subtitle = QLabel("Please log in to continue")
        subtitle.setStyleSheet("font-size: 14px; color: #666; padding-bottom: 12px;")
        subtitle.setAlignment(Qt.AlignCenter)
        v.addWidget(subtitle)

        # On-screen keyboard (create before inputs)
        self.keyboard = OnScreenKeyboard(self)
        self.keyboard.setVisible(False)

        # Form
        form = QFormLayout()
        form.setSpacing(12)

        self.username_input = KeyboardLineEdit(self.keyboard)
        self.username_input.setPlaceholderText("Enter email address")
        self.username_input.setMinimumHeight(44)
        self.username_input.setStyleSheet("font-size: 16px;")

        self.password_input = KeyboardLineEdit(self.keyboard)
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setMinimumHeight(44)
        self.password_input.setStyleSheet("font-size: 16px;")
        self.password_input.returnPressed.connect(self.validate_login)

        form.addRow("Email:", self.username_input)
        form.addRow("Password:", self.password_input)
        v.addLayout(form)

        # Error message label
        self.error_label = QLabel("")
        self.error_label.setStyleSheet("color: #e74c3c; font-weight: 600; padding: 6px;")
        self.error_label.setAlignment(Qt.AlignCenter)
        self.error_label.setVisible(False)
        v.addWidget(self.error_label)

        # Add keyboard widget
        v.addWidget(self.keyboard)

        # Buttons
        btns = QDialogButtonBox()
        self.login_btn = btns.addButton("Login", QDialogButtonBox.AcceptRole)
        self.cancel_btn = btns.addButton("Cancel", QDialogButtonBox.RejectRole)

        self.login_btn.setMinimumHeight(44)
        self.cancel_btn.setMinimumHeight(44)
        self.cancel_btn.setObjectName("secondary")

        btns.accepted.connect(self.validate_login)
        btns.rejected.connect(self.reject)
        v.addWidget(btns)

        # Set initial focus
        self.username_input.setFocus(Qt.OtherFocusReason)

        # Track failed login attempts
        self.failed_attempts = 0
        self.max_attempts = 5

    def validate_login(self):
        """Validate login credentials using Picnic API."""
        from api_client import AuthenticationError, NetworkError, PicnicAPIError

        email = self.username_input.text().strip()
        password = self.password_input.text().strip()

        # Check if inputs are empty
        if not email or not password:
            self.show_error("Please enter both email and password")
            return

        # Try local credentials first (fallback for offline mode)
        if self.check_credentials(email, password):
            self.accept()
            return

        # Disable login button while processing
        self.login_btn.setEnabled(False)
        self.login_btn.setText("Logging in...")
        QApplication.processEvents()

        try:
            # Attempt API login
            self.api_client.login(email, password)
            # Success - close dialog
            self.accept()

        except AuthenticationError as e:
            self.failed_attempts += 1
            remaining = self.max_attempts - self.failed_attempts

            if self.failed_attempts >= self.max_attempts:
                self.show_error("Too many failed attempts. Access denied.")
                QTimer.singleShot(2000, self.reject)
            else:
                self.show_error(f"Invalid credentials. {remaining} attempts remaining.")
                self.password_input.clear()
                self.password_input.setFocus()

        except NetworkError as e:
            self.show_error(f"Network error: {str(e)}")

        except PicnicAPIError as e:
            self.show_error(f"Login failed: {str(e)}")

        finally:
            # Re-enable login button
            self.login_btn.setEnabled(True)
            self.login_btn.setText("Login")

    def check_credentials(self, username: str, password: str) -> bool:
        """
        Check credentials against environment variables.

        Supports two modes:
        1. DASHBOARD_USERNAME + DASHBOARD_PASSWORD_HASH (SHA256)
        2. DASHBOARD_PIN (simple numeric PIN for touchscreens)

        Args:
            username: Entered username
            password: Entered password

        Returns:
            True if credentials are valid
        """
        # Load environment from broadcast.env
        env_vars = load_env_file(ENV_PATH)

        # Mode 1: Simple PIN authentication (for touchscreens)
        pin = env_vars.get("DASHBOARD_PIN", os.getenv("DASHBOARD_PIN"))
        if pin and pin == password:
            return True

        # Mode 2: Username + Password Hash authentication
        expected_username = env_vars.get("DASHBOARD_USERNAME", os.getenv("DASHBOARD_USERNAME", "admin"))
        password_hash = env_vars.get("DASHBOARD_PASSWORD_HASH", os.getenv("DASHBOARD_PASSWORD_HASH"))

        # If no password hash is set, use default for first-time setup
        if not password_hash and not pin:
            # Default credentials: admin/admin (for initial setup only)
            default_hash = hashlib.sha256(b"admin").hexdigest()
            if username == expected_username and hashlib.sha256(password.encode()).hexdigest() == default_hash:
                return True

        # Validate username
        if username != expected_username:
            return False

        # Validate password hash
        if password_hash:
            computed_hash = hashlib.sha256(password.encode()).hexdigest()
            return computed_hash == password_hash

        return False

    def show_error(self, message: str):
        """Display error message."""
        self.error_label.setText(message)
        self.error_label.setVisible(True)


# =============================
# Health Metrics Worker
# =============================

class HealthMonitorWorker(QThread):
    """Background worker to fetch service health metrics."""

    metrics_updated = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._running = True

    def run(self):
        """Periodically check service status."""
        while self._running:
            try:
                status = get_service_status()
                self.metrics_updated.emit(status)
            except Exception as e:
                print(f"Health monitor error: {e}")

            # Sleep for 5 seconds
            for _ in range(50):
                if not self._running:
                    break
                self.msleep(100)

    def stop(self):
        """Stop the worker thread."""
        self._running = False


# =============================
# Dashboard Page
# =============================

class DashboardPage(QWidget):
    """Main dashboard page with frequency control and service monitoring."""

    freq_set = pyqtSignal(float, bool)  # (frequency, immediate)

    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)

        # Title
        title = QLabel("FM Broadcast Dashboard")
        title.setStyleSheet("font-size: 22px; font-weight: 600;")

        # Frequency Control
        control_group = QGroupBox("Frequency Control")
        control_layout = QVBoxLayout()

        freq_controls = QHBoxLayout()
        lbl = QLabel("Frequency (MHz):")
        self.freq_spin = QDoubleSpinBox()
        self.freq_spin.setRange(76.0, 108.0)
        self.freq_spin.setDecimals(1)
        self.freq_spin.setSingleStep(0.1)
        self.freq_spin.setValue(90.8)

        self.chk_immediate = QCheckBox("Switch immediately")
        self.chk_immediate.setToolTip("Abort current broadcast and switch now (SIGUSR2)")

        self.btn_set_freq = QPushButton("Set Frequency")
        self.btn_set_freq.setMinimumHeight(44)

        freq_controls.addWidget(lbl)
        freq_controls.addWidget(self.freq_spin)
        freq_controls.addWidget(self.chk_immediate)
        freq_controls.addWidget(self.btn_set_freq)
        freq_controls.addStretch(1)

        control_layout.addLayout(freq_controls)
        control_group.setLayout(control_layout)

        # Service Status
        status_group = QGroupBox("Service Status")
        status_layout = QGridLayout()

        self.lbl_status_running = QLabel("Status:")
        self.lbl_status_value = QLabel("Unknown")
        self.lbl_status_value.setStyleSheet("font-weight: 600;")

        self.lbl_enabled = QLabel("Auto-start:")
        self.lbl_enabled_value = QLabel("Unknown")

        status_layout.addWidget(self.lbl_status_running, 0, 0)
        status_layout.addWidget(self.lbl_status_value, 0, 1)
        status_layout.addWidget(self.lbl_enabled, 1, 0)
        status_layout.addWidget(self.lbl_enabled_value, 1, 1)
        status_layout.setColumnStretch(2, 1)

        status_group.setLayout(status_layout)

        # Broadcaster Output Log
        log_group = QGroupBox("Service Output")
        log_layout = QVBoxLayout()

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setPlaceholderText("Service output will appear here…")
        self.log.setMinimumHeight(200)

        log_controls = QHBoxLayout()
        self.btn_clear_log = QPushButton("Clear Log")
        self.btn_clear_log.setObjectName("secondary")
        self.btn_clear_log.clicked.connect(self.log.clear)
        log_controls.addStretch()
        log_controls.addWidget(self.btn_clear_log)

        log_layout.addWidget(self.log)
        log_layout.addLayout(log_controls)
        log_group.setLayout(log_layout)

        # Compose
        lay.addWidget(title)
        lay.addWidget(control_group)
        lay.addWidget(status_group)
        lay.addWidget(log_group, 1)

        # Connect signals
        self.btn_set_freq.clicked.connect(
            lambda: self.freq_set.emit(self.freq_spin.value(), self.chk_immediate.isChecked())
        )

    def update_service_status(self, status: dict):
        """Update service status display."""
        is_running = status.get("running", False)
        is_enabled = status.get("enabled", False)

        if is_running:
            self.lbl_status_value.setText("Running")
            self.lbl_status_value.setStyleSheet("color: #2ecc94; font-weight: 600;")
        else:
            self.lbl_status_value.setText("Stopped")
            self.lbl_status_value.setStyleSheet("color: #e74c3c; font-weight: 600;")

        self.lbl_enabled_value.setText("Enabled" if is_enabled else "Disabled")


class GroupsPage(QWidget):
    """Groups page for displaying and managing Picnic Groups."""

    def __init__(self, api_client, parent=None):
        super().__init__(parent)
        self.api_client = api_client
        lay = QVBoxLayout(self)

        # Title
        title = QLabel("My Groups")
        title.setStyleSheet("font-size: 22px; font-weight: 600;")

        # Instruction label
        instruction_label = QLabel("📻 Click a group to view and broadcast messages")
        instruction_label.setStyleSheet(
            "font-size: 16px; padding: 12px; background-color: #e3f2fd; "
            "color: #1976d2; border-radius: 6px; font-weight: 600;"
        )
        instruction_label.setAlignment(Qt.AlignCenter)

        # Refresh button
        refresh_layout = QHBoxLayout()
        self.btn_refresh = QPushButton("Refresh Groups")
        self.btn_refresh.setMinimumHeight(44)
        self.btn_refresh.clicked.connect(self.load_groups)
        refresh_layout.addWidget(self.btn_refresh)
        refresh_layout.addStretch()

        # Groups list
        groups_group = QGroupBox("Groups")
        groups_layout = QVBoxLayout()

        self.groups_list = QListWidget()
        self.groups_list.setMinimumHeight(300)
        self.groups_list.setStyleSheet("""
            QListWidget {
                font-size: 16px;
                border: 2px solid #ddd;
                border-radius: 6px;
            }
            QListWidget::item {
                padding: 15px;
                border-bottom: 1px solid #eee;
                min-height: 50px;
            }
            QListWidget::item:hover {
                background-color: #e3f2fd;
            }
            QListWidget::item:selected {
                background-color: #2196F3;
                color: white;
                font-weight: 600;
            }
        """)
        self.groups_list.itemClicked.connect(self.on_group_selected)

        groups_layout.addWidget(self.groups_list)
        groups_group.setLayout(groups_layout)

        # Group details
        details_group = QGroupBox("Group Details")
        details_layout = QVBoxLayout()

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setPlaceholderText("Click a group to view messages...")
        self.details_text.setMinimumHeight(200)
        self.details_text.setVisible(False)  # Hide details text since we navigate directly

        details_layout.addWidget(self.details_text)
        details_group.setLayout(details_layout)
        details_group.setVisible(False)  # Hide the entire details group

        # Status label
        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)

        # Compose
        lay.addWidget(title)
        lay.addWidget(instruction_label)
        lay.addLayout(refresh_layout)
        lay.addWidget(groups_group, 1)
        lay.addWidget(details_group, 1)
        lay.addWidget(self.status_label)

        # Store groups data
        self._groups_data = []

    def showEvent(self, event):
        """Called when the page is shown."""
        super().showEvent(event)
        # Auto-load groups when page is first shown
        if not self._groups_data:
            self.load_groups()

    def load_groups(self):
        """Load groups from the API."""
        from api_client import TokenExpiredError, NetworkError, PicnicAPIError

        self.status_label.setText("Loading groups...")
        self.status_label.setStyleSheet("color: #3498db;")
        self.btn_refresh.setEnabled(False)
        QApplication.processEvents()  # Update UI immediately

        try:
            # First, get the list of groups
            groups = self.api_client.get_my_groups()

            if not groups:
                self.status_label.setText("No groups found.")
                self.status_label.setStyleSheet("color: #95a5a6;")
                return

            # Clear the list
            self.groups_list.clear()
            self._groups_data = []

            # For each group, fetch full details to get radio_frequency
            for group in groups:
                # Get group ID
                group_id = (
                    group.get("id") or
                    group.get("_id") or
                    group.get("group_id") or
                    group.get("event_id")
                )

                logger.info(f"Processing group from list: {json.dumps(group, indent=2)}")

                if not group_id:
                    logger.warning(f"Group has no ID, skipping: {group}")
                    continue

                # Fetch full group details to get radio_frequency
                try:
                    logger.info(f"Fetching full details for group ID: {group_id}")
                    full_group = self.api_client.get_group_detail(group_id)
                    if full_group:
                        logger.info(f"Full group details received: {json.dumps(full_group, indent=2)}")
                        # Use full group data which includes radio_frequency
                        group = full_group
                    else:
                        logger.warning(f"get_group_detail returned None for {group_id}")
                except Exception as e:
                    logger.error(f"Failed to fetch details for group {group_id}: {e}")
                    import traceback
                    traceback.print_exc()
                    # Continue with basic group data

                # Store the group data
                self._groups_data.append(group)

                # Display group name or ID
                group_name = group.get("name", group.get("id", "Unknown Group"))
                logger.info(f"Group name: '{group_name}'")

                # Get frequency from group data
                frequency = group.get("radio_frequency")
                logger.info(f"Radio frequency for '{group_name}': {frequency}")

                # Format display text with frequency if available
                if frequency:
                    try:
                        freq_float = float(frequency)
                        display_text = f"{group_name}  •  {freq_float:.1f} MHz"
                        logger.info(f"Group '{group_name}' has frequency: {freq_float:.1f} MHz")
                    except (ValueError, TypeError):
                        display_text = f"{group_name}  •  {frequency} MHz"
                        logger.warning(f"Group '{group_name}' has invalid frequency: {frequency}")
                else:
                    display_text = f"{group_name}  •  No frequency"
                    logger.info(f"Group '{group_name}' has no radio_frequency field")

                item = QListWidgetItem(display_text)
                item.setData(Qt.UserRole, group)  # Store full group data
                self.groups_list.addItem(item)

            self.status_label.setText(f"Loaded {len(self._groups_data)} group(s) successfully.")
            self.status_label.setStyleSheet("color: #2ecc94;")

        except TokenExpiredError as e:
            self.status_label.setText(f"Session expired: {str(e)}")
            self.status_label.setStyleSheet("color: #e74c3c;")
            # Emit signal to show login dialog
            QMessageBox.warning(self, "Session Expired", "Your session has expired. Please login again.")
            # Parent should handle re-login

        except NetworkError as e:
            self.status_label.setText(f"Network error: {str(e)}")
            self.status_label.setStyleSheet("color: #e74c3c;")

        except PicnicAPIError as e:
            self.status_label.setText(f"API error: {str(e)}")
            self.status_label.setStyleSheet("color: #e74c3c;")

        except Exception as e:
            self.status_label.setText(f"Unexpected error: {str(e)}")
            self.status_label.setStyleSheet("color: #e74c3c;")

        finally:
            self.btn_refresh.setEnabled(True)

    def on_group_selected(self, item):
        """Navigate directly to message list screen when a group is clicked."""
        group = item.data(Qt.UserRole)

        if not group:
            return

        # Try different possible ID field names
        group_id = (
            group.get("id") or
            group.get("_id") or
            group.get("group_id") or
            group.get("event_id") or
            ""
        )

        # Get group name
        group_name = group.get("name", "Unknown Group")

        if not group_id:
            # Debug: Show what fields are available
            available_fields = ", ".join(group.keys()) if group else "none"
            QMessageBox.warning(
                self,
                "Error",
                f"Selected group has no ID field.\n\nAvailable fields: {available_fields}"
            )
            return

        # Get parent window and switch to messages page
        parent_window = self.window()
        if hasattr(parent_window, 'page_messages') and hasattr(parent_window, '_goto'):
            # Get frequency from group data (now available from full group details)
            frequency = group.get("radio_frequency")

            # Default to 90.8 if not found
            if frequency is None:
                frequency = 90.8
                logger.warning(f"No radio_frequency field found for group '{group_name}', using default 90.8")
            else:
                # Convert to float if it's a string
                if isinstance(frequency, str):
                    try:
                        frequency = float(frequency)
                    except ValueError:
                        logger.warning(f"Invalid radio_frequency '{frequency}' for group {group_name}, defaulting to 90.8")
                        frequency = 90.8

            logger.info(f"Selected group '{group_name}' with frequency {frequency:.1f} MHz")

            # Start silence carrier on the group's frequency immediately
            self._start_group_silence_carrier(frequency, parent_window)

            # Set the group and navigate
            parent_window.page_messages.set_group(group_id, group_name, frequency)
            parent_window._goto(2)  # Navigate to messages page

    def _start_group_silence_carrier(self, frequency: float, parent_window):
        """Start silence carrier when a group is selected."""
        try:
            if not hasattr(parent_window, '_start_silence_carrier'):
                logger.warning("Parent window does not have _start_silence_carrier method")
                return

            # Stop any existing pifm processes first
            logger.info("Stopping any existing pifm processes...")
            subprocess.run(
                ["sudo", "pkill", "-9", "pifm"],
                capture_output=True,
                timeout=5
            )
            subprocess.run(
                ["sudo", "pkill", "-9", "pifm_broadcast"],
                capture_output=True,
                timeout=5
            )

            # Brief delay to ensure /dev/mem is released
            import time
            time.sleep(0.5)

            # Get environment variables
            env_vars = load_env_file(ENV_PATH)

            # Update BROADCAST_CMD with the group's frequency
            broadcast_cmd_template = env_vars.get(
                "BROADCAST_CMD",
                "/usr/bin/sudo /usr/local/bin/pifm_broadcast.sh {file} -f {freq}"
            )
            new_broadcast_cmd = render_broadcast_cmd(broadcast_cmd_template, frequency)

            # Write the updated BROADCAST_CMD to the env file
            write_env_key(ENV_PATH, "BROADCAST_CMD", new_broadcast_cmd)
            logger.info(f"Updated BROADCAST_CMD to frequency {frequency:.1f} MHz: {new_broadcast_cmd}")

            # Update env_vars dict for immediate use
            env_vars["BROADCAST_CMD"] = new_broadcast_cmd

            # Create a simple log list
            log_messages = []

            class LogCapture:
                def append(self, msg):
                    log_messages.append(msg)
                    logger.info(f"Group silence carrier: {msg}")

            log = LogCapture()

            # Start silence carrier on group's frequency
            logger.info(f"Starting silence carrier for group on {frequency:.1f} MHz")
            parent_window._start_silence_carrier(frequency, env_vars, log)

            # Update status
            self.status_label.setText(f"✓ Broadcasting silence carrier on {frequency:.1f} MHz")
            self.status_label.setStyleSheet("color: #2ecc94;")

        except Exception as e:
            logger.error(f"Failed to start group silence carrier: {e}")
            self.status_label.setText(f"Warning: Could not start silence carrier - {e}")
            self.status_label.setStyleSheet("color: #ff9800;")

    def view_group_messages(self):
        """Navigate to message list screen for selected group (button handler)."""
        item = self.groups_list.currentItem()
        if item:
            self.on_group_selected(item)


class MessageListScreen(QWidget):
    """Message list screen for viewing and broadcasting group messages."""

    def __init__(self, api_client, parent=None):
        super().__init__(parent)
        self.api_client = api_client
        self.broadcaster = None
        self.current_group_id = None
        self.current_group_name = "Unknown Group"
        self.current_frequency = 90.8
        self.messages_data = []

        # Main layout
        lay = QVBoxLayout(self)
        lay.setSpacing(12)
        lay.setContentsMargins(16, 16, 16, 16)

        # Header section
        header_layout = QHBoxLayout()
        header_layout.setSpacing(12)

        # Group name and frequency display
        self.header_label = QLabel("Group Messages")
        self.header_label.setStyleSheet(
            "font-size: 24px; font-weight: 600; color: white; "
            "background-color: #2196F3; padding: 15px; border-radius: 8px;"
        )
        self.header_label.setAlignment(Qt.AlignCenter)

        header_layout.addWidget(self.header_label, 1)
        lay.addLayout(header_layout)

        # Messages list
        messages_group = QGroupBox("Messages")
        messages_group.setStyleSheet("QGroupBox { font-size: 18px; font-weight: 600; }")
        messages_layout = QVBoxLayout()

        self.messages_list = QListWidget()
        self.messages_list.setSelectionMode(QListWidget.MultiSelection)
        self.messages_list.setStyleSheet("""
            QListWidget {
                font-size: 16px;
                border: 2px solid #ddd;
                border-radius: 6px;
            }
            QListWidget::item {
                padding: 15px;
                border-bottom: 1px solid #eee;
                min-height: 60px;
            }
            QListWidget::item:selected {
                background-color: #e3f2fd;
                color: #1976d2;
                font-weight: 600;
            }
            QListWidget::item:hover {
                background-color: #f5f5f5;
            }
        """)
        self.messages_list.setMinimumHeight(400)

        messages_layout.addWidget(self.messages_list)
        messages_group.setLayout(messages_layout)
        lay.addWidget(messages_group, 1)

        # Status label
        self.status_label = QLabel("Select a group to view messages")
        self.status_label.setStyleSheet("font-size: 16px; padding: 8px; color: #666;")
        self.status_label.setWordWrap(True)
        self.status_label.setAlignment(Qt.AlignCenter)
        lay.addWidget(self.status_label)

        # Action buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)

        self.btn_back = QPushButton("← Back")
        self.btn_back.setMinimumHeight(60)
        self.btn_back.setStyleSheet("""
            QPushButton {
                font-size: 18px;
                font-weight: 600;
                background-color: #f44336;
                color: white;
                border-radius: 8px;
                padding: 12px 24px;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
            QPushButton:pressed {
                background-color: #b71c1c;
            }
        """)
        self.btn_back.clicked.connect(self.go_back)

        self.btn_refresh = QPushButton("🔄 Refresh Messages")
        self.btn_refresh.setMinimumHeight(60)
        self.btn_refresh.setStyleSheet("""
            QPushButton {
                font-size: 18px;
                font-weight: 600;
                background-color: #2196F3;
                color: white;
                border-radius: 8px;
                padding: 12px 24px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:pressed {
                background-color: #0D47A1;
            }
        """)
        self.btn_refresh.clicked.connect(self.refresh_messages)

        self.btn_broadcast = QPushButton("📻 Broadcast Selected")
        self.btn_broadcast.setMinimumHeight(60)
        self.btn_broadcast.setStyleSheet("""
            QPushButton {
                font-size: 18px;
                font-weight: 600;
                background-color: #4CAF50;
                color: white;
                border-radius: 8px;
                padding: 12px 24px;
            }
            QPushButton:hover {
                background-color: #388E3C;
            }
            QPushButton:pressed {
                background-color: #1B5E20;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        self.btn_broadcast.clicked.connect(self.broadcast_selected)
        self.btn_broadcast.setEnabled(False)

        btn_layout.addWidget(self.btn_back)
        btn_layout.addWidget(self.btn_refresh)
        btn_layout.addWidget(self.btn_broadcast, 1)
        lay.addLayout(btn_layout)

        # Connect selection change
        self.messages_list.itemSelectionChanged.connect(self._on_selection_changed)

    def set_group(self, group_id: str, group_name: str, frequency: float = 90.8):
        """
        Set the group to display messages for.

        Args:
            group_id: The group ID
            group_name: The group name for display
            frequency: FM frequency for broadcasting
        """
        self.current_group_id = group_id
        self.current_group_name = group_name
        self.current_frequency = frequency

        # Update header
        self.header_label.setText(f"{group_name} • {frequency:.1f} MHz")

        # Initialize broadcaster with current token
        if self.api_client and self.api_client._access_token:
            from message_broadcaster import PicnicMessageBroadcaster
            # Get TTS configuration from environment
            env_vars = load_env_file(ENV_PATH)
            tts_endpoint = env_vars.get("TTS_ENDPOINT", os.getenv("TTS_ENDPOINT", ""))
            tts_api_key = env_vars.get("TTS_API_KEY", os.getenv("TTS_API_KEY", ""))
            s3_bucket = env_vars.get("TTS_S3_BUCKET", os.getenv("TTS_S3_BUCKET", "audio-txt-broadcast"))
            s3_prefix = env_vars.get("TTS_S3_PREFIX", os.getenv("TTS_S3_PREFIX", "tts/"))
            self.broadcaster = PicnicMessageBroadcaster(
                self.api_client._access_token,
                tts_endpoint,
                s3_bucket=s3_bucket,
                s3_prefix=s3_prefix,
                tts_api_key=tts_api_key
            )

        # Start silence carrier on the group's frequency
        logger.info(f"Starting silence carrier for group '{group_name}' on {frequency:.1f} MHz")
        self._restart_silence_carrier()

        # Auto-load messages
        self.refresh_messages()

    def refresh_messages(self):
        """Refresh messages from the API."""
        from message_broadcaster import MessageFetchError
        import traceback

        if not self.current_group_id:
            self.status_label.setText("No group selected")
            self.status_label.setStyleSheet("font-size: 16px; padding: 8px; color: #e74c3c;")
            return

        if not self.broadcaster:
            self.status_label.setText("Not authenticated. Please login again.")
            self.status_label.setStyleSheet("font-size: 16px; padding: 8px; color: #e74c3c;")
            return

        self.status_label.setText(f"Loading messages for group {self.current_group_id}...")
        self.status_label.setStyleSheet("font-size: 16px; padding: 8px; color: #3498db;")
        self.btn_refresh.setEnabled(False)
        QApplication.processEvents()

        try:
            print(f"\n=== FETCHING MESSAGES ===")
            print(f"Group ID: {self.current_group_id}")
            print(f"Group Name: {self.current_group_name}")

            # Fetch messages
            messages = self.broadcaster.get_group_messages(self.current_group_id, limit=50)
            self.messages_data = messages

            print(f"Received {len(messages)} messages")

            # Clear and populate list
            self.messages_list.clear()

            if not messages:
                self.status_label.setText("No text messages found in this group")
                self.status_label.setStyleSheet("font-size: 16px; padding: 8px; color: #95a5a6;")
                print("No messages to display")
                return

            # Add messages to list
            for i, msg in enumerate(messages):
                print(f"\nMessage {i+1}: {msg.get('message', '')[:50]}...")
                formatted = self.broadcaster.format_message_for_display(msg)
                display_text = formatted["display_text"]

                item = QListWidgetItem(display_text)
                item.setData(Qt.UserRole, msg)  # Store original message data
                self.messages_list.addItem(item)

            self.status_label.setText(f"✓ Loaded {len(messages)} message(s) successfully")
            self.status_label.setStyleSheet("font-size: 16px; padding: 8px; color: #2ecc94;")
            print(f"Successfully displayed {len(messages)} messages")

        except MessageFetchError as e:
            error_msg = str(e)
            self.status_label.setText(f"Error: {error_msg}")
            self.status_label.setStyleSheet("font-size: 16px; padding: 8px; color: #e74c3c;")
            print(f"MessageFetchError: {error_msg}")
            traceback.print_exc()

            # Show detailed error dialog
            QMessageBox.critical(
                self,
                "Failed to Load Messages",
                f"Could not load messages from group.\n\n{error_msg}\n\nCheck the console for details."
            )

        except Exception as e:
            error_msg = str(e)
            self.status_label.setText(f"Unexpected error: {error_msg}")
            self.status_label.setStyleSheet("font-size: 16px; padding: 8px; color: #e74c3c;")
            print(f"Unexpected error: {error_msg}")
            traceback.print_exc()

            # Show detailed error dialog
            QMessageBox.critical(
                self,
                "Error",
                f"Unexpected error loading messages.\n\n{error_msg}\n\nCheck the console for details."
            )

        finally:
            self.btn_refresh.setEnabled(True)

    def broadcast_selected(self):
        """Broadcast selected messages via TTS."""
        from message_broadcaster import TTSBroadcastError

        selected_items = self.messages_list.selectedItems()

        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select at least one message to broadcast.")
            return

        if not self.broadcaster:
            QMessageBox.critical(self, "Error", "Broadcaster not initialized. Please try again.")
            return

        # Confirm broadcast
        reply = QMessageBox.question(
            self,
            "Confirm Broadcast",
            f"Broadcast {len(selected_items)} message(s) on {self.current_frequency:.1f} MHz?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes
        )

        if reply != QMessageBox.Yes:
            return

        # Stop silence carrier BEFORE broadcasting to free /dev/mem
        logger.info("Stopping silence carrier before message broadcast...")
        self._stop_all_pifm_processes()

        # Disable buttons during broadcast
        self.btn_broadcast.setEnabled(False)
        self.btn_refresh.setEnabled(False)
        self.status_label.setText(f"Broadcasting {len(selected_items)} message(s)...")
        self.status_label.setStyleSheet("font-size: 16px; padding: 8px; color: #ff9800;")
        QApplication.processEvents()

        success_count = 0
        error_count = 0

        for item in selected_items:
            msg = item.data(Qt.UserRole)
            formatted = self.broadcaster.format_message_for_display(msg)

            try:
                # Broadcast the message
                self.broadcaster.broadcast_message(
                    formatted["message_text"],
                    formatted["user_name"],
                    self.current_frequency
                )

                # Visual feedback - green highlight
                item.setBackground(Qt.green)
                item.setForeground(Qt.darkGreen)
                success_count += 1

            except TTSBroadcastError as e:
                # Visual feedback - red highlight
                item.setBackground(Qt.red)
                item.setForeground(Qt.white)
                error_count += 1
                logger.error(f"Failed to broadcast message: {e}")

            except Exception as e:
                item.setBackground(Qt.red)
                item.setForeground(Qt.white)
                error_count += 1
                logger.error(f"Unexpected error broadcasting message: {e}")

            QApplication.processEvents()

        # Update status
        if error_count == 0:
            self.status_label.setText(f"✓ Successfully broadcast {success_count} message(s)")
            self.status_label.setStyleSheet("font-size: 16px; padding: 8px; color: #2ecc94; font-weight: 600;")
            QMessageBox.information(
                self,
                "Broadcast Complete",
                f"Successfully broadcast {success_count} message(s) on {self.current_frequency:.1f} MHz"
            )
        else:
            self.status_label.setText(
                f"Broadcast complete: {success_count} succeeded, {error_count} failed"
            )
            self.status_label.setStyleSheet("font-size: 16px; padding: 8px; color: #ff9800; font-weight: 600;")
            QMessageBox.warning(
                self,
                "Broadcast Completed with Errors",
                f"{success_count} message(s) broadcast successfully\n{error_count} message(s) failed"
            )

        # Restart silence carrier after broadcast to prevent static
        if success_count > 0:
            self._restart_silence_carrier()

        # Re-enable buttons
        self.btn_broadcast.setEnabled(True)
        self.btn_refresh.setEnabled(True)

    def _on_selection_changed(self):
        """Handle selection change in messages list."""
        has_selection = len(self.messages_list.selectedItems()) > 0
        self.btn_broadcast.setEnabled(has_selection)

    def _stop_all_pifm_processes(self):
        """Stop all running pifm/pifm_broadcast processes to free /dev/mem."""
        try:
            logger.info("Stopping all pifm processes to free /dev/mem...")
            # Kill all pifm processes
            subprocess.run(
                ["sudo", "pkill", "-9", "pifm"],
                capture_output=True,
                timeout=5
            )
            # Also kill any pifm_broadcast.sh processes
            subprocess.run(
                ["sudo", "pkill", "-9", "pifm_broadcast"],
                capture_output=True,
                timeout=5
            )
            # Brief delay to ensure /dev/mem is released
            import time
            time.sleep(0.5)
            logger.info("All pifm processes stopped")
        except Exception as e:
            logger.warning(f"Failed to stop pifm processes: {e}")

    def _restart_silence_carrier(self):
        """Restart silence carrier after message broadcast."""
        try:
            # Get parent window (MainWindow)
            parent_window = self.window()
            if not hasattr(parent_window, '_start_silence_carrier'):
                logger.warning("Parent window does not have _start_silence_carrier method")
                return

            # Stop any existing pifm processes first
            self._stop_all_pifm_processes()

            # Get environment variables
            env_vars = load_env_file(ENV_PATH)

            # Create a simple log list for _start_silence_carrier
            log_messages = []

            class LogCapture:
                def append(self, msg):
                    log_messages.append(msg)
                    logger.info(f"Silence carrier: {msg}")

            log = LogCapture()

            # Restart silence carrier on current frequency
            logger.info(f"Restarting silence carrier on {self.current_frequency:.1f} MHz")
            parent_window._start_silence_carrier(self.current_frequency, env_vars, log)

            # Update status with success
            self.status_label.setText(f"✓ Broadcast complete • Silence carrier restarted on {self.current_frequency:.1f} MHz")

        except Exception as e:
            logger.error(f"Failed to restart silence carrier: {e}")

    def go_back(self):
        """Navigate back to groups page."""
        # Clear messages
        self.messages_list.clear()
        self.messages_data = []
        self.current_group_id = None

        # Signal parent to switch page
        parent_window = self.window()
        if hasattr(parent_window, '_goto'):
            parent_window._goto(1)  # Go to Groups page


# =============================
# Main Window
# =============================

class MainWindow(QMainWindow):
    """Main application window with integrated service management."""

    def __init__(self, api_client):
        super().__init__()
        self.proc = None  # QProcess for broadcaster
        self.health_worker = None
        self.api_client = api_client

        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setWindowIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        self.resize(1000, 700)

        # Settings
        self.settings = QSettings(APP_ORG, APP_NAME)
        self._restore_geometry()

        # Root layout
        central = QWidget()
        root = QHBoxLayout(central)
        self.setCentralWidget(central)

        # Sidebar
        side = QVBoxLayout()
        self.btn_dashboard = QPushButton("Dashboard")
        self.btn_groups = QPushButton("Groups")
        self.btn_wifi = QPushButton("WiFi")
        self.btn_dashboard.setCheckable(True)
        self.btn_groups.setCheckable(True)
        self.btn_dashboard.setChecked(True)

        side.addWidget(self.btn_dashboard)
        side.addWidget(self.btn_groups)
        side.addWidget(self.btn_wifi)
        side.addStretch(1)

        # Logout button at bottom
        self.btn_logout = QPushButton("Logout")
        self.btn_logout.setObjectName("logout")
        side.addWidget(self.btn_logout)

        side_wrap = QWidget()
        side_wrap.setLayout(side)
        side_wrap.setFixedWidth(160)
        side_wrap.setObjectName("Sidebar")
        side_wrap.setStyleSheet(
            "#Sidebar {border-right: 1px solid palette(mid); padding: 8px;}\n"
            "QPushButton {text-align: left; padding: 10px; min-height: 44px;}\n"
            "QPushButton:checked {font-weight: 600; background: #e8f8f2;}"
        )

        # Pages
        self.pages = QStackedWidget()
        self.page_dashboard = DashboardPage()
        self.page_groups = GroupsPage(api_client)
        self.page_messages = MessageListScreen(api_client)

        # Load frequency from env file
        freq_from_env = extract_current_frequency(ENV_PATH)
        if freq_from_env is not None and validate_frequency(freq_from_env):
            self.page_dashboard.freq_spin.setValue(freq_from_env)

        self.pages.addWidget(self.page_dashboard)  # Index 0
        self.pages.addWidget(self.page_groups)     # Index 1
        self.pages.addWidget(self.page_messages)   # Index 2

        # Compose
        root.addWidget(side_wrap)
        content = QVBoxLayout()
        content_wrap = QWidget()
        content_wrap.setLayout(content)
        content.addWidget(self.pages, 1)
        root.addWidget(content_wrap, 1)

        # Restore saved frequency
        try:
            saved_freq = float(self.settings.value("radio/frequency", 90.8))
            if validate_frequency(saved_freq):
                self.page_dashboard.freq_spin.setValue(saved_freq)
        except (ValueError, TypeError):
            pass

        # Connect signals
        self.page_dashboard.freq_set.connect(self.on_set_frequency)
        self.btn_dashboard.clicked.connect(lambda: self._goto(0))
        self.btn_groups.clicked.connect(lambda: self._goto(1))
        self.btn_wifi.clicked.connect(self.open_wifi_dialog)
        self.btn_logout.clicked.connect(self.handle_logout)

        # System tray
        self._setup_tray()

        # Touch-friendly styling
        self.setStyleSheet("""
            QPushButton { min-height: 44px; font-size: 16px; }
            QDoubleSpinBox { min-height: 44px; font-size: 16px; }
            QCheckBox { min-height: 36px; font-size: 15px; }
        """)

        # Start health monitoring
        self._start_health_monitoring()

        # Check WiFi connection on startup (delayed to ensure window is shown)
        QTimer.singleShot(500, self._check_wifi_on_startup)

    # ---------- WiFi Connection Check ----------

    def _check_wifi_on_startup(self):
        """Check WiFi connection status on startup and prompt if not connected."""
        if not self._is_wifi_connected():
            reply = QMessageBox.question(
                self,
                "WiFi Not Connected",
                "No active WiFi connection detected.\n\n"
                "Would you like to configure WiFi now?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            if reply == QMessageBox.Yes:
                self.open_wifi_dialog()

    def _is_wifi_connected(self) -> bool:
        """
        Check if WiFi is connected.

        Returns:
            True if WiFi is connected, False otherwise
        """
        try:
            # Check network connectivity using nmcli
            result = subprocess.run(
                ["nmcli", "-t", "-f", "STATE", "general"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                state = result.stdout.strip()
                # States: connected, connected (local only), connected (site only), disconnected
                return "connected" in state.lower()
        except FileNotFoundError:
            # nmcli not available, try alternative method using ip route
            try:
                result = subprocess.run(
                    ["ip", "route", "get", "8.8.8.8"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                # If we can get a route to 8.8.8.8, we have internet connectivity
                return result.returncode == 0
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
        except subprocess.TimeoutExpired:
            pass

        # If all checks fail, assume connected to avoid false positives
        return True

    # ---------- Frequency Control ----------

    def on_set_frequency(self, freq: float, immediate: bool):
        """Handle frequency change request."""
        # Save frequency
        self.settings.setValue("radio/frequency", float(freq))

        # Validate
        if not validate_frequency(freq):
            QMessageBox.warning(
                self,
                "Invalid Frequency",
                f"Please choose a frequency between 76.0 and 108.0 MHz.\n\nYou entered: {freq:.1f} MHz"
            )
            return

        try:
            # Build environment
            env_vars = os.environ.copy()
            env_from_file = load_env_file(ENV_PATH)
            env_vars.update(env_from_file)

            # GPU libraries path for pifm
            if not env_vars.get("LD_LIBRARY_PATH"):
                candidates = ["/opt/vc/lib", "/usr/lib/arm-linux-gnueabihf", "/usr/lib/aarch64-linux-gnu"]
                existing = [d for d in candidates if os.path.exists(d)]
                if existing:
                    env_vars["LD_LIBRARY_PATH"] = ":".join(existing)

            # Compute and persist new BROADCAST_CMD
            tmpl = env_vars.get(
                "BROADCAST_CMD",
                "/usr/bin/sudo /usr/local/bin/pifm {file} -f {freq}",
            )
            new_cmd = render_broadcast_cmd(tmpl, freq)
            env_vars["BROADCAST_CMD"] = new_cmd

            write_env_key(ENV_PATH, "BROADCAST_CMD", new_cmd)

        except Exception as e:
            QMessageBox.critical(
                self,
                "Configuration Error",
                f"Failed to update configuration:\n{e}"
            )
            return

        log = self.page_dashboard.log
        log.append(f"\n[{self._timestamp()}] Frequency set to {freq:.1f} MHz")
        log.append(f"BROADCAST_CMD updated: {new_cmd}")

        # Signal running service or start it
        running = self.proc and self.proc.state() != QProcess.NotRunning

        if running:
            pid = int(self.proc.processId())

            # CRITICAL: Validate PID before sending signals
            if pid <= 0:
                log.append(f"WARNING: Invalid PID {pid}, cannot signal process")
                logger.error(f"Invalid process ID: {pid}")
                self._start_broadcaster_with_env(env_vars, fresh=True)
            else:
                try:
                    if immediate:
                        os.kill(pid, signal.SIGUSR2)
                        log.append(f"Sent SIGUSR2 to PID {pid} (immediate switch)")
                    else:
                        os.kill(pid, signal.SIGHUP)
                        log.append(f"Sent SIGHUP to PID {pid} (reload after current message)")
                except ProcessLookupError:
                    log.append(f"Process {pid} not found, restarting service...")
                    self._start_broadcaster_with_env(env_vars, fresh=True)
                except PermissionError as e:
                    log.append(f"Permission denied signaling process {pid}: {e}")
                    logger.error(f"Permission error sending signal to PID {pid}: {e}")
                    QMessageBox.critical(self, "Permission Error", f"Cannot signal process (need sudo?): {e}")
                except OSError as e:
                    log.append(f"OS error signaling process {pid}: {e}")
                    logger.error(f"OS error sending signal to PID {pid}: {e}")
                    self._start_broadcaster_with_env(env_vars, fresh=True)
                except Exception as e:
                    log.append(f"Failed to signal process: {e}")
                    logger.error(f"Unexpected error signaling PID {pid}: {e}")
                    self._start_broadcaster_with_env(env_vars, fresh=True)
        else:
            log.append("Service not running, starting...")
            self._start_broadcaster_with_env(env_vars, fresh=True)

        # Start silence carrier to prevent static
        self._start_silence_carrier(freq, env_vars, log)

        QMessageBox.information(
            self,
            "Frequency Updated",
            f"Broadcasting frequency {'switched to' if immediate else 'will switch to'} {freq:.1f} MHz"
        )

    def _start_silence_carrier(self, freq: float, env_vars: dict, log):
        """Start broadcasting silence carrier to prevent static."""
        import wave

        # Ensure WAV directory exists
        wav_dir = "/home/rpibroadcaster/wav"
        if not os.path.exists(wav_dir):
            os.makedirs(wav_dir, exist_ok=True)

        # Create or verify silence WAV file
        silence_file = os.path.join(wav_dir, "silence_carrier.wav")

        try:
            # Create silence WAV if it doesn't exist (1800 seconds = 30 minutes)
            if not os.path.exists(silence_file):
                log.append(f"Creating silence carrier file: {silence_file}")
                with wave.open(silence_file, "wb") as wav:
                    wav.setnchannels(1)  # Mono
                    wav.setsampwidth(2)  # 16-bit
                    wav.setframerate(16000)  # 16kHz

                    # Write 30 minutes of silence (all zeros)
                    silence_secs = 1800
                    silence_data = b"\x00\x00" * 16000 * silence_secs
                    wav.writeframes(silence_data)

                log.append("Silence carrier file created successfully")

            # Validate frequency
            if not isinstance(freq, (int, float)) or freq < 76.0 or freq > 108.0:
                raise ValueError(f"Invalid FM frequency: {freq} (must be 76.0-108.0 MHz)")

            # Build broadcast command for silence
            broadcast_cmd_template = env_vars.get(
                "BROADCAST_CMD",
                "/usr/bin/sudo /usr/local/bin/pifm_broadcast.sh {file} -f {freq}"
            )

            # Parse command safely without shell=True
            cmd_parts = broadcast_cmd_template.split()
            cmd_args = []
            for part in cmd_parts:
                if '{file}' in part:
                    # Verify silence file exists
                    if not os.path.exists(silence_file):
                        raise FileNotFoundError(f"Silence file not found: {silence_file}")
                    cmd_args.append(part.replace('{file}', silence_file))
                elif '{freq}' in part:
                    cmd_args.append(part.replace('{freq}', f"{freq:.1f}"))
                else:
                    cmd_args.append(part)

            log.append(f"Starting silence carrier on {freq:.1f} MHz...")
            log.append(f"Command: {' '.join(cmd_args)}")

            # Start silence carrier in background without shell=True
            # Note: We don't track this process intentionally - it should run until killed
            subprocess.Popen(
                cmd_args,
                shell=False,  # CRITICAL: Prevent command injection
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL
            )

            log.append("Silence carrier started successfully")

        except Exception as e:
            log.append(f"Warning: Could not start silence carrier: {e}")
            logger.warning(f"Failed to start silence carrier: {e}")

    def _start_broadcaster_with_env(self, env_vars: dict, fresh: bool = False):
        """Start the broadcaster service with given environment."""
        if fresh:
            self._stop_script()

        log = self.page_dashboard.log

        # Determine Python executable
        py = PYTHON_BIN if os.path.isfile(PYTHON_BIN) else sys.executable

        # Check if service executable exists
        if not os.path.exists(SERVICE_PATH):
            log.append(f"\nERROR: Service not found at {SERVICE_PATH}")
            QMessageBox.critical(
                self,
                "Service Not Found",
                f"Cannot find broadcaster service at:\n{SERVICE_PATH}\n\n"
                f"Please ensure the service is properly installed."
            )
            return

        log.append(f"\n[{self._timestamp()}] Starting service: {py} {SERVICE_PATH}")

        # Create QProcess if needed
        if not (self.proc and self.proc.state() != QProcess.NotRunning):
            self.proc = QProcess(self)
            self.proc.setProcessChannelMode(QProcess.MergedChannels)
            self.proc.readyReadStandardOutput.connect(self._on_ready_read)
            self.proc.finished.connect(self._on_finished)

        # Set environment
        penv = self.proc.processEnvironment()
        penv.clear()
        for k, v in env_vars.items():
            penv.insert(k, v)
        self.proc.setProcessEnvironment(penv)

        # Start process
        self.proc.start(py, [SERVICE_PATH])
        if not self.proc.waitForStarted(5000):
            log.append(f"ERROR: Failed to start service")
            QMessageBox.critical(self, "Startup Failed", "Failed to start the broadcaster service.")
            self.proc = None

    def _stop_script(self):
        """Stop the running broadcaster process."""
        if self.proc and self.proc.state() != QProcess.NotRunning:
            log = self.page_dashboard.log
            log.append(f"\n[{self._timestamp()}] Stopping service...")

            self.proc.terminate()
            if not self.proc.waitForFinished(3000):
                log.append("Service did not terminate gracefully, forcing shutdown...")
                self.proc.kill()
                self.proc.waitForFinished(1000)

            log.append("Service stopped")
        self.proc = None

    # ---------- QProcess Output ----------

    def _on_ready_read(self):
        """Handle output from broadcaster process."""
        if not self.proc:
            return
        data = bytes(self.proc.readAllStandardOutput()).decode(errors="ignore")
        if data:
            cursor = self.page_dashboard.log.textCursor()
            cursor.movePosition(cursor.End)
            cursor.insertText(data)
            self.page_dashboard.log.setTextCursor(cursor)
            self.page_dashboard.log.ensureCursorVisible()

    def _on_finished(self, exitCode, exitStatus):
        """Handle broadcaster process exit."""
        status_str = "normal" if exitStatus == QProcess.NormalExit else "crashed"
        self.page_dashboard.log.append(
            f"\n[{self._timestamp()}] Process exited: code={exitCode}, status={status_str}"
        )

    # ---------- Health Monitoring ----------

    def _start_health_monitoring(self):
        """Start background health monitoring."""
        self.health_worker = HealthMonitorWorker()
        self.health_worker.metrics_updated.connect(self.page_dashboard.update_service_status)
        self.health_worker.start()

    def _stop_health_monitoring(self):
        """Stop background health monitoring."""
        if self.health_worker:
            self.health_worker.stop()
            self.health_worker.wait(2000)
            self.health_worker = None

    # ---------- Wi-Fi ----------

    def open_wifi_dialog(self):
        """Open WiFi management dialog."""
        dlg = WifiDialog(self)
        dlg.exec_()

    # ---------- Navigation ----------

    def _goto(self, index: int):
        """Navigate to page by index."""
        self.pages.setCurrentIndex(index)
        self.btn_dashboard.setChecked(index == 0)
        self.btn_groups.setChecked(index == 1)

    def handle_logout(self):
        """Handle user logout."""
        reply = QMessageBox.question(
            self,
            "Logout",
            "Are you sure you want to logout?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            # Clear the token
            self.api_client.logout()

            # Close main window
            self.close()

            # Show login dialog again
            login = LoginDialog(self.api_client, self)
            if login.exec_() == QDialog.Accepted:
                # User logged in again, show main window
                self.show()
            else:
                # User cancelled, exit application
                QApplication.instance().quit()

    # ---------- System Tray ----------

    def _setup_tray(self):
        """Setup system tray icon."""
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return

        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))

        menu = QMenu()
        act_show = menu.addAction("Show / Hide")
        act_quit = menu.addAction("Quit")

        act_show.triggered.connect(self._toggle_visible)
        act_quit.triggered.connect(self._safe_quit)

        self.tray.setContextMenu(menu)
        self.tray.setToolTip(APP_NAME)
        self.tray.show()

    def _toggle_visible(self):
        """Toggle window visibility."""
        self.setVisible(not self.isVisible())

    def _safe_quit(self):
        """Safely quit application."""
        self._stop_script()
        self._stop_health_monitoring()
        QApplication.instance().quit()

    # ---------- Settings & Cleanup ----------

    def closeEvent(self, e):
        """Handle window close event."""
        self.settings.setValue("ui/geometry", self.saveGeometry())

        # Stop background workers
        self._stop_health_monitoring()

        # Stop service (optional - service can continue running)
        # Uncomment if you want to stop service on dashboard close:
        # self._stop_script()

        super().closeEvent(e)

    def _restore_geometry(self):
        """Restore window geometry from settings."""
        geo = self.settings.value("ui/geometry")
        if geo is not None:
            self.restoreGeometry(geo)

    def _timestamp(self):
        """Get formatted timestamp for logging."""
        import datetime
        return datetime.datetime.now().strftime("%H:%M:%S")


# =============================
# Application Entry Point
# =============================

def fetch_sailing_group_frequency(api_client) -> Optional[float]:
    """
    Fetch the Sailing group's frequency from the API.

    Uses the group detail endpoint to get full group data including radio_frequency.

    Args:
        api_client: Authenticated PicnicAPIClient instance

    Returns:
        Frequency as float, or None if not found
    """
    SAILING_GROUP_ID = "6918ed90a92aa58974af4ed1"

    try:
        logger.info(f"Fetching Sailing group frequency from detail endpoint...")
        # Use get_group_detail which calls /api/v1/group/detail/{id}
        group = api_client.get_group_detail(SAILING_GROUP_ID)

        if not group:
            logger.warning(f"Sailing group {SAILING_GROUP_ID} not found")
            return None

        # Get radio_frequency field directly
        frequency = group.get("radio_frequency")

        if frequency is None:
            logger.warning("No radio_frequency field found in Sailing group data")
            return None

        # Convert to float if it's a string
        if isinstance(frequency, str):
            try:
                frequency = float(frequency)
            except ValueError:
                logger.warning(f"Invalid frequency value '{frequency}', ignoring")
                return None

        logger.info(f"Sailing group frequency: {frequency:.1f} MHz")
        return frequency

    except Exception as e:
        logger.warning(f"Failed to fetch Sailing group frequency: {e}")
        return None


def main():
    """Main application entry point."""
    from api_client import PicnicAPIClient

    # High DPI support
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_SynthesizeMouseForUnhandledTouchEvents, True)
    QApplication.setAttribute(Qt.AA_SynthesizeTouchForUnhandledMouseEvents, True)

    app = QApplication(sys.argv)

    # Apply theme
    apply_theme(app)

    # Set organization/app name for QSettings
    app.setOrganizationName(APP_ORG)
    app.setApplicationName(APP_NAME)

    # Create API client
    api_client = PicnicAPIClient()

    # Check if user has a valid token (auto-login)
    if not api_client.is_authenticated():
        # Show login dialog if no valid token
        login = LoginDialog(api_client)
        if login.exec_() != QDialog.Accepted:
            # User cancelled or failed login
            sys.exit(0)

    # Fetch Sailing group frequency and set as default
    sailing_frequency = fetch_sailing_group_frequency(api_client)

    # User authenticated successfully, show main window
    w = MainWindow(api_client)

    # Set the fetched frequency if available
    if sailing_frequency is not None and validate_frequency(sailing_frequency):
        logger.info(f"Setting dashboard frequency to Sailing group frequency: {sailing_frequency:.1f} MHz")
        w.page_dashboard.freq_spin.setValue(sailing_frequency)

    w.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()

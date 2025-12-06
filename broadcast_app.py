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

# Configure logging - use INFO level for better performance
logging.basicConfig(
    level=logging.INFO,  # Changed from DEBUG for performance
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
    QSpinBox,
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

def kill_all_pifm_processes():
    """
    Kill all running pifm/pifm_broadcast processes.

    This is critical when switching users or starting new broadcasts
    to ensure /dev/mem is released and no conflicts occur.

    Optimized to reduce subprocess overhead.
    """
    import time

    try:
        logger.debug("Killing all pifm processes...")

        # Combine pkill commands into single call for better performance
        # Use ; to run both commands even if first fails
        subprocess.run(
            ["sudo", "sh", "-c", "pkill -9 pifm; pkill -9 pifm_broadcast"],
            capture_output=True,
            timeout=3  # Reduced timeout from 5s to 3s
        )

        # Reduced sleep time from 1.0s to 0.5s for better responsiveness
        time.sleep(0.5)

        logger.debug("All pifm processes killed")

    except subprocess.TimeoutExpired:
        logger.warning("Timeout killing pifm processes")
    except FileNotFoundError:
        logger.warning("pkill command not found")
    except Exception as e:
        logger.warning(f"Failed to kill pifm processes: {e}")


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

        # Special characters row
        special_chars = list("!@#$%^&*()-_=+")

        g = QVBoxLayout()
        g.setContentsMargins(4, 3, 4, 4)  # Reduced for smaller screen
        g.setSpacing(6)  # Reduced vertical spacing for 7" screen

        def row_of(chars, prefix_widgets=None, suffix_widgets=None):
            h = QHBoxLayout()
            h.setSpacing(3)  # Reduced horizontal spacing
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

        # Add special characters row
        g.addLayout(row_of(special_chars))

        hide = self._mk_btn("Hide", wide=True)
        hide.clicked.connect(self.hide)

        space = self._mk_btn("Space", wide=True)
        space.clicked.connect(lambda: self._type_text(" "))

        enter = self._mk_btn("Enter", wide=True)
        enter.clicked.connect(lambda: self._special_key("Enter"))

        bottom = QHBoxLayout()
        bottom.setSpacing(6)  # Reduced spacing for 7" screen
        bottom.addWidget(hide)
        bottom.addWidget(space, 2)
        bottom.addWidget(enter)
        g.addLayout(bottom)

        self.setLayout(g)

        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setFixedHeight(200)  # Reduced height for 7" screen
        self.setStyleSheet("""
            #OnScreenKeyboard QPushButton { min-width: 26px; min-height: 30px; font-size: 12px; }
            #OnScreenKeyboard QPushButton[wide="true"] { min-width: 50px; }
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
        # Fit exactly within 7-inch screen (800x480)
        self.setFixedSize(780, 460)  # Leave small margin for window decorations

        # Apply styling to match login page (smaller for 7" screen)
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #fafbfa, stop:1 #f0fdf9);
            }
            QLabel {
                font-size: 12px;
                color: #1a1a1a;
            }
            QListWidget {
                background: white;
                border: 2px solid #cdeee0;
                border-radius: 6px;
                padding: 4px;
                font-size: 11px;
            }
            QListWidget::item {
                padding: 8px;
                border-radius: 4px;
            }
            QListWidget::item:selected {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #8df2c9, stop:1 #7fdcb7);
                color: white;
            }
            QPushButton {
                font-size: 13px;
                font-weight: 600;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #8df2c9, stop:1 #7fdcb7);
                color: white;
                border: 2px solid #6fcaa6;
                border-radius: 6px;
                padding: 8px 12px;
                min-height: 32px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #7fdcb7, stop:1 #6fcaa6);
            }
            QPushButton:pressed {
                background: #5cb892;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
                border: 2px solid #aaa;
            }
        """)

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
        pwd_dlg.setFixedSize(780, 460)  # Fit within 7-inch screen

        # Apply same styling to password dialog
        pwd_dlg.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #fafbfa, stop:1 #f0fdf9);
            }
            QLabel {
                font-size: 16px;
                font-weight: 600;
                color: #1a1a1a;
            }
            QLineEdit {
                padding: 12px;
                font-size: 16px;
                background: white;
                border: 2px solid #cdeee0;
                border-radius: 8px;
                min-height: 50px;
            }
            QLineEdit:focus {
                border: 2px solid #6fcaa6;
            }
            QPushButton {
                font-size: 16px;
                font-weight: 600;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #8df2c9, stop:1 #7fdcb7);
                color: white;
                border: 2px solid #6fcaa6;
                border-radius: 8px;
                padding: 10px 20px;
                min-height: 40px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #7fdcb7, stop:1 #6fcaa6);
            }
            QPushButton:pressed {
                background: #5cb892;
            }
        """)

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
        # Apply login page keyboard styling (smaller for 7" screen)
        kb.setStyleSheet("""
            #OnScreenKeyboard {
                background: transparent;
                padding: 4px;
            }
            #OnScreenKeyboard QPushButton {
                min-width: 28px;
                min-height: 32px;
                font-size: 12px;
                font-weight: 600;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #8df2c9, stop:1 #7fdcb7);
                color: white;
                border: 2px solid #6fcaa6;
                border-radius: 6px;
            }
            #OnScreenKeyboard QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #7fdcb7, stop:1 #6fcaa6);
            }
            #OnScreenKeyboard QPushButton:pressed {
                background: #5cb892;
            }
            #OnScreenKeyboard QPushButton[wide="true"] {
                min-width: 80px;
                font-size: 13px;
                font-weight: 700;
            }
        """)
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


class LoginPage(QWidget):
    """Integrated login page with username/password authentication."""

    login_successful = pyqtSignal()  # Signal emitted on successful login

    def __init__(self, api_client, parent=None):
        super().__init__(parent)
        self.api_client = api_client

        # Main layout with centering
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Title and WiFi button row
        title_row = QHBoxLayout()

        title = QLabel("Picnic Groups")
        title.setStyleSheet("font-size: 20px; font-weight: 700; padding: 8px 10px 8px 10px; color: #2ecc94;")  # Reduced from 36px and padding
        title.setAlignment(Qt.AlignCenter)

        # WiFi button
        self.wifi_btn = QPushButton("WiFi")
        self.wifi_btn.setFixedSize(80, 32)  # Reduced from 150x50
        self.wifi_btn.setStyleSheet("""
            QPushButton {
                font-size: 11px;
                font-weight: 600;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #8df2c9, stop:1 #7fdcb7);
                color: white;
                border: 2px solid #6fcaa6;
                border-radius: 6px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #7fdcb7, stop:1 #6fcaa6);
            }
            QPushButton:pressed {
                background: #5cb892;
            }
        """)
        self.wifi_btn.clicked.connect(self.open_wifi)

        title_row.addStretch()
        title_row.addWidget(title)
        title_row.addStretch()
        title_row.addWidget(self.wifi_btn)
        title_row.setContentsMargins(0, 5, 10, 0)  # Reduced margins

        # Create a centered container for login form
        container = QWidget()
        container.setMaximumWidth(400)  # Reduced from 600
        container.setStyleSheet("""
            QWidget {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #f0fdf9, stop:1 #e8f5ef);
                border: 2px solid #cdeee0;
                border-radius: 8px;
            }
        """)

        v = QVBoxLayout(container)
        v.setSpacing(8)  # Reduced from 20
        v.setContentsMargins(16, 12, 16, 12)  # Reduced from 40

        subtitle = QLabel("Please log in")
        subtitle.setStyleSheet("font-size: 12px; color: #555; padding-bottom: 4px;")  # Reduced font and padding
        subtitle.setAlignment(Qt.AlignCenter)
        v.addWidget(subtitle)

        # On-screen keyboard (create before inputs)
        self.keyboard = OnScreenKeyboard(self)
        # Keep keyboard always visible on login page for easy access
        self.keyboard.setVisible(True)
        # Style keyboard buttons to match login button (smaller for 7" screen)
        self.keyboard.setStyleSheet("""
            #OnScreenKeyboard {
                background: transparent;
                padding: 4px;
            }
            #OnScreenKeyboard QPushButton {
                min-width: 28px;
                min-height: 32px;
                font-size: 12px;
                font-weight: 600;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #8df2c9, stop:1 #7fdcb7);
                color: white;
                border: 2px solid #6fcaa6;
                border-radius: 6px;
            }
            #OnScreenKeyboard QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #7fdcb7, stop:1 #6fcaa6);
            }
            #OnScreenKeyboard QPushButton:pressed {
                background: #5cb892;
            }
            #OnScreenKeyboard QPushButton[wide="true"] {
                min-width: 80px;
                font-size: 13px;
                font-weight: 700;
            }
        """)

        # Hide the "Hide" button on login page since keyboard should always be visible
        for i in range(self.keyboard.layout().count()):
            layout_item = self.keyboard.layout().itemAt(i)
            if layout_item and layout_item.layout():
                for j in range(layout_item.layout().count()):
                    widget = layout_item.layout().itemAt(j).widget()
                    if widget and isinstance(widget, QPushButton) and widget.text() == "Hide":
                        widget.setVisible(False)
                        break

        # Form
        form = QFormLayout()
        form.setSpacing(6)  # Reduced from 16
        form.setLabelAlignment(Qt.AlignRight)

        email_label = QLabel("Email:")
        email_label.setStyleSheet("font-size: 11px; font-weight: 600; color: #1a1a1a;")  # Reduced font

        self.username_input = KeyboardLineEdit(self.keyboard)
        self.username_input.setPlaceholderText("Email")
        self.username_input.setMinimumHeight(32)  # Reduced from 50
        self.username_input.setStyleSheet("""
            font-size: 12px;
            padding: 6px;
            border: 2px solid #cdeee0;
            border-radius: 6px;
            background-color: white;
        """)

        password_label = QLabel("Password:")
        password_label.setStyleSheet("font-size: 11px; font-weight: 600; color: #1a1a1a;")  # Reduced font

        self.password_input = KeyboardLineEdit(self.keyboard)
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setMinimumHeight(32)  # Reduced from 50
        self.password_input.setStyleSheet("""
            font-size: 12px;
            padding: 6px;
            border: 2px solid #cdeee0;
            border-radius: 6px;
            background-color: white;
        """)
        self.password_input.returnPressed.connect(self.validate_login)

        form.addRow(email_label, self.username_input)
        form.addRow(password_label, self.password_input)
        v.addLayout(form)

        # Error message label
        self.error_label = QLabel("")
        self.error_label.setStyleSheet("""
            color: #e74c3c;
            font-weight: 600;
            font-size: 10px;
            padding: 6px;
            background-color: #fee;
            border-radius: 4px;
        """)
        self.error_label.setAlignment(Qt.AlignCenter)
        self.error_label.setVisible(False)
        self.error_label.setWordWrap(True)
        v.addWidget(self.error_label)

        # Login button
        self.login_btn = QPushButton("Login")
        self.login_btn.setMinimumHeight(36)  # Reduced from 56
        self.login_btn.setStyleSheet("""
            QPushButton {
                font-size: 14px;
                font-weight: 600;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #8df2c9, stop:1 #7fdcb7);
                color: white;
                border: 2px solid #6fcaa6;
                border-radius: 8px;
                padding: 8px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #7fdcb7, stop:1 #6fcaa6);
            }
            QPushButton:pressed {
                background: #5cb892;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
                border: 2px solid #aaa;
            }
        """)
        self.login_btn.clicked.connect(self.validate_login)
        v.addWidget(self.login_btn)

        # Center the container
        h_layout = QHBoxLayout()
        h_layout.addStretch()
        h_layout.addWidget(container)
        h_layout.addStretch()

        v_outer = QVBoxLayout()
        v_outer.addLayout(title_row)  # Add title and WiFi button row
        v_outer.addSpacing(3)  # Minimal spacing
        v_outer.addLayout(h_layout)
        v_outer.addSpacing(3)  # Minimal spacing between login form and keyboard

        main_layout.addLayout(v_outer)

        # Add keyboard widget OUTSIDE the centered container so it spans full width
        main_layout.addWidget(self.keyboard)

        # Set background to match app theme
        self.setStyleSheet("background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #fafbfa, stop:1 #f0fdf9);")

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
            self.login_successful.emit()
            return

        # Disable login button while processing
        self.login_btn.setEnabled(False)
        self.login_btn.setText("Logging in...")

        try:
            # Attempt API login
            self.api_client.login(email, password)
            # Success - emit signal
            self.login_successful.emit()

        except AuthenticationError as e:
            self.failed_attempts += 1
            remaining = self.max_attempts - self.failed_attempts

            if self.failed_attempts >= self.max_attempts:
                self.show_error("Too many failed attempts. Access denied.")
                QTimer.singleShot(2000, lambda: QApplication.instance().quit())
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

    def open_wifi(self):
        """Open WiFi settings dialog."""
        from PyQt5.QtWidgets import QDialog
        # Get the main window (parent's parent)
        main_window = self.parent()
        if main_window and hasattr(main_window, 'open_wifi_dialog'):
            main_window.open_wifi_dialog()
        else:
            # Fallback: create dialog directly
            dlg = WifiDialog(self)
            dlg.exec_()


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
        """Load groups from the API using background worker for better performance."""
        from api_client import TokenExpiredError, NetworkError, PicnicAPIError

        self.status_label.setText("Loading groups...")
        self.status_label.setStyleSheet("color: #3498db;")
        self.btn_refresh.setEnabled(False)

        # Use QThread to avoid blocking UI
        class GroupsLoader(QThread):
            finished_signal = pyqtSignal(list, str)  # (groups, error_message)

            def __init__(self, api_client):
                super().__init__()
                self.api_client = api_client

            def run(self):
                try:
                    # Get groups list
                    groups = self.api_client.get_my_groups()

                    if not groups:
                        self.finished_signal.emit([], "")
                        return

                    # Process groups and fetch details if frequency is missing
                    processed_groups = []
                    for group in groups:
                        group_id = (
                            group.get("id") or
                            group.get("_id") or
                            group.get("group_id") or
                            group.get("event_id")
                        )

                        if not group_id:
                            logger.warning(f"Group has no ID, skipping")
                            continue

                        # Check if group already has radio_frequency
                        if "radio_frequency" not in group or group.get("radio_frequency") is None:
                            # Fetch full group details to get radio_frequency
                            try:
                                logger.debug(f"Fetching details for group {group_id} (missing frequency)")
                                full_group = self.api_client.get_group_detail(group_id)
                                if full_group and "radio_frequency" in full_group:
                                    # Merge frequency into group data
                                    group["radio_frequency"] = full_group["radio_frequency"]
                                    logger.debug(f"Got frequency: {full_group['radio_frequency']}")
                            except Exception as e:
                                logger.warning(f"Failed to fetch details for group {group_id}: {e}")
                                # Continue with group even without frequency

                        processed_groups.append(group)

                    self.finished_signal.emit(processed_groups, "")

                except TokenExpiredError as e:
                    self.finished_signal.emit([], f"session_expired:{str(e)}")
                except NetworkError as e:
                    self.finished_signal.emit([], f"network_error:{str(e)}")
                except Exception as e:
                    self.finished_signal.emit([], f"error:{str(e)}")

        def on_groups_loaded(groups, error_msg):
            """Handle groups loaded from background thread."""
            try:
                if error_msg:
                    if error_msg.startswith("session_expired:"):
                        msg = error_msg.replace("session_expired:", "")
                        self.status_label.setText(f"Session expired: {msg}")
                        self.status_label.setStyleSheet("color: #e74c3c;")
                        QMessageBox.warning(self, "Session Expired", "Your session has expired. Please login again.")
                    elif error_msg.startswith("network_error:"):
                        msg = error_msg.replace("network_error:", "")
                        self.status_label.setText(f"Network error: {msg}")
                        self.status_label.setStyleSheet("color: #e74c3c;")
                    else:
                        msg = error_msg.replace("error:", "")
                        self.status_label.setText(f"Error: {msg}")
                        self.status_label.setStyleSheet("color: #e74c3c;")
                    return

                if not groups:
                    self.status_label.setText("No groups found.")
                    self.status_label.setStyleSheet("color: #95a5a6;")
                    return

                # Clear and populate list (fast UI operations)
                self.groups_list.clear()
                self._groups_data = []

                # Batch UI updates for better performance
                self.groups_list.setUpdatesEnabled(False)
                try:
                    for group in groups:
                        self._groups_data.append(group)

                        # Display group name or ID
                        group_name = group.get("name", group.get("id", "Unknown Group"))

                        # Get frequency from group data
                        frequency = group.get("radio_frequency")

                        # Format display text with frequency if available
                        if frequency:
                            try:
                                freq_float = float(frequency)
                                display_text = f"{group_name}  •  {freq_float:.1f} MHz"
                            except (ValueError, TypeError):
                                display_text = f"{group_name}  •  {frequency} MHz"
                        else:
                            display_text = f"{group_name}  •  No frequency"

                        item = QListWidgetItem(display_text)
                        item.setData(Qt.UserRole, group)
                        self.groups_list.addItem(item)
                finally:
                    self.groups_list.setUpdatesEnabled(True)

                self.status_label.setText(f"Loaded {len(self._groups_data)} group(s) successfully.")
                self.status_label.setStyleSheet("color: #2ecc94;")

            finally:
                self.btn_refresh.setEnabled(True)
                # Clean up worker
                if hasattr(self, '_groups_worker'):
                    self._groups_worker.deleteLater()

        # Start background loading
        self._groups_worker = GroupsLoader(self.api_client)
        self._groups_worker.finished_signal.connect(on_groups_loaded)
        self._groups_worker.start()

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
            parent_window._goto(2)  # Navigate to messages page (index 2 now)

    def _start_group_silence_carrier(self, frequency: float, parent_window):
        """Start silence carrier when a group is selected (non-blocking)."""
        # Use QTimer to defer heavy work, keeping UI responsive
        def start_carrier_async():
            try:
                if not hasattr(parent_window, '_start_silence_carrier'):
                    logger.warning("Parent window does not have _start_silence_carrier method")
                    return

                # Kill all existing pifm processes first
                logger.info("Cleaning up pifm processes before starting group silence carrier...")
                kill_all_pifm_processes()

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
                logger.info(f"Updated BROADCAST_CMD to frequency {frequency:.1f} MHz")

                # Update env_vars dict for immediate use
                env_vars["BROADCAST_CMD"] = new_broadcast_cmd

                # Start silence carrier on group's frequency
                logger.info(f"Starting silence carrier for group on {frequency:.1f} MHz")
                parent_window._start_silence_carrier(frequency, env_vars)

                # Update status
                self.status_label.setText(f"✓ Broadcasting silence carrier on {frequency:.1f} MHz")
                self.status_label.setStyleSheet("color: #2ecc94;")

            except Exception as e:
                logger.error(f"Failed to start group silence carrier: {e}")
                self.status_label.setText(f"Warning: Could not start silence carrier - {e}")
                self.status_label.setStyleSheet("color: #ff9800;")

        # Defer to next event loop iteration for better responsiveness
        QTimer.singleShot(0, start_carrier_async)

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
        self._stop_requested = False  # Flag to interrupt loop

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

        # Store loop count (will be set via popup)
        self.loop_count = 1

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

        self.btn_stop = QPushButton("⏹ Stop Broadcasting")
        self.btn_stop.setMinimumHeight(60)
        self.btn_stop.setStyleSheet("""
            QPushButton {
                font-size: 18px;
                font-weight: 600;
                background-color: #FF9800;
                color: white;
                border-radius: 8px;
                padding: 12px 24px;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
            QPushButton:pressed {
                background-color: #E65100;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        self.btn_stop.clicked.connect(self.stop_broadcasting)
        self.btn_stop.setEnabled(False)
        self.btn_stop.setVisible(False)  # Hidden until broadcasting starts

        self.btn_loop_settings = QPushButton("⚙ Loop Settings")
        self.btn_loop_settings.setMinimumHeight(60)
        self.btn_loop_settings.setStyleSheet("""
            QPushButton {
                font-size: 18px;
                font-weight: 600;
                background-color: #9C27B0;
                color: white;
                border-radius: 8px;
                padding: 12px 24px;
            }
            QPushButton:hover {
                background-color: #7B1FA2;
            }
            QPushButton:pressed {
                background-color: #6A1B9A;
            }
        """)
        self.btn_loop_settings.clicked.connect(self.open_loop_settings)

        btn_layout.addWidget(self.btn_back)
        btn_layout.addWidget(self.btn_refresh)
        btn_layout.addWidget(self.btn_loop_settings)
        btn_layout.addWidget(self.btn_broadcast, 1)
        btn_layout.addWidget(self.btn_stop, 1)
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
        """Refresh messages from the API using background thread."""
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

        self.status_label.setText(f"Loading messages...")
        self.status_label.setStyleSheet("font-size: 16px; padding: 8px; color: #3498db;")
        self.btn_refresh.setEnabled(False)

        # Use QThread for non-blocking message loading
        class MessagesLoader(QThread):
            finished_signal = pyqtSignal(list, str)  # (messages, error_message)

            def __init__(self, broadcaster, group_id):
                super().__init__()
                self.broadcaster = broadcaster
                self.group_id = group_id

            def run(self):
                try:
                    logger.debug(f"Fetching messages for group {self.group_id}")
                    messages = self.broadcaster.get_group_messages(self.group_id, limit=50)
                    self.finished_signal.emit(messages, "")
                except MessageFetchError as e:
                    self.finished_signal.emit([], f"fetch_error:{str(e)}")
                except Exception as e:
                    self.finished_signal.emit([], f"error:{str(e)}")

        def on_messages_loaded(messages, error_msg):
            """Handle messages loaded from background thread."""
            try:
                if error_msg:
                    if error_msg.startswith("fetch_error:"):
                        msg = error_msg.replace("fetch_error:", "")
                        self.status_label.setText(f"Error: {msg}")
                        self.status_label.setStyleSheet("font-size: 16px; padding: 8px; color: #e74c3c;")
                        QMessageBox.critical(self, "Failed to Load Messages", f"Could not load messages.\n\n{msg}")
                    else:
                        msg = error_msg.replace("error:", "")
                        self.status_label.setText(f"Unexpected error: {msg}")
                        self.status_label.setStyleSheet("font-size: 16px; padding: 8px; color: #e74c3c;")
                        QMessageBox.critical(self, "Error", f"Unexpected error loading messages.\n\n{msg}")
                    return

                self.messages_data = messages

                if not messages:
                    self.status_label.setText("No text messages found in this group")
                    self.status_label.setStyleSheet("font-size: 16px; padding: 8px; color: #95a5a6;")
                    self.messages_list.clear()
                    return

                # Batch UI updates for performance
                self.messages_list.setUpdatesEnabled(False)
                try:
                    self.messages_list.clear()

                    # Add messages to list
                    for msg in messages:
                        formatted = self.broadcaster.format_message_for_display(msg)
                        display_text = formatted["display_text"]

                        item = QListWidgetItem(display_text)
                        item.setData(Qt.UserRole, msg)
                        self.messages_list.addItem(item)
                finally:
                    self.messages_list.setUpdatesEnabled(True)

                self.status_label.setText(f"✓ Loaded {len(messages)} message(s) successfully")
                self.status_label.setStyleSheet("font-size: 16px; padding: 8px; color: #2ecc94;")
                logger.debug(f"Successfully displayed {len(messages)} messages")

            finally:
                self.btn_refresh.setEnabled(True)
                # Clean up worker
                if hasattr(self, '_messages_worker'):
                    self._messages_worker.deleteLater()

        # Start background loading
        self._messages_worker = MessagesLoader(self.broadcaster, self.current_group_id)
        self._messages_worker.finished_signal.connect(on_messages_loaded)
        self._messages_worker.start()

    def open_loop_settings(self):
        """Open a dialog to configure loop settings."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Loop Settings")
        dialog.setFixedSize(400, 200)
        dialog.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #fafbfa, stop:1 #f0fdf9);
            }
            QLabel {
                font-size: 14px;
                font-weight: 600;
                color: #1a1a1a;
            }
            QSpinBox {
                font-size: 16px;
                font-weight: 600;
                padding: 8px;
                border: 2px solid #cdeee0;
                border-radius: 6px;
                min-height: 40px;
            }
            QPushButton {
                font-size: 14px;
                font-weight: 600;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #8df2c9, stop:1 #7fdcb7);
                color: white;
                border: 2px solid #6fcaa6;
                border-radius: 8px;
                padding: 10px 20px;
                min-height: 40px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #7fdcb7, stop:1 #6fcaa6);
            }
            QPushButton:pressed {
                background: #5cb892;
            }
        """)

        layout = QVBoxLayout(dialog)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)

        # Title
        title = QLabel("Configure Loop Count")
        title.setStyleSheet("font-size: 18px; font-weight: 700; color: #2ecc94;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # Loop count input
        form = QHBoxLayout()
        label = QLabel("Loop Count:")
        spinbox = QSpinBox()
        spinbox.setRange(1, 10)
        spinbox.setValue(self.loop_count)
        spinbox.setMinimumWidth(120)

        info = QLabel("(1-10 times)")
        info.setStyleSheet("font-size: 12px; color: #666;")

        form.addWidget(label)
        form.addWidget(spinbox)
        form.addWidget(info)
        form.addStretch()
        layout.addLayout(form)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)

        if dialog.exec_() == QDialog.Accepted:
            self.loop_count = spinbox.value()
            logger.info(f"Loop count set to {self.loop_count}")

    def broadcast_selected(self):
        """Broadcast selected messages via TTS with loop support."""
        from message_broadcaster import TTSBroadcastError

        selected_items = self.messages_list.selectedItems()

        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select at least one message to broadcast.")
            return

        if not self.broadcaster:
            QMessageBox.critical(self, "Error", "Broadcaster not initialized. Please try again.")
            return

        # Validate broadcaster has required method
        if not hasattr(self.broadcaster, 'broadcast_message') or not callable(getattr(self.broadcaster, 'broadcast_message')):
            QMessageBox.critical(self, "Error", "Broadcaster is not properly configured.")
            logger.error("Broadcaster missing broadcast_message method")
            return

        # Get loop count from stored value
        loop_count = self.loop_count
        total_messages = len(selected_items) * loop_count

        # Kill all pifm processes BEFORE broadcasting to free /dev/mem
        logger.info("Cleaning up pifm processes before message broadcast...")
        kill_all_pifm_processes()

        # Reset stop flag
        self._stop_requested = False

        # Disable buttons during broadcast, enable stop button
        self.btn_broadcast.setEnabled(False)
        self.btn_refresh.setEnabled(False)
        self.btn_back.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_stop.setVisible(True)
        self.btn_loop_settings.setEnabled(False)

        self.status_label.setText(f"Broadcasting {len(selected_items)} message(s) × {loop_count} loop(s) = {total_messages} total...")
        self.status_label.setStyleSheet("font-size: 16px; padding: 8px; color: #ff9800;")
        QApplication.processEvents()

        success_count = 0
        error_count = 0
        broadcast_number = 0

        # Loop through messages the specified number of times
        for loop_iteration in range(loop_count):
            # Check if stop was requested
            if self._stop_requested:
                logger.info(f"Broadcasting stopped by user at loop {loop_iteration + 1}/{loop_count}")
                self.status_label.setText(f"⏹ Broadcasting stopped: {success_count} succeeded, {error_count} failed")
                self.status_label.setStyleSheet("font-size: 16px; padding: 8px; color: #ff9800; font-weight: 600;")
                break

            for i, item in enumerate(selected_items):
                # Check if stop was requested before each message
                if self._stop_requested:
                    logger.info(f"Broadcasting stopped by user at message {i+1}/{len(selected_items)} in loop {loop_iteration + 1}")
                    self.status_label.setText(f"⏹ Broadcasting stopped: {success_count} succeeded, {error_count} failed")
                    self.status_label.setStyleSheet("font-size: 16px; padding: 8px; color: #ff9800; font-weight: 600;")
                    break

                broadcast_number += 1
                msg = item.data(Qt.UserRole)
                formatted = self.broadcaster.format_message_for_display(msg)

                # Update status with current progress
                self.status_label.setText(
                    f"Broadcasting {broadcast_number}/{total_messages}: Loop {loop_iteration + 1}/{loop_count}, "
                    f"Message {i + 1}/{len(selected_items)}"
                )
                QApplication.processEvents()

                try:
                    # Kill all pifm processes before EACH message to ensure /dev/mem is free
                    logger.info(f"Broadcasting message {broadcast_number}/{total_messages} (Loop {loop_iteration + 1}/{loop_count}, Message {i+1}/{len(selected_items)})...")
                    if broadcast_number > 1:
                        # For messages after the first, kill any leftover processes
                        logger.info("Ensuring /dev/mem is free before next broadcast...")
                        kill_all_pifm_processes()

                    # Broadcast the message (this waits for completion)
                    self.broadcaster.broadcast_message(
                        formatted["message_text"],
                        formatted["user_name"],
                        self.current_frequency
                    )

                    logger.info(f"Message {broadcast_number}/{total_messages} broadcast successfully")

                    # Visual feedback - green highlight (only on first loop)
                    if loop_iteration == 0:
                        item.setBackground(Qt.green)
                        item.setForeground(Qt.darkGreen)
                    success_count += 1

                except subprocess.TimeoutExpired:
                    # Process was killed (user clicked stop)
                    logger.info("Broadcast process was terminated")
                    if loop_iteration == 0:
                        item.setBackground(Qt.yellow)
                        item.setForeground(Qt.black)
                    # Break out of loop immediately
                    self._stop_requested = True
                    break

                except TTSBroadcastError as e:
                    # Check if this was due to process being killed
                    if self._stop_requested:
                        logger.info("Broadcast interrupted by user")
                        break
                    # Visual feedback - red highlight (only on first loop)
                    if loop_iteration == 0:
                        item.setBackground(Qt.red)
                        item.setForeground(Qt.white)
                    error_count += 1
                    logger.error(f"Failed to broadcast message {broadcast_number}/{total_messages}: {e}")

                except Exception as e:
                    # Check if this was due to process being killed
                    if self._stop_requested:
                        logger.info("Broadcast interrupted by user")
                        break
                    if loop_iteration == 0:
                        item.setBackground(Qt.red)
                        item.setForeground(Qt.white)
                    error_count += 1
                    logger.error(f"Unexpected error broadcasting message {broadcast_number}/{total_messages}: {e}")

                QApplication.processEvents()

            # If stopped, break outer loop
            if self._stop_requested:
                break

        # Update status (no popup dialogs)
        if not self._stop_requested:
            if error_count == 0:
                self.status_label.setText(f"✓ Successfully broadcast {success_count} message(s) ({loop_count} loop(s))")
                self.status_label.setStyleSheet("font-size: 16px; padding: 8px; color: #2ecc94; font-weight: 600;")
            else:
                self.status_label.setText(
                    f"Broadcast complete: {success_count} succeeded, {error_count} failed ({loop_count} loop(s))"
                )
                self.status_label.setStyleSheet("font-size: 16px; padding: 8px; color: #ff9800; font-weight: 600;")

        # Automatically kill all pifm processes after broadcast
        logger.info("Automatically killing all pifm processes after broadcast...")
        kill_all_pifm_processes()

        # Restart silence carrier after broadcast to prevent static
        if success_count > 0:
            self._restart_silence_carrier()

        # Re-enable buttons, hide stop button
        self.btn_broadcast.setEnabled(True)
        self.btn_refresh.setEnabled(True)
        self.btn_back.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_stop.setVisible(False)
        self.btn_loop_settings.setEnabled(True)

    def stop_broadcasting(self):
        """Stop the current broadcast immediately by killing the process."""
        self._stop_requested = True
        self.btn_stop.setEnabled(False)
        self.status_label.setText("⏹ Stopping broadcast immediately...")
        self.status_label.setStyleSheet("font-size: 16px; padding: 8px; color: #ff9800;")
        logger.info("User requested immediate stop - killing broadcast process")

        # Immediately kill the current broadcast process
        if self.broadcaster:
            try:
                self.broadcaster.stop_broadcast()
                logger.info("Broadcast stopped successfully")
            except Exception as e:
                logger.error(f"Error stopping broadcast: {e}")

        # Also kill all pifm processes as a failsafe
        kill_all_pifm_processes()

    def _on_selection_changed(self):
        """Handle selection change in messages list."""
        has_selection = len(self.messages_list.selectedItems()) > 0
        self.btn_broadcast.setEnabled(has_selection)

    def _restart_silence_carrier(self):
        """Restart silence carrier after message broadcast."""
        try:
            # Get parent window (MainWindow)
            parent_window = self.window()
            if not hasattr(parent_window, '_start_silence_carrier'):
                logger.warning("Parent window does not have _start_silence_carrier method")
                return

            # Kill all existing pifm processes first (handled by _start_silence_carrier)
            # No need to call here since _start_silence_carrier does it

            # Get environment variables
            env_vars = load_env_file(ENV_PATH)

            # Restart silence carrier on current frequency
            logger.info(f"Restarting silence carrier on {self.current_frequency:.1f} MHz")
            parent_window._start_silence_carrier(self.current_frequency, env_vars)

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
            parent_window._goto(1)  # Go to Groups page (index 1 now)


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

        # Set fixed size for 7-inch LCD touchscreen (800x480)
        self.setFixedSize(800, 480)
        # Show window normally with title bar (for debugging)
        # Can switch to self.showFullScreen() for production if needed

        # Settings
        self.settings = QSettings(APP_ORG, APP_NAME)

        # Root layout
        central = QWidget()
        root = QHBoxLayout(central)
        self.setCentralWidget(central)

        # Sidebar
        side = QVBoxLayout()
        self.btn_groups = QPushButton("Groups")
        self.btn_wifi = QPushButton("WiFi")
        self.btn_groups.setCheckable(True)
        self.btn_groups.setChecked(True)

        side.addWidget(self.btn_groups)
        side.addWidget(self.btn_wifi)
        side.addStretch(1)

        # Logout button at bottom
        self.btn_logout = QPushButton("Logout")
        self.btn_logout.setObjectName("logout")
        side.addWidget(self.btn_logout)

        side_wrap = QWidget()
        side_wrap.setLayout(side)
        side_wrap.setFixedWidth(120)  # Reduced from 200 for smaller screen
        side_wrap.setObjectName("Sidebar")
        side_wrap.setStyleSheet(
            "#Sidebar {\n"
            "    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #f0fdf9, stop:1 #e8f5ef);\n"
            "    border-right: 2px solid #cdeee0;\n"
            "    padding: 8px 6px;\n"  # Reduced padding
            "}\n"
            "#Sidebar QPushButton {\n"
            "    text-align: center;\n"  # Center text for smaller buttons
            "    padding: 10px 8px;\n"  # Reduced padding
            "    min-height: 36px;\n"  # Reduced from 52px
            "    font-size: 13px;\n"  # Reduced from 16px
            "    font-weight: 600;\n"
            "    border-radius: 8px;\n"  # Reduced from 12px
            "    background: transparent;\n"
            "    color: #1a1a1a;\n"
            "    border: 2px solid transparent;\n"
            "    margin: 3px 0px;\n"  # Reduced margin
            "}\n"
            "#Sidebar QPushButton:hover {\n"
            "    background: #ffffff;\n"
            "    border: 2px solid #cdeee0;\n"
            "}\n"
            "#Sidebar QPushButton:checked {\n"
            "    font-weight: 700;\n"
            "    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #8df2c9, stop:1 #7fdcb7);\n"
            "    color: #ffffff;\n"
            "    border: 2px solid #6fcaa6;\n"
            "}\n"
            "#Sidebar QPushButton:pressed {\n"
            "    background: #cdeee0;\n"
            "}"
        )

        # Store sidebar reference for showing/hiding
        self.side_wrap = side_wrap

        # Pages
        self.pages = QStackedWidget()
        self.page_login = LoginPage(api_client)
        self.page_groups = GroupsPage(api_client)
        self.page_messages = MessageListScreen(api_client)

        self.pages.addWidget(self.page_login)      # Index 0 (Login)
        self.pages.addWidget(self.page_groups)     # Index 1 (Groups)
        self.pages.addWidget(self.page_messages)   # Index 2 (Messages)

        # Compose
        root.addWidget(side_wrap)
        content = QVBoxLayout()
        content.setContentsMargins(8, 8, 8, 8)  # Reduced from 24 for smaller screen
        content.setSpacing(8)  # Reduced from 16
        content_wrap = QWidget()
        content_wrap.setLayout(content)
        content_wrap.setObjectName("ContentArea")
        content_wrap.setStyleSheet(
            "#ContentArea { background: #fafbfa; }"
        )
        content.addWidget(self.pages, 1)
        root.addWidget(content_wrap, 1)

        # Connect signals
        self.btn_groups.clicked.connect(lambda: self._goto(1))  # Groups is now index 1
        self.btn_wifi.clicked.connect(self.open_wifi_dialog)
        self.btn_logout.clicked.connect(self.handle_logout)
        self.page_login.login_successful.connect(self.on_login_success)

        # System tray
        self._setup_tray()

        # Check WiFi connection FIRST before showing login/main app
        QTimer.singleShot(100, self._check_wifi_and_show_appropriate_page)

    # ---------- Login/Logout Management ----------

    def _show_login_page(self):
        """Show login page and hide sidebar."""
        self.pages.setCurrentIndex(0)  # Login page
        self.side_wrap.setVisible(False)
        logger.info("Showing login page")

    def _show_main_app(self):
        """Show main app with sidebar."""
        self.side_wrap.setVisible(True)
        self._goto(1)  # Go to groups page
        logger.info("Showing main app")

    def on_login_success(self):
        """Handle successful login."""
        logger.info("Login successful, switching to main app")
        self._show_main_app()

        # Check WiFi after login
        QTimer.singleShot(500, self._check_wifi_on_startup)

    # ---------- WiFi Connection Check ----------

    def _check_wifi_and_show_appropriate_page(self):
        """Check WiFi first, then show login or main app."""
        # Check WiFi connection - if not connected, automatically open WiFi dialog
        if not self._is_wifi_connected():
            logger.warning("No WiFi connection detected on startup - opening WiFi settings")
            # Show a message and open WiFi dialog
            QMessageBox.warning(
                self,
                "WiFi Not Connected",
                "No active WiFi connection detected.\n\n"
                "WiFi settings will open automatically.",
                QMessageBox.Ok
            )
            self.open_wifi_dialog()

        # After WiFi check (or if already connected), show appropriate page
        if not self.api_client.is_authenticated():
            self._show_login_page()
        else:
            self._show_main_app()

    def _check_wifi_on_startup(self):
        """Check WiFi connection status on startup and prompt if not connected."""
        if not self._is_wifi_connected():
            logger.warning("WiFi not connected")
            QMessageBox.warning(
                self,
                "WiFi Not Connected",
                "No active WiFi connection detected.\n\n"
                "Please configure WiFi for full functionality.",
                QMessageBox.Ok
            )

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

        logger.info(f"Frequency set to {freq:.1f} MHz")
        logger.info(f"BROADCAST_CMD updated: {new_cmd}")

        # Signal running service or start it
        running = self.proc and self.proc.state() != QProcess.NotRunning

        if running:
            pid = int(self.proc.processId())

            # CRITICAL: Validate PID before sending signals
            if pid <= 0:
                logger.error(f"Invalid process ID: {pid}, restarting service")
                self._start_broadcaster_with_env(env_vars, fresh=True)
            else:
                try:
                    if immediate:
                        os.kill(pid, signal.SIGUSR2)
                        logger.info(f"Sent SIGUSR2 to PID {pid} (immediate switch)")
                    else:
                        os.kill(pid, signal.SIGHUP)
                        logger.info(f"Sent SIGHUP to PID {pid} (reload after current message)")
                except ProcessLookupError:
                    logger.info(f"Process {pid} not found, restarting service...")
                    self._start_broadcaster_with_env(env_vars, fresh=True)
                except PermissionError as e:
                    logger.error(f"Permission error sending signal to PID {pid}: {e}")
                    QMessageBox.critical(self, "Permission Error", f"Cannot signal process (need sudo?): {e}")
                except OSError as e:
                    logger.error(f"OS error sending signal to PID {pid}: {e}")
                    self._start_broadcaster_with_env(env_vars, fresh=True)
        else:
            logger.info("Service not running, starting...")
            self._start_broadcaster_with_env(env_vars, fresh=True)

        # Start silence carrier to prevent static
        self._start_silence_carrier(freq, env_vars)

        QMessageBox.information(
            self,
            "Frequency Updated",
            f"Broadcasting frequency {'switched to' if immediate else 'will switch to'} {freq:.1f} MHz"
        )

    def _start_silence_carrier(self, freq: float, env_vars: dict):
        """Start broadcasting silence carrier to prevent static."""
        import wave

        # Kill all existing pifm processes before starting silence carrier
        logger.info("Cleaning up existing pifm processes...")
        kill_all_pifm_processes()

        # Ensure WAV directory exists
        wav_dir = "/home/rpibroadcaster/wav"
        if not os.path.exists(wav_dir):
            os.makedirs(wav_dir, exist_ok=True)

        # Create or verify silence WAV file
        silence_file = os.path.join(wav_dir, "silence_carrier.wav")

        try:
            # Create silence WAV if it doesn't exist (1800 seconds = 30 minutes)
            if not os.path.exists(silence_file):
                logger.info(f"Creating silence carrier file: {silence_file}")
                with wave.open(silence_file, "wb") as wav:
                    wav.setnchannels(1)  # Mono
                    wav.setsampwidth(2)  # 16-bit
                    wav.setframerate(16000)  # 16kHz

                    # Write 30 minutes of silence (all zeros)
                    silence_secs = 1800
                    silence_data = b"\x00\x00" * 16000 * silence_secs
                    wav.writeframes(silence_data)

                logger.info("Silence carrier file created successfully")

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

            logger.info(f"Starting silence carrier on {freq:.1f} MHz...")
            logger.info(f"Command: {' '.join(cmd_args)}")

            # Start silence carrier in background without shell=True
            # Note: We don't track this process intentionally - it should run until killed
            subprocess.Popen(
                cmd_args,
                shell=False,  # CRITICAL: Prevent command injection
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL
            )

            logger.info("Silence carrier started successfully")

        except Exception as e:
            logger.warning(f"Warning: Could not start silence carrier: {e}")
            logger.warning(f"Failed to start silence carrier: {e}")

    def _start_broadcaster_with_env(self, env_vars: dict, fresh: bool = False):
        """Start the broadcaster service with given environment."""
        if fresh:
            self._stop_script()

        # Determine Python executable
        py = PYTHON_BIN if os.path.isfile(PYTHON_BIN) else sys.executable

        # Check if service executable exists
        if not os.path.exists(SERVICE_PATH):
            logger.error(f"Service not found at {SERVICE_PATH}")
            QMessageBox.critical(
                self,
                "Service Not Found",
                f"Cannot find broadcaster service at:\n{SERVICE_PATH}\n\n"
                f"Please ensure the service is properly installed."
            )
            return

        logger.info(f"Starting service: {py} {SERVICE_PATH}")

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
            logger.error("Failed to start service")
            QMessageBox.critical(self, "Startup Failed", "Failed to start the broadcaster service.")
            self.proc = None

    def _stop_script(self):
        """Stop the running broadcaster process."""
        if self.proc and self.proc.state() != QProcess.NotRunning:
            logger.info("Stopping service...")

            # Disconnect signals before terminating
            try:
                self.proc.readyReadStandardOutput.disconnect()
                self.proc.finished.disconnect()
            except TypeError:
                pass  # Signals already disconnected

            self.proc.terminate()
            if not self.proc.waitForFinished(3000):
                logger.warning("Service did not terminate gracefully, forcing shutdown...")
                self.proc.kill()
                self.proc.waitForFinished(1000)

            logger.info("Service stopped")
            self.proc.deleteLater()
            self.proc = None

    # ---------- QProcess Output ----------

    def _on_ready_read(self):
        """Handle output from broadcaster process."""
        if not self.proc:
            return
        data = bytes(self.proc.readAllStandardOutput()).decode(errors="ignore")
        if data:
            logger.debug(f"Process output: {data}")

    def _on_finished(self, exitCode, exitStatus):
        """Handle broadcaster process exit."""
        status_str = "normal" if exitStatus == QProcess.NormalExit else "crashed"
        logger.info(f"Process exited: code={exitCode}, status={status_str}")

    # ---------- Wi-Fi ----------

    def open_wifi_dialog(self):
        """Open WiFi management dialog."""
        dlg = WifiDialog(self)
        dlg.exec_()

    # ---------- Navigation ----------

    def _goto(self, index: int):
        """Navigate to page by index."""
        self.pages.setCurrentIndex(index)
        # Groups is now at index 1
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
            # Kill all pifm processes before logout to clean up resources
            logger.info("Cleaning up pifm processes on logout...")
            kill_all_pifm_processes()

            # Clear the token
            self.api_client.logout()

            # Clear cached data
            logger.info("Clearing cached data after logout...")
            self.page_groups._groups_data = []  # Clear cached groups
            self.page_groups.groups_list.clear()  # Clear UI list
            self.page_messages.messages_list.clear()
            self.page_messages.messages_data = []
            self.page_messages.current_group_id = None

            # Reset login page
            self.page_login.username_input.clear()
            self.page_login.password_input.clear()
            self.page_login.error_label.setVisible(False)
            self.page_login.failed_attempts = 0

            # Show login page
            self._show_login_page()

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

        # Stop service (optional - service can continue running)
        # Uncomment if you want to stop service on dashboard close:
        # self._stop_script()

        super().closeEvent(e)

    def _restore_geometry(self):
        """Restore window geometry from settings."""
        geo = self.settings.value("ui/geometry")
        if geo is not None:
            self.restoreGeometry(geo)


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

    # Create and show main window (handles login internally)
    w = MainWindow(api_client)
    w.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()

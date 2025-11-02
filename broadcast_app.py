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
from pathlib import Path
from typing import Optional, Dict, Any

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


# =============================
# Main Window
# =============================

class MainWindow(QMainWindow):
    """Main application window with integrated service management."""

    def __init__(self):
        super().__init__()
        self.proc = None  # QProcess for broadcaster
        self.health_worker = None

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
        self.btn_wifi = QPushButton("WiFi")
        self.btn_dashboard.setCheckable(True)
        self.btn_dashboard.setChecked(True)

        side.addWidget(self.btn_dashboard)
        side.addWidget(self.btn_wifi)
        side.addStretch(1)

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

        # Load frequency from env file
        freq_from_env = extract_current_frequency(ENV_PATH)
        if freq_from_env is not None and validate_frequency(freq_from_env):
            self.page_dashboard.freq_spin.setValue(freq_from_env)

        self.pages.addWidget(self.page_dashboard)

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
        self.btn_wifi.clicked.connect(self.open_wifi_dialog)

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
            except Exception as e:
                log.append(f"Failed to signal process: {e}")
                self._start_broadcaster_with_env(env_vars, fresh=True)
        else:
            log.append("Service not running, starting...")
            self._start_broadcaster_with_env(env_vars, fresh=True)

        QMessageBox.information(
            self,
            "Frequency Updated",
            f"Broadcasting frequency {'switched to' if immediate else 'will switch to'} {freq:.1f} MHz"
        )

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

def main():
    """Main application entry point."""
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

    # Create and show main window
    w = MainWindow()
    w.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()

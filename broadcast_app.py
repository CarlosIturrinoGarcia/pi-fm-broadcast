#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PyQt5 App
- Dashboard with Frequency spinbox + Set Frequency (hot-reload to running broadcaster)
- Wi-Fi scan/connect (nmcli) with embedded on-screen keyboard in password dialog
- Persists window geometry + last frequency
"""

import os
import sys
import re
import signal
import subprocess

from theme import apply_theme
from config import (
    ENV_PATH,
    extract_current_frequency,
)

from PyQt5.QtCore import (
    Qt,
    QSettings,
    QThread,
    pyqtSignal,
    QEvent,
    QCoreApplication,
    QProcess,
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
)

APP_ORG = "Picnic Groups"
APP_NAME = "PyQt5 App"

# --- Adjust these if needed ---
SCRIPT_PATH = "/home/rpibroadcaster/pi_broadcast.py"      # your broadcaster
ENV_FILE    = "/home/rpibroadcaster/broadcast.env"        # env vars (QUEUE_URL, etc.)
PYTHON_BIN  = "/home/rpibroadcaster/venv/bin/python"      # venv python (preferred)

# ---------- helpers from your runner ----------
def load_env_file(path: str) -> dict:
    """Read KEY=VALUE lines from an env file. Supports 'export', quotes, spaces, CRLF."""
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
            if (len(val) >= 2) and (val[0] == val[-1]) and val[0] in ("'", '"'):
                val = val[1:-1]
            env[key] = val
    return env

def render_broadcast_cmd(tmpl: str, freq: float) -> str:
    """Return command with frequency set; supports {freq}, '<num>', or replacing an existing -f number."""
    if "{freq}" in tmpl:
        return tmpl.replace("{freq}", f"{freq:.1f}")
    if "<num>" in tmpl:
        return tmpl.replace("<num>", f"{freq:.1f}")
    if re.search(r"(?<!\S)-f\s+\d+(?:\.\d+)?(?!\S)", tmpl):
        return re.sub(r"(?<!\S)(-f\s+)\d+(?:\.\d+)?(?!\S)",
                      lambda m: f"{m.group(1)}{freq:.1f}", tmpl)
    return f"{tmpl} -f {freq:.1f}"

def write_env_key(path: str, key: str, value: str):
    """Upsert KEY in the .env file while preserving other lines & comments."""
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
            out.append("")  # keep a blank line at the end before appending
        out.append(f'{key}="{value}"')
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")

# =============================
# Embedded On-Screen Keyboard
# =============================
class OnScreenKeyboard(QWidget):
    """Embedded compact QWERTY keyboard that types into a specific target widget."""
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
        self._target = w

    def _mk_btn(self, text, wide=False):
        b = QPushButton(text)
        b.setProperty("wide", "true" if wide else "false")
        b.setFocusPolicy(Qt.NoFocus)  # do NOT steal focus from the input
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
                fw.backspace(); return
            if isinstance(fw, QTextEdit):
                c = fw.textCursor(); c.deletePreviousChar(); fw.setTextCursor(c); return
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
            c = fw.textCursor(); c.insertText(text); fw.setTextCursor(c); return
        for ch in text:
            self._post_key(Qt.Key_Space if ch == " " else 0, ch)

    def _post_key(self, key, text=""):
        fw = self._target_widget()
        if not fw: return
        evp = QKeyEvent(QEvent.KeyPress, key, Qt.NoModifier, text)
        evr = QKeyEvent(QEvent.KeyRelease, key, Qt.NoModifier, text)
        QCoreApplication.postEvent(fw, evp); QCoreApplication.postEvent(fw, evr)


# =============================
# Wi-Fi worker & dialog
# =============================
class WifiWorker(QThread):
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
                res = subprocess.run(cmd, capture_output=True, text=True)
                if res.returncode != 0:
                    self.finished.emit("error", res.stderr.strip() or res.stdout.strip() or "nmcli scan failed")
                    return
                nets = self._parse_nmcli_scan(res.stdout)
                self.finished.emit("scanned", nets)
                return
            if self.action == "connect":
                cmd = ["nmcli", "device", "wifi", "connect", self.ssid, "password", self.password]
                res = subprocess.run(cmd, capture_output=True, text=True)
                if res.returncode == 0:
                    self.finished.emit("connected", res.stdout.strip() or "Connected")
                else:
                    self.finished.emit("error", res.stderr.strip() or res.stdout.strip() or "nmcli connect failed")
                return
            self.finished.emit("error", f"Unknown action: {self.action}")
        except FileNotFoundError:
            self.finished.emit("error", "nmcli not found on this system.")
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

        # Password dialog with embedded keyboard targeted to the password field
        pwd_dlg = QDialog(self)
        pwd_dlg.setWindowTitle(f"Password for {ssid}")

        v = QVBoxLayout(pwd_dlg)
        form = QFormLayout()
        v.addLayout(form)

        info = QLabel(f"Network: {ssid}")
        pwd_input = QLineEdit()
        pwd_input.setEchoMode(QLineEdit.Password)
        pwd_input.setPlaceholderText("Enter Wi-Fi password")
        pwd_input.setAttribute(Qt.WA_AcceptTouchEvents, True)
        pwd_input.setFocusPolicy(Qt.StrongFocus)

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
                self.info.setText("No networks found (or nmcli unavailable).")
                return
            self.info.setText(f"Found {len(nets)} network(s). Select one to connect.")
            for net in nets:
                ssid = net.get("ssid") or "<hidden>"
                text = f"{ssid}  —  Signal: {net.get('signal','')}  —  Sec: {net.get('security','')}"
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
# Dashboard Page
# =============================
class DashboardPage(QWidget):
    freq_set = pyqtSignal(float, bool)  # (frequency, immediate)
    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)

        title = QLabel("Broadcast Dashboard")
        title.setStyleSheet("font-size: 22px; font-weight: 600;")

        controls = QHBoxLayout()
        lbl = QLabel("Frequency (MHz)")
        self.freq_spin = QDoubleSpinBox()
        self.freq_spin.setRange(76.0, 108.0)
        self.freq_spin.setDecimals(1)
        self.freq_spin.setSingleStep(0.1)
        self.freq_spin.setValue(90.8)

        self.chk_immediate = QCheckBox("Switch immediately")
        self.chk_immediate.setToolTip("Abort current playback and switch now")

        self.btn_set_freq = QPushButton("Set Frequency")
        controls.addWidget(lbl)
        controls.addWidget(self.freq_spin)
        controls.addWidget(self.chk_immediate)
        controls.addWidget(self.btn_set_freq)
        controls.addStretch(1)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setPlaceholderText("Broadcaster output will appear here…")

        lay.addWidget(title)
        lay.addLayout(controls)
        lay.addWidget(self.log, 1)

        self.btn_set_freq.clicked.connect(
            lambda: self.freq_set.emit(self.freq_spin.value(), self.chk_immediate.isChecked())
        )


# =============================
# Main Window (integrates QProcess runner)
# =============================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.proc = None  # QProcess for broadcaster
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        self.resize(1000, 650)

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
        self.btn_wifi.setMinimumHeight(36)
        self.btn_dashboard.setCheckable(True)
        self.btn_dashboard.setChecked(True)

        side.addWidget(self.btn_dashboard)
        side.addWidget(self.btn_wifi)
        self.btn_wifi.clicked.connect(self.open_wifi_dialog)
        side.addStretch(1)

        side_wrap = QWidget()
        side_wrap.setLayout(side)
        side_wrap.setFixedWidth(160)
        side_wrap.setObjectName("Sidebar")
        side_wrap.setStyleSheet(
            "#Sidebar {border-right: 1px solid palette(mid); padding: 8px;}\n"
            "QPushButton {text-align: left; padding: 6px 10px;}\n"
            "QPushButton:checked {font-weight: 600;}"
        )

        # Pages
        self.pages = QStackedWidget()
        self.page_dashboard = DashboardPage()

        # Try to read the frequency from .env -> BROADCAST_CMD
        freq_from_env = extract_current_frequency(ENV_PATH)
        if freq_from_env is not None:
            self.page_dashboard.freq_spin.setValue(freq_from_env)

        self.pages.addWidget(self.page_dashboard)

        # Compose
        root.addWidget(side_wrap)
        content = QVBoxLayout()
        content_wrap = QWidget()
        content_wrap.setLayout(content)
        content.addWidget(self.pages, 1)
        root.addWidget(content_wrap, 1)

        # Frequency settings & signals
        try:
            saved_freq = float(self.settings.value("radio/frequency", 90.8))
        except Exception:
            saved_freq = 90.8
        self.page_dashboard.freq_spin.setValue(saved_freq)
        self.page_dashboard.freq_set.connect(self.on_set_frequency)

        # Navigation
        self.btn_dashboard.clicked.connect(lambda: self._goto(0))

        # Tray
        self._setup_tray()

        # Touch-friendly
        self.setStyleSheet("""
            QPushButton { min-height: 44px; font-size: 16px; }
            QDoubleSpinBox { min-height: 44px; font-size: 16px; }
        """)

    # ---------- Broadcast via QProcess with hot-reload ----------
    def on_set_frequency(self, freq: float, immediate: bool):
        self.settings.setValue("radio/frequency", float(freq))
        if not (76.0 <= freq <= 108.0):
            QMessageBox.warning(self, "Frequency", "Please choose 76.0–108.0 MHz.")
            return

        # 1) Build/refresh environment for command rendering
        env_vars = os.environ.copy()
        env_from_file = load_env_file(ENV_FILE)
        env_vars.update(env_from_file)

        # 2) Ensure GPU libs path (sudo pifm expects libbcm_host etc.)
        if not env_vars.get("LD_LIBRARY_PATH"):
            candidates = ["/opt/vc/lib", "/usr/lib/arm-linux-gnueabihf", "/usr/lib/aarch64-linux-gnu"]
            existing = [d for d in candidates if os.path.exists(d)]
            if existing:
                env_vars["LD_LIBRARY_PATH"] = ":".join(existing)

        # 3) Compute and persist new BROADCAST_CMD into ENV_FILE
        tmpl = env_vars.get(
            "BROADCAST_CMD",
            "/usr/bin/sudo /usr/local/bin/pifm_broadcast.sh {file} -f {freq}",
        )
        new_cmd = render_broadcast_cmd(tmpl, freq)
        env_vars["BROADCAST_CMD"] = new_cmd
        try:
            write_env_key(ENV_FILE, "BROADCAST_CMD", new_cmd)
        except Exception as e:
            QMessageBox.critical(self, "Env write error", f"Could not update {ENV_FILE}:\n{e}")
            return

        log = self.page_dashboard.log
        log.append(f"\nBROADCAST_CMD -> {new_cmd}")

        # 4) If broadcaster is running, just signal it. Else, start it.
        running = self.proc and self.proc.state() != QProcess.NotRunning
        if running:
            pid = int(self.proc.processId())
            try:
                if immediate:
                    os.kill(pid, signal.SIGUSR2)  # abort current & reload
                    log.append("Sent SIGUSR2 for immediate switch")
                else:
                    os.kill(pid, signal.SIGHUP)   # gentle reload after current
                    log.append("Sent SIGHUP for gentle reload")
            except Exception as e:
                log.append(f"Failed to signal process ({e}); restarting instead…")
                self._start_broadcaster_with_env(env_vars, fresh=True)
        else:
            self._start_broadcaster_with_env(env_vars, fresh=True)

        QMessageBox.information(
            self, "Broadcast",
            f"{'Switching now' if immediate else 'Will switch after current message'} to {freq:.1f} MHz"
        )

    def _start_broadcaster_with_env(self, env_vars: dict, fresh: bool = False):
        if fresh:
            self._stop_script()

        # Log command line
        log = self.page_dashboard.log
        py = PYTHON_BIN if os.path.isfile(PYTHON_BIN) else sys.executable
        log.append(f"$ {py} {SCRIPT_PATH}")

        # Start QProcess if not running
        if not (self.proc and self.proc.state() != QProcess.NotRunning):
            self.proc = QProcess(self)
            self.proc.setProcessChannelMode(QProcess.MergedChannels)
            self.proc.readyReadStandardOutput.connect(self._on_ready_read)
            self.proc.finished.connect(self._on_finished)

        # Pass environment (including updated BROADCAST_CMD)
        penv = self.proc.processEnvironment()
        penv.clear()
        for k, v in env_vars.items():
            penv.insert(k, v)
        self.proc.setProcessEnvironment(penv)

        self.proc.start(py, [SCRIPT_PATH])
        if not self.proc.waitForStarted(3000):
            QMessageBox.critical(self, "Error", "Failed to start the broadcaster.")
            self.proc = None
            return

    def _stop_script(self):
        if self.proc and self.proc.state() != QProcess.NotRunning:
            self.proc.terminate()
            if not self.proc.waitForFinished(2000):
                self.proc.kill()
        self.proc = None

    # ---------- QProcess output plumbing ----------
    def _on_ready_read(self):
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
        self.page_dashboard.log.append(f"\n[process exited: code={exitCode}]")

    # ---------- Wi-Fi ----------
    def open_wifi_dialog(self):
        dlg = WifiDialog(self)
        dlg.exec_()

    # ---------- Navigation ----------
    def _goto(self, index: int):
        self.pages.setCurrentIndex(index)
        self.btn_dashboard.setChecked(index == 0)

    # ---------- Tray ----------
    def _setup_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        menu = QMenu()
        act_show = menu.addAction("Show / Hide")
        act_quit = menu.addAction("Quit")
        act_show.triggered.connect(self._toggle_visible)
        act_quit.triggered.connect(QApplication.instance().quit)
        self.tray.setContextMenu(menu)
        self.tray.setToolTip(APP_NAME)
        self.tray.show()

    def _toggle_visible(self):
        self.setVisible(not self.isVisible())

    # ---------- Settings ----------
    def closeEvent(self, e):
        self.settings.setValue("ui/geometry", self.saveGeometry())
        try:
            self._stop_script()
        except Exception:
            pass
        super().closeEvent(e)

    def _restore_geometry(self):
        geo = self.settings.value("ui/geometry")
        if geo is not None:
            self.restoreGeometry(geo)


# =============================
# App entry
# =============================
def main():
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_SynthesizeMouseForUnhandledTouchEvents, True)
    QApplication.setAttribute(Qt.AA_SynthesizeTouchForUnhandledMouseEvents, True)

    app = QApplication(sys.argv)
    apply_theme(app)
    app.setOrganizationName(APP_ORG)
    app.setApplicationName(APP_NAME)

    w = MainWindow()
    w.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()

# PyQt5 theme helper
from PyQt5.QtWidgets import QApplication

def apply_theme(app: QApplication):
    qss = """
    /* Main window and base widgets */
    QWidget {
        background: #fafbfa;
        color: #1a1a1a;
        font-size: 15px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }

    QMainWindow {
        background: #f5f7f6;
    }

    /* Labels */
    QLabel {
        color: #1a1a1a;
        font-weight: 500;
        background: transparent;
    }

    /* Input fields */
    QTextEdit, QLineEdit, QPlainTextEdit {
        background: #ffffff;
        border: 2px solid #e5e7e6;
        border-radius: 10px;
        padding: 12px 16px;
        selection-background-color: #cdeee0;
        selection-color: #1a1a1a;
        font-size: 15px;
    }
    QTextEdit:focus, QLineEdit:focus, QPlainTextEdit:focus {
        border: 2px solid #7fdcb7;
        background: #ffffff;
        outline: none;
    }
    QTextEdit:hover, QLineEdit:hover, QPlainTextEdit:hover {
        border: 2px solid #b8e5d4;
    }

    /* Radio buttons */
    QRadioButton {
        spacing: 10px;
        font-weight: 500;
        background: transparent;
    }
    QRadioButton::indicator {
        width: 20px;
        height: 20px;
        border-radius: 10px;
        border: 2px solid #2ecc94;
        background: #fff;
    }
    QRadioButton::indicator:hover {
        border-color: #23c487;
        background: #f0fdf9;
    }
    QRadioButton::indicator:checked {
        background: #8df2c9;
        border: 3px solid #2ecc94;
    }

    /* Checkboxes */
    QCheckBox {
        spacing: 10px;
        font-weight: 500;
        background: transparent;
    }
    QCheckBox::indicator {
        width: 20px;
        height: 20px;
        border-radius: 6px;
        border: 2px solid #2ecc94;
        background: #ffffff;
    }
    QCheckBox::indicator:hover {
        border-color: #23c487;
        background: #f0fdf9;
    }
    QCheckBox::indicator:checked {
        background: #8df2c9;
        border: 2px solid #2ecc94;
        image: url(data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIiIGhlaWdodD0iOSIgdmlld0JveD0iMCAwIDEyIDkiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHBhdGggZD0iTTEgNEw0LjUgNy41TDExIDEiIHN0cm9rZT0iIzFhMWExYSIgc3Ryb2tlLXdpZHRoPSIyIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiLz48L3N2Zz4=);
    }

    /* Spin boxes */
    QDoubleSpinBox, QSpinBox {
        background: #ffffff;
        border: 2px solid #e5e7e6;
        border-radius: 10px;
        padding: 10px 14px;
        font-weight: 600;
        min-height: 36px;
        font-size: 15px;
    }
    QDoubleSpinBox:focus, QSpinBox:focus {
        border: 2px solid #7fdcb7;
    }
    QDoubleSpinBox:hover, QSpinBox:hover {
        border: 2px solid #b8e5d4;
    }
    QDoubleSpinBox::up-button, QDoubleSpinBox::down-button,
    QSpinBox::up-button, QSpinBox::down-button {
        width: 20px;
        border: none;
        background: transparent;
        margin: 0 4px;
    }
    QDoubleSpinBox::up-button:hover, QDoubleSpinBox::down-button:hover,
    QSpinBox::up-button:hover, QSpinBox::down-button:hover {
        background: #e8f5ef;
        border-radius: 6px;
    }

    /* Primary buttons */
    QPushButton {
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #8df2c9, stop:1 #7fdcb7);
        color: #ffffff;
        border: none;
        border-radius: 12px;
        padding: 14px 24px;
        font-weight: 700;
        font-size: 15px;
    }
    QPushButton:hover {
        background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #7fdcb7, stop:1 #6fcaa6);
    }
    QPushButton:pressed {
        background: #6fcaa6;
        padding: 15px 23px 13px 25px; /* Subtle press effect */
    }
    QPushButton:disabled {
        background: #d9ece4;
        color: #a8c9bc;
    }

    /* Secondary buttons */
    QPushButton#secondary {
        background: #ffffff;
        color: #1a1a1a;
        border: 2px solid #e5e7e6;
    }
    QPushButton#secondary:hover {
        background: #f5f7f6;
        border: 2px solid #b8e5d4;
    }
    QPushButton#secondary:pressed {
        background: #eff3f1;
    }

    /* Logout button */
    QPushButton#logout {
        background: #ffffff;
        color: #dc3545;
        border: 2px solid #f5c2c7;
        font-weight: 600;
    }
    QPushButton#logout:hover {
        background: #fff5f5;
        border: 2px solid #f1aeb5;
    }
    QPushButton#logout:pressed {
        background: #ffe8ea;
    }

    /* Group boxes */
    QGroupBox {
        border: 2px solid #e8f5ef;
        border-radius: 14px;
        margin-top: 16px;
        padding: 20px 16px 16px 16px;
        font-weight: 700;
        font-size: 16px;
        background: #ffffff;
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        padding: 4px 12px;
        background: #ffffff;
        border-radius: 8px;
        color: #2ecc94;
    }

    /* List widgets */
    QListWidget {
        background: #ffffff;
        border: 2px solid #e8f5ef;
        border-radius: 12px;
        padding: 8px;
        outline: none;
    }
    QListWidget::item {
        border-radius: 10px;
        padding: 16px;
        margin: 4px 0px;
        border: 1px solid transparent;
    }
    QListWidget::item:hover {
        background: #f0fdf9;
        border: 1px solid #cdeee0;
    }
    QListWidget::item:selected {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #cdeee0, stop:1 #d4f3e8);
        color: #1a1a1a;
        border: 1px solid #7fdcb7;
        font-weight: 600;
    }

    /* Scrollbars */
    QScrollBar:vertical {
        background: #f5f7f6;
        width: 12px;
        border-radius: 6px;
        margin: 0px;
    }
    QScrollBar::handle:vertical {
        background: #cdeee0;
        border-radius: 6px;
        min-height: 30px;
    }
    QScrollBar::handle:vertical:hover {
        background: #b8e5d4;
    }
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
        height: 0px;
    }
    QScrollBar:horizontal {
        background: #f5f7f6;
        height: 12px;
        border-radius: 6px;
        margin: 0px;
    }
    QScrollBar::handle:horizontal {
        background: #cdeee0;
        border-radius: 6px;
        min-width: 30px;
    }
    QScrollBar::handle:horizontal:hover {
        background: #b8e5d4;
    }
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
        width: 0px;
    }

    /* Dialogs */
    QDialog {
        background: #fafbfa;
    }

    /* Message boxes */
    QMessageBox {
        background: #ffffff;
    }
    QMessageBox QPushButton {
        min-width: 100px;
        padding: 12px 20px;
    }
    """
    app.setStyleSheet(qss)

# PyQt5 theme helper
from PyQt5.QtWidgets import QApplication

def apply_theme(app: QApplication):
    qss = """
    QWidget { background: #ffffff; color: #111; font-size: 14px; }
    QLabel { color: #111; font-weight: 600; }

    QTextEdit, QLineEdit, QPlainTextEdit {
        background: #efefef; border: 1px solid #e2e2e2; border-radius: 8px; padding: 10px;
        selection-background-color: #cdeee0; selection-color: #111;
    }
    QTextEdit:focus, QLineEdit:focus, QPlainTextEdit:focus { border: 1px solid #7fdcb7; background: #f5f7f6; }

    QRadioButton { spacing: 8px; font-weight: 500; }
    QRadioButton::indicator { width: 18px; height: 18px; border-radius: 9px; border: 2px solid #2ecc94; background: #fff; }
    QRadioButton::indicator:hover { border-color: #23c487; }
    QRadioButton::indicator:checked { background: #8df2c9; border: 2px solid #2ecc94; }

    QDoubleSpinBox, QSpinBox {
        background: #efefef; border: 1px solid #e2e2e2; border-radius: 12px;
        padding: 6px 12px; font-weight: 700; min-height: 30px;
    }
    QDoubleSpinBox::up-button, QDoubleSpinBox::down-button,
    QSpinBox::up-button, QSpinBox::down-button { width: 18px; border: none; background: transparent; margin: 0 2px; }
    QDoubleSpinBox::up-button:hover, QDoubleSpinBox::down-button:hover,
    QSpinBox::up-button:hover, QSpinBox::down-button:hover { background: #e8e8e8; border-radius: 6px; }

    QPushButton { background: #8df2c9; color: #fff; border: none; border-radius: 16px; padding: 10px 16px; font-weight: 700; }
    QPushButton:hover { background: #7fdcb7; }
    QPushButton:pressed { background: #6fcaa6; }
    QPushButton:disabled { background: #cfe9df; color: #f7f7f7; }

    QPushButton#secondary { background: #efefef; color: #111; border: 1px solid #e2e2e2; }
    QPushButton#secondary:hover { background: #e9e9e9; }

    QGroupBox { border: 1px solid #ededed; border-radius: 12px; margin-top: 12px; padding: 10px; font-weight: 600; }
    """
    app.setStyleSheet(qss)

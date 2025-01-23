import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget,
                             QLabel, QPushButton, QLineEdit, QTextEdit, QListWidget, QMessageBox)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor, QPalette
import logging

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ShadowChat GUI")

class ShadowChatGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        """Initializes the GUI components."""
        self.setWindowTitle("ShadowChat")
        self.setGeometry(100, 100, 800, 600)

        # Apply theme
        self.apply_theme()

        # Main layout
        main_layout = QVBoxLayout()
        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        # Title Label
        self.title_label = QLabel("ShadowChat")
        self.title_label.setAlignment(Qt.AlignCenter)
        self.title_label.setFont(QFont("Courier", 24))
        main_layout.addWidget(self.title_label)

        # Message Log
        self.message_log = QTextEdit()
        self.message_log.setReadOnly(True)
        main_layout.addWidget(self.message_log)

        # Input Layout
        input_layout = QHBoxLayout()

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message here...")
        input_layout.addWidget(self.message_input)

        self.send_button = QPushButton("Send")
        self.send_button.clicked.connect(self.send_message)
        input_layout.addWidget(self.send_button)

        main_layout.addLayout(input_layout)

    def apply_theme(self):
        """Applies a custom theme to the GUI."""
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor("#2b2b2b"))  # Dark background
        palette.setColor(QPalette.WindowText, QColor("#ffffff"))  # White text
        palette.setColor(QPalette.Base, QColor("#1e1e1e"))
        palette.setColor(QPalette.Text, QColor("#00ff00"))  # Green input text
        palette.setColor(QPalette.Button, QColor("#3c3f41"))
        palette.setColor(QPalette.ButtonText, QColor("#ffffff"))
        palette.setColor(QPalette.Highlight, QColor("#ffcc00"))  # Yellow highlight
        self.setPalette(palette)

    def send_message(self):
        """Handles the sending of a message."""
        message = self.message_input.text().strip()
        if message:
            self.message_log.append(f"You: {message}")
            logger.info(f"Sent message: {message}")
            # Placeholder for backend integration to actually send the message
            self.message_input.clear()
        else:
            QMessageBox.warning(self, "Error", "Cannot send an empty message.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ShadowChatGUI()
    window.show()
    sys.exit(app.exec_())

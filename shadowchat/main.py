import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QWidget
from shadowchat.utils.config import load_config
from shadowchat.auth.login import validate_login
from shadowchat.gui.dashboard import Dashboard
import logging

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ShadowChat")

class ShadowChatApp(QMainWindow):
    def __init__(self):
        super().__init__()

        # Set window properties
        self.setWindowTitle("ShadowChat")
        self.setGeometry(100, 100, 800, 600)

        # Placeholder for login or dashboard
        self.central_widget = QLabel("Welcome to ShadowChat! Initializing...")
        self.central_widget.setAlignment(Qt.AlignCenter)
        self.setCentralWidget(self.central_widget)

        # Load configuration
        try:
            self.config = load_config()
            logger.info("Configuration loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            self.central_widget.setText("Error loading configuration. Please check logs.")
            return

        # Initialize the dashboard (or placeholder for login system)
        self.init_dashboard()

    def init_dashboard(self):
        try:
            # Simulate login validation (placeholder)
            user_authenticated = validate_login("username_placeholder", "password_placeholder")
            if user_authenticated:
                logger.info("User successfully authenticated.")

                # Load Dashboard
                dashboard = Dashboard(self.config)
                self.setCentralWidget(dashboard)
            else:
                logger.warning("Authentication failed. Showing login screen.")
                self.central_widget.setText("Authentication Failed. Please restart the app.")
        except Exception as e:
            logger.error(f"Error initializing dashboard: {e}")
            self.central_widget.setText("Initialization Error. Please check logs.")

if __name__ == "__main__":
    # Create application instance
    app = QApplication(sys.argv)

    # Create main window
    window = ShadowChatApp()
    window.show()

    # Run application event loop
    sys.exit(app.exec_())

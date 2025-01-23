import unittest
import os
from shadowchat.keygen import generate_keys
from shadowchat.login import validate_login
from shadowchat.gui import ShadowChatGUI
from shadowchat.client import ShadowChatClient
from shadowchat.server import ShadowChatServer
from PyQt5.QtWidgets import QApplication
import sys
import threading

class TestShadowChat(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up resources needed for the tests."""
        cls.test_password = "StrongPassword123!"
        cls.key_dir = os.path.expanduser("~/.shadowchat/keys/")

        # Ensure the key directory exists
        os.makedirs(cls.key_dir, exist_ok=True)

        # Generate keys for testing
        generate_keys(cls.test_password)

    def test_key_generation(self):
        """Test that key generation creates the necessary files."""
        private_key_path = os.path.join(self.key_dir, "login_key.pem")
        self.assertTrue(os.path.exists(private_key_path), "Private key not generated.")
        public_key_path = os.path.join(self.key_dir, "login_key_pub.pem")
        self.assertTrue(os.path.exists(public_key_path), "Public key not generated.")

    def test_login_validation(self):
        """Test that the login validation works with correct password."""
        result = validate_login("testuser", self.test_password)
        self.assertTrue(result, "Login failed with correct password.")

    def test_login_validation_failure(self):
        """Test that the login validation fails with incorrect password."""
        result = validate_login("testuser", "WrongPassword")
        self.assertFalse(result, "Login succeeded with incorrect password.")

    def test_gui_initialization(self):
        """Test that the GUI initializes without crashing."""
        app = QApplication(sys.argv)
        window = ShadowChatGUI()
        self.assertIsNotNone(window, "GUI failed to initialize.")
        app.quit()

    def test_client_server_communication(self):
        """Test client-server communication with a simple message."""
        server = ShadowChatServer(
            private_key_path=os.path.join(self.key_dir, "comm_key.pem"),
            public_key_path=os.path.join(self.key_dir, "server_pub.pem")
        )

        client = ShadowChatClient(
            server_ip="127.0.0.1",
            public_key_path=os.path.join(self.key_dir, "server_pub.pem"),
            private_key_path=os.path.join(self.key_dir, "comm_key.pem")
        )

        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()

        client.connect()

        try:
            client.send_message("Test Message")
            self.assertTrue(True, "Client-Server communication succeeded.")
        except Exception as e:
            self.fail(f"Client-Server communication failed: {e}")
        finally:
            client.close()
            server.socket.close()

    @classmethod
    def tearDownClass(cls):
        """Clean up resources after the tests."""
        # Remove generated key files
        for file in os.listdir(cls.key_dir):
            os.remove(os.path.join(cls.key_dir, file))

if __name__ == "__main__":
    unittest.main()

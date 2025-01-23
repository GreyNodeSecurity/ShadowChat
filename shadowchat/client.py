import socket
import threading
import json
import logging
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ShadowChat Client")

# Constants
SERVER_PORT = 31337
BUFFER_SIZE = 4096  # 4 KB

class ShadowChatClient:
    def __init__(self, server_ip, public_key_path, private_key_path):
        self.server_ip = server_ip
        self.server_port = SERVER_PORT
        self.public_key = self.load_key(public_key_path, is_public=True)
        self.private_key = self.load_key(private_key_path, is_public=False)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def check_port_availability(self):
        """Checks if the server port is available."""
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.bind(("0.0.0.0", self.server_port))
            test_socket.close()
            logger.info(f"Port {self.server_port} is available.")
        except Exception as e:
            logger.error(f"Port {self.server_port} is not available: {e}")
            print(f"Port {self.server_port} is already in use. Please close other connections on this port and try again.")
            exit(1)

    def load_key(self, path, is_public):
        """Loads a PEM-encoded public or private key."""
        try:
            with open(path, "rb") as key_file:
                key_data = key_file.read()
                if is_public:
                    return load_pem_public_key(key_data)
                else:
                    return load_pem_private_key(key_data, password=None)
        except Exception as e:
            logger.error(f"Failed to load key from {path}: {e}")
            raise

    def encrypt_message(self, message):
        """Encrypts the message using the server's public key."""
        try:
            ciphertext = self.public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return ciphertext
        except Exception as e:
            logger.error(f"Failed to encrypt message: {e}")
            return None

    def sign_message(self, message):
        """Signs the message using the client's private key."""
        try:
            signature = self.private_key.sign(
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return signature
        except Exception as e:
            logger.error(f"Failed to sign message: {e}")
            return None

    def send_message(self, message):
        """Encrypts and sends a message to the server."""
        try:
            ciphertext = self.encrypt_message(message)
            signature = self.sign_message(message)
            if ciphertext and signature:
                payload = {
                    "ciphertext": base64.b64encode(ciphertext).decode(),
                    "signature": base64.b64encode(signature).decode()
                }
                self.socket.sendall(json.dumps(payload).encode())
                logger.info("Message sent successfully.")
            else:
                logger.error("Failed to prepare message for sending.")
        except Exception as e:
            logger.error(f"Error sending message: {e}")

    def connect(self):
        """Connects to the server."""
        self.check_port_availability()
        try:
            self.socket.connect((self.server_ip, self.server_port))
            logger.info(f"Connected to server at {self.server_ip}:{self.server_port}")
            threading.Thread(target=self.listen_for_messages, daemon=True).start()
        except Exception as e:
            logger.error(f"Failed to connect to server: {e}")

    def listen_for_messages(self):
        """Listens for messages from the server."""
        while True:
            try:
                data = self.socket.recv(BUFFER_SIZE).decode()
                if data:
                    logger.info(f"Message received: {data}")
            except Exception as e:
                logger.error(f"Error receiving message: {e}")
                break

    def close(self):
        """Closes the client connection."""
        self.socket.close()
        logger.info("Connection closed.")

if __name__ == "__main__":
    # Example usage
    server_ip = input("Enter the server IP: ")
    public_key_path = os.path.expanduser("~/.shadowchat/keys/server_pub.pem")  # Replace with actual path
    private_key_path = os.path.expanduser("~/.shadowchat/keys/comm_key.pem")  # Replace with actual path

    client = ShadowChatClient(server_ip, public_key_path, private_key_path)
    client.connect()

    try:
        while True:
            message = input("Enter a message to send (or 'exit' to quit): ")
            if message.lower() == 'exit':
                break
            client.send_message(message)
    finally:
        client.close()

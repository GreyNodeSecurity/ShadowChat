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
logger = logging.getLogger("ShadowChat Server")

# Constants
SERVER_PORT = 31337
BUFFER_SIZE = 4096  # 4 KB

class ShadowChatServer:
    def __init__(self, private_key_path, public_key_path):
        self.server_port = SERVER_PORT
        self.private_key = self.load_key(private_key_path, is_public=False)
        self.public_key = self.load_key(public_key_path, is_public=True)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = []

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

    def decrypt_message(self, ciphertext):
        """Decrypts the ciphertext using the server's private key."""
        try:
            plaintext = self.private_key.decrypt(
                base64.b64decode(ciphertext),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext.decode()
        except Exception as e:
            logger.error(f"Failed to decrypt message: {e}")
            return None

    def verify_message(self, message, signature, client_public_key):
        """Verifies the message signature using the client's public key."""
        try:
            client_public_key.verify(
                base64.b64decode(signature),
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            logger.error(f"Failed to verify message: {e}")
            return False

    def handle_client(self, client_socket, client_address):
        """Handles incoming messages from a client."""
        logger.info(f"Connection established with {client_address}.")
        self.clients.append(client_socket)

        try:
            while True:
                data = client_socket.recv(BUFFER_SIZE).decode()
                if not data:
                    break

                payload = json.loads(data)
                ciphertext = payload.get("ciphertext")
                signature = payload.get("signature")

                # Decrypt and verify the message
                decrypted_message = self.decrypt_message(ciphertext)
                if decrypted_message:
                    logger.info(f"Decrypted message: {decrypted_message}")

                    # Broadcast the decrypted message to other clients
                    for client in self.clients:
                        if client != client_socket:
                            client.sendall(decrypted_message.encode())
                else:
                    logger.warning("Failed to process message from client.")

        except Exception as e:
            logger.error(f"Error handling client {client_address}: {e}")
        finally:
            client_socket.close()
            self.clients.remove(client_socket)
            logger.info(f"Connection with {client_address} closed.")

    def start(self):
        """Starts the server to accept incoming connections."""
        try:
            self.socket.bind(("0.0.0.0", self.server_port))
            self.socket.listen(5)
            logger.info(f"Server listening on port {self.server_port}.")

            while True:
                client_socket, client_address = self.socket.accept()
                threading.Thread(target=self.handle_client, args=(client_socket, client_address), daemon=True).start()
        except Exception as e:
            logger.error(f"Error starting server: {e}")
        finally:
            self.socket.close()

if __name__ == "__main__":
    private_key_path = os.path.expanduser("~/.shadowchat/keys/comm_key.pem")  # Replace with actual path
    public_key_path = os.path.expanduser("~/.shadowchat/keys/server_pub.pem")  # Replace with actual path

    server = ShadowChatServer(private_key_path, public_key_path)
    server.start()

import socket
import threading
import json
import logging
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ShadowChat Discovery")

# Constants
BROADCAST_PORT = 31338
BUFFER_SIZE = 4096  # 4 KB
FRIEND_REQUEST_MESSAGE = "FRIEND_REQUEST"

class PeerDiscovery:
    def __init__(self, username, public_key_path, private_key_path):
        self.username = username
        self.public_key = self.load_key(public_key_path, is_public=True)
        self.private_key = self.load_key(private_key_path, is_public=False)
        self.peers = {}  # Stores discovered peers: {peer_ip: peer_public_key}

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

    def start_discovery(self):
        """Starts broadcasting and listening for peers."""
        threading.Thread(target=self.broadcast_presence, daemon=True).start()
        threading.Thread(target=self.listen_for_peers, daemon=True).start()

    def broadcast_presence(self):
        """Broadcasts the user's availability to the local network."""
        try:
            broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            public_key_bytes = self.public_key.public_bytes(
                encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
            )

            payload = {
                "username": self.username,
                "public_key": base64.b64encode(public_key_bytes).decode(),
            }

            while True:
                broadcast_socket.sendto(json.dumps(payload).encode(), ("<broadcast>", BROADCAST_PORT))
                logger.info("Broadcasting presence...")
                threading.Event().wait(10)  # Broadcast every 10 seconds
        except Exception as e:
            logger.error(f"Error broadcasting presence: {e}")

    def listen_for_peers(self):
        """Listens for other peers broadcasting their presence."""
        try:
            listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            listen_socket.bind(("0.0.0.0", BROADCAST_PORT))

            while True:
                data, addr = listen_socket.recvfrom(BUFFER_SIZE)
                peer_info = json.loads(data.decode())
                if addr[0] not in self.peers:
                    peer_public_key = load_pem_public_key(base64.b64decode(peer_info["public_key"]))
                    self.peers[addr[0]] = peer_public_key
                    logger.info(f"Discovered peer: {peer_info['username']} at {addr[0]}")
        except Exception as e:
            logger.error(f"Error listening for peers: {e}")

    def send_friend_request(self, peer_ip):
        """Sends a friend request to the specified peer."""
        if peer_ip not in self.peers:
            logger.error("Peer not discovered. Cannot send friend request.")
            return

        peer_public_key = self.peers[peer_ip]
        friend_request = {
            "type": FRIEND_REQUEST_MESSAGE,
            "username": self.username,
            "public_key": base64.b64encode(
                self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            ).decode(),
        }

        encrypted_request = peer_public_key.encrypt(
            json.dumps(friend_request).encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((peer_ip, BROADCAST_PORT))
                s.sendall(encrypted_request)
                logger.info(f"Friend request sent to {peer_ip}")
        except Exception as e:
            logger.error(f"Failed to send friend request: {e}")

    def receive_friend_request(self, encrypted_request):
        """Decrypts and processes an incoming friend request."""
        try:
            decrypted_request = self.private_key.decrypt(
                encrypted_request,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            request_data = json.loads(decrypted_request.decode())
            logger.info(f"Received friend request from {request_data['username']}.")

            # Automatically accept friend request for now (optional UI prompt in future)
            self.peers[request_data["username"]] = load_pem_public_key(
                base64.b64decode(request_data["public_key"])
            )
            logger.info(f"Friend request accepted from {request_data['username']}.")
        except Exception as e:
            logger.error(f"Failed to process friend request: {e}")

if __name__ == "__main__":
    username = input("Enter your username: ")
    public_key_path = "~/.shadowchat/keys/comm_key_pub.pem"  # Replace with actual path
    private_key_path = "~/.shadowchat/keys/comm_key.pem"  # Replace with actual path

    discovery = PeerDiscovery(username, public_key_path, private_key_path)
    discovery.start_discovery()

    try:
        while True:
            command = input("Enter 'friend [IP]' to send a friend request, or 'exit' to quit: ")
            if command.lower() == "exit":
                break
            elif command.startswith("friend"):
                _, peer_ip = command.split()
                discovery.send_friend_request(peer_ip)
    except KeyboardInterrupt:
        logger.info("Shutting down.")

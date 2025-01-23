from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os
import base64

# Define key storage paths
LOGIN_KEY_PATH = os.path.expanduser("~/.shadowchat/keys/login_key.pem")
COMM_KEY_PATH = os.path.expanduser("~/.shadowchat/keys/comm_key.pem")

# Ensure directories exist
def ensure_key_directory():
    key_dir = os.path.dirname(LOGIN_KEY_PATH)
    if not os.path.exists(key_dir):
        os.makedirs(key_dir)

# Generate RSA key pair
def generate_rsa_key_pair():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )

# Encrypt private key using a password
def encrypt_private_key(private_key, password):
    # Derive a symmetric key from the password
    salt = os.urandom(16)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Serialize private key
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Encrypt the private key
    cipher = Cipher(algorithms.AES(key), modes.CFB(os.urandom(16)), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_key = padder.update(private_key_bytes) + padder.finalize()
    encrypted_key = encryptor.update(padded_key) + encryptor.finalize()

    return salt + cipher.algorithm.iv + encrypted_key

# Save encrypted private key to a file
def save_encrypted_private_key(path, private_key, password):
    encrypted_key = encrypt_private_key(private_key, password)
    with open(path, "wb") as key_file:
        key_file.write(encrypted_key)

# Save public key to a file
def save_public_key(path, public_key):
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(path, "wb") as key_file:
        key_file.write(public_key_bytes)

# Generate keys for login and communication
def generate_keys(password):
    ensure_key_directory()

    # Generate login key pair
    login_key = generate_rsa_key_pair()
    save_encrypted_private_key(LOGIN_KEY_PATH, login_key, password)
    save_public_key(LOGIN_KEY_PATH.replace(".pem", "_pub.pem"), login_key.public_key())

    # Generate communication key pair
    comm_key = generate_rsa_key_pair()
    save_public_key(COMM_KEY_PATH, comm_key.public_key())
    save_public_key(COMM_KEY_PATH.replace(".pem", "_pub.pem"), comm_key.public_key())

if __name__ == "__main__":
    # Example usage
    user_password = input("Enter a strong password for your login key: ")
    generate_keys(user_password)
    print("Keys have been generated and saved.")

import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import logging
import base64

# Initialize logging
logger = logging.getLogger("ShadowChat")

# Paths
LOGIN_KEY_PATH = os.path.expanduser("~/.shadowchat/keys/login_key.pem")

# Helper to derive a symmetric key from a password
def derive_key(password, salt):
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Decrypt the private key using the password
def decrypt_private_key(password):
    try:
        # Read the encrypted private key
        with open(LOGIN_KEY_PATH, "rb") as key_file:
            encrypted_data = key_file.read()

        # Extract salt, IV, and encrypted key
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        encrypted_key = encrypted_data[32:]

        # Derive the symmetric key from the password
        symmetric_key = derive_key(password, salt)

        # Decrypt the private key
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_key = decryptor.update(encrypted_key) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        private_key_bytes = unpadder.update(padded_key) + unpadder.finalize()

        return private_key_bytes

    except Exception as e:
        logger.error(f"Failed to decrypt private key: {e}")
        return None

# Validate login credentials
def validate_login(username, password):
    # For now, username is ignored since authentication is key-based
    if not os.path.exists(LOGIN_KEY_PATH):
        logger.error("Login key does not exist. Please generate keys first.")
        return False

    private_key_bytes = decrypt_private_key(password)
    if private_key_bytes:
        logger.info("Login successful.")
        return True
    else:
        logger.warning("Login failed. Incorrect password or corrupted key.")
        return False

if __name__ == "__main__":
    # Example usage
    user_password = input("Enter your password: ")
    if validate_login("username_placeholder", user_password):
        print("Login successful!")
    else:
        print("Login failed. Please check your password.")

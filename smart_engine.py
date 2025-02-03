import os
import hashlib
import base64
import secrets
from cryptography.fernet import Fernet

class SmartEngine:
    def __init__(self):
        # Generate a key for encryption and decryption
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        print("SmartEngine initialized with secure encryption key.")

    def hash_password(self, password: str) -> str:
        """Hash a password using SHA-256."""
        print(f"Hashing password: {password}")
        password_bytes = password.encode('utf-8')
        hash_digest = hashlib.sha256(password_bytes).digest()
        hashed_password = base64.urlsafe_b64encode(hash_digest).decode('utf-8')
        print(f"Password hashed: {hashed_password}")
        return hashed_password

    def encrypt_data(self, data: str) -> str:
        """Encrypt data using the Fernet symmetric encryption."""
        print(f"Encrypting data: {data}")
        data_bytes = data.encode('utf-8')
        encrypted_data = self.cipher_suite.encrypt(data_bytes)
        encrypted_data_str = encrypted_data.decode('utf-8')
        print(f"Data encrypted: {encrypted_data_str}")
        return encrypted_data_str

    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt data using the Fernet symmetric encryption."""
        print(f"Decrypting data: {encrypted_data}")
        encrypted_data_bytes = encrypted_data.encode('utf-8')
        decrypted_data = self.cipher_suite.decrypt(encrypted_data_bytes)
        decrypted_data_str = decrypted_data.decode('utf-8')
        print(f"Data decrypted: {decrypted_data_str}")
        return decrypted_data_str

    def generate_secure_token(self) -> str:
        """Generate a secure token for session management."""
        token = secrets.token_urlsafe(32)
        print(f"Generated secure token: {token}")
        return token

# Example usage
if __name__ == "__main__":
    engine = SmartEngine()
    password = "SuperSecurePassword123!"
    hashed_password = engine.hash_password(password)
    
    data = "Sensitive information that needs encryption"
    encrypted_data = engine.encrypt_data(data)
    decrypted_data = engine.decrypt_data(encrypted_data)

    token = engine.generate_secure_token()
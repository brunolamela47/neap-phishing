# utils/crypto.py

from cryptography.fernet import Fernet
import os

# ─── Key ───
KEY_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".neap_key")

def get_key() -> bytes:
    """Get or create encryption key."""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        return key

def encrypt(text: str) -> str:
    """Encrypt a string."""
    f = Fernet(get_key())
    return f.encrypt(text.encode()).decode()

def decrypt(text: str) -> str:
    """Decrypt a string."""
    f = Fernet(get_key())
    return f.decrypt(text.encode()).decode()

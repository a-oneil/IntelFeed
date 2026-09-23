from cryptography.fernet import Fernet, InvalidToken

from app.config import settings


def encrypt_value(plaintext: str) -> str:
    """Encrypt a value for storage."""
    f = Fernet(settings.encryption_key.encode())
    return f.encrypt(plaintext.encode()).decode()


def decrypt_value(ciphertext: str) -> str:
    """Decrypt a value from storage. Supports key rotation."""
    # Try current key first
    try:
        f = Fernet(settings.encryption_key.encode())
        return f.decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        pass
    # Try previous key (rotation support)
    if settings.encryption_key_previous:
        try:
            f = Fernet(settings.encryption_key_previous.encode())
            return f.decrypt(ciphertext.encode()).decode()
        except InvalidToken:
            pass
    raise ValueError("Unable to decrypt value with any available key")

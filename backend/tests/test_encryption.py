import pytest

from app.core.encryption import decrypt_value, encrypt_value


def test_encrypt_decrypt_roundtrip():
    plaintext = "super-secret-api-key-12345"
    ciphertext = encrypt_value(plaintext)
    assert ciphertext != plaintext
    result = decrypt_value(ciphertext)
    assert result == plaintext


def test_decrypt_invalid_raises():
    with pytest.raises(ValueError, match="Unable to decrypt"):
        decrypt_value("not-valid-ciphertext")


def test_different_encryptions_differ():
    """Fernet uses a unique IV each time, so the same plaintext
    should produce different ciphertext on each call."""
    plaintext = "same-value-encrypted-twice"
    ct1 = encrypt_value(plaintext)
    ct2 = encrypt_value(plaintext)
    assert ct1 != ct2
    # Both should still decrypt to the same value
    assert decrypt_value(ct1) == plaintext
    assert decrypt_value(ct2) == plaintext

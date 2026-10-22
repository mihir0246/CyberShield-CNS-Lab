import pytest
from cybershield.services.ciphers.caesar import CaesarCipher
from cybershield.services.ciphers.vernam import VernamCipher
from cybershield.services.ciphers.railfence import RailFenceCipher


# ==========================================
# 1. Caesar Cipher Tests
# ==========================================

def test_caesar_roundtrip():
    original = "The Quick Brown Fox Jumps Over 13 Lazy Dogs!"
    for shift in [0, 1, 3, 13, 25]:
        enc = CaesarCipher.encrypt(original, shift)
        dec = CaesarCipher.decrypt(enc["ciphertext"], shift)
        assert dec["plaintext"] == original
        assert enc["shift"] == shift


def test_caesar_preserves_punctuation_and_numbers():
    msg = "CyberShield Lab @ 2026: #Security!"
    res = CaesarCipher.encrypt(msg, 5)
    # Punctuation and spaces preserved
    assert "@" in res["ciphertext"]
    assert "2026:" in res["ciphertext"]
    assert "#" in res["ciphertext"]
    dec = CaesarCipher.decrypt(res["ciphertext"], 5)
    assert dec["plaintext"] == msg


def test_caesar_invalid_shift():
    with pytest.raises(ValueError):
        CaesarCipher.encrypt("Test", -1)
    with pytest.raises(ValueError):
        CaesarCipher.encrypt("Test", 26)
    with pytest.raises(ValueError):
        CaesarCipher.encrypt("Test", "invalid")


# ==========================================
# 2. Vernam Cipher Tests
# ==========================================

def test_vernam_roundtrip():
    original = "CYBERSHIELD_LAB_VERIFY"
    enc = VernamCipher.encrypt(original)
    assert "ciphertext_hex" in enc
    assert "key_hex" in enc
    assert len(bytes.fromhex(enc["ciphertext_hex"])) == len(original.encode("utf-8"))

    dec = VernamCipher.decrypt(enc["ciphertext_hex"], enc["key_hex"])
    assert dec["plaintext"] == original


def test_vernam_key_length_validation():
    plain = "HELLO"
    # Plaintext is 5 bytes; supply a key of 3 bytes
    short_key_hex = "a1b2c3"
    with pytest.raises(ValueError, match="Strict One-Time Pad Error"):
        VernamCipher.encrypt(plain, key_hex=short_key_hex)


def test_vernam_empty_input():
    with pytest.raises(ValueError, match="Plaintext cannot be empty"):
        VernamCipher.encrypt("")


# ==========================================
# 3. Rail Fence Cipher Tests
# ==========================================

def test_railfence_roundtrip():
    original = "DEFEND THE EAST WALL"
    for rails in [2, 3, 4, 5]:
        enc = RailFenceCipher.encrypt(original, rails)
        dec = RailFenceCipher.decrypt(enc["ciphertext"], rails)
        assert dec["plaintext"] == original


def test_railfence_known_vector():
    text = "DEFENDTHEEASTWALL"
    enc = RailFenceCipher.encrypt(text, 3)
    # Classic rail fence depth 3
    dec = RailFenceCipher.decrypt(enc["ciphertext"], 3)
    assert dec["plaintext"] == text


def test_railfence_invalid_rails():
    with pytest.raises(ValueError, match="rails must be at least 2"):
        RailFenceCipher.encrypt("Hello", 1)
    with pytest.raises(ValueError, match="rails must be at least 2"):
        RailFenceCipher.encrypt("Hello", 0)

"""
Vernam Cipher / One-Time Pad (OTP) Implementation
Implements true byte-wise XOR encryption/decryption with strict key length validation.
"""
import secrets
import base64
from typing import Dict, Any, Tuple


class VernamCipher:
    @staticmethod
    def generate_key(length: int) -> bytes:
        """Generate a cryptographically secure random key using OS entropy source."""
        if length <= 0:
            raise ValueError("Key length must be greater than zero.")
        return secrets.token_bytes(length)

    @staticmethod
    def xor_bytes(data: bytes, key: bytes) -> bytes:
        """Byte-wise XOR operation between data and key."""
        if len(data) != len(key):
            raise ValueError(
                f"Strict OTP requirement violated: Plaintext length ({len(data)} bytes) "
                f"must exactly match Key length ({len(key)} bytes)."
            )
        return bytes(d ^ k for d, k in zip(data, key))

    @classmethod
    def encrypt(cls, plaintext: str, key_hex: str = None) -> Dict[str, Any]:
        data_bytes = plaintext.encode("utf-8")
        msg_len = len(data_bytes)

        if not msg_len:
            raise ValueError("Plaintext cannot be empty.")

        if key_hex:
            try:
                key_bytes = bytes.fromhex(key_hex.strip())
            except ValueError:
                raise ValueError("Key must be a valid hexadecimal string.")
            if len(key_bytes) != msg_len:
                raise ValueError(
                    f"Strict One-Time Pad Error: Key length ({len(key_bytes)} bytes) "
                    f"does not match plaintext length ({msg_len} bytes)."
                )
        else:
            # Generate fresh cryptographically random key of identical length
            key_bytes = cls.generate_key(msg_len)

        cipher_bytes = cls.xor_bytes(data_bytes, key_bytes)

        # Build step-by-step byte XOR traces (up to 12 bytes for demonstration)
        steps = []
        for i in range(min(msg_len, 12)):
            p_b = data_bytes[i]
            k_b = key_bytes[i]
            c_b = cipher_bytes[i]
            steps.append({
                "byte_index": i,
                "plain_char": chr(p_b) if 32 <= p_b <= 126 else f"\\x{p_b:02x}",
                "plain_byte": f"0x{p_b:02X} ({p_b:08b})",
                "key_byte": f"0x{k_b:02X} ({k_b:08b})",
                "xor_op": f"{p_b:08b} ^ {k_b:08b} = {c_b:08b}",
                "cipher_byte": f"0x{c_b:02X}",
            })

        return {
            "algorithm": "Vernam Cipher (One-Time Pad)",
            "operation": "encryption",
            "plaintext": plaintext,
            "byte_length": msg_len,
            "key_hex": key_bytes.hex(),
            "key_base64": base64.b64encode(key_bytes).decode("ascii"),
            "ciphertext_hex": cipher_bytes.hex(),
            "ciphertext_base64": base64.b64encode(cipher_bytes).decode("ascii"),
            "steps": steps,
            "security_notice": (
                "CRITICAL SECURITY PRINCIPLE: The Vernam Cipher provides Shannon's information-theoretic "
                "perfect secrecy ONLY if: (1) The key is truly random, (2) The key is as long as the message, "
                "(3) The key is kept strictly secret, and (4) THE KEY IS NEVER REUSED. Reusing a key allows "
                "two-time pad cryptanalysis: C1 ^ C2 = P1 ^ P2."
            ),
        }

    @classmethod
    def decrypt(cls, ciphertext_hex: str, key_hex: str) -> Dict[str, Any]:
        if not ciphertext_hex or not key_hex:
            raise ValueError("Both ciphertext and key in hexadecimal format are required.")

        try:
            cipher_bytes = bytes.fromhex(ciphertext_hex.strip())
        except ValueError:
            raise ValueError("Ciphertext must be a valid hexadecimal string.")

        try:
            key_bytes = bytes.fromhex(key_hex.strip())
        except ValueError:
            raise ValueError("Key must be a valid hexadecimal string.")

        if len(cipher_bytes) != len(key_bytes):
            raise ValueError(
                f"Length mismatch: Ciphertext is {len(cipher_bytes)} bytes, "
                f"but Key is {len(key_bytes)} bytes."
            )

        plain_bytes = cls.xor_bytes(cipher_bytes, key_bytes)

        try:
            plaintext = plain_bytes.decode("utf-8")
        except UnicodeDecodeError:
            plaintext = plain_bytes.decode("latin-1")

        steps = []
        for i in range(min(len(cipher_bytes), 12)):
            c_b = cipher_bytes[i]
            k_b = key_bytes[i]
            p_b = plain_bytes[i]
            steps.append({
                "byte_index": i,
                "cipher_byte": f"0x{c_b:02X} ({c_b:08b})",
                "key_byte": f"0x{k_b:02X} ({k_b:08b})",
                "xor_op": f"{c_b:08b} ^ {k_b:08b} = {p_b:08b}",
                "plain_byte": f"0x{p_b:02X}",
                "plain_char": chr(p_b) if 32 <= p_b <= 126 else f"\\x{p_b:02x}",
            })

        return {
            "algorithm": "Vernam Cipher (One-Time Pad)",
            "operation": "decryption",
            "ciphertext_hex": ciphertext_hex,
            "key_hex": key_hex,
            "plaintext": plaintext,
            "byte_length": len(plain_bytes),
            "steps": steps,
            "security_notice": "Decryption is symmetric: Plaintext = Ciphertext ^ Key because (P ^ K) ^ K = P.",
        }

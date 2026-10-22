"""
Caesar Cipher Implementation
Shift cipher preserving uppercase, lowercase, punctuation, and whitespace.
"""
from typing import Dict, Any, List


class CaesarCipher:
    @staticmethod
    def validate_shift(shift: int) -> int:
        if not isinstance(shift, int):
            try:
                shift = int(shift)
            except (ValueError, TypeError):
                raise ValueError("Shift value must be an integer between 0 and 25.")
        if not (0 <= shift <= 25):
            raise ValueError(f"Shift value must be between 0 and 25 (received {shift}).")
        return shift

    @classmethod
    def encrypt(cls, plaintext: str, shift: int) -> Dict[str, Any]:
        shift = cls.validate_shift(shift)
        ciphertext_chars = []
        steps: List[Dict[str, str]] = []

        for ch in plaintext:
            if "A" <= ch <= "Z":
                base = ord("A")
                orig_pos = ord(ch) - base
                new_pos = (orig_pos + shift) % 26
                res_char = chr(base + new_pos)
                ciphertext_chars.append(res_char)
                if len(steps) < 20:  # Sample trace up to 20 chars
                    steps.append({
                        "char": ch,
                        "orig_pos": str(orig_pos),
                        "formula": f"({orig_pos} + {shift}) mod 26 = {new_pos}",
                        "result": res_char,
                    })
            elif "a" <= ch <= "z":
                base = ord("a")
                orig_pos = ord(ch) - base
                new_pos = (orig_pos + shift) % 26
                res_char = chr(base + new_pos)
                ciphertext_chars.append(res_char)
                if len(steps) < 20:
                    steps.append({
                        "char": ch,
                        "orig_pos": str(orig_pos),
                        "formula": f"({orig_pos} + {shift}) mod 26 = {new_pos}",
                        "result": res_char,
                    })
            else:
                ciphertext_chars.append(ch)
                if len(steps) < 20 and not ch.isspace():
                    steps.append({
                        "char": ch,
                        "orig_pos": "N/A",
                        "formula": "Preserved literal",
                        "result": ch,
                    })

        ciphertext = "".join(ciphertext_chars)
        return {
            "algorithm": "Caesar Cipher",
            "operation": "encryption",
            "plaintext": plaintext,
            "ciphertext": ciphertext,
            "shift": shift,
            "steps": steps,
            "explanation": (
                f"Each alphabetical character is shifted forward by {shift} position(s) "
                f"modulo 26: C = (P + {shift}) mod 26. Punctuation, numbers, and spaces remain unchanged."
            ),
        }

    @classmethod
    def decrypt(cls, ciphertext: str, shift: int) -> Dict[str, Any]:
        shift = cls.validate_shift(shift)
        plaintext_chars = []
        steps: List[Dict[str, str]] = []

        for ch in ciphertext:
            if "A" <= ch <= "Z":
                base = ord("A")
                orig_pos = ord(ch) - base
                new_pos = (orig_pos - shift) % 26
                res_char = chr(base + new_pos)
                plaintext_chars.append(res_char)
                if len(steps) < 20:
                    steps.append({
                        "char": ch,
                        "orig_pos": str(orig_pos),
                        "formula": f"({orig_pos} - {shift}) mod 26 = {new_pos}",
                        "result": res_char,
                    })
            elif "a" <= ch <= "z":
                base = ord("a")
                orig_pos = ord(ch) - base
                new_pos = (orig_pos - shift) % 26
                res_char = chr(base + new_pos)
                plaintext_chars.append(res_char)
                if len(steps) < 20:
                    steps.append({
                        "char": ch,
                        "orig_pos": str(orig_pos),
                        "formula": f"({orig_pos} - {shift}) mod 26 = {new_pos}",
                        "result": res_char,
                    })
            else:
                plaintext_chars.append(ch)
                if len(steps) < 20 and not ch.isspace():
                    steps.append({
                        "char": ch,
                        "orig_pos": "N/A",
                        "formula": "Preserved literal",
                        "result": ch,
                    })

        plaintext = "".join(plaintext_chars)
        return {
            "algorithm": "Caesar Cipher",
            "operation": "decryption",
            "ciphertext": ciphertext,
            "plaintext": plaintext,
            "shift": shift,
            "steps": steps,
            "explanation": (
                f"Each alphabetical character is shifted backward by {shift} position(s) "
                f"modulo 26: P = (C - {shift}) mod 26. Non-alphabetical characters remain unchanged."
            ),
        }

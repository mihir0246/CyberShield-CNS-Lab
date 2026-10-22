"""
Rail Fence Cipher (Zig-Zag Transposition Cipher)
Provides encryption, decryption, input validation, and visual transposition matrix.
"""
from typing import Dict, Any, List


class RailFenceCipher:
    @staticmethod
    def validate_rails(rails: int, text_length: int) -> int:
        if not isinstance(rails, int):
            try:
                rails = int(rails)
            except (ValueError, TypeError):
                raise ValueError("Number of rails must be an integer.")
        if rails < 2:
            raise ValueError("Number of rails must be at least 2.")
        if rails >= text_length and text_length > 1:
            # Still valid mathematically, but warn/handle
            pass
        return rails

    @classmethod
    def encrypt(cls, plaintext: str, rails: int) -> Dict[str, Any]:
        if not plaintext:
            raise ValueError("Plaintext cannot be empty.")
        rails = cls.validate_rails(rails, len(plaintext))

        if rails == 1 or rails >= len(plaintext):
            return {
                "algorithm": "Rail Fence Cipher",
                "operation": "encryption",
                "plaintext": plaintext,
                "ciphertext": plaintext,
                "rails": rails,
                "matrix": [[ch for ch in plaintext]],
                "explanation": "With rails >= text length, no transposition occurs.",
            }

        # Build grid
        grid = [["" for _ in range(len(plaintext))] for _ in range(rails)]
        row, direction = 0, 1

        for col, char in enumerate(plaintext):
            grid[row][col] = char
            if row == 0:
                direction = 1
            elif row == rails - 1:
                direction = -1
            row += direction

        # Read row by row
        ciphertext_chars = []
        for r in range(rails):
            for c in range(len(plaintext)):
                if grid[r][c] != "":
                    ciphertext_chars.append(grid[r][c])

        ciphertext = "".join(ciphertext_chars)

        # Generate a display friendly visualization
        visual_rows = []
        for r in range(rails):
            row_str = "".join(grid[r][c] if grid[r][c] != "" else "·" for c in range(min(len(plaintext), 40)))
            visual_rows.append(row_str)

        return {
            "algorithm": "Rail Fence Cipher",
            "operation": "encryption",
            "plaintext": plaintext,
            "ciphertext": ciphertext,
            "rails": rails,
            "visual_rows": visual_rows,
            "grid": [[grid[r][c] for c in range(min(len(plaintext), 40))] for r in range(rails)],
            "explanation": (
                f"Plaintext is written diagonally downwards and upwards between {rails} rails in a "
                f"zig-zag trajectory, then read off row-by-row to produce the transposed ciphertext."
            ),
        }

    @classmethod
    def decrypt(cls, ciphertext: str, rails: int) -> Dict[str, Any]:
        if not ciphertext:
            raise ValueError("Ciphertext cannot be empty.")
        rails = cls.validate_rails(rails, len(ciphertext))

        if rails == 1 or rails >= len(ciphertext):
            return {
                "algorithm": "Rail Fence Cipher",
                "operation": "decryption",
                "ciphertext": ciphertext,
                "plaintext": ciphertext,
                "rails": rails,
                "visual_rows": [ciphertext],
                "explanation": "With rails >= text length, ciphertext matches plaintext.",
            }

        # Mark zig-zag positions with placeholder '*'
        grid = [["" for _ in range(len(ciphertext))] for _ in range(rails)]
        row, direction = 0, 1
        for col in range(len(ciphertext)):
            grid[row][col] = "*"
            if row == 0:
                direction = 1
            elif row == rails - 1:
                direction = -1
            row += direction

        # Fill marked spots with ciphertext characters row by row
        idx = 0
        for r in range(rails):
            for c in range(len(ciphertext)):
                if grid[r][c] == "*" and idx < len(ciphertext):
                    grid[r][c] = ciphertext[idx]
                    idx += 1

        # Read off along the zig-zag path to recover plaintext
        plaintext_chars = []
        row, direction = 0, 1
        for col in range(len(ciphertext)):
            plaintext_chars.append(grid[row][col])
            if row == 0:
                direction = 1
            elif row == rails - 1:
                direction = -1
            row += direction

        plaintext = "".join(plaintext_chars)

        visual_rows = []
        for r in range(rails):
            row_str = "".join(grid[r][c] if grid[r][c] != "" else "·" for c in range(min(len(ciphertext), 40)))
            visual_rows.append(row_str)

        return {
            "algorithm": "Rail Fence Cipher",
            "operation": "decryption",
            "ciphertext": ciphertext,
            "plaintext": plaintext,
            "rails": rails,
            "visual_rows": visual_rows,
            "explanation": (
                f"Transposition pattern reconstructed across {rails} rails; "
                f"characters read back following the original zig-zag sequence."
            ),
        }

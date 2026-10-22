"""
Hill Cipher Implementation
Supports 2x2 and 3x3 key matrices, strict modulo-26 invertibility validation,
step-by-step vector matrix multiplication math traces, and padding handling.
"""
import math
import re
from typing import List, Dict, Any, Tuple


class HillCipher:
    @staticmethod
    def mod_inverse(a: int, m: int = 26) -> int:
        """Compute modular multiplicative inverse of a modulo m using extended Euclidean algorithm."""
        a = a % m
        if math.gcd(a, m) != 1:
            raise ValueError(f"Value {a} has no modular inverse modulo {m} because gcd({a}, {m}) != 1.")
        return pow(a, -1, m)

    @classmethod
    def determinant_2x2(cls, matrix: List[List[int]]) -> int:
        return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]

    @classmethod
    def determinant_3x3(cls, m: List[List[int]]) -> int:
        return (
            m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1])
            - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0])
            + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0])
        )

    @classmethod
    def inverse_matrix_2x2(cls, matrix: List[List[int]]) -> Tuple[List[List[int]], int, int]:
        det = cls.determinant_2x2(matrix)
        det_mod = det % 26
        if math.gcd(det_mod, 26) != 1:
            raise ValueError(
                f"Matrix is not invertible modulo 26: det = {det}, det mod 26 = {det_mod}. "
                f"gcd({det_mod}, 26) = {math.gcd(det_mod, 26)} (must be 1). "
                f"{'det mod 26 is even (factor of 2)' if det_mod % 2 == 0 else 'det mod 26 is multiple of 13'}."
            )
        det_inv = cls.mod_inverse(det_mod, 26)

        # Adjugate for 2x2: [[d, -b], [-c, a]]
        adj = [
            [matrix[1][1] % 26, (-matrix[0][1]) % 26],
            [(-matrix[1][0]) % 26, matrix[0][0] % 26],
        ]

        inv_matrix = [
            [(det_inv * adj[r][c]) % 26 for c in range(2)]
            for r in range(2)
        ]
        return inv_matrix, det_mod, det_inv

    @classmethod
    def inverse_matrix_3x3(cls, m: List[List[int]]) -> Tuple[List[List[int]], int, int]:
        det = cls.determinant_3x3(m)
        det_mod = det % 26
        if math.gcd(det_mod, 26) != 1:
            raise ValueError(
                f"Matrix is not invertible modulo 26: det = {det}, det mod 26 = {det_mod}. "
                f"gcd({det_mod}, 26) = {math.gcd(det_mod, 26)} (must be 1). "
                f"A valid 3x3 key matrix must have gcd(det % 26, 26) == 1."
            )
        det_inv = cls.mod_inverse(det_mod, 26)

        # Compute 3x3 adjugate (transpose of cofactor matrix)
        cofactors = [[0, 0, 0], [0, 0, 0], [0, 0, 0]]
        for r in range(3):
            for c in range(3):
                # Submatrix 2x2
                sub = []
                for i in range(3):
                    if i == r:
                        continue
                    row = []
                    for j in range(3):
                        if j == c:
                            continue
                        row.append(m[i][j])
                    sub.append(row)
                minor = sub[0][0] * sub[1][1] - sub[0][1] * sub[1][0]
                sign = (-1) ** (r + c)
                cofactors[r][c] = sign * minor

        # Transpose to get adjugate
        adj = [[cofactors[c][r] % 26 for c in range(3)] for r in range(3)]

        inv_matrix = [
            [(det_inv * adj[r][c]) % 26 for c in range(3)]
            for r in range(3)
        ]
        return inv_matrix, det_mod, det_inv

    @classmethod
    def validate_and_parse_key(cls, key_input: Any, size: int) -> Tuple[List[List[int]], List[List[int]], int, int]:
        """Parses key input (either 2D array or string of space/comma separated numbers), validates dimensions & invertibility."""
        if size not in (2, 3):
            raise ValueError("Hill Cipher currently supports dimension size 2 (2x2) and 3 (3x3).")

        matrix = []
        if isinstance(key_input, list):
            if len(key_input) == size and all(isinstance(row, list) and len(row) == size for row in key_input):
                matrix = [[int(cell) % 26 for cell in row] for row in key_input]
            elif len(key_input) == size * size:
                matrix = [
                    [int(key_input[r * size + c]) % 26 for c in range(size)]
                    for r in range(size)
                ]
        elif isinstance(key_input, str):
            # Parse tokens (numbers or letters)
            tokens = [t.strip() for t in re.split(r"[\s,;]+", key_input.strip()) if t.strip()]
            if len(tokens) != size * size:
                # Check if it's a word of length size*size, e.g. "HILL" -> [[7, 8], [11, 11]]
                letters_only = re.sub(r"[^A-Za-z]", "", key_input).upper()
                if len(letters_only) == size * size:
                    nums = [ord(ch) - ord("A") for ch in letters_only]
                    matrix = [[nums[r * size + c] for c in range(size)] for r in range(size)]
                else:
                    raise ValueError(
                        f"Expected {size * size} values for a {size}x{size} matrix, but got {len(tokens)}."
                    )
            else:
                nums = []
                for t in tokens:
                    if t.lstrip("-").isdigit():
                        nums.append(int(t) % 26)
                    elif len(t) == 1 and t.isalpha():
                        nums.append((ord(t.upper()) - ord("A")) % 26)
                    else:
                        raise ValueError(f"Invalid matrix token '{t}'. Must be an integer or letter.")
                matrix = [[nums[r * size + c] for c in range(size)] for r in range(size)]

        if not matrix or len(matrix) != size:
            raise ValueError(f"Unable to parse valid {size}x{size} matrix.")

        if size == 2:
            inv_matrix, det_mod, det_inv = cls.inverse_matrix_2x2(matrix)
        else:
            inv_matrix, det_mod, det_inv = cls.inverse_matrix_3x3(matrix)

        return matrix, inv_matrix, det_mod, det_inv

    @classmethod
    def clean_text(cls, text: str, block_size: int, pad_char: str = "X") -> Tuple[str, int]:
        """Normalize text: only A-Z, padded to multiple of block_size."""
        cleaned = re.sub(r"[^A-Za-z]", "", text).upper()
        if not cleaned:
            raise ValueError("Text contains no valid alphabetical characters (A-Z).")
        pad_len = (block_size - (len(cleaned) % block_size)) % block_size
        padded_text = cleaned + (pad_char * pad_len)
        return padded_text, pad_len

    @classmethod
    def encrypt(cls, plaintext: str, key_input: Any, size: int = 2) -> Dict[str, Any]:
        key_matrix, inv_matrix, det_mod, det_inv = cls.validate_and_parse_key(key_input, size)
        padded_text, pad_len = cls.clean_text(plaintext, size)

        ciphertext_chars = []
        steps = []

        for i in range(0, len(padded_text), size):
            block = padded_text[i:i + size]
            vec_p = [ord(c) - ord("A") for c in block]

            # Vector matrix multiplication: C = K * P mod 26
            vec_c = [0] * size
            calc_strings = []
            for r in range(size):
                terms = [f"({key_matrix[r][c]} * {vec_p[c]})" for c in range(size)]
                sum_val = sum(key_matrix[r][c] * vec_p[c] for c in range(size))
                res_mod = sum_val % 26
                vec_c[r] = res_mod
                calc_strings.append(f"[{' + '.join(terms)}] mod 26 = {sum_val} mod 26 = {res_mod} ('{chr(ord('A') + res_mod)}')")

            c_block = "".join(chr(ord("A") + val) for val in vec_c)
            ciphertext_chars.append(c_block)

            if len(steps) < 8:
                steps.append({
                    "block_index": i // size + 1,
                    "plain_block": block,
                    "vector_p": vec_p,
                    "calculations": calc_strings,
                    "cipher_block": c_block,
                })

        ciphertext = "".join(ciphertext_chars)
        return {
            "algorithm": f"Hill Cipher ({size}x{size})",
            "operation": "encryption",
            "plaintext_input": plaintext,
            "normalized_plaintext": padded_text,
            "padded_chars_count": pad_len,
            "ciphertext": ciphertext,
            "key_matrix": key_matrix,
            "inverse_key_matrix": inv_matrix,
            "determinant_mod26": det_mod,
            "det_modular_inverse": det_inv,
            "steps": steps,
            "mathematical_explanation": (
                f"1. Key matrix K is {size}x{size} with det(K) mod 26 = {det_mod}, invertible with det^-1 = {det_inv}.\n"
                f"2. Plaintext is blocked into column vectors P of size {size}.\n"
                f"3. Each ciphertext block C is calculated via C = (K · P) mod 26.\n"
                f"4. Resulting numerical coordinates [0..25] map back to uppercase letters [A..Z]."
            ),
        }

    @classmethod
    def decrypt(cls, ciphertext: str, key_input: Any, size: int = 2) -> Dict[str, Any]:
        key_matrix, inv_matrix, det_mod, det_inv = cls.validate_and_parse_key(key_input, size)
        cleaned_cipher, _ = cls.clean_text(ciphertext, size)

        if len(cleaned_cipher) % size != 0:
            raise ValueError(f"Ciphertext length must be a multiple of the key dimension {size}.")

        plaintext_chars = []
        steps = []

        for i in range(0, len(cleaned_cipher), size):
            block = cleaned_cipher[i:i + size]
            vec_c = [ord(c) - ord("A") for c in block]

            # Vector matrix multiplication: P = K^-1 * C mod 26
            vec_p = [0] * size
            calc_strings = []
            for r in range(size):
                terms = [f"({inv_matrix[r][c]} * {vec_c[c]})" for c in range(size)]
                sum_val = sum(inv_matrix[r][c] * vec_c[c] for c in range(size))
                res_mod = sum_val % 26
                vec_p[r] = res_mod
                calc_strings.append(f"[{' + '.join(terms)}] mod 26 = {sum_val} mod 26 = {res_mod} ('{chr(ord('A') + res_mod)}')")

            p_block = "".join(chr(ord("A") + val) for val in vec_p)
            plaintext_chars.append(p_block)

            if len(steps) < 8:
                steps.append({
                    "block_index": i // size + 1,
                    "cipher_block": block,
                    "vector_c": vec_c,
                    "calculations": calc_strings,
                    "plain_block": p_block,
                })

        recovered_text = "".join(plaintext_chars)
        return {
            "algorithm": f"Hill Cipher ({size}x{size})",
            "operation": "decryption",
            "ciphertext_input": ciphertext,
            "recovered_plaintext": recovered_text,
            "key_matrix": key_matrix,
            "inverse_key_matrix": inv_matrix,
            "determinant_mod26": det_mod,
            "det_modular_inverse": det_inv,
            "steps": steps,
            "mathematical_explanation": (
                f"Decryption recovers plaintext using the modular inverse matrix K^-1 mod 26:\n"
                f"P = (K^-1 · C) mod 26. Since (K^-1 · K) = I mod 26, P is reconstructed losslessly."
            ),
        }

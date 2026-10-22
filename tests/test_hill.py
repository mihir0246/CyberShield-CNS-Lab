import pytest
from cybershield.services.ciphers.hill import HillCipher


def test_hill_2x2_roundtrip():
    # Valid key: [[3, 3], [2, 5]], det = 15 - 6 = 9, gcd(9, 26) = 1, det^-1 = 3
    key = [[3, 3], [2, 5]]
    original = "HELP"
    enc = HillCipher.encrypt(original, key, size=2)
    assert enc["ciphertext"] == "HIAT"
    dec = HillCipher.decrypt(enc["ciphertext"], key, size=2)
    assert dec["recovered_plaintext"] == original


def test_hill_2x2_padding_handling():
    # Plaintext length 5 -> should pad with 'X' to 6 (multiple of 2)
    key = [[3, 3], [2, 5]]
    original = "HELLO"
    enc = HillCipher.encrypt(original, key, size=2)
    assert len(enc["ciphertext"]) == 6
    assert enc["padded_chars_count"] == 1
    dec = HillCipher.decrypt(enc["ciphertext"], key, size=2)
    assert dec["recovered_plaintext"] == "HELLOX"


def test_hill_3x3_roundtrip():
    # Valid 3x3 matrix: [[6, 24, 1], [13, 16, 10], [20, 17, 15]]
    key = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]
    original = "ACT"
    enc = HillCipher.encrypt(original, key, size=3)
    dec = HillCipher.decrypt(enc["ciphertext"], key, size=3)
    assert dec["recovered_plaintext"] == original


def test_hill_non_invertible_key_rejected():
    # Matrix [[2, 4], [4, 6]]: det = 12 - 16 = -4 = 22 mod 26.
    # gcd(22, 26) = 2 != 1 -> Not invertible!
    invalid_key = [[2, 4], [4, 6]]
    with pytest.raises(ValueError, match="Matrix is not invertible modulo 26"):
        HillCipher.encrypt("TEST", invalid_key, size=2)


def test_hill_parse_string_keys():
    # Test passing key as space/comma separated numbers
    str_key = "3 3 2 5"
    mat, inv_mat, det_mod, det_inv = HillCipher.validate_and_parse_key(str_key, size=2)
    assert mat == [[3, 3], [2, 5]]
    assert det_mod == 9
    assert det_inv == 3

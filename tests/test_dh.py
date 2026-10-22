import pytest
from cybershield.services.diffie_hellman.dh_service import DHService


def test_diffie_hellman_production_exchange():
    res = DHService.run_cryptographic_exchange(key_size=512)  # 512-bit for rapid unit test
    assert res["exchange_verification"]["secrets_match"] is True
    assert res["exchange_verification"]["derived_keys_match"] is True
    assert len(res["exchange_verification"]["derived_symmetric_key_hex"]) == 64  # 32 bytes = 256 bits


def test_diffie_hellman_educational_trace():
    # Textbook parameters: p=23, g=5, a=6, b=15
    res = DHService.run_educational_math_trace(p=23, g=5, a=6, b=15)
    assert res["alice_public_A"] == 8
    assert res["bob_public_B"] == 19
    assert res["shared_secret"] == 2
    assert res["secrets_equal"] is True
    assert len(res["steps"]) == 7


def test_diffie_hellman_invalid_parameters():
    with pytest.raises(ValueError, match="prime p must be >= 5"):
        DHService.run_educational_math_trace(p=3, g=2)

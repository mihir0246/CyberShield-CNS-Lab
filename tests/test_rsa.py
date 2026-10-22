import pytest
from cybershield.services.rsa.rsa_service import RSAService


def test_rsa_key_generation_and_serialization():
    priv, pub, ms = RSAService.generate_key_pair(key_size=1024)
    assert ms > 0
    assert pub.key_size == 1024
    pub_pem = RSAService.serialize_public_key(pub)
    priv_pem = RSAService.serialize_private_key(priv)
    assert "BEGIN PUBLIC KEY" in pub_pem
    assert "BEGIN PRIVATE KEY" in priv_pem


def test_rsa_oaep_roundtrip():
    priv, pub, _ = RSAService.generate_key_pair(key_size=2048)
    pub_pem = RSAService.serialize_public_key(pub)
    priv_pem = RSAService.serialize_private_key(priv)

    message = "CyberShield Confidential Asymmetric Payload"
    enc = RSAService.encrypt(message, pub_pem)
    assert "ciphertext_b64" in enc
    assert "ciphertext_hex" in enc

    dec = RSAService.decrypt(enc["ciphertext_b64"], priv_pem)
    assert dec["recovered_plaintext"] == message


def test_rsa_message_too_long():
    priv, pub, _ = RSAService.generate_key_pair(key_size=1024)
    pub_pem = RSAService.serialize_public_key(pub)

    # 1024-bit RSA max OAEP payload with SHA-256 is 128 - 66 = 62 bytes
    long_msg = "A" * 100
    with pytest.raises(ValueError, match="Plaintext too long for RSA-1024"):
        RSAService.encrypt(long_msg, pub_pem)


def test_rsa_benchmark_suite():
    bench = RSAService.run_benchmark()
    assert "benchmark_results" in bench
    assert len(bench["benchmark_results"]) == 3
    for b in bench["benchmark_results"]:
        assert b["key_size_bits"] in [1024, 2048, 3072]
        assert b["key_gen_time_ms"] > 0

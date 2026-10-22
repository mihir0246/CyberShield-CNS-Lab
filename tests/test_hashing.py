import pytest
from cybershield.services.hashing.hash_service import HashService


def test_hash_correctness():
    text = "CyberShield"
    res = HashService.hash_text(text)
    # Known MD5 and SHA-256 digests for "CyberShield"
    assert res["md5"]["digest"] == "d7df133c8e941fad4801fd5da155b2b6"
    assert res["sha256"]["digest"] == "7d0ba125319e43b53eb503f2864dd862a99a5aab74dda3f925abb8f88d8c00fe"


def test_integrity_verification():
    h1 = "9a039755b4bc703e7c80dbb7cf4cbcfd"
    h2 = "9A039755B4BC703E7C80DBB7CF4CBCFD"  # Case-insensitive
    h3 = "11111111111111111111111111111111"

    match_res = HashService.verify_integrity(h1, h2)
    assert match_res["match"] is True

    diff_res = HashService.verify_integrity(h1, h3)
    assert diff_res["match"] is False


def test_benchmark_suite_execution():
    suite = HashService.run_benchmark_suite(trials=2)
    assert "benchmark_data" in suite
    assert len(suite["benchmark_data"]) == 5
    for row in suite["benchmark_data"]:
        assert row["md5_avg_us"] > 0
        assert row["sha256_avg_us"] > 0

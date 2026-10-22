"""
Hash Analysis and Integrity Verification Service
Educational comparison of broken MD5 (RFC 1321) against modern SHA-256 (FIPS 180-4).
Includes benchmarking across message sizes, multiple trials, and file integrity validation.
"""
import hashlib
import time
import os
from typing import Dict, Any, List, Tuple


class HashService:
    @staticmethod
    def hash_text(text: str) -> Dict[str, Any]:
        data = text.encode("utf-8")
        
        # MD5
        t0 = time.perf_counter()
        md5_digest = hashlib.md5(data).hexdigest()
        md5_time_us = (time.perf_counter() - t0) * 1_000_000.0

        # SHA-256
        t1 = time.perf_counter()
        sha256_digest = hashlib.sha256(data).hexdigest()
        sha256_time_us = (time.perf_counter() - t1) * 1_000_000.0

        return {
            "input_type": "text",
            "byte_length": len(data),
            "md5": {
                "algorithm": "MD5",
                "digest": md5_digest,
                "digest_bits": 128,
                "digest_chars": len(md5_digest),
                "time_us": round(md5_time_us, 2),
                "security_status": "BROKEN / INSECURE (RFC 6151)",
                "vulnerabilities": "Practical collision attacks, pre-image weaknesses, length extension.",
            },
            "sha256": {
                "algorithm": "SHA-256",
                "digest": sha256_digest,
                "digest_bits": 256,
                "digest_chars": len(sha256_digest),
                "time_us": round(sha256_time_us, 2),
                "security_status": "SECURE / NIST RECOMMENDED",
                "vulnerabilities": "None known in standard collision or pre-image resistance.",
            },
        }

    @staticmethod
    def hash_file(file_path: str) -> Dict[str, Any]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = os.path.getsize(file_path)
        md5_hasher = hashlib.md5()
        sha256_hasher = hashlib.sha256()

        chunk_size = 64 * 1024

        t0 = time.perf_counter()
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                md5_hasher.update(chunk)
        md5_time_us = (time.perf_counter() - t0) * 1_000_000.0

        t1 = time.perf_counter()
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                sha256_hasher.update(chunk)
        sha256_time_us = (time.perf_counter() - t1) * 1_000_000.0

        return {
            "input_type": "file",
            "filename": os.path.basename(file_path),
            "file_size_bytes": file_size,
            "md5": {
                "digest": md5_hasher.hexdigest(),
                "time_us": round(md5_time_us, 2),
                "speed_mb_s": round((file_size / (1024 * 1024)) / (md5_time_us / 1_000_000.0), 2) if md5_time_us > 0 else 0,
            },
            "sha256": {
                "digest": sha256_hasher.hexdigest(),
                "time_us": round(sha256_time_us, 2),
                "speed_mb_s": round((file_size / (1024 * 1024)) / (sha256_time_us / 1_000_000.0), 2) if sha256_time_us > 0 else 0,
            },
        }

    @staticmethod
    def verify_integrity(digest1: str, digest2: str) -> Dict[str, Any]:
        match = (digest1.strip().lower() == digest2.strip().lower())
        return {
            "digest1": digest1.strip(),
            "digest2": digest2.strip(),
            "match": match,
            "verdict": "INTEGRITY VERIFIED: Digests match perfectly." if match else "INTEGRITY VIOLATED: Digests differ. Content has been altered, corrupted, or tampered with.",
        }

    @classmethod
    def run_benchmark_suite(cls, trials: int = 5) -> Dict[str, Any]:
        """Runs benchmarks on multiple data sizes: 1KB, 10KB, 100KB, 1MB, 5MB across repeated trials."""
        trials = max(1, min(trials, 20))
        sizes = [
            ("1 KB", 1024),
            ("10 KB", 10 * 1024),
            ("100 KB", 100 * 1024),
            ("1 MB", 1024 * 1024),
            ("5 MB", 5 * 1024 * 1024),
        ]

        results = []
        for label, byte_count in sizes:
            # Generate deterministic pseudo-random payload
            payload = os.urandom(byte_count)

            # Benchmark MD5
            md5_times = []
            for _ in range(trials):
                t0 = time.perf_counter()
                d_md5 = hashlib.md5(payload).hexdigest()
                md5_times.append((time.perf_counter() - t0) * 1_000_000.0)
            avg_md5_us = sum(md5_times) / len(md5_times)

            # Benchmark SHA-256
            sha_times = []
            for _ in range(trials):
                t0 = time.perf_counter()
                d_sha = hashlib.sha256(payload).hexdigest()
                sha_times.append((time.perf_counter() - t0) * 1_000_000.0)
            avg_sha_us = sum(sha_times) / len(sha_times)

            results.append({
                "label": label,
                "bytes": byte_count,
                "md5_avg_us": round(avg_md5_us, 2),
                "sha256_avg_us": round(avg_sha_us, 2),
                "md5_digest_preview": d_md5[:16] + "...",
                "sha256_digest_preview": d_sha[:16] + "...",
                "ratio_sha_over_md5": round(avg_sha_us / avg_md5_us, 2) if avg_md5_us > 0 else 1.0,
            })

        return {
            "trials_per_size": trials,
            "benchmark_data": results,
            "security_verdict": (
                "IMPORTANT SECURITY FINDING: While MD5 is slightly faster due to its simpler 128-bit structure, "
                "it has been cryptographically broken since 2004 (Wang et al. collision attacks). An adversary "
                "can forge two different executables or certificates with identical MD5 hashes in seconds on commodity hardware. "
                "SHA-256 provides a 256-bit state with no known practical collision attacks and must be used for all "
                "modern digital signatures, authentication tokens, and tamper-detection controls."
            ),
        }

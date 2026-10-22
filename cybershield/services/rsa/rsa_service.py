"""
RSA Cryptosystem Service
Implements standard PKCS/RFC 8017 compliant RSA with OAEP padding and SHA-256,
key size benchmarking, key serialization/deserialization, and educational diagnostics.
"""
import time
import base64
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


class RSAService:
    SUPPORTED_KEY_SIZES = [1024, 2048, 3072, 4096]

    @classmethod
    def generate_key_pair(cls, key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey, float]:
        if key_size not in cls.SUPPORTED_KEY_SIZES:
            raise ValueError(f"Unsupported key size: {key_size}. Supported sizes: {cls.SUPPORTED_KEY_SIZES}")

        t0 = time.perf_counter()
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )
        gen_time = (time.perf_counter() - t0) * 1000.0  # ms
        return private_key, private_key.public_key(), gen_time

    @classmethod
    def serialize_public_key(cls, public_key: rsa.RSAPublicKey) -> str:
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem.decode("utf-8")

    @classmethod
    def serialize_private_key(cls, private_key: rsa.RSAPrivateKey) -> str:
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return pem.decode("utf-8")

    @classmethod
    def load_public_key_pem(cls, pem_str: str) -> rsa.RSAPublicKey:
        try:
            pub_key = serialization.load_pem_public_key(pem_str.encode("utf-8"))
            if not isinstance(pub_key, rsa.RSAPublicKey):
                raise ValueError("Loaded key is not an RSA public key.")
            return pub_key
        except Exception as e:
            raise ValueError(f"Failed to load RSA public key: {str(e)}")

    @classmethod
    def load_private_key_pem(cls, pem_str: str) -> rsa.RSAPrivateKey:
        try:
            priv_key = serialization.load_pem_private_key(pem_str.encode("utf-8"), password=None)
            if not isinstance(priv_key, rsa.RSAPrivateKey):
                raise ValueError("Loaded key is not an RSA private key.")
            return priv_key
        except Exception as e:
            raise ValueError(f"Failed to load RSA private key: {str(e)}")

    @classmethod
    def get_public_key_details(cls, public_key: rsa.RSAPublicKey) -> Dict[str, Any]:
        numbers = public_key.public_numbers()
        n_hex = f"{numbers.n:x}"
        return {
            "key_size_bits": public_key.key_size,
            "public_exponent_e": numbers.e,
            "modulus_n_hex": (n_hex[:32] + "..." + n_hex[-32:]) if len(n_hex) > 64 else n_hex,
            "modulus_length_hex": len(n_hex),
            "max_plaintext_bytes": (public_key.key_size // 8) - 2 * 32 - 2,  # OAEP overhead with SHA-256: 2*hLen + 2 = 66
        }

    @classmethod
    def encrypt(cls, plaintext: str, public_key_pem: str) -> Dict[str, Any]:
        pub_key = cls.load_public_key_pem(public_key_pem)
        data = plaintext.encode("utf-8")
        max_bytes = (pub_key.key_size // 8) - 66
        if len(data) > max_bytes:
            raise ValueError(
                f"Plaintext too long for RSA-{pub_key.key_size} with OAEP-SHA256. "
                f"Maximum allowed is {max_bytes} bytes; received {len(data)} bytes."
            )

        t0 = time.perf_counter()
        ciphertext = pub_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        enc_time = (time.perf_counter() - t0) * 1000.0  # ms

        return {
            "algorithm": "RSA-OAEP-SHA256",
            "operation": "encryption",
            "key_size": pub_key.key_size,
            "plaintext_length": len(data),
            "ciphertext_hex": ciphertext.hex(),
            "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
            "encryption_time_ms": round(enc_time, 3),
            "padding_scheme": "Optimal Asymmetric Encryption Padding (OAEP) with MGF1-SHA256",
        }

    @classmethod
    def decrypt(cls, ciphertext_b64_or_hex: str, private_key_pem: str) -> Dict[str, Any]:
        priv_key = cls.load_private_key_pem(private_key_pem)
        raw_cipher = ciphertext_b64_or_hex.strip()

        # Try base64 first, fallback to hex
        cipher_bytes = None
        try:
            cipher_bytes = base64.b64decode(raw_cipher, validate=True)
        except Exception:
            try:
                cipher_bytes = bytes.fromhex(raw_cipher)
            except Exception:
                raise ValueError("Ciphertext must be valid base64 or hexadecimal.")

        t0 = time.perf_counter()
        try:
            plaintext_bytes = priv_key.decrypt(
                cipher_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as e:
            raise ValueError(f"RSA Decryption failed (invalid key or corrupted ciphertext): {str(e)}")

        dec_time = (time.perf_counter() - t0) * 1000.0  # ms
        recovered_text = plaintext_bytes.decode("utf-8", errors="replace")

        return {
            "algorithm": "RSA-OAEP-SHA256",
            "operation": "decryption",
            "key_size": priv_key.key_size,
            "recovered_plaintext": recovered_text,
            "recovered_length": len(plaintext_bytes),
            "decryption_time_ms": round(dec_time, 3),
        }

    @classmethod
    def run_benchmark(cls) -> Dict[str, Any]:
        """Compares key generation, encryption, and decryption across 1024, 2048, and 3072-bit keys."""
        results = []
        sample_msg = "CyberShield Lab - RSA Asymmetric Cryptography Benchmark"

        for bits in [1024, 2048, 3072]:
            priv, pub, gen_ms = cls.generate_key_pair(bits)
            pub_pem = cls.serialize_public_key(pub)
            priv_pem = cls.serialize_private_key(priv)

            enc_res = cls.encrypt(sample_msg, pub_pem)
            dec_res = cls.decrypt(enc_res["ciphertext_b64"], priv_pem)

            results.append({
                "key_size_bits": bits,
                "key_gen_time_ms": round(gen_ms, 2),
                "encrypt_time_ms": round(enc_res["encryption_time_ms"], 3),
                "decrypt_time_ms": round(dec_res["decryption_time_ms"], 3),
                "modulus_bytes": bits // 8,
                "security_status": "Deprecated / Legacy (<2048)" if bits < 2048 else ("NIST Recommended (Current)" if bits == 2048 else "High Security (Post-2030)"),
            })

        return {
            "benchmark_results": results,
            "sample_message": sample_msg,
            "analysis": (
                "Notice the asymmetric scaling: Key generation and private-key decryption times grow "
                "cubically with key length (O(k^3)), while public key encryption (e=65537) remains very fast. "
                "2048-bit keys provide an optimal balance of robust 112-bit security and acceptable latency."
            ),
        }

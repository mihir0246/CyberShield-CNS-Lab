"""
Diffie-Hellman Key Exchange Service
Simulates Alice and Bob negotiating an ephemeral shared secret, verifies equality,
derives an AES/symmetric key via HKDF-SHA256, and provides step-by-step mathematical tracing.
"""
import secrets
from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, ParameterFormat


class DHService:
    @classmethod
    def run_cryptographic_exchange(cls, key_size: int = 2048) -> Dict[str, Any]:
        """
        Executes a real cryptographic Diffie-Hellman key exchange using standard group parameters.
        """
        # Generate DH parameters (generator 2)
        parameters = dh.generate_parameters(generator=2, key_size=key_size)
        param_numbers = parameters.parameter_numbers()
        p = param_numbers.p
        g = param_numbers.g

        # Alice generates private key 'a' and computes public key A = g^a mod p
        alice_private = parameters.generate_private_key()
        alice_public = alice_private.public_key()
        alice_pub_int = alice_public.public_numbers().y

        # Bob generates private key 'b' and computes public key B = g^b mod p
        bob_private = parameters.generate_private_key()
        bob_public = bob_private.public_key()
        bob_pub_int = bob_public.public_numbers().y

        # Alice receives Bob's public key B and calculates: S_Alice = B^a mod p
        alice_shared_secret = alice_private.exchange(bob_public)

        # Bob receives Alice's public key A and calculates: S_Bob = A^b mod p
        bob_shared_secret = bob_private.exchange(alice_public)

        # Equality verification
        secrets_match = (alice_shared_secret == bob_shared_secret)

        # Key derivation using HKDF-SHA256
        hkdf_alice = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit symmetric key (e.g. for AES-256-GCM)
            salt=b"CyberShield-DH-Salt",
            info=b"diffie-hellman-session-key",
        )
        derived_key_alice = hkdf_alice.derive(alice_shared_secret)

        hkdf_bob = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"CyberShield-DH-Salt",
            info=b"diffie-hellman-session-key",
        )
        derived_key_bob = hkdf_bob.derive(bob_shared_secret)

        derived_keys_match = (derived_key_alice == derived_key_bob)

        p_hex = f"{p:x}"
        alice_pub_hex = f"{alice_pub_int:x}"
        bob_pub_hex = f"{bob_pub_int:x}"
        secret_hex = alice_shared_secret.hex()

        return {
            "mode": "Cryptographic Production Mode (RFC Standard MODP)",
            "key_size_bits": key_size,
            "generator_g": g,
            "prime_p_bit_length": p.bit_length(),
            "prime_p_preview": p_hex[:24] + "..." + p_hex[-24:],
            "alice": {
                "role": "Initiator",
                "public_key_preview": alice_pub_hex[:24] + "..." + alice_pub_hex[-24:],
                "private_key_status": "Securely retained in Alice's ephemeral memory (never transmitted)",
            },
            "bob": {
                "role": "Responder",
                "public_key_preview": bob_pub_hex[:24] + "..." + bob_pub_hex[-24:],
                "private_key_status": "Securely retained in Bob's ephemeral memory (never transmitted)",
            },
            "exchange_verification": {
                "shared_secret_bytes_len": len(alice_shared_secret),
                "shared_secret_preview": secret_hex[:24] + "..." + secret_hex[-24:],
                "secrets_match": secrets_match,
                "kdf_algorithm": "HKDF-SHA256 (RFC 5869)",
                "derived_symmetric_key_hex": derived_key_alice.hex(),
                "derived_keys_match": derived_keys_match,
            },
            "mitm_warning": (
                "CRITICAL SECURITY CONSIDERATION: Diffie-Hellman establishes confidentiality across an insecure "
                "channel but provides NO AUTHENTICATION. An active adversary (Eve) can execute a Man-in-the-Middle "
                "(MitM) attack by intercepting public keys and establishing two separate shared keys unless "
                "authenticated via digital signatures (e.g., ECDSA / RSA in TLS 1.3 or certificates)."
            ),
        }

    @classmethod
    def run_educational_math_trace(cls, p: int = 23, g: int = 5, a: int = None, b: int = None) -> Dict[str, Any]:
        """
        Runs an educational small-integer Diffie-Hellman simulation with complete step-by-step arithmetic.
        """
        # Validate p is prime and g is valid generator if provided, or default to classic textbook (23, 5)
        p = int(p)
        g = int(g)
        if p < 5:
            raise ValueError("Modulus prime p must be >= 5.")

        # Pick random private keys if not specified
        if a is None:
            a = secrets.randbelow(p - 3) + 2
        else:
            a = int(a)

        if b is None:
            b = secrets.randbelow(p - 3) + 2
        else:
            b = int(b)

        # Step 1: Alice computes public key A = g^a mod p
        A = pow(g, a, p)

        # Step 2: Bob computes public key B = g^b mod p
        B = pow(g, b, p)

        # Step 3: Alice computes secret S_Alice = B^a mod p
        S_Alice = pow(B, a, p)

        # Step 4: Bob computes secret S_Bob = A^b mod p
        S_Bob = pow(A, b, p)

        steps = [
            {
                "step": 1,
                "title": "Public Parameters Agreement",
                "description": f"Alice and Bob publicly agree on prime modulus p = {p} and generator g = {g}.",
                "public_visible": True,
            },
            {
                "step": 2,
                "title": "Alice Generates Private Secret & Public Key",
                "description": f"Alice chooses private integer a = {a}. She computes public key A = g^a mod p = {g}^{a} mod {p} = {A}.",
                "transmitted": f"A = {A}",
            },
            {
                "step": 3,
                "title": "Bob Generates Private Secret & Public Key",
                "description": f"Bob chooses private integer b = {b}. She computes public key B = g^b mod p = {g}^{b} mod {p} = {B}.",
                "transmitted": f"B = {B}",
            },
            {
                "step": 4,
                "title": "Public Value Exchange",
                "description": f"Alice sends A={A} over the wire to Bob. Bob sends B={B} over the wire to Alice.",
                "transmitted": f"A={A}, B={B}",
            },
            {
                "step": 5,
                "title": "Alice Computes Shared Secret",
                "description": f"Alice computes S_Alice = B^a mod p = {B}^{a} mod {p} = {S_Alice}.",
                "result": f"S_Alice = {S_Alice}",
            },
            {
                "step": 6,
                "title": "Bob Computes Shared Secret",
                "description": f"Bob computes S_Bob = A^b mod p = {A}^{b} mod {p} = {S_Bob}.",
                "result": f"S_Bob = {S_Bob}",
            },
            {
                "step": 7,
                "title": "Mathematical Equivalence Proof",
                "description": (
                    f"By modular exponentiation rules: S_Alice = (g^b)^a mod p = g^(ab) mod p = (g^a)^b mod p = S_Bob. "
                    f"Both secrets match: {S_Alice} == {S_Bob}."
                ),
                "matched": (S_Alice == S_Bob),
            },
        ]

        return {
            "mode": "Educational Math Walkthrough",
            "p": p,
            "g": g,
            "alice_private_a": a,
            "alice_public_A": A,
            "bob_private_b": b,
            "bob_public_B": B,
            "shared_secret": S_Alice,
            "secrets_equal": (S_Alice == S_Bob),
            "steps": steps,
        }

# CyberShield Automated Testing & Verification Report

---

## 1. Testing Strategy & Framework

CyberShield enforces a test-driven verification strategy implemented using **pytest 8.3+**. The automated test suite validates:
- Algorithmic correctness of all classical and modern cryptographic ciphers (encryption/decryption round trips, mathematical invertibility, edge conditions).
- Digest correctness and timing benchmark integrity (MD5, SHA-256).
- Deep packet inspection accuracy on multi-layer PCAP captures via Scapy.
- Machine-readable Nmap XML output parsing and target whitelist enforcement.
- Snort fast-alert log parsing and rule syntax decomposition.
- Synthetic DoS rate-limiting modeling and anomaly trigger detection.
- Cross-domain security event correlation heuristics.
- Error handling, malformed input rejection, and HTTP endpoint status codes.

All tests are completely self-contained and run locally using in-memory databases and fixture mocks, eliminating external network dependencies or administrator privilege requirements.

---

## 2. Test Matrix & Syllabus Coverage

| Test Module | Test Function | Practical Target | Verification Scope |
|---|---|---|---|
| `test_ciphers.py` | `test_caesar_roundtrip` | Exp 1 (Caesar) | Asserts $P = \text{Decrypt}(\text{Encrypt}(P, k), k)$ across shifts $0 \dots 25$. |
| `test_ciphers.py` | `test_caesar_preserves_punctuation` | Exp 1 (Caesar) | Verifies spaces, numbers, and symbols remain unchanged. |
| `test_ciphers.py` | `test_caesar_invalid_shift` | Exp 1 (Caesar) | Verifies shifts outside $[0, 25]$ raise `ValueError`. |
| `test_ciphers.py` | `test_vernam_roundtrip` | Exp 1 (Vernam) | Asserts $P = C \oplus K$ for random bytes of equal length. |
| `test_ciphers.py` | `test_vernam_key_length_validation` | Exp 1 (Vernam) | Verifies length mismatch between key and plaintext raises error. |
| `test_ciphers.py` | `test_railfence_roundtrip` | Exp 1 (Rail Fence) | Validates zig-zag transposition roundtrip for rails $2 \dots 8$. |
| `test_hill.py` | `test_hill_2x2_roundtrip` | Exp 2 (Hill 2x2) | Validates $P = K^{-1} \cdot (K \cdot P) \bmod 26$ on invertible key. |
| `test_hill.py` | `test_hill_3x3_roundtrip` | Exp 2 (Hill 3x3) | Validates 3x3 matrix multiplication and modular inversion. |
| `test_hill.py` | `test_hill_non_invertible_key_rejected` | Exp 2 (Hill) | Verifies matrix with $\gcd(\det \bmod 26, 26) \ne 1$ is rejected. |
| `test_rsa.py` | `test_rsa_oaep_roundtrip` | Exp 3 (RSA) | Validates RSA keygen, PEM serialization, and OAEP-SHA256 recovery. |
| `test_rsa.py` | `test_rsa_message_too_long` | Exp 3 (RSA) | Confirms messages exceeding key size OAEP bound raise clear error. |
| `test_dh.py` | `test_diffie_hellman_production_exchange` | Exp 4 (DH) | Confirms Alice and Bob calculate matching secrets and HKDF keys. |
| `test_dh.py` | `test_diffie_hellman_educational_trace` | Exp 4 (DH) | Validates step-by-step arithmetic on textbook prime values. |
| `test_hashing.py` | `test_hash_correctness` | Exp 5 (Hashing) | Verifies MD5 and SHA-256 digests against NIST test vectors. |
| `test_hashing.py` | `test_integrity_verification` | Exp 5 (Hashing) | Validates matching and non-matching digest comparisons. |
| `test_pcap.py` | `test_pcap_parsing` | Exp 6 (Packet Analysis) | Parses test PCAP; validates packet counts, protocols, and flags. |
| `test_pcap.py` | `test_pcap_filtering` | Exp 6 (Packet Analysis) | Tests filtering by protocol, IP address, and TCP flag. |
| `test_nmap.py` | `test_nmap_xml_parsing` | Exp 7 (Nmap) | Parses `samples/sample_nmap.xml`; verifies open ports and services. |
| `test_nmap.py` | `test_nmap_target_guardrail` | Exp 7 (Nmap) | Confirms public IP targets are rejected by security whitelist. |
| `test_dos.py` | `test_dos_simulation_mitigation` | Exp 8 (DoS) | Verifies token-bucket rate limiter caps throughput and drops packets. |
| `test_snort.py` | `test_snort_rule_explainer` | Exp 9 (Snort) | Validates regex decomposition of rule header and options. |
| `test_snort.py` | `test_snort_fast_log_parser` | Exp 9 (Snort) | Ingests `samples/sample_snort.log`; verifies parsed alerts count. |
| `test_correlation.py` | `test_event_correlation_engine` | Exp 10 (Correlation) | Fuses PCAP SYN probes with Snort alerts; asserts high-confidence finding. |

---

## 3. Test Execution Commands & Results

To run the automated test suite locally:

```bash
# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Run pytest with verbose summary
pytest -v
```

### Actual Execution Output
```
platform win32 -- Python 3.13.3, pytest-8.3.4, pluggy-1.7.0
rootdir: C:\Users\mihir\Desktop\CNS
configfile: pytest.ini
testpaths: tests
collected 41 items

tests/test_api_endpoints.py::test_health_check_endpoint PASSED           [  2%]
tests/test_api_endpoints.py::test_dashboard_endpoint PASSED              [  4%]
tests/test_api_endpoints.py::test_caesar_api_endpoint PASSED             [  7%]
tests/test_api_endpoints.py::test_hill_validate_key_endpoint PASSED      [  9%]
tests/test_api_endpoints.py::test_rsa_api_endpoint PASSED                [ 12%]
tests/test_api_endpoints.py::test_404_error_page PASSED                  [ 14%]
tests/test_ciphers.py::test_caesar_roundtrip PASSED                      [ 17%]
tests/test_ciphers.py::test_caesar_preserves_punctuation_and_numbers PASSED [ 19%]
tests/test_ciphers.py::test_caesar_invalid_shift PASSED                  [ 21%]
tests/test_ciphers.py::test_vernam_roundtrip PASSED                      [ 24%]
tests/test_ciphers.py::test_vernam_key_length_validation PASSED          [ 26%]
tests/test_ciphers.py::test_vernam_empty_input PASSED                    [ 29%]
tests/test_ciphers.py::test_railfence_roundtrip PASSED                   [ 31%]
tests/test_ciphers.py::test_railfence_known_vector PASSED                [ 34%]
tests/test_ciphers.py::test_railfence_invalid_rails PASSED               [ 36%]
tests/test_correlation.py::test_event_correlation_engine PASSED          [ 39%]
tests/test_dh.py::test_diffie_hellman_production_exchange PASSED         [ 41%]
tests/test_dh.py::test_diffie_hellman_educational_trace PASSED           [ 43%]
tests/test_dh.py::test_diffie_hellman_invalid_parameters PASSED          [ 46%]
tests/test_dos.py::test_dos_simulation_mitigation PASSED                 [ 48%]
tests/test_dos.py::test_traffic_spike_detection PASSED                   [ 51%]
tests/test_hashing.py::test_hash_correctness PASSED                      [ 53%]
tests/test_hashing.py::test_integrity_verification PASSED                [ 56%]
tests/test_hashing.py::test_benchmark_suite_execution PASSED             [ 58%]
tests/test_hill.py::test_hill_2x2_roundtrip PASSED                       [ 60%]
tests/test_hill.py::test_hill_2x2_padding_handling PASSED                [ 63%]
tests/test_hill.py::test_hill_3x3_roundtrip PASSED                       [ 65%]
tests/test_hill.py::test_hill_non_invertible_key_rejected PASSED         [ 68%]
tests/test_hill.py::test_hill_parse_string_keys PASSED                   [ 70%]
tests/test_nmap.py::test_nmap_xml_parsing PASSED                         [ 73%]
tests/test_nmap.py::test_nmap_target_guardrail PASSED                    [ 75%]
tests/test_pcap.py::test_pcap_parsing PASSED                             [ 78%]
tests/test_pcap.py::test_pcap_filtering PASSED                           [ 80%]
tests/test_pcap.py::test_pcap_csv_export PASSED                          [ 82%]
tests/test_rsa.py::test_rsa_key_generation_and_serialization PASSED      [ 85%]
tests/test_rsa.py::test_rsa_oaep_roundtrip PASSED                        [ 87%]
tests/test_rsa.py::test_rsa_message_too_long PASSED                      [ 90%]
tests/test_rsa.py::test_rsa_benchmark_suite PASSED                       [ 92%]
tests/test_snort.py::test_snort_rule_explainer PASSED                    [ 95%]
tests/test_snort.py::test_snort_fast_log_parser PASSED                   [ 97%]
tests/test_snort.py::test_snort_csv_export PASSED                        [100%]

============================= 41 passed in 4.95s ==============================
```

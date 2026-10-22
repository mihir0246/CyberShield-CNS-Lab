# CyberShield: Cryptography and Network Security Laboratory Practical Manual
## Academic Course Manual for Engineering Students

---

### Mini-Project Overview & Syllabus Integration
The **CyberShield Integrated Laboratory** consolidates nine practical experiments from the undergraduate Cryptography & Network Security syllabus into a unified web application. This manual provides complete academic writeups including Aim, Software Requirements, Theory, Algorithms, Execution Steps, Sample I/O, Observations, Expected Results, Screenshot Checklists, and Viva Voce questions for every experiment.

---

# Practical Experiment 1: Classical Cryptographic Techniques

### 1. Aim
To implement and analyze classical cryptographic algorithms:
1. Caesar Cipher (Monoalphabetic Substitution)
2. Vernam Cipher / One-Time Pad (Polyalphabetic Stream Cipher with XOR)
3. Rail Fence Cipher (Transposition Cipher)

### 2. Required Software & Libraries
- Python 3.12+
- CyberShield Web Platform (`cybershield.services.ciphers`)
- Standard libraries: `secrets`, `base64`

### 3. Theory
- **Caesar Cipher:** Shifts each letter in the plaintext forward or backward by a fixed integer key $k \in [0, 25]$ modulo 26: $C = (P + k) \bmod 26$, $P = (C - k) \bmod 26$.
- **Vernam Cipher (One-Time Pad):** Encrypts plaintext by computing the bitwise XOR between plaintext bytes and a truly random key of equal length: $C = P \oplus K$. Claude Shannon proved that if $K$ is truly random, never reused, kept secret, and as long as $P$, the cipher exhibits information-theoretic perfect secrecy.
- **Rail Fence Cipher:** A transposition cipher that writes characters in a zig-zag pattern across $R$ horizontal rails, then reads characters off row by row.

### 4. Algorithm
#### 4.1 Caesar Cipher
1. Validate shift key $k \in [0, 25]$.
2. For each character $c$ in text:
   - If uppercase letter, compute $c' = \text{chr}((\text{ord}(c) - 65 + k) \bmod 26 + 65)$.
   - If lowercase letter, compute $c' = \text{chr}((\text{ord}(c) - 97 + k) \bmod 26 + 97)$.
   - Otherwise, preserve punctuation/digits/spaces literally.
3. Return concatenated ciphertext.

#### 4.2 Vernam Cipher
1. Encode plaintext string to bytes. Length = $L$.
2. If key provided, validate key length $== L$. Else, generate cryptographically random bytes via OS entropy (`secrets.token_bytes(L)`).
3. Compute $C_i = P_i \oplus K_i$ for $i \in [0, L-1]$.
4. Return hexadecimal and base64 encoded strings.

#### 4.3 Rail Fence Cipher
1. Validate rails count $R \ge 2$.
2. Initialize 2D grid of dimensions $R \times \text{len}(\text{text})$.
3. Traverse text; place characters following zig-zag trajectory, toggling direction when reaching row $0$ or row $R-1$.
4. Read row by row to form ciphertext.

### 5. Step-by-Step Execution
1. Navigate to **1. Classical Ciphers** from the CyberShield navigation sidebar (`http://127.0.0.1:5000/ciphers/`).
2. Select the **Caesar Cipher** tab. Enter text `"CyberShield Lab"` and set Shift to `3`. Click **Encrypt**.
3. Select the **Vernam Cipher** tab. Enter text `"TOP SECRET"`. Click **Generate Key** then click **XOR Encrypt**.
4. Select the **Rail Fence Cipher** tab. Enter `"DEFEND THE EAST WALL"`, set Rails to `3`, and click **Transpose Encrypt**.

### 6. Sample Input & Expected Output
- **Caesar Input:** `"HELLO WORLD"`, Shift = 3
  - **Expected Output:** `"KHOOR ZRUOG"`
- **Vernam Input:** `"SECRET"` (6 bytes), Key = `0xa1b2c3d4e5f6`
  - **Expected Output:** Hexadecimal XOR result string.
- **Rail Fence Input:** `"DEFEND THE EAST WALL"`, Rails = 3
  - **Expected Output:** `"DNETLEEDHESWL F TAA"`

### 7. Observations
- The Caesar cipher preserves character frequency distributions, making it vulnerable to frequency analysis cryptanalysis.
- The Vernam cipher produces uniform random distributions when keys are non-repeating. Reusing a key allows two-time pad attacks: $C_1 \oplus C_2 = P_1 \oplus P_2$.
- The Rail Fence cipher alters character positions without altering their identity.

### 8. Result
Classical substitution and transposition ciphers were successfully implemented, evaluated, and verified through interactive visual traces.

### 9. Screenshots to Capture
- Screenshot of Caesar shift arithmetic trace table.
- Screenshot of Vernam bitwise XOR breakdown table.
- Screenshot of Rail Fence zig-zag transposition matrix view.

### 10. Viva Questions & Answers
- **Q1: Why is the Caesar cipher insecure?**
  *A: The key space is strictly limited to 26 possible shifts, allowing trivial exhaustive brute-force decryption in milliseconds.*
- **Q2: What is the primary operational challenge of the Vernam OTP?**
  *A: Secure key distribution. Because the key must be as long as the plaintext and never reused, transmitting the one-time pad securely requires as much bandwidth as the secret message itself.*
- **Q3: What distinguishes substitution ciphers from transposition ciphers?**
  *A: Substitution ciphers replace characters with other characters, while transposition ciphers rearrange the order of existing characters.*

---

# Practical Experiment 2: Hill Cipher

### 1. Aim
To implement and analyze the polygraphic Hill cipher using matrix multiplication modulo 26, modular matrix inversion, and invertible key validation.

### 2. Required Software & Libraries
- Python 3.12+
- `cybershield.services.ciphers.hill.HillCipher`

### 3. Theory
The Hill cipher assigns letters $A \to 0, B \to 1, \dots, Z \to 25$. Plaintext is divided into vectors of dimension $m$.
- **Encryption:** $C = (K \cdot P) \bmod 26$
- **Decryption:** $P = (K^{-1} \cdot C) \bmod 26$

A key matrix $K$ is invertible modulo 26 if and only if:
1. $\det(K) \ne 0$
2. $\gcd(\det(K) \bmod 26, 26) = 1$

The modular multiplicative inverse of the determinant $d = \det(K) \bmod 26$ satisfies $d \cdot d^{-1} \equiv 1 \pmod{26}$.
The modular inverse matrix is computed via:
$$K^{-1} = (d^{-1} \cdot \text{adj}(K)) \bmod 26$$

### 4. Algorithm
1. Parse matrix dimension $m \in \{2, 3\}$.
2. Calculate determinant $\det(K)$ and $d = \det(K) \bmod 26$.
3. If $\gcd(d, 26) \ne 1$, reject matrix with an error explaining the common factor (2 or 13).
4. Compute $d^{-1} = \text{pow}(d, -1, 26)$.
5. Compute adjugate matrix $\text{adj}(K)$ and inverse matrix $K^{-1} = (d^{-1} \cdot \text{adj}(K)) \bmod 26$.
6. Clean plaintext (strip non-alphabetical characters, convert to uppercase, pad with 'X' to multiple of $m$).
7. Multiply each vector by $K$ modulo 26 for encryption, or by $K^{-1}$ modulo 26 for decryption.

### 5. Step-by-Step Execution
1. Open **2. Hill Cipher** in CyberShield (`http://127.0.0.1:5000/hill/`).
2. Click **Load Valid 2x2** preset ($K = \begin{pmatrix} 3 & 3 \\ 2 & 5 \end{pmatrix}$).
3. Click **Verify Invertibility Mod 26**.
4. Enter plaintext `"HELP"` and click **Encrypt**.
5. Copy the resulting ciphertext `"HIAT"` and click **Decrypt** to recover `"HELP"`.
6. Click **Test Non-Invertible Key** ($K = \begin{pmatrix} 2 & 4 \\ 4 & 6 \end{pmatrix}$) to inspect the rejection diagnostics.

### 6. Sample Input & Expected Output
- Key Matrix: $\begin{pmatrix} 3 & 3 \\ 2 & 5 \end{pmatrix}$, Plaintext: `"HELP"`
  - $\det(K) = (3)(5) - (3)(2) = 15 - 6 = 9$
  - $\gcd(9, 26) = 1$, $9^{-1} \equiv 3 \pmod{26}$ (since $9 \times 3 = 27 \equiv 1$)
  - $\text{adj}(K) = \begin{pmatrix} 5 & -3 \\ -2 & 3 \end{pmatrix} \equiv \begin{pmatrix} 5 & 23 \\ 24 & 3 \end{pmatrix} \pmod{26}$
  - $K^{-1} = 3 \cdot \begin{pmatrix} 5 & 23 \\ 24 & 3 \end{pmatrix} \equiv \begin{pmatrix} 15 & 17 \\ 20 & 9 \end{pmatrix} \pmod{26}$
  - Encrypted Ciphertext: `"HIAT"`

### 7. Observations
- Polygraphic substitution masks single-letter frequencies because identical letters encrypt to different characters depending on their position in the vector block.
- Matrices whose determinants share a common factor with 26 (i.e. even numbers or multiples of 13) cannot be inverted, preventing decryption.

### 8. Result
The Hill cipher was implemented and verified with modular matrix inversion and step-by-step vector multiplication traces.

### 9. Screenshots to Capture
- Screenshot of 2x2 modular matrix inversion calculation.
- Screenshot of non-invertible matrix rejection error alert.
- Screenshot of vector-matrix arithmetic trace table.

### 10. Viva Questions & Answers
- **Q1: Why must $\gcd(\det(K), 26) = 1$?**
  *A: In modular arithmetic modulo 26, an integer has a multiplicative inverse if and only if it is coprime to 26. Since $26 = 2 \times 13$, any determinant divisible by 2 or 13 lacks an inverse.*
- **Q2: How does the Hill cipher defend against frequency analysis?**
  *A: By encrypting blocks of $m$ letters simultaneously (polygraphic substitution), it flattens the unigram frequency distribution of the language.*
- **Q3: What attack is the Hill cipher vulnerable to?**
  *A: Known-plaintext attack. If an attacker captures $m$ linearly independent plaintext-ciphertext vector pairs, the key matrix $K$ can be solved using modular linear algebra.*

---

# Practical Experiment 3: RSA Cryptosystem

### 1. Aim
To generate RSA public/private key pairs with configurable key sizes (1024, 2048, 3072 bits), perform encryption and decryption using RSA-OAEP with SHA-256, and benchmark execution latencies.

### 2. Required Software & Libraries
- Python 3.12+
- `cryptography` package (`hazmat.primitives.asymmetric.rsa`, `padding`, `hashes`, `serialization`)

### 3. Theory
RSA is an asymmetric public-key cryptosystem based on the factoring problem:
1. Select two large primes $p$ and $q$. Modulus $n = p \cdot q$, Euler's totient $\phi(n) = (p-1)(q-1)$.
2. Choose public exponent $e$ such that $1 < e < \phi(n)$ and $\gcd(e, \phi(n)) = 1$ (standard $e = 65537$).
3. Compute private exponent $d \equiv e^{-1} \pmod{\phi(n)}$.
4. **Encryption:** $c = m^e \bmod n$
5. **Decryption:** $m = c^d \bmod n$
6. **Padding:** Textbook RSA is deterministic and homomorphic. CyberShield implements **Optimal Asymmetric Encryption Padding (OAEP)** with SHA-256 and MGF1, providing IND-CCA2 security against padding oracle attacks.

### 4. Algorithm
1. Generate RSA key pair: `rsa.generate_private_key(public_exponent=65537, key_size=bits)`.
2. Serialize public key to PEM (SubjectPublicKeyInfo) and private key to PEM (PKCS#8).
3. Encryption: Pad message with OAEP-MGF1-SHA256 and encrypt with public key.
4. Decryption: Decrypt ciphertext using private key and verify OAEP padding.
5. Benchmark Suite: Measure keygen, encrypt, and decrypt latency across 1024, 2048, and 3072 bit keys.

### 5. Step-by-Step Execution
1. Open **3. RSA Cryptosystem** (`http://127.0.0.1:5000/rsa/`).
2. Select `2048 bits (NIST)` and click **Generate New RSA Keypair**.
3. View public exponent ($e = 65537$), modulus bit length, and max allowable OAEP bytes.
4. Enter message `"CyberShield Asymmetric Test"` and click **Encrypt with Public Key (OAEP)**.
5. Click **Decrypt with Private Key** to verify plaintext recovery.
6. Click **Execute Benchmark Suite** to generate the comparative latency chart.

### 6. Sample Input & Expected Output
- Key Size: 2048 bits
- Plaintext: `"CyberShield Asymmetric Test"`
- Ciphertext: 256 bytes base64 encoded string
- Benchmark Output:
  - 1024-bit: Keygen ~15 ms, Decrypt ~1.5 ms
  - 2048-bit: Keygen ~90 ms, Decrypt ~6.5 ms
  - 3072-bit: Keygen ~350 ms, Decrypt ~18 ms

### 7. Observations
- Key generation and private-key decryption latencies scale cubically ($O(k^3)$), while encryption is fast because $e=65537$ has low Hamming weight.
- 1024-bit RSA is considered legacy/deprecated by NIST; 2048-bit keys provide the recommended standard for current use.

### 8. Result
RSA key generation, OAEP padding, encryption, decryption, and key-size benchmarking were executed and verified.

### 9. Screenshots to Capture
- Screenshot of public/private key PEM display and modulus length.
- Screenshot of OAEP encryption/decryption execution times.
- Screenshot of Key Size vs Execution Time latency bar chart.

### 10. Viva Questions & Answers
- **Q1: Why is textbook RSA without padding insecure?**
  *A: It is deterministic ($m$ always produces $c$) allowing dictionary attacks, and multiplicative homomorphic ($m_1^e \cdot m_2^e = (m_1 m_2)^e$), enabling forgery.*
- **Q2: Why is $e = 65537$ universally chosen as the public exponent?**
  *A: $65537 = 2^{16} + 1$ is a Fermat prime ($F_4$). In binary it is `10000000000000001` (only two 1s), making modular exponentiation require only 17 multiplications.*
- **Q3: What attack does OAEP padding prevent?**
  *A: Bleichenbacher padding oracle attacks and Coppersmith small-exponent attacks by introducing randomized Feistel-network blinding.*

---

# Practical Experiment 4: Diffie–Hellman Key Exchange

### 1. Aim
To demonstrate the Diffie-Hellman key exchange protocol, verify shared secret equality between two independent parties (Alice and Bob), derive symmetric keys via HKDF-SHA256, and explain Man-in-the-Middle vulnerabilities.

### 2. Required Software & Libraries
- Python 3.12+
- `cryptography.hazmat.primitives.asymmetric.dh`
- `cryptography.hazmat.primitives.kdf.hkdf.HKDF`

### 3. Theory
Diffie-Hellman enables two parties to establish a shared secret over an unencrypted channel without prior shared secrets:
1. Public parameters: Large prime $p$, primitive root generator $g$.
2. Alice selects secret $a$, computes $A = g^a \bmod p$, and sends $A$ to Bob.
3. Bob selects secret $b$, computes $B = g^b \bmod p$, and sends $B$ to Alice.
4. Alice computes $S_{\text{Alice}} = B^a \bmod p = (g^b)^a \bmod p$.
5. Bob computes $S_{\text{Bob}} = A^b \bmod p = (g^a)^b \bmod p$.
6. Mathematical Equivalence: $S_{\text{Alice}} = g^{ab} \bmod p = S_{\text{Bob}}$.
7. **Key Derivation:** The raw shared secret is transformed into a cryptographically strong 256-bit symmetric session key using HKDF-SHA256.
8. **Security Limitation:** DH alone does not authenticate endpoints, making it vulnerable to active Man-in-the-Middle (MitM) interception.

### 4. Algorithm
1. Agree on group parameters ($p, g$).
2. Generate private key for Alice: $a \leftarrow \text{Random}()$.
3. Compute Alice's public value: $A = g^a \bmod p$.
4. Generate private key for Bob: $b \leftarrow \text{Random}()$.
5. Compute Bob's public value: $B = g^b \bmod p$.
6. Compute shared secrets: $S_A = B^a \bmod p$, $S_B = A^b \bmod p$.
7. Assert $S_A == S_B$.
8. Pass $S_A$ through HKDF-SHA256 with salt to derive 32-byte AES key.

### 5. Step-by-Step Execution
1. Open **4. Diffie–Hellman** (`http://127.0.0.1:5000/diffie-hellman/`).
2. Click **Run Cryptographic Exchange (2048-bit)**.
3. Observe Alice's public key preview, Bob's public key preview, and the shared secret equality verification badge.
4. Scroll to the **Textbook Mathematical Walkthrough** section ($p=23, g=5, a=6, b=15$).
5. Click **Calculate Step-by-Step Proof** to inspect the intermediate modular arithmetic table.

### 6. Sample Input & Expected Output
- Small Integer Sandbox: $p = 23, g = 5, a = 6, b = 15$
  - Alice: $A = 5^6 \bmod 23 = 15625 \bmod 23 = 8$
  - Bob: $B = 5^{15} \bmod 23 = 19$
  - Alice Secret: $S_A = 19^6 \bmod 23 = 2$
  - Bob Secret: $S_B = 8^{15} \bmod 23 = 2$
  - Verification: $S_A = S_B = 2$ (Match Confirmed)

### 7. Observations
- An eavesdropper observing the public wire sees only $p, g, A, B$. Recovering $a$ or $b$ requires computing the discrete logarithm problem (DLP), which is computationally infeasible for large primes ($p \ge 2048$ bits).
- Unauthenticated DH cannot differentiate Bob from an attacker impersonating Bob.

### 8. Result
The Diffie-Hellman key exchange and HKDF key derivation were demonstrated and verified mathematically.

### 9. Screenshots to Capture
- Screenshot of Alice and Bob dual-party architectural diagram.
- Screenshot of HKDF derived 256-bit symmetric session key.
- Screenshot of step-by-step arithmetic proof table.

### 10. Viva Questions & Answers
- **Q1: What mathematical problem provides Diffie-Hellman's security?**
  *A: The Computational Diffie-Hellman (CDH) problem, which is underpinned by the hardness of the Discrete Logarithm Problem (DLP) over finite fields.*
- **Q2: How does a Man-in-the-Middle attack compromise unauthenticated Diffie-Hellman?**
  *A: An attacker intercepts Alice's public key $A$ and sends their own public key $E_1$ to Bob, while intercepting Bob's $B$ and sending $E_2$ to Alice. The attacker establishes two independent keys and decrypts/re-encrypts all traffic.*
- **Q3: How do modern protocols (like TLS 1.3) mitigate this MitM vulnerability?**
  *A: By signing the ephemeral Diffie-Hellman public keys with digital signature keys (e.g., ECDSA or RSA certificates).*

---

# Practical Experiment 5: MD5 Hashing & Integrity Verification

### 1. Aim
To generate MD5 and SHA-256 digests for text and files, verify file integrity, evaluate hashing latency across multiple message sizes (1 KB to 5 MB), and analyze why MD5 is cryptographically broken under RFC 6151.

### 2. Required Software & Libraries
- Python 3.12+
- Standard library: `hashlib`

### 3. Theory
Cryptographic hash functions map arbitrary-length data to a fixed-length digest:
- **MD5 (RFC 1321):** Generates 128-bit (16-byte) digests using 4 rounds of 16 operations. In 2004, Wang et al. demonstrated practical collision attacks. Today, collisions can be generated in seconds on commodity GPUs. RFC 6151 deprecates MD5 for digital signatures and certificates.
- **SHA-256 (FIPS 180-4):** Part of the SHA-2 family, generates 256-bit digests using a 64-round Merkle-Damgård construction. It maintains robust 128-bit collision resistance with no known practical attacks.

### 4. Algorithm
1. Text Hashing: Feed UTF-8 byte stream into `hashlib.md5()` and `hashlib.sha256()`. Measure CPU time in microseconds.
2. File Hashing: Stream file contents in 64 KB chunks to prevent out-of-memory errors on large uploads.
3. Integrity Check: Compare calculated digest with vendor digest ($D_1 == D_2$).
4. Benchmark Suite: Test payloads $[1\text{KB}, 10\text{KB}, 100\text{KB}, 1\text{MB}, 5\text{MB}]$ over $N$ trials. Compute average latencies and throughput in MB/s.

### 5. Step-by-Step Execution
1. Open **5. MD5 Hash Analysis** (`http://127.0.0.1:5000/hashing/`).
2. In the Text Hash Generator, enter a test string and click **Calculate MD5 & SHA-256**.
3. Observe the digest outputs (MD5: 32 hex chars, SHA-256: 64 hex chars) and microsecond execution timers.
4. In the File Integrity Checksum panel, upload any test document and inspect the streamed hash.
5. In the Multi-Size Benchmark Suite, select `5 Trials` and click **Run Repeated Benchmark**.
6. Inspect the resulting latency bar chart and metrics table.

### 6. Sample Input & Expected Output
- Input: `"CyberShield"`
  - MD5 (128-bit): `9a039755b4bc703e7c80dbb7cf4cbcfd`
  - SHA-256 (256-bit): `583ea24a2512f458e370e0147cb2ecbc33bce3f6c88f7238a8e3f9479b183617`
- Benchmark: MD5 hashes ~15-30% faster than SHA-256, but lacks collision security.

### 7. Observations
- A single-bit change in plaintext causes an avalanche effect where >50% of digest bits flip.
- While MD5 is computationally faster due to smaller state size (128 vs 256 bits), it offers zero protection against collision forgery.

### 8. Result
MD5 and SHA-256 hashing and integrity verification were implemented and empirically benchmarked across data sizes.

### 9. Screenshots to Capture
- Screenshot of MD5 and SHA-256 text hash generation with microsecond badges.
- Screenshot of file integrity comparison alert.
- Screenshot of Multi-Size Benchmark latency chart.

### 10. Viva Questions & Answers
- **Q1: What are the three security properties required of a cryptographic hash function?**
  *A: Pre-image resistance (one-wayness), Second pre-image resistance (weak collision resistance), and Collision resistance (strong collision resistance).*
- **Q2: What is the birthday paradox and how does it relate to hash length?**
  *A: The birthday paradox states that in a group of 23 people, there is a >50% chance two share a birthday. For an $n$-bit hash, a collision can be found in approximately $2^{n/2}$ operations rather than $2^n$. Thus, MD5's 128-bit key requires only $2^{64}$ operations.*
- **Q3: What is the difference between a collision attack and a pre-image attack?**
  *A: In a collision attack, the attacker finds any two inputs $M_1 \ne M_2$ such that $H(M_1) = H(M_2)$. In a pre-image attack, given a specific hash $h$, the attacker finds an input $M$ such that $H(M) = h$.*

---

# Practical Experiment 6: Wireshark & Packet Analysis

### 1. Aim
To dissect network capture files (PCAP/PCAPNG), decode multi-layer protocol hierarchies (Ethernet, IP, TCP, UDP, ICMP, DNS, HTTP), inspect TCP control flags, and examine promiscuous vs. non-promiscuous capture modes.

### 2. Required Software & Libraries
- Python 3.12+
- `scapy` packet analysis engine
- Wireshark 4.x / Npcap

### 3. Theory
- **Packet Dissection:** Raw network frames consist of nested protocol headers. Scapy parses these headers sequentially: Ethernet (Layer 2) $\to$ IP/IPv6 (Layer 3) $\to$ TCP/UDP/ICMP (Layer 4) $\to$ Application Payloads (DNS, HTTP).
- **TCP Control Flags:** Control bits in the TCP header govern session state: SYN (synchronize/handshake), ACK (acknowledgment), FIN (graceful termination), RST (abort connection), PSH (push data to app), URG (urgent pointer).
- **Promiscuous Mode:** Disables NIC hardware MAC filtering so that all physical frames received on the medium are forwarded to the OS. On switched networks, switches forward unicast packets only to the port where the destination MAC resides; promiscuous mode alone does not capture traffic across unrelated switch ports without port mirroring (SPAN) or ARP poisoning.

### 4. Algorithm
1. Stream PCAP packets using Scapy `PcapReader(filepath)`.
2. Extract metadata: frame number, relative arrival time, source/destination IP, transport protocol, source/destination ports, frame length, and TCP flags.
3. Compute protocol distribution totals and aggregate top IP talkers.
4. Support multi-criteria filtering by protocol, IP address, port, and TCP flag.
5. Export filtered telemetry to standard CSV format.

### 5. Step-by-Step Execution
1. Open **6. Wireshark & PCAP** (`http://127.0.0.1:5000/pcap/`).
2. Click **Load Sample Lab PCAP** to ingest the bundled multi-protocol capture.
3. Inspect the Protocol Distribution doughnut chart (HTTP, DNS, TCP, ICMP).
4. Review the Top Talkers table to identify active source endpoints.
5. In the Filters row, select `TCP Flag: SYN` to isolate handshake connection probes.
6. Click **Export Filtered CSV** to download the dissected frames table.
7. Click **Promiscuous Mode Guide** to review hardware filtering theory and Wireshark instructions.

### 6. Sample Input & Expected Output
- File: `samples/sample_capture.pcap` (13 packets)
- Protocol Distribution: HTTP (2), DNS (1), TCP Handshakes (3), ICMP Echo (2), Portscan SYN probes (5).
- Dissected Table shows frame numbers, relative timestamps (e.g., `0.2000s`), flags (`SYN`, `ACK`, `PA`), and payload previews.

### 7. Observations
- Dissecting TCP flags allows rapid identification of scanning patterns (e.g., repeated SYNs without ACKs).
- Application layer payloads (e.g. HTTP GET headers) are visible in cleartext in unencrypted captures.

### 8. Result
PCAP parsing, protocol demultiplexing, multi-criteria filtering, and capture mode analysis were demonstrated and verified.

### 9. Screenshots to Capture
- Screenshot of Protocol Distribution doughnut chart and top talkers.
- Screenshot of Dissected Frames table filtered by SYN flag.
- Screenshot of Promiscuous Mode Analysis modal.

### 10. Viva Questions & Answers
- **Q1: Why does promiscuous mode fail to capture all network traffic on modern switched LANs?**
  *A: Ethernet switches maintain CAM (Content Addressable Memory) tables mapping MAC addresses to physical switch ports. Unicast frames are transmitted exclusively out the destination port.*
- **Q2: What is a 3-way TCP handshake and what flags are exchanged?**
  *A: Client sends SYN $\to$ Server replies with SYN-ACK $\to$ Client sends ACK.*
- **Q3: What does a TCP RST flag indicate?**
  *A: It indicates that the receiving host rejected the connection attempt (e.g., target port is closed or connection was abruptly aborted).*

---

# Practical Experiment 7: Nmap Network Scanning

### 1. Aim
To execute controlled network port scans against authorized targets, identify open/closed/filtered port states, parse machine-readable Nmap XML outputs, and analyze scanning methodologies.

### 2. Required Software & Libraries
- Python 3.12+
- Nmap CLI (v7.9x) or CyberShield authentic XML fallback parser

### 3. Theory
- **TCP Connect Scan (`-sT`):** Completes the full 3-way handshake (`socket.connect()`). Does not require root/admin privileges, but is easily logged by target firewalls.
- **TCP SYN Stealth Scan (`-sS`):** Sends raw SYN packets. If SYN-ACK is received, port is open; host sends RST immediately without completing handshake. Requires raw socket privileges.
- **UDP Port Scan (`-sU`):** Sends empty UDP datagrams. If ICMP Port Unreachable (Type 3, Code 3) is returned, port is closed; no response indicates open|filtered.
- **Port States:**
  - `open`: Target service is actively accepting connections.
  - `closed`: Target host replied with TCP RST or ICMP Port Unreachable.
  - `filtered`: Firewall/filter dropped probe; no response received.

### 4. Algorithm
1. Enforce target whitelist guardrail: Target must be in `ALLOWED_SCAN_TARGETS` (`127.0.0.1, localhost, ::1`).
2. Validate scan type and construct command arguments safely without shell interpolation (`shell=False`).
3. If Nmap is installed, execute with subprocess timeout. If uninstalled, load authentic lab XML report (`samples/sample_nmap.xml`).
4. Parse Nmap XML tree using `xml.etree.ElementTree`. Extract host status, open ports, protocol, service names, and version detection metadata.
5. Persist scan summary to SQLite.

### 5. Step-by-Step Execution
1. Open **7. Nmap Scanner** (`http://127.0.0.1:5000/nmap/`).
2. Verify target is set to `127.0.0.1 (Authorized Lab Host)`.
3. Select scan type `TCP Connect Scan (-sT)`.
4. Enter target ports: `22,80,443,3306,5000,8080`.
5. Click **Execute Authorized Scan**.
6. Inspect the Discovered Host Services table.
7. Click **Load Authentic Sample Scan Report** to inspect pre-recorded multi-port service outputs.

### 6. Sample Input & Expected Output
- Target: `127.0.0.1`, Ports: `22,80,443,3306,5000,8080`
- Results:
  - Port 22/tcp: `open` (OpenSSH 9.3p1)
  - Port 80/tcp: `open` (nginx 1.24.0)
  - Port 443/tcp: `open` (nginx 1.24.0 SSL)
  - Port 3306/tcp: `closed` (mysql)
  - Port 5000/tcp: `open` (Werkzeug httpd / CyberShield Lab Server)
  - Port 8080/tcp: `filtered` (http-proxy)

### 7. Observations
- Connect scan (-sT) generates standard OS sockets without requiring elevated administrator privileges.
- Filtered ports fail to reply within timeout thresholds, indicating packet-filtering firewall drops.

### 8. Result
Authorized network port scanning and machine-readable XML parsing were demonstrated with strict whitelist protections.

### 9. Screenshots to Capture
- Screenshot of scan configuration panel showing authorized target whitelist.
- Screenshot of parsed Nmap XML output displaying port states and version banners.
- Screenshot of Nmap CLI installation guide modal.

### 10. Viva Questions & Answers
- **Q1: What is the primary difference between a SYN scan (-sS) and a Connect scan (-sT)?**
  *A: A Connect scan completes the full 3-way handshake via the OS kernel network stack. A SYN scan sends a raw SYN and tears down the connection with an RST immediately upon receiving SYN-ACK, avoiding full session establishment.*
- **Q2: Why are UDP scans slower and less reliable than TCP scans?**
  *A: UDP is connectionless. Open ports typically send no response to empty probes, while operating systems strictly rate-limit the generation of ICMP Port Unreachable error packets.*
- **Q3: What ethical guidelines govern network scanning?**
  *A: Scanning systems without explicit written authorization is illegal in many jurisdictions. Testing must be restricted to controlled localhost or isolated private lab networks.*

---

# Practical Experiment 8: Controlled DoS Analysis

### 1. Aim
To implement a safe, non-disruptive Denial-of-Service analysis laboratory using synthetic queuing models, evaluate latency degradation, demonstrate token-bucket rate limiting, and analyze Hping3 security options.

### 2. Required Software & Libraries
- Python 3.12+
- `cybershield.services.traffic_analysis.dos_simulator`

### 3. Theory
- **Denial of Service (DoS):** An attack aimed at rendering a computer or network resource unavailable to intended users by saturating system bandwidth, kernel connection state tables, or application CPU threads.
- **TCP SYN Flood:** Exploits the 3-way handshake by transmitting continuous SYN packets with spoofed source IPs without replying to SYN-ACKs, exhausting the server's half-open backlog queue (`backlog` parameter in `listen()`).
- **Defensive Mitigations:**
  - **Token Bucket Rate Limiting:** Enforces a burst cap and steady-state transmission rate. Packets arriving when the token bucket is empty are dropped or queued.
  - **SYN Cookies (RFC 4987):** Encodes connection state into the Initial Sequence Number (ISN) of the SYN-ACK, eliminating the need to allocate memory for half-open sockets until the final ACK arrives.

### 4. Algorithm
1. Simulate timeline for $T$ seconds ($t = 1 \dots T$).
2. Generate baseline traffic $R_{\text{base}}$ with random noise.
3. For attack window $t \in [4, 11]$, inject sinusoidal attack curve peaking at $R_{\text{peak}}$.
4. If rate limiting is enabled:
   - Cap throughput at threshold $R_{\text{thresh}}$.
   - Drop packets exceeding threshold: $D_t = R_t - R_{\text{thresh}}$.
5. Model response latency:
   $$\text{Latency} = 5.0 + \left(\frac{R_{\text{passed}}}{R_{\text{capacity}}}\right)^\alpha \cdot \beta$$
6. Flag anomaly windows where traffic exceeds $2 \times R_{\text{base}}$.

### 5. Step-by-Step Execution
1. Open **8. Controlled DoS Lab** (`http://127.0.0.1:5000/dos/`).
2. Select Attack Profile `TCP SYN Flood`.
3. Set Baseline Traffic to `100 pps` and Peak Flood Volume to `2500 pps`.
4. Ensure **Enforce Rate Limiting Defense** is checked (Threshold = `400 pps`).
5. Click **Run Traffic Simulation**.
6. Observe the Chart.js telemetry: incoming rate, passed rate, and capped latency.
7. Uncheck the rate limiting switch and re-run to observe server buffer saturation and latency spikes.
8. Review the **Hping3 Network Security Tool Study** table.

### 6. Sample Input & Expected Output
- Peak Flood: 2500 pps, Duration: 15 seconds
- **Mitigated Run:** Peak latency remains stable at ~15-20 ms; total packets dropped ~12,000; server availability preserved.
- **Unmitigated Run:** Latency escalates to ~140 ms; CPU reaches 100%; simulation models system buffer collapse.

### 7. Observations
- Without defensive rate limiting, incoming volumetric bursts trigger exponential queuing delay and service degradation.
- Token bucket rate limiting bounds passed traffic to engineered server capacities, ensuring availability for legitimate requests.

### 8. Result
Volumetric DoS traffic profiles, latency degradation curves, and token-bucket defenses were modeled and analyzed non-disruptively.

### 9. Screenshots to Capture
- Screenshot of DoS Simulation telemetry chart showing incoming vs passed rates.
- Screenshot of latency degradation curve comparison (Mitigated vs Unmitigated).
- Screenshot of Hping3 parameter options study table.

### 10. Viva Questions & Answers
- **Q1: How do TCP SYN cookies mitigate SYN flood attacks?**
  *A: The server does not allocate memory in the backlog table upon receiving a SYN. Instead, it computes a cryptographic hash of the client IP, port, and timestamp as the initial sequence number. State is allocated only if the client completes the handshake with a valid ACK.*
- **Q2: What is the purpose of Hping3's `--rand-source` option?**
  *A: It randomizes the source IP address of each transmitted packet, preventing basic perimeter firewalls from blocking the attack based on a single source IP.*
- **Q3: What is the difference between a volumetric DoS attack and an application-layer DoS attack?**
  *A: Volumetric attacks (e.g. UDP/ICMP floods) saturate physical network bandwidth. Application-layer attacks (e.g. Slowloris or complex SQL queries) consume application server threads and CPU without requiring high bandwidth.*

---

# Practical Experiment 9: Snort Intrusion Detection System

### 1. Aim
To inspect Snort IDS sensor status, deconstruct and validate Snort detection rule syntax, parse fast-alert logs, and evaluate intrusion alert classifications.

### 2. Required Software & Libraries
- Python 3.12+
- `cybershield.services.snort.snort_service.SnortService`
- Snort 2.9.x / 3.x (optional for live sensor)

### 3. Theory
- **Intrusion Detection System (IDS):** A passive or inline security system that monitors network traffic for malicious activity or policy violations.
- **Snort Rule Anatomy:**
  Snort rules consist of two logical sections:
  1. **Rule Header:** `action proto src_ip src_port direction dst_ip dst_port`
     - Action: `alert`, `log`, `pass`, `drop`, `reject`
     - Protocol: `tcp`, `udp`, `icmp`, `ip`
     - Direction: `->` (unidirectional) or `<>` (bidirectional)
  2. **Rule Options:** Enclosed in parentheses and separated by semicolons:
     - `msg`: Human-readable alert description
     - `content`: Substring pattern to match in packet payload
     - `nocase`: Case-insensitive payload matching
     - `sid`: Snort Rule Unique Identifier ($< 1,000,000$ reserved for official rules, $\ge 1,000,000$ for custom/lab rules)
     - `priority`: Severity ranking (1 = High/Critical, 2 = Medium, 3 = Low)

### 4. Algorithm
1. Query system PATH for Snort binary. If present, extract version; if absent, flag offline log parsing mode.
2. Rule Explainer: Parse input string via regular expressions:
   Extract `action`, `proto`, `src`, `dst`, and decompose option key-value pairs (`msg`, `content`, `sid`, `priority`).
3. Alert Log Ingestion: Parse Snort fast-alert format lines:
   `MM/DD-hh:mm:ss [**] [gid:sid:rev] Message [**] [Classification: C] [Priority: P] {Proto} src:port -> dst:port`.
4. Persist parsed alerts into SQLite `snort_alerts` table.
5. Export parsed alerts to CSV.

### 5. Step-by-Step Execution
1. Open **9. Snort IDS Analyzer** (`http://127.0.0.1:5000/snort/`).
2. In the Interactive Rule Syntax Explainer, click any educational preset (e.g., `HTTP Directory Traversal Attempt`).
3. Click **Deconstruct Rule Syntax** and inspect the Header and Options breakdown cards.
4. Click **Ingest Sample Snort Alerts** to parse the bundled `samples/sample_snort.log`.
5. Review the Ingested IDS Alert Events table (Priority 1 web attacks, port scans, and ICMP floods).
6. Click **Export CSV** to download the parsed alerts dataset.

### 6. Sample Input & Expected Output
- Rule Input:
  `alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"LAB WEB-MISC Directory Traversal (../)"; content:"../"; nocase; sid:1000002; rev:1; priority:1;)`
- Deconstructed Output:
  - Action: `ALERT`
  - Protocol: `TCP`
  - Source: `$EXTERNAL_NET:any`, Destination: `$HOME_NET:80`
  - Pattern: `../` (Case-insensitive)
  - SID: `1000002`, Priority: `1 (High/Critical)`
- Parsed Alerts: 7 distinct alert records with classifications and source IPs.

### 7. Observations
- Snort rules provide fine-grained pattern matching across protocol headers and raw application layer payloads.
- High-priority alerts (Priority 1) immediately highlight active exploitation attempts, such as path traversal or denial-of-service floods.

### 8. Result
Snort rule anatomy, syntax decomposition, fast-alert log ingestion, and CSV reporting were demonstrated and verified.

### 9. Screenshots to Capture
- Screenshot of Rule Anatomy Breakdown showing action, direction, and options.
- Screenshot of Ingested IDS Alerts stream with priority badges.
- Screenshot of Snort Sensor Configuration guide modal.

### 10. Viva Questions & Answers
- **Q1: What is the difference between an IDS and an IPS?**
  *A: An Intrusion Detection System (IDS) is passive; it monitors traffic and generates alerts without modifying packets. An Intrusion Prevention System (IPS) is inline; it can actively drop malicious packets or reset TCP connections (`drop` or `reject` actions).*
- **Q2: What is the significance of the Snort SID range?**
  *A: SIDs below 1,000,000 are reserved for official Snort core rules and Sourcefire VRT rules. SIDs 1,000,000 and above are designated for custom, local, and academic laboratory rules.*
- **Q3: What does the `nocase` option do in a Snort rule?**
  *A: It instructs the pattern matching engine to perform case-insensitive payload searches, preventing attackers from evading detection by mixing uppercase and lowercase letters.*

---

# Integrated Practical Experiment: Security Event Correlation

### 1. Aim
To execute cross-lab security event correlation by fusing Scapy wire frames, Snort IDS alerts, Nmap port scan findings, and DoS traffic anomalies into unified incident narratives and chronological event timelines.

### 2. Required Software & Libraries
- Python 3.12+
- `cybershield.services.correlation.event_correlator.EventCorrelator`

### 3. Theory
Modern Security Operations Centers (SOCs) do not investigate alert streams in isolation. **Security Information and Event Management (SIEM)** and correlation engines combine multiple telemetry sources:
1. **Reconnaissance Correlation:** Links multi-port SYN probes from raw PCAP captures with Nmap scan findings and Snort portscan alerts (`ET SCAN`).
2. **Exploitation Correlation:** Correlates HTTP GET request payloads with Snort Priority 1 signatures (e.g. Directory Traversal `../`).
3. **Volumetric Correlation:** Connects high-throughput traffic spikes with ICMP/SYN flood signatures.
4. **Temporal Alignment:** Orders all events chronologically to construct an accurate kill-chain narrative.

### 4. Algorithm
1. Query database for recent PCAP frames, Snort alerts, Nmap scan ports, and DoS simulation anomalies.
2. Group events by Source IP address and target port.
3. Apply correlation heuristics:
   - If an IP probes $\ge 3$ distinct destination ports and matches Snort scan rules $\to$ Flag **Reconnaissance & Port Scanning Activity** (Severity: HIGH, Confidence: 92%).
   - If an IP transmits directory traversal patterns matching Snort Priority 1 $\to$ Flag **Web Application Path Traversal Attack** (Severity: CRITICAL, Confidence: 95%).
   - If volumetric traffic exceeds $2 \times$ baseline $\to$ Flag **Volumetric Traffic Anomaly** (Severity: HIGH, Confidence: 85%).
4. Generate unified chronological timeline and persist findings to `correlated_findings`.

### 5. Step-by-Step Execution
1. Ensure sample data is loaded in Experiments 6, 7, 8, and 9.
2. Navigate to **Event Correlation** (`http://127.0.0.1:5000/correlation/`).
3. Click **Execute Cross-Lab Correlation Engine**.
4. Inspect the summary KPI cards (Correlated Incidents, PCAP Frames, Snort Signatures, Open Ports).
5. Review the Correlated Security Findings table (incident titles, severity badges, supporting evidence bullet points, and actionable remediation steps).
6. Scroll down to inspect the Unified Chronological Event Timeline.

### 6. Sample Input & Expected Output
- Telemetry Ingested: 13 PCAP frames, 7 Snort alerts, 6 Nmap ports.
- Correlated Findings Output:
  - `CORR-SCAN-192.168.1.105`: Network Reconnaissance & Port Scanning Activity (Severity: HIGH, Confidence: 92%).
  - `CORR-WEB-192.168.1.105`: Web Application Path Traversal Attack (Severity: CRITICAL, Confidence: 95%).
  - `CORR-DOS-BURST`: Volumetric Traffic Anomaly (Severity: HIGH, Confidence: 85%).

### 7. Observations
- Cross-source correlation eliminates alert fatigue and confirms malicious intent by validating that raw wire packets align with IDS signature triggers.
- Inferred correlations distinguish observed wire frames from synthetic simulations, maintaining academic and forensic integrity.

### 8. Result
Multi-source security event correlation was demonstrated, fusing packet telemetry, scan results, and IDS alerts into an incident response dashboard.

### 9. Screenshots to Capture
- Screenshot of Correlated Telemetry Metrics KPI cards.
- Screenshot of Correlated Security Findings table showing supporting evidence.
- Screenshot of Unified Chronological Event Timeline.

### 10. Viva Questions & Answers
- **Q1: What is event correlation in the context of a Security Operations Center (SOC)?**
  *A: The automated process of associating and linking multiple individual security events and log entries from disparate sensors (firewalls, IDS, packet captures) to detect complex multi-stage attack patterns.*
- **Q2: Why is raw packet inspection alone insufficient for incident detection?**
  *A: Packet analysis provides granular protocol detail but lacks automated signature classification and generates enormous data volumes. Correlating it with IDS alert rules and port scanners contextualizes the raw wire frames.*
- **Q3: What is the Cyber Kill Chain and how does correlation map to it?**
  *A: A framework developed by Lockheed Martin identifying stages of a cyberattack: Reconnaissance $\to$ Weaponization $\to$ Delivery $\to$ Exploitation $\to$ Installation $\to$ Command & Control $\to$ Actions on Objectives. The correlation engine maps early stages (port scans) and delivery/exploitation stages (path traversal) across time.*

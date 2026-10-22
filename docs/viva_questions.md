# Comprehensive Viva Voce & Oral Examination Preparation Guide
## Cryptography and Network Security Laboratory

---

### Category 1: Classical Ciphers & Cryptanalysis

#### Q1: What are Shannon's properties of Confusion and Diffusion, and how do classical ciphers relate to them?
**Answer:**
- **Confusion:** Obscures the relationship between the secret key and the ciphertext (e.g., complex substitution).
- **Diffusion:** Spreads the influence of individual plaintext characters across multiple ciphertext characters (e.g., transposition or polygraphic block substitution).
Classical monoalphabetic ciphers like the Caesar cipher provide minimal confusion and zero diffusion, making them trivial to crack via frequency analysis.

#### Q2: What is the difference between a monoalphabetic and a polyalphabetic cipher?
**Answer:**
- A **monoalphabetic cipher** (e.g., Caesar, simple substitution) maps each letter of the alphabet to a single fixed substitute throughout the entire text.
- A **polyalphabetic cipher** (e.g., Vigenère, Hill, Vernam) uses multiple substitution alphabets or key streams, meaning a single plaintext letter will encrypt to different ciphertext letters at different positions.

#### Q3: Why is the Vernam One-Time Pad (OTP) said to have "perfect secrecy"?
**Answer:**
Claude Shannon proved mathematically that if the key is truly random, as long as the plaintext, kept strictly secret, and used only once:
$$P(\text{Plaintext} = M \mid \text{Ciphertext} = C) = P(\text{Plaintext} = M)$$
Observing the ciphertext reveals zero statistical information about the plaintext. Every possible plaintext of that length is equally probable.

#### Q4: What is a "Two-Time Pad" attack?
**Answer:**
If an attacker intercepts two ciphertexts $C_1 = P_1 \oplus K$ and $C_2 = P_2 \oplus K$ encrypted with the same key $K$, XORing the ciphertexts cancels the key:
$$C_1 \oplus C_2 = (P_1 \oplus K) \oplus (P_2 \oplus K) = P_1 \oplus P_2$$
Using natural language redundancy and space-dragging techniques, both plaintexts can be completely reconstructed.

---

### Category 2: Hill Cipher & Modular Linear Algebra

#### Q5: Under what condition is a matrix invertible modulo 26?
**Answer:**
A square matrix $K$ is invertible modulo 26 if and only if its determinant $\det(K)$ is coprime to 26:
$$\gcd(\det(K) \bmod 26, 26) = 1$$
Because $26 = 2 \times 13$, $\det(K) \bmod 26$ must not be divisible by 2 or 13.

#### Q6: How do you calculate the modular multiplicative inverse of an integer $a$ modulo $m$?
**Answer:**
By using the **Extended Euclidean Algorithm**, which solves Bézout's identity: $a x + m y = \gcd(a, m)$. When $\gcd(a, m) = 1$, $x \bmod m$ is the modular multiplicative inverse: $a \cdot x \equiv 1 \pmod m$.

#### Q7: How does a known-plaintext attack break the Hill cipher?
**Answer:**
For an $m \times m$ matrix, if an attacker obtains $m$ distinct plaintext vectors $P_1, \dots, P_m$ and corresponding ciphertext vectors $C_1, \dots, C_m$, they can form matrix equations:
$$C = K \cdot P \pmod{26} \implies K = C \cdot P^{-1} \pmod{26}$$
If $P$ is invertible modulo 26, the secret key matrix $K$ is directly recovered.

---

### Category 3: RSA & Public Key Cryptography

#### Q8: On what hard mathematical problem is RSA based?
**Answer:**
The **Integer Factorization Problem**. Multiplying two large prime numbers $p$ and $q$ to obtain $n = p \cdot q$ is computationally easy ($O(\log^2 n)$), but finding $p$ and $q$ given only $n$ is computationally intractable for large numbers ($n \ge 2048$ bits) using classical algorithms.

#### Q9: What is Euler's totient function $\phi(n)$ and why is it critical in RSA?
**Answer:**
$\phi(n)$ counts the positive integers up to $n$ that are coprime to $n$. For $n = p \cdot q$ with distinct primes:
$$\phi(n) = (p-1)(q-1)$$
By Euler's theorem, $m^{\phi(n)} \equiv 1 \pmod n$ for $\gcd(m, n) = 1$. This ensures that choosing $e \cdot d \equiv 1 \pmod{\phi(n)}$ allows decryption:
$$(m^e)^d = m^{e \cdot d} = m^{k \phi(n) + 1} \equiv m \pmod n$$

#### Q10: Why is Optimal Asymmetric Encryption Padding (OAEP) necessary in RSA?
**Answer:**
Textbook RSA is deterministic ($m$ always produces the same $c$), allowing dictionary attacks. It is also homomorphic: $E(m_1) \cdot E(m_2) = E(m_1 \cdot m_2 \bmod n)$, allowing malleability attacks. OAEP adds randomized asymmetric Feistel-network padding to achieve IND-CCA2 (indistinguishability under adaptive chosen ciphertext attack) security.

#### Q11: What is the maximum message length that can be encrypted using RSA-2048 with OAEP-SHA256?
**Answer:**
For a 2048-bit key ($256$ bytes) with OAEP using SHA-256 ($hLen = 32$ bytes):
$$\text{Max Bytes} = \text{KeyBytes} - 2 \cdot hLen - 2 = 256 - 64 - 2 = 190 \text{ bytes}$$

---

### Category 4: Diffie–Hellman Key Exchange

#### Q12: How does Diffie-Hellman allow key agreement without transmitting the secret?
**Answer:**
It exploits modular exponentiation commutativity:
$$(g^a)^b \bmod p = g^{ab} \bmod p = (g^b)^a \bmod p$$
Alice and Bob each compute $g^{ab} \bmod p$ independently using their own private exponent and the other party's public value. Eavesdroppers only see $g^a$ and $g^b$, but cannot compute $g^{ab}$ without solving the Discrete Logarithm Problem.

#### Q13: What is the Discrete Logarithm Problem (DLP)?
**Answer:**
Given a prime $p$, a generator $g$, and a value $y = g^x \bmod p$, the Discrete Logarithm Problem is the task of finding the integer exponent $x$. While modular exponentiation is fast, calculating discrete logs over large prime fields is computationally infeasible.

#### Q14: Why must Diffie-Hellman outputs be processed through a Key Derivation Function (KDF)?
**Answer:**
The raw integer secret $g^{ab} \bmod p$ does not have a completely uniform bit distribution across all bits. A cryptographic KDF (such as HKDF-SHA256, RFC 5869) extracts and expands the entropy into a pseudorandom, uniform 256-bit symmetric key suitable for AES-GCM.

---

### Category 5: Hashing & Integrity

#### Q15: Why is MD5 unsuitable for security-sensitive applications today?
**Answer:**
MD5's 128-bit output gives a theoretical collision resistance of at most $2^{64}$. In 2004, Xiaoyun Wang demonstrated practical collision-generating differentials. Today, identical MD5 hash collisions can be generated in seconds on standard laptops, allowing attackers to forge certificates or malware matching legitimate checksums.

#### Q16: What is a length extension attack, and which hash functions are vulnerable?
**Answer:**
Hash functions based on the Merkle-Damgård construction with internal state equal to output size (MD5, SHA-1, SHA-256) are vulnerable. Given $H(M)$ and the length of $M$, an attacker can append data $M'$ and compute $H(M \parallel \text{pad} \parallel M')$ without knowing $M$. SHA-3 (Keccak sponge) and HMAC constructions are immune.

#### Q17: What is the avalanche effect in cryptographic hash functions?
**Answer:**
A design requirement where flipping a single bit in the input message causes an unpredictable change in approximately 50% of the output digest bits, preventing linear cryptanalysis.

---

### Category 6: Packet Analysis & Scapy

#### Q18: What is a PCAP file and how is it structured?
**Answer:**
A PCAP (Packet Capture) file consists of a 24-byte global header (magic number, version, timezone, snapshot length, link-layer header type) followed by sequential packet records, each containing a 16-byte packet header (timestamp seconds, microseconds, captured length, wire length) and the raw serialized frame bytes.

#### Q19: Explain the TCP 3-way handshake and corresponding flags.
**Answer:**
1. Client sends **SYN** (Synchronize) with an initial sequence number (ISN_c).
2. Server replies with **SYN-ACK** (Synchronize + Acknowledgment) confirming ISN_c + 1 with its own ISN_s.
3. Client replies with **ACK** (Acknowledgment) confirming ISN_s + 1. The full-duplex session is established.

#### Q20: What is the role of ARP (Address Resolution Protocol)?
**Answer:**
ARP translates Layer 3 logical IP addresses into Layer 2 physical MAC addresses on local Ethernet broadcast domains using ARP Requests (`Who has IP?`) and unicast ARP Replies.

---

### Category 7: Network Scanning & Nmap

#### Q21: What are the primary differences between TCP Connect (-sT), SYN (-sS), and UDP (-sU) scans?
**Answer:**
- **`-sT` (Connect):** Uses the OS `connect()` API to complete the 3-way handshake. Unprivileged, but heavily logged.
- **`-sS` (SYN Stealth):** Transmits raw SYN packets. Sends RST upon receiving SYN-ACK. Leaves connections half-open; requires raw socket privileges.
- **`-sU` (UDP):** Transmits empty UDP packets. Open ports rarely reply; closed ports return ICMP Port Unreachable. Slow due to OS ICMP rate limits.

#### Q22: What does an Nmap port state of "filtered" mean?
**Answer:**
It means Nmap could not determine whether the port is open or closed because packet filtering (firewall rules, router ACLs) dropped the probe before it reached the target port, or dropped the target's response.

---

### Category 8: Denial of Service (DoS) & Defenses

#### Q23: How does a SYN Flood exhaust server resources?
**Answer:**
When a server receives a SYN, it allocates a Transmission Control Block (TCB) in kernel memory and places the connection in a half-open backlog queue while waiting for the client's final ACK. In a SYN flood, the attacker transmits thousands of SYNs with spoofed or unreachable IPs, filling the backlog queue until legitimate connection requests are dropped.

#### Q24: How does a Token Bucket rate limiter function?
**Answer:**
Tokens are added to a bucket of fixed capacity $B$ at a constant fill rate $R$ tokens/second. Each incoming packet requires 1 token to pass. If tokens are available, the packet passes and 1 token is removed. If the bucket is empty, incoming packets are dropped or queued. This allows controlled burstiness up to $B$ while bounding steady-state traffic to $R$.

#### Q25: What is BCP 38 and why is it important in mitigating DoS attacks?
**Answer:**
Best Current Practice 38 (BCP 38) mandates that Internet Service Providers (ISPs) implement **ingress filtering** to drop outgoing packets whose source IP does not belong to the customer's allocated IP prefix. This eliminates IP spoofing used in reflective amplification and flood attacks.

---

### Category 9: Intrusion Detection & Snort

#### Q26: What are the components of a Snort rule?
**Answer:**
A Snort rule consists of:
1. **Rule Header:** `action protocol src_ip src_port direction dst_ip dst_port` (e.g. `alert tcp $EXTERNAL_NET any -> $HOME_NET 80`)
2. **Rule Options:** Enclosed in parentheses and separated by semicolons (e.g. `msg:"..."; content:"..."; sid:...; rev:...; priority:...;`)

#### Q27: What is the difference between signature-based and anomaly-based IDS?
**Answer:**
- **Signature-based IDS (e.g. Snort):** Compares network traffic against a database of known exploit patterns and byte sequences. Highly accurate with low false positives, but cannot detect unknown (zero-day) attacks.
- **Anomaly-based IDS:** Establishes a baseline of normal network behavior and flags statistical deviations (e.g., sudden traffic surges or unusual port access). Capable of detecting zero-days, but has higher false positive rates.

---

### Category 10: Event Correlation & SOC Engineering

#### Q28: What is Security Event Correlation?
**Answer:**
The automated analysis and fusion of security telemetry from multiple sources (packet captures, IDS alerts, firewall logs, vulnerability scans) to identify patterns, determine attack stages, filter false positives, and present actionable incidents.

#### Q29: How does CyberShield correlate PCAP packets with Snort alerts?
**Answer:**
The correlation engine indexes raw packets and IDS alerts by Source IP, Destination Port, and timestamp. If an IP exhibits multi-port SYN probing in the PCAP and simultaneously triggers Snort portscan alerts (`ET SCAN`), the engine correlates both data points into a single high-confidence finding: **Reconnaissance & Port Scanning Activity**.

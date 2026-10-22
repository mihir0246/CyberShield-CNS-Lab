# CyberShield Security Considerations & Safe Execution Policy

---

## 1. Academic Ethics & Defensive Security Philosophy

CyberShield is built strictly for **educational, defensive, and diagnostic research**. Security engineering laboratories frequently deal with tools capable of dual-use application (reconnaissance, packet capture, flooding, vulnerability enumeration). The application is engineered with structural guardrails ensuring that students cannot inadvertently or maliciously compromise external computing systems.

---

## 2. Specific Security Guardrails

### 2.1 Network Scanning Scope & Target Whitelisting
- **Strict Whitelist Policy:** The Nmap scanner module enforces a hardcoded/environment-configured target whitelist (`ALLOWED_SCAN_TARGETS = 127.0.0.1, localhost, ::1`).
- **No Arbitrary Public Range Scanning:** Any attempt to scan external public IP ranges (e.g., `8.8.8.8` or university CIDR blocks) is intercepted by `NmapService.validate_target()` and immediately rejected with an HTTP 400 response.
- **Command Sanitization:** Subprocess calls pass parameters as strict tokenized arrays (`cmd = [path, "-sT", target]`) with `shell=False`. Shell metacharacters (`;`, `&`, `|`, `` ` ``, `$`, `>`, `<`) trigger immediate validation exceptions.

### 2.2 Controlled Denial-of-Service (DoS) Modeling
- **Zero Real Packet Flooding:** CyberShield deliberately excludes unrestricted packet-flooding loops or raw socket bombardment against external hosts.
- **Synthetic Queuing Simulation:** All DoS experiments operate via statistical queuing models (sinusoidal burst equations, token bucket rate limiters, and server capacity thresholds) executed entirely within process memory.
- **Academic Distinction:** The web UI explicitly identifies synthetic measurements versus real measurements to preserve academic accuracy.

### 2.3 Cryptographic Key & Credential Confidentiality
- **Ephemeral Key Isolation:** RSA private keys (PKCS#8 PEMs) and Vernam one-time pads are never persisted to SQLite database tables. They exist solely in client memory and ephemeral request buffers for educational decryption demonstrations.
- **Standard Cryptographic Padding:** Textbook RSA is rejected in favor of RFC 8017 PKCS#1 v2.2 OAEP padding with SHA-256 and MGF1, preventing Bleichenbacher and Coppersmith small-exponent attacks.
- **Broken Algorithm Disclaimers:** MD5 is prominently labeled with RFC 6151 security advisories. Practical collision risks are demonstrated and contrasted against SHA-256.

### 2.4 File Upload Security & Resource Protection
- **Extension Allowlisting:** Only approved capture and log formats (`.pcap`, `.cap`, `.pcapng`, `.log`, `.txt`, `.xml`) are permitted. Executables (`.exe`, `.sh`, `.bat`, `.php`) are blocked.
- **Size Bounds:** Inbound uploads are capped at 16 MB via Flask's `MAX_CONTENT_LENGTH`.
- **Path Traversal Prevention:** Uploaded filenames are sanitized through Werkzeug's `secure_filename()` before saving to isolated `instance/uploads/` directories.
- **Temporary File Cleanup:** Transient files created during checksum calculation are immediately unlinked upon completion.

### 2.5 Web Application Security Controls
- **Cross-Site Request Forgery (CSRF):** State-changing web forms require `Flask-WTF` CSRF token validation.
- **Security Response Headers:** Global middleware applies:
  - `X-Frame-Options: SAMEORIGIN` (prevents clickjacking)
  - `X-Content-Type-Options: nosniff` (prevents MIME-confusion attacks)
  - `X-XSS-Protection: 1; mode=block`
  - `Referrer-Policy: strict-origin-when-cross-origin`
- **Session Protection:** Session cookies are configured with `HttpOnly=True` and `SameSite=Lax`.

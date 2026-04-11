# Chapter 7: Security Architecture & Threat Model

> *"A security product that can be bypassed by the malware it's supposed to detect is not a security product — it's a false promise."*

---

## 7.1 The Attacker's Perspective

Before understanding ShadowStrike's security architecture, consider who the attacker is. ShadowStrike faces three categories of adversary:

| Adversary | Capability | Goal |
|-----------|-----------|------|
| **Commodity malware** | Known signatures, common packers, script kiddies | Evade detection, persist |
| **Advanced threats (APT)** | Custom tooling, zero-days, living-off-the-land | Disable/blind the sensor |
| **Red teams** | Full knowledge of EDR internals, kernel exploitation | Prove bypass for client |

ShadowStrike assumes **all three simultaneously**. The architecture doesn't optimize for the easy case (commodity malware detected by hash) — it's designed so that even when a sophisticated attacker specifically targets ShadowStrike, the detection chain doesn't collapse.

---

## 7.2 Cryptographic Foundation

### 7.2.1 CryptoManager

The `CryptoManager` (`src/Shared_modules/SelfProtection/CryptoManager.hpp`) is the centralized cryptographic provider. No module implements its own cryptography — every crypto operation flows through this single, auditable interface.

**Symmetric Encryption:**

| Algorithm | Mode | Key Size | Use Case |
|-----------|------|----------|----------|
| AES-256-GCM | AEAD | 256-bit | **Default** — database encryption, IPC |
| AES-128-GCM | AEAD | 128-bit | Performance-sensitive paths |
| AES-256-XTS | Disk | 256-bit | Quarantine file encryption |
| AES-256-CBC | Block | 256-bit | Legacy compatibility only |
| ChaCha20-Poly1305 | Stream AEAD | 256-bit | Software-only environments |

> ⚠️ **Security Note:** AES-256-GCM is the default for all new code. CBC modes exist only for compatibility with legacy quarantine files. New code that uses CBC without justification will be rejected in code review. GCM provides authenticated encryption (integrity + confidentiality) in a single operation — CBC requires a separate HMAC step that developers often forget.

**Asymmetric Cryptography:**

| Algorithm | Key Size | Use Case |
|-----------|----------|----------|
| RSA-2048 | 2048-bit | Minimum for signature verification |
| RSA-4096 | 4096-bit | High-security operations |
| ECDSA P-256/P-384/P-521 | 256/384/521-bit | Modern signatures |
| Ed25519 | 256-bit | **Preferred** — fast, constant-time |
| ECDH P-256/P-384 | 256/384-bit | Key exchange |
| X25519 | 256-bit | **Preferred** — modern key exchange |

**Hash Functions:**

| Algorithm | Output | Status |
|-----------|--------|--------|
| SHA-256 | 32 bytes | **Primary** — file hashing, integrity |
| SHA-384 | 48 bytes | Extended security |
| SHA-512 | 64 bytes | Maximum security |
| SHA3-256/512 | 32/64 bytes | NIST standard, quantum-ready |
| BLAKE2b-256/512 | 32/64 bytes | High-speed hashing |
| BLAKE2s-256 | 32 bytes | Low-memory environments |
| BLAKE3 | 32 bytes | Fastest, parallelizable |
| MD5 / SHA-1 | 16/20 bytes | **Deprecated** — compatibility only |

**Key Derivation Functions:**

| Algorithm | Parameters | Use Case |
|-----------|-----------|----------|
| PBKDF2-SHA256 | 600,000 iterations | Password-based key derivation |
| Argon2id | 64 MB memory, 3 iterations, 4 threads | **Preferred** — memory-hard |
| HKDF-SHA256/SHA512 | N/A | Key expansion from master keys |
| scrypt | Configurable | Alternative to Argon2 |

> 🔬 **Deep Dive:** The PBKDF2 iteration count of 600,000 follows OWASP 2024 recommendations. Argon2id is preferred for new designs because it resists both GPU-based and side-channel attacks through memory-hardness and data-dependent memory access patterns.

### 7.2.2 Key Storage Hierarchy

```
┌──────────────────────────────────────────────────┐
│                    TPM 2.0                         │
│   Hardware-bound keys (root of trust)              │
│   Cannot be extracted, even by kernel code          │
├──────────────────────────────────────────────────┤
│                    DPAPI                            │
│   Windows Data Protection API                       │
│   Keys tied to user/machine credential              │
├──────────────────────────────────────────────────┤
│              Encrypted Memory                       │
│   Runtime keys in SecureBuffer                      │
│   VirtualLock'd, encrypted-at-rest                  │
├──────────────────────────────────────────────────┤
│              Encrypted File                         │
│   Configuration keys in AES-256-GCM files          │
│   DPAPI-protected master key                        │
└──────────────────────────────────────────────────┘
```

```cpp
enum class KeyStorage {
    Memory,     // In-process SecureBuffer (volatile)
    DPAPI,      // Windows DPAPI (user/machine scope)
    TPM,        // TPM 2.0 sealed storage
    HSM,        // Hardware Security Module (future)
    KeyVault,   // Cloud-based (future)
    File        // Encrypted file (DPAPI-wrapped AES key)
};
```

### 7.2.3 Secure Memory Primitives

The CryptoManager provides three secure memory containers:

**SecureBuffer** — Fixed-size encrypted-at-rest buffer:
```cpp
// Data is encrypted in memory when not actively being used
// VirtualLock prevents paging to disk
// SecureZero on destruction
auto key = CryptoManager::Instance().GenerateRandomKey(32);
SecureBuffer buffer(key);
// buffer encrypts its contents between accesses
```

**SecureVector** — Dynamic array with auto-zeroing:
```cpp
// Like std::vector<uint8_t> but:
// - SecureZero on destruction
// - SecureZero on reallocation (old memory is wiped)
// - VirtualLock'd pages
```

**SecureString** — Password storage:
```cpp
// Like std::string but:
// - Constant-time comparison (ConstantTimeCompare)
// - SecureZero on destruction
// - Never logged, even at Trace level
```

**Critical Secure Operations:**

```cpp
// Constant-time memory zeroing (compiler cannot optimize away)
void SecureZero(void* ptr, size_t size);

// Timing-attack resistant comparison
bool ConstantTimeCompare(span<const uint8_t> a, span<const uint8_t> b) noexcept;
```

> ⚠️ **Security Note:** `SecureZero` uses `RtlSecureZeroMemory` on Windows — a compiler intrinsic that is **guaranteed** not to be optimized away. Standard `memset` can be (and often is) removed by the optimizer when the buffer is about to be freed, leaving sensitive data in memory. This is not theoretical — it's a documented class of real-world vulnerability.

---

## 7.3 Self-Protection Architecture

### 7.3.1 The Self-Protection Stack

ShadowStrike protects itself through 10 specialized modules in `src/Shared_modules/SelfProtection/`:

```
┌─────────────────────────────────────────────┐
│            SelfDefense (Coordinator)          │
│  Orchestrates all protection modules          │
├─────────────────────────────────────────────┤
│  ┌──────────────┐  ┌───────────────────┐    │
│  │TamperProtect │  │MemoryProtection   │    │
│  │- Registry    │  │- ASLR enforcement │    │
│  │- Service     │  │- DEP/NX           │    │
│  │- File        │  │- CFG              │    │
│  │- Process     │  │- CET              │    │
│  └──────────────┘  └───────────────────┘    │
│  ┌──────────────┐  ┌───────────────────┐    │
│  │ProcessProtect│  │FileIntegMonitor   │    │
│  │- Handle      │  │- CRC monitoring   │    │
│  │- Termination │  │- Section hashing  │    │
│  │- Injection   │  │- Tamper alerting  │    │
│  └──────────────┘  └───────────────────┘    │
│  ┌──────────────┐  ┌───────────────────┐    │
│  │CertValidator │  │DigSigValidator    │    │
│  │- X.509 chain │  │- Authenticode     │    │
│  │- OCSP/CRL   │  │- Catalog          │    │
│  │- Pinning     │  │- WHQL             │    │
│  └──────────────┘  └───────────────────┘    │
│  ┌──────────────┐  ┌───────────────────┐    │
│  │AntiDebug     │  │CryptoManager      │    │
│  │- IsDebugger  │  │- AES/RSA/ECDSA   │    │
│  │- Hardware BP │  │- Key management   │    │
│  │- Timing      │  │- Secure memory    │    │
│  └──────────────┘  └───────────────────┘    │
└─────────────────────────────────────────────┘
```

### 7.3.2 Memory Protection

**MemoryProtection** (`MemoryProtection.hpp`) enforces hardware and OS security features:

| Protection | Mechanism | Prevents |
|-----------|-----------|----------|
| **ASLR** | High-entropy randomization | ROP/JOP gadget prediction |
| **DEP/NX** | Data Execution Prevention | Stack/heap buffer overflow → code execution |
| **CFG** | Control Flow Guard | Indirect call target validation |
| **CET** | Control-flow Enforcement Technology | Shadow stack for return address protection |
| **Guard Pages** | Heap overflow detection | Heap buffer overflows |
| **VirtualLock** | Prevent paging to disk | Sensitive data exposure in pagefile |
| **Code CRC** | Periodic code section hashing | Inline hook detection |
| **Stack Canaries** | Stack cookie monitoring | Stack buffer overflow |
| **Return Address** | Return address validation | ROP chain execution |

> 🛡️ **Threat Model:** An attacker who achieves code execution in the ShadowStrike process faces: ASLR (can't predict addresses), DEP (can't execute data), CFG (can't redirect control flow), CET (can't manipulate return addresses), and code CRC monitoring (can't patch functions). This is defense-in-depth — each layer assumes the previous one has been bypassed.

### 7.3.3 Process Protection

**ProcessProtection** (`ProcessProtection.hpp`) defends the ShadowStrike process:

- **Handle protection** — prevents `OpenProcess` with dangerous access rights
- **Termination protection** — blocks `TerminateProcess` from unauthorized callers
- **Injection protection** — detects and blocks DLL injection attempts
- **Token integrity** — validates process token integrity level

These protections work in concert with the kernel driver's `ObRegisterCallbacks` (which strips dangerous handle access rights at the kernel level) and process creation callbacks (which can block suspicious process launches).

### 7.3.4 Digital Signature Validation

**DigitalSignatureValidator** (`DigitalSignatureValidator.hpp`) verifies code authenticity:

| Capability | Details |
|-----------|---------|
| **Authenticode** | PE/DLL/SYS/OCX signature verification |
| **Script Signatures** | PS1/VBS/JS signature checking |
| **Catalog Signatures** | Windows catalog-based verification |
| **Dual Signatures** | SHA-1 + SHA-256 (required for Win7 compat) |
| **Timestamps** | RFC 3161 counter-signature validation |
| **WHQL** | Windows Hardware Quality Labs driver certification |
| **EV Code Signing** | Extended Validation certificate detection |
| **Trusted Publishers** | Enterprise trusted publisher list |
| **Blocked Signers** | Known-compromised certificate blocking |

**Certificate Validation Chain:**

```
Binary file
    ↓
[1] Extract Authenticode signature (WinVerifyTrust)
    ↓
[2] Verify signature cryptographic validity
    ↓
[3] Build certificate chain to trusted root
    ↓
[4] Check each certificate for revocation:
    ├─ OCSP (Online Certificate Status Protocol) — real-time
    ├─ CRL (Certificate Revocation List) — cached
    └─ OCSP Stapling — embedded in TLS handshake
    ↓
[5] Verify temporal validity (not expired, not premature)
    ↓
[6] Check against trusted/blocked publisher lists
    ↓
[7] Verify EV status if required
    ↓
SIGNED / UNSIGNED / INVALID / REVOKED / EXPIRED
```

### 7.3.5 Anti-Debugging

**AntiDebug** (`AntiDebug.hpp`) detects analysis attempts:

| Technique | Detection Method |
|-----------|-----------------|
| User-mode debugger | `IsDebuggerPresent()`, `NtQueryInformationProcess` |
| Kernel debugger | `NtQuerySystemInformation(SystemKernelDebuggerInformation)` |
| Hardware breakpoints | `GetThreadContext` — check DR0-DR3 |
| Software breakpoints | Code section CRC (INT3 = 0xCC injection) |
| Timing attacks | RDTSC-based execution timing anomalies |
| VM detection | CPUID leaf analysis (see Ch. 3 of Volume 2) |

> ⚠️ **Security Note:** Anti-debugging is a detection mechanism, not a prevention mechanism. When debugging is detected, ShadowStrike logs the event and adjusts its sensitivity level — it does not crash or self-destruct. An EDR that crashes under analysis is worse than one that reports the analysis attempt to the SOC.

---

## 7.4 Kernel↔User Security Channel

### 7.4.1 Communication Security

The kernel driver (`PhantomSensor.sys`) communicates with the user-mode service via Filter Communication Ports — a secure, kernel-managed IPC mechanism:

```
PhantomSensor.sys                     ShadowStrike.exe
     │                                       │
     ├─ FltCreateCommunicationPort()         │
     │   ├─ SecurityDescriptor: DACL         │
     │   ├─ Connection callback: validate PID│
     │   └─ Message callback: dispatch       │
     │                                       │
     │                 ←── FltConnectPort ───┤
     │                                       │
     ├─ Verify connecting process:           │
     │   ├─ Check digital signature          │
     │   ├─ Check binary hash                │
     │   ├─ Check process integrity level    │
     │   └─ Check parent process chain       │
     │                                       │
     │   ←── Messages (encrypted) ────→      │
     │                                       │
```

### 7.4.2 Session Key Derivation

Once the connection is established, a session key is derived using ECDH:

```cpp
// User-mode side:
auto result = CryptoManager::Instance().DeriveKernelSessionKey(
    driverPublicKey,     // Driver's ECDH public key
    driverBinaryHash,    // SHA-256 of PhantomSensor.sys
    "kernel-session-v1"  // Context label
);
// result.sessionKey — AES-256 key for this session
// result.hmacKey — HMAC key for message integrity

// Verify message from kernel:
bool valid = CryptoManager::Instance().VerifyKernelMessageIntegrity(
    messageBytes,
    hmacBytes,
    result.sessionKey
);
```

---

## 7.5 Input Validation Philosophy

### 7.5.1 Trust Boundaries

ShadowStrike defines explicit trust boundaries:

```
┌─ UNTRUSTED ──────────────────────────────────┐
│  Files on disk (any origin)                    │
│  Network traffic (any source)                  │
│  Registry values (any writer)                  │
│  Process memory (any process)                  │
│  User input (any user)                         │
│  Driver communication (until verified)         │
│  Cloud API responses (until signature-checked) │
└──────────────────────────────────────────────┘

┌─ TRUSTED ────────────────────────────────────┐
│  ShadowStrike binary (signature-verified)      │
│  PhantomSensor.sys (signature-verified)        │
│  Signature database (integrity-checked)        │
│  Configuration (DPAPI-encrypted)               │
│  Session keys (ECDH-derived)                   │
└──────────────────────────────────────────────┘
```

### 7.5.2 Validation Rules

**File Paths:**
```cpp
// NEVER trust a file path from external input without:
// 1. Canonicalization (resolve .., symlinks, junctions)
// 2. Length check (MAX_PATH or extended path limit)
// 3. Character validation (no null bytes, no reserved names)
// 4. Access check (impersonate caller, then open)
```

**File Sizes:**
```cpp
// NEVER trust reported file size:
// 1. Stat the file to get size
// 2. Cap maximum processing size (50 MB for real-time, 500 MB for on-demand)
// 3. Read in chunks, validate as you go
// 4. Abort if actual bytes read exceeds expected size
```

**Network Data:**
```cpp
// NEVER trust network data:
// 1. TLS 1.2+ with certificate pinning
// 2. Signature verification on all server responses
// 3. Size limits on all received payloads
// 4. Schema validation on all JSON/XML
// 5. Rate limiting on all endpoints
```

**Memory Allocations:**
```cpp
// ALWAYS cap allocations:
// 1. Maximum buffer size constants per operation type
// 2. Pre-calculate required size before allocating
// 3. Use SafeInt<> for size arithmetic (overflow-safe)
// 4. Fail fast on allocation failure — never silently continue
```

---

## 7.6 MITRE ATT&CK Coverage

ShadowStrike maps every detection to the MITRE ATT&CK framework. The `BehaviorAnalyzer` covers:

### 7.6.1 Execution (TA0002)

| Technique | ID | Detection Method |
|-----------|-----|-----------------|
| Command & Scripting Interpreter | T1059 | Process creation monitoring, script content analysis |
| Native API | T1106 | API call sequence analysis |
| Shared Modules | T1129 | DLL load monitoring |
| Exploitation for Client Execution | T1203 | Exploit prevention (CFG, DEP, ASLR) |
| User Execution | T1204 | Behavioral context analysis |

### 7.6.2 Persistence (TA0003)

| Technique | ID | Detection Method |
|-----------|-----|-----------------|
| Boot/Logon Autostart | T1547 | Registry monitoring, startup folder |
| Scheduled Task/Job | T1053 | schtasks/at monitoring |
| Valid Accounts | T1078 | Credential access patterns |
| Account Manipulation | T1098 | Account modification events |
| Create Account | T1136 | Account creation monitoring |
| BITS Jobs | T1197 | BITS transfer monitoring |
| Boot/Logon Init Scripts | T1037 | Startup script analysis |

### 7.6.3 Privilege Escalation (TA0004)

| Technique | ID | Detection Method |
|-----------|-----|-----------------|
| Process Injection | T1055 | VirtualAllocEx, WriteProcessMemory monitoring |
| Exploitation for Privilege Escalation | T1068 | Exploit detection (kernel + user) |
| Access Token Manipulation | T1134 | Token impersonation detection |
| Abuse Elevation Control | T1548 | UAC bypass technique detection |

### 7.6.4 Defense Evasion (TA0005)

| Technique | ID | Detection Method |
|-----------|-----|-----------------|
| Obfuscated Files | T1027 | Entropy analysis, packer detection |
| Process Injection | T1055 | Multiple injection technique detection |
| Indicator Removal | T1070 | Log/event tampering detection |
| Modify Registry | T1112 | Critical registry key monitoring |
| Deobfuscate/Decode | T1140 | Dynamic decoding behavior |
| System Binary Proxy | T1218 | LOLBin execution monitoring |
| Impair Defenses | T1562 | Self-protection (tamper detection) |

### 7.6.5 Credential Access (TA0006)

| Technique | ID | Detection Method |
|-----------|-----|-----------------|
| LSASS Memory | T1003.001 | LSASS access monitoring |
| SAM | T1003.002 | SAM file access detection |
| Keylogging | T1056.001 | Hook detection, API monitoring |
| Credential Dumping | T1003 | Mimikatz-like API sequences |

### 7.6.6 Exfiltration (TA0010)

| Technique | ID | Detection Method |
|-----------|-----|-----------------|
| Exfiltration Over C2 | T1041 | Large outbound transfer detection |
| Exfiltration via Web | T1567 | Cloud storage API monitoring |
| DNS Tunneling | T1048.003 | DNS query analysis |
| Archive Collected Data | T1560 | Suspicious archive creation |

---

## 7.7 Secure Development Practices

### 7.7.1 Code Review Requirements

Every code change must pass:
1. **Peer review** — at least one reviewer who understands the security context
2. **Static analysis** — Coverity Scan (0.25 defects/KLoC target)
3. **Warning-free build** — W4 with selected suppressions only
4. **Thread safety review** — all shared state uses appropriate synchronization

### 7.7.2 Banned Functions

The following are banned in production code:

| Banned | Replacement | Reason |
|--------|------------|--------|
| `strcpy` | `StringCchCopy` | Buffer overflow |
| `strcat` | `StringCchCat` | Buffer overflow |
| `sprintf` | `StringCchPrintf` | Buffer overflow |
| `gets` | N/A | Unbounded read |
| `scanf` | Custom parser | Format string attacks |
| `malloc`/`free` | `std::unique_ptr`, RAII containers | Memory leaks |
| `new`/`delete` | Smart pointers | Memory leaks |
| `memset` (for secrets) | `SecureZero` | Compiler optimization |
| `memcmp` (for secrets) | `ConstantTimeCompare` | Timing attacks |

### 7.7.3 Kernel-Specific Bans

| Banned | Replacement | Reason |
|--------|------------|--------|
| `ExAllocatePool` | `ExAllocatePool2` | Deprecated, uninitialized memory |
| `RtlCopyMemory` (untrusted) | `RtlCopyMemory` + ProbeForRead | Missing user buffer validation |
| `ZwCreateFile` (user paths) | Validate + canonicalize first | Path traversal |
| Spin lock at PASSIVE_LEVEL | FAST_MUTEX or ERESOURCE | Excessive CPU usage |

---

## 7.8 Summary

ShadowStrike's security architecture is built on the principle that **every layer assumes the previous layer has been compromised**:

| Layer | Protects Against | Assumes |
|-------|-----------------|---------|
| Kernel callbacks | Process/file/registry tampering | Nothing — first line of defense |
| Self-protection stack | Sensor process manipulation | Kernel is functioning |
| Memory protection | Code injection, ROP, heap corruption | OS ASLR/DEP enabled |
| Cryptographic foundation | Data tampering, credential theft | Hardware (TPM) is trusted |
| Input validation | Malformed data exploitation | Nothing from external sources |
| Code signing validation | Supply chain attacks | Certificate infrastructure |
| MITRE ATT&CK mapping | Coverage gaps in detection | Behavioral data is available |

This is defense-in-depth for a security product — where the product itself is the attack target.

---

*Previous: [Chapter 6 — Error Handling & Logging Infrastructure](ch06-error-handling-logging.md)*
*Next: [Chapter 8 — The Detection Pipeline](ch08-detection-pipeline.md)*

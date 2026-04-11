# Chapter 8: The Detection Pipeline

> *"Every file that touches a protected endpoint passes through this pipeline. A single missed detection is a breach. A single false positive is an incident response team wasting hours."*

---

## 8.1 Pipeline Philosophy

The ShadowStrike detection pipeline processes every file access, process creation, and network connection through a multi-stage analysis chain. The pipeline is designed around two competing requirements:

1. **Real-time decisions in <5ms** — the kernel driver blocks file access until the verdict arrives
2. **Maximum detection coverage** — advanced threats require deep analysis that takes seconds

The solution is a **progressive analysis pipeline** where cheap checks run first. If a file is whitelisted or matches a known hash, the verdict returns in microseconds. Only unknown, suspicious files proceed to expensive analysis stages.

```
                           TIME →
    ┌────────┐
    │ File   │
    │ Access │
    └───┬────┘
        │
        ▼
   ┌─────────────┐  <1ms
   │ [1] Whitelist│────────────→ ALLOW (fast path)
   └──────┬──────┘
          │ miss
          ▼
   ┌─────────────┐  <1ms
   │ [2] Cache   │────────────→ CACHED VERDICT
   └──────┬──────┘
          │ miss
          ▼
   ┌─────────────┐  <2ms
   │ [3] Hash    │────────────→ KNOWN MALWARE / KNOWN CLEAN
   └──────┬──────┘
          │ unknown
          ▼
   ┌─────────────┐  <2ms
   │[4] ThreatInt│────────────→ BAD REPUTATION
   └──────┬──────┘
          │ no match
          ▼
   ┌─────────────┐  <10ms
   │ [5] YARA    │────────────→ PATTERN MATCH
   └──────┬──────┘
          │ no match
          ▼
   ┌─────────────┐  <50ms
   │[6] Heuristic│────────────→ SUSPICIOUS SCORE
   └──────┬──────┘
          │ below threshold
          ▼
   ┌─────────────┐  <100ms
   │[7] Behavior │────────────→ BEHAVIORAL MATCH
   └──────┬──────┘
          │ no match
          ▼
   ┌─────────────┐  <200ms
   │  [8] ML     │────────────→ ML VERDICT
   └──────┬──────┘
          │
          ▼
      FINAL VERDICT
```

---

## 8.2 The Scan Engine

### 8.2.1 Architecture

The `ScanEngine` (`src/Shared_modules/Core/Engine/ScanEngine.hpp`) is a Meyers' Singleton using the PIMPL idiom:

```cpp
class ScanEngine {
public:
    [[nodiscard]] static ScanEngine& Instance();

    [[nodiscard]] bool Initialize(const EngineConfig& config);
    void Shutdown(bool waitForCompletion = true);

    [[nodiscard]] EngineResult ScanFile(const ScanContext& ctx);
    [[nodiscard]] std::future<EngineResult> ScanFileAsync(const ScanContext& ctx);

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};
```

The `Impl` class contains all state — database handles, thread pool references, caches, and configuration. This PIMPL boundary ensures:

1. **ABI stability** — `Impl` changes don't change `ScanEngine`'s header size
2. **Compile firewall** — changes to internal logic don't trigger full rebuilds
3. **Encapsulation** — no implementation details visible to consumers

### 8.2.2 Scan Types

```cpp
enum class ScanType : uint8_t {
    RealTime,        // Kernel-initiated, <5ms budget, high priority
    OnDemand,        // User-initiated full scan, minutes allowed
    Memory,          // Volatile memory scanning (fileless malware)
    Boot,            // Boot-time scan (before full OS load)
    Contextual,      // Right-click "Scan with ShadowStrike"
    Scheduled,       // Automated scheduled scans
    Cloud,           // Cloud-assisted deep analysis
    Forensic         // Full forensic analysis mode
};
```

**Timeout Budgets:**

| Scan Type | Default Timeout | Maximum | Priority |
|-----------|----------------|---------|----------|
| RealTime | 5 seconds | 30 seconds | Critical |
| OnDemand | 30 seconds | 5 minutes | High |
| Memory | 60 seconds | 10 minutes | High |
| Scheduled | 30 seconds | 5 minutes | Normal |
| Forensic | None | None | Low |

### 8.2.3 Scan Context

Every scan carries a `ScanContext` that controls behavior:

```cpp
struct ScanContext {
    ScanType type;                           // Scan type
    ScanPriority priority;                   // Queue priority
    uint32_t processId;                      // Requesting process PID
    std::wstring filePath;                   // Target file path
    bool isNetworkPath;                      // UNC / mapped drive?
    bool isRemovableMedia;                   // USB / CD-ROM?
    std::chrono::milliseconds timeout{5000}; // Scan timeout
    bool stopOnFirstMatch;                   // Return on first detection
    std::string userSid;                     // User security context
    bool scanArchives;                       // Recurse into archives?
    bool scanPacked;                         // Unpack and scan?
    bool deepScan;                           // Enable all analysis stages?
    uint32_t maxNestingDepth;                // Archive nesting limit
    uint32_t maxThreads;                     // Parallelism control
    bool useCache;                           // Use result cache?
    bool submitToCloud;                      // Submit unknown to cloud?
};
```

> 📌 **Key Insight:** `stopOnFirstMatch` is `true` for real-time scans (we need speed, not completeness) and `false` for forensic scans (we need every detection for the incident report). This single flag changes the pipeline from "fast verdict" to "deep analysis" mode.

---

## 8.3 Pipeline Stage 1: Whitelist Check

### 8.3.1 Purpose

The whitelist provides an O(1) fast-path for known-good files. Without it, every Windows system DLL, every signed Microsoft binary, and every user-approved application would flow through the full pipeline on every access — thousands of times per second.

### 8.3.2 Whitelist Store Architecture

The `WhitelistStore` (`src/Shared_modules/Whitelist/WhiteListStore.hpp`) uses:

- **Bloom filter** — probabilistic first check (zero false negatives, configurable false positive rate)
- **Hash index** — B+Tree for exact SHA-256 lookup
- **Pattern index** — Aho-Corasick for path pattern matching
- **String pool** — Deduplicated storage for path strings

```
File access: C:\Windows\System32\ntdll.dll
    │
    ├─ Hash file → SHA-256: a1b2c3...
    │
    ├─ Bloom filter check → MAYBE PRESENT (or DEFINITELY NOT)
    │   │
    │   └─ If maybe: Hash index B+Tree lookup → FOUND
    │       │
    │       └─ Result: Whitelisted (SystemFile)
    │
    └─ ALLOW — skip all further stages
```

**Whitelist Reasons:**

```cpp
enum class WhitelistReason : uint8_t {
    SystemFile     = 0,  // Windows system binary
    TrustedVendor  = 1,  // Signed by trusted vendor
    UserApproved   = 2,  // User manually approved
    PolicyBased    = 3,  // Enterprise policy exclusion
    TemporaryBypass = 4  // Temporary exclusion (time-limited)
};
```

### 8.3.3 Performance

| Operation | Time | Data Structure |
|-----------|------|---------------|
| Bloom filter check | ~100 ns | In-memory bit array |
| Hash index lookup | ~500 ns | Memory-mapped B+Tree |
| Path pattern match | ~1 μs | Aho-Corasick automaton |
| **Total whitelist check** | **<2 μs** | **Combined** |

---

## 8.4 Pipeline Stage 2: Result Cache

### 8.4.1 Purpose

The result cache stores recent scan verdicts keyed by file hash. If a file was scanned 30 seconds ago and hasn't changed, the cached verdict is returned instantly.

### 8.4.2 Cache Configuration

```cpp
// From EngineConfig:
bool enableResultCache = true;
size_t resultCacheSize = 100000;           // 100K entries
std::chrono::minutes resultCacheTTL{15};   // 15-minute TTL
```

### 8.4.3 Cache Invalidation

The cache is invalidated when:
1. **TTL expires** — entries older than `resultCacheTTL` are evicted
2. **File changes** — file modification time changes (kernel notifies)
3. **Signature update** — new signatures may change verdicts for cached files
4. **Manual flush** — administrator requests re-scan

> ⚠️ **Security Note:** Cache invalidation on signature update is critical. Without it, a file that was "clean" yesterday (before the new signature was added) would remain cached as "clean" even though it's now detectable. This is a real-world bypass technique — attackers time their payloads to execute between signature updates and hope the cache protects them.

---

## 8.5 Pipeline Stage 3: Hash Lookup

### 8.5.1 HashStore Architecture

The `HashStore` (`src/Shared_modules/HashStore/HashStore.hpp`) provides O(1) lookup of known malware hashes:

**Data Structures:**
- **Bloom filter** — first-pass probabilistic check
- **Hash buckets** — open-addressing hash table for exact match
- **Memory-mapped files** — database backed by memory-mapped I/O

**Supported Hash Types:**
- SHA-256 (primary — 32 bytes)
- MD5 (legacy — 16 bytes, for compatibility with older IoC feeds)
- SHA-1 (legacy — 20 bytes)
- Fuzzy hashes (SSDEEP, TLSH — for similarity matching)

### 8.5.2 Lookup Flow

```
Input: SHA-256 of file

[1] Bloom filter → NOT IN SET → UNKNOWN (skip to next stage)
                 → MAYBE IN SET
                     ↓
[2] Hash bucket lookup → NOT FOUND → UNKNOWN
                       → FOUND
                           ↓
[3] Return: ThreatName, ThreatLevel, Family, Tags
```

### 8.5.3 Database Size

The HashStore is designed to hold millions of entries:

| Entries | Bloom Filter | Hash Table | Total |
|---------|-------------|------------|-------|
| 1M | ~1.2 MB | ~48 MB | ~50 MB |
| 10M | ~12 MB | ~480 MB | ~500 MB |
| 50M | ~60 MB | ~2.4 GB | ~2.5 GB |

> 📊 **Performance Note:** With memory-mapped I/O, the OS manages which pages are in physical RAM. The working set (frequently accessed hashes) stays hot in memory, while cold entries are paged in on demand. This means a 2.5 GB database doesn't require 2.5 GB of RAM — it requires only enough RAM for the active working set.

---

## 8.6 Pipeline Stage 4: Threat Intelligence Lookup

### 8.6.1 ThreatIntelStore Architecture

The `ThreatIntelStore` (`src/Shared_modules/ThreatIntel/ThreatIntelStore.hpp`) correlates indicators of compromise (IoCs) across multiple dimensions:

**IoC Types Tracked:**
- File hashes (SHA-256, MD5, SHA-1)
- IP addresses (IPv4, IPv6)
- Domain names
- URLs
- Email addresses
- YARA rule names
- MITRE ATT&CK technique IDs
- CVE identifiers

**Feed Management:**

```cpp
// ThreatIntelFeedManager handles:
// - STIX/TAXII feed ingestion
// - CSV/JSON/XML IoC format parsing
// - Automatic feed refresh (configurable interval)
// - Feed source prioritization
// - Deduplication across feeds
// - Confidence score normalization
```

### 8.6.2 Reputation Scoring

Each IoC has a reputation score and confidence level:

```
IoC: evil-domain.com
  ├─ Source: AlienVault OTX (confidence: 85%)
  ├─ Source: Abuse.ch (confidence: 92%)
  ├─ First seen: 2025-01-10
  ├─ Last seen: 2025-01-15
  ├─ MITRE: T1071.001 (Application Layer Protocol: Web)
  └─ Composite score: 89% → HIGH confidence malicious
```

---

## 8.7 Pipeline Stage 5: Signature Scanning (YARA + Pattern Matching)

### 8.7.1 SignatureStore Architecture

The `SignatureStore` (`src/Shared_modules/SignatureStore/SignatureStore.hpp`) combines three detection engines:

1. **Hash signatures** — exact match (delegated to HashStore)
2. **Pattern signatures** — byte pattern matching (Aho-Corasick + Boyer-Moore)
3. **YARA rules** — complex behavioral/structural rules

### 8.7.2 Pattern Matching Algorithms

**Aho-Corasick:**
- Multi-pattern search in O(n + m) time
- Processes all patterns simultaneously in a single file pass
- Used for: byte sequences, string literals, API name detection

**Boyer-Moore:**
- Single-pattern search optimized for long patterns
- Best-case O(n/m) — can skip large portions of the file
- Used for: specific malware signatures, exploit shellcode patterns

**KMP (Knuth-Morris-Pratt):**
- Failure function-based pattern matching
- Guaranteed O(n) worst case
- Used for: patterns where Boyer-Moore's bad character heuristic fails

**SIMD-Accelerated Matching:**
- SSE4.2 `PCMPISTRI` for 16-byte parallel comparison
- AVX2 `VPMOVMSKB` for 32-byte parallel comparison
- Used for: high-throughput scanning of large files

```
PatternStore index structure:

Input file: [byte stream, N bytes]
    │
    ├─ Aho-Corasick automaton scan (all patterns simultaneously)
    │   ├─ Pattern "MZ\x90\x00" → PE header
    │   ├─ Pattern "\x68\x00\x00\x40\x00\xC3" → push/ret (shellcode)
    │   └─ Pattern "HEUR:Trojan.Generic" → heuristic signature
    │
    └─ For each match:
        ├─ Look up full signature rule
        ├─ Validate context (offset, section, conditions)
        └─ Return: ThreatName, ThreatLevel, MITRE mapping
```

### 8.7.3 YARA Rules

The `YaraRuleStore` wraps the YARA engine for complex detection rules:

```yara
rule Ransomware_Generic_FileEncryption {
    meta:
        description = "Detects ransomware file encryption behavior"
        author = "ShadowStrike Research"
        severity = "critical"
        mitre_technique = "T1486"

    strings:
        $crypto1 = "CryptEncrypt" ascii
        $crypto2 = "BCryptEncrypt" ascii
        $ransom1 = "Your files have been encrypted" ascii nocase
        $ransom2 = "bitcoin" ascii nocase
        $ext1 = ".encrypted" ascii
        $ext2 = ".locked" ascii
        $ext3 = ".crypto" ascii

    condition:
        uint16(0) == 0x5A4D and
        (any of ($crypto*)) and
        (any of ($ransom*) or 2 of ($ext*))
}
```

> 📌 **Key Insight:** YARA rules bridge the gap between fast hash matching (binary decision) and slow behavioral analysis (requires execution). A YARA rule can check file structure, string content, byte patterns, and mathematical conditions — all without executing the file. This is critical for detecting threats that evade hash-based detection by changing a single byte.

---

## 8.8 Pipeline Stage 6: Heuristic Analysis

### 8.8.1 Purpose

Heuristic analysis scores files based on structural anomalies that are common in malware but rare in legitimate software:

**PE Header Anomalies:**
- Entry point outside code section
- Section names with non-printable characters
- Extremely high entropy sections (packed/encrypted)
- Missing or corrupted optional header fields
- Unusual number of sections (>10 is suspicious)
- Section with both WRITE and EXECUTE permissions

**Import Table Anomalies:**
- Suspicious API combinations (VirtualAlloc + WriteProcessMemory + CreateRemoteThread)
- API hashing (import by ordinal only, no readable names)
- Empty import table (dynamically resolves all APIs at runtime)
- Imports from unusual DLLs

**Resource Anomalies:**
- Embedded executables in resources
- High-entropy resources (encrypted payloads)
- Resource size > code size (resource-only dropper)

### 8.8.2 Scoring Model

Each anomaly contributes to a composite score:

```
Anomaly                              Score    Max
──────────────────────────────────────────────────
Entry point outside .text            +15      15
RWX section permissions              +20      20
High entropy section (>7.5)          +10      30 (per section)
Suspicious API combo                 +15      45 (per combo)
No imports                           +25      25
Embedded PE in resources             +20      20
Section name obfuscation             +5       15
──────────────────────────────────────────────────
Threshold: 50 → SUSPICIOUS
Threshold: 80 → HIGH CONFIDENCE MALWARE
```

---

## 8.9 Pipeline Stage 7: Behavioral Analysis

### 8.9.1 BehaviorAnalyzer

The `BehaviorAnalyzer` (`src/Shared_modules/Core/Engine/BehaviorAnalyzer.hpp`) performs dynamic analysis — it monitors what a process **does** rather than what it **looks like**.

**Detection Categories:**

| Category | Monitors | Example Technique |
|----------|----------|------------------|
| **Ransomware** | File modification patterns, entropy, shadow copies | T1486 Data Encrypted for Impact |
| **Process Injection** | Remote thread, VirtualAllocEx, process hollowing | T1055 Process Injection |
| **Persistence** | Registry run keys, services, scheduled tasks | T1547 Boot/Logon Autostart |
| **Credential Theft** | LSASS access, SAM database, credential stores | T1003 OS Credential Dumping |
| **Exfiltration** | Large transfers, archive creation, DNS tunneling | T1041 Exfiltration Over C2 |
| **Evasion** | Anti-debug, VM detection, timestomping | T1497 Virtualization/Sandbox Evasion |
| **Privilege Escalation** | UAC bypass, token manipulation | T1548 Abuse Elevation Control |

### 8.9.2 Ransomware Detection (Deep Dive)

Ransomware detection uses a multi-signal approach:

```
Signal                          Weight    Threshold
─────────────────────────────────────────────────────
Rapid file modification (>50/s)    30        —
High-entropy writes (>7.0)         25        —
Shadow copy deletion               40        —
Canary file modification           50        —
File extension mass-change         20        —
Ransom note creation               35        —
─────────────────────────────────────────────────────
Combined score ≥ 70 → BLOCK + QUARANTINE
```

**Canary File System:**
ShadowStrike places hidden "canary" files in common user directories. These files:
- Are invisible to the user (hidden + system attributes)
- Contain known content with known hashes
- Are monitored by the kernel driver's minifilter
- If modified → **immediate ransomware alert** (zero false positives)

> 🛡️ **Threat Model:** The canary system is specifically designed to catch ransomware that encrypts files in directory order. Even if the ransomware evades all other detection stages, modifying a canary file triggers an instant alert. The canary content is randomized per-installation to prevent ransomware authors from building a canary-detection routine.

---

## 8.10 Pipeline Stage 8: Machine Learning

### 8.10.1 ML Architecture

The `ModelInference` module (`src/Shared_modules/AI/ModelInference.hpp`) runs trained neural network models for file classification:

**Feature Extraction:**
- PE structure features (header fields, section characteristics)
- Byte histogram (256 bins)
- Entropy per section
- Import/export table features
- String features (URLs, IPs, suspicious keywords)
- Opcode n-gram features

**Model Types:**
- Random Forest — fast, interpretable, good for PE classification
- Gradient Boosted Trees — high accuracy, slightly slower
- Neural Network — deep feature learning, highest accuracy

### 8.10.2 Inference Pipeline

```
File → FeatureExtractor → Feature Vector (500+ dimensions)
    → ModelInference → Probability (0.0 - 1.0)
    → Threshold (0.7 default) → MALWARE / CLEAN

Latency budget: <200ms for complete inference
```

### 8.10.3 Model Cache

The `ModelCache` module caches loaded model weights in memory to avoid repeated disk I/O:

```cpp
// Models are loaded once at startup:
// - Lazy initialization on first use
// - Pinned in memory (VirtualLock)
// - Version-checked against on-disk model files
// - Automatically reloaded when model updates arrive
```

---

## 8.11 Verdict Aggregation

### 8.11.1 EngineResult Structure

Every pipeline stage contributes to the final `EngineResult`:

```cpp
struct EngineResult {
    ScanVerdict verdict;              // CLEAN / INFECTED / SUSPICIOUS / ...

    // Threat Identity
    std::string threatName;           // "Worm.Win32.Stuxnet"
    std::string threatFamily;         // "Emotet"
    std::string threatCategory;       // "Ransomware"
    SignatureStore::ThreatLevel severity;
    uint64_t threatId;
    std::string detectionSource;      // "HashStore", "YARA", "BehaviorAnalyzer"

    // Confidence
    float confidence;                 // 0.0 - 100.0
    float threatScore;                // Composite weighted score

    // Performance
    uint64_t scanDurationUs;          // Total scan time (microseconds)
    std::string sha256, md5, fuzzyHash;

    // Detailed Findings
    std::vector<std::string> detectionMethods;
    std::vector<std::string> matchedRules;
    std::vector<std::string> suspiciousAPIs;
    std::vector<std::string> indicators;

    // MITRE ATT&CK
    std::vector<std::string> mitreTactics;
    std::vector<std::string> mitreTechniques;

    // Remediation
    bool requiresReboot;
    bool canRemediate;
    std::wstring remediationAction;
};
```

### 8.11.2 Verdict Priority

When multiple stages produce verdicts, the most severe wins:

```
INFECTED (hash match) > INFECTED (YARA) > SUSPICIOUS (heuristic 80+)
    > SUSPICIOUS (behavior) > SUSPICIOUS (ML 0.9+) > PUA > CLEAN
```

If `stopOnFirstMatch` is true (real-time scans), the pipeline stops at the first positive detection.

### 8.11.3 Scan Verdicts

```cpp
enum class ScanVerdict : uint8_t {
    Clean,        // No threats found
    Whitelisted,  // Explicitly allowed
    Infected,     // Confirmed malware
    Suspicious,   // Heuristic score exceeded threshold
    PUA,          // Potentially Unwanted Application
    Adware,       // Adware detected
    Riskware,     // Legitimate but risky software
    Error,        // Scan failed (access denied, locked)
    Timeout,      // Exceeded time budget
    Cancelled     // User cancelled the scan
};
```

---

## 8.12 Callback System

The ScanEngine provides event callbacks for real-time notification:

```cpp
// Detection callback — fires when a threat is found
using ScanDetectionCallback = 
    std::function<void(const EngineResult&)>;

// Completion callback — fires when scan finishes
using ScanCompleteCallback = 
    std::function<void(const ScanStatistics&)>;

// Error callback — fires on scan failure
using ScanErrorCallback = 
    std::function<void(const std::wstring& error, uint32_t errorCode)>;

// Progress callback — fires periodically during long scans
using ScanProgressCallback = 
    std::function<void(const ScanProgress&)>;

// Registration returns a callback ID for later unregistration:
uint64_t id = engine.RegisterDetectionCallback(
    [](const EngineResult& result) {
        if (result.verdict == ScanVerdict::Infected) {
            QuarantineManager::Instance().Quarantine(result);
            AlertSystem::Instance().RaiseAlert(result);
        }
    }
);
```

---

## 8.13 Summary

| Stage | Time Budget | Data Source | Detection Type |
|-------|------------|-------------|---------------|
| Whitelist | <2 μs | Bloom + B+Tree | Known-good exclusion |
| Cache | <1 μs | In-memory LRU | Recent verdict replay |
| Hash | <2 ms | Memory-mapped HashStore | Known malware detection |
| Threat Intel | <2 ms | ThreatIntelStore + feeds | IoC correlation |
| YARA/Pattern | <10 ms | Aho-Corasick + YARA | Structural pattern detection |
| Heuristic | <50 ms | PE analysis | Anomaly scoring |
| Behavior | <100 ms | Kernel + API monitoring | Dynamic threat detection |
| ML | <200 ms | Neural network inference | Unknown threat classification |

The pipeline processes ~50,000 file accesses per second in real-time mode, with the vast majority resolved at stages 1-3 (whitelist, cache, hash). Only truly unknown files reach the expensive analysis stages — and even then, the total pipeline time stays under 200ms.

---

*Previous: [Chapter 7 — Security Architecture & Threat Model](ch07-security-architecture.md)*
*Next: [Chapter 9 — Module Relationships & Dependency Graph](ch09-module-relationships.md)*

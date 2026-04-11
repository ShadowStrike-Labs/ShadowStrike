# Chapter 2: System Architecture Overview

> *"Architecture is not about the components — it is about the constraints between them."*

---

## 2.1 The Layered Defense Model

ShadowStrike Phantom implements **defense in depth** — the principle that no single detection layer should be trusted alone. The system is organized into four horizontal layers, each operating at increasing privilege levels and decreasing performance budgets:

```
Layer 4: Intelligence          (slowest, most accurate)
┌──────────────────────────────────────────────────────────┐
│  PhantomEmulator (sandboxed execution)                   │
│  PhantomCortex (ML classification)                       │
│  Behavioral Correlation (MITRE kill-chain analysis)      │
│  ≈ 10–500ms per sample                                   │
└──────────────────────────────────────────────────────────┘

Layer 3: Deep Analysis         (moderate cost)
┌──────────────────────────────────────────────────────────┐
│  YARA rule scanning (SignatureStore)                     │
│  Heuristic analysis (PE structure, entropy, imports)     │
│  Fuzzy hash comparison (TLSH/ssdeep)                     │
│  ThreatIntel IOC correlation (STIX 2.1)                  │
│  ≈ 1–10ms per sample                                     │
└──────────────────────────────────────────────────────────┘

Layer 2: Fast Lookup           (sub-millisecond)
┌──────────────────────────────────────────────────────────┐
│  HashStore (Bloom filter → B+ tree lookup)               │
│  WhitelistStore (trusted file verification)              │
│  PatternStore (Aho-Corasick multi-pattern match)         │
│  ReputationCache (cached cloud verdicts)                 │
│  ≈ 1–100μs per sample                                    │
└──────────────────────────────────────────────────────────┘

Layer 1: Kernel Observation    (fastest, hardware-level)
┌──────────────────────────────────────────────────────────┐
│  PhantomSensor.sys                                       │
│  Minifilter IRP callbacks · Process/Thread callbacks     │
│  Registry callbacks · Object callbacks · WFP filters     │
│  Kernel cache (known-good/known-bad decisions)           │
│  ≈ 0.1–10μs overhead per operation                       │
└──────────────────────────────────────────────────────────┘
```

The critical insight: **most operations never leave Layer 1 or Layer 2**. The kernel cache resolves the vast majority of file operations. Only genuinely unknown or suspicious items escalate to the expensive Layer 3 and Layer 4 analyses.

> 📊 **Performance Note:** On a typical enterprise workstation running Office, Visual Studio, and web browsers, over 99% of file operations are resolved within 10 microseconds by the kernel cache and whitelist. The full pipeline — including emulation and ML — is reserved for the <1% of truly unknown executables.

---

## 2.2 Subsystem Architecture

### 2.2.1 PhantomSensor.sys — The Kernel Sentinel

The kernel driver is the foundation of the entire platform. Without it, user-mode detection can be trivially bypassed.

**Type:** WDM Minifilter Driver
**Altitude:** 385210
**Source:** `PhantomSensor/PhantomSensor/`
**Size:** ~380,000 lines of C across 241 files

The driver registers callbacks for seven categories of system events:

| Category | Windows API | What It Observes |
|----------|------------|-----------------|
| **File System** | `FltRegisterFilter` (14 IRP_MJ callbacks) | Every file create, read, write, rename, delete |
| **Process** | `PsSetCreateProcessNotifyRoutineEx2` | Every process creation and termination |
| **Thread** | `PsSetCreateThreadNotifyRoutine` | Every thread creation (remote thread detection) |
| **Image Load** | `PsSetLoadImageNotifyRoutine` | Every DLL/EXE load (injection detection) |
| **Registry** | `CmRegisterCallbackEx` | Every registry key/value operation |
| **Object** | `ObRegisterCallbacks` | Process/thread handle operations (self-protection) |
| **Network** | WFP Callout drivers | Network connections and DNS queries |

Additionally, the driver has internal subsystems that do not depend on OS callbacks:

| Subsystem | Purpose |
|-----------|---------|
| **Memory Monitor** | VAD tree analysis, injection chain detection |
| **Syscall Monitor** | Direct syscall / Heaven's Gate / Hell's Gate detection |
| **Behavioral Engine** | MITRE ATT&CK technique scoring with kill-chain correlation |
| **Self-Protection** | Anti-unload, callback guard, code integrity |
| **ALPC Monitor** | Cross-process communication analysis |
| **Transaction Monitor** | NTFS TxF abuse detection (process doppelgänging) |
| **ETW Provider** | Structured telemetry emission |
| **Cache System** | LRU scan result cache with TTL expiry |

> 📌 **Key Insight:** The kernel driver makes *fast, conservative decisions*. It does not perform complex analysis itself — that would risk BSOD on edge cases. Instead, it observes, scores, and escalates to user mode when the score exceeds a threshold. The phrase "observe in kernel, analyze in user mode" is the core design principle.

### 2.2.2 Shared Modules — The Detection Infrastructure

The Shared Modules layer is the algorithmic heart of ShadowStrike. These 23 module families live in `src/Shared_modules/` and provide the detection engines, data stores, and analysis capabilities that the kernel driver feeds into.

**Organized by function:**

#### Data Stores (The Memory)

These modules manage persistent and in-memory stores of threat knowledge:

```
src/Shared_modules/
├── HashStore/          # Known-malware hash database
│   ├── HashStore.hpp   #   Memory-mapped B+ tree
│   ├── BloomFilter.hpp #   Probabilistic fast-reject
│   └── HashBucket.hpp  #   Bucket-level storage
│
├── PatternStore/       # Multi-pattern string matching
│   ├── PatternStore.hpp#   Pattern management
│   ├── AhoCorasick.hpp #   Aho-Corasick automaton
│   ├── BoyerMoore.hpp  #   Boyer-Moore for single patterns
│   └── SIMD_matcher.hpp#   AVX2/SSE4.2 acceleration
│
├── SignatureStore/      # YARA rules + signature database
│   ├── SignatureStore.hpp#  B+ tree with COW updates
│   ├── YaraRuleStore.hpp#   YARA integration
│   └── SignatureBuilder.hpp# Signature creation API
│
├── ThreatIntel/         # Threat intelligence feeds
│   ├── ThreatIntelStore.hpp#   STIX 2.1 IOC storage
│   ├── ThreatIntelFeedManager.hpp# Feed ingestion
│   └── ThreatIntelIndex.hpp#    Fast IOC lookup
│
├── Whitelist/           # Trusted file database
│   ├── WhiteListStore.hpp#  Trust chain verification
│   └── WhiteListBloomFilter.hpp# Fast exclusion check
│
├── FuzzyHasher/         # Approximate matching
│   ├── FuzzyHasher.hpp  #   TLSH + ssdeep
│   └── DigestComparer.hpp#  Similarity scoring
│
└── Database/            # Persistent storage
    ├── QuarantineDB.hpp #   Quarantined file metadata
    ├── LogDB.hpp        #   Detection event logs
    └── ConfigurationDB.hpp# Runtime configuration
```

#### Detection Engines (The Analysts)

These modules perform active threat analysis:

```
src/Shared_modules/
├── PEParser/            # Portable Executable analysis
│   ├── PEParser.hpp     #   Section, import, export parsing
│   └── PEValidation.hpp #   Structure validation
│
├── Core/                # Core detection orchestration
│   ├── ScanEngine.hpp   #   The master scan orchestrator
│   ├── BehaviorAnalyzer.hpp# Dynamic behavior analysis
│   ├── ThreatDetector.hpp#  Threat classification
│   └── FileReputation.hpp#  Reputation scoring
│
├── AntiEvasion/         # Counter-evasion detection
│   ├── VMEvasionDetector.hpp      # VM detection evasion
│   ├── SandboxEvasionDetector.hpp # Sandbox evasion
│   ├── DebuggerEvasionDetector.hpp# Anti-debug evasion
│   ├── PackerDetector.hpp         # Packer identification
│   └── ... (9 detectors total)
│
└── Scripts/             # Script analysis
    ├── PowerShellAnalyzer.hpp     # PowerShell deobfuscation
    ├── JavaScriptAnalyzer.hpp     # JS malware detection
    └── AMSIIntegration.hpp        # AMSI provider
```

#### Real-Time Protection (The Shield)

These modules provide active threat blocking:

```
src/Shared_modules/
├── RealTime/
│   ├── RealTimeProtection.hpp     # Master orchestrator
│   ├── FileSystemFilter.hpp       # On-access scan coordination
│   ├── ProcessCreationMonitor.hpp # Process launch control
│   ├── BehaviorBlocker.hpp        # MITRE-based blocking
│   ├── MemoryProtection.hpp       # ROP/shellcode defense
│   ├── NetworkTrafficFilter.hpp   # C2/DGA/exfil blocking
│   └── ZeroHourProtection.hpp     # Unknown threat handling
│
├── Exploits/
│   ├── ExploitPrevention.hpp      # DEP/ASLR/CFG enforcement
│   ├── ROPProtection.hpp          # Return-oriented programming defense
│   ├── HeapSprayDetector.hpp      # Heap spray detection
│   └── ... (7 modules total)
│
├── RansomwareProtection/
│   ├── RansomwareDetector.hpp     # Pattern-based detection
│   └── ShadowCopyProtection.hpp   # VSS defense
│
└── SelfProtection/
    ├── TamperProtection.hpp       # Anti-tampering
    ├── SelfDefense.hpp            # Process self-defense
    └── ... (10 modules total)
```

#### Infrastructure (The Backbone)

```
src/Shared_modules/
├── Utils/               # Utility library (30+ modules)
│   ├── CryptoUtils.hpp  #   AES, RSA, SHA, HMAC, key management
│   ├── NetworkUtils.hpp #   HTTP/HTTPS, DNS, proxy, adapters
│   ├── FileUtils.hpp    #   Safe file I/O with path validation
│   ├── StringUtils.hpp  #   String conversion (UTF-8/16/32)
│   ├── Logger.hpp       #   Async structured logging
│   └── ThreadPool.hpp   #   Work-stealing thread pool
│
├── Communication/       # IPC and messaging
│   ├── IPCManager.hpp   #   Kernel↔user message bridge
│   ├── AlertSystem.hpp  #   Detection alert routing
│   └── TelemetryCollector.hpp# Event aggregation
│
├── Config/              # Configuration management
│   ├── CortexConfig.hpp #   Centralized configuration
│   └── ... (policy, profiles)
│
├── Service/             # Windows service
│   ├── ServiceCommunication.hpp# Service control
│   └── ...
│
├── Update/              # Update mechanism
│   ├── UpdateManager.hpp#   Binary and signature updates
│   └── DeltaUpdate.hpp  #   Bandwidth-efficient updates
│
└── Performance/         # Performance monitoring
    ├── PerformanceProfiler.hpp# CPU/disk/network profiling
    └── ...
```

### 2.2.3 PhantomEmulator — The Sandbox

When static analysis is inconclusive, ShadowStrike can *execute* the suspicious file in a sandboxed CPU emulator:

```
PhantomEmulator/
├── Core/
│   ├── CPU/
│   │   ├── CpuCore.hpp          # x86/x64 register state
│   │   ├── Decoder.hpp          # Instruction decode
│   │   └── Executor/            # 16 execution modules
│   │       ├── ArithmeticExecutor.hpp
│   │       ├── BranchExecutor.hpp
│   │       ├── SSEExecutor.hpp
│   │       ├── AVX2Executor.hpp
│   │       ├── AESNIExecutor.hpp
│   │       └── ... (16 total)
│   ├── Memory/
│   │   └── MemoryManager.hpp    # Virtual memory (pages, protection)
│   ├── Loader/
│   │   └── PELoader.hpp         # PE loading, import resolution
│   ├── Kernel/
│   │   └── KernelBridge.hpp     # Ring transition emulation
│   └── Threading/
│       └── ThreadManager.hpp    # Multi-thread emulation
│
├── VirtualOS/
│   ├── FileSystem/              # Virtual file system
│   ├── Registry/                # Virtual registry
│   ├── Process/                 # Virtual process table
│   └── AntiEvasion/             # Environment spoofing
│
├── WinAPI/                      # 10 DLLs, 90+ API handlers
│   ├── Kernel32/
│   ├── Ntdll/
│   ├── Advapi32/
│   ├── User32/
│   └── ... (10 total)
│
└── Analysis/
    ├── BehaviorDetector.hpp     # Runtime behavior analysis
    ├── CryptoDetector.hpp       # Encryption pattern detection
    ├── IOCExtractor.hpp         # Indicator extraction
    └── MITREMapper.hpp          # ATT&CK technique mapping
```

> 🛡️ **Threat Model:** The emulator is ShadowStrike's answer to polymorphic and metamorphic malware. When a file is packed or obfuscated beyond static analysis, the emulator executes it in a controlled environment and observes its behavior — API calls, memory allocations, file operations, network attempts — to classify it. The emulated environment spoofs real hardware characteristics to defeat sandbox-detection techniques.

### 2.2.4 PhantomCortex — The AI/ML Engine

PhantomCortex provides machine learning classification using five neural network models:

| Model | Architecture | Purpose | Inference Time |
|-------|-------------|---------|---------------|
| **Static Classifier** | LightGBM | PE feature classification | <0.5ms |
| **Behavioral Classifier** | CNN | Syscall sequence analysis | <0.5ms |
| **Anomaly Detector** | Autoencoder | Novel threat detection | <0.3ms |
| **Sequence Analyzer** | GRU | Temporal behavior patterns | <0.8ms |
| **Ensemble** | MLP | Combined verdict | <0.2ms |

```
PhantomCortex/
├── include/
│   ├── ModelInference.hpp   # C++ ONNX bridge
│   ├── FeatureExtractor.hpp # PE → feature vector
│   └── ModelCache.hpp       # Model lifecycle management
│
├── src/
│   ├── ModelInference.cpp   # ONNX Runtime integration
│   ├── FeatureExtractor.cpp # 256-dimensional feature extraction
│   └── ModelCache.cpp       # Lazy loading, hot-reload
│
└── training/                # Python training pipeline
    ├── train.py             # Model training entry point
    ├── datasets/            # EMBER + custom datasets
    └── models/              # Exported ONNX models
```

> 📌 **Key Insight:** PhantomCortex runs entirely on-device. No samples are sent to a cloud service for classification. This is a deliberate design decision for privacy and offline operation. The models are trained offline and distributed as signed ONNX files.

### 2.2.5 PhantomDisassembler — The Decoder

A custom x86/x64 instruction decoder that ShadowStrike uses internally instead of depending on Zydis or Capstone:

```
PhantomDisassembler/
├── include/
│   ├── PhantomDisasm.hpp    # Public API
│   ├── Instruction.hpp      # Decoded instruction representation
│   ├── Decoder.hpp          # Decode engine
│   ├── Formatter.hpp        # Intel/AT&T syntax output
│   └── Types.hpp            # Opcode tables, register enums
└── src/
    ├── Decoder.cpp          # Core decode logic
    └── Formatter.cpp        # Human-readable output
```

> 💡 **Advanced Note:** Building a custom disassembler eliminates a third-party dependency (Zydis) and gives ShadowStrike full control over instruction decode — critical for syscall detection, ROP analysis, and emulator instruction fetch. The decoder handles all x86/x64 instruction encodings including VEX, EVEX, and legacy prefixes.

---

## 2.3 Inter-Subsystem Communication

The five subsystems communicate through well-defined channels:

### 2.3.1 Kernel ↔ User Mode (FilterConnectPort)

```
PhantomSensor.sys ←──FilterConnectPort──→ Communication Module
                    │                     │
                    │  Messages:           │
                    │  • ScanRequest       │
                    │  • ScanResult        │
                    │  • PolicyUpdate      │
                    │  • ExclusionSync     │
                    │  • TelemetryEvent    │
                    │  • HealthCheck       │
                    │                      │
                    │  Protocol:           │
                    │  • Type-safe structs │
                    │  • Shared headers    │
                    │  • CRC32 integrity   │
                    │  • Sequence numbers  │
                    └──────────────────────┘
```

The IPC protocol uses shared C struct definitions (no serialization framework) for maximum performance. Messages are exchanged through the Windows Filter Communication Port mechanism, which provides kernel-managed security and buffering.

### 2.3.2 User-Mode Module Interaction

Within user mode, modules interact through C++ interfaces:

```
ScanEngine
    │
    ├── calls → WhitelistStore::IsWhitelisted(hash)
    ├── calls → HashStore::Lookup(hash)
    ├── calls → ThreatIntelDatabase::CheckReputation(hash, url, ip)
    ├── calls → SignatureStore::ScanBuffer(data, rules)
    ├── calls → PEParser::Parse(filePath) → PEInfo
    ├── calls → FuzzyHasher::Compare(hash1, hash2) → similarity
    ├── calls → PhantomEmulator::Analyze(filePath) → EmulationResult
    └── calls → PhantomCortex::Inference(features) → Verdict
```

> ⚠️ **Security Note:** All module boundaries validate their inputs. A corrupted PE file passed to `PEParser::Parse()` must not crash the process — it returns an error result. A malformed YARA rule loaded into `SignatureStore` must not cause undefined behavior. Every module assumes hostile input.

### 2.3.3 Data Flow Summary

```
┌────────────────┐
│ File System I/O │
│ Process Create  │         ┌──────────────────┐
│ Registry Write  │────────→│ PhantomSensor.sys│
│ Network Conn.   │         │ (Kernel Driver)  │
│ DLL Load        │         └────────┬─────────┘
└────────────────┘                   │
                                     │ IPC (FilterConnectPort)
                                     ▼
                            ┌────────────────────┐
                            │ Communication      │
                            │ Module             │
                            └────────┬───────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    ▼                ▼                ▼
             ┌────────────┐  ┌────────────┐  ┌────────────┐
             │ ScanEngine │  │ RealTime   │  │ Behavior   │
             │            │  │ Protection │  │ Blocker    │
             └──────┬─────┘  └──────┬─────┘  └──────┬─────┘
                    │               │               │
          ┌────────┼────────┐      │               │
          ▼        ▼        ▼      ▼               ▼
    ┌──────────┐ ┌─────┐ ┌──────┐ ┌─────────┐ ┌────────┐
    │HashStore │ │YARA │ │PE    │ │Memory   │ │MITRE   │
    │PatternSt.│ │Rules│ │Parser│ │Protect  │ │Mapping │
    │WhiteList │ │     │ │      │ │Exploit  │ │        │
    │ThreatInt.│ │     │ │      │ │Prevent  │ │        │
    └──────────┘ └─────┘ └──────┘ └─────────┘ └────────┘
                    │
                    ▼ (if inconclusive)
    ┌──────────────────────────────────────────┐
    │         PhantomEmulator                  │
    │  CPU → Memory → VirtualOS → WinAPI       │
    │         ↓                                │
    │  Analysis: Behavior · IOC · MITRE        │
    └──────────────────┬───────────────────────┘
                       │
                       ▼ (features)
    ┌──────────────────────────────────────────┐
    │         PhantomCortex                    │
    │  Feature Extraction → ONNX Inference     │
    │         ↓                                │
    │  Verdict: Clean / Suspicious / Malicious │
    └──────────────────────────────────────────┘
                       │
                       ▼
    ┌──────────────────────────────────────────┐
    │         Response                         │
    │  Allow / Block / Quarantine / Alert      │
    └──────────────────────────────────────────┘
```

---

## 2.4 Deployment Architecture

ShadowStrike deploys as three Windows components:

### 2.4.1 The Kernel Driver

```
PhantomSensor.sys        → Kernel driver (ring 0)
PhantomSensor.inf        → Driver installation manifest
PhantomSensorELAM.sys    → Early Launch Anti-Malware variant (ring 0, boot-time)
```

The driver is loaded by the Windows Service Control Manager (SCM) as a boot-start or demand-start service. The ELAM variant loads before any other third-party driver, providing protection from the earliest point in the boot sequence.

### 2.4.2 The Service

```
PhantomEDR.exe           → Enterprise service (EDR mode)
PhantomXDR.exe           → Extended detection service (XDR mode)
PhantomHome.exe          → Consumer protection (home use)
```

These are Windows services running as `LocalSystem` that host all user-mode detection logic. They connect to the kernel driver via `FilterConnectCommunicationPort`.

### 2.4.3 Build Configurations

| Configuration | Purpose | Output |
|---------------|---------|--------|
| Debug\|x64 | Development with full symbols and runtime checks | `bin/Debug/` |
| Release\|x64 | Production with optimizations | `bin/Release/` |
| Debug\|ARM64 | ARM64 development (kernel only, future) | `x64/Debug/` |

---

## 2.5 Why This Architecture?

Every architectural decision has a rationale. Here are the key ones:

### Why a kernel minifilter instead of user-mode hooks?

User-mode hooks (IAT patching, inline hooks) can be trivially bypassed by malware that uses direct syscalls. A kernel minifilter is registered with the OS and cannot be bypassed without kernel-level access.

### Why a custom emulator instead of a commercial sandbox?

1. **Control** — ShadowStrike can tune anti-evasion behavior per-sample
2. **Speed** — No VM boot time; emulation starts in microseconds
3. **Transparency** — The emulator's behavior is auditable
4. **Integration** — Deep integration with detection engines (real-time IOC extraction)

### Why on-device ML instead of cloud?

1. **Privacy** — No samples leave the endpoint
2. **Offline** — Detection works without internet connectivity
3. **Latency** — Sub-millisecond inference vs. seconds for cloud roundtrip
4. **Trust** — Users can inspect the models and training data

### Why C++20 instead of Rust?

1. **Ecosystem** — Windows SDK, WDK, COM, and Win32 are C/C++ native
2. **Maturity** — Battle-tested compilers, debuggers, and analysis tools
3. **Performance** — Deterministic memory layout, zero-cost abstractions
4. **Workforce** — More security engineers know C++ than Rust (pragmatic reality)

> 📌 **Key Insight:** Architecture decisions are always tradeoffs. ShadowStrike optimizes for *auditability*, *detection accuracy*, and *enterprise reliability* — in that order. Where these goals conflict (e.g., on-device ML is less accurate than cloud ML with more data), we document the tradeoff and provide configuration options.

---

## 2.6 Summary

ShadowStrike Phantom's architecture is:

- **Layered** — Four defense layers from kernel observation to ML intelligence
- **Modular** — 23+ module families with clean interfaces and no circular dependencies
- **Split** — Kernel observes, user mode analyzes (safety + power)
- **Progressive** — Fast, cheap checks first; expensive, accurate checks only when needed
- **On-device** — All detection happens locally (privacy by design)
- **Auditable** — Every decision path is traceable through logs and telemetry

In the next chapter, we will examine the design patterns and coding conventions that make this architecture work in practice.

---

*Previous: [Chapter 1 — Introduction](ch01-introduction.md)*
*Next: [Chapter 3 — Design Patterns & Conventions](ch03-design-patterns.md)*

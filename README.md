<div align="center">
<a href="https://shadowstrike.dev">
  <img src="https://shadowstrike.dev/logo.png" alt="ShadowStrike Phantom" width="120"/>
</a>

<h1>ShadowStrike Phantom</h1>

<strong>Open-Source Next-Generation Endpoint Protection Platform for Windows</strong>

<br/>
<em>Custom kernel sensor · On-device AI/ML · Full-system emulation engine · 1.5M+ lines of C/C++/ASM</em>

<br/><br/>

[![Status](https://img.shields.io/badge/status-alpha-orange?style=flat-square)](https://github.com/ShadowStrike-Labs/ShadowStrike)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square)](LICENSE.txt)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-lightgrey?style=flat-square)](https://github.com/ShadowStrike-Labs/ShadowStrike)
[![Language](https://img.shields.io/badge/language-C%20%2F%20C%2B%2B20%20%2F%20ASM%20%2F%20Python-orange?style=flat-square)](https://github.com/ShadowStrike-Labs/ShadowStrike)
[![Coverity](https://img.shields.io/badge/Coverity%20Scan-0.25%20defect%2FKLoC-brightgreen?style=flat-square&logo=synopsys)](https://scan.coverity.com/projects/ShadowStrike-Labs-ShadowStrike)
[![Commits](https://img.shields.io/github/commit-activity/w/ShadowStrike-Labs/ShadowStrike?style=flat-square&label=commits%2Fweek)](https://github.com/ShadowStrike-Labs/ShadowStrike/commits/master)
[![LoC](https://img.shields.io/badge/lines%20of%20code-1.5M%2B-blue?style=flat-square)](https://github.com/ShadowStrike-Labs/ShadowStrike)
[![Beta](https://img.shields.io/badge/beta%20target-early%202027-blueviolet?style=flat-square)](https://www.shadowstrike.dev/beta)

[Website](https://www.shadowstrike.dev) · [Architecture](https://www.shadowstrike.dev/architecture) · [Roadmap](https://www.shadowstrike.dev/roadmap) · [Join Beta](https://www.shadowstrike.dev/beta) · [Research](https://www.shadowstrike.dev/research)

</div>

---

### PhantomSensor.sys — Loaded and Verified

<details>
<summary>Driver loaded with ETW tracing active</summary>

<img width="2552" height="1327" alt="PhantomSensor loaded with ETW tracing" src="https://github.com/user-attachments/assets/1bc89108-3c12-414c-b538-df35db11d62f" />

</details>

<details>
<summary>Driver Verifier — all checks passed</summary>

<img width="2506" height="1323" alt="Driver Verifier pass" src="https://github.com/user-attachments/assets/d9e97fcd-9730-453e-a1a3-e9f123ded97d" />

</details>

---

### Support This Project

If you believe in open-source security, consider supporting development:

[![Sponsor ShadowStrike](https://img.shields.io/badge/💝%20Sponsor%20on%20GitHub-ea4aaa?style=for-the-badge)](https://github.com/sponsors/ShadowStrike-Labs)

Your support helps build transparent, auditable endpoint protection that anyone can verify.

---

## What Is ShadowStrike Phantom?

ShadowStrike Phantom is a **from-scratch, open-source endpoint protection platform** for Windows 10/11 x64, engineered to compete with the detection capabilities of commercial EDR/XDR solutions — CrowdStrike Falcon, SentinelOne Singularity, Microsoft Defender for Endpoint — with one fundamental difference: **every line of code is auditable.**

This is not a wrapper around existing tools. This is not a PoC. This is a production-grade security platform comprising **five major subsystems**, each purpose-built from the ground up:

| Subsystem | What It Is | Scale |
|-----------|-----------|-------|
| **[PhantomSensor](#-phantomsensor--kernel-driver)** | WDM minifilter kernel driver with 20 detection subsystems | 380K LoC · 241 source files |
| **[Shared Modules](#-shared-modules--user-mode-detection-infrastructure)** | User-mode detection, protection, and intelligence infrastructure | 500K+ LoC · 461 source files · 23 modules |
| **[PhantomEmulator](#-phantomemulator--malware-emulation-engine)** | Custom x86/x64 CPU emulation engine for safe malware detonation | 300K+ LoC · 195 source files |
| **[PhantomCortex](#-phantomcortex--ondevice-aiml)** | On-device AI/ML threat classification — 5 neural network models | 23K LoC · 56 Python files |
| **[PhantomDisassembler](#-phantomdisassembler--custom-instruction-decoder)** | In-house x86/x64 disassembler replacing third-party dependencies | In development |

> **1.5 million lines** of C, C++20, x86 Assembly, and Python.

> **Current state:** Alpha. Kernel driver is complete and Coverity-verified. PhantomCore is ready. AI models trained on 3.5M+ real PE samples (EMBER 2018 + EMBER 2024). Emulation engine operational. On track for public beta early 2027.

---

## Why This Exists

Commercial endpoint protection products run kernel-level code you cannot inspect. Every major vendor — including those who have caused [global outages](https://en.wikipedia.org/wiki/2024_CrowdStrike_incident) from faulty kernel updates — ships a black box with ring-0 access to your machine.

ShadowStrike Phantom is the alternative:

- **No hidden telemetry.** Every network call the product makes is in the source.
- **No black-box detection.** Every rule, every heuristic, every model weight is auditable.
- **No trust required.** Read the code. Build it. Verify it. Run it on your own infrastructure.

---

## Project Status

| Component | Status | Detail |
|-----------|--------|--------|
| Architecture | ✅ Complete | Designed and documented |
| PhantomSensor.sys | ✅ Complete | 20 subsystems · Coverity 0.25 defect/KLoC · Driver Verifier passed |
| PhantomCore | ✅ Complete | 23 modules — security audit phase |
| PhantomEmulator | ✅ Complete | CPU emulation · 10 DLL stubs · Analysis suite |
| PhantomCortex AI/ML | 🔧 85% | 5 models trained · ONNX inference · Nightly retraining pipeline |
| PhantomDisassembler | ✅ Complete | Custom x86/x64 decoder — replacing Zydis dependency |
| Kernel ↔ User-Mode Wiring | ✅ Complete | Encrypted IPC · Module-by-module integration in progress |
| Product Tiers (Home/EDR/XDR) | 🔧 58% | After shared infrastructure |
| Management Dashboard | 🔧 38% | EDR/XDR fleet management |
| Public Beta | 🎯 1st day of 2027 | |

---

## Platform Architecture

```
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                                      USER MODE                                            │
├──────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                  │
│  │  PhantomEDR  │  │ PhantomHome  │  │ PhantomXDR   │  │  Dashboard   │                  │
│  │  (Service)   │  │    (GUI)     │  │  (Service)   │  │  (Planned)   │                  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────────────┘                  │
│         └──────────────────┴──────────────────┘                                           │
│                            │                                                              │
│  ┌─────────────────────────┴──────────────────────────┐                                  │
│  │           Shared Detection Infrastructure           │                                  │
│  │  ┌────────────────────────────────────────────────┐ │                                  │
│  │  │ RealTimeProtection · ExploitPrevention         │ │                                  │
│  │  │ BehaviorBlocker · ProcessCreationMonitor       │ │                                  │
│  │  │ NetworkTrafficFilter · MemoryProtection        │ │                                  │
│  │  │ FileSystemFilter · ZeroHourProtection          │ │                                  │
│  │  └────────────────────────────────────────────────┘ │                                  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐ │                                  │
│  │  │Signature │ │ Pattern  │ │  Hash    │ │ Threat │ │                                  │
│  │  │  Store   │ │  Store   │ │  Store   │ │ Intel  │ │                                  │
│  │  │ (B-tree) │ │(Aho-Cor.)│ │ (Bloom)  │ │(STIX)  │ │                                  │
│  │  └──────────┘ └──────────┘ └──────────┘ └────────┘ │                                  │
│  │  ┌──────────────────┐  ┌──────────────────────────┐ │                                  │
│  │  │ PhantomEmulator  │  │     PhantomCortex AI     │ │                                  │
│  │  │ x86/x64 CPU Emu  │  │  5 Neural Network Models │ │                                  │
│  │  │ 10 DLL Emulation │  │  ONNX · On-Device · <1ms │ │                                  │
│  │  └──────────────────┘  └──────────────────────────┘ │                                  │
│  └─────────────────────────┬──────────────────────────┘                                  │
│                            │                                                              │
│              ┌─────────────┴─────────────┐                                               │
│              │   Encrypted IPC Bridge    │                                                │
│              │  (FilterConnectPort)      │                                                │
│              └─────────────┬─────────────┘                                               │
├────────────────────────────┼─────────────────────────────────────────────────────────────┤
│                        KERNEL MODE                                                        │
├────────────────────────────┼─────────────────────────────────────────────────────────────┤
│              ┌─────────────┴─────────────┐                                               │
│              │    PhantomSensor.sys       │                                               │
│              │  WDM Minifilter · Alt 385210                                              │
│              │  380K LoC · 20 Subsystems │                                               │
│              └─────────────┬─────────────┘                                               │
│   ┌────────────────────────┼────────────────────────┐                                    │
│   ▼                        ▼                        ▼                                    │
│ ┌──────────────┐ ┌─────────────────────┐ ┌──────────────────┐                            │
│ │ File System  │ │  Process / Thread   │ │ Registry Monitor │                            │
│ │  Callbacks   │ │  Image · Syscall    │ │ Persistence Det. │                            │
│ └──────────────┘ └─────────────────────┘ └──────────────────┘                            │
│ ┌──────────────┐ ┌─────────────────────┐ ┌──────────────────┐                            │
│ │ Memory Mon   │ │  Object Callbacks   │ │ Self-Protection  │                            │
│ │ VAD·ROP·Inj  │ │  Handle Protection  │ │ Anti-Tamper      │                            │
│ └──────────────┘ └─────────────────────┘ └──────────────────┘                            │
│ ┌──────────────┐ ┌─────────────────────┐ ┌──────────────────┐                            │
│ │ Network Flt  │ │  Behavioral Engine  │ │ ETW Telemetry    │                            │
│ │ C2·DGA·Exfil │ │  MITRE · Scoring    │ │ Structured Trace │                            │
│ └──────────────┘ └─────────────────────┘ └──────────────────┘                            │
├──────────────────────────────────────────────────────────────────────────────────────────┤
│                              HARDWARE / FIRMWARE                                          │
│                Secure Boot · TPM Attestation · Firmware Integrity                         │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ PhantomSensor — Kernel Driver

A **From scratch WDM minifilter** kernel driver that intercepts, analyzes, and blocks threats at the lowest software level. Coverity static analysis at **0.25 defects/KLoC**. Driver Verifier: zero violations.

| Subsystem | Techniques Covered |
|-----------|-------------------|
| **Syscall Monitor** | Direct syscall detection · Heaven's Gate (WoW64) · Hell's Gate / Halo's Gate · NTDLL integrity · Callstack origin analysis · SSN validation |
| **Memory Monitor** | VAD tree tracking · Process injection chains · Process hollowing · Reflective DLL loading · Shellcode detection · ROP chains · Heap spray · Code cave detection |
| **Behavioral Engine** | MITRE ATT&CK mapping (550+ TIDs) · Kill-chain correlation · Threat scoring (0–100) · IOC matching · Attack chain tracking · Anomaly detection |
| **File System Callbacks** | Pre/post I/O interception · Ransomware pattern detection (write-rate, entropy, extension analysis) · Rename/delete monitoring · MFT analysis |
| **Process Callbacks** | LOLBin detection · Parent PID spoofing · Token manipulation · Command-line analysis · WSL boundary crossing · Process masquerading |
| **Thread Callbacks** | Remote thread detection · APC injection monitoring · Thread context hijacking · Start address validation |
| **Image Load Callbacks** | DLL injection detection · Reflective loading · Unsigned module tracking · Known-vulnerable driver blocking |
| **Registry Callbacks** | Persistence detection (Run/RunOnce/Services) · Security descriptor tampering · Registry key protection |
| **Network Filter** | C2 beacon detection · DGA domain recognition · DNS anomaly analysis · Data exfiltration detection · TLS metadata inspection |
| **Object Callbacks** | Handle-based self-protection · Suspicion scoring · Handle stripping for protected processes |
| **Self-Protection** | Anti-unload · Callback guard · Runtime `.text` integrity verification · Anti-debug · UEFI variable monitoring |
| **ALPC Monitor** | Advanced Local Procedure Call tracking · Cross-process communication analysis |
| **ETW Provider** | Structured kernel telemetry · Event correlation · Diagnostic tracing |
| **Sync Infrastructure** | Thread pool · Timer manager · Work queue · Deferred procedure calls · Async work queue |
| **Cache System** | Scan cache with LRU eviction · TTL-based expiry · Concurrent access optimization |
| **Transaction Monitor** | NTFS transactional operations · TxF abuse detection (process doppelgänging) |
| **Power Management** | Sleep/hibernate state tracking · Resume-time integrity checks |
| **Exclusion Engine** | Per-process · Per-path · Per-hash exclusion management with kernel-user sync |

### Kernel Technologies
- Windows Filter Manager minifilter — altitude **385210**, 14 operation callbacks
- `PsSetCreateProcessNotifyRoutineEx2` — process lifecycle with LOLBin scoring
- `CmRegisterCallbackEx` — registry monitoring with persistence detection
- `ObRegisterCallbacks` — handle-based self-protection with suspicion scoring
- `/INTEGRITYCHECK` linked for `PsSetCreateProcessNotifyRoutineEx` compliance
- CNG (BCrypt) — kernel-mode SHA-256/MD5 hashing for file reputation
- Memory-mapped shared definitions for kernel↔user-mode type safety

---

## 🧠 PhantomCortex — On-Device AI/ML

Five purpose-built neural network models running inference **locally on each endpoint** — no cloud dependency for detection decisions. Trained on **3.5-3.6M real PE samples** from the EMBER 2018-2024 datasets plus synthetic behavioral, memory, network, and emulation data.

| Model | Architecture | Input | Purpose |
|-------|-------------|-------|---------|
| **Cortex-Static** | LightGBM (gradient boosting) | PE headers, imports, sections, entropy | Static file classification before execution |
| **Cortex-Behavioral** | 1D CNN | API call sequences (512-length) | Runtime behavior pattern recognition |
| **Cortex-Emulation** | GRU (recurrent) | Emulation trace sequences | Malware family classification from sandbox runs |
| **Cortex-Memory** | MLP (feedforward) | Memory region features | Injected code / shellcode detection in process memory |
| **Cortex-Network** | Autoencoder (anomaly) | Network flow features | C2 communication and exfiltration anomaly detection |

### Training Pipeline
- **Nightly automated retraining** with fresh threat intelligence feeds
- **INT8 quantization** for minimal CPU footprint on endpoints
- **ONNX Runtime** inference — sub-millisecond scoring per sample
- **6 threat intel feeds**: EMBER, Feodo Tracker, MalwareBazaar, OTX AlienVault, ThreatFox, URLhaus
- **Feature extraction pipeline** with PE, behavioral, emulation, memory, and network feature modules
- **Model evaluation** with precision/recall/F1 tracking, A/B deployment support

### C++ Inference Bridge (`src/PhantomCore/AI/`)
- `PhantomCortex.cpp` — Singleton orchestrator coordinating all 5 models
- `ModelInference.cpp` — ONNX Runtime integration with thread-safe batch inference
- `ModelCache.cpp` — LRU model cache with secure hash verification
- `FeatureExtractor.cpp` — Real-time feature extraction from scan pipeline
- `CortexConfig.cpp` — Dynamic model configuration with hot-reload

---

## 🔬 PhantomEmulator — Malware Emulation Engine

A **custom-built x86/x64 CPU emulation engine** for safe malware detonation and analysis — no hypervisor dependency, no third-party emulation library. Designed to execute and analyze packed, obfuscated, and evasion-aware malware in a fully controlled virtual environment.

### Core Engine
| Component | Description |
|-----------|-------------|
| **CPU Emulator** | Full x86/x64 instruction execution — arithmetic, logic, control flow, stack, string, FPU, SSE2, SSE4, AES-NI |
| **Instruction Decoder** | Custom decoder with VEX/EVEX/AVX-512 prefix support and YMM register handling |
| **JIT Compiler** | Just-in-time compilation framework for hot-path acceleration |
| **Virtual Memory** | Page-level memory management with protection flags, guard pages, and access tracking |
| **PE Loader** | Full PE32/PE32+ loading — imports, exports, relocations, TLS callbacks, resources, shellcode injection |
| **Thread Scheduler** | Cooperative multi-threading with synchronization primitives (mutex, event, semaphore, critical section) |

### Windows API Emulation — 10 DLLs, 90+ API Handlers
| DLL | Emulated APIs |
|-----|--------------|
| **kernel32.dll** | File I/O · Memory · Process · Thread · Console · Library · APC Injection · File Mapping · Sync · Time · Environment · Strings |
| **ntdll.dll** | Nt/Zw File · Memory · Process · Thread · Registry · System Info · Token · Loader · RTL · Syscall dispatch |
| **advapi32.dll** | Registry · Service · Security · Credential access |
| **ws2_32.dll** | Socket · Connect · Send/Recv · DNS resolution |
| **winhttp.dll** | HTTP sessions · Request/Response · TLS |
| **wininet.dll** | Internet sessions · FTP · HTTP · Cache |
| **ole32.dll** | COM initialization · Object creation |
| **shell32.dll** | Shell execution · File operations |
| **user32.dll** | Window messages · Screen capture · Input |
| **urlmon.dll** | URL download · MIME detection |

### Virtual OS Environment
- **Virtual File System** — Isolated FS with pre-seeded Windows directory structure
- **Virtual Registry** — Full HKLM/HKCU emulation with common key population
- **Virtual Network** — Simulated DNS, HTTP, and socket responses for C2 detonation
- **Virtual Process** — Process environment block (PEB/TEB) emulation

### Anti-Evasion Countermeasures
- **Timing anti-evasion** — Accelerated tick counts, `QueryPerformanceCounter` spoofing, `GetTickCount` manipulation
- **Debugger anti-evasion** — `IsDebuggerPresent` returns false, PEB flags cleaned, NtQueryInformationProcess spoofed
- **Environment anti-evasion** — Realistic CPU/RAM/disk metrics, proper username/computername, registry artifacts
- **VM anti-evasion** — No hypervisor artifacts, realistic CPUID responses, clean SMBIOS/DMI data

### Analysis Suite — 12 Analyzers
| Analyzer | Capability |
|----------|-----------|
| **APISequenceAnalyzer** | Markov chain API call pattern analysis · n-gram extraction · Sequence similarity scoring |
| **BehaviorMonitor** | 150 behavioral rules covering fileless, LOLBin, injection, credential theft, evasion, ransomware |
| **CryptoDetector** | AES/Twofish/Serpent/ECC detection · Encoding/obfuscation · Ransomware crypto patterns |
| **EvasionDetector** | Anti-debug, anti-VM, anti-sandbox technique identification |
| **IOCExtractor** | IP/domain/URL/email/hash/mutex/registry IOC extraction from emulation traces |
| **MemoryForensics** | Process memory diff analysis · Injected code detection · Unpacking artifact recovery |
| **MITREMapper** | Automatic MITRE ATT&CK technique attribution from observed behaviors |
| **NetworkBehaviorAnalyzer** | C2 signature matching · JA3 fingerprinting · TLS analysis · P2P detection · HTTP header profiling |
| **StringExtractor** | ASCII/Unicode/stack-constructed string recovery from emulation memory |
| **ThreatScorer** | Multi-signal threat scoring with weighted evidence aggregation |
| **UnpackingEngine** | Runtime unpacking with OEP detection · Multi-layer unpacking · 100+ packer signatures |
| **PerformanceProfiler** | Instruction-level profiling for emulation optimization |

### Integration
- **KernelIPCBridge** — Direct communication with PhantomSensor.sys for kernel-assisted analysis
- **ResultConverter** — Translates emulation results to unified detection events
- **EmulationSession** — Orchestrates full sample analysis with timeout and resource limits

---

## 🔧 PhantomDisassembler — Custom Instruction Decoder

> **Status: In Development**

A from-scratch x86/x64 instruction decoder being built to replace the Zydis third-party dependency. Goal: zero external dependencies for instruction-level analysis across the entire platform.

The PhantomEmulator's existing instruction decoder (VEX/EVEX/AVX-512 support) serves as the foundation.

---

## 🔍 PhantomCore - Main Malware Hunting Engine which is shared for the Phantom EDR - XDR - Home products

**23 module families** comprising the user-mode detection, protection, and intelligence stack:

### Real-Time Protection Layer
| Module | Role |
|--------|------|
| **RealTimeProtection** | Master orchestrator — coordinates all detection engines |
| **ExploitPrevention** | ROP · JIT spray · Stack pivot · Heap spray · Kernel exploit detection · DEP/ASLR/CFG/CET enforcement |
| **BehaviorBlocker** | Real-time behavioral analysis with MITRE ATT&CK correlation |
| **FileSystemFilter** | On-access scan orchestration · LRU cache · Kernel minifilter communication |
| **NetworkTrafficFilter** | C2 beacon analysis · DGA detection · Exfiltration monitoring · WFP integration |
| **ProcessCreationMonitor** | LOLBin classification · Parent-child validation · Command-line analysis · Masquerading detection |
| **MemoryProtection** | DEP enforcement · Guard pages · W^X policy · ROP/shellcode/reflective DLL detection |
| **ZeroHourProtection** | Zero-day cloud verdict · Adaptive heuristics · Outbreak mode |
| **FileIntegrityMonitor** | Critical system file integrity verification |
| **AccessControlManager** | Fine-grained access policy enforcement |

### Detection Data Stores
| Store | Technology |
|-------|-----------|
| **SignatureStore** | Custom B-tree index · YARA rule integration · Copy-on-write updates · Bulk import |
| **PatternStore** | Aho-Corasick automaton · Boyer-Moore · KMP failure functions · SSE4.2/AVX2 SIMD acceleration |
| **HashStore** | Bloom filter (0.001% FP) · Memory-mapped DB · O(1) reputation lookups |
| **FuzzyHasher** | Custom approximate hash engine · Clean-room implementation · Zero GPL dependencies |
| **ThreatIntel** | STIX 2.1 / TAXII 2.1 ingestion · Sharded B-tree index · LRU cache · IOC correlation |
| **Whitelist** | Hash + pattern whitelisting · Bloom filter · Publisher trust chains |

### Core Detection Modules
| Category | Modules |
|----------|---------|
| **Process** | ProcessAnalyzer · ProcessInjectionDetector · ProcessHollowingDetector · AtomBombingDetector · DLLInjectionDetector · ReflectiveDLLDetector · ThreadHijackDetector · MemoryScanner · ProcessMonitor · ProcessKiller |
| **File System** | DirectoryMonitor · FileWatcher · FileHasher · FileTypeAnalyzer · ExecutableAnalyzer · ArchiveExtractor · DocumentScanner · MediaFileScanner · FileLockManager · MountPointMonitor · FileReputation |
| **Network** | NetworkMonitor · DNSMonitor · BotnetDetector · FirewallManager · DDosProtection · EmailScanner · TorDetector · P2PMonitor · WebProtection |
| **Registry** | RegistryAnalyzer · EventLogger |
| **Engine** | ScanEngine · ThreatDetector · HeuristicAnalyzer · QuarantineManager · PolymorphicDetector · ZeroDayDetector · PackerUnpacker · SandboxAnalyzer · EmulationEngine · MachineLearningDetector |
| **System** | CrashHandler |

### Anti-Evasion Suite
| Module | Detection |
|--------|----------|
| **VMEvasionDetector** | 50+ VM detection techniques with ASM-level CPUID/RDTSC/MSR checks |
| **SandboxEvasionDetector** | Sleep acceleration · Mouse movement · Screen resolution · Environment fingerprinting |
| **DebuggerEvasionDetector** | Hardware breakpoints · Software breakpoints · Timing checks · NtQueryInformationProcess |
| **PackerDetector** | 100+ packer signatures · Entropy analysis · Section characteristics · Import table anomalies |
| **ProcessEvasionDetector** | Parent PID spoofing · Token theft · Job object escape · WoW64 abuse |
| **NetworkBasedEvasionDetector** | DNS tunneling · Domain fronting · Fast-flux · Encrypted C2 channels |
| **TimeBasedEvasionDetector** | RDTSC delta analysis · NTP manipulation · Delayed execution |
| **EnvironmentEvasionDetector** | User/system artifact checks · Registry fingerprinting · File system probing |
| **Metamorphic/Polymorphic** | Instruction-level mutation detection · Code morphing analysis |

### Security & Self-Defense
| Module | Protection |
|--------|-----------|
| **SelfDefense** | Orchestrates all protection modules |
| **TamperProtection** | File hash integrity · DLL hijack prevention · Critical path monitoring |
| **ProcessProtection** | Anti-termination · Handle stripping · Token protection |
| **MemoryProtection** | DEP · Guard pages · RWX prevention |
| **FileProtection** | ACL hardening · ADS stripping · Integrity monitoring |
| **RegistryProtection** | Service key protection · Run/RunOnce guarding |
| **AntiDebug** | Multi-layer debugger detection and prevention |
| **CryptoManager** | AES-GCM encryption · BCryptGenRandom · Key zeroization |
| **CertificateValidator** | Chain validation · CRL/OCSP checking |
| **DigitalSignatureValidator** | Authenticode verification · Catalog file validation |

### Scripts & Scripting Engine Protection
| Module | Coverage |
|--------|---------|
| **AMSIIntegration** | AMSI bypass detection · Provider integrity · Tamper repair |
| **PowerShellScanner** | -EncodedCommand · IEX · AMSI bypass · Constrained Language Mode bypass |
| **JavaScriptScanner** | Obfuscation detection · eval() chains · WSH abuse |
| **VBScriptScanner** | WScript.Shell · CreateObject · ActiveX abuse |
| **MacroDetector** | VBA macros · AutoOpen/AutoExec · Macro 4.0 · DDE |
| **PythonScriptScanner** | exec/eval · subprocess · ctypes injection · PyInstaller analysis |

### Other Infrastructure
| Module | Purpose |
|--------|---------|
| **PEParser** | Full PE32/PE32+ parsing · Section analysis · Import/export · Delay imports · .NET metadata |
| **Communication** | Encrypted kernel↔user-mode IPC · Message dispatch · Protocol handling |
| **Database** | SQLite-backed persistent storage · Configuration management |
| **RansomwareProtection** | Honeypot files · VSS guard · Entropy-based detection · Rollback |
| **Performance** | CPU/Disk/Network monitoring · Ransomware write-rate detection · C2 beaconing |
| **Update** | Secure delta updates · Cryptographic verification · Rollback support |
| **Config** | Centralized configuration management |

### MITRE ATT&CK Coverage

**550+ technique IDs** mapped across all 14 ATT&CK tactics. Every detection fires with precise T-ID attribution for SOC integration.

---

## Product Tiers

| Tier | Target | Description |
|------|--------|-------------|
| **Phantom Home** | Consumer endpoints | Lightweight protection with local desktop UI |
| **Phantom EDR** | Enterprise endpoints | Full detection + response with management dashboard |
| **Phantom XDR** | Enterprise fleet | Extended detection across endpoint, cloud, identity, network |

All three tiers share the same kernel sensor, detection engines, AI models, and emulation engine. Product differentiation happens at the orchestration, UI, and management layers.

---

## Building

> ⚠️ The codebase is under active development and not yet packaged for external builds. Full build instructions will be provided when the project reaches beta.

**Requirements:**
- Visual Studio 2022 with C++20 support (MSVC v143)
- Windows Driver Kit (WDK) 10.0.22621.0+
- Windows SDK 10.0.22621.0+
- Python 3.10+ with PyTorch (for PhantomCortex training only)
- Test environment: Windows 10/11 x64 VM with Driver Verifier enabled

**Quick build (user-mode only):**
```powershell
MSBuild.exe ShadowStrike.sln /p:Configuration=Release /p:Platform=x64 /t:ShadowStrike /m
```

**Full build (includes kernel driver — requires WDK):**
```powershell
MSBuild.exe ShadowStrike.sln /p:Configuration=Release /p:Platform=x64 /m
```

---

## Repository Structure

```
ShadowStrike/
├── PhantomSensor/              # Kernel driver — WDM minifilter (380K LoC, 20 subsystems)
│   └── PhantomSensor/
│       ├── Behavioral/         # MITRE engine · Threat scoring · IOC matching
│       ├── Callbacks/          # Process · Thread · Image · Registry · FS callbacks
│       ├── Communication/      # Kernel↔user-mode IPC port
│       ├── Memory/             # VAD tracking · Injection detection · ROP/shellcode
│       ├── Network/            # WFP filters · C2/DGA/exfil detection
│       ├── Syscall/            # Direct syscall · Heaven's Gate · Hell's Gate
│       ├── SelfProtection/     # Anti-tamper · Callback guard · Integrity
│       ├── Sync/               # Thread pool · Timer · Work queue · DPC
│       └── ...                 # 20 subsystem folders total
│
├── PhantomEmulator/            # Custom x86/x64 emulation engine (195 source files)
│   ├── Core/                   # CPU · Memory · JIT · PE Loader · Threading
│   │   ├── CPU/                # Instruction decoder · Executor (15 categories)
│   │   ├── Memory/             # Virtual memory manager · Memory tracker
│   │   ├── Loader/             # PE/shellcode loading · Import/export resolution
│   │   └── Threading/          # Cooperative scheduler · Sync primitives
│   ├── WinAPI/                 # 10 DLLs · 90+ API handlers
│   ├── VirtualOS/              # Virtual FS · Registry · Network · Anti-evasion
│   ├── Analysis/               # 12 analyzers · Behavior · Crypto · MITRE · IOC
│   ├── Integration/            # Kernel IPC bridge · Session · Result converter
│   └── Common/                 # Types · Config · Constants · Errors
│
├── PhantomCortex/              # AI/ML training pipeline (Python)
│   └── training/
│       ├── models/             # 5 model architectures (LightGBM, CNN, GRU, MLP, AE)
│       ├── features/           # Feature extraction pipeline
│       ├── feeds/              # 6 threat intel feed integrators
│       ├── data/               # Dataset generators · EMBER loader
│       ├── evaluation/         # Model evaluation · Metrics
│       └── export/             # ONNX export · Quantization
│
├── src/
│   └── PhantomCore/         # User-mode detection infrastructure (461 source files)
│       ├── AI/                 # C++ inference bridge → PhantomCortex models
│       ├── Core/               # Engine · FileSystem · Network · Process · Registry · System
│       ├── RealTime/           # RTP · Exploit prevention · Behavior blocking
│       ├── AntiEvasion/        # 9 evasion detection modules + ASM
│       ├── Security/           # 10 self-defense modules
│       ├── Scripts/            # 6 script analysis engines
│       ├── SignatureStore/     # B-tree · YARA · Copy-on-write
│       ├── PatternStore/       # Aho-Corasick · Boyer-Moore · SIMD
│       ├── HashStore/          # Bloom filter · Memory-mapped DB
│       ├── ThreatIntel/        # STIX 2.1 · IOC · Sharded index
│       ├── PEParser/           # Full PE32/PE32+ parser
│       ├── RansomwareProtection/ # Honeypot · VSS · Entropy · Rollback
│       ├── Performance/        # CPU · Disk · Network monitoring
│       └── ...                 # 23 module families total
│
├── include/                    # Vendored headers (YARA · SQLiteCpp · tlsh)
├── vendor/                     # Vendored libraries
├── tests/                      # Unit · integration · fuzz tests
├── malware_tests/              # Malware sample testing framework
└── docs/                       # Architecture documentation
```

---

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting anything.

> ShadowStrike is not actively accepting external code contributions during the alpha phase. Contribution guidelines will be published when the project reaches beta. Issues and discussions are welcome.

---

## Security

To report a vulnerability, **do not open a public GitHub issue.** See [SECURITY.md](SECURITY.md) for the private disclosure process.

---

## License

[GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE.txt)

Any derivative work must also be released under AGPL-3.0. For commercial licensing inquiries: **contact@shadowstrike.dev**

---

## Acknowledgments

- The Windows Driver Kit documentation and Microsoft kernel engineering resources
- [YARA](https://github.com/VirusTotal/yara) — malware pattern matching engine
- The [EMBER](https://github.com/elastic/ember) dataset by Elastic — PE feature training data
- The security research community whose published work makes open-source EDR possible
- Every open-source threat intel feed provider (abuse.ch, AlienVault OTX, MalwareBazaar)

---

<div align="center">

**ShadowStrike-Labs** · Alpha · [shadowstrike.dev](https://www.shadowstrike.dev)

*Every line auditable.*

For business inquiries: [contact@shadowstrike.dev](mailto:contact@shadowstrike.dev)

</div>

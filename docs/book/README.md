<div align="center">

# The Art of ShadowStrike Phantom

### A Comprehensive Technical Reference

**Version 0.1 — April 2026**

*From kernel callbacks to neural networks: the complete guide to building*
*an open-source endpoint protection platform from scratch.*

</div>

---

## About This Book

**The Art of ShadowStrike Phantom** is the definitive technical reference for the ShadowStrike Phantom endpoint protection platform. Written in the spirit of Randall Hyde's *The Art of Assembly Language*, this book goes beyond API documentation — it teaches the *why* behind every architectural decision, the *how* behind every algorithm, and the *what* behind every detection technique.

ShadowStrike Phantom is a 1.5-million-line open-source NGAV/EDR/XDR platform for Windows, built from scratch in C/C++20 and x86-64 Assembly. It comprises five major subsystems: a WDM minifilter kernel driver, a full x86/x64 CPU emulator, an on-device AI/ML inference engine, a custom disassembler, and a comprehensive user-mode detection infrastructure with 23 module families.

This book is both a reference manual and a learning resource. Whether you are:

- A **security researcher** studying detection techniques
- A **kernel developer** building drivers
- A **systems programmer** learning advanced C++20 patterns
- A **contributor** wanting to understand the codebase
- A **student** studying endpoint security architecture

...you will find this book invaluable.

### Conventions Used

Throughout this book:

- 📌 **Key Insight** boxes highlight critical architectural decisions
- ⚠️ **Security Note** boxes flag security-relevant implementation details
- 💡 **Advanced C++** footnotes explain modern C++ techniques used in context
- 🔬 **Deep Dive** sections provide low-level implementation walkthroughs
- 📊 **Performance** notes discuss optimization tradeoffs
- 🛡️ **Threat Model** sections explain what attacks each component defends against

Code examples are drawn directly from the ShadowStrike source tree. File paths are relative to the repository root.

---

## Table of Contents

### Volume 1: Foundations

*The architectural bedrock — design philosophy, patterns, and the systems that everything else depends on.*

| Chapter | Title | Status |
|---------|-------|--------|
| [1](vol1-foundations/ch01-introduction.md) | Introduction to ShadowStrike Phantom | ✅ |
| [2](vol1-foundations/ch02-architecture-overview.md) | System Architecture Overview | ✅ |
| [3](vol1-foundations/ch03-design-patterns.md) | Design Patterns & Conventions | ✅ |
| [4](vol1-foundations/ch04-build-system.md) | The Build System | ✅ |
| [5](vol1-foundations/ch05-threading-model.md) | Threading Model & Concurrency | ✅ |
| [6](vol1-foundations/ch06-error-handling-logging.md) | Error Handling & Logging Infrastructure | ✅ |
| [7](vol1-foundations/ch07-security-architecture.md) | Security Architecture & Threat Model | ✅ |
| [8](vol1-foundations/ch08-detection-pipeline.md) | The Detection Pipeline | ✅ |
| [9](vol1-foundations/ch09-module-relationships.md) | Module Relationships & Dependency Graph | ✅ |
| [10](vol1-foundations/ch10-development-testing.md) | Development Workflow & Testing | ✅ |

### Volume 2: The Kernel Sentinel — PhantomSensor.sys

*380,000 lines of kernel-mode code: minifilter callbacks, behavioral analysis, and self-protection at ring 0.*

| Chapter | Title | Status |
|---------|-------|--------|
| [11](vol2-kernel-sentinel/ch11-kernel-fundamentals.md) | Windows Kernel Fundamentals for EDR | 📝 |
| [12](vol2-kernel-sentinel/ch12-driver-entry.md) | DriverEntry & Initialization Sequence | 📝 |
| [13](vol2-kernel-sentinel/ch13-minifilter-callbacks.md) | Minifilter Callbacks & File System Monitoring | 📝 |
| [14](vol2-kernel-sentinel/ch14-process-thread-callbacks.md) | Process & Thread Callbacks | 📝 |
| [15](vol2-kernel-sentinel/ch15-image-load-callbacks.md) | Image Load Monitoring | 📝 |
| [16](vol2-kernel-sentinel/ch16-registry-callbacks.md) | Registry Monitoring & Persistence Detection | 📝 |
| [17](vol2-kernel-sentinel/ch17-object-callbacks.md) | Object Callbacks & Handle Protection | 📝 |
| [18](vol2-kernel-sentinel/ch18-network-wfp.md) | Network Filtering with WFP | 📝 |
| [19](vol2-kernel-sentinel/ch19-memory-analysis.md) | Memory Analysis & Injection Detection | 📝 |
| [20](vol2-kernel-sentinel/ch20-syscall-monitor.md) | Syscall Monitoring (Heaven's Gate / Hell's Gate) | 📝 |
| [21](vol2-kernel-sentinel/ch21-behavioral-engine.md) | Kernel Behavioral Engine & MITRE Mapping | 📝 |
| [22](vol2-kernel-sentinel/ch22-self-protection.md) | Self-Protection & Anti-Tampering | 📝 |
| [23](vol2-kernel-sentinel/ch23-alpc-transactions.md) | ALPC Monitoring & Transaction Abuse Detection | 📝 |
| [24](vol2-kernel-sentinel/ch24-etw-provider.md) | ETW Provider & Structured Telemetry | 📝 |
| [25](vol2-kernel-sentinel/ch25-cache-performance.md) | Kernel Cache System & Performance | 📝 |
| [26](vol2-kernel-sentinel/ch26-ipc-bridge.md) | Kernel ↔ User-Mode IPC Bridge | 📝 |
| [27](vol2-kernel-sentinel/ch27-elam.md) | Early Launch Anti-Malware (ELAM) | 📝 |
| [28](vol2-kernel-sentinel/ch28-exclusion-engine.md) | Exclusion Engine & Policy Sync | 📝 |

### Volume 3: The Detection Engine — Data Stores & Pattern Matching

*The algorithmic heart: B+ trees, Bloom filters, Aho-Corasick, Boyer-Moore, YARA, and SIMD acceleration.*

| Chapter | Title | Status |
|---------|-------|--------|
| [29](vol3-detection-engine/ch29-hashstore.md) | HashStore — Bloom Filters & Memory-Mapped Hash DB | 📝 |
| [30](vol3-detection-engine/ch30-patternstore.md) | PatternStore — Multi-Algorithm Pattern Matching | 📝 |
| [31](vol3-detection-engine/ch31-aho-corasick.md) | Aho-Corasick Automaton Implementation | 📝 |
| [32](vol3-detection-engine/ch32-boyer-moore.md) | Boyer-Moore & SIMD-Accelerated Search | 📝 |
| [33](vol3-detection-engine/ch33-signaturestore.md) | SignatureStore — B+ Tree & Copy-on-Write Updates | 📝 |
| [34](vol3-detection-engine/ch34-yara-integration.md) | YARA Rule Engine Integration | 📝 |
| [35](vol3-detection-engine/ch35-fuzzyhasher.md) | FuzzyHasher — Approximate Matching (TLSH/ssdeep) | 📝 |
| [36](vol3-detection-engine/ch36-peparser.md) | PE Parser — Portable Executable Analysis | 📝 |
| [37](vol3-detection-engine/ch37-threatintel.md) | Threat Intelligence — STIX/TAXII, IOC Management | 📝 |
| [38](vol3-detection-engine/ch38-whitelist.md) | Whitelist Store — Trust Chains & Exclusion Logic | 📝 |
| [39](vol3-detection-engine/ch39-scan-engine.md) | ScanEngine — The Orchestrator | 📝 |

### Volume 4: The Shield — Real-Time Protection & Defense

*Nine real-time protection modules, anti-evasion techniques, and ransomware defense.*

| Chapter | Title | Status |
|---------|-------|--------|
| [40](vol4-the-shield/ch40-realtime-protection.md) | RealTimeProtection — The Master Orchestrator | 📝 |
| [41](vol4-the-shield/ch41-filesystem-filter.md) | FileSystemFilter — On-Access Scanning | 📝 |
| [42](vol4-the-shield/ch42-process-creation-monitor.md) | ProcessCreationMonitor — LOLBin Detection | 📝 |
| [43](vol4-the-shield/ch43-behavior-blocker.md) | BehaviorBlocker — MITRE ATT&CK Correlation | 📝 |
| [44](vol4-the-shield/ch44-memory-protection.md) | MemoryProtection — ROP / Shellcode / Injection | 📝 |
| [45](vol4-the-shield/ch45-network-traffic-filter.md) | NetworkTrafficFilter — C2/DGA/Exfiltration | 📝 |
| [46](vol4-the-shield/ch46-zero-hour-protection.md) | ZeroHourProtection — Adaptive Cloud Verdicts | 📝 |
| [47](vol4-the-shield/ch47-exploit-prevention.md) | ExploitPrevention — DEP/ASLR/CFG/CET Enforcement | 📝 |
| [48](vol4-the-shield/ch48-ransomware-protection.md) | RansomwareProtection — Shadow Copy & Canary Files | 📝 |
| [49](vol4-the-shield/ch49-anti-evasion-suite.md) | Anti-Evasion Suite — 9 Detector Modules | 📝 |
| [50](vol4-the-shield/ch50-self-protection-usermode.md) | Self-Protection — User-Mode Tamper Defense | 📝 |

### Volume 5: The Emulation Engine — PhantomEmulator

*A complete x86/x64 CPU emulator with virtual OS, WinAPI emulation, and malware behavior analysis.*

| Chapter | Title | Status |
|---------|-------|--------|
| [51](vol5-emulation-engine/ch51-emulator-overview.md) | PhantomEmulator Architecture Overview | 📝 |
| [52](vol5-emulation-engine/ch52-cpu-core.md) | CPU Core — Registers, EFLAGS & Instruction Decode | 📝 |
| [53](vol5-emulation-engine/ch53-instruction-executors.md) | Instruction Executors (x86/x64, SSE, AVX, AES-NI) | 📝 |
| [54](vol5-emulation-engine/ch54-memory-management.md) | Memory Management & Virtual Address Space | 📝 |
| [55](vol5-emulation-engine/ch55-pe-loader.md) | PE Loader — Import Resolution & Relocation | 📝 |
| [56](vol5-emulation-engine/ch56-winapi-emulation.md) | WinAPI Emulation — 10 DLLs, 90+ API Handlers | 📝 |
| [57](vol5-emulation-engine/ch57-virtual-os.md) | VirtualOS — File System, Registry, Network | 📝 |
| [58](vol5-emulation-engine/ch58-kernel-emulation.md) | Kernel Mode Emulation & Ring Transitions | 📝 |
| [59](vol5-emulation-engine/ch59-analysis-modules.md) | Analysis Modules — IOC, Behavior, Crypto, MITRE | 📝 |
| [60](vol5-emulation-engine/ch60-anti-evasion-sandbox.md) | Anti-Evasion in Emulation (Sandbox Transparency) | 📝 |
| [61](vol5-emulation-engine/ch61-jit-acceleration.md) | JIT Compilation & Acceleration | 📝 |

### Volume 6: The Mind — AI/ML & Analysis

*PhantomCortex neural networks, the custom disassembler, and script analysis engines.*

| Chapter | Title | Status |
|---------|-------|--------|
| [62](vol6-the-mind/ch62-cortex-overview.md) | PhantomCortex — AI/ML Architecture | 📝 |
| [63](vol6-the-mind/ch63-feature-extraction.md) | Feature Extraction from PE Files & Behaviors | 📝 |
| [64](vol6-the-mind/ch64-model-architecture.md) | Model Architecture (LightGBM, CNN, GRU, MLP, AE) | 📝 |
| [65](vol6-the-mind/ch65-onnx-inference.md) | ONNX Runtime Inference (<1ms Classification) | 📝 |
| [66](vol6-the-mind/ch66-training-pipeline.md) | Training Pipeline & Dataset Curation | 📝 |
| [67](vol6-the-mind/ch67-disassembler.md) | PhantomDisassembler — Custom x86/x64 Decoder | 📝 |
| [68](vol6-the-mind/ch68-script-analysis.md) | Script Analysis — PowerShell, JS, VB, Python, AMSI | 📝 |

### Volume 7: Integration & Operations

*Service management, IPC protocols, configuration, database systems, and deployment.*

| Chapter | Title | Status |
|---------|-------|--------|
| [69](vol7-integration-operations/ch69-service-architecture.md) | Windows Service Architecture | 📝 |
| [70](vol7-integration-operations/ch70-communication.md) | Communication Module — IPC, Alerts, Telemetry | 📝 |
| [71](vol7-integration-operations/ch71-configuration.md) | Configuration & Policy Management | 📝 |
| [72](vol7-integration-operations/ch72-database-systems.md) | Database Systems (Quarantine, Logs, Config) | 📝 |
| [73](vol7-integration-operations/ch73-update-system.md) | Update System — Signatures, Binaries, Delta | 📝 |
| [74](vol7-integration-operations/ch74-utils-crypto.md) | Utility Library & Cryptography | 📝 |
| [75](vol7-integration-operations/ch75-performance.md) | Performance Monitoring & Profiling | 📝 |
| [76](vol7-integration-operations/ch76-deployment.md) | Deployment, WHQL & Code Signing | 📝 |

### Appendices

| Appendix | Title | Status |
|----------|-------|--------|
| [A](appendices/appendix-a-mitre-coverage.md) | MITRE ATT&CK Coverage Matrix | 📝 |
| [B](appendices/appendix-b-api-reference.md) | Complete API Reference | 📝 |
| [C](appendices/appendix-c-file-inventory.md) | Source File Inventory (1,298 files) | 📝 |
| [D](appendices/appendix-d-glossary.md) | Glossary of Terms | 📝 |
| [E](appendices/appendix-e-bibliography.md) | Bibliography & Further Reading | 📝 |

---

## Reading Order

**For security researchers:** Start with Chapters 1–2, then jump to Volume 4 (The Shield) for detection techniques.

**For kernel developers:** Chapters 1–3, then Volume 2 (The Kernel Sentinel) in order.

**For contributors:** Read Volume 1 completely, then the volume relevant to your area of work.

**For students:** Read front-to-back. The volumes build on each other.

---

## Building This Book

This documentation lives alongside the code in `docs/book/` and renders natively on GitHub. Each chapter is a standalone Markdown file with cross-references to other chapters and to source files.

To contribute to the documentation, follow the same workflow as code contributions — see [CONTRIBUTING.md](../../CONTRIBUTING.md).

---

<div align="center">

*"The best security software is the one you can read."*

**ShadowStrike Phantom** — Open-Source Endpoint Protection

</div>

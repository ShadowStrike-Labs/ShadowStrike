<div align="center">
<a href="https://shadowstrike.dev">
  <img src="https://shadowstrike.dev/logo.png" alt="ShadowStrike Phantom" width="120"/>
</a>

<h3>ShadowStrike Phantom</h3>

**Open-Source Next-Generation Endpoint Protection Platform for Windows**

[![Status](https://img.shields.io/badge/status-alpha-orange?style=flat-square)](https://github.com/ShadowStrike-Labs/ShadowStrike)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square)](LICENSE.txt)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-lightgrey?style=flat-square)](https://github.com/ShadowStrike-Labs/ShadowStrike)
[![Language](https://img.shields.io/badge/language-C%20%2F%20C%2B%2B20%20%2F%20ASM-orange?style=flat-square)](https://github.com/ShadowStrike-Labs/ShadowStrike)
[![Coverity](https://img.shields.io/badge/Coverity%20Scan-0.25%20defect%2FKLoC-brightgreen?style=flat-square&logo=synopsys)](https://scan.coverity.com/projects/ShadowStrike-Labs-ShadowStrike)
[![Commits](https://img.shields.io/github/commit-activity/w/ShadowStrike-Labs/ShadowStrike?style=flat-square&label=commits%2Fweek)](https://github.com/ShadowStrike-Labs/ShadowStrike/commits/master)
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

ShadowStrike Phantom is a **from-scratch, open-source endpoint protection platform** for Windows 10/11 x64. It follows the same architectural principles as commercial EDR/XDR solutions — custom kernel sensor, behavioral analysis engine, memory-mapped threat intelligence databases, exploit prevention orchestrator — with one fundamental difference: **every line of code is auditable.**

This is not a wrapper around existing tools. `PhantomSensor.sys` is a 380,000-line WDM minifilter that has passed Coverity static analysis at 0.25 defects/KLoC and runs under Driver Verifier with zero violations. The user-mode agent implements 23+ detection modules covering everything from ROP chain detection to STIX 2.1 threat intelligence ingestion.

> **Current state:** Alpha. The kernel driver is complete and verified. User-mode shared infrastructure is 76% complete, undergoing module-by-module security audits. On track for public beta in early 2027.

---

## Why This Exists

Commercial endpoint protection products run kernel-level code you cannot inspect. Every major vendor — including those who have caused global outages from faulty kernel updates — ships a black box with ring-0 access to your machine.

ShadowStrike Phantom is the alternative:

- **No hidden telemetry.** Every network call the product makes is in the source.
- **No black-box detection.** Every rule, every heuristic, every scoring weight is auditable.
- **No trust required.** Read the code. Verify it yourself.

---

## Project Status

| Component | Status |
|---|---|
| Architecture | ✅ Designed and documented |
| Core Infrastructure | ✅ Complete |
| Kernel Driver (PhantomSensor.sys) | ✅ Complete — Coverity 0.25 defect/KLoC, Driver Verifier passed |
| User-Mode Shared Modules | 🔧 In Progress — 76% (security audit phase) |
| Local AI/ML Inference Pipeline | 📋 Planned — on-device threat classification |
| Product Splits (EDR / XDR / Home) | 📋 Planned — after shared infrastructure |
| Windows Service & IPC | 🔧 In Progress |
| Management Dashboard (EDR/XDR) | 📋 Planned |
| Desktop UI (Home) | 📋 Planned |
| Public Beta | 🎯 Early 2027 |

**Overall progress: ~76%** — Kernel sensor done, user-mode modules in active security audit and hardening.

---

## Detection Coverage

ShadowStrike Phantom implements detection across **18 kernel subsystems** and **23+ user-space modules**:

### Kernel-Mode (PhantomSensor.sys)

| Subsystem | Techniques Covered |
|---|---|
| **Syscall Monitor** | Direct syscall detection · Heaven's Gate (WoW64) · Hell's Gate / Halo's Gate · NTDLL integrity · Callstack origin analysis |
| **Memory Monitor** | VAD tree tracking · Process injection (VirtualAllocEx chain) · Process hollowing · Reflective DLL · Shellcode detection · ROP chains · Heap spray |
| **Behavioral Engine** | MITRE ATT&CK mapping · Kill-chain correlation · Threat scoring (0–100) · IOC matching |
| **File System Callbacks** | Pre/post I/O interception · Ransomware pattern detection · Rename/delete monitoring · Entropy analysis |
| **Process Callbacks** | LOLBin detection · Parent spoofing · Token manipulation · AMSI bypass detection · WSL boundary crossing |
| **Network Filter** | C2 beacon detection · DGA pattern recognition · DNS anomaly · Data exfiltration · SSL metadata inspection |
| **Self-Protection** | Anti-unload · Callback protection · Runtime `.text` integrity · UEFI variable monitoring · Anti-debug |
| **ELAM Alternative** | Boot-time driver validation · Signature verification · Early threat heuristics |

### User-Space (Detection Engines)

| Category | Modules |
|---|---|
| **Anti-Evasion** | VM detection · Sandbox evasion · Debugger detection · Packer analysis · Metamorphic/polymorphic engine (Zydis) |
| **Exploit Prevention** | ROP detection · JIT spray · Stack pivot · Heap spray · Kernel exploit detection · EAF/IAF · DEP/ASLR/CFG/CET enforcement |
| **Behavioral Analysis** | BehaviorBlocker · AccessControlManager · Real-time process monitoring · MITRE ATT&CK correlation |
| **Data Stores** | SignatureStore (B-tree + YARA) · PatternStore (Aho-Corasick + SIMD) · HashStore (Bloom filter) · ThreatIntel (STIX 2.1) |
| **Protection** | Ransomware (honeypot + VSS guard + entropy) · Self-defense · File/Registry/Process protection |
| **Other** | Script scanning (AMSI · PowerShell · JS) · Web protection · USB/BadUSB · Crypto-miner detection · Forensics |

### MITRE ATT&CK Coverage

**550+ technique IDs** defined across all 14 ATT&CK tactics. Every detection fires with precise T-ID attribution.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER MODE                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   GUI App   │  │  Service    │  │  Scanner    │  │  Threat Intel       │ │
│  │  (Planned)  │  │  Manager    │  │  Engine     │  │  Feed Manager       │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
│         └────────────────┴────────────────┴─────────────────────┘            │
│                                   │                                          │
│                    ┌──────────────┴──────────────┐                           │
│                    │     Communication Port      │                           │
│                    │    (FilterConnectPort)      │                           │
│                    └──────────────┬──────────────┘                           │
├───────────────────────────────────┼─────────────────────────────────────────┤
│                              KERNEL MODE                                     │
├───────────────────────────────────┼─────────────────────────────────────────┤
│                    ┌──────────────┴──────────────┐                           │
│                    │       PhantomSensor.sys     │                           │
│                    │    (Minifilter · Alt. 385210)│                          │
│                    └──────────────┬──────────────┘                           │
│    ┌──────────────────────────────┼──────────────────────────────┐           │
│    ▼                              ▼                              ▼           │
│ ┌──────────────┐  ┌───────────────────────────┐  ┌──────────────────────┐   │
│ │  File System │  │  Process/Thread/Image     │  │  Registry Callback   │   │
│ │  Callbacks   │  │  Callbacks + Syscall Mon  │  │  Persistence Det.    │   │
│ └──────────────┘  └───────────────────────────┘  └──────────────────────┘   │
│ ┌──────────────┐  ┌───────────────────────────┐  ┌──────────────────────┐   │
│ │  Memory Mon  │  │    Object Callbacks       │  │   Self Protection    │   │
│ │  VAD/ROP/Inj │  │    (Handle Protection)    │  │   Anti-Tamper        │   │
│ └──────────────┘  └───────────────────────────┘  └──────────────────────┘   │
├─────────────────────────────────────────────────────────────────────────────┤
│                         HARDWARE / FIRMWARE                                  │
│              Secure Boot · TPM Attestation · Firmware Integrity              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Core Technologies

### Kernel Driver
- Windows Filter Manager minifilter — altitude 385210, 14 operation callbacks
- `CmRegisterCallbackEx` — registry monitoring with persistence detection
- `PsSetCreateProcessNotifyRoutineEx2` — process lifecycle with LOLBin scoring
- `ObRegisterCallbacks` — handle-based self-protection with suspicion scoring
- CNG (BCrypt) — kernel-mode SHA-256 hashing for file reputation
- 380,000 lines of C, Coverity-scanned at 0.25 defects/KLoC

### Detection Data Stores
- **SignatureStore** — Custom B-tree index with YARA rule integration and copy-on-write updates
- **PatternStore** — Aho-Corasick + Boyer-Moore with SSE4.2/AVX2 SIMD acceleration
- **HashStore** — Bloom filter + memory-mapped DB for O(1) hash reputation lookups
- **FuzzyHasher** — Custom approximate hash engine (built in-house, zero GPL dependencies)
- **ThreatIntel** — STIX 2.1 / TAXII 2.1 feed ingestion, sharded B-tree index with LRU cache

### Infrastructure
- Memory-mapped file databases for zero-copy persistence
- Lock-free data structures on hot paths
- ETW-based structured telemetry
- Encrypted kernel ↔ user-space IPC (FilterConnectPort)
- Enterprise thread pool with task priorities, cancellation, and ETW tracing
- Secure update pipeline with cryptographic verification (Windows BCrypt)

---

## Planned: Local AI/ML Integration

On-device machine learning models for threat classification — no cloud dependency for detection decisions. Trained on curated malware datasets, running inference locally on each endpoint for real-time scoring alongside the heuristic and signature engines.

---

## Product Tiers (Planned)

| Tier | Target | Description |
|---|---|---|
| **Phantom Home** | Consumer endpoints | Lightweight protection with local UI |
| **Phantom EDR** | Enterprise endpoints | Full detection + response with management dashboard |
| **Phantom XDR** | Enterprise fleet | Extended detection across endpoint, cloud, identity, network |

All three tiers share the same kernel sensor and detection engine. Product differentiation happens at the orchestration, UI, and management layers.

---

## Building

> The codebase is under active development and not yet packaged for external builds. Build instructions will be provided when the project reaches beta.

**Requirements:**
- Visual Studio 2022 with C++20 support
- Windows Driver Kit (WDK) 10.0.22621.0+
- Windows SDK 10.0.22621.0+
- Test environment: Windows 10/11 x64 VM with Driver Verifier enabled

---

## Repository Structure

```
ShadowStrike/
├── PhantomSensor/           # Kernel driver (WDM minifilter, 380K LoC)
├── src/
│   ├── Shared_modules/      # Shared detection infrastructure
│   │   ├── RealTime/        # RTP · ExploitPrevention · BehaviorBlocker · ACM
│   │   ├── Security/        # File · Registry · Process · Self-defense
│   │   ├── SignatureStore/   # B-tree · YARA rules · COW updates
│   │   ├── ThreatIntel/     # STIX/TAXII · IOC · Bloom filter · LRU cache
│   │   ├── HashStore/       # Bloom filter · memory-mapped reputation DB
│   │   ├── PatternStore/    # Aho-Corasick · Boyer-Moore · SIMD
│   │   ├── Whitelist/       # Hash/pattern whitelisting with Bloom filter
│   │   ├── Update/          # Secure delta-update pipeline (BCrypt verified)
│   │   ├── AntiEvasion/     # VM · debugger · sandbox · packer · polymorphic
│   │   ├── Exploits/        # ROP · JIT spray · heap spray · kernel exploits
│   │   ├── Utils/           # Logger · ThreadPool · StringUtils · SystemUtils
│   │   └── ...              # 23+ modules
│   ├── PhantomEDR/          # EDR product layer
│   ├── PhantomHome/         # Home product layer
│   └── PhantomXDR/          # XDR product layer (planned)
├── include/                 # Vendored headers (YARA · Zydis · SQLiteCpp · tlsh)
├── vendor/                  # Vendored libraries
├── tests/                   # Unit · integration · fuzz
├── malware_tests/           # Malware sample testing framework
└── docs/                    # Architecture documentation
```

---

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting anything.

> ShadowStrike is not actively accepting external code contributions during the alpha phase. Contribution guidelines will be published when the project reaches beta.

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
- [YARA](https://github.com/VirusTotal/yara) — malware pattern matching
- [Zydis](https://github.com/zyantific/zydis) — x86/x64 instruction decoder
- The security research community whose published work makes open-source EDR possible

---

<div align="center">

**ShadowStrike-Labs** · Alpha · [shadowstrike.dev](https://www.shadowstrike.dev)

For business inquiries: [contact@shadowstrike.dev](mailto:contact@shadowstrike.dev)

</div>

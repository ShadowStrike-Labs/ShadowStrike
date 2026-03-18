<div align="center">
<a href="https://shadowstrike.dev">
  <img src="https://shadowstrike.dev/logo.png" alt="ShadowStrike Phantom" width="120"/>
</a>
# ShadowStrike Phantom

**Next-Generation Open-Source Endpoint Protection Platform for Windows**

[![Status](https://img.shields.io/badge/status-pre--alpha-red?style=flat-square)](https://github.com/ShadowStrike-Labs/ShadowStrike)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square)](LICENSE.txt)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-lightgrey?style=flat-square)](https://github.com/ShadowStrike-Labs/ShadowStrike)
[![Language](https://img.shields.io/badge/language-C%20%2F%20C%2B%2B%20%2F%20ASM-orange?style=flat-square)](https://github.com/ShadowStrike-Labs/ShadowStrike)
[![Coverity](https://img.shields.io/badge/Coverity%20Scan-passed-brightgreen?style=flat-square&logo=synopsys)](https://scan.coverity.com/projects/ShadowStrike-Labs-ShadowStrike)
[![Phase 1](https://img.shields.io/badge/phase%201%20kernel-77%25-brightgreen?style=flat-square)](https://www.shadowstrike.dev/roadmap)
[![Commits](https://img.shields.io/github/commit-activity/w/ShadowStrike-Labs/ShadowStrike?style=flat-square&label=commits%2Fweek)](https://github.com/ShadowStrike-Labs/ShadowStrike/commits/master)
[![Beta](https://img.shields.io/badge/beta%20target-2028-blueviolet?style=flat-square)](https://www.shadowstrike.dev/beta)

[Website](https://www.shadowstrike.dev) · [Architecture](https://www.shadowstrike.dev/architecture) · [Roadmap](https://www.shadowstrike.dev/roadmap) · [Join Beta](https://www.shadowstrike.dev/beta) · [Research](https://www.shadowstrike.dev/research)

</div>
### Support This Project

If you believe in open-source security, consider supporting our development:

[![Sponsor ShadowStrike](https://img.shields.io/badge/💝%20Sponsor%20on%20GitHub-ea4aaa?style=for-the-badge)](https://github.com/sponsors/ShadowStrike-Labs)

Your support helps us build transparent, auditable endpoint protection for everyone.

---

## What Is ShadowStrike Phantom?

ShadowStrike Phantom is a **from-scratch, open-source endpoint protection platform** for Windows 10/11 x64 — built with the same architectural principles as commercial EDR/XDR solutions, with one fundamental difference: every line of code is auditable.

This is not a wrapper around existing tools. It is a complete security platform with a custom kernel sensor (`PhantomSensor.sys`), behavioral analysis engine, memory-mapped threat intelligence databases, and a planned local AI/ML inference pipeline — all built in public, licensed under AGPL-3.0.

> **Current state:** Pre-alpha. The kernel driver is in active development (Phase 1: 77% complete). The codebase does not yet produce a compiled binary. This is a long-term engineering effort being built transparently.

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
| Architecture | ✅ Designed |
| Core Infrastructure | ✅ Completed |
| Kernel Driver (PhantomSensor) | 🔧 In Development — Phase 1: 77% |
| User-Mode Detection Engines | 🔧 In Development — Phase 2: 43% |
| Windows Service | 🔧 Planned |
| GUI | ❌ Not Started |
| Compilation | ❌ Not Yet Functional |
| Beta Release | 🎯 Target: 2028 |

Both Phase 1 (kernel) and Phase 2 (user-space) are running in parallel. See the full [Roadmap](https://www.shadowstrike.dev/roadmap).

---

## Detection Coverage

ShadowStrike Phantom implements detection across **18 kernel subsystems** and **23 user-space modules**, covering:

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

Anti-evasion (VM · sandbox · debugger · packer · metamorphic/polymorphic via Zydis), exploit protection (ROP · JIT spray · stack pivot · heap spray · kernel exploits), ransomware protection (honeypot · VSS guard · entropy), script scanning (AMSI · PowerShell · JS · macros), web protection, email security, USB/BadUSB detection, crypto-miner detection, forensics, and more.

Full architecture detail: [shadowstrike.dev/architecture](https://www.shadowstrike.dev/architecture)

### MITRE ATT&CK Coverage

**550+ technique IDs** defined across all 14 ATT&CK tactics in the kernel header. 14 behavioral rules currently active. Every detection fires with a precise T-ID attribution.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER MODE                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   GUI App   │  │  Service    │  │  Scanner    │  │  Threat Intel       │ │
│  │  (Future)   │  │  Manager    │  │  Engine     │  │  Feed Manager       │ │
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
│                    │    (Minifilter · Alt. 328000)│                          │
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
- Windows Filter Manager minifilter — altitude 328000, 14 operation callbacks
- `CmRegisterCallbackEx` — registry monitoring
- `PsSetCreateProcessNotifyRoutineEx2` — process lifecycle
- `ObRegisterCallbacks` — handle-based self-protection
- CNG (BCrypt) — kernel-mode SHA-256 hashing

### Detection Data Stores
- **SignatureStore** — Custom B-tree index with YARA rule integration and COW updates
- **PatternStore** — Aho-Corasick + Boyer-Moore with SSE4.2/AVX2 SIMD acceleration
- **HashStore** — Bloom filter + memory-mapped DB for O(1) hash reputation lookups
- **FuzzyHasher** — Custom approximate hash engine (built in-house, zero GPL dependencies)
- **ThreatIntel** — STIX 2.1 / TAXII 2.1 feed ingestion, sharded B-tree with LRU cache

### Infrastructure
- Memory-mapped file databases for zero-copy persistence
- Lock-free data structures on hot paths
- ETW-based structured telemetry
- Encrypted kernel ↔ user-space IPC channel (FilterConnectPort)

---

## Product Tiers (Planned)

| Tier | Target | Status |
|---|---|---|
| **Phantom Home** | Consumer endpoints | Planned — Phase 3 |
| **Phantom EDR** | Enterprise endpoints | Planned — Phase 3 |
| **Phantom XDR** | Extended detection across endpoint, cloud, identity, network | Planned — Phase 4 |

---

## Building

**Current status:** Does not compile. Build instructions will be provided when the codebase reaches a compilable state.

**Requirements (for future reference):**
- Visual Studio 2022 with C++20 support
- Windows Driver Kit (WDK) 10.0.22621.0 or later
- Windows SDK 10.0.22621.0 or later
- Test machine: Windows 10/11 x64 VM with Driver Verifier enabled

---

## Repository Structure

```
ShadowStrike/
├── PhantomSensor/           # Kernel driver (minifilter)
├── src/                     # User-space detection engines
│   ├── AntiEvasion/         # VM · debugger · sandbox · packer detection
│   ├── Core/                # Scan engine · ML inference · process analysis
│   ├── Exploits/            # ROP · JIT spray · heap spray · kernel exploits
│   ├── RansomwareProtection/
│   ├── ThreatIntel/         # STIX/TAXII · IOC management · bloom filter
│   ├── SignatureStore/      # B-tree · YARA rules
│   ├── HashStore/           # Bloom filter · memory-mapped DB
│   ├── PatternStore/        # Aho-Corasick · Boyer-Moore · SIMD
│   ├── FuzzyHasher/         # Custom approximate hash engine
│   └── ...                  # 23 modules total
├── include/                 # Vendored headers (YARA · Zydis · SQLiteCpp · tlsh)
├── vendor/                  # Vendored libraries
├── tests/                   # Unit · integration · fuzz
└── docs/                    # Architecture documentation
```

---

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting anything.

> ShadowStrike Phantom is not actively accepting external code contributions during the current pre-alpha phase. Contribution guidelines will apply when contributions are formally opened in a future phase.

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
- The [YARA](https://github.com/VirusTotal/yara) project — malware pattern matching
- [Zydis](https://github.com/zyantific/zydis) — x86/x64 disassembler
- The security research community whose published work makes open EDR possible

---

<div align="center">

**ShadowStrike-Labs** · Pre-Alpha · Not for production use

[shadowstrike.dev](https://www.shadowstrike.dev) · [contact@shadowstrike.dev](mailto:contact@shadowstrike.dev)


</div>

*Building the Open-Source Endpoint Protection Platform...*

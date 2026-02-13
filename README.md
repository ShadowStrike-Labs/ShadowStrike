# ShadowStrike

**Next-Generation Antivirus Engine for Windows**

A from-scratch implementation of an enterprise-grade endpoint protection platform for Windows 10/11 64-bit Operating Systems , built with the same architectural principles as industry leaders. This is not a wrapper around existing tools—it's a complete antivirus engine with custom kernel drivers, memory-mapped databases, YARA integration, and real-time threat detection.

---

## Project Status

| Component | Status |
|-----------|--------|
| **Architecture** | Designed |
| **Core Infrastructure** | Completed |
| **Kernel Driver** | In Development |
| **User-Mode Service** | In Development |
| **GUI** | Not Started |
| **Compilation** | Not Yet Functional |

**Current State:** Pre-alpha. The codebase does not compile. This is a long-term development effort being built in public.

**Why publish now?** Transparency, accountability, and community feedback. Building in public forces discipline and attracts contributors who believe in the vision.

---

## The Vision

ShadowStrike aims to be a fully functional, open-source Windows antivirus that implements the same detection techniques used by commercial endpoint protection platforms:

- **Kernel-level file system filtering** via Windows Filter Manager (minifilter)
- **Real-time process monitoring** with injection detection
- **Behavioral analysis** and heuristic detection
- **YARA rule integration** for signature matching
- **Memory-mapped databases** for high-performance lookups
- **Self-protection** against tampering and evasion
- **Threat intelligence feeds** with IOC management

This is a 3-5 year development effort. The goal is a production-ready beta by 2028.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER MODE                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   GUI App   │  │  Service    │  │  Scanner    │  │  Threat Intel       │ │
│  │  (Future)   │  │  Manager    │  │  Engine     │  │  Feed Manager       │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
│         │                │                │                     │            │
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
│                    │     ShadowStrikeFlt.sys     │                           │
│                    │      (Minifilter Driver)    │                           │
│                    └──────────────┬──────────────┘                           │
│                                   │                                          │
│    ┌──────────────────────────────┼──────────────────────────────┐           │
│    │                              │                              │           │
│    ▼                              ▼                              ▼           │
│ ┌──────────────┐  ┌───────────────────────────┐  ┌──────────────────────┐   │
│ │  File System │  │    Process/Thread/Image   │  │  Registry Callback   │   │
│ │  Callbacks   │  │       Callbacks           │  │  (Persistence Det.)  │   │
│ └──────────────┘  └───────────────────────────┘  └──────────────────────┘   │
│                                                                              │
│ ┌──────────────┐  ┌───────────────────────────┐  ┌──────────────────────┐   │
│ │  Scan Cache  │  │    Object Callbacks       │  │   Self Protection    │   │
│ │  (SHA-256)   │  │    (Handle Protection)    │  │   (Anti-Tamper)      │   │
│ └──────────────┘  └───────────────────────────┘  └──────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Core Technologies

### Kernel Driver (Shadow Sensor)
- Windows Filter Manager minifilter for file system interception
- `CmRegisterCallbackEx` for registry monitoring
- `PsSetCreateProcessNotifyRoutineEx` for process creation tracking
- `ObRegisterCallbacks` for handle-based self-protection
- CNG (BCrypt) for kernel-mode SHA-256 hashing

### Detection Engines
- **SignatureStore**: Custom B-tree indexed signature database with YARA integration
- **PatternStore**: Aho-Corasick and Boyer-Moore pattern matching with SIMD acceleration
- **HashStore**: Bloom filter + memory-mapped hash database for O(1) lookups
- **ThreatIntel**: IOC management with STIX/TAXII feed support

### Anti-Evasion Detection
- Debugger detection (hardware breakpoints, timing attacks)
- VM/Sandbox evasion detection
- Process hollowing and injection detection
- Metamorphic and polymorphic code analysis
- Packer detection and unpacking

### Infrastructure
- Memory-mapped file databases for persistence
- Lock-free data structures where possible
- Comprehensive logging and telemetry
- Crash handling and recovery

---

## Project Structure

```
ShadowStrike/
├── bin/
│   ├── debug/
│   └── release/
├── build/
├── debug/
├── docs/
├── Drivers/
│   ├── Build/
│   ├── Install/
│   ├── ShadowSensor/
│   │   ├── cache/
│   │   ├── callbacks/
│   │   ├── communication/
│   │   ├── core/
│   │   ├── exclusions/
│   │   ├── selfprotection/
│   │   ├── sync/
│   │   ├── tracing/
│   │   ├── utilities/
│   │   └── modules/
│   └── Shared/
├── include/
│   ├── gmock/
│   ├── gtest/
│   ├── nlohmann/
│   ├── pugixml/
│   ├── SQLiteCpp/
│   ├── FuzzyHasher/
│   ├── tlsh/
│   ├── YARA/
│   └── Zydis/
├── ShadowStrike/
├── src/
│   ├── AntiEvasion/
│   ├── Backup/
│   ├── Banking/
│   ├── Communication/
│   ├── Config/
│   ├── Core/
│   ├── CryptoMinersProtection/
│   ├── Database/
│   ├── Email/
│   ├── Exploits/
│   ├── External/
│   ├── Forensics/
│   ├── GameMode/
│   ├── HashStore/
│   ├── IoT/
│   ├── PatternStore/
│   ├── PEParser/
│   ├── Performance/
│   ├── Privacy/
│   ├── RansomwareProtection/
│   ├── RealTime/
│   ├── Security/
│   ├── Service/
│   ├── SignatureStore/
│   ├── ThreatIntel/
│   ├── Update/
│   ├── USB_Protection/
│   ├── Utils/
│   ├── WebProtection/
│   └── Whitelist/
├── tests/
│   ├── integration/
│   ├── fuzz/
│   └── unit/
└── vendor/
    ├── gtest_framework/
    ├── openssl_lib/
    ├── yara_lib/
    └── zydis_lib/


---


## Building

**Current Status:** Does not compile. Build instructions will be provided once the codebase reaches a compilable state.

**Requirements (for future reference):**
- Visual Studio 2022 with C++20 support
- Windows Driver Kit (WDK) 10.0.22621.0 or later
- Windows SDK 10.0.22621.0 or later

---

## Contributing

This project is in early development. Contributions are welcome, but please understand:

1. **The code is not in a good condition.** We're working on it.
2. **Architecture may change.** Early-stage means refactoring happens.
3. **Documentation is incomplete.** We're building it as we go.

If you're interested in contributing:
- Open an issue to discuss before submitting PRs
- Focus on specific, well-defined improvements
- Be patient with review times

---

## Why Open Source?

Commercial antivirus products are black boxes. Users trust them with kernel-level access to their systems without being able to verify what they actually do.

ShadowStrike aims to be:
- **Transparent**: Every line of code is auditable
- **Educational**: Learn how real AV engines work
- **Trustworthy**: No hidden telemetry or backdoors
- **Community-driven**: Built by and for the security community

---

## Disclaimer

**This software is experimental and should not be used for production security FOR NOW.**

- Do not rely on ShadowStrike to protect your systems
- The detection capabilities are incomplete
- The self-protection mechanisms are not battle-tested
- Use at your own risk

---

## License

GPL-3.0

This means:
- You can use, modify, and distribute this code
- Any derivative work must also be GPL-3.0
- You must provide attribution
- You must share your modifications

---

## Acknowledgments

This project stands on the shoulders of giants:
- The Windows Driver Kit documentation and samples
- The YARA project for malware pattern matching
- The security research community for detection techniques
- Open source projects: SQLite, Zydis, and others

---

## Contact

This is a personal project. For now, use GitHub issues for all communication.

---

*Building the antivirus we wish existed.*

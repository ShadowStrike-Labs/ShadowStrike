# ShadowStrike — Comprehensive Production Readiness Plan

> **Priority:** Phantom Home (consumer endpoint protection) → EDR → XDR
> **Principle:** Home must be battle-tested against real-world malware before
> EDR/XDR layers ship. Endpoint protection is the most critical surface — it
> runs on millions of consumer machines and must be rock-solid first.
>
> **Collaboration model:** Opus focuses on code — bugs, security, performance,
> architecture. The architect focuses on product testing, instrumentation,
> direction, and real-world malware validation on VMware Workstation Pro.

---

# PART A — PHANTOM HOME: PATH TO PRODUCTION

> Everything below must be completed — sequentially, in order — before
> Phantom Home can be deployed on a single real user's machine.

---

## TIER 0: BUILD SYSTEM — MAKE IT LINK ✅ COMPLETE

All six T0 items are finished. The Phantom Home build system is fully operational.

| Task | Status | Artifact |
|------|--------|----------|
| **T0-01** PhantomCore static library | ✅ Done | `PhantomCoreLib.vcxproj` → `lib\Debug\PhantomCoreLib.lib` (1.35 GB, 260 sources + 6 ASM) |
| **T0-02** Full link — Service EXE | ✅ Done | `bin\Debug\ShadowStrikePhantomService.exe` (73 MB) — 83 PhantomHome modules + full engine |
| **T0-03** Full link — Tray EXE | ✅ Done | `bin\Debug\ShadowStrikePhantomTray.exe` (1.9 MB) — IPC client + Logger |
| **T0-04** Full link — UI EXE | ✅ Done | `bin\Debug\ShadowStrikePhantomUI.exe` (2.1 MB) — Qt6 QML shell, 31 Qt runtime DLLs deployed |
| **T0-05** MSI end-to-end build | ✅ Done | `bin\Debug\ShadowStrikePhantomHome.msi` (37.65 MB) — WiX v5, includes Qt runtime + OpenSSL |
| **T0-06** Code signing | ⏭️ Deferred | No EV certificate yet (money constraint). SmartScreen must be disabled on test VMs. |

**Build fixes applied during T0:**
- VMEvasionDetector_x64.asm: removed 12 duplicate PUBLIC symbols (EXTERNDEF strategy)
- SandboxEvasionDetector_x64.asm: ALIGN 64→16, PROC FRAME directives
- MemoryProtection.cpp / IPLeakProtection.cpp: .obj name collision resolution
- MountPointMonitor.cpp: UNICODE macro collision with member name
- NetworkBasedEvasionDetector.cpp: LPCTSTR/ANSI cast for InternetQueryOptionA
- HomeConfigRegistration.cpp: include path fixes
- SpamDetector.cpp: missing IsInitialized() forwarding
- TrackerBlocker.cpp: ODR violation (duplicate GetRequestTypeName)
- CookieManager.cpp: removed sqlite3.lib pragma
- tlsh_compat.h: added stdlib.h
- SHADOWSTRIKE_HAS_YARA enabled for YARA rule store activation
- PhantomDisassembler Decoder/Formatter added to lib for AntiEvasion link

---

## TIER 1: GLOBAL THREAT INTELLIGENCE — API KEYS & FEED SYSTEM

### Current Status (Post-Survey)
The `ThreatIntelFeedManager` is **80-90% production-ready**:
- HTTP client: WinINet (Windows native), HTTPS, TLS cert validation ✅
- IOC storage: Memory-mapped B+Tree/Radix/Trie, <100ns hash lookup ✅
- JSON/CSV parsers: Implemented with size/depth caps ✅
- Feed infrastructure: Concurrent sync, rate limiting, exponential backoff ✅
- Credential sanitization: secureClear() with volatile overwrite ✅
- **GAPS**: API key loading from env/config not wired, Feodo CSV parser incomplete,
  STIX parser minimal. AI inference requires ONNX Runtime SDK (optional dep).

### 1A. Commercial-Use License Audit (VERIFIED — April 2026)

> **Decision:** All non-commercial-licensed feeds are DEFERRED to Phantom Pro/Enterprise.
> Phantom Home (Community) ships ONLY with feeds that are 100% free for commercial use.
> NLNet funding applied for — no budget for paid APIs at this time.

#### ✅ FREE FOR COMMERCIAL USE — Ships with Phantom Home

| Service | License | Auth | Rate Limit | Parser Status |
|---------|---------|------|-----------|--------------|
| **URLhaus** (abuse.ch) | CC BY 4.0 | None | 10 req/min | ✅ CSV parser wired |
| **MalwareBazaar** (abuse.ch) | CC BY 4.0 | None | 10 req/min | ✅ POST JSON wired |
| **ThreatFox** (abuse.ch) | CC BY 4.0 | None | 10 req/min | ✅ POST JSON wired |
| **Feodo Tracker** (abuse.ch) | CC BY 4.0 | None | 30 req/min | ⚠️ CSV parser incomplete |
| **Emerging Threats Open** (Proofpoint) | MIT/BSD | None | Public download | 🆕 Parser needed |
| **Botvrij.eu** | OSINT / no restriction | None | Public MISP | 🆕 Parser needed |
| **PhishTank** (Cisco Talos) | Free commercial (ToS) | API key (free) | Rate-limited | 🆕 Parser needed |
| **MISP** | Open-source (self-hosted) | `Authorization` | Self-hosted | ✅ Implemented |
| **NIST NVD** | US Gov public data | Optional | Unlimited | ✅ Implemented (EDR VulnDB) |
| **GitHub Advisories** | Public | None | Public | ✅ Implemented |
| **EMBER 2024** | Apache-2.0 | None | Open dataset | ✅ Integrated (PhantomCortex) |

> **Attribution requirement:** All abuse.ch feeds (URLhaus, MalwareBazaar, ThreatFox,
> Feodo) require: `"Data provided by abuse.ch — https://abuse.ch"` in the About dialog
> and documentation. ET Open requires MIT/BSD attribution notice.

#### ❌ DEFERRED TO PRO/ENTERPRISE (Not free for commercial use)

| Service | License | Why Deferred | Code Status |
|---------|---------|-------------|-------------|
| **VirusTotal** | Paid ($5K-$15K/yr) | Prohibits commercial use on free tier | Full REST impl (cpp:535) — dormant |
| **AlienVault OTX** | Non-commercial EULA | LevelBlue EULA prohibits commercial integration without written approval | Full REST impl (cpp:565) — dormant |
| **AbuseIPDB** | Non-commercial free tier | Paid plan required for commercial products | Full REST impl (cpp:594) — dormant |
| **Spamhaus DROP/EDROP** | Commercial license required | Cannot bundle into commercial security products without license | 🆕 Not yet implemented |
| **OpenPhish** | Non-commercial only | Community feed is strictly non-commercial | 🆕 Not yet implemented |
| **C2IntelFeeds** | CC BY-NC-SA 4.0 | Non-commercial, share-alike — cannot use commercially | 🆕 Not yet implemented |

> **Note:** All deferred feeds have full parsers or infrastructure in the codebase.
> When Pro/Enterprise launches and revenue arrives, flipping them on is a config change +
> API key insertion. Zero code changes needed.

### 1B. Revised Task Breakdown

**YOUR TASKS (Architect):**
1. Register for a **free PhishTank API key** at https://phishtank.org/register.php
   → Set env var `SHADOWSTRIKE_PHISHTANK_KEY=<your-key>`
2. **Test feeds on VM** — start Service, check logs for IOC counts after 5-min sync
3. **Verify attribution** — check About dialog / docs include abuse.ch + ET Open credits
4. **Contact LevelBlue** (optional, long-term) — request commercial license for OTX
   if future Pro/Enterprise tiers are planned
5. **NLNet follow-up** — if funded, revisit VT/AbuseIPDB paid API purchases

**MY TASKS (Opus — Code):**

- [ ] **T1-01 · API Key Loading Infrastructure**
  - Implement env-var loading: `SHADOWSTRIKE_PHISHTANK_KEY` (only key needed now)
  - Fallback chain: env-var → Windows Credential Manager (DPAPI) → ConfigManager
  - Build the generic `CredentialProvider` class for future Pro/Enterprise keys too
  - Keep env-var names defined for ALL feeds (VT, OTX, AbuseIPDB) so Pro can just set them
  - **Acceptance:** Feed system auto-discovers PhishTank key from environment on startup.
    VT/OTX/AbuseIPDB remain dormant with clear log: "Feed disabled — no API key"

- [ ] **T1-02 · Activate abuse.ch feeds (URLhaus + MalwareBazaar + ThreatFox)**
  - These are free, no-API-key, CC BY 4.0 (commercial OK with attribution).
  - Verify FeedManager actually fetches on startup, parses, stores IOCs.
  - Ensure sync intervals respect rate limits (10 req/min per feed).
  - Add abuse.ch attribution string to About dialog / settings.
  - **Acceptance:** After service startup, ThreatIntelStore contains fresh IOCs from all 3.

- [ ] **T1-03 · Complete Feodo Tracker CSV parser**
  - URL is configured but CSV parser is incomplete.
  - Implement Feodo CSV column mapping: first_seen, dst_ip, dst_port, c2_status,
    last_online, malware.
  - Same CC BY 4.0 license — commercial OK with attribution.
  - **Acceptance:** Feodo C2 IPs flow into ThreatIntelStore IP index.

- [ ] **T1-04 · Implement Emerging Threats Open rules feed** ← REPLACES OTX
  - License: MIT/BSD — fully free for commercial use (Proofpoint confirmed)
  - Download Suricata rules from `rules.emergingthreats.net/open/`
  - Parse: extract IOCs (IPs, domains, URLs) from `alert` rules
  - Map to ThreatIntelStore entries with ET rule SID as reference
  - **Acceptance:** ET Open IOCs flow into ThreatIntelStore. Attribution in docs.

- [ ] **T1-05 · Implement PhishTank feed** ← NEW (replaces VT dormancy task)
  - License: Free for commercial use (Cisco Talos ToS)
  - Requires free API key from architect (SHADOWSTRIKE_PHISHTANK_KEY)
  - Download phishing URL database (JSON/CSV, hourly updates)
  - Parse: extract verified phishing URLs, store in ThreatIntelStore URL index
  - Wire into WebProtection + SafeBrowsing modules for real-time URL blocking
  - **Acceptance:** PhishTank URLs block known phishing sites in real-time.

- [ ] **T1-06 · Implement Botvrij.eu MISP feed** ← NEW (replaces mixed feed task)
  - License: OSINT, no commercial restrictions, as-is
  - Download MISP-format IOC exports from botvrij.eu
  - Parse: MISP event JSON → extract hashes, domains, IPs, URLs
  - We already have MISP parser — adapt for Botvrij.eu endpoint
  - **Acceptance:** Botvrij.eu IOCs enrich ThreatIntelStore.

- [ ] **T1-07 · Safe dormancy for deferred feeds (VT + OTX + AbuseIPDB)**
  - Ensure code compiles clean with zero API keys configured
  - Add clear log messages per feed: "VirusTotal feed disabled — no API key.
    Available in Phantom Pro/Enterprise."
  - Ensure no HTTP requests are made for dormant feeds
  - Guard all deferred feed parsers behind `if (hasApiKey())` checks
  - **Acceptance:** Service starts clean with zero warnings about missing keys
    for commercial-restricted feeds. Only PhishTank warns if key missing.

- [ ] **T1-08 · ONNX Runtime integration verification**
  - Verify `__has_include(<onnxruntime_c_api.h>)` fallback works cleanly.
  - If SDK present: 5-model ensemble (static, behavioral, memory, network, emulation)
  - If SDK absent: graceful skip with clear log, heuristic-only mode.
  - Document ONNX Runtime SDK installation in README for developers.
  - **Acceptance:** Build with and without ONNX SDK — both produce working EXE.

- [ ] **T1-09 · Feed health monitoring + attribution compliance**
  - Add per-feed health counters: lastSuccessTime, lastFailureTime, consecutiveFailures,
    totalIOCsLoaded, lastSyncDuration.
  - Expose via IPC so UI can show feed status in Settings page.
  - Log warnings when a feed fails 3+ consecutive times.
  - Add attribution strings in About dialog: abuse.ch, Proofpoint ET, PhishTank, Botvrij.eu
  - **Acceptance:** UI Settings page shows feed name + last-sync + IOC count + attribution.

---

## TIER 2: STATIC ANALYSIS — PVS-STUDIO & COVERITY SWEEP

Status: No repo-wide static analysis has been run except a partial sensor
check. PVS-Studio and Coverity are industry-standard for catching bugs that
compilers and code review miss.

**Process:** The architect provides PVS-Studio / Coverity scan results
per-module. Opus triages every finding into (a) false positive — suppress
with comment, or (b) real bug — fix at production-grade quality.

- [ ] **T2-01 · PhantomCore scan**
  - Module: `src/PhantomCore/` (26 subsystems, ~200 files)
  - Expected categories: uninitialized memory, buffer overflows, use-after-free,
    TOCTOU, integer overflow, dead code, unreachable branches.

- [ ] **T2-02 · PhantomSensor scan**
  - Module: `PhantomSensor/` (kernel driver — highest severity)
  - Special attention: IRQL violations, pool tag leaks, double-free in
    completion routines, missing `try/except` around user buffers.
  - Note: Already partially scanned; re-check recommended.

- [ ] **T2-03 · PhantomEmulator scan**
  - Module: `PhantomEmulator/` (16 analysis components + virtual OS)
  - Focus: Memory safety in emulation loops, stack exhaustion in recursive
    unpacking, bounds checking in API emulation.

- [ ] **T2-04 · PhantomDisassembler scan**
  - Module: `PhantomDisassembler/` (7 files, self-contained)
  - Focus: Decoder edge cases, malformed instruction handling.

- [ ] **T2-05 · PhantomHome modules scan**
  - Module: `src/Products/Community/PhantomHome/` (18 modules)
  - Focus: Wiring correctness, config validation, IPC message handling.

- [ ] **T2-06 · UI / IPC layer scan**
  - Module: `src/Products/Community/PhantomHome/UI/` (Service, Tray, Client, IPC)
  - Focus: Named pipe security, frame parsing, message deserialization,
    privilege boundary crossings.

- [ ] **T2-07 · PhantomCortex scan (Python)**
  - Module: `PhantomCortex/` (Python training pipeline)
  - Tool: `bandit` + `mypy` + `ruff` (Python static analyzers)
  - Focus: Unsafe deserialization, path traversal, model poisoning vectors.

---

## TIER 3: END-TO-END INTEGRATION & SMOKE TESTING

Status: No end-to-end smoke test has ever been run. Individual modules are
reviewed but never linked and exercised together as a running product.

- [ ] **T3-01 · Service standalone startup**
  - Start `ShadowStrikePhantomService.exe` on the VM (console mode first).
  - Verify: HomeProductOrchestrator initializes all 18 modules in phase order.
  - Verify: PipeServer opens `\\.\pipe\ShadowStrike.PhantomHome.IPC` and accepts connections.
  - Verify: Logger output shows each module transitioning to Running.
  - Fix any crash, hang, or initialization failure.

- [ ] **T3-02 · Tray → Service IPC handshake**
  - Start Service, then start Tray.
  - Verify: Tray connects, sends Hello, receives HelloOk.
  - Verify: Tray icon shows green shield (OverallState::Green).
  - Verify: State polling (every 5s) works; tray tooltip updates.

- [ ] **T3-03 · UI → Service IPC handshake**
  - Start Service, then start UI.
  - Verify: QML shell loads, ProtectionViewModel connects via PipeClient.
  - Verify: Main page shows "We are protecting you" with green shield animation.
  - Verify: Security page populates module list from GetState response.

- [ ] **T3-04 · Scan dispatch round-trip**
  - From Tray context menu: trigger Quick Scan.
  - Verify: ScanStartRequest reaches Service, ScanEngine executes, progress
    events flow back to Tray/UI via EventStateChanged push frames.
  - From UI Main page: trigger Fast Scan. Same verification.

- [ ] **T3-05 · Module toggle round-trip**
  - From UI Security page: disable a module (e.g. Email Protection).
  - Verify: SetModuleEnabled IPC message reaches Service, module stops.
  - Re-enable: verify module restarts.

- [ ] **T3-06 · Pause / Resume protection**
  - From Tray: Pause 15 minutes.
  - Verify: OverallState changes to Paused, tray icon changes, UI updates.
  - Verify: Auto-resume after 15 minutes (or test with shorter interval).

- [ ] **T3-07 · MSI install / uninstall on clean VM**
  - Install MSI on Windows 10 x64 VM.
  - Verify: Service registered and auto-started, tray appears on logon,
    HKLM Run key present.
  - Uninstall: verify service removed, tray Run key removed, install dir
    cleaned up. No orphaned registry keys.

- [ ] **T3-08 · Multi-user / fast-user-switch**
  - Two user accounts on the VM, both logged in.
  - Verify: Each session gets its own tray instance (Local\ mutex).
  - Verify: Service serves both sessions (session_id in IPC).

---

## TIER 4: REAL-WORLD MALWARE TESTING (VM Lab)

Status: PhantomCore + PhantomSensor + PhantomEmulator have never been tested
against real-world malware. The detection engine is "raw" — untested against
adversarial samples.

**Environment:** VMware Workstation Pro, snapshots before each test, network
isolated (host-only adapter), samples from MalwareBazaar / VirusTotal / own collection.

**Process:** The architect executes malware on the VM and reports findings.
Opus analyzes the detection gap or false positive and applies surgical fixes.

### 4A. Detection Gap Fixing (Bypasses)

- [ ] **T4-01 · Ransomware family testing**
  - Test against: WannaCry, LockBit, BlackCat/ALPHV, Conti, REvil samples.
  - For each bypass: analyze what the sample does that our engine misses.
  - Fix in PhantomCore/RansomwareProtection/*, PhantomCore/AI/*, or
    PhantomEmulator/Analysis/*.
  - **Goal:** 100% detection of known ransomware families.

- [ ] **T4-02 · Trojan / RAT testing**
  - Test against: Emotet, Remcos, AsyncRAT, QuasarRAT, NjRAT.
  - Focus: C2 communication detection, persistence mechanism detection,
    process injection detection.

- [ ] **T4-03 · Fileless / living-off-the-land testing**
  - Test against: PowerShell downloaders, WMI persistence, LOLBin abuse
    (mshta, regsvr32, certutil, bitsadmin).
  - Focus: PhantomCore/Scripts/* (AMSI, PowerShell, VBScript monitors) and
    PhantomCore/Core/Process/* (injection detection).

- [ ] **T4-04 · Packer / crypter evasion testing**
  - Test against: UPX, Themida, VMProtect, custom-packed samples.
  - Focus: PhantomEmulator unpacking engine, PhantomCore/AntiEvasion/*
    packer detection, PhantomCore/Core/FileSystem/ExecutableAnalyzer.

- [ ] **T4-05 · Zero-day / polymorphic testing**
  - Test against: fresh samples from MalwareBazaar (< 24h old).
  - Focus: ML model confidence (PhantomCortex), heuristic scoring,
    behavioral analysis, emulator-based detection.

### 4B. False Positive Reduction

- [ ] **T4-06 · Legitimate software baseline**
  - Install and run: Chrome, Firefox, VSCode, Steam, Discord, 7-Zip,
    Python, Node.js, Git, OBS, VLC, LibreOffice, Wireshark.
  - Log every detection event. Each false positive is a bug.
  - Fix by: whitelist entry, heuristic threshold adjustment, behavioral
    signature refinement, or ML model retraining.

- [ ] **T4-07 · Windows system process baseline**
  - Verify zero false positives on: svchost, lsass, csrss, dwm, explorer,
    RuntimeBroker, SearchIndexer, Windows Update, Defender (if coexisting).
  - Any FP on a system process is P0 severity.

- [ ] **T4-08 · Developer toolchain baseline**
  - Compile and run: Visual Studio, MSBuild, cl.exe, link.exe, CMake,
    Cargo, Go compiler, Python scripts with subprocess calls.
  - Developer tools trigger many heuristics (code injection patterns,
    memory manipulation, DLL loading). Must not false-positive.

### 4C. Engine Tuning

- [ ] **T4-09 · Heuristic threshold calibration**
  - After T4-01..T4-08, adjust scoring thresholds in:
    - `PhantomCore/AI/HeuristicAnalyzer` (rule weights)
    - `PhantomCore/AI/BehaviorAnalyzer` (behavior scores)
    - `PhantomCore/Core/Engine/ThreatDetector` (detection thresholds)
  - Document each adjustment with before/after detection rates.

- [ ] **T4-10 · ML model retraining cycle**
  - Use PhantomCortex training pipeline with EMBER 2024 dataset.
  - Add any new samples from T4-01..T4-05 to the training set.
  - Retrain, validate on held-out test set, deploy updated model.

---

## TIER 5: KERNEL DRIVER STABILITY (PhantomSensor)

Status: PhantomSensor is a WDM minifilter driver (x64/ARM64). It has never
been tested under real workloads. Kernel bugs cause BSOD → total system
loss. This tier is the highest-risk component.

**Process:** The architect loads PhantomSensor.sys on the VM. Any BSOD
produces a `.dmp` file. Opus analyzes the dump with `kd.exe` (kernel
debugger), identifies the faulting module/line, and fixes the root cause.

- [ ] **T5-01 · Driver load / unload cycle**
  - Load PhantomSensor.sys via `sc create` + `fltmc load`.
  - Verify: minifilter attaches to volumes, callbacks registered, CommPort opens.
  - Unload: verify clean teardown, no leaked pool tags, no dangling callbacks.
  - Repeat 100 times in a loop. Any BSOD = P0.

- [ ] **T5-02 · File I/O stress under minifilter**
  - With driver loaded: copy 10,000 files, compile a large project (Chromium
    or LLVM), run disk benchmarks (CrystalDiskMark).
  - Verify: no BSOD, no deadlock, no measurable I/O latency regression > 5%.

- [ ] **T5-03 · Process creation/termination storm**
  - Fork-bomb (controlled): create and terminate 10,000 processes in rapid
    succession with driver loaded.
  - Verify: process callbacks handle the storm without pool exhaustion or BSOD.

- [ ] **T5-04 · Registry callback stress**
  - Batch-create 100,000 registry keys, modify, delete.
  - Verify: registry callbacks fire correctly, no BSOD, no missed events.

- [ ] **T5-05 · BSOD crash dump analysis workflow**
  - When a BSOD occurs:
    1. Collect `C:\Windows\MEMORY.DMP` or minidump from `C:\Windows\Minidump\`.
    2. Share the `.dmp` file.
    3. Opus runs: `kd.exe -z <dump> -c "!analyze -v; .bugcheck; kb; lmvm PhantomSensor; q"`
    4. Identify: bugcheck code, faulting instruction, call stack, pool tag.
    5. Fix the root cause. Never band-aid a kernel bug.

- [ ] **T5-06 · Driver Verifier pass**
  - Enable Driver Verifier (`verifier /standard /driver PhantomSensor.sys`)
    on the VM.
  - Run the full workload from T5-02..T5-04 with Verifier active.
  - **Acceptance:** Zero Verifier violations after 4 hours of mixed workload.

---

## TIER 6: INTEGRATION HARDENING & FINAL POLISH

- [ ] **T6-01 · PhantomHome orchestrator integration test**
  - All 18 modules loaded together in the Service process.
  - Verify: no duplicate registrations, no namespace collisions, no ODR
    violations (Banking/Privacy `enum class ModuleStatus` conflicts).
  - Verify: shutdown in reverse-phase order, no use-after-free, no hung threads.

- [ ] **T6-02 · IPC fuzz re-validation**
  - Re-run `build\ipc_frame_fuzz.exe 8192 424242` after any Messages.hpp
    or PipeServer.cpp changes.
  - **Acceptance:** 0 exceptions, 0 crashes.

- [ ] **T6-03 · Memory leak soak test**
  - Run Service + Tray + UI for 72 hours on the VM.
  - Monitor RSS every 5 minutes. Growth must plateau (< 5% increase after
    the first hour).
  - Any monotonic growth = memory leak → fix.

- [ ] **T6-04 · Performance budget enforcement in production config**
  - Verify PerfBudget limits are met in Release builds:
    - Tray: < 48 MB RSS, < 200 ms cold start
    - UI: < 120 MB RSS, < 500 ms cold start
    - Service: < 256 MB RSS, < 1500 ms cold start
  - Measure on: Intel i5-8250U (low-end), Ryzen 5 5600X (mid-range).

- [ ] **T6-05 · Accessibility verification**
  - Run Narrator + Tab navigation through the entire UI.
  - Every interactive element must announce its name and role.
  - Documented in `qml/ACCESSIBILITY.md` verification checklist.

---

## TIER 7: RELEASE CANDIDATE

- [ ] **T7-01 · Full regression pass**
  - Re-run all unit tests (`tests/unit/`), integration tests (`tests/integration/`).
  - 100% pass rate. Any failure = block.

- [ ] **T7-02 · Clean install on 3 VM configurations**
  - Windows 10 22H2 x64, Windows 11 23H2 x64, Windows 11 24H2 x64.
  - MSI install, verify all three processes, run Quick Scan, uninstall clean.

- [ ] **T7-03 · Version stamp and changelog**
  - Set `ProductVersion` in the MSI build to `1.0.0`.
  - Write `CHANGELOG.md` with all capabilities.

- [ ] **T7-04 · Tag and push `v1.0.0-rc1`**
  - Git tag on the release commit.
  - Push to GitHub. Community can build from source.

---

# PART B — PHANTOM EDR & XDR (AFTER HOME IS BATTLE-READY)

> The EDR/XDR plan below is preserved from the original planning session.
> Implementation begins ONLY after Phantom Home passes all Tier 0–7 gates.
> **InteractiveSandbox (EDR-T4-01)** — user-facing VM detonation — remains
> a long-term differentiator and has NOT been implemented yet.

---

## Architecture Philosophy: LOCAL-FIRST, CLOUD-READY

ShadowStrike follows an **open-core** model (like Wazuh). The engine and Community
products are fully open-source. Cloud systems, enterprise dashboards, fleet management,
and premium integrations are reserved for Pro/Enterprise (paid, gitignored).

### The Golden Rule

> **Every Community module MUST be a complete, production-grade, standalone product.**
> If we never build a cloud backend, this product MUST still work at maximized
> malware-hunting rates and enterprise-grade quality. It should never go to garbage.

### Local-First Pattern

Every module that *could* use cloud infrastructure is built behind a clean **interface**:

```
┌──────────────────────────────────────────────────────────┐
│                   Module (e.g. Telemetry)                 │
│                                                          │
│  ┌──────────────────┐    ┌──────────────────────────┐    │
│  │  ITelemetryStore │◄───│  LocalTelemetryStore     │    │  ← Community
│  │  (interface)      │    │  (SQLite ring-buffer)    │    │
│  └──────────────────┘    └──────────────────────────┘    │
│           ▲                                              │
│           │              ┌──────────────────────────┐    │
│           └──────────────│  CloudTelemetryStore     │    │  ← Pro/Enterprise
│                          │  (future — gitignored)   │    │     (FUTURE)
│                          └──────────────────────────┘    │
└──────────────────────────────────────────────────────────┘
```

Community modules define interfaces. Pro/Enterprise provides cloud backends.
The Community implementations use:
- **SQLite** (already vendored) for all local data storage
- **Local files** for artifact/report storage
- **Named pipes / localhost** for IPC (agent ↔ localhost dashboard)
- **HTTP(S) GET** for pulling public threat intel feeds (NVD, abuse.ch, etc.)
  — this is internet access, NOT cloud infrastructure

### What Gets Deferred to Pro/Enterprise (NOT in Community)

| Module | Why Cloud-Only |
|--------|---------------|
| FleetManagement | Multi-endpoint coordination requires central server |
| CloudSecurity (CSPM/CWPP) | Requires AWS/Azure/GCP API credentials + cloud account |
| DataIngestion (syslog/API collector) | Requires network listener/collector server |
| SOAR external integrations | Jira/Slack/ServiceNow connectors need paid API auth |
| Cloud Dashboard data providers | Feeds the paid cloud dashboard in dashboard-cloud/ |
| Remote LiveResponse (cross-endpoint) | Requires central management server |
| Centralized Policy Push (fleet-wide) | Requires server-side policy distribution |

---

## Competitor Benchmark (research performed 2026-04-17)

| Capability                         | CrowdStrike Falcon | SentinelOne Singularity | Palo Alto Cortex XDR | Kaspersky Next EDR | Bitdefender GravityZone |
|------------------------------------|:------------------:|:-----------------------:|:--------------------:|:------------------:|:-----------------------:|
| Forensics & Timeline               | ✔                  | ✔ (Storyline)           | ✔                    | ✔                  | ✔                       |
| Threat Hunting (query language)     | ✔ (Falcon LQL)    | ✔ (Deep Visibility)     | ✔ (XQL)             | ✔                  | ✔ (Live Search)         |
| Automated Playbooks / SOAR         | ✔ (Fusion)        | ✔ (STAR rules)          | ✔ (XSOAR)           | ✔                  | ✔                       |
| Incident Workbench / Viz           | ✔                  | ✔ (Storyline)           | ✔ (Causality)       | ✔                  | ✔ (Attack Chain)        |
| Remote Shell / Live Response       | ✔                  | ✔                       | ✔ (Live Terminal)   | ✔                  | ✔                       |
| Device Control (extended)          | ✔                  | ✔                       | ✔                    | ✔                  | ✔                       |
| Vulnerability / Patch Management   | ✔ (Spotlight)      | ✔ (Ranger)              | ✔ (Host Insights)   | ✔                  | ✔ (Risk Analytics)      |
| Identity Threat Detection          | ✔                  | ✔                       | ✔                    | ✔                  | ✔                       |
| Network Detection (NDR)            |                    | ✔                       | ✔                    | ✔                  | ✔                       |
| Cloud Workload Protection (CWPP)   | ✔ (Horizon)       | ✔                       | ✔                    |                    | ✔                       |
| Email Threat Correlation           |                    |                         | ✔ (2026)            |                    | ✔                       |
| Sandboxing / Detonation            | ✔                  | ✔                       | ✔ (WildFire)        | ✔                  | ✔                       |
| Asset Discovery / IT Hygiene       | ✔ (Discover)      | ✔ (Ranger)              | ✔                    | ✔                  | ✔                       |
| Managed Detection & Response (MDR) | ✔ (Overwatch)     | ✔ (Vigilance)           | ✔ (Unit 42)         | ✔                  | ✔                       |
| Compliance / Reporting             | ✔                  | ✔                       | ✔                    | ✔                  | ✔                       |
| AI SOC Assistant                   | ✔ (Charlotte AI)  | ✔ (Purple AI)           | ✔ (Agentic Asst.)   | ✔ (KIRA)          | ✔                       |

---

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────┐
│  PhantomCore (shared engine — open source)                    │
│  NGAV · Behavioral · AI/ML · Sigs · Heuristic                │
│  RealTime · SelfProtection · RansomwareProtection             │
│  HashStore · PatternStore · SignatureStore · ThreatIntel       │
│  Database · Config · Utils · PEParser · API                   │
└────────────┬─────────────────────┬───────────────────────────┘
             │                     │
    ┌────────▼────────┐   ┌───────▼────────────┐
    │  Phantom EDR     │   │  Phantom XDR        │
    │  (endpoint-only) │   │  (cross-domain)     │
    │  LOCAL-FIRST     │   │  = EDR + NDR +       │
    │                  │   │  Identity + Email +   │
    │  Forensics       │   │  XDR Correlation      │
    │  ThreatHunting   │   │                      │
    │  IncidentResponse│   │  ALL LOCAL — no       │
    │  LiveResponse    │   │  cloud dependency     │
    │  Playbooks       │   │                      │
    │  AssetInventory  │   │  Cloud extensions     │
    │  Vulnerability   │   │  live in Pro/         │
    │  DeviceControl   │   │  Enterprise (future)  │
    │  Compliance      │   │                      │
    │  Telemetry       │   │                      │
    └──────────────────┘   └──────────────────────┘
```

**Key rule:** PhantomXDR EXTENDS PhantomEDR — it inherits all EDR modules and adds
cross-domain correlation. XDR source files may `#include` EDR headers.

---

## PHANTOM EDR — Module Plan (Community / Local-First)

### TIER 1: Core EDR Capabilities (Foundation)

- [x] **EDR-T1-01 · Forensics/** (existing — needs hardening)
  - `TimelineAnalyzer.hpp/.cpp` — attack timeline reconstruction, MITRE ATT&CK mapping
  - `EvidenceCollector.hpp/.cpp` — automated evidence packaging (memory, files, registry, logs)
  - `MemoryDumper.hpp/.cpp` — selective process / full-system memory acquisition
  - `NetworkCapture.hpp/.cpp` — packet capture with BPF-style filters for incident scope
  - `ArtifactExtractor.hpp/.cpp` — browser history, prefetch, shimcache, amcache extraction
  - `IncidentRecorder.hpp/.cpp` — tamper-proof incident journal with chain-of-custody hashing
  - **Storage:** Local files + SQLite index

- [x] **EDR-T1-02 · ThreatHunting/**
  - `HuntQueryEngine.hpp/.cpp` — SQL-like query language (ShadowStrike Query Language — SSQL) over LOCAL telemetry
  - `HuntRuleManager.hpp/.cpp` — YARA-L / Sigma rule ingestion, versioning, and evaluation
  - `IOCScanner.hpp/.cpp` — bulk IOC sweep (hash, IP, domain, mutex, registry, pipe)
  - `HuntScheduler.hpp/.cpp` — recurring hunt jobs with result caching
  - **Storage:** Queries against local SQLite telemetry store

- [x] **EDR-T1-03 · IncidentResponse/**
  - `IncidentManager.hpp/.cpp` — incident lifecycle (create → triage → investigate → contain → remediate → close)
  - `ContainmentEngine.hpp/.cpp` — network isolation, process termination, account lockout
  - `RemediationEngine.hpp/.cpp` — file quarantine, registry rollback, service removal, scheduled-task cleanup
  - `AlertCorrelator.hpp/.cpp` — group raw alerts into unified incidents with severity scoring
  - **Storage:** Local SQLite incident database

- [x] **EDR-T1-04 · LiveResponse/**
  - `ProcessInspector.hpp/.cpp` — live process tree, loaded DLLs, open handles, network connections
  - `RegistryInspector.hpp/.cpp` — registry browse, search, diff on THIS endpoint
  - `FileInspector.hpp/.cpp` — file system browse, hash, timeline for THIS endpoint
  - `LiveResponseTypes.hpp` — shared types
  - **Note:** Remote LiveResponse (cross-endpoint shell) deferred to Pro/Enterprise.
    Community LiveResponse inspects the LOCAL endpoint only.

- [x] **EDR-T1-05 · Telemetry/**
  - `ITelemetryStore.hpp` — **INTERFACE** for storage backends (local vs cloud)
  - `LocalTelemetryStore.hpp/.cpp` — SQLite ring-buffer implementation (Community)
  - `TelemetryCollector.hpp/.cpp` — ring-buffer event collection (process, file, registry, network, DNS)
  - `TelemetrySerializer.hpp/.cpp` — ECS-compatible JSON serialization
  - `TelemetryFilter.hpp/.cpp` — configurable noise reduction (process allowlist, path exclusions)
  - `TelemetryTypes.hpp` — shared event type definitions
  - **Note:** `TelemetryForwarder` (cloud upload) deferred to Pro/Enterprise.
    Community stores locally and serves localhost dashboard queries.

- [x] **EDR-T1-06 · Config/** (existing — needs review)
  - `EDRConfigRegistration.hpp/.cpp` — EDR-specific config keys registered into PhantomCore ConfigManager

### TIER 2: Advanced Detection & Response

- [x] **EDR-T2-01 · Playbooks/**
  - `PlaybookEngine.hpp/.cpp` — YAML/JSON playbook parser and executor (if/then/else, loops, parallel)
  - `PlaybookLibrary.hpp/.cpp` — built-in playbooks (ransomware containment, lateral-movement lockdown, etc.)
  - `PlaybookAction.hpp/.cpp` — action primitives (isolate, kill, quarantine, notify, enrich)
  - `PlaybookScheduler.hpp/.cpp` — trigger on alert, on schedule, or on-demand
  - **Note:** External actions (Jira ticket, Slack alert) deferred to Pro/Enterprise SOAR.
    Community playbooks execute LOCAL actions only.

- [x] **EDR-T2-02 · AssetInventory/**
  - `AssetDiscovery.hpp/.cpp` — local endpoint discovery (WMI, agent heartbeat)
  - `AssetDatabase.hpp/.cpp` — per-endpoint record: OS, patches, users, installed software, hardware
  - `SoftwareInventory.hpp/.cpp` — installed applications with version tracking
  - **Storage:** Local SQLite
  - **Note:** Multi-endpoint fleet view deferred to Pro/Enterprise FleetManagement.

- [x] **EDR-T2-03 · Vulnerability/**
  - `VulnScanner.hpp/.cpp` — match installed software versions against CVE/NVD feeds
  - `VulnDatabase.hpp/.cpp` — local CVE cache with periodic HTTP sync from NVD/GitHub Advisory feeds
  - `PatchAssessment.hpp/.cpp` — Windows Update status, missing KBs, third-party patch state
  - `RiskScorer.hpp/.cpp` — per-endpoint risk score (CVSS + exposure + asset criticality)
  - `VulnTypes.hpp` — shared types
  - **Storage:** Local SQLite CVE cache

- [x] **EDR-T2-04 · DeviceControl/**
  - `DevicePolicyEngine.hpp/.cpp` — granular USB / Bluetooth / Thunderbolt policy (allow, block, read-only, audit)
  - `DeviceAuditLog.hpp/.cpp` — device connect/disconnect event journal
  - `DeviceExceptions.hpp/.cpp` — per-device / per-user exceptions with serial number matching
  - **Storage:** Local config + SQLite audit log

- [x] **EDR-T2-05 · Compliance/**
  - `ComplianceEngine.hpp/.cpp` — CIS Benchmark, NIST 800-53, PCI-DSS, HIPAA checks
  - `ComplianceReporter.hpp/.cpp` — per-endpoint pass/fail/unknown reports (HTML/JSON)
  - `CompliancePolicies.hpp/.cpp` — policy definition and mapping to registry/service/file checks
  - `HardeningAdvisor.hpp/.cpp` — actionable hardening recommendations with auto-fix capability
  - **Storage:** Local files + SQLite

### TIER 3: Enterprise Integration & Polish

- [x] **EDR-T3-01 · Sandboxing/**
  - `LocalSandbox.hpp/.cpp` — lightweight local sandbox (Windows Job Object, restricted token, filesystem virtualization)
  - `SandboxAnalyzer.hpp/.cpp` — parse detonation results: dropped files, network IOCs, behavior tags
  - `SandboxPolicy.hpp/.cpp` — auto-submit rules (by file type, reputation score, detection confidence)
  - `ISandboxBackend.hpp` — **INTERFACE** for sandbox backends (local vs cloud)
  - **Note:** Cloud deep analysis (WildFire-style) deferred to Pro/Enterprise.
    Community provides local lightweight detonation using restricted job objects.

- [x] **EDR-T3-02 · Reporting/**
  - `ReportGenerator.hpp/.cpp` — scheduled and on-demand reports (HTML/JSON to localhost dashboard)
  - `ExecutiveSummary.hpp/.cpp` — KPI dashboard data (threats blocked, MTTD, MTTR)
  - `IncidentReport.hpp/.cpp` — per-incident narrative generation with timeline and IOCs
  - **Storage:** Local HTML/JSON files served to localhost dashboard

- [x] **EDR-T3-03 · PolicyEngine/**
  - `PolicyManager.hpp/.cpp` — local policy management (config files, no central distribution)
  - `PolicyEnforcer.hpp/.cpp` — continuous drift detection and auto-remediation
  - `PolicyAuditLog.hpp/.cpp` — who-changed-what-when tracking
  - `IPolicyDistributor.hpp` — **INTERFACE** for policy distribution (local file vs cloud push)
  - **Note:** Fleet-wide policy push deferred to Pro/Enterprise.

- [x] **EDR-T3-04 · EDROrchestrator**
  - `EDRProductOrchestrator.hpp/.cpp` — product entry point: initializes all EDR subsystems on top of PhantomCore
  - `EDRProductEntry.cpp` — `RegisterEDRModules()` called from main

### TIER 4: Future Differentiator (Long-Term)

- [ ] **EDR-T4-01 · InteractiveSandbox/**
  - `SandboxVMManager.hpp/.cpp` — user-facing VM sandbox: user clicks "Start VM" in UI, runs high-risk file
  - `SandboxUI.hpp/.cpp` — UI integration for sandbox launch, progress, and results display
  - `VMDetonationEngine.hpp/.cpp` — Hyper-V / VirtualBox integration for isolated file execution
  - `SandboxResultViewer.hpp/.cpp` — visual report of what the malware did inside the VM
  - **DIFFERENTIATOR:** No other EDR/XDR vendor offers user-interactive VM sandboxing.
    Users can manually detonate suspicious files and watch behavior in real time.
  - **Note:** This is a long-term feature. Depends on EDR-T3-01 (Sandboxing foundation).

---

## PHANTOM XDR — Module Plan (Community / Local-First)

> XDR = EDR + Cross-Domain Detection. PhantomXDR includes ALL of PhantomEDR plus:

### TIER 1: Cross-Domain Detection (Foundation)

- [x] **XDR-T1-01 · XDRCorrelation/**
  - `CorrelationEngine.hpp/.cpp` — cross-source event stitching (endpoint + network + identity + email)
  - `CorrelationRules.hpp/.cpp` — rule definitions: multi-source patterns, time windows, entity linking
  - `StorylineBuilder.hpp/.cpp` — automatic attack-chain reconstruction (inspired by SentinelOne Storyline)
  - `IncidentScorer.hpp/.cpp` — severity scoring using MITRE ATT&CK tactic/technique coverage
  - `XDRTypes.hpp` — shared cross-domain event types and enums
  - **Storage:** Correlates data from local SQLite telemetry + network + identity stores

- [x] **XDR-T1-02 · NetworkDetection/**
  - `NetworkSensor.hpp/.cpp` — passive traffic analysis (agent-based socket hooking, raw socket capture)
  - `DNSAnalyzer.hpp/.cpp` — DNS query logging, DGA detection, tunneling detection
  - `TLSInspector.hpp/.cpp` — JA3/JA3S fingerprinting, certificate anomaly detection
  - `LateralMovementDetector.hpp/.cpp` — detect SMB/WMI/RDP/PSExec lateral movement patterns
  - `BeaconDetector.hpp/.cpp` — C2 beacon interval analysis (periodic, jitter-aware)
  - `NetworkTypes.hpp` — shared types
  - **Note:** Host-based NDR — no TAP/mirror needed. All local packet inspection.

- [x] **XDR-T1-03 · IdentityProtection/**
  - `ADMonitor.hpp/.cpp` — Active Directory event monitoring (logon, group change, GPO, DCSync, Kerberoasting)
  - `IdentityAnalytics.hpp/.cpp` — UEBA: impossible travel, anomalous access patterns, privilege escalation
  - `CredentialProtection.hpp/.cpp` — LSASS protection, credential cache monitoring, pass-the-hash detection
  - `IdentityTypes.hpp` — shared types
  - **Storage:** Local event log monitoring + SQLite analytics store

- [x] **XDR-T1-04 · EmailThreat/** (moved from XDR-T2 — it's local email header/file analysis)
  - `EmailAnalyzer.hpp/.cpp` — scan local email files (.eml, .msg, .pst) for phishing indicators
  - `PhishingCorrelator.hpp/.cpp` — correlate phishing email → attachment hash → endpoint execution
  - `EmailTypes.hpp` — shared types
  - **Note:** O365/Exchange/Google Workspace cloud connectors deferred to Pro/Enterprise.
    Community analyzes locally available email files only.

### TIER 2: Orchestration & Intelligence

- [x] **XDR-T2-01 · SOARLocal/**
  - `SOAREngine.hpp/.cpp` — local SOAR orchestration: trigger → enrich → decide → act → notify
  - `SOARPlaybooks.hpp/.cpp` — cross-domain playbooks (e.g. phishing → isolate endpoint → block sender)
  - `SOARTypes.hpp` — shared types
  - **Note:** External integrations (Jira, Slack, ServiceNow, SIEM) deferred to Pro/Enterprise.
    Community SOAR executes LOCAL cross-domain actions only.

- [x] **XDR-T2-02 · AIAssistant/**
  - `SOCAssistant.hpp/.cpp` — natural-language threat hunting powered by PhantomCortex LOCAL inference
  - `QueryTranslator.hpp/.cpp` — NL → SSQL translation for hunt queries
  - `IncidentSummarizer.hpp/.cpp` — auto-generate human-readable incident narratives
  - `AssistantTypes.hpp` — shared types
  - **Note:** Uses PhantomCortex local ML models. Cloud-enhanced LLM deferred to Pro/Enterprise.

### TIER 3: Configuration & Orchestration

- [x] **XDR-T3-01 · Config/** (existing — needs review)
  - `XDRConfigRegistration.hpp/.cpp` — XDR-specific config keys registered into PhantomCore ConfigManager

- [x] **XDR-T3-02 · XDROrchestrator**
  - `XDRProductOrchestrator.hpp/.cpp` — product entry point: initializes EDR subsystems + XDR subsystems
  - `XDRProductEntry.cpp` — `RegisterXDRModules()` called from main

---

## Modules DEFERRED to Pro/Enterprise (NOT in Community)

These require cloud infrastructure, external API subscriptions, or multi-endpoint coordination.
They will live in `Products/Pro/` and `Products/Enterprise/` (gitignored).

| Module | Tier | Reason for Deferral |
|--------|------|---------------------|
| FleetManagement | Pro | Multi-endpoint fleet view requires central server |
| CloudSecurity (CSPM/CWPP) | Enterprise | Requires AWS/Azure/GCP API credentials |
| DataIngestion (syslog/API) | Pro | Requires network listener/collector infrastructure |
| SOAR External Integrations | Pro | Jira/Slack/ServiceNow need paid API subscriptions |
| Cloud Dashboard Providers | Pro | Feeds dashboard-cloud/ (paid per-endpoint) |
| Remote LiveResponse | Pro | Cross-endpoint shell requires central management |
| Centralized Policy Push | Enterprise | Fleet-wide policy requires server-side distribution |
| TelemetryForwarder (cloud) | Pro | Forward telemetry to cloud SIEM/OpenSearch |
| Cloud Sandbox (deep) | Enterprise | WildFire-style cloud detonation chamber |

---

## Implementation Order

```
Phase 1 — EDR Tier 1 (Foundation)
  EDR-T1-06 Config (review existing)
  EDR-T1-05 Telemetry (everything else depends on local event store)
  EDR-T1-01 Forensics (harden existing 6 modules)
  EDR-T1-03 IncidentResponse
  EDR-T1-02 ThreatHunting
  EDR-T1-04 LiveResponse

Phase 2 — EDR Tier 2 (Advanced)
  EDR-T2-01 Playbooks
  EDR-T2-02 AssetInventory
  EDR-T2-03 Vulnerability
  EDR-T2-04 DeviceControl
  EDR-T2-05 Compliance

Phase 3 — EDR Tier 3 (Enterprise Local)
  EDR-T3-01 Sandboxing (local lightweight)
  EDR-T3-02 Reporting
  EDR-T3-03 PolicyEngine
  EDR-T3-04 EDROrchestrator (wires everything)

Phase 4 — XDR Tier 1 (Cross-Domain)
  XDR-T1-01 XDRCorrelation (the brain)
  XDR-T1-02 NetworkDetection (host-based NDR)
  XDR-T1-03 IdentityProtection
  XDR-T1-04 EmailThreat (local email analysis)

Phase 5 — XDR Tier 2 (Orchestration)
  XDR-T2-01 SOARLocal
  XDR-T2-02 AIAssistant

Phase 6 — XDR Tier 3 (Config & Orchestration)
  XDR-T3-01 Config (review existing)
  XDR-T3-02 XDROrchestrator

Phase 7 — EDR Tier 4 (Future Differentiator)
  EDR-T4-01 InteractiveSandbox (user-facing VM detonation — UNIQUE FEATURE)
```

---

## Interface Contracts (Cloud-Ready Slots)

These interfaces are defined in Community but only implemented locally.
Pro/Enterprise will provide cloud implementations.

| Interface | Community Impl | Pro/Enterprise Impl (Future) |
|-----------|---------------|-------------------------------|
| `ITelemetryStore` | `LocalTelemetryStore` (SQLite) | `CloudTelemetryStore` (OpenSearch) |
| `ISandboxBackend` | `LocalSandbox` (Job Object) | `CloudSandbox` (VM detonation) |
| `IPolicyDistributor` | `LocalPolicyFile` (config) | `CloudPolicyPush` (gRPC) |
| `IVulnFeed` | `NVDHttpSync` (periodic GET) | `CloudVulnFeed` (real-time) |
| `ISOARConnector` | (none — local only) | `JiraConnector`, `SlackConnector`, etc. |

---

## What PhantomCore Already Provides (DO NOT DUPLICATE)

| Module              | Provided By PhantomCore     | EDR/XDR Just Consumes It  |
|---------------------|-----------------------------|---------------------------|
| NGAV Scanning       | ScanEngine, SignatureStore   | ✔ via API                |
| Behavioral Analysis | AI/BehaviorAnalyzer          | ✔ via callbacks          |
| Heuristic Analysis  | AI/HeuristicAnalyzer         | ✔ via callbacks          |
| ML Inference        | AI/CortexInference           | ✔ via API                |
| Real-Time Monitor   | RealTime/*                   | ✔ via event stream       |
| Self-Protection     | SelfProtection/*             | ✔ automatic              |
| Anti-Evasion        | AntiEvasion/*                | ✔ automatic              |
| Ransomware Block    | RansomwareProtection/*       | ✔ automatic              |
| Hash/Pattern/Sig    | HashStore, PatternStore, etc.| ✔ via singleton access   |
| Threat Intel        | ThreatIntel/*                | ✔ via API                |
| Config              | Config/ConfigManager         | EDR/XDR register own keys|
| Database            | Database/*                   | ✔ shared DB layer        |
| Logging             | Utils/Logger                 | ✔ shared                 |

---

## Notes

1. **All EDR/XDR code lives OUTSIDE PhantomCore** — clean product-layer separation.
2. **XDR includes EDR** — XDR orchestrator initializes EDR orchestrator first, then adds cross-domain.
3. **PhantomHome does NOT get EDR/XDR features** — Home has its own consumer modules (Banking, Privacy, etc.).
4. **LOCAL-FIRST:** Community implementations use SQLite, local files, and localhost APIs.
   Cloud backends are injected via interfaces in Pro/Enterprise only.
5. **Every module follows ShadowStrike conventions:** Meyers' Singleton or PIMPL, RAII, C++20, no raw new/delete,
   thread-safe, enterprise-grade error handling and logging.
6. **InteractiveSandbox is a DIFFERENTIATOR** — no competitor offers user-facing VM detonation. Long-term goal.

# Chapter 10: Development Workflow & Testing

> *"An EDR without comprehensive tests is an EDR that will regress. In security software, a regression means a bypass."*

---

## 10.1 Testing Philosophy

ShadowStrike's testing strategy is built on three principles:

1. **Deterministic contracts** — tests validate module behavior through API contracts, not implementation details
2. **No external dependencies** — tests run without network access, cloud services, or external files
3. **Defense-in-depth** — unit tests validate individual modules, integration tests validate module chains, adversary simulations validate the complete detection pipeline

---

## 10.2 Test Infrastructure Overview

### 10.2.1 Scale

| Category | Files | Purpose |
|----------|-------|---------|
| Unit tests | 174 | Individual module contract validation |
| Integration tests | 16 | Cross-module pipeline testing |
| Adversary simulations | 10 | MITRE ATT&CK technique simulation |
| Support files | 9 | Stubs, link shims, dependency stubs |
| Test utilities | 11 | Shared fixtures and helpers |
| **Total** | **220** | |

### 10.2.2 Framework

ShadowStrike uses **Google Test 1.14+** with **Google Mock** for all C++ testing:

```cpp
// tests/test_main.cpp — shared entry point for all test harnesses
#include <gtest/gtest.h>

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
```

Libraries are vendored in `vendor/gtest_framework/`:
- `gtest.lib` / `gtest.dll` — Test framework (compiled as debug DLL)
- `gmock.lib` / `gmock.dll` — Mocking framework (compiled as debug DLL)

> ⚠️ **Important:** Both `gtest.dll` and `gmock.dll` are **debug builds** (depend on `MSVCP140D.dll`). All test harnesses **must** compile with `/MDd` (debug multi-threaded DLL runtime). Mismatching runtimes causes linker errors or cryptic crashes at test startup.

---

## 10.3 Test Directory Structure

```
tests/
├── test_main.cpp                    # Shared GTest entry point
│
├── unit/                            # Unit tests (174 files)
│   ├── ai_unit/                     # AI/ML modules (5 tests)
│   │   ├── AI_TestUtils.hpp
│   │   ├── FeatureExtractor_Tests.cpp
│   │   ├── ModelCache_Tests.cpp
│   │   ├── ModelInference_Tests.cpp
│   │   ├── PhantomCortexConfig_Tests.cpp
│   │   └── ZeroHourProtection_Tests.cpp
│   │
│   ├── antievasion_unit/            # Anti-evasion detectors (9 tests)
│   │   ├── AntiEvasion_TestUtils.hpp
│   │   ├── DebuggerEvasionDetector_Tests.cpp
│   │   ├── EnvironmentEvasionDetector_Tests.cpp
│   │   ├── NetworkBasedEvasionDetector_Tests.cpp
│   │   ├── PackerDetector_Tests.cpp
│   │   ├── ProcessEvasionDetector_Tests.cpp
│   │   ├── SandboxEvasionDetector_Tests.cpp
│   │   ├── TimeBasedEvasionDetector_Tests.cpp
│   │   └── VMEvasionDetector_Tests.cpp
│   │
│   ├── communication_unit/          # IPC & telemetry (8 tests)
│   ├── config_unit/                 # Configuration management (4 tests)
│   ├── core_engine_unit/            # Engine core (8 tests)
│   ├── core_filesys_unit/           # File system analysis (4 tests)
│   ├── core_network_unit/           # Network monitoring (5 tests)
│   ├── core_process_unit/           # Process analysis (10 tests)
│   ├── core_registry_unit/          # Registry monitoring (5 tests)
│   ├── core_sys_unit/               # System utilities (7 tests)
│   ├── exploits_unit/               # Exploit prevention (7 tests)
│   ├── FuzzyHasher_Unit/            # Fuzzy hashing (3 tests)
│   ├── peparser_unit/               # PE binary parsing (3 tests)
│   ├── perf_unit/                   # Performance monitoring (3 tests)
│   ├── perf_dev_unit/               # Dev profiling (2 tests)
│   ├── ransomware_protection_unit/  # Ransomware detection (9 tests)
│   ├── realtime_unit/               # Real-time protection (10 tests)
│   ├── scripts_unit/                # Script scanning (6 tests)
│   ├── selfprotection_unit/         # Self-protection stack (10 tests)
│   ├── service_unit/                # Service lifecycle (5 tests)
│   ├── update_unit/                 # Update system (8 tests)
│   ├── utils_unit/                  # Utility modules (12 tests)
│   └── Database_systems_unit/       # Database subsystems
│       ├── sig_store/               # Signature store (12 tests)
│       ├── threat_intel/            # Threat intelligence (10 tests)
│       └── white_list/              # Whitelist store (5 tests)
│
├── integration/                     # Integration tests (16 files)
│   ├── ai_pipeline/
│   ├── anti_evasion/
│   ├── communication_pipeline/
│   ├── config_propagation/
│   ├── core_filesystem/
│   ├── core_network/
│   ├── core_process/
│   ├── core_registry/               # (3 tests)
│   ├── exploit_protection/
│   ├── ransomware_protection/
│   ├── realtime_protection_pipeline/
│   ├── scan_pipeline/
│   ├── self_protection/
│   └── update_lifecycle/
│
└── (stubs & shims)
    ├── ZeroHour_stubs.cpp
    ├── RealTimeProtection_stubs.cpp
    ├── ProcessCreationMonitor_stubs.cpp
    ├── MemoryProtection_stubs.cpp
    ├── FileSystemFilter_stubs.cpp
    ├── SelfProtection_LinkShim.cpp
    ├── RansomwareDetector_LinkShim.cpp
    ├── ExploitProtection_DependencyStubs.cpp
    └── SelfProtection_DependencyStubs.cpp
```

---

## 10.4 Unit Test Categories

### 10.4.1 Coverage by Module

| Category | Tests | Focus |
|----------|-------|-------|
| utils_unit | 12 | String, file, crypto, network utilities |
| sig_store | 12 | Signature store, pattern matching, YARA |
| threat_intel | 10 | Threat intelligence, feeds, IoC lookup |
| realtime_unit | 10 | File system filter, memory, process, exploit monitoring |
| core_process_unit | 10 | Process analysis, injection, memory scanning |
| selfprotection_unit | 10 | Tamper protection, signatures, anti-debug |
| ransomware_protection_unit | 9 | Ransomware detection, backup, snapshots |
| antievasion_unit | 9 | Debugger/VM/packer/sandbox evasion detection |
| core_engine_unit | 8 | ML detection, behavior analysis, emulation |
| communication_unit | 8 | IPC, telemetry, alerts, reporting |
| update_unit | 8 | Update verification, rollback, signature updates |
| exploits_unit | 7 | ROP, heap spray, buffer overflow, JIT spray |
| core_sys_unit | 7 | System info, event logging, performance |
| scripts_unit | 6 | VB/Python/PowerShell/JavaScript/AMSI |
| white_list | 5 | Whitelist storage and filtering |
| core_network_unit | 5 | DNS, firewall, traffic analysis |
| core_registry_unit | 5 | Registry monitoring, persistence |
| service_unit | 5 | Service lifecycle, installation |
| ai_unit | 5 | ML model inference, feature extraction |
| config_unit | 4 | Configuration, policy management |
| core_filesys_unit | 4 | File type analysis, reputation |
| peparser_unit | 3 | PE binary parsing and validation |
| perf_unit | 3 | CPU/disk/network performance |
| FuzzyHasher_Unit | 3 | Fuzzy hashing (SSDEEP, TLSH) |
| perf_dev_unit | 2 | Development profiling |

### 10.4.2 Unit Test Conventions

**Naming:**
- Test files: `{ModuleName}_Tests.cpp`
- Test fixtures: `{ModuleName}Test` (inherits `::testing::Test`)
- Test cases: `TEST_F({Fixture}, {DescriptiveName})`

**Fixture Pattern:**

```cpp
class FileSystemFilterTest : public ::testing::Test {
protected:
    FileSystemFilter& filter = FileSystemFilter::Instance();

    void SetUp() override {
        // Reset singleton state for test isolation
    }

    void TearDown() override {
        // Clean up any test artifacts
    }
};

TEST_F(FileSystemFilterTest, ExclusionMatchingAndCallbacksRemainDeterministic) {
    const auto defaults = FileSystemFilterConfig::CreateDefault();
    const auto performance = FileSystemFilterConfig::CreateHighPerformance();
    const auto paranoid = FileSystemFilterConfig::CreateParanoid();

    EXPECT_TRUE(defaults.scanOnOpen);
    EXPECT_FALSE(performance.enableNotifications);
    EXPECT_TRUE(paranoid.blockOnTimeout);
}
```

**Value Contract Testing:**

Tests validate **contracts** (what the module promises), not **implementation** (how it does it):

```cpp
// GOOD: Tests the contract — "TechniqueMetadata is stable across versions"
TEST(DebuggerEvasionDetector_Helpers, TechniqueMetadataMappingsRemainStable) {
    EXPECT_STREQ("T1622", 
        EvasionTechniqueToMitreId(EvasionTechnique::PEB_BeingDebugged));
    EXPECT_EQ(EvasionCategory::PEBBased, 
        GetTechniqueCategory(EvasionTechnique::PEB_BeingDebugged));
    EXPECT_EQ(EvasionSeverity::Medium, 
        GetDefaultTechniqueSeverity(EvasionTechnique::PEB_BeingDebugged));
}

// GOOD: Tests the builder pattern — "Builder populates all fields"
TEST(DebuggerEvasionDetector_Builder, DetectionPatternBuilderPopulatesDerivedFields) {
    DetectedTechnique detection = DetectionPatternBuilder{}
        .Technique(EvasionTechnique::THREAD_TLSCallback)
        .Confidence(0.94)
        .Address(0x1000)
        .Build();
    EXPECT_EQ(detection.technique, EvasionTechnique::THREAD_TLSCallback);
    EXPECT_DOUBLE_EQ(detection.confidence, 0.94);
}
```

**No External Dependencies:**

```cpp
// Tests work without ONNX Runtime, model files, or network access
class ModelInferenceTest : public ::testing::Test {
protected:
    ScopedTempDir tempDir{L"ShadowStrike_AIModelInference_"};

    void SetUp() override {
        ModelInference::Instance().Shutdown();  // Clean state
    }
};

TEST_F(ModelInferenceTest, InferenceWithoutLoadedModelsReturnsGuardResult) {
    // Validates guard behavior — no model file needed
    auto result = ModelInference::Instance().Classify(features);
    EXPECT_FALSE(result.has_value());
}
```

---

## 10.5 Integration Tests

### 10.5.1 Purpose

Integration tests validate that modules work correctly **together** — that the wiring between components is correct and that data flows through the pipeline as expected.

### 10.5.2 Integration Test Chains

| Chain | Tests | Validates |
|-------|-------|-----------|
| **FileSystemChain** | File filter ↔ signature/threat intel stores | File access triggers correct scan pipeline |
| **ProcessChain** | Process monitoring ↔ detection pipeline | Process creation triggers behavioral analysis |
| **RegistryChain** | Registry analysis ↔ threat intelligence | Registry changes correlated with known IoCs |
| **NetworkChain** | Network monitoring ↔ reputation lookups | Network connections checked against blocklists |
| **RTPPipeline** | End-to-end real-time protection | Complete scan from kernel notification to verdict |
| **AIPipeline** | Feature extraction → model inference → verdict | ML classification pipeline |
| **ScanPipeline** | Whitelist → hash → TI → YARA → heuristic → behavior → ML | Full detection pipeline ordering |
| **RansomwareDetector** | Ransomware detection + backup protection | Canary files, entropy analysis, shadow copies |
| **SelfProtectionStack** | Anti-tampering + self-defense coordination | Process protection, file integrity, tamper alerts |
| **ExploitProtection** | Multi-layer exploit prevention | ROP, heap spray, stack pivot, JIT spray |
| **CommunicationPipeline** | IPC → telemetry → alerts → reporting | Event flow from detection to administrator |
| **ConfigPropagation** | Policy → configuration → module settings | Configuration changes propagate correctly |
| **UpdateLifecycle** | Download → verify → apply → rollback | Signature update integrity and rollback |

### 10.5.3 Store-Wired Integration Pattern

```cpp
// Integration test that wires real disk-backed stores:
class AntiEvasionIntegrationTest : public ::testing::Test {
protected:
    ScopedTempDir tempDir{L"ShadowStrike_AntiEvasion_"};
    std::unique_ptr<SignatureStore> sigStore;
    std::unique_ptr<ThreatIntelStore> tiStore;

    void SetUp() override {
        // Create real on-disk stores
        sigStore = std::make_unique<SignatureStore>();
        sigStore->CreateNew(tempDir.Path() / L"sigs.db", 1024*1024);

        tiStore = std::make_unique<ThreatIntelStore>();
        tiStore->Initialize(ThreatIntelStore::StoreConfig{
            .storePath = tempDir.Path() / L"ti.db"
        });

        // Wire detectors to real stores
        DebuggerEvasionDetector::Instance().SetSignatureStore(sigStore.get());
        VMEvasionDetector::Instance().SetThreatIntelStore(tiStore.get());
    }
};
```

This pattern validates that:
1. Store initialization works with real disk I/O
2. Detectors correctly query stores during analysis
3. Results propagate through the detection chain
4. Cleanup is complete (RAII, `ScopedTempDir`)

---

## 10.6 Adversary Simulation Tests

### 10.6.1 Purpose

The `malware_tests/` directory contains controlled adversary technique simulators. Each program implements a specific MITRE ATT&CK technique to validate that the kernel driver (`PhantomSensor.sys`) detects it correctly.

### 10.6.2 Simulation Catalog

| # | Executable | MITRE Technique | Kernel Modules Tested |
|---|-----------|-----------------|----------------------|
| 01 | `heavens_gate.exe` | T1106 — Native API (Heaven's Gate) | SyscallMonitor, NtdllIntegrity |
| 02 | `process_hollowing.exe` | T1055.012 — Process Hollowing | InjectionDetector, MemoryScanner |
| 03 | `dll_injection.exe` | T1055.001 — DLL Injection | ThreadProtection, ProcessProtection |
| 04 | `direct_syscall.exe` | T1106 — Direct Syscalls | SyscallMonitor |
| 05 | `credential_access.exe` | T1003.001/.002 — LSASS/SAM | ProcessProtection, PreCreate |
| 06 | `ransomware_sim.exe` | T1486 — Data Encrypted for Impact | PreSetInfo, BehaviorEngine |
| 07 | `registry_persistence.exe` | T1547/T1546/T1543 — Persistence | RegistryCallback, ThreatScoring |
| 08 | `self_protection.exe` | T1562.001 — Disable Security | AntiUnload, HandleProtection |
| 09 | `ppid_spoof.exe` | T1134.004 — PPID Spoofing | ProcessNotify, BehaviorEngine |
| 10 | `apc_injection.exe` | T1055.004 — APC Injection | ThreadProtection, MemoryScanner |

### 10.6.3 Safety

> ⚠️ **Important:** These are **controlled simulations**, not actual malware. They:
> - Contain no destructive payloads
> - Operate only on test files in temporary directories
> - Are designed to trigger detection, not to evade it
> - Must be run in an isolated VM with the kernel driver loaded
> - Are compiled from C source in `malware_tests/` — fully reviewable

---

## 10.7 Test Build System

### 10.7.1 Build Scripts

Each test suite has a dedicated build script in `build/`:

| Script | Output | Tests |
|--------|--------|-------|
| `build_ai_tests.bat` | `ai_unit_tests.exe` | AI/ML modules |
| `build_anti_evasion_integration.bat` | `anti_evasion_tests.exe` | Anti-evasion chain |
| `build_comm_pipeline_integration.bat` | `communication_tests.exe` | IPC pipeline |
| `build_core_filesystem_integration.bat` | `core_filesystem_tests.exe` | File system chain |
| `build_core_network_integration.bat` | `core_network_tests.exe` | Network chain |
| `build_exploit_protection_integration.bat` | `exploit_tests.exe` | Exploit prevention |
| `build_scan_pipeline_integration.bat` | `scan_pipeline_tests.exe` | Scan pipeline |
| `build_self_protection_integration.bat` | `self_protection_tests.exe` | Self-protection |
| `build_ai_integration.bat` | `ai_integration_tests.exe` | AI pipeline |

### 10.7.2 Build Pattern

All build scripts follow a consistent pattern:

```batch
@echo off
:: Initialize MSVC x64 environment
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64

:: Compiler flags (same across all scripts)
set CFLAGS=/std:c++20 /EHsc /MDd /W4 /wd4100 /wd4189 /wd4244 /wd4267 /wd4996

:: Include paths
set INCLUDES=/I. /Isrc /Isrc\Shared_modules /Iinclude /Iinclude\YARA /Ivendor

:: Compile all sources
cl %CFLAGS% %INCLUDES% ^
    tests\test_main.cpp ^
    tests\unit\ai_unit\*_Tests.cpp ^
    src\Shared_modules\AI\*.cpp ^
    src\Shared_modules\Utils\*.cpp ^
    /Fe:build\ai_unit_tests.exe ^
    /link /LIBPATH:vendor\gtest_framework gtest.lib gmock.lib ^
          /LIBPATH:vendor\openssl_lib libcrypto.lib libssl.lib ^
          advapi32.lib ws2_32.lib crypt32.lib ...
```

### 10.7.3 Response Files

For large test suites with hundreds of source files, MSVC response files (`.rsp`) manage the compilation:

```
build/
├── exploits_sources.rsp         # Exploits module source list
├── antievasion_sources.rsp      # AntiEvasion source list
├── database_sources.rsp         # Database module source list
├── config_sources.rsp           # Config module source list
├── comm_sources.rsp             # Communication source list
└── rtp_pipeline/
    ├── compile_current.rsp      # Compiler flags
    ├── link_current_min.rsp     # Linker flags
    └── build_and_run_focused.ps1  # PowerShell build+run script
```

### 10.7.4 Running Tests

```powershell
# Set DLL paths (required for gtest.dll resolution)
$env:PATH = "build;vendor\gtest_framework;vendor\openssl_lib;$env:PATH"

# Build and run a specific test suite:
.\build\build_ai_tests.bat
.\build\ai_unit_tests.exe

# Run with Google Test filters:
.\build\ai_unit_tests.exe --gtest_filter="ModelInference*"

# Run with verbose output:
.\build\ai_unit_tests.exe --gtest_print_time=1

# Run with XML output for CI:
.\build\ai_unit_tests.exe --gtest_output=xml:build\results\ai_tests.xml
```

> 📌 **Key Insight:** Test executables require `build/` on the PATH for `gtest.dll` resolution. Without this, tests fail with exit code `-1073741515` (`STATUS_DLL_NOT_FOUND`). This is the most common "tests won't run" issue.

---

## 10.8 Test Helpers and Utilities

### 10.8.1 ScopedTempDir

The most frequently used test utility — creates a unique temporary directory that auto-cleans on destruction:

```cpp
// From AI_TestUtils.hpp:
class ScopedTempDir {
    std::filesystem::path m_path;
public:
    explicit ScopedTempDir(const std::wstring& prefix) {
        // Creates: %TEMP%/{prefix}{PID}_{atomic_counter}/
        // Unique per test, per process, per run
    }
    ~ScopedTempDir() {
        std::filesystem::remove_all(m_path);  // Recursive cleanup
    }
    const std::filesystem::path& Path() const { return m_path; }
};
```

### 10.8.2 Test Utility Headers

| Utility | Location | Provides |
|---------|----------|----------|
| `AI_TestUtils.hpp` | `ai_unit/` | ScopedTempDir, binary I/O, PE header generation |
| `RealTime_TestUtils.hpp` | `realtime_unit/` | Real-time monitoring fixtures |
| `AntiEvasion_TestUtils.hpp` | `antievasion_unit/` | Evasion detection fixtures |
| `CoreNetwork_TestUtils.hpp` | `core_network_unit/` | Network chain helpers |
| `CoreFileSystem_TestUtils.hpp` | `core_filesys_unit/` | File system helpers |
| `PEParser_TestUtils.hpp` | `peparser_unit/` | PE binary test data |
| `Config_TestUtils.hpp` | `config_unit/` | Configuration fixtures |
| `CoreRegistry_TestUtils.hpp` | `core_registry_unit/` | Registry monitor helpers |
| `CoreSystem_TestUtils.hpp` | `core_sys_unit/` | System info fixtures |
| `Update_TestUtils.hpp` | `update_unit/` | Update lifecycle helpers |
| `RansomwareProtection_TestUtils.hpp` | `ransomware_protection_unit/` | Ransomware simulation |

### 10.8.3 Stubs and Link Shims

For modules with complex dependencies that can't be easily mocked, ShadowStrike uses **stubs** (empty implementations) and **link shims** (forwarding layers):

**Stubs** — provide minimal implementations for linker satisfaction:

```cpp
// ZeroHour_stubs.cpp — stub for ZeroHourProtection in test builds
namespace ZeroHour {
    bool Initialize() { return true; }
    void Shutdown() {}
    ScanResult Scan(const ScanContext&) { return ScanResult::Clean; }
}
```

**Link Shims** — provide controlled forwarding for specific test scenarios:

```cpp
// SelfProtection_LinkShim.cpp — redirects self-protection calls
// Allows testing detection logic without actually locking down the process
```

---

## 10.9 Continuous Integration

### 10.9.1 Coverity Scan

The primary CI pipeline runs Coverity static analysis on every push to `master`:

```yaml
# .github/workflows/coverity-scan.yml
on:
  push:
    branches: [master, main]
  schedule:
    - cron: '0 0 * * 0'  # Weekly Sunday midnight UTC
```

**Current Metrics:**
- Defect density: **0.25 defects per 1,000 lines** (industry average: 1.0)
- Zero high-severity findings
- Full kernel driver analysis included

### 10.9.2 Future CI Enhancements

Planned additions to the CI pipeline:
- Google Test result reporting (XML → GitHub Actions annotations)
- Code coverage measurement (MSVC `/coverage`)
- Build matrix (Debug/Release × x64/ARM64)
- WHQL pre-certification checks

---

## 10.10 Development Workflow

### 10.10.1 Module Development Cycle

```
1. Read existing headers and implementations
   └─ Understand contracts, naming, patterns

2. Implement the module
   └─ Follow patterns from Chapter 3

3. Write unit tests
   └─ Test contracts, not implementation
   └─ Cover edge cases and error paths

4. Build and run unit tests
   └─ 100% pass rate required

5. Write integration tests (if cross-module)
   └─ Wire real stores and validate data flow

6. Build and run integration tests
   └─ 100% pass rate required

7. Static analysis (Coverity)
   └─ Zero new defects

8. Commit with descriptive message
   └─ No AI signatures, no Copilot trailers
   └─ Author: ShadowStrike-Labs <contact@ShadowStrike.dev>
```

### 10.10.2 Multi-Agent Development Protocol

When multiple developers (or AI agents) work simultaneously, ShadowStrike uses a lock file protocol:

```
1. Before modifying a file:
   - Check if {filename}.lock exists
   - If yes: wait for it to be deleted
   - If no: create {filename}.lock

2. Make changes to the .lock file

3. Transfer changes from .lock to the real file

4. Delete the .lock file

5. Before building:
   - Check if BUILDING.warning exists in project root
   - If yes: wait for it to be deleted
   - If no: create BUILDING.warning, build, delete BUILDING.warning
```

This prevents:
- Two agents editing the same file simultaneously
- Two agents running builds simultaneously (MSBuild conflicts)
- Lost changes from concurrent writes

---

## 10.11 Summary

| Aspect | Details |
|--------|---------|
| **Test Count** | 190 files (174 unit + 16 integration) |
| **Framework** | GoogleTest 1.14+ with GoogleMock |
| **Language Standard** | C++20 (`/std:c++20 /MDd`) |
| **Build System** | MSVC cl.exe with batch scripts + .rsp files |
| **Test Pattern** | Fixture-based with SetUp/TearDown |
| **Mocking** | Stubs, link shims, dependency injection |
| **Key Principle** | Deterministic contracts, no external dependencies |
| **Adversary Tests** | 10 MITRE ATT&CK technique simulators |
| **CI/CD** | Coverity Scan (0.25 defects/KLoC) |
| **Pass Requirement** | 100% — no failing tests allowed |

---

*Previous: [Chapter 9 — Module Relationships & Dependency Graph](ch09-module-relationships.md)*

*End of Volume 1: Foundations*

*Next Volume: [Volume 2 — The Kernel Sentinel](../vol2-kernel-sentinel/)*

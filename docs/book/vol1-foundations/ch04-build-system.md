# Chapter 4: The Build System

> *"A build system is the first thing an attacker probes and the last thing a developer wants to debug."*

---

## 4.1 Solution Overview

ShadowStrike builds as a Visual Studio 2022 solution (`ShadowStrike.sln`) containing five projects that produce binaries for three distinct execution environments:

| Project | Output | Environment | Toolset |
|---------|--------|-------------|---------|
| **ShadowStrike** | `ShadowStrike.exe` | User mode (x64/x86) | v143 (MSVC) |
| **PhantomSensor** | `PhantomSensor.sys` | Kernel mode (x64/ARM64) | WindowsKernelModeDriver10.0 |
| **PhantomHome** | `PhantomHome.exe` | User mode — consumer UI | v145 (MSVC) |
| **PhantomEDR** | `PhantomEDR.exe` | User mode — enterprise service | v145 (MSVC) |
| **PhantomXDR** | `PhantomXDR.exe` | User mode — XDR service | v145 (MSVC) |

```
ShadowStrike.sln
├── ShadowStrike.vcxproj              GUID: {7E511BF5-...}
├── PhantomSensor\PhantomSensor.vcxproj  GUID: {78370031-...}
├── PhantomHome.vcxproj               GUID: {264DE895-...}
├── PhantomEDR.vcxproj                GUID: {A3904751-...}
└── PhantomXDR.vcxproj                GUID: {C1829004-...}
```

---

## 4.2 Configurations and Platforms

### 4.2.1 User-Mode Projects (ShadowStrike, PhantomHome, PhantomEDR, PhantomXDR)

| Configuration | Platform | Purpose |
|---------------|----------|---------|
| Debug\|Win32 | x86 32-bit | Legacy testing, WoW64 validation |
| Release\|Win32 | x86 32-bit | 32-bit release (rare) |
| Debug\|x64 | x64 64-bit | **Primary development configuration** |
| Release\|x64 | x64 64-bit | **Production release** |

### 4.2.2 Kernel Driver (PhantomSensor)

| Configuration | Platform | Purpose |
|---------------|----------|---------|
| Debug\|x64 | x64 64-bit | **Primary driver development** |
| Release\|x64 | x64 64-bit | **Production driver release** |
| Debug\|ARM64 | ARM64 | Windows on ARM development (future) |
| Release\|ARM64 | ARM64 | Windows on ARM release (future) |

> 📌 **Key Insight:** The kernel driver supports ARM64 as a first-class platform. While x64 is the current focus, ARM64 support in the build system means ShadowStrike is future-proofed for Windows on ARM devices (Surface Pro X, Snapdragon laptops).

---

## 4.3 Compiler Configuration

### 4.3.1 Language Standards

| Setting | Value | Notes |
|---------|-------|-------|
| C++ Standard | `/std:c++23` (vcxproj) / `/std:c++20` (build scripts) | C++23 in project files, C++20 in test builds |
| C Standard | `/std:c17` | For C sources (SQLite, kernel shared headers) |
| Exception Handling | `/EHsc` | Synchronous C++ exceptions only |
| Warning Level | `/W4` (projects) / `/W4` (scripts) | High warning level |
| Multi-processor | `MultiProcessorCompilation=true` | Parallel compilation |

> 💡 **Advanced C++ Note:** The vcxproj files specify `/std:c++23`, but the standalone build scripts use `/std:c++20`. This is intentional — the project files use the latest standard for IntelliSense and future-proofing, while build scripts use C++20 for compatibility with older toolchain installations. All code is written to compile under both standards.

### 4.3.2 Warning Suppressions

ShadowStrike suppresses a carefully selected set of MSVC warnings in build scripts:

| Warning | Meaning | Reason for Suppression |
|---------|---------|----------------------|
| `/wd4100` | Unreferenced formal parameter | Interface methods with unused params |
| `/wd4189` | Local variable initialized but not referenced | Debug-only variables |
| `/wd4244` | Conversion from larger to smaller type | Intentional narrowing (size_t → uint32_t) |
| `/wd4267` | Conversion from `size_t` to smaller type | Same as 4244 for 64-bit `size_t` |
| `/wd4996` | Deprecated function | Use of `GetVersionEx`, legacy Win32 APIs |
| `/wd4834` | Discarding `[[nodiscard]]` return | Test code that intentionally ignores returns |

> ⚠️ **Security Note:** Warning suppression is applied surgically. In production code, every suppression is justified. The kernel driver compiles with `/W4` **and** `TreatWarningAsError=true` — meaning any warning in the driver code fails the build.

### 4.3.3 Preprocessor Definitions

**User-Mode (x64):**

```
GTEST_LINKED_AS_SHARED_LIBRARY=1     // Google Test linked as DLL
GMOCK_LINKED_AS_SHARED_LIBRARY=1     // Google Mock linked as DLL
```

**User-Mode (Win32, Debug):**

```
WIN32
_DEBUG
_WINDOWS
```

**User-Mode (Win32, Release):**

```
WIN32
NDEBUG
_WINDOWS
```

**Conditional Compilation Guards:**

```cpp
// YARA-backed signature store implementations
#ifdef SHADOWSTRIKE_HAS_YARA
    // Real YARA integration
#else
    // Stub implementations
#endif
```

### 4.3.4 Optimization Flags

**Release Builds:**

| Flag | Purpose |
|------|---------|
| `/Gy` | Function-level linking (enables dead code elimination) |
| `/Gw` | Global data optimization (merges identical COMDAT sections) |
| `/Zc:inline` | Remove unreferenced inline functions |
| `EnableCOMDATFolding=true` | Merge identical functions in final binary |
| `OptimizeReferences=true` | Remove unreferenced functions/data |

**Debug Builds:**

| Flag | Purpose |
|------|---------|
| `GenerateDebugInformation=true` | Full PDB generation |
| Link Incremental: `false` | Clean link for reliability |

---

## 4.4 Include Paths

### 4.4.1 User-Mode Include Hierarchy

```
$(ProjectDir)include                    # Vendored third-party headers
$(ProjectDir)include\YARA              # YARA engine headers
$(ProjectDir)src                        # Source tree root
$(ProjectDir)src\Shared_modules         # Module headers (test builds)
$(ProjectDir)vendor                     # Vendor library headers
$(ProjectDir)vendor\gtest_framework\include  # GoogleTest (test builds)
```

### 4.4.2 Kernel Driver Include Hierarchy

The kernel driver has an extensive include path reflecting its 19-subsystem architecture:

```
.                                       # Solution root
PhantomSensor                           # Driver root
PhantomSensor\Utilities                 # Kernel utility functions
PhantomSensorELAM                       # ELAM driver
PhantomSensor\Network                   # WFP network filtering
PhantomSensor\Core                      # DriverEntry, initialization
PhantomSensor\Memory                    # VAD tracking, injection detection
PhantomSensor\Callbacks\Process         # Process/Thread callbacks
PhantomSensor\Callbacks\FileSystem      # Minifilter IRP callbacks
PhantomSensor\Callbacks\Registry        # Registry callbacks
PhantomSensor\Callbacks\Object          # Object callbacks
PhantomSensor\Sync                      # Thread pool, timers
PhantomSensor\Performance               # Performance monitoring
PhantomSensor\Power                     # Power state callbacks
PhantomSensor\Behavioral                # MITRE behavioral engine
PhantomSensor\Telemetry                 # Structured telemetry
Shared                                  # Kernel↔user shared definitions
PhantomSensor\SelfProtection            # Anti-tampering
PhantomSensor\Communication             # FilterConnectPort IPC
PhantomSensor\Cache                     # LRU scan cache
PhantomSensor\Exclusions                # Exclusion engine
PhantomSensor\Context                   # Instance context structures
PhantomSensor\ETW                       # Event Tracing provider
PhantomSensor\Transactions              # TxF abuse detection
PhantomSensor\Syscall                   # Direct syscall detection
PhantomSensor\Objects                   # Handle protection
PhantomSensor\ALPC                      # ALPC monitoring
PhantomSensor\Tracing                   # Behavioral tracing
```

---

## 4.5 Library Dependencies

### 4.5.1 User-Mode Link Libraries

**Core Windows SDK:**

| Library | Purpose |
|---------|---------|
| `advapi32.lib` | Registry, security, service control APIs |
| `ws2_32.lib` | Winsock 2 — TCP/UDP/DNS networking |
| `crypt32.lib` | Certificate/CMS/cryptographic APIs |
| `userenv.lib` | User profile/environment APIs |
| `psapi.lib` | Process status/memory information |
| `wbemuuid.lib` | WMI COM interface UUIDs |
| `ole32.lib` | COM runtime (`CoInitialize`, etc.) |
| `oleaut32.lib` | OLE Automation (BSTR, VARIANT) |
| `bcrypt.lib` | CNG — modern Windows cryptography |
| `secur32.lib` | Security Support Provider Interface |
| `version.lib` | File version information (`GetFileVersionInfo`) |
| `shlwapi.lib` | Shell path/string utilities |
| `fltlib.lib` | User-mode filter manager (kernel communication) |
| `iphlpapi.lib` | IP Helper — adapter enumeration, routing table |

**Vendored Libraries:**

| Library | Location | Purpose |
|---------|----------|---------|
| `gtest.lib` | `vendor/gtest_framework/` | Google Test unit testing |
| `gmock.lib` | `vendor/gtest_framework/` | Google Mock mocking framework |
| `libcrypto.lib` | `vendor/openssl_lib/` | OpenSSL cryptographic primitives |
| `libssl.lib` | `vendor/openssl_lib/` | OpenSSL TLS/SSL protocol |
| `Zydis.lib` | `vendor/zydis_lib/` | Zydis x86/x64 disassembler (legacy) |
| `libyara.lib` | `vendor/yara_lib/` (or build/) | YARA pattern matching engine |

### 4.5.2 Kernel Driver Link Libraries

| Library | Purpose |
|---------|---------|
| `fltMgr.lib` | Filter Manager — minifilter registration and IRP handling |
| `cng.lib` | Cryptography Next Generation — kernel-mode SHA-256, AES |
| `fwpkclnt.lib` | Windows Filtering Platform — network packet inspection |
| `ndis.lib` | Network Driver Interface — NIC interaction |
| `ntstrsafe.lib` | Kernel-safe string functions (`RtlStringCb*`) |
| `aux_klib.lib` | Auxiliary Kernel Library — image info, bug check callbacks |

**Critical Linker Flag:**

```
/INTEGRITYCHECK
```

> ⚠️ **Security Note:** `/INTEGRITYCHECK` is mandatory for kernel drivers that register `Ps*` process/thread callbacks and `ObRegisterCallbacks`. Without this flag, Windows refuses to load the driver's callback routines. This is a security requirement enforced by the kernel — it ensures the driver binary has a valid Authenticode signature before granting access to sensitive callback infrastructure.

### 4.5.3 Runtime DLL Dependencies

These DLLs must be present at runtime:

| DLL | Source | Distribution |
|-----|--------|-------------|
| `gtest.dll` | `vendor/gtest_framework/` | Test-only (not shipped) |
| `gmock.dll` | `vendor/gtest_framework/` | Test-only (not shipped) |
| `libcrypto-3-x64.dll` | `vendor/openssl_lib/` | Shipped with product |
| `libssl-3-x64.dll` | `vendor/openssl_lib/` | Shipped with product |

> ⚠️ **Important:** Both `gtest.dll` (in `bin/Release/` and `bin/Debug/`) are compiled as **debug builds** (they depend on `MSVCP140D.dll`, `VCRUNTIME140D.dll`). Therefore, all test binaries **must** be compiled with `/MDd` (debug multi-threaded DLL runtime). Using `/MD` (release runtime) causes linker errors.

---

## 4.6 Output Directory Structure

```
ShadowStrike/
├── bin/
│   ├── Debug/               # Debug executables
│   │   ├── ShadowStrike.exe
│   │   ├── gtest.dll
│   │   └── libcrypto-3-x64.dll
│   └── Release/             # Release executables
│       ├── ShadowStrike.exe
│       ├── gtest.dll
│       └── libcrypto-3-x64.dll
├── build/
│   ├── Debug/               # Debug intermediate files (.obj, .pch)
│   ├── Release/             # Release intermediate files
│   └── *.exe               # Test harness executables
└── x64/
    ├── Debug/               # Kernel driver debug
    │   └── PhantomSensor.sys
    └── Release/             # Kernel driver release
        └── PhantomSensor.sys
```

---

## 4.7 Precompiled Headers

The project uses precompiled headers (PCH) for compilation speed:

```
Source file:   src/pch.h (header)
               src/pch.cpp (compilation unit)
Output:        $(IntDir)pch.pch
```

**PCH Exclusions:** Third-party code compiles without PCH to avoid header conflicts:

- `pugixml.cpp` — XML parser
- `sqlite3.c` — SQLite engine
- SQLiteCpp wrappers (`Backup.cpp`, `Column.cpp`, `Database.cpp`, etc.)
- TLSH components (`tlsh.cpp`, `tlsh_impl.cpp`, `tlsh_util.cpp`)

**Assembly Files (MASM):** Excluded from certain build configurations:

```
src/Shared_modules/AntiEvasion/EnvironmentEvasionDetector_x64.asm
src/Shared_modules/AntiEvasion/PackerDetector_x64.asm
src/Shared_modules/AntiEvasion/SandboxEvasionDetector_x64.asm
src/Shared_modules/AntiEvasion/TimeBasedEvasionDetector_x64.asm
src/Shared_modules/AntiEvasion/VMEvasionDetector_x64.asm
src/Shared_modules/AntiEvasion/DebuggerEvasionDetector_x64.asm
```

These MASM files provide hand-optimized assembly routines for anti-evasion detection techniques that require direct hardware inspection (CPUID, RDTSC, debug register access).

---

## 4.8 Build Scripts and Response Files

### 4.8.1 Test Build Scripts

ShadowStrike uses standalone batch files for building individual test harnesses outside the main solution:

| Script | Output | Purpose |
|--------|--------|---------|
| `build/build_ai_tests.bat` | `build/ai_unit_tests.exe` | AI module unit tests |
| `build/build_core_network_integration.bat` | `build/core_network_integration_tests.exe` | Network integration |
| `build/build_comm_pipeline_integration.bat` | `build/communication_tests.exe` | IPC pipeline tests |
| `build/build_scan_pipeline_integration.bat` | `build/scan_pipeline_integration_tests.exe` | Scan engine integration |
| `build/build_ai_integration.bat` | `build/ai_integration_tests.exe` | AI pipeline integration |
| `build/build_anti_evasion_integration.bat` | `build/anti_evasion_tests.exe` | Anti-evasion detection |
| `build/build_exploit_protection_integration.bat` | `build/exploit_tests.exe` | Exploit prevention |
| `build/build_self_protection_integration.bat` | `build/self_protection_tests.exe` | Self-protection stack |

**Common Build Script Pattern:**

```batch
@echo off
:: 1. Initialize MSVC environment
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64

:: 2. Set compiler flags
set CFLAGS=/std:c++20 /EHsc /MDd /W4 /wd4100 /wd4189 /wd4244 /wd4267 /wd4996

:: 3. Set include paths
set INCLUDES=/I. /Isrc /Isrc\Shared_modules /Iinclude /Iinclude\YARA /Ivendor

:: 4. Compile source files
cl %CFLAGS% %INCLUDES% @sources.rsp /Fo:build\

:: 5. Link
link /OUT:build\test.exe build\*.obj ^
    /LIBPATH:vendor\gtest_framework gtest.lib gmock.lib ^
    /LIBPATH:vendor\openssl_lib libcrypto.lib libssl.lib ^
    advapi32.lib ws2_32.lib crypt32.lib ...
```

### 4.8.2 Response Files (.rsp)

For builds with hundreds of source files, MSVC response files keep command lines manageable:

**Compiler Response Files:**

```
build/rtp_pipeline/compile_current.rsp:
    /nologo /c /std:c++20 /EHsc /MDd /Gy /Gw /Zc:inline
    /W4 /wd4100 /wd4189 /wd4244 /wd4267 /wd4996 /wd4834
    /I. /Isrc /Isrc\Shared_modules /Iinclude /Iinclude\YARA
    /Ivendor /Ivendor\gtest_framework\include
```

**Linker Response Files:**

```
build/rtp_pipeline/link_current_min.rsp:
    /OUT:build\rtp_pipeline\RTPPipeline_current.exe
    /OPT:REF
    vendor\gtest_framework\gtest.lib
    vendor\gtest_framework\gmock.lib
    vendor\zydis_lib\Zydis.lib
    fltlib.lib iphlpapi.lib advapi32.lib ws2_32.lib
    crypt32.lib userenv.lib psapi.lib wbemuuid.lib
    ole32.lib oleaut32.lib bcrypt.lib secur32.lib
    version.lib shlwapi.lib
```

**Source List Response Files:**

```
build/exploits_sources.rsp       — All Exploits module sources
build/antievasion_sources.rsp    — All AntiEvasion module sources
build/database_sources.rsp       — All Database module sources
build/config_sources.rsp         — All Config module sources
build/comm_sources.rsp           — All Communication module sources
```

---

## 4.9 Vendor Directory

Pre-built third-party libraries and their organization:

```
vendor/
├── gtest_framework/
│   ├── gtest.lib              # Google Test static library
│   ├── gmock.lib              # Google Mock static library
│   ├── gtest.dll              # Google Test runtime (debug build)
│   ├── gmock.dll              # Google Mock runtime (debug build)
│   └── include/               # Framework headers
│
├── openssl_lib/
│   ├── libcrypto.lib          # OpenSSL 3.x crypto static lib
│   ├── libssl.lib             # OpenSSL 3.x TLS static lib
│   ├── libcrypto-3-x64.dll    # Crypto runtime
│   └── libssl-3-x64.dll       # TLS runtime
│
├── yara_lib/                   # YARA pattern matching
│   └── libyara.lib
│
├── zydis_core_lib/             # Zydis disassembler (core only)
│   └── ZydisCore.lib
│
└── zydis_lib/                  # Zydis disassembler (full)
    └── Zydis.lib
```

---

## 4.10 CI/CD Pipeline

### 4.10.1 Coverity Scan (GitHub Actions)

**Workflow:** `.github/workflows/coverity-scan.yml`

```yaml
triggers:
  - push to master/main
  - weekly schedule (Sunday 00:00 UTC)

steps:
  1. Checkout with full history
  2. Download Coverity 2024.12.1
  3. Verify WDK installation
     - Check ntifs.h exists in Windows Kits
     - Auto-detect latest WDK version
  4. Setup MSBuild
  5. Configure Coverity for MSVC
  6. Build PhantomSensor with Coverity wrapper:
     cov-build --dir cov-int msbuild \
       PhantomSensor\PhantomSensor.vcxproj \
       /t:Rebuild /p:Configuration=Release /p:Platform=x64
  7. Submit results to Coverity Scan
```

**Required Secrets:**
- `COVERITY_SCAN_TOKEN` — Authentication token
- `COVERITY_SCAN_EMAIL` — Notification email

**Current Metric:** 0.25 defects per 1,000 lines of code (industry average: 1.0)

---

## 4.11 Building from Source

### 4.11.1 Prerequisites

```
- Visual Studio 2022 (v143/v145 toolset)
- Windows SDK 10.0.22621.0+
- Windows Driver Kit (WDK) 10.0.22621.0+
- Python 3.10+ (PhantomCortex training only)
```

### 4.11.2 Full Solution Build

```powershell
# Open Developer Command Prompt for VS 2022, then:
MSBuild.exe ShadowStrike.sln /p:Configuration=Release /p:Platform=x64 /m

# Or kernel driver only:
MSBuild.exe PhantomSensor\PhantomSensor.vcxproj /p:Configuration=Release /p:Platform=x64
```

### 4.11.3 Individual Test Builds

```powershell
# Set up MSVC environment
& "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=amd64

# Build specific test harness
.\build\build_ai_tests.bat

# Run with correct DLL path
$env:PATH = "build;vendor\gtest_framework;$env:PATH"
.\build\ai_unit_tests.exe
```

> 📌 **Key Insight:** Test executables require `build/` and `vendor/gtest_framework/` on the PATH for DLL resolution. Without this, tests exit with error code `-1073741515` (STATUS_DLL_NOT_FOUND).

---

## 4.12 Summary

The ShadowStrike build system:

- **5 projects** spanning user mode (C++20/23) and kernel mode (WDK/C17)
- **6 platforms** including ARM64 kernel support
- **Vendored dependencies** for supply-chain security
- **Response files** for managing 400+ source file compilations
- **Coverity CI** for continuous static analysis
- **Strict kernel warnings** (W4 + TreatWarningAsError)

---

*Previous: [Chapter 3 — Design Patterns & Conventions](ch03-design-patterns.md)*
*Next: [Chapter 5 — Threading Model & Concurrency](ch05-threading-model.md)*

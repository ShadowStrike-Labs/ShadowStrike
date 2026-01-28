# ShadowStrike NGAV - Master Integration Plan

## Executive Summary

This document maps the entire ShadowStrike codebase, identifies all incomplete components, and provides a comprehensive integration plan to connect all systems together.

**Current State:** ~400k+ LOC with many stubbed/incomplete implementations
**Target State:** Fully integrated enterprise NGAV with kernel-user communication

---

## Part 1: Codebase Architecture Map

### 1.1 Core Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              KERNEL MODE (Ring 0)                                │
│  ┌─────────────────────────────────────────────────────────────────────────────┐│
│  │                    ShadowStrikeFlt Minifilter Driver                        ││
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐       ││
│  │  │  PreCreate   │ │ PostCreate   │ │  PreWrite    │ │ PreSetInfo   │       ││
│  │  │  Callback    │ │  Callback    │ │  Callback    │ │  Callback    │       ││
│  │  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘       ││
│  │         │                │                │                │                ││
│  │         └────────────────┴────────────────┴────────────────┘                ││
│  │                                   │                                          ││
│  │                    ┌──────────────▼──────────────┐                          ││
│  │                    │      CommPort.c             │                          ││
│  │                    │  FltSendMessage/Reply       │                          ││
│  │                    └──────────────┬──────────────┘                          ││
│  └───────────────────────────────────┼──────────────────────────────────────────┘│
│                                      │ \\ShadowStrikePort                        │
└──────────────────────────────────────┼──────────────────────────────────────────┘
                                       │
┌──────────────────────────────────────┼──────────────────────────────────────────┐
│                              USER MODE (Ring 3)                                  │
│                                      │                                           │
│  ┌───────────────────────────────────▼───────────────────────────────────────┐  │
│  │                     src/Communication/ [MISSING!]                          │  │
│  │   ┌─────────────────────────────────────────────────────────────────────┐ │  │
│  │   │  IPCManager.hpp/cpp - FilterConnectCommunicationPort                │ │  │
│  │   │  FilterConnection.hpp/cpp - Message handling                        │ │  │
│  │   │  MessageDispatcher.hpp/cpp - Route messages to handlers             │ │  │
│  │   └─────────────────────────────────┬───────────────────────────────────┘ │  │
│  └─────────────────────────────────────┼─────────────────────────────────────┘  │
│                                        │                                         │
│  ┌─────────────────────────────────────▼─────────────────────────────────────┐  │
│  │                        src/RealTime/                                       │  │
│  │  ┌────────────────────┐  ┌────────────────────┐  ┌────────────────────┐   │  │
│  │  │ RealTimeProtection │──│ FileSystemFilter   │──│ProcessCreationMon  │   │  │
│  │  │   (Orchestrator)   │  │ (File events)      │  │ (Process events)   │   │  │
│  │  └────────────────────┘  └────────────────────┘  └────────────────────┘   │  │
│  │  ┌────────────────────┐  ┌────────────────────┐  ┌────────────────────┐   │  │
│  │  │ NetworkTrafficFlt  │  │ BehaviorBlocker    │  │ ExploitPrevention  │   │  │
│  │  │ (WFP integration)  │  │ (Behavior rules)   │  │ (Memory mitigations)│   │  │
│  │  └────────────────────┘  └────────────────────┘  └────────────────────┘   │  │
│  │  ┌────────────────────┐  ┌────────────────────┐  ┌────────────────────┐   │  │
│  │  │ MemoryProtection   │  │ FileIntegrityMon   │  │ ZeroHourProtection │   │  │
│  │  │ (Memory scanning)  │  │ (FIM baselines)    │  │ (Cloud verdicts)   │   │  │
│  │  └────────────────────┘  └────────────────────┘  └────────────────────┘   │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
│                                        │                                         │
│  ┌─────────────────────────────────────▼─────────────────────────────────────┐  │
│  │                        src/Core/Engine/                                    │  │
│  │  ┌────────────────────┐  ┌────────────────────┐  ┌────────────────────┐   │  │
│  │  │    ScanEngine      │  │  ThreatDetector    │  │ QuarantineManager  │   │  │
│  │  │ (Multi-engine scan)│  │ (Threat analysis)  │  │ (File quarantine)  │   │  │
│  │  └────────────────────┘  └────────────────────┘  └────────────────────┘   │  │
│  │  ┌────────────────────┐  ┌────────────────────┐  ┌────────────────────┐   │  │
│  │  │  EmulationEngine   │  │  PackerUnpacker    │  │  SignatureEngine   │   │  │
│  │  │ (Code emulation)   │  │ (Unpacking)        │  │ (Sig matching)     │   │  │
│  │  └────────────────────┘  └────────────────────┘  └────────────────────┘   │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
│                                        │                                         │
│  ┌─────────────────────────────────────▼─────────────────────────────────────┐  │
│  │                     Data Stores & Infrastructure                           │  │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐      │  │
│  │  │  HashStore   │ │ PatternStore │ │SignatureStore│ │  ThreatIntel │      │  │
│  │  │ (Hash DB)    │ │ (YARA rules) │ │ (Sigs DB)    │ │ (IOC feeds)  │      │  │
│  │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘      │  │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────────────┐       │  │
│  │  │  Whitelist   │ │    Utils/    │ │          Tests/              │       │  │
│  │  │ (Allow list) │ │ (Utilities)  │ │     (Unit tests)             │       │  │
│  │  └──────────────┘ └──────────────┘ └──────────────────────────────┘       │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Part 2: Critical Missing Components

### 2.1 CRITICAL: src/Communication/ Folder - DOES NOT EXIST

This is the **most critical gap**. The kernel driver sends messages but there's no user-mode code to receive them!

**Must Create:**
| File | Purpose | Priority |
|------|---------|----------|
| `Communication/IPCManager.hpp` | Main IPC interface declaration | P0 |
| `Communication/IPCManager.cpp` | FilterConnectCommunicationPort, message loop | P0 |
| `Communication/FilterConnection.hpp` | Connection state management | P0 |
| `Communication/FilterConnection.cpp` | Handle management, reconnection | P0 |
| `Communication/MessageDispatcher.hpp` | Route messages to handlers | P0 |
| `Communication/MessageDispatcher.cpp` | Dispatch file/process/registry events | P0 |
| `Communication/Communication.hpp` | Shared structures (already referenced!) | P0 |

### 2.2 Kernel Driver - Incomplete Folders

| Folder | Status | Missing |
|--------|--------|---------|
| `Callbacks/FileSystem/` | Empty | PreCreate.c, PostCreate.c, PreWrite.c, etc. |
| `Callbacks/Process/` | Empty | ProcessNotify.c, ThreadNotify.c, ImageNotify.c |
| `Callbacks/Registry/` | Empty | RegistryCallback.c, RegistryFilter.c |
| `Callbacks/Object/` | Empty | ObjectCallback.c, ProcessProtection.c |
| `SelfProtection/` | Empty | SelfProtect.c, HandleProtection.c, FileProtection.c |
| `Cache/` | Empty | ScanCache.c, ProcessCache.c |
| `Exclusions/` | Empty | ExclusionManager.c, PathExclusion.c |
| `Utilities/` | Empty | StringUtils.c, MemoryUtils.c, FileUtils.c |

---

## Part 3: Stub/TODO Inventory

### 3.1 High-Priority Stubs (Blocking Integration)

| File | Line | Issue | Impact |
|------|------|-------|--------|
| `RealTime/FileSystemFilter.cpp` | PerformScan() | Returns Allow by default | **No actual scanning!** |
| `RealTime/FileSystemFilter.cpp` | GetDriverStatus() | Hardcoded version | No real driver query |
| `RealTime/ProcessCreationMonitor.cpp` | PerformScan() | "Simulates a scan" | **No actual scanning!** |
| `RealTime/ProcessCreationMonitor.cpp` | SendVerdictToKernel() | TODO | Can't block processes |
| `RealTime/ProcessCreationMonitor.cpp` | ConnectToKernelDriver() | Placeholder | No kernel connection |
| `RealTime/NetworkTrafficFilter.cpp` | WFPMessageLoop() | "Simulated" | No real WFP events |
| `RealTime/FileIntegrityMonitor.cpp` | CalculateHash() | Returns placeholder | **No real hashing!** |
| `RealTime/ZeroHourProtection.cpp` | GetCloudVerdict() | "Stub for cloud" | No cloud integration |

### 3.2 Medium-Priority Stubs

| File | Issue |
|------|-------|
| `Core/Engine/QuarantineManager.cpp` | TODO: Implement DoD 5220.22-M secure wipe |
| `Core/Engine/EmulationEngine.cpp` | Unicorn Engine not integrated |
| `Core/Engine/PackerUnpacker.cpp` | Static unpacking not implemented |
| `Core/Network/DDosProtection.cpp` | Mitigation action not implemented |
| `Email/EMLParser.cpp` | Stub - needs email parsing library |
| `Email/MimeParser.cpp` | Stub - needs MIME parsing library |
| `Email/OutlookPSTParser.cpp` | Stub - needs PST parsing library |
| `Email/MailboxScanner.cpp` | Stub - coordinate parsers |

### 3.3 Low-Priority Stubs (Features)

| File | Issue |
|------|-------|
| `Banking/CertificatePinning.cpp` | ParseCertificate needs raw bytes |
| `WebProtection/TrackerBlocker.cpp` | URL blocklist loading not implemented |
| `WebProtection/FirefoxAddonScanner.cpp` | PKCS#7 signature verification |
| `Privacy/CookieManager.cpp` | Cookie deletion in read-only mode |
| `Scripts/PythonScriptScanner.cpp` | Decompilation needs external tools |
| `Core/FileSystem/FileWatcher.cpp` | Batch processing, rate limiting |
| `Forensics/ArtifactExtractor.cpp` | File recovery not implemented |
| `Forensics/MemoryDumper.cpp` | Dump conversion not implemented |

### 3.4 Stub Modules (Entire Files Are Stubs)

| Module | Files | Status |
|--------|-------|--------|
| `Core/ThreatHunting/` | AnomalyDetector, BehavioralAnalysis, AttributionEngine, IOCScanner | All stub implementations |
| `Core/System/` | FileIntegrityMonitor, BootRecordProtector, AntiTampering, SelfDefense | All stub implementations |
| `CryptoMiners/` | MinerDetector | Stub implementation |

---

## Part 4: Integration Wire Map

### 4.1 Kernel → User Communication Flow

```
KERNEL DRIVER                          USER MODE
─────────────────────────────────────────────────────────────────────

[File Open] ──► CommPort.c
              FltSendMessage() ────────► IPCManager.cpp
                                         FilterGetMessage()
                                              │
                                              ▼
                                         MessageDispatcher.cpp
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    ▼                         ▼                         ▼
              FileSystemFilter     ProcessCreationMonitor      Other handlers
                    │                         │
                    ▼                         ▼
              RealTimeProtection.OnKernelFileScan()
                    │
                    ▼
              ScanEngine.ScanFile()
                    │
                    ▼
              Verdict (Allow/Block/Quarantine)
                    │
                    ▼
              IPCManager.SendReply() ──────► CommPort.c
                                             FltReplyMessage()
                                                  │
                                                  ▼
                                        [Allow or Block I/O]
```

### 4.2 Component Integration Matrix

| Source Component | Target Component | Integration Method | Status |
|-----------------|------------------|-------------------|--------|
| **Kernel Driver** | IPCManager | FilterGetMessage/Reply | ❌ IPCManager missing |
| IPCManager | RealTimeProtection | Callback registration | ❌ Not connected |
| RealTimeProtection | FileSystemFilter | Direct call | ⚠️ Stubbed |
| RealTimeProtection | ProcessCreationMonitor | Direct call | ⚠️ Stubbed |
| RealTimeProtection | ScanEngine | OnKernelFileScan() | ⚠️ Partially done |
| FileSystemFilter | ScanEngine | PerformScan() | ❌ Returns Allow |
| FileSystemFilter | HashStore | Hash lookup | ❌ Not connected |
| FileSystemFilter | WhitelistStore | Exclusion check | ❌ Not connected |
| ProcessCreationMonitor | ScanEngine | PerformScan() | ❌ Simulated |
| ProcessCreationMonitor | HashStore | Hash check | ❌ Placeholder |
| BehaviorBlocker | RealTimeProtection | Behavior events | ⚠️ Needs integration |
| NetworkTrafficFilter | Kernel WFP | WFPMessageLoop() | ❌ Simulated |
| ZeroHourProtection | Cloud Service | GetCloudVerdict() | ❌ Stub |
| FileIntegrityMonitor | CryptoUtils | CalculateHash() | ❌ Placeholder |
| AccessControlManager | Kernel Driver | IOCTL | ⚠️ Simulated |

---

## Part 5: Implementation Phases

### Phase 1: Critical Path - Kernel-User Communication (Week 1-2)

**Goal:** Establish working communication between kernel and user mode

#### 1.1 Create src/Communication/ Module

```cpp
// Files to create:
src/Communication/
├── Communication.hpp        // Shared structures (FileScanRequest, etc.)
├── IPCManager.hpp          // Main interface
├── IPCManager.cpp          // Implementation
├── FilterConnection.hpp    // Connection management
├── FilterConnection.cpp    // Handle lifecycle
├── MessageDispatcher.hpp   // Message routing
└── MessageDispatcher.cpp   // Dispatch to handlers
```

#### 1.2 Complete Kernel Driver Callbacks

```
Drivers/ShadowStrikeFlt/Callbacks/
├── FileSystem/
│   ├── PreCreate.c         // Scan trigger
│   ├── PostCreate.c        // Get file info, send request
│   ├── PreWrite.c          // Track modifications
│   └── FileContext.c       // Per-file state
├── Process/
│   ├── ProcessNotify.c     // PsSetCreateProcessNotifyRoutineEx2
│   ├── ImageNotify.c       // PsSetLoadImageNotifyRoutine
│   └── ProcessContext.c    // Per-process tracking
└── Registry/
    └── RegistryCallback.c  // CmRegisterCallbackEx
```

#### 1.3 Integration Points

| Kernel File | User File | Message Type |
|-------------|-----------|--------------|
| PostCreate.c | FileSystemFilter.cpp | FileScanOnOpen |
| PreAcquireSection.c | FileSystemFilter.cpp | FileScanOnExecute |
| ProcessNotify.c | ProcessCreationMonitor.cpp | ProcessScan |
| RegistryCallback.c | (New) RegistryMonitor.cpp | RegistryNotify |

---

### Phase 2: Connect Real-Time Components (Week 2-3)

#### 2.1 Fix FileSystemFilter.cpp

```cpp
// Current (broken):
ScanVerdict Impl::PerformScan(...) {
    // No actual scanning
    return ScanVerdict::Allow;
}

// Fixed:
ScanVerdict Impl::PerformScan(const FileScanRequest& request) {
    // 1. Check whitelist
    if (Whitelist::WhitelistStore::Instance().IsWhitelisted(request.filePath)) {
        return ScanVerdict::Allow;
    }

    // 2. Check hash store for known malware
    auto hash = HashStore::HashStore::Instance().CalculateSHA256(request.filePath);
    if (HashStore::HashStore::Instance().IsKnownMalware(hash)) {
        return ScanVerdict::Block;
    }

    // 3. Invoke scan engine
    auto result = Core::Engine::ScanEngine::Instance().ScanFile(request.filePath);
    return MapScanResult(result);
}
```

#### 2.2 Fix ProcessCreationMonitor.cpp

```cpp
// Current (broken):
ScanResult Impl::PerformScan(const ProcessCreateEvent& event) {
    // Simulate a scan
    return ScanResult{true, 0.1f, {}};
}

// Fixed:
ScanResult Impl::PerformScan(const ProcessCreateEvent& event) {
    // 1. Check process path against whitelist
    if (Whitelist::WhitelistStore::Instance().IsWhitelisted(event.imagePath)) {
        return ScanResult{true, 0.0f, {}};
    }

    // 2. Scan the executable
    auto result = Core::Engine::ScanEngine::Instance().ScanFile(event.imagePath);

    // 3. Analyze command line
    auto cmdAnalysis = AnalyzeCommandLine(event.commandLine);

    return MapToScanResult(result, cmdAnalysis);
}
```

#### 2.3 Connect BehaviorBlocker

```cpp
// In RealTimeProtection.cpp, add behavior event routing:
void RealTimeProtectionImpl::OnFileModification(const FileEvent& event) {
    ProcessBehavior behavior;
    behavior.processId = event.processId;
    behavior.type = BehaviorType::FileModification;
    behavior.target = event.filePath;
    behavior.timestamp = event.timestamp;

    BehaviorBlocker::Instance().AnalyzeBehavior(behavior);
}
```

---

### Phase 3: Complete Kernel Driver (Week 3-4)

#### 3.1 Self-Protection Module

```c
// Drivers/ShadowStrikeFlt/SelfProtection/HandleProtection.c
OB_PREOP_CALLBACK_STATUS
ShadowStrikeObPreOperationCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
) {
    // 1. Get target process ID
    HANDLE targetPid = PsGetProcessId(OperationInformation->Object);

    // 2. Check if target is protected
    if (IsProtectedProcess(targetPid)) {
        // 3. Strip dangerous access rights
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &=
                ~(PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_OPERATION);
        }
    }

    return OB_PREOP_SUCCESS;
}
```

#### 3.2 Scan Cache

```c
// Drivers/ShadowStrikeFlt/Cache/ScanCache.c
typedef struct _CACHE_ENTRY {
    RTL_BALANCED_NODE TreeNode;
    UCHAR FileHash[32];
    SHADOWSTRIKE_VERDICT Verdict;
    LARGE_INTEGER ExpirationTime;
} CACHE_ENTRY;

NTSTATUS
ShadowStrikeCacheLookup(
    _In_ PUCHAR FileHash,
    _Out_ PSHADOWSTRIKE_VERDICT Verdict
) {
    // AVL tree lookup by hash
}
```

#### 3.3 Exclusion Manager

```c
// Drivers/ShadowStrikeFlt/Exclusions/ExclusionManager.c
BOOLEAN
ShadowStrikeIsPathExcluded(
    _In_ PCUNICODE_STRING FilePath
) {
    // Prefix trie matching for path exclusions
    // Extension matching
    // Process exclusions
}
```

---

### Phase 4: Connect Data Stores (Week 4-5)

#### 4.1 HashStore Integration

| Component | Integration Point |
|-----------|------------------|
| FileSystemFilter | PerformScan() → HashStore.IsKnownMalware() |
| ProcessCreationMonitor | CheckHashStore() → HashStore.Lookup() |
| MetamorphicDetector | Query TLSH hashes |
| ZeroHourProtection | CheckMicroSignatures() |

#### 4.2 PatternStore Integration

| Component | Integration Point |
|-----------|------------------|
| ScanEngine | YARA rule scanning |
| BehaviorBlocker | Behavior pattern matching |
| ZeroHourProtection | Micro-signature checks |

#### 4.3 ThreatIntel Integration

| Component | Integration Point |
|-----------|------------------|
| NetworkTrafficFilter | IP/Domain reputation |
| ZeroHourProtection | IOC lookups |
| AttributionEngine | Threat actor attribution |

---

### Phase 5: Fix Stub Implementations (Week 5-6)

#### 5.1 FileIntegrityMonitor - Real Hashing

```cpp
// Current:
std::string CalculateHash(...) {
    return "SHA256_HASH_PLACEHOLDER_";  // Broken!
}

// Fixed:
std::string CalculateHash(const std::wstring& path, HashAlgorithm algo) {
    return Utils::CryptoUtils::HashFile(path, algo);
}
```

#### 5.2 Email Parsers - Library Integration

```cpp
// Use libpff for PST parsing
// Use mimetic or vmime for MIME parsing
#include <libpff.h>

bool OutlookPSTParser::Parse(const fs::path& pstPath) {
    libpff_file_t* file = nullptr;
    libpff_file_initialize(&file);
    libpff_file_open(file, pstPath.string().c_str(), LIBPFF_OPEN_READ);
    // ... enumerate folders and messages
}
```

#### 5.3 ThreatHunting Modules

```cpp
// AnomalyDetector - Integrate ML model
bool AnomalyDetector::Analyze(const ProcessBehavior& behavior) {
    // Load ONNX model
    // Extract features
    // Run inference
    return model.Predict(features) > threshold;
}
```

---

### Phase 6: Testing & Hardening (Week 6-7)

#### 6.1 Integration Tests

| Test | Components |
|------|------------|
| File scan flow | Kernel → IPCManager → FileSystemFilter → ScanEngine |
| Process block | Kernel → ProcessMonitor → BehaviorBlocker |
| Network block | WFP → NetworkFilter → ThreatIntel |
| Self-protection | ObCallback → Protected process list |

#### 6.2 Driver Verifier Testing

```cmd
verifier /standard /driver ShadowStrikeFlt.sys
```

#### 6.3 Stress Testing

- High I/O volume (file copy storms)
- Rapid process creation
- Network saturation
- Memory pressure

---

## Part 6: File Creation Checklist

### 6.1 New Files to Create

| Priority | Path | Description |
|----------|------|-------------|
| P0 | `src/Communication/Communication.hpp` | Shared structures |
| P0 | `src/Communication/IPCManager.hpp` | IPC interface |
| P0 | `src/Communication/IPCManager.cpp` | IPC implementation |
| P0 | `src/Communication/FilterConnection.hpp` | Connection mgmt |
| P0 | `src/Communication/FilterConnection.cpp` | Handle lifecycle |
| P0 | `src/Communication/MessageDispatcher.hpp` | Message routing |
| P0 | `src/Communication/MessageDispatcher.cpp` | Dispatch logic |
| P1 | `Drivers/.../Callbacks/FileSystem/PreCreate.c` | Pre-create callback |
| P1 | `Drivers/.../Callbacks/FileSystem/PostCreate.c` | Post-create callback |
| P1 | `Drivers/.../Callbacks/Process/ProcessNotify.c` | Process callback |
| P1 | `Drivers/.../Callbacks/Registry/RegistryCallback.c` | Registry callback |
| P1 | `Drivers/.../SelfProtection/HandleProtection.c` | Handle protection |
| P1 | `Drivers/.../Cache/ScanCache.c` | Kernel cache |
| P2 | `Drivers/.../Exclusions/ExclusionManager.c` | Exclusion logic |
| P2 | `Drivers/.../Utilities/StringUtils.c` | String helpers |

### 6.2 Files to Fix

| Priority | Path | Fix Required |
|----------|------|--------------|
| P0 | `src/RealTime/FileSystemFilter.cpp` | Connect to ScanEngine |
| P0 | `src/RealTime/ProcessCreationMonitor.cpp` | Connect to ScanEngine |
| P0 | `src/RealTime/RealTimeProtection.cpp` | Wire up IPCManager |
| P1 | `src/RealTime/NetworkTrafficFilter.cpp` | Real WFP integration |
| P1 | `src/RealTime/FileIntegrityMonitor.cpp` | Real hash calculation |
| P2 | `src/Core/ThreatHunting/*.cpp` | Replace stubs |
| P2 | `src/Email/*.cpp` | Add parsing libraries |
| P3 | `src/Core/Engine/QuarantineManager.cpp` | Secure wipe |

---

## Part 7: Dependency Graph

```
                    ┌────────────────┐
                    │  Kernel Driver │
                    └───────┬────────┘
                            │
                    ┌───────▼────────┐
                    │  IPCManager    │ ◄── MUST CREATE
                    └───────┬────────┘
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
  ┌───────▼───────┐ ┌───────▼───────┐ ┌───────▼───────┐
  │FileSystemFlt  │ │ProcessMonitor │ │NetworkFilter  │
  └───────┬───────┘ └───────┬───────┘ └───────┬───────┘
          │                 │                 │
          └─────────────────┼─────────────────┘
                            │
                    ┌───────▼────────┐
                    │RealTimeProtect │
                    └───────┬────────┘
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
  ┌───────▼───────┐ ┌───────▼───────┐ ┌───────▼───────┐
  │  ScanEngine   │ │BehaviorBlocker│ │ZeroHourProtect│
  └───────┬───────┘ └───────┬───────┘ └───────┬───────┘
          │                 │                 │
          └─────────────────┼─────────────────┘
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
  ┌───────▼───────┐ ┌───────▼───────┐ ┌───────▼───────┐
  │   HashStore   │ │  PatternStore │ │  ThreatIntel  │
  └───────────────┘ └───────────────┘ └───────────────┘
```

---

## Part 8: Immediate Action Items

### Today's Priority Tasks

1. **Create `src/Communication/` folder and files** - Without this, nothing works
2. **Complete kernel driver callback files** - The driver is only 60% done
3. **Fix `FileSystemFilter.PerformScan()`** - Currently returns Allow for everything
4. **Fix `ProcessCreationMonitor.PerformScan()`** - Currently simulated
5. **Connect `RealTimeProtection` to `IPCManager`** - Main integration point

### This Week

1. Full kernel-user communication working
2. File scans actually scanning files
3. Process scans actually scanning processes
4. Basic self-protection working

### This Month

1. All RealTime components connected
2. All data stores integrated
3. Network filtering with WFP
4. All stubs replaced with real implementations
5. Integration tests passing

---

## Appendix A: Message Protocol Summary

### Kernel → User Messages

| Type | ID | Structure | Reply Required |
|------|-----|-----------|----------------|
| FileScanOnOpen | 1 | SHADOWSTRIKE_FILE_SCAN_REQUEST | Yes |
| FileScanOnExecute | 2 | SHADOWSTRIKE_FILE_SCAN_REQUEST | Yes |
| FileScanOnWrite | 3 | SHADOWSTRIKE_FILE_SCAN_REQUEST | Yes |
| ProcessScan | 5 | SHADOWSTRIKE_PROCESS_NOTIFICATION | Yes |
| NotifyFileCreate | 100 | SHADOWSTRIKE_FILE_NOTIFICATION | No |
| NotifyProcessCreate | 110 | SHADOWSTRIKE_PROCESS_NOTIFICATION | No |

### User → Kernel Messages

| Type | ID | Structure |
|------|-----|-----------|
| ScanVerdict | 300 | SHADOWSTRIKE_SCAN_VERDICT_REPLY |
| UpdatePolicy | 201 | SHADOWSTRIKE_POLICY_UPDATE |
| RegisterProtected | 207 | SHADOWSTRIKE_PROTECTED_PROCESS |

---

*Document Version: 1.0*
*Created: 2026-01-27*
*Author: ShadowStrike Development Team*

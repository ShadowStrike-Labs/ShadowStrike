# Chapter 9: Module Relationships & Dependency Graph

> *"In a million-line codebase, a circular dependency is a ticking time bomb. In a security product, it's a bomb that goes off during the incident you were supposed to prevent."*

---

## 9.1 Architectural Integrity

ShadowStrike's user-mode codebase (`src/Shared_modules/`) contains **24 module groups** with over **100 individual components** and **137 dependency edges**. Despite this complexity, the architecture maintains:

- **Zero circular dependencies** — verified through include-graph analysis
- **Clean 3-tier layering** — foundation → infrastructure → detection
- **Isolated subsystems** — self-protection has zero external dependencies
- **Clear hub points** — only 2 critical aggregation hubs

This chapter maps the complete dependency graph, identifies critical paths, and explains the design decisions that keep the architecture clean.

---

## 9.2 The Three Tiers

```
┌─────────────────────────────────────────────────────────────────┐
│  TIER 3: Detection & Protection                                  │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌──────────┐       │
│  │Core/Engine│  │ RealTime │  │AntiEvasion│  │ Scripts  │       │
│  │(41 deps)  │  │(28 deps) │  │(5 deps)   │  │(3 deps)  │       │
│  └─────┬─────┘  └─────┬────┘  └─────┬─────┘  └─────┬────┘       │
│        │              │              │              │             │
├────────┼──────────────┼──────────────┼──────────────┼────────────┤
│  TIER 2: Infrastructure                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │Signature │  │ ThreatInt│  │ Whitelist │  │ Database │        │
│  │Store     │  │ (18 deps)│  │ (5 deps)  │  │ (7 deps) │        │
│  │(13 deps) │  └──────────┘  └──────────┘  └──────────┘        │
│  └──────────┘                                                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                      │
│  │ HashStore│  │PatternSt │  │    AI    │                       │
│  │          │  │          │  │(minimal) │                       │
│  └──────────┘  └──────────┘  └──────────┘                      │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│  TIER 1: Foundation (0 external dependencies)                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │  Utils   │  │  Format  │  │  Comms   │  │ SelfProt │        │
│  │(13 utils)│  │ (defs)   │  │(10 mods) │  │(10 mods) │        │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │
└──────────────────────────────────────────────────────────────────┘
```

### Tier 1: Foundation (Zero External Dependencies)

These modules depend on nothing except the C++ standard library and the Windows SDK:

| Module Group | Components | Role |
|-------------|-----------|------|
| **Utils** | 13 utilities (Logger, ThreadPool, StringUtils, FileUtils, HashUtils, CryptoUtils, NetworkUtils, JSONUtils, XMLUtils, CompressionUtils, MemoryUtils, RegistryUtils, SystemUtils) | Common infrastructure used by all tiers |
| **Format Definitions** | SignatureFormat, WhiteListFormat, ThreatIntelFormat | Data type definitions (enums, structs) — no logic |
| **Communication** | 10 modules (IPCManager, ServiceCommunication, MessageDispatcher, FilterConnection, AlertSystem, TelemetryCollector) | IPC and service infrastructure |
| **SelfProtection** | 10 modules (CryptoManager, MemoryProtection, ProcessProtection, TamperProtection, AntiDebug, SelfDefense, CertificateValidator, DigitalSignatureValidator, FileIntegrityMonitor [self-protection variant]) | **Completely isolated** — no imports from any other ShadowStrike module |

> 📌 **Key Insight:** SelfProtection's complete isolation is a deliberate security decision. If a vulnerability in the detection engine is exploited, the self-protection stack continues operating independently. An attacker who compromises the scan pipeline still faces an intact process protection, tamper detection, and crypto layer.

### Tier 2: Infrastructure (Depends on Tier 1 Only)

| Module Group | Components | Depends On |
|-------------|-----------|------------|
| **SignatureStore** | SignatureStore, SignatureBuilder, SignatureIndex, YaraRuleStore, SignatureFormat | HashStore, PatternStore, Utils |
| **HashStore** | HashStore, HashBucket, BloomFilter, HashUtils | Utils, SignatureFormat (types only) |
| **PatternStore** | PatternStore, PatternIndex, AhoCorasick, BoyerMoore, SIMD matcher | Utils, SignatureFormat (types only) |
| **ThreatIntel** | ThreatIntelStore, ThreatIntelLookup, ThreatIntelIndex, ThreatIntelDatabase, ThreatIntelFeedManager, ThreatIntelIOCManager, ReputationCache, Exporters/Importers | Utils, Database |
| **Whitelist** | WhiteListStore, WhiteListBloomFilter, WhiteListHashIndex, WhiteListPatternIndex, WhiteListStringPool | Utils, WhiteListFormat |
| **Database** | DatabaseManager, ConfigurationDB, LogDB, QuarantineDB | Utils (SQLite vendored separately) |
| **AI** | ModelInference, ModelCache, FeatureExtractor, PhantomCortexConfig | Utils (CortexTypes internal) |

### Tier 3: Detection & Protection (Depends on Tiers 1 and 2)

| Module Group | Components | Depends On |
|-------------|-----------|------------|
| **Core/Engine** | ScanEngine, BehaviorAnalyzer, BehaviorBlocker, ThreatDetector, ZeroHourProtection, ExecutableAnalyzer, FileHasher, FileTypeAnalyzer, URLAnalyzer, WebProtection, PEParser | **41 deps** across SignatureStore, HashStore, Whitelist, ThreatIntel, Database, AI, Utils |
| **RealTime** | RealTimeProtection, ProcessCreationMonitor, FileSystemFilter, NetworkTrafficFilter, FileIntegrityMonitor, ExploitPrevention, MemoryProtection, AccessControlManager, ZeroHourProtection, ProcessMonitor | **28 deps** across ThreatIntel, Whitelist, HashStore, Utils |
| **AntiEvasion** | 9 detectors (Debugger, VM, Sandbox, Packer, Process, Environment, Network, Time, DKOM) | **5 deps** — mostly independent, only SandboxEvasion and TimeBasedEvasion use PatternStore |
| **Scripts** | ScriptAnalyzer, AMSIScanner, VBScriptScanner, PowerShellScanner, JavaScriptScanner, PythonScanner | **3 deps** — Utils, PEParser |
| **Exploits** | ROPProtection, HeapSprayDetector, StackPivotDetector, JITSprayDetector, BufferOverflowProtection, KernelExploitDetector | Utils, MemoryProtection |

---

## 9.3 Dependency Hubs

Two modules serve as critical aggregation points:

### 9.3.1 ScanEngine — The Orchestration Hub

```
                    ┌──────────────────┐
                    │    ScanEngine    │
                    │  (Orchestrator)  │
                    └────────┬─────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
    ┌────▼────┐       ┌─────▼─────┐      ┌──────▼──────┐
    │Signature│       │ThreatIntel│      │  Whitelist  │
    │  Store  │       │  Lookup   │      │   Store     │
    └────┬────┘       └─────┬─────┘      └─────────────┘
         │                  │
    ┌────▼────┐       ┌─────▼─────┐
    │HashStore│       │  Database │
    │PatternSt│       │           │
    └─────────┘       └───────────┘
```

The ScanEngine pulls from **6 major subsystems** to orchestrate the detection pipeline. It's the single most connected module in the codebase — a change to ScanEngine's interface affects the entire detection chain.

**Risk Mitigation:** The ScanEngine uses PIMPL to hide all these dependencies behind a stable ABI. Consumer code only sees `ScanEngine.hpp` — never the 6 subsystems it orchestrates internally.

### 9.3.2 SignatureStore — The Data Hub

```
                    ┌──────────────────┐
                    │ SignatureStore   │
                    │  (Aggregator)   │
                    └────────┬─────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
    ┌────▼────┐       ┌─────▼─────┐      ┌──────▼──────┐
    │HashStore│       │PatternSt  │      │ YaraRuleSt  │
    │  + Bloom│       │ +AhoCoras │      │  + YARA     │
    │  + Bkts │       │ +BoyerMre │      │    Engine   │
    └─────────┘       └───────────┘      └─────────────┘
```

SignatureStore aggregates three detection backends into a unified query interface. Each backend can be loaded, updated, or disabled independently.

---

## 9.4 Module Dependency Matrix

The complete dependency matrix for major module groups (✓ = depends on):

```
                 Utils  SigFmt  SigSt  HashSt PatSt  TI    WL   DB   AI  SelfP
─────────────────────────────────────────────────────────────────────────────────
Utils              —                                                          
SignatureFormat    ✓      —                                                    
HashStore          ✓      ✓       —                                            
PatternStore       ✓      ✓              —                                     
SignatureStore     ✓      ✓       ✓      ✓     ✓     —                         
ThreatIntel        ✓                                   —                       
Whitelist          ✓              ✓                          —                 
Database           ✓                                               —           
AI                 ✓                                                    —      
SelfProtection                                                              —  
Communication      ✓                                                          
Core/Engine        ✓      ✓       ✓      ✓     ✓     ✓     ✓    ✓   ✓         
RealTime           ✓              ✓      ✓           ✓     ✓                  
AntiEvasion        ✓                     ✓     ✓                              
Scripts            ✓                                                          
Exploits           ✓                                                          
─────────────────────────────────────────────────────────────────────────────────
```

> 🔬 **Deep Dive:** Notice that `SelfProtection` has **zero incoming or outgoing dependencies** with any other ShadowStrike module. This is the most important row in the matrix. It means: (1) a bug in any detection module cannot compromise self-protection, (2) self-protection can be tested in complete isolation, (3) self-protection can be loaded before any other module initializes.

---

## 9.5 Critical Paths

### 9.5.1 Real-Time Scan Path (Latency-Critical)

```
Kernel notification (IRP_MJ_CREATE)
    → FilterConnection::Receive()
    → RealTimeProtection::OnFileAccess()
        → WhitelistStore::Check()        [Tier 2, <2 μs]
        → HashStore::Lookup()            [Tier 2, <500 μs]
        → SignatureStore::ScanBuffer()   [Tier 2, <10 ms]
        → ScanEngine::QuickScan()        [Tier 3, <50 ms]
    → FilterConnection::Reply(verdict)
    → Kernel allows/blocks access
```

Every module on this path must be initialized before the first file access. Initialization order follows the tier hierarchy: Utils → Database → Stores → Engine → RealTime.

### 9.5.2 Initialization Order

```
Phase 1: Foundation
    Logger::Initialize()
    CryptoManager::Initialize()
    ThreadPool::Initialize()

Phase 2: Self-Protection
    SelfDefense::Initialize()
    ProcessProtection::Initialize()
    MemoryProtection::Initialize()
    TamperProtection::Initialize()

Phase 3: Data Stores
    DatabaseManager::Initialize()
    HashStore::Load()
    PatternStore::Load()
    SignatureStore::Initialize()
    WhitelistStore::Load()
    ThreatIntelStore::Initialize()

Phase 4: Detection Engine
    ScanEngine::Initialize()
    BehaviorAnalyzer::Initialize()
    ModelInference::Initialize()

Phase 5: Real-Time Protection
    FileSystemFilter::Initialize()
    ProcessCreationMonitor::Initialize()
    NetworkTrafficFilter::Initialize()
    RealTimeProtection::Enable()

Phase 6: Kernel Connection
    FilterConnection::Connect()
    → Begin receiving kernel notifications
```

> ⚠️ **Security Note:** Self-protection initializes **before** data stores and detection engines. This ensures the process is protected against tampering from the moment it starts, even if a signature database is corrupted or a detection module fails to load.

### 9.5.3 Shutdown Order (Reverse)

Shutdown proceeds in reverse order to prevent use-after-free:

```
Phase 1: Disconnect from kernel (stop receiving events)
Phase 2: Disable real-time monitoring
Phase 3: Shutdown detection engine (drain scan queue)
Phase 4: Close data stores (flush and close files)
Phase 5: Disable self-protection (last to go)
Phase 6: Shutdown foundation (Logger flushes final messages)
```

---

## 9.6 Verified Safety Properties

### 9.6.1 No Circular Dependencies ✅

The include-graph analysis confirms zero circular dependencies across all 24 module groups. Potential risk areas that were verified clean:

| Potential Risk | Analysis | Result |
|---------------|----------|--------|
| SignatureStore ↔ HashStore | HashStore imports `SignatureFormat` (types only), not `SignatureStore` | ✅ Safe |
| ThreatIntel internal structure | Well-layered parent-child (Store → Lookup → Index → DB) | ✅ Safe |
| Core/Engine ↔ RealTime | Both use same stores but never cross-import each other | ✅ Safe |
| Database ↔ Utils | One-way dependency (Database → Utils, never reverse) | ✅ Safe |

### 9.6.2 Isolation Boundaries ✅

| Module | Can be disabled without affecting | Cannot be disabled without breaking |
|--------|----------------------------------|-------------------------------------|
| AI/ML | All other detection stages | ML-based verdicts only |
| AntiEvasion | Core scanning pipeline | Evasion technique detection |
| Scripts | File scanning, network scanning | Script content analysis |
| ThreatIntel | Hash/pattern scanning still works | IoC correlation, reputation |
| Whitelist | Scanning works (slower) | Fast-path optimization |

### 9.6.3 ABI Stability ✅

Modules that use PIMPL (Chapter 3) maintain stable ABIs across the dependency graph:

- `ScanEngine` — PIMPL hides all 6 subsystem dependencies
- `SignatureStore` — PIMPL hides HashStore/PatternStore/YARA internals
- `ThreatIntelStore` — PIMPL hides database and index internals
- `BehaviorAnalyzer` — PIMPL hides detection engine internals

This means a change to HashStore's internal implementation doesn't force recompilation of ScanEngine's consumers.

---

## 9.7 Dependency Management Rules

These rules maintain the clean architecture:

1. **Tier N never imports Tier N+1** — infrastructure never depends on detection
2. **Format headers contain only types** — no logic, no allocations, no side effects
3. **PIMPL at every hub** — ScanEngine and SignatureStore hide their dependencies
4. **SelfProtection is an island** — zero imports from any other ShadowStrike module
5. **Utils is foundational** — every module may depend on Utils, but Utils depends on nothing
6. **No lateral Tier 3 dependencies** — Core/Engine and RealTime never import each other

Violating any of these rules in a pull request is grounds for rejection.

---

## 9.8 Summary

| Metric | Value |
|--------|-------|
| Total module groups | 24 |
| Total components | 100+ |
| Total dependency edges | 137 |
| Circular dependencies | **0** |
| Architecture tiers | 3 (Foundation → Infrastructure → Detection) |
| Critical hubs | 2 (ScanEngine, SignatureStore) |
| Fully isolated modules | 1 (SelfProtection — 10 components, 0 external deps) |
| PIMPL-protected hubs | 4 (ScanEngine, SignatureStore, ThreatIntelStore, BehaviorAnalyzer) |

The dependency graph is the skeleton of the codebase. Every new module must fit cleanly into the tier hierarchy. Every new dependency edge must be justified. The zero-circular-dependency property is not aspirational — it's a verified invariant.

---

*Previous: [Chapter 8 — The Detection Pipeline](ch08-detection-pipeline.md)*
*Next: [Chapter 10 — Development Workflow & Testing](ch10-development-testing.md)*

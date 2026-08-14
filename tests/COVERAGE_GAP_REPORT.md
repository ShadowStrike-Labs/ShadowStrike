# Coverage Gap Report — `src/PhantomCore/` and `src/Products/`

Generated 2026-08-14. Findings only. Nothing in this document is proposed as a fix.

---

## 0. Method and its limits

**Corpus measured**

| Set | Count | Definition |
|---|---:|---|
| Source modules | 466 | `*.cpp` under `src/PhantomCore/` + `src/Products/`, excluding `src/PhantomCore/External/` (vendored pugixml / SQLiteCpp / tlsh) |
| Test translation units | 232 | `*.cpp` / `*.hpp` / `*.h` under `tests/` |
| Fuzz harnesses | 26 | `Fuzzer/src/*Harness.cpp` |

**How "has a test" was decided.** Filename matching alone is unreliable here — `SignatureStore.cpp` is covered by
`sig_store_tests.cpp`, `CryptoUtils_SymmetricCipher.cpp` by `CryptoUtils_Tests.cpp`. So each module was reduced to its
*primary class symbol* (most frequent `X::method` definition in the TU) and the whole test corpus was searched for
(a) that symbol as a whole word and (b) an `#include` of the module's header. A module counts as **no test evidence**
only when both are absent.

**Three limits of this measurement, stated plainly.**

1. A symbol appearing in the test corpus does **not** mean the module is tested. In this codebase it frequently means the
   opposite: the module is named inside a `*_stubs.cpp` link-shim that *replaces* the real implementation. Section 2.0
   covers this, and it is the single most important finding in this report.
2. Header-partitioned classes (`ThreatIntelIndex_Core/_Trees/_Lookups/…`, `HashStore_*`, `SignatureIndex_*`) resolve to
   internal helper classes. Where the umbrella class is tested but the internal helper is never named, that is recorded as
   a partial gap, not a total one.
3. Sections 2 and 4 required reading ~90 test files and all 26 harnesses. That reading was delegated. Every claim marked
   **[verified]** below was re-checked directly against the source in this session; unmarked claims come from the
   delegated read and are quoted from the file they cite.

---

## 1. Modules with NO corresponding test file anywhere under `tests/`

**128 of 466 modules (27%)** have no test evidence at all — primary class never named in the test corpus, header never
included by any test.

### 1.1 `src/PhantomCore/` — 22 modules

| Module | Primary symbol | Note |
|---|---|---|
| `Core/FileSystem/ArchiveExtractor.cpp` | `ArchiveFormat` | Untrusted archive bytes. **[verified: zero references in `tests/`]** |
| `Core/FileSystem/DocumentScanner.cpp` | `DocumentType` | Untrusted OOXML/RTF/OLE bytes. **[verified: zero references]** |
| `Core/FileSystem/MediaFileScanner.cpp` | `MediaType` | Untrusted media containers. **[verified: zero references]** |
| `Core/Engine/HeuristicAnalyzer.cpp` | `SuspiciousAPICategory` | Scan-verdict contributor. **[verified: zero references]** |
| `Core/Network/EmailScanner.cpp` | `EmailScanner` | Untrusted MIME. **[verified: zero references]** |
| `Core/Network/DDosProtection.cpp` | `DDosProtection` | |
| `Core/FileSystem/MountPointMonitor.cpp` | `MountPointMonitor` | Removable-media entry point |
| `Service/IpcAuthToken.cpp` | `IpcAuthToken` | **IPC authentication primitive** |
| `Service/ProductExtensions.cpp` | `ProductExtensions` | |
| `Service/BootTrace.cpp` | `BootTrace` | |
| `API/Http/HttpServer.cpp` | `HttpServerImpl` | Network-exposed listener; only reached indirectly via the fuzzer (§4.1) |
| `API/Http/HttpTypes.cpp` | `HttpMethod` | HTTP request parsing types |
| `ThreatIntel/FeedCredentials.cpp` | `FeedCredentials` | Credential handling |
| `ThreatIntel/ThreatIntelIndex_DataStructures.cpp` | `IndexBloomFilter` | Partial — see §1.3 |
| `ThreatIntel/ThreatIntelIndex_Trees.cpp` | `GenericBPlusTree` | Partial — see §1.3 |
| `ThreatIntel/ThreatIntelIndex_URLMatcher.cpp` | `URLPatternMatcher` | Partial — see §1.3 |
| `Utils/CryptoUtils_SecureBuffer.cpp` | `SecureString` | Secret-bearing buffer type |
| `Utils/NetworkUtils_URL.cpp` | `PunycodeConstants` | Punycode/IDN decoding of untrusted hostnames |
| `Utils/ProcessSnapshotCache.cpp` | `ProcessSnapshotCache` | |
| `Utils/Timer.cpp` | `TimerManager` | |
| `Diagnostics/DiagTrace.cpp` | `ScopeTrace` | |
| `RealTime/RealtTimeProtection.cpp` | — | **Dead file.** 18 lines: AGPL header + `#include "pch.h"`, no code. Note the typo'd name next to the real `RealTimeProtection.cpp`. **[verified: full file read]** |

### 1.2 `src/Products/` — 106 modules

No test file exists anywhere under `tests/` for any of these groups. `tests/integration/product_orchestrator/`
exercises only `HomeProductOrchestrator`.

**PhantomEDR (31)** — `EDRProductOrchestrator`; `AssetInventory/` (AssetDiscovery, SoftwareInventory);
`Compliance/` (all 4); `DeviceControl/` (all 3); `Forensics/` (EvidenceCollector, IncidentRecorder, MemoryDumper,
NetworkCapture); `IncidentResponse/AlertCorrelator`; `LiveResponse/RegistryInspector`; `Playbooks/PlaybookScheduler`;
`PolicyEngine/` (PolicyAuditLog, PolicyEnforcer); `Sandboxing/` (LocalSandbox, SandboxPolicy);
`Telemetry/TelemetryFilter`; `ThreatHunting/` (all 4, incl. `IOCScanner`); `Vulnerability/` (all 4).

**PhantomHome (54)** — `AmsiProvider/` (2); `Backup/` (3, and see §5.1); `Banking/` (6 + `KeyloggerProtectionWiring`);
`CryptoMinersProtection/` (5); `Email/` (OutlookScanner, ThunderbirdScanner, SpamDetector, PhishingEmailDetector,
AttachmentScanner); `GameMode/` (2); `IoT/` (IPLeakProtection, RouterSecurityChecker, WiFiSecurityAnalyzer);
`NetworkAttackBlocker/`; `Privacy/` (LocationPrivacy, PrivacyCleaner); `ThreatIntel/PgtiFeedManager`;
`USB_Protection/` (all 5); `WebProtection/` (ChromeExtensionScanner, FirefoxAddonScanner, MaliciousDownloadBlocker,
PhishingDetector, SafeBrowsingAPI, TrackerBlocker); `ZeroTrustGuard/ZeroTrustPromptQueue`;
`Installer/DriverResume/SecureBootCheck`; `UI/` (21: all 11 ViewModels, PipeClient, TrayApp/TrayIpc/TrayMenu,
InstallProbe, PerfBudget, ModuleCatalog, HighContrastContext, WindowActivator, Translator).

**PhantomXDR (21)** — `XDRProductOrchestrator`, `XDRProductEntry`; `AIAssistant/` (all 3); `EmailThreat/` (both);
`IdentityProtection/` (all 3); `NetworkDetection/` (BeaconDetector, DNSAnalyzer, TLSInspector); `SOARLocal/` (both);
`XDRCorrelation/` (all 4); `Config/XDRConfigRegistration`.

### 1.3 Partial gaps — umbrella class tested, internals never named

`ThreatIntelIndex_tests.cpp` and `ThreatIntel_bloom_filter_tests.cpp` exist, but the classes
`IndexBloomFilter`, `GenericBPlusTree`, `URLPatternMatcher` and `ThreatIntelBloomFilter` are **never named anywhere in
`tests/unit/Database_systems_unit/threat_intel/`** **[verified: zero matches]**. The index's bloom filter, B+ tree and
URL matcher are reached only incidentally, if at all. A bloom filter that answers "not present" to every query is
indistinguishable from a working one under the current assertions.

A further **126 modules** are named somewhere in the corpus but have no test that includes their header. These are
predominantly `*Wiring.cpp` / `*Wire.cpp` registration shims whose only appearance is the namespace token
`ShadowStrike`, plus the `SignatureStore_*` / `HashStore_*` partitions whose only match is the shared
`SignatureStoreError` enum. Treat these as unverified rather than covered.

---

## 2. Shape-only tests among modules that DO have tests

### 2.0 The structural cause: link-shims replace the detection pipeline

This must be read before the per-file tables, because it explains why the assertions below cannot fail.

`tests/unit/realtime_unit/RealTimeProtection_stubs.cpp` is 48 KB of out-of-line definitions that displace the **real**
implementations of every subsystem the RTP orchestrator coordinates. Its own header states the intent
**[verified: file read]**:

```
// Provides minimal out-of-line definitions for every symbol pulled in by
// RealTimeProtection.cpp that is NOT compiled as part of this harness.
// No test logic lives here — these stubs exist solely to satisfy the linker.
```

Verbatim from that file **[verified]**:

```cpp
INST(ScanEngine)
EngineResult ScanEngine::ScanFile(const std::wstring&, const ScanContext&) { return {}; }
INST(QuarantineManager)
bool QuarantineManager::Initialize() { return false; }
INST(VPNDetector)
bool VPNDetector::Initialize(const VPNDetectorConfig&) { return false; }
bool TorDetector::Start() { return false; }
```

Displaced in that one file: `ScanEngine`, `ThreatDetector`, `BehaviorAnalyzer`, `QuarantineManager`,
`ExecutableAnalyzer`, `PhantomCortex`, `CortexConfigManager`, all nine `AntiEvasion::*` detectors, all six `Exploits::*`
detectors, `IPCManager`, `TelemetryCollector`, `AlertSystem`, `DigitalSignatureValidator`, and the whole
`Core::Network` chain (`BotnetDetector`, `WebProtection`, `TorDetector`, `VPNDetector`, `P2PMonitor`). Every
`Initialize`/`Start` returns `false`; every `Scan*`/`Analyze*` returns a default-constructed result.

**Consequence for §1's accuracy:** `ExecutableAnalyzer`, `QuarantineManager`, `BotnetDetector`, `WebProtection`,
`TorDetector`, `VPNDetector`, `P2PMonitor` and `FileLockManager` did *not* appear in the §1 gap list — because their only
appearance in `tests/` is inside these stub files **[verified]**. They are functionally as untested as §1's entries.

Four more shims do the same at narrower scope: `FileSystemFilter_stubs.cpp` (ScanEngine → `EngineResult{}`,
PhantomCortex → `CortexVerdict{}`, `IsOperational` → `false`), `ProcessCreationMonitor_stubs.cpp` (signature validator,
AI, hash store, whitelist, behavior analyzer all → null/false), `MemoryProtection_stubs.cpp` (AlertSystem → `""`),
`ZeroHour_stubs.cpp` (ThreatIntel lookups → empty, whitelist → empty), and
`selfprotection_unit/SelfProtection_LinkShim.cpp` (`IPCManager::SendToKernel` → `false` with `*replySize = 0`).

The project's own `tests/link_seams.cpp` articulates the correct standard and names this exact failure mode:

> "Stubbing it would have been faster and would have made every test that reaches a report query pass against a store
> that returns nothing, which is indistinguishable from a store that works and holds no reports. This codebase has
> produced that exact failure often enough (an empty Bloom filter answering 'not present' to every lookup; a fixture
> that never initialised the store so every scan assertion was vacuous) that a stub is only acceptable where the absence
> of behaviour IS the correct behaviour."

That standard is met in `link_seams.cpp` itself. It is not met in the five shims above, where the stubbed-away
subsystems *are* the detection pipeline of the module under test.

### 2.1 The two hollow security test files

**`tests/unit/communication_unit/IPCManager_Tests.cpp` — 6 tests, 0 exercise the class. [verified]**
The token `IPCManager` occurs in exactly two contexts: the `#include` on line 5, and the gtest suite name
`TEST(IPCManagerTest, …)`. There is no `IPCManager::Instance()`, no `SendToKernel`, no `ReplyToKernel`, no
`ConnectFilterPort` anywhere in the file **[verified: grep for `IPCManager|SendToKernel|ReplyToKernel|ConnectFilterPort`
returns only the include line and 4 suite names]**. The tests cover `IPCConfiguration::IsValid`,
`IPCStatistics::Reset`, `ConnectionInfo::ToJson`, and accessors on wire-structs the test itself populated. No message is
sent, no message is received, no malformed frame is rejected, no peer is authenticated.

**`tests/unit/selfprotection_unit/CryptoManager_Tests.cpp` — 3 tests, 0 exercise the class. [verified]**
`CryptoManager::Instance()` is never called; the tokens `Encrypt` and `Decrypt` do not appear **[verified: grep for
`CryptoManager|Encrypt|Decrypt|Instance\(\)` matches only the include line and struct-field assertions]**. No
encrypt/decrypt round-trip, no ciphertext-differs-from-plaintext check, no AEAD tamper-tag rejection, no key
zeroization re-read. The "encryption" test hand-populates an `EncryptionResult` and asserts only that
`GetCombinedOutput` concatenates `iv + ciphertext + tag`. Never called: `Encrypt`, `Decrypt`, `Sign`, `Verify`, `HMAC`,
`DeriveKey`, `DeriveKernelSessionKey`, `VerifyKernelMessageIntegrity`, `ComputeKernelMessageHMAC`,
`ValidateKernelDriverAttestation`, `SecureZero`.

Both files would pass unchanged if the classes were reduced to empty shells — which is precisely what
`SelfProtection_LinkShim.cpp` does at link time, and the tests do not notice.

### 2.2 `RealTimeProtection_Tests.cpp` — 3 tests, 0 assert a verdict [verified: full file read]

The three tests cover: `RTPConfig` factory field values; `PerformanceMetrics::Reset()` / `RTPStatistics::Reset()`
zeroing; exclusion-list add/remove bookkeeping; and callback-registration ID hygiene. No `RTPFileScanRequest` is ever
submitted and no `ScanResult` is ever asserted. Registered callbacks are unregistered without being invoked.

Two specifics worth recording as facts:
- The suite asserts the shipped default is fail-open: `EXPECT_EQ(FailurePolicy::FAIL_OPEN, defaults.failurePolicy);`
- The callback tests carry an unusually careful comment explaining *why* an empty `std::function` must be refused at
  registration ("a path that owes the kernel a verdict"). The reasoning is sound; it is also the only place in the file
  where kernel-verdict semantics are reasoned about, and it is reasoned about for registration bookkeeping, not scanning.

### 2.3 `PackerDetector_Tests.cpp` — 5 tests, 1 real [verified: full file read]

| Test | Class |
|---|---|
| `CategoryAndTypeStringMappingsRemainStable` | shape-only — `PackerTypeToString`, `PackerCategoryToString` |
| `CalculateEntropyHandlesNullUniformAndHighEntropyBuffers` | **real** — feeds byte buffers, asserts Shannon entropy 0.0 / ≈1.0 / ≈8.0 |
| `MatchBuilderPopulatesDerivedMetadata` | shape-only — `PackerMatchBuilder` setter round-trip |
| `MatchQueriesAndClearResetAllEntropyMetrics` | shape-only — hand-populated `PackingInfo`, then `Clear()` zero-check |
| `ResetClearsCounters` | shape-only — `Statistics::Reset()` |

Never called with a packed sample: `AnalyzeFile`, `AnalyzeBuffer`, `AnalyzeSections`, `AnalyzeImports`,
`AnalyzeOverlay`, `AnalyzeEntryPoint`, `MatchEPSignature`, `AnalyzeRichHeader`, `ScanWithYARA`. The README's "100+
packer signatures" are not exercised by any test.

### 2.4 The nine anti-evasion detectors — 48 tests, 8 real (83% shape-only)

| Detector | Total | Real | End-to-end entry point ever called? |
|---|---:|---:|---|
| `DebuggerEvasionDetector` | 6 | 0 | **No** — `AnalyzeProcess`, `CheckPEBFlags`, `CheckHardwareBreakpoints`, +15 more never called |
| `EnvironmentEvasionDetector` | 6 | 0 | **No** — `AnalyzeProcess`, `AnalyzeSystemEnvironment`, +15 never called |
| `SandboxEvasionDetector` | 4 | 0 | **No** — `ScanSystem`, `AnalyzeHardware`, `VerifyHumanInteraction` never called |
| `TimeBasedEvasionDetector` | 4 | 0 | **No** — `AnalyzeProcess`, `AnalyzeRDTSC`, `AnalyzeSleep` never called |
| `ProcessEvasionDetector` | 5 | 0 | **No** — `AnalyzeProcess`, `DetectInjection`, `DetectMasquerading` never called |
| `PackerDetector` | 5 | 1 | Entropy helper only (§2.3) |
| `MetamorphicDetector` | 6 | 1 | Entropy helper only; `CompareFuzzyHash`/`CompareTLSH` called only for invalid-input rejection |
| `VMEvasionDetector` | 6 | 3 | Static classifiers only (`ClassifyImport`, `ParseHypervisorVendor`, `CheckMACAddress`); all 12 `Check*` host collectors never called |
| `NetworkBasedEvasionDetector` | 6 | 3 | Real DGA + beaconing-interval tests; `AnalyzeProcess`/`AnalyzeDomain`/`DetectFastFlux` never called |

Representative shape-only assertion, `EnvironmentEvasionDetector_Tests.cpp`:
```cpp
EnvironmentEvasionResult result; result.isEvasive = true; result.evasionScore = 91.0;
result.Clear();
EXPECT_FALSE(result.isEvasive); EXPECT_DOUBLE_EQ(0.0, result.evasionScore);
```
The detector object is never constructed.

### 2.5 The "assert the detector detects nothing" pattern

Seven detector test files use an uninitialised singleton, a nonexistent PID, or a made-up path so that the sole call to
the public analyze entry point returns empty — and then assert the emptiness. Each would pass if the detector were
deleted and replaced with `return {};`.

| File | The one call to the analyze entry point | Asserted |
|---|---|---|
| `MemoryProtection_Tests.cpp` | `ScanProcess(0xDEADu, ScanMode::Fast)` | `violations.empty()`, `pagesScanned == 0` |
| `ZeroHourProtection_Tests.cpp` | `AnalyzeFile(request)` uninitialised | `errorCode == 1u`, `errorMessage == L"Not initialized"` |
| `MachineLearningDetector_Tests.cpp` | `Analyze(features)` uninitialised | `Classification::Unknown`, `probability == 0.0f` |
| `PackerUnpacker_Tests.cpp` | `DetectPacker(sample)` uninitialised | `isPacked == false`, `packerType == Unknown` |
| `PolymorphicDetector_Tests.cpp` | `Analyze(code)` uninitialised | `isPolymorphic == false`, 14 further empty-returns |
| `SandboxAnalyzer_Tests.cpp` | `Analyze(path)` uninitialised | `isMalicious == false`, `error.code == ERROR_NOT_READY` |
| `ZeroDayDetector_Tests.cpp` (guard test) | `AnalyzeBuffer({0x90,0x90,0xCC})` | `detected == false` |

`BehaviorBlocker_Tests.cpp` is the sharpest case — it constructs a genuinely suspicious sample and asserts it is allowed:
```cpp
behavior.commandLine = L"powershell.exe -enc SGVsbG8=";
behavior.type = BehaviorType::ScriptExecution;
EXPECT_EQ(BlockAction::Allow, blocker.AnalyzeBehavior(behavior));
```
No rule that would flag this input is ever loaded, so the assertion documents "allow-by-default", not analysis.

`ZeroDayDetector` is the one module in this group that also has a positive partner test
(`InitializedHeuristicsDetectShellcodeHeapAndRopSignals`: NOP-sled, GET_PC, decoder stub, heap-spray with an
insufficient-size **negative control**, ROP chain). The other six have no such partner.

### 2.6 Kernel-facing entry points with zero test coverage

Not invoked by any test in the corpus:

| Module | Kernel-facing method |
|---|---|
| `ProcessCreationMonitor` | `OnProcessCreate(ProcessCreateEvent)`, `OnProcessCreate(pid,path,ppid)`, `OnProcessTerminate` |
| `MemoryProtection` | `ProcessKernelMemoryAlert(msgType, data, size)` |
| `FileSystemFilter` | `HandleScanRequest`, `HandleNotification`, `ProcessMessage` |
| `ExploitPrevention` | `OnKernelMemoryAlert` |
| `BehaviorBlocker` | `OnKernelBehavioralAlert` |
| `AMSIIntegration` | `OnKernelProcessNotify`, `OnKernelImageLoad`, `RequestKernelProcessBlock` |
| `IPCManager` | `SendToKernel`, `ReplyToKernel`, `ConnectFilterPort` |
| `CryptoManager` | `VerifyKernelMessageIntegrity`, `ComputeKernelMessageHMAC`, `ValidateKernelDriverAttestation` |

Every bridge at which the driver hands work to user mode is untested.

### 2.7 `ThreatDetector` — the central correlator has no correlation test

`ThreatDetector` fans in ten `AnalyzeWith*` engines. Its 5 tests contain zero calls to `ProcessEvent`,
`ProcessEventBatch`, or any of the ten (`AnalyzeWithBehaviorEngine`, `…HeuristicEngine`, `…SignatureEngine`,
`…ThreatIntel`, `…MLEngine`, `…EmulationEngine`, `…PackerUnpacker`, `…PolymorphicDetector`, `…ZeroDayDetector`,
`…SandboxAnalyzer`). No `SystemEvent` is submitted; no `ThreatVerdict` is observed; registered callbacks are
unregistered without firing.

### 2.8 Script and document scanners

| File | Total | Real | Gap |
|---|---:|---:|---|
| `AMSIIntegration_Tests.cpp` | 4 | **0** | All 4 are enum tables, DTO JSON, `Statistics::Reset`, and pre-init fail-closed. `ScanString` is called once and asserted to return `AmsiResult::Unknown`. No content is ever scanned; no bypass event generated; `CheckIntegrity`/`RepairIntegrity` never called |
| `MacroDetector_Tests.cpp` | 4 | 3 | `ScanDocument` — the Office-macro attack surface — is **never called**. Real coverage is `DetectFormat` on byte headers and `AnalyzeVBA` on hand-passed VBA strings |
| `VBScriptScanner_Tests.cpp` | 4 | 3 | `ScanFile`, `ScanEncodedVBE`, `ScanWSF`, `ScanHTA`, `DecodeVBE` never called. `ScanSource` is called post-init but the only assertion is `totalScans >= 1u` |
| `PythonScriptScanner_Tests.cpp` | 7 | 3 | `ScanPyInstallerExe`, `DecompileBytecode`, `ExtractFromPacked` never called. One test feeds real malicious source and asserts only `status != ErrorParsing` |
| `JavaScriptScanner_Tests.cpp` | 6 | 2 | `ScanFile`, `ScanString`, `Deobfuscate` never called with an asserted verdict |
| `PowerShellScanner_Tests.cpp` | 5 | 3 | Best of the group — real `V2_DOWNGRADE` and `Invoke-Mimikatz` MALICIOUS verdicts, real `-enc` payload detection. `scanFile` never called |

### 2.9 Where the tests are genuinely strong

Recording these because they set the achievable bar in this codebase.

- **`peparser_unit/` — 16 tests, 15 real (94%).** Every public method of `PEParser`, `PEValidation` and `SafeReader` is
  fed synthetic PE input with specific asserted values (machine type, entropy, Rich-header entries, overlay offset,
  `ValidationResult::LfanewOutOfBounds`, `SectionBeyondFile`, `SecurityDirectoryInvalid`).
- **`FileTypeAnalyzer_Tests.cpp` — 16 tests, 14 real.** Positive detections *and* negative controls, including a `.scr`
  screen-saver with a PE body asserted **not** to be spoofing, and RTL-override / double-extension detection.
- **`FileHasher_Tests.cpp` — 15 tests, 10 real.** SHA-256 of `"abc"` asserted against the FIPS vector; cache
  invalidation verified by rewriting the file.
- **`CommunicationProtocol_Tests.cpp` — 16 tests, 15 real.** Genuinely drives
  `MessageDispatcher::ParseFileScanRequest(buffer)` including malformed-buffer rejection.
- **`ScanEngineTeardown_Tests.cpp` — 3 tests, all real** (lifecycle, not detection): verifies a real `0xC0000005`
  at-exit defect via a `testing::Environment` that keeps the engine initialised past `RUN_ALL_TESTS()`.

### 2.10 Aggregate

For the 22 files in `realtime_unit/`, `core_engine_unit/`, `core_filesys_unit/`, `scan_engine_teardown/`:
**126 tests — 45 real, 83 shape-only (66%)**. 38 of the 45 real tests live in three files (`FileTypeAnalyzer`,
`FileHasher`, `FileReputation`). All nine `realtime_unit` files and seven of eight `core_engine_unit` files have
≤ 1 real detection test.

Adding the audited anti-evasion (48/8), scripts (30/14), PEParser (16/15), communication (53/41) and
selfprotection (32/24) directories, the pattern holds: DTO, enum, config-factory and `Statistics::Reset` coverage is
thorough; behavioural coverage of the security functions is thin and concentrated in a handful of files.

---

## 3. Ranked by attack-surface exposure

Ranking criterion: reachability by attacker-controlled input × absence of any assertion that would catch a regression.

### Tier 1 — Untrusted bytes reach production code that no test and no fuzzer touches

| # | Module | Exposure | Evidence |
|---|---|---|---|
| 1 | `Communication/FilterConnection.cpp` | Kernel↔user filter-port trust boundary | No unit test. In the fuzzer it is `class FilterConnection {};` — an empty class **[verified: `ScriptScannerHarnessDepsStub.cpp:53`]**. `HarnessAdapterCatalog.cpp:111-112` advertises a "FilterConnection handshake harness" and "FilterConnection overlapped I/O harness"; **neither file exists** **[verified]** |
| 2 | `Communication/IPCManager.cpp` | Kernel message send/reply | 6 tests, none touch the class (§2.1) **[verified]**. Faked in fuzzer: `SendToKernel → false, *replySize = 0` |
| 3 | `Core/FileSystem/ArchiveExtractor.cpp` | Zip bombs, path traversal, malformed central directory | Zero tests **[verified]**. In fuzzer, `ScanArchive` is a fake returning a synthetic entry, flagging only a literal `"FUZZ_ARCHIVE_BOMB"` string |
| 4 | `Core/FileSystem/DocumentScanner.cpp` | OOXML / RTF / PDF / OLE-CFB | Zero tests **[verified]**. In fuzzer, `Scan` is a fake keyed on `"FUZZ_SIG_INFECTED"` |
| 5 | `Scripts/` — all 6 scanners | Attacker-authored script text | `AMSIIntegration` 0 real tests; `MacroDetector::ScanDocument` never called; all six faked to empty verdicts in the fuzzer (§4.2) |
| 6 | `SelfProtection/CryptoManager.cpp` | Crypto + kernel-message HMAC/attestation | 3 tests, none touch the class (§2.1) **[verified]** |
| 7 | `Core/FileSystem/MediaFileScanner.cpp` | Untrusted media containers | Zero tests **[verified]**, zero fuzzer references **[verified]** |
| 8 | `Core/Network/EmailScanner.cpp` | MIME from the wire | Zero tests **[verified]**, zero fuzzer references **[verified]** |
| 9 | `Core/Network/DNSMonitor.cpp` | DNS responses from the wire | Zero fuzzer references **[verified]**; unit tests exist but do not parse packets |
| 10 | `Utils/NetworkUtils_URL.cpp` (`PunycodeConstants`) | IDN/Punycode decode of hostile hostnames | Zero tests **[verified]** |
| 11 | `Service/IpcAuthToken.cpp` | IPC authentication primitive | Zero tests **[verified]** |
| 12 | `Config/{ConfigManager,PolicyManager}.cpp` | Policy JSON/XML | Unit tests exist, but in the fuzzer every parse **succeeds unconditionally** (§4.2) **[verified]** |

### Tier 2 — On the kernel-verdict path, tests present but shape-only

`RealTimeProtection` (§2.2) · `ThreatDetector` (§2.7) · `PackerDetector` (§2.3) · the other 8 evasion detectors (§2.4) ·
`ExecutableAnalyzer` and `QuarantineManager` (real impls displaced by `RealTimeProtection_stubs.cpp`, §2.0) ·
`HeuristicAnalyzer` (zero tests) · `MachineLearningDetector`, `PackerUnpacker`, `PolymorphicDetector`,
`SandboxAnalyzer`, `BehaviorAnalyzer`, `ZeroHourProtection` (§2.5) · `MemoryProtection`, `ExploitPrevention`,
`BehaviorBlocker`, `FileSystemFilter`, `ProcessCreationMonitor`, `AccessControlManager`, `FileIntegrityMonitor`,
`NetworkTrafficFilter` (§2.5–2.6) · `Communication/MessageDispatcher.cpp` — **the one Tier-2 exception**: it has real
parse tests including malformed-buffer rejection, but **no fuzz harness at all** **[verified: zero references in
`Fuzzer/`]**.

### Tier 3 — Product-layer ingestion, no tests and no fuzzing

`PhantomHome/Email/{AttachmentScanner,OutlookScanner,ThunderbirdScanner,SpamDetector,PhishingEmailDetector}` ·
`PhantomHome/WebProtection/{ChromeExtensionScanner,FirefoxAddonScanner,MaliciousDownloadBlocker,PhishingDetector,
SafeBrowsingAPI}` · `PhantomHome/USB_Protection/` (all 5, incl. `BadUSBDetector`) ·
`PhantomXDR/NetworkDetection/{BeaconDetector,DNSAnalyzer,TLSInspector}` ·
`PhantomXDR/EmailThreat/{EmailAnalyzer,PhishingCorrelator}` · `PhantomEDR/ThreatHunting/IOCScanner` ·
`PhantomEDR/Sandboxing/LocalSandbox`. All parse attacker-supplied content (PST/MBOX/MIME, CRX/XPI, USB descriptors,
TLS/DNS on the wire). None has a test file or a harness **[verified: zero `Fuzzer/` references for the email and
browser-extension scanners]**.

### Tier 4 — Lower exposure

`API/Http/{HttpServer,HttpTypes}` (fuzzed via `ServiceProtocolHarness` over a real loopback socket, but no unit test) ·
`ThreatIntel` index internals (§1.3) · `Utils/CryptoUtils_SecureBuffer` (`SecureString`) ·
`Core/FileSystem/MountPointMonitor` · `Core/Network/DDosProtection` · `PhantomEDR`/`PhantomXDR` orchestration and
reporting · all 21 `PhantomHome/UI/` modules.

---

## 4. Fuzzer: what is harnessed vs. what has no harness

### 4.1 Harnesses that reach real production code (13 of 26)

| Harness | Production code reached | Sample verified call |
|---|---|---|
| `PEParserHarness` | `PEParser.cpp`, `PEValidation.cpp` | `parser.ParseBuffer(data,size,info,&error)` + 10 directory parsers + 4 standalone validators |
| `DisassemblerHarness` | `PhantomDisassembler/Decoder.cpp` | `decoder.DecodeFull(buffer,length,instruction,operands.data())` |
| `EmulatorDecoderHarness` | `InstructionDecoder.cpp` | `decoder.Decode(inputSpan, kFuzzRIPBase, mode, inst)` |
| `EmulatorExecutionHarness` | `CPU.cpp`, `VirtualMemory.cpp`, `MemoryTracker.cpp` | `cpu.Execute(memory, &tracker, config)` |
| `EmulatorPEHarness` | Emulator `PEParser`, `PELoader`, `ImportResolver` | `loader.Load(candidate.bytes, config)` |
| `DatabaseConfigHarness` | `DatabaseManager.cpp`, `ConfigurationDB.cpp` | `Execute(sql,&error)`, `ValidateAgainstRule` |
| `ProcessCommandLineHarness` | `ProcessCreationMonitor.cpp` | `OnProcessCreate`, `AnalyzeCommandLine`, `AnalyzeGraph` |
| `ServiceProtocolHarness` | `HttpServer.cpp`, `HttpTypes.cpp` | raw HTTP over real loopback socket |
| `CryptoCertHarness` | `HashUtils`, `CryptoUtils*`, `CertUtils` | `Crypto::EncryptString/DecryptString`, `Cert::LoadCertificate` |
| `CompressionHarness` | `CompressionUtils.cpp` | `DecompressBuffer` + `Compressor`/`Decompressor` over 4 algorithms |
| `ParserUtilsHarness` | `JSONUtils`, `XMLUtils`, `Base64Utils`, pugixml | `SSJson::Parse`, `SSXml::Parse`, `Base64Decode` (std + urlsafe) |
| `SignaturePatternHarness` | `PatternStore` + 3 matchers, `SignatureFormat` | `store->Scan(...)`, `Format::ParseHashString` |
| `StringPathHashHarness` | `StringUtils`, `HashUtils`, `FileUtils` | `ToWide/ToNarrow/utf8_to_wstring/EscapeJson` |
| `ThreatIntelHarness` | `ThreatIntelFeedManager_parsers.cpp` | `JsonFeedParser::Parse` / `Csv` / `Stix` across 13 real feed configs |
| `ThreatIntelFormatHarness` | `ThreatIntelFormat.cpp` | `ParseIPv4/IPv6`, `ParseHashString` (11 algos), `ParseSTIXTimestamp`, `ParseUUID` |

Partial: `BehaviorHarness` and `TrafficHarness` reach the real `BehaviorAnalyzer`/`BehaviorBlocker` and
`TrafficAnalyzer`/`NetworkTrafficFilter`, but every enrichment they consult is faked.

### 4.2 Harnesses that exist but reach nothing (10 of 26)

Each calls a production API that a `*DepsStub.cpp` intercepts; the production `.cpp` is deliberately absent from
`Fuzzer.vcxproj`.

| Harness | What the stub returns instead |
|---|---|
| `ConfigParserHarness` | **`ConfigManager::ImportFromJson` → `return true;` unconditionally** **[verified: `ConfigParserHarnessDepsStub.cpp:88-90`]**. `ParsePolicyFromJson`/`FromXml` → `return Policy{};`, never `nullopt` **[verified: :151-157]**. Harness then sets `result.parsedOk = true` for every input. **A malformed-policy bug is unreachable by construction.** |
| `ScriptScannerHarness` | All four scanners → default-constructed empty verdicts |
| `AntiEvasionHarness` | `PackerDetector::AnalyzeBuffer` → `PackingInfo{fileSize, analysisComplete=true}`, nothing else; `VMEvasionDetector::AnalyzeCodeBuffer` → counts 1 instruction, detects nothing |
| `ExploitDetectorHarness` | `DetectNopSled`/`DetectShellcode` → `false`; `DisassembleGadget` → `{}`; `DetectConstantEmbedding` → `nullopt` |
| `RansomwareAnalysisHarness` | `CalculateEntropy` → `0.0`; `IsEncrypted` → `false`; every WannaCry/Locky predicate → `false` |
| `AIFeatureHarness` | All 5 extractors → fixed-size all-zero float vectors; harness validates only the vector *length* |
| `FuzzyHasherHarness` | `HashBuffer` → literal `"3:fuzz:fuzz"`; `Compare` → `0`; `IsSuspiciousDigest` → `false` |
| `ScanEngineHarness` | Real `ScanEngine` routing, but **all ~25 downstream engines faked**; verdicts keyed on literal markers |
| `BehaviorHarness` | Ransomware/Persistence/ProcessInjection/ThreatIntel/Whitelist faked; `PersistenceDetector` reduced to a substring test for `"\\CurrentVersion\\Run"` |
| `TrafficHarness` | URLAnalyzer/Tor/VPN/P2P/Botnet/ThreatIntelLookup faked; `SignatureStore::ScanBuffer` keyed on a marker |

**Marker-based self-confirmation.** `kMarkerInfected = "FUZZ_SIG_INFECTED"` is defined in **both** the harness
(`ScanEngineHarness.cpp:38`) and the stub that "detects" it (`ScanEngineHarnessDepsStub.cpp:43`), and again in
`TrafficHarnessDepsStub.cpp:157` **[verified]**. The seed corpus embeds the marker. The fuzzer therefore validates its
detection expectations against **its own hardcoded string**, not against any detector. A regression in real detection
logic cannot fail this check.

### 4.3 Untrusted-input parsers with no harness at all

**Zero references anywhere in `Fuzzer/`** **[verified: single grep across the whole project returns no matches for any
of these nine]**:

1. `src/PhantomCore/Core/FileSystem/MediaFileScanner.cpp`
2. `src/PhantomCore/Core/Network/EmailScanner.cpp`
3. `src/PhantomCore/Core/Network/DNSMonitor.cpp`
4. `src/PhantomCore/Communication/MessageDispatcher.cpp` — real entry point `DispatchMessage(std::span<const uint8_t>)`
5. `src/Products/.../PhantomHome/Email/AttachmentScanner.cpp`
6. `src/Products/.../PhantomHome/Email/OutlookScanner.cpp`
7. `src/Products/.../PhantomHome/Email/ThunderbirdScanner.cpp`
8. `src/Products/.../PhantomHome/WebProtection/ChromeExtensionScanner.cpp`
9. `src/Products/.../PhantomHome/WebProtection/FirefoxAddonScanner.cpp`

**Present in the fuzzer but faked** (harness appears to cover them; calls never reach production code):
`ArchiveExtractor`, `DocumentScanner`, `ExecutableAnalyzer`, all 6 `Scripts/` scanners, `IPCManager`,
`FilterConnection`, `ConfigManager`, `PolicyManager`, `PackerDetector`, `VMEvasionDetector`, `FeatureExtractor`,
`PhantomCortex`, `FuzzyHasher`, `HeapSprayDetector`, `ROPProtection`, `JITSprayDetector`, `RansomwareDetector`,
`WannaCryDetector`, `LockyDetector`, `SignatureStore`, `HashStore`, `WhitelistStore`, `ThreatIntelStore/Database/
Index/Lookup`, `URLAnalyzer`, `TorDetector`, `VPNDetector`, `P2PMonitor`, `BotnetDetector`, `PersistenceDetector`,
`ProcessInjectionDetector`, `AlertSystem`, `TelemetryCollector`, `LogDB`, `ProcessUtils`.

**Covered for real:** `PEParser`, `PEValidation`, `XMLUtils`, `JSONUtils`, `Base64Utils`, `CompressionUtils`,
`ThreatIntelFormat`, `ThreatIntelFeedManager_parsers`, `PatternStore`, `SignatureFormat`, `HttpServer`/`HttpTypes`,
`FileTypeAnalyzer` (compiled, reached only indirectly), the disassembler, and the emulator CPU/memory/loader.

### 4.4 Catalog integrity

- **2 advertised harnesses do not exist**: `"FilterConnection handshake harness"` and
  `"FilterConnection overlapped I/O harness"` (`HarnessAdapterCatalog.cpp:111-112`, repeated at
  `UserModeTargetCatalog.cpp:105,116`) **[verified]**. `AttackSurface.cpp:271-280` lists
  `FilterConnection / IPCManager` and `src\PhantomCore\Communication\FilterConnection.cpp` as covered surface.
- **21 of 26 harnesses are unreachable from `CampaignPlanner`.** Only PE, PE-differential, ThreatIntel,
  ThreatIntel-differential and ServiceCommunication have an adapter entry; the rest run only via a manual `--fuzz-*`
  flag.
- The only stub that is a legitimate build seam is `ThreatIntelFeedManagerStub.cpp`, which replaces just
  `DetectIOCType` and still delegates to the real `ThreatIntel_Util::IsValid*` validators.

---

## 5. Two incidental findings

**5.1 A whole product module is excluded from git.** `.gitignore:258` contains `Backup*/`, intended for Visual Studio
project-upgrade backup folders. It also matches `src/Products/Community/PhantomHome/Backup/`, so
`BackupManager`, `BackupScheduler`, `IncrementalBackup`, `RestoreManager` and `BackupWiring` (9 files) are untracked
**[verified: gitignore-aware glob omits the directory; direct filesystem glob lists all 9 files]**. They are also
untested. Ransomware rollback depends on this module.

**5.2 A dead translation unit sits beside a live one.** `src/PhantomCore/RealTime/RealtTimeProtection.cpp` (note the
transposed `t`) contains only the AGPL header and `#include "pch.h"` — 18 lines, no code — adjacent to the real
`RealTimeProtection.cpp` **[verified: full file read]**.

---

## 6. Summary

| Question | Answer |
|---|---:|
| Modules with no test evidence at all | **128 / 466 (27%)** |
| — in `src/PhantomCore/` | 22 |
| — in `src/Products/` | 106 |
| Additional modules named only inside link-shims that replace them | 8 identified (`ExecutableAnalyzer`, `QuarantineManager`, `BotnetDetector`, `WebProtection`, `TorDetector`, `VPNDetector`, `P2PMonitor`, `FileLockManager`) |
| Shape-only rate, `realtime_unit` + `core_engine_unit` + `core_filesys_unit` + `scan_engine_teardown` | **83 / 126 (66%)** |
| Shape-only rate, `antievasion_unit` | **40 / 48 (83%)** |
| Shape-only rate, `scripts_unit` | **16 / 30 (53%)** |
| Shape-only rate, `peparser_unit` | **1 / 16 (6%)** |
| Test files where the module's own class is never instantiated | 2 (`IPCManager_Tests.cpp`, `CryptoManager_Tests.cpp`) |
| Kernel-facing entry points with any test | **0 of 8 modules** |
| Fuzz harnesses reaching real production code | **13 / 26** |
| Fuzz harnesses reaching nothing (fully stubbed) | **10 / 26** |
| Untrusted-input parsers with no harness of any kind | **9** |
| Advertised harnesses with no implementing file | **2** |

The measurement that generalises: across the audited directories, coverage of DTOs, enum-to-string maps, config-factory
defaults, `Statistics::Reset()` and JSON serialisation is thorough and disciplined. Coverage of the detection, IPC and
cryptographic behaviour those types exist to serve is concentrated in about six files — `peparser_unit/` (all three),
`FileTypeAnalyzer_Tests.cpp`, `FileHasher_Tests.cpp`, `CommunicationProtocol_Tests.cpp` — and is largely absent
elsewhere. For most modules on the kernel-verdict path, deleting the detection implementation and returning a
default-constructed result would not change the passing test count.

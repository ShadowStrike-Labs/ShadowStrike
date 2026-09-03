/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike NGAV - MAIN SERVICE IMPLEMENTATION
 * ============================================================================
 *
 * @file AntivirusService.cpp
 * @brief Enterprise-grade Windows Service implementation.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "AntivirusService.hpp"
#include "BootTrace.hpp"

// The single place the shipped product version is written down. Included here
// so the service can state its own build identity in its log; the deploy
// harness parses the same header to stamp the MSI and every binary's
// VERSIONINFO resource, so the logged version and the installed version cannot
// drift apart.
#include "../../VersionInfo.h"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/Logger.hpp"
#include "../Utils/ThreadPool.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/DataStorePaths.hpp"   // SeedSignatureDatabaseFromBaseline
#include "ServiceMonitor.hpp"

// ============================================================================
// SECURITY MODULE INCLUDES
// ============================================================================
#include "../SelfProtection/CryptoManager.hpp"
#include "../SelfProtection/AntiDebug.hpp"
#include "../SelfProtection/MemoryProtection.hpp"
#include "../SelfProtection/FileProtection.hpp"
#include "../SelfProtection/TamperProtection.hpp"
#include "../SelfProtection/ProcessProtection.hpp"
#include "../SelfProtection/RegistryProtection.hpp"
#include "../SelfProtection/CertificateValidator.hpp"
#include "../SelfProtection/DigitalSignatureValidator.hpp"
#include "../SelfProtection/SelfDefense.hpp"
#include "../Scripts/AMSIIntegration.hpp"
#include "../RealTime/RealTimeProtection.hpp"
#include "../Communication/IPCManager.hpp"
#include "../Communication/AlertSystem.hpp"
#include "../Communication/NotificationManager.hpp"
#include "../Communication/TelemetryCollector.hpp"
#include "../Communication/ReportGenerator.hpp"
#include "../Communication/ServiceCommunication.hpp"
#include "../Update/UpdateManager.hpp"
#include "../Update/SignatureUpdater.hpp"
#include "../Update/ProgramUpdater.hpp"
#include "../Core/Engine/ScanEngine.hpp"

// Live registry event monitoring. This module supplies the event stream that
// RegistryAnalyzer's DKOM detection, StartupAnalyzer's persistence-key
// monitoring and BootTimeAnalyzer's BCD change monitoring all consume. Nothing
// in production started it before, so all three ran with no data.
#include "../Core/Registry/RegistryMonitor.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../ThreatIntel/ThreatIntelStore.hpp"
#include "../Config/ConfigManager.hpp"
#include "ProductExtensions.hpp"
#include "HomeIpcDispatcher.hpp"
#include "ServiceCommunicator.hpp"
#include "IpcAuthToken.hpp"

// ============================================================================
// WINDOWS SDK
// ============================================================================
#include <tchar.h>
#include <strsafe.h>
#include <sddl.h>
#include <wtsapi32.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <sstream>
#include <iomanip>
#include <iterator>

namespace ShadowStrike {
namespace Service {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================
static constexpr const wchar_t* LOG_CATEGORY = L"Service";

// ============================================================================
// IPC AUTH TOKEN PROVISIONING HELPERS
// ============================================================================
//
// IpcAuthToken::Verify() consults an in-memory per-session token cache that is
// only populated by EnsureForSession(). Without an explicit provisioning step
// the cache is permanently cold and every UI AuthHandshake fails — every v2
// command handler in HomeIpcDispatcher is unreachable. EnsureForSession is
// therefore invoked at two well-defined service-lifecycle moments:
//
//   1. After IPC subsystems are running (Impl::Start), for the currently
//      active console session.
//   2. On WTS_SESSION_LOGON / WTS_CONSOLE_CONNECT session-change events, so a
//      user logging in after service start receives a fresh token file.
//
// Provisioning failure is logged but never fatal: the service must continue
// to provide kernel/realtime protection even when no interactive desktop is
// available (Server Core, sessions where the user has no profile, etc.).
namespace {

void ProvisionIpcAuthToken(std::uint32_t sessionId, const wchar_t* reason) noexcept {
    // Session 0 is the non-interactive services session and has no profile
    // directory; WTSQueryUserToken would fail anyway.
    if (sessionId == 0u || sessionId == 0xFFFFFFFFu) {
        return;
    }
    try {
        const std::string token = IpcAuthToken::EnsureForSession(sessionId);
        if (token.empty()) {
            SS_LOG_WARN(LOG_CATEGORY,
                L"IPC auth token provisioning failed for session %u (%ls)",
                sessionId, reason ? reason : L"");
        } else {
            SS_LOG_INFO(LOG_CATEGORY,
                L"IPC auth token provisioned for session %u (%ls)",
                sessionId, reason ? reason : L"");
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY,
            L"IPC auth token provisioning threw for session %u: %hs",
            sessionId, e.what());
    } catch (...) {
        SS_LOG_ERROR(LOG_CATEGORY,
            L"IPC auth token provisioning threw unknown exception for session %u",
            sessionId);
    }
}

void ProvisionInteractiveIpcAuthTokens(const wchar_t* reason) noexcept {
    PWTS_SESSION_INFOW sessions = nullptr;
    DWORD count = 0;
    ::ShadowStrikeAppendBootTrace(L"provision-WTSEnumerateSessions-enter");
    const BOOL enumerated =
        ::WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count);
    ::ShadowStrikeAppendBootTrace(L"provision-WTSEnumerateSessions-leave");
    if (!enumerated) {
        SS_LOG_WARN(LOG_CATEGORY,
            L"WTSEnumerateSessionsW failed during IPC token provisioning (err=%lu)",
            GetLastError());
        const DWORD activeConsole = ::WTSGetActiveConsoleSessionId();
        ::ShadowStrikeAppendBootTrace(L"provision-fallback-console-session-enter");
        ProvisionIpcAuthToken(static_cast<std::uint32_t>(activeConsole), reason);
        ::ShadowStrikeAppendBootTrace(L"provision-fallback-console-session-leave");
        return;
    }

    struct WtsSessionGuard final {
        PWTS_SESSION_INFOW ptr{};
        ~WtsSessionGuard() noexcept { if (ptr) ::WTSFreeMemory(ptr); }
    } guard{sessions};

    for (DWORD i = 0; i < count; ++i) {
        const auto state = sessions[i].State;
        if (state == WTSActive || state == WTSConnected || state == WTSDisconnected) {
            wchar_t tag[96]{};
            (void)::_snwprintf_s(tag, _countof(tag), _TRUNCATE,
                                 L"provision-session-%u-state-%d-enter",
                                 static_cast<unsigned>(sessions[i].SessionId),
                                 static_cast<int>(state));
            ::ShadowStrikeAppendBootTrace(tag);
            ProvisionIpcAuthToken(static_cast<std::uint32_t>(sessions[i].SessionId), reason);
            (void)::_snwprintf_s(tag, _countof(tag), _TRUNCATE,
                                 L"provision-session-%u-leave",
                                 static_cast<unsigned>(sessions[i].SessionId));
            ::ShadowStrikeAppendBootTrace(tag);
        }
    }
}

} // anonymous namespace

// ============================================================================
// STATIC INITIALIZATION
// ============================================================================
std::atomic<bool> AntivirusService::s_instanceCreated{false};

// ============================================================================
// SERVICE IMPLEMENTATION (PIMPL)
// ============================================================================

class AntivirusServiceImpl final {
public:
    AntivirusServiceImpl() = default;
    ~AntivirusServiceImpl() { Stop(); }

    // Non-copyable
    AntivirusServiceImpl(const AntivirusServiceImpl&) = delete;
    AntivirusServiceImpl& operator=(const AntivirusServiceImpl&) = delete;

    [[nodiscard]] bool Initialize() {
        std::unique_lock lock(m_mutex);

        if (m_initialized) return true;

        ::ShadowStrikeAppendBootTrace(L"impl-Initialize-enter");
        try {
            // 1. Initialize Logging only if ServiceMain did not already do it.
            // Reinitializing here used to move service logs back to the default
            // relative "logs" directory (often System32\logs), hiding startup
            // failures from the installer and VM triage workflow.
            if (!Utils::Logger::Instance().IsInitialized()) {
                Utils::LoggerConfig loggerConfig{};
                wchar_t expanded[MAX_PATH]{};
                if (::ExpandEnvironmentStringsW(L"%ProgramData%\\ShadowStrike\\Logs",
                                                 expanded,
                                                 static_cast<DWORD>(std::size(expanded))) != 0) {
                    loggerConfig.logDirectory = expanded;
                }
                loggerConfig.baseFileName = L"PhantomHome.Service";
                loggerConfig.eventLogSource = ServiceConstants::SERVICE_NAME;
                loggerConfig.toConsole = false;
                loggerConfig.toEventLog = true;
                loggerConfig.flushLevel = Utils::LogLevel::Trace;
                Utils::Logger::Instance().Initialize(loggerConfig);
            }
            // STATE THE BUILD IDENTITY FIRST, before anything else can fail.
            // Until now the service never logged its own version, so no field
            // log could prove which build produced it: every triage cycle had
            // to infer the version from the MSI or the installer log, which are
            // separate artefacts that can disagree with the binary actually
            // running. That inference has already been needed for 1.0.92, 1.0.93
            // and 1.0.94, and it is exactly the kind of gap that turns a log
            // into evidence about an unknown build.
            //
            // %hs because SS_VERSION_STRING and SS_PRODUCT_NAME are narrow
            // literals from VersionInfo.h while the log macros take wide format
            // strings.
            //
            // RESIDUAL, stated rather than implied: this runs inside
            // Impl::Initialize, which all three service start paths call, so it
            // covers every normal start - but a failure BEFORE Initialize still
            // produces no version line. The boot trace is what covers that
            // window.
            SS_LOG_INFO(LOG_CATEGORY,
                        L"%hs %hs initializing...",
                        SS_PRODUCT_NAME,
                        SS_VERSION_STRING);

            // 2. Initialize ConfigManager (must be available before any module reads config)
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-ConfigManager-enter");
            if (!Config::ConfigManager::Instance().Initialize()) {
                SS_LOG_WARN(LOG_CATEGORY, L"ConfigManager initialization failed, using defaults");
                // Non-fatal: modules will use hardcoded defaults
            }
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-ConfigManager-leave");

            // 2b. Install the shipped detection content before ANY module opens it.
            //
            // This has to happen here, not later, because module initialization is
            // what opens the database and the first module to do so wins or loses
            // permanently. Field evidence from 1.0.89: AmsiProvider initialized
            // first, opened C:\ProgramData\ShadowStrike\Data\signatures.sdb, got
            // WinError 2 because nothing had put a file there yet, and logged
            // "Initialize failed: No components could be initialized". The seeding
            // then ran from RealTimeProtection a few hundred log lines later and
            // every subsequent open succeeded with 11,053 YARA rules. So the
            // database was fine and the product was working - except that AMSI
            // script scanning spent the entire life of the process with a dead
            // signature store, silently, while reporting itself as started.
            //
            // A module that initializes successfully against nothing is worse than
            // one that fails loudly, because nothing ever revisits it. Seeding
            // before the first consumer removes the ordering dependency instead of
            // reordering the modules, which would only move the problem to whoever
            // ends up first next time.
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-SeedContent-enter");
            if (!Utils::DataStorePaths::SeedSignatureDatabaseFromBaseline()) {
                // Non-fatal by design. A missing or unreadable baseline must not
                // stop the service: an existing working database is left untouched
                // by every failure path, and a first install with no content still
                // has behavioural and heuristic detection. The condition is logged
                // by the callee with the reason.
                SS_LOG_WARN(LOG_CATEGORY,
                            L"Shipped detection content could not be installed; "
                            L"continuing with whatever database is already present");
            }
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-SeedContent-leave");

            // 3. Initialize Infrastructure
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-ThreadPool-enter");
            if (!m_threadPool) {
                Utils::ThreadPoolConfig threadPoolConfig{};
                threadPoolConfig.minThreads = 4;
                threadPoolConfig.maxThreads = 8;
                threadPoolConfig.threadNamePrefix = L"ShadowStrike-Service";
                m_threadPool = std::make_unique<Utils::ThreadPool>(threadPoolConfig);
            }

            if (!m_threadPool->Initialize()) {
                SS_LOG_FATAL(LOG_CATEGORY, L"Failed to initialize ThreadPool");
                ::ShadowStrikeAppendBootTrace(L"impl-Initialize-ThreadPool-FAIL");
                return false;
            }
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-ThreadPool-leave");

            // 4. Configure Service Health Monitor (early, tracks init duration)
            ServiceMonitor::Instance().SetMaxMemoryLimit(1024ULL * 1024ULL * 1024ULL); // 1 GB limit
            ServiceMonitor::Instance().SetMaxCpuLimit(50.0);                           // 50% CPU limit
            ServiceMonitor::Instance().SetHeartbeatTimeout(std::chrono::milliseconds(60000)); // 60s timeout

            // 5. Initialize Security Subsystems
            SS_LOG_INFO(LOG_CATEGORY, L"Initializing security subsystems...");

            // Threat Intel (database-backed IOC store + facade binding)
            //
            // Use the process-wide instance rather than a private one. A default
            // constructed store falls back to StoreConfig::CreateDefault(), which
            // puts the database under %TEMP% with a per-process, per-instance
            // filename - so the service was building a second, throwaway IOC
            // database on every start, next to the persistent one that
            // RealTimeProtection opens. It was always empty, it never survived a
            // restart, and because a miss in an empty store is indistinguishable
            // from "not a known threat", every IOC lookup through the bound
            // facade quietly reported clean.
            //
            // Shared() opens the hardened persistent path once and hands the same
            // instance to every consumer, which also avoids the sharing violation
            // that made the per-instance temp filenames necessary in the first
            // place: the database is memory mapped GENERIC_READ|GENERIC_WRITE with
            // FILE_SHARE_READ only, so two writable opens of one path cannot
            // coexist.
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-ThreatIntelStore-enter");
            if (!m_threatIntelStore) {
                m_threatIntelStore = ThreatIntel::ThreatIntelStore::Shared();
            }

            if (!m_threatIntelStore || !m_threatIntelStore->IsInitialized()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to initialize ThreatIntelStore");
                ::ShadowStrikeAppendBootTrace(L"impl-Initialize-ThreatIntelStore-FAIL");
                return false;
            }

            ThreatIntel::ThreatIntelManager::Instance().Bind(m_threatIntelStore.get());
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-ThreatIntelStore-leave");

            // CryptoManager (foundation — used by ConfigManager, CertificateValidator,
            // and secure IPC; must be available before other security modules)
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-CryptoManager-enter");
            Security::CryptoManagerConfiguration cryptoConfig;
            cryptoConfig.enableHardwareAcceleration = true;
            cryptoConfig.enableSecureMemory = true;
            cryptoConfig.enableAuditLogging = true;
            if (!Security::CryptoManager::Instance().Initialize(cryptoConfig)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to initialize CryptoManager");
                ::ShadowStrikeAppendBootTrace(L"impl-Initialize-CryptoManager-FAIL");
                return false;
            }
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-CryptoManager-leave");

            // Anti-Debug Protection (detect hostile analysis early, before
            // other self-defense modules expose their initialization surface)
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-AntiDebug-enter");
            Security::AntiDebugConfiguration adConfig;
            adConfig.protectionLevel = Security::AntiDebugProtectionLevel::Enhanced;
            adConfig.monitoringMode = Security::MonitoringMode::Adaptive;
            adConfig.enableCodeIntegrity = true;
            adConfig.enableHookDetection = true;
            if (!Security::AntiDebug::Instance().Initialize(adConfig)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize AntiDebug");
                // Non-fatal: anti-debug degrades but service can continue
            }
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-AntiDebug-leave");

            // Memory Protection (protect our process memory before tamper
            // protection starts its integrity monitoring)
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-MemoryProtection-enter");
            Security::MemoryProtectionConfiguration memConfig;
            memConfig.level = Security::MemoryProtectionLevel::Enhanced;
            memConfig.enableCodeIntegrity = true;
            memConfig.enableHeapProtection = true;
            memConfig.enableStackProtection = true;
            // Anti-dump obfuscates this image's PE headers in-memory at
            // [ImageBase, SizeOfHeaders): it wipes the DOS stub and zeroes
            // OptionalHeader.CheckSum/LoaderFlags while PRESERVING e_magic,
            // e_lfanew and the NT signature (see
            // MemoryProtectionImpl::obfuscatePEHeadersInternal).
            //
            // It was previously disabled because a self-integrity monitor
            // baselined an image-base-inclusive CRC region that covered those
            // header bytes, so the mutation tripped a violation and terminated
            // the service before Initialize() returned. That collision no
            // longer exists in the current code, verified across all three
            // self-integrity monitors:
            //   * AntiDebugImpl::RegisterSelfIntegrity — baselines ONLY
            //     executable sections at section->VirtualAddress, which begins
            //     after SizeOfHeaders; headers are not covered.
            //   * MemoryProtectionImpl::ProtectSelfCode — same: code sections
            //     at their VirtualAddress only.
            //   * TamperProtectionImpl::ScanForInlineHooks — only parses the
            //     (preserved) e_lfanew / export RVAs to walk exports for hook
            //     detection; it does not CRC the header bytes.
            // MemoryProtection init failure is already handled non-fatally
            // below, so anti-dump degrades gracefully if it ever fails.
            //
            // INVARIANT: self-integrity registration must remain
            // per-executable-section (never image-base-inclusive) or this
            // collision returns. Re-enabled as intended for the Enhanced level.
            memConfig.enableAntiDump = true;
            if (!Security::MemoryProtection::Instance().Initialize(memConfig)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize MemoryProtection");
                // Non-fatal: memory protection degrades
            }
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-MemoryProtection-leave");

            // Tamper Protection (Critical - protect self first)
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-TamperProtection-enter");
            SS_LOG_INFO(LOG_CATEGORY, L"Initializing TamperProtection...");
            Security::TamperProtectionConfiguration tamperConfig;
            tamperConfig.mode = Security::TamperProtectionMode::Enforce;
            if (!Security::TamperProtection::Instance().Initialize(tamperConfig)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to initialize TamperProtection");
                ::ShadowStrikeAppendBootTrace(L"impl-Initialize-TamperProtection-FAIL");
                return false;
            }
            SS_LOG_INFO(LOG_CATEGORY, L"TamperProtection initialized — calling ProtectSelf");
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-TamperProtection-ProtectSelf-enter");
            if (!Security::TamperProtection::Instance().ProtectSelf()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"TamperProtection ProtectSelf failed");
                ::ShadowStrikeAppendBootTrace(L"impl-Initialize-TamperProtection-ProtectSelf-FAIL");
                return false;
            }
            SS_LOG_INFO(LOG_CATEGORY, L"TamperProtection ProtectSelf completed");
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-TamperProtection-leave");

            // Process Protection (must be initialized before RealTimeProtection
            // so the kernel HandleAlert bridge is ready when IPC starts)
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-ProcessProtection-enter");
            SS_LOG_INFO(LOG_CATEGORY, L"Initializing ProcessProtection...");
            Security::ProcessProtectionConfiguration ppConfig;
            if (!Security::ProcessProtection::Instance().Initialize(ppConfig)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize ProcessProtection");
                // Non-fatal: handle monitoring degrades but service can continue
            } else {
                // Initialize() already protects our own PID internally.
                // Attempt PPL elevation via kernel driver for maximum protection.
                SS_LOG_INFO(LOG_CATEGORY, L"ProcessProtection initialized — attempting PPL elevation");
                ::ShadowStrikeAppendBootTrace(L"impl-Initialize-ProcessProtection-ElevateToPPL-enter");
                (void)Security::ProcessProtection::Instance().ElevateToPPL();
                SS_LOG_INFO(LOG_CATEGORY, L"ProcessProtection PPL elevation attempt completed");
                ::ShadowStrikeAppendBootTrace(L"impl-Initialize-ProcessProtection-ElevateToPPL-leave");
            }
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-ProcessProtection-leave");

            // Registry Protection (initializes kernel registry callback handler
            // and starts integrity monitoring before RealTimeProtection activates)
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-RegistryProtection-enter");
            SS_LOG_INFO(LOG_CATEGORY, L"Initializing RegistryProtection...");
            Security::RegistryProtectionConfiguration rpConfig;
            rpConfig.mode = Security::RegistryProtectionMode::Rollback;
            rpConfig.enableAutoRollback = true;
            rpConfig.enableKernelCallbacks = true;
            rpConfig.enableUserModePolling = true;
            rpConfig.enableIntegrityMonitoring = true;
            rpConfig.enableSnapshots = true;
            if (!Security::RegistryProtection::Instance().Initialize(rpConfig)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize RegistryProtection");
                // Non-fatal: registry tamper detection degrades
            }
            SS_LOG_INFO(LOG_CATEGORY, L"RegistryProtection init returned");
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-RegistryProtection-leave");

            // Registry Monitor (live kernel registry event feed).
            //
            // This is the event SOURCE, not a duplicate of RegistryProtection.
            // RegistryProtection is self-defence for our own keys; this module
            // supplies the general registry event stream that three detectors
            // consume - RegistryAnalyzer's DKOM detection, StartupAnalyzer's
            // persistence-key (T1547) monitoring and BootTimeAnalyzer's BCD
            // store monitoring. Nothing in production started it before, so all
            // three have run with no data on every single release.
            //
            // Both modules subscribe to the same kernel registry fan-out and
            // coexist by design; the fan-out combines subscriber verdicts
            // most-severe-wins, so neither displaces the other.
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-RegistryMonitor-enter");
            SS_LOG_INFO(LOG_CATEGORY, L"Initializing RegistryMonitor...");
            {
                auto& regMon = Core::Registry::RegistryMonitor::Instance();
                if (!regMon.Initialize(Core::Registry::RegistryMonitorConfig::CreateDefault())) {
                    SS_LOG_WARN(LOG_CATEGORY,
                        L"Failed to initialize RegistryMonitor - DKOM, persistence-key and "
                        L"BCD monitoring will have no event source");
                    // Non-fatal: those three detectors degrade to inactive, which
                    // is the state they were already in before this was wired.
                } else if (!regMon.Start()) {
                    SS_LOG_WARN(LOG_CATEGORY,
                        L"RegistryMonitor could not subscribe to the kernel registry feed - "
                        L"DKOM, persistence-key and BCD monitoring will have no event source");
                } else {
                    SS_LOG_INFO(LOG_CATEGORY,
                        L"RegistryMonitor started on the kernel registry fan-out");
                }
            }
            SS_LOG_INFO(LOG_CATEGORY, L"RegistryMonitor init returned");
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-RegistryMonitor-leave");

            // File Protection (protect installation directory and databases
            // before Real-Time Protection opens its signature/pattern files)
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-FileProtection-enter");
            SS_LOG_INFO(LOG_CATEGORY, L"Initializing FileProtection...");
            Security::FileProtectionConfiguration fpConfig;
            fpConfig.mode = Security::FileProtectionMode::Protect;
            fpConfig.enableIntegrityMonitoring = true;
            fpConfig.enableRansomwareProtection = true;
            fpConfig.enableSignatureValidation = true;
            if (!Security::FileProtection::Instance().Initialize(fpConfig)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize FileProtection");
                // Non-fatal: file tamper detection degrades
            }
            SS_LOG_INFO(LOG_CATEGORY, L"FileProtection init returned");
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-FileProtection-leave");

            // Digital Signature Validator (used by RealTimeProtection and
            // ProcessCreationMonitor for Authenticode verification)
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-DigitalSignatureValidator-enter");
            SS_LOG_INFO(LOG_CATEGORY, L"Initializing DigitalSignatureValidator...");
            Security::SignatureValidatorConfiguration dsvConfig;
            dsvConfig.enableCaching = true;
            dsvConfig.allowCatalogSignatures = true;
            dsvConfig.requireTimestamps = true;
            if (!Security::DigitalSignatureValidator::Instance().Initialize(dsvConfig)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize DigitalSignatureValidator");
                // Non-fatal: signature validation degrades
            }
            SS_LOG_INFO(LOG_CATEGORY, L"DigitalSignatureValidator init returned");
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-DigitalSignatureValidator-leave");

            // Certificate Validator
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-CertificateValidator-enter");
            SS_LOG_INFO(LOG_CATEGORY, L"Initializing CertificateValidator...");
            Security::CertificateValidatorConfiguration certConfig;
            if (!Security::CertificateValidator::Instance().Initialize(certConfig)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize CertificateValidator");
            }
            SS_LOG_INFO(LOG_CATEGORY, L"CertificateValidator init returned");
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-CertificateValidator-leave");

            // SelfDefense (central orchestrator — coordinates all protection
            // modules, starts watchdog/heartbeat monitoring. Must be last in
            // the self-protection chain so all subsystems are ready.)
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-SelfDefense-enter");
            SS_LOG_INFO(LOG_CATEGORY, L"Initializing SelfDefense...");
            Security::SelfDefenseConfiguration sdConfig;
            sdConfig.level = Security::SelfDefenseLevel::Enhanced;
            sdConfig.enableWatchdog = true;
            sdConfig.enableHeartbeat = true;
            sdConfig.enableAutoRecovery = true;
            if (!Security::SelfDefense::Instance().Initialize(sdConfig)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize SelfDefense orchestrator");
                // Non-fatal: watchdog/heartbeat monitoring degrades
            }
            SS_LOG_INFO(LOG_CATEGORY, L"SelfDefense init returned");
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-SelfDefense-leave");

            // AMSI Integration
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-AMSIIntegration-enter");
            SS_LOG_INFO(LOG_CATEGORY, L"Initializing AMSIIntegration...");
            if (!Scripts::AMSIIntegration::Instance().Initialize()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize AMSIIntegration");
                // Warning only, service can run without AMSI
            }
            SS_LOG_INFO(LOG_CATEGORY, L"AMSIIntegration init returned");
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-AMSIIntegration-leave");

            // 4. Initialize Communication
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-IPCManager-enter");
            SS_LOG_INFO(LOG_CATEGORY, L"Initializing IPCManager...");
            if (!Communication::IPCManager::Instance().Initialize()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to initialize IPCManager");
                ::ShadowStrikeAppendBootTrace(L"impl-Initialize-IPCManager-FAIL");
                return false;
            }
            SS_LOG_INFO(LOG_CATEGORY, L"IPCManager init returned");

            // Restore kernel-side configuration on every channel establishment.
            //
            // WHY THESE THREE AND WHY HERE. RegistryProtection (above, step 3),
            // FileProtection and SelfDefense each push configuration the driver
            // needs for the whole session, and each pushes it from its own
            // Initialize - all of which ran earlier on THIS thread, before
            // IPCManager even existed, let alone before its encrypted channel
            // came up. Every one of those pushes was refused and lost, so the
            // kernel held no protected key list, no protected path set and no
            // protected process registration for the entire session, on every
            // boot. Registering here is provably after IPCManager::Initialize
            // succeeded, and the publishers fire later still, when the channel
            // is actually established.
            //
            // Each publisher re-reads its module's CURRENT state, so it is
            // correct to call repeatedly and it cannot ship a stale snapshot.
            // Each guards on its own module being initialized, because a module
            // whose Initialize failed above must not be asked to publish.
            {
                auto& ipc = Communication::IPCManager::Instance();

                // Each publisher RETURNS whether the kernel took its configuration,
                // and the aggregator counts confirmations rather than calls. The
                // RegistryProtection sync already returned bool and this site used
                // to discard it with an explicit (void) - the answer was available
                // and thrown away, which is why the 1.0.100 summary could claim
                // success while all three pushes were being refused.
                //
                // An uninitialized module returns false: it genuinely has no
                // configuration in the kernel. The aggregator reports that as
                // "not confirmed" rather than as a failed send, because it does
                // not know which of the two it was and must not guess.
                ipc.RegisterKernelConfigPublisher("RegistryProtection", [] {
                    if (Security::RegistryProtection::HasInstance() &&
                        Security::RegistryProtection::Instance().IsInitialized()) {
                        return Security::RegistryProtection::Instance().SyncProtectedKeysToKernel();
                    }
                    return false;
                });

                ipc.RegisterKernelConfigPublisher("FileProtection", [] {
                    if (Security::FileProtection::HasInstance() &&
                        Security::FileProtection::Instance().IsInitialized()) {
                        return Security::FileProtection::Instance().SyncProtectedPathsToKernel();
                    }
                    return false;
                });

                ipc.RegisterKernelConfigPublisher("SelfDefense", [] {
                    if (Security::SelfDefense::HasInstance() &&
                        Security::SelfDefense::Instance().IsInitialized()) {
                        return Security::SelfDefense::Instance().SyncProtectedProcessesToKernel();
                    }
                    return false;
                });
            }
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-IPCManager-leave");

            // Initialize Communication subsystems (singletons — all depend on IPCManager)
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-AlertSystem-enter");
            if (!Communication::AlertSystem::Instance().Initialize(Communication::AlertConfiguration{})) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize AlertSystem");
            }
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-AlertSystem-leave");
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-TelemetryCollector-enter");
            if (!Communication::TelemetryCollector::Instance().Initialize()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize TelemetryCollector");
            }
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-TelemetryCollector-leave");
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-NotificationManager-enter");
            if (!Communication::NotificationManager::Instance().Initialize()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize NotificationManager");
            }
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-NotificationManager-leave");
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-ReportGenerator-enter");
            if (!Communication::ReportGenerator::Instance().Initialize()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize ReportGenerator");
            }
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-ReportGenerator-leave");
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-ServiceCommunication-enter");
            if (!Communication::ServiceCommunication::Instance().Initialize()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize ServiceCommunication");
            }
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-ServiceCommunication-leave");

            // 5. Initialize Update Manager
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-UpdateManager-enter");

            //
            // THE STAGING DIRECTORY IS NAMED HERE BECAUSE THIS IS WHERE IT IS
            // KNOWN. UpdateConfiguration::stagingDirectory has no default, and
            // this call used to pass a default-constructed config, so the path
            // was empty. UpdateManager then handed
            // stagingDirectory / "signatures" to SignatureUpdater and
            // stagingDirectory / "program" to ProgramUpdater - and an EMPTY path
            // joined with a subdirectory is the RELATIVE path "signatures", not
            // an empty one. Both sub-modules carry their own fallback for an
            // empty staging directory; a relative path is non-empty, so neither
            // fallback fired and both tried to create a directory relative to
            // the process working directory, which for a service is
            // C:\Windows\System32. Either they failed - taking the whole update
            // subsystem down with them - or they succeeded and wrote into a
            // system directory.
            //
            // DataStorePaths owns every path decision in this product, so the
            // answer comes from there rather than being spelled out again. The
            // directory is a CHILD of the data directory so it inherits its
            // hardened ACL (SYSTEM and Administrators only).
            //
            // DELIBERATELY NOT SELF-EXCLUDED: task 55's exclusion set covers our
            // own databases because they contain malware indicators verbatim. A
            // downloaded update package is the opposite case - it is untrusted
            // content that arrived from the network and MUST be scanned.
            //
            Update::UpdateConfiguration updateConfig{};
            updateConfig.stagingDirectory = Utils::DataStorePaths::GetDataDirectory();
            updateConfig.stagingDirectory /= L"Updates";

            if (!Update::UpdateManager::Instance().Initialize(updateConfig)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize UpdateManager");
            }
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-UpdateManager-leave");

            // 6. Wire Update callbacks for hot-reload and telemetry
            if (Update::UpdateManager::Instance().IsInitialized()) {
                // Hot-reload: when signatures are updated, trigger ScanEngine database reload
                Update::SignatureUpdater::Instance().RegisterReloadCallback(
                    [](Update::SignatureDatabaseType type) {
                        SS_LOG_INFO(L"Service", L"Signature database %u updated — triggering ScanEngine reload",
                            static_cast<unsigned>(type));
                        if (Core::Engine::ScanEngine::Instance().IsInitialized()) {
                            if (!Core::Engine::ScanEngine::Instance().ReloadDatabases()) {
                                SS_LOG_ERROR(L"Service", L"ScanEngine database reload failed after signature update");
                            }
                        }
                    });

                // Signature update completion telemetry
                Update::SignatureUpdater::Instance().RegisterCompletionCallback(
                    [](const Update::SigUpdateResult& result) {
                        if (result.success) {
                            SS_LOG_INFO(L"Service", L"Signature update completed: %hs -> %hs",
                                result.oldVersion.versionString.c_str(),
                                result.newVersion.versionString.c_str());
                        } else {
                            SS_LOG_WARN(L"Service", L"Signature update failed: %hs",
                                result.errorMessage.c_str());
                        }
                    });

                // Program update completion — may require reboot for drivers
                Update::ProgramUpdater::Instance().RegisterCompletionCallback(
                    [](const Update::ProgUpdateResult& result) {
                        if (result.success) {
                            SS_LOG_INFO(L"Service", L"Program update applied: %hs -> %hs (reboot=%d)",
                                result.oldVersion.ToString().c_str(),
                                result.newVersion.ToString().c_str(),
                                result.rebootRequired ? 1 : 0);
                        } else {
                            SS_LOG_WARN(L"Service", L"Program update failed: %hs (rollback=%d)",
                                result.errorMessage.c_str(),
                                result.wasRollback ? 1 : 0);
                        }
                    });

                SS_LOG_INFO(LOG_CATEGORY, L"Update callbacks wired: hot-reload, completion telemetry");
            }

            // ==================================================================
            // PRODUCT EXTENSION HOOK
            // ==================================================================
            // PhantomCore is product-agnostic. If a product binary (PhantomHome,
            // PhantomEDR, PhantomXDR, ...) registered its orchestrator via a
            // static initializer in its entry TU, invoke it now. Engine-only
            // binaries and tests link cleanly because no product registers.
            //
            // Failure of a product extension is a hard error: we've already
            // committed resources and the user expects the product to be up.
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-ProductExtensions-enter");
            if (!ProductExtensions::Instance().InitializeProduct()) {
                SS_LOG_FATAL(LOG_CATEGORY, L"Product extension initialization failed");
                ::ShadowStrikeAppendBootTrace(L"impl-Initialize-ProductExtensions-FAIL");
                return false;
            }
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-ProductExtensions-leave");

            m_initialized = true;
            SS_LOG_INFO(LOG_CATEGORY, L"Service initialization complete");
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-leave-ok");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_FATAL(LOG_CATEGORY, L"Exception during initialization: %hs", e.what());
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-EXCEPTION-std");
            return false;
        } catch (...) {
            SS_LOG_FATAL(LOG_CATEGORY, L"Unknown exception during initialization");
            ::ShadowStrikeAppendBootTrace(L"impl-Initialize-EXCEPTION-unknown");
            return false;
        }
    }

    [[nodiscard]] bool Start() {
        std::unique_lock lock(m_mutex);
        ::ShadowStrikeAppendBootTrace(L"impl-Start-enter");
        if (!m_initialized) {
            SS_LOG_FATAL(LOG_CATEGORY, L"Start requested before successful initialization.");
            ::ShadowStrikeAppendBootTrace(L"impl-Start-FAIL-not-initialized");
            return false;
        }
        if (m_running) return true;

        SS_LOG_INFO(LOG_CATEGORY, L"Starting services...");

        // Start Subsystems
        ::ShadowStrikeAppendBootTrace(L"impl-Start-TamperProtection-SetEnabled-enter");
        Security::TamperProtection::Instance().SetEnabled(true);
        ::ShadowStrikeAppendBootTrace(L"impl-Start-TamperProtection-SetEnabled-leave");
        ::ShadowStrikeAppendBootTrace(L"impl-Start-RealTimeProtection-enter");
        if (!RealTime::RealTimeProtection::Instance().Start()) {
            SS_LOG_FATAL(LOG_CATEGORY, L"Failed to start RealTimeProtection");
            ::ShadowStrikeAppendBootTrace(L"impl-Start-RealTimeProtection-FAIL");
            return false;
        }
        ::ShadowStrikeAppendBootTrace(L"impl-Start-RealTimeProtection-leave");
        ::ShadowStrikeAppendBootTrace(L"impl-Start-IPCManager-enter");
        if (!Communication::IPCManager::Instance().Start()) {
            SS_LOG_FATAL(LOG_CATEGORY, L"Failed to start IPCManager");
            ::ShadowStrikeAppendBootTrace(L"impl-Start-IPCManager-FAIL");
            RealTime::RealTimeProtection::Instance().Stop();
            return false;
        }
        ::ShadowStrikeAppendBootTrace(L"impl-Start-IPCManager-leave");

        // Engine fully initialized (RealTimeProtection + IPCManager up): open the
        // scan-servicing gate. Until this point DispatchMessage fail-opens kernel
        // file-scan requests (immediate Verdict_Clean) so the cold-boot scan storm
        // cannot stall login I/O while the scan engine is still warming up.
        Communication::IPCManager::Instance().SetScanServicingReady(true);
        ::ShadowStrikeAppendBootTrace(L"impl-Start-ScanServicingReady");

        // Start Communication subsystems
        ::ShadowStrikeAppendBootTrace(L"impl-Start-ServiceCommunication-enter");
        if (!Communication::ServiceCommunication::Instance().Start(true)) {
            SS_LOG_WARN(LOG_CATEGORY, L"ServiceCommunication failed to start; service telemetry channel degraded");
        }
        ::ShadowStrikeAppendBootTrace(L"impl-Start-ServiceCommunication-leave");

        // Initialize and start the v2 IPC pipe server, then wire all PhantomHome
        // UI command handlers before any client can connect and send a verb.
        {
            auto& ipcSvc = ServiceCommunicator::Instance();
            ::ShadowStrikeAppendBootTrace(L"impl-Start-ServiceCommunicator-Initialize-enter");
            if (!ipcSvc.Initialize()) {
                SS_LOG_FATAL(LOG_CATEGORY, L"ServiceCommunicator::Initialize() failed — PhantomHome UI IPC unavailable");
                ::ShadowStrikeAppendBootTrace(L"impl-Start-ServiceCommunicator-Initialize-FAIL");
                Communication::IPCManager::Instance().Stop();
                RealTime::RealTimeProtection::Instance().Stop();
                return false;
            }
            ::ShadowStrikeAppendBootTrace(L"impl-Start-ServiceCommunicator-Initialize-leave");

            // Register every PhantomHome UI verb handler (AuthHandshake, GetStatus,
            // scan controls, etc.) BEFORE the pipe server starts accepting clients.
            // The dispatcher only populates the v2 handler map (guarded by the
            // ServiceCommunicator's handler mutex) and does not depend on the server
            // running, so installing here closes the accept-before-register race:
            // a UI client that connects the instant Start() opens the pipe will
            // always find the AuthHandshake handler present and receive a reply.
            // Without this call ProcessV2Message reports "no v2 handler" and never
            // responds, so the UI's auth handshake times out (AUTH_TIMEOUT) and the
            // dashboard reports the service as offline despite SCM showing RUNNING.
            ::ShadowStrikeAppendBootTrace(L"impl-Start-HomeIpcDispatcher-Install-enter");
            HomeIpcDispatcher::Instance().Install(ipcSvc);
            ::ShadowStrikeAppendBootTrace(L"impl-Start-HomeIpcDispatcher-Install-leave");

            ::ShadowStrikeAppendBootTrace(L"impl-Start-ServiceCommunicator-Start-enter");
            if (!ipcSvc.Start()) {
                SS_LOG_FATAL(LOG_CATEGORY, L"ServiceCommunicator::Start() failed — PhantomHome UI IPC unavailable");
                ::ShadowStrikeAppendBootTrace(L"impl-Start-ServiceCommunicator-Start-FAIL");
                Communication::IPCManager::Instance().Stop();
                RealTime::RealTimeProtection::Instance().Stop();
                return false;
            }
            ::ShadowStrikeAppendBootTrace(L"impl-Start-ServiceCommunicator-Start-leave");
            // Provision every already-present interactive session. Services
            // can start after the first user logon, in which case the SCM
            // SESSIONCHANGE event may already be gone.
            //
            // Deliberately OFF the start thread. This call was observed entering
            // WriteTokenFile and never returning, and because it sat on the
            // critical start path the consequences were wildly out of proportion
            // to the work: Start() never completed, the service never reported
            // RUNNING, the verdict pipeline never came up, and every file create
            // on the machine then blocked in the minifilter waiting for verdicts
            // that could not arrive. A stalled auth-token write froze the whole
            // system.
            //
            // Token provisioning is not a prerequisite for protection - it exists
            // so the desktop UI can authenticate to the service. Running it on a
            // detached thread keeps its blast radius proportional: if it stalls,
            // the UI cannot authenticate, and that is all. Protection still comes
            // up. The underlying stall is still a defect and is still being traced
            // per-call inside WriteTokenFile; this bounds the damage, it does not
            // excuse the bug.
            ::ShadowStrikeAppendBootTrace(L"impl-Start-ProvisionInteractive-detach");
            std::thread([]() noexcept {
                ::ShadowStrikeAppendBootTrace(L"provision-thread-enter");
                ProvisionInteractiveIpcAuthTokens(L"service-start");
                ::ShadowStrikeAppendBootTrace(L"provision-thread-leave");
            }).detach();
        }

        // Register AMSI provider
        ::ShadowStrikeAppendBootTrace(L"impl-Start-AMSI-RegisterProvider-enter");
        if (!Scripts::AMSIIntegration::Instance().RegisterProvider()) {
            SS_LOG_WARN(LOG_CATEGORY, L"AMSI provider registration failed; script scanning remains available through direct scanners");
        }
        ::ShadowStrikeAppendBootTrace(L"impl-Start-AMSI-RegisterProvider-leave");

        // Start health monitoring (all modules now initialized, heartbeat loop can begin)
        ::ShadowStrikeAppendBootTrace(L"impl-Start-ServiceMonitor-enter");
        if (!ServiceMonitor::Instance().StartMonitoring()) {
            SS_LOG_WARN(LOG_CATEGORY, L"Failed to start ServiceMonitor");
        }
        ::ShadowStrikeAppendBootTrace(L"impl-Start-ServiceMonitor-leave");
        // Prime heartbeats so monitors don't immediately flag a hang
        ServiceMonitor::Instance().UpdateHeartbeat();
        if (Security::SelfDefense::HasInstance() &&
            Security::SelfDefense::Instance().IsInitialized()) {
            try {
                Security::SelfDefense::Instance().SendHeartbeat("ServiceMain");
            } catch (...) {}
        }

        m_running = true;

        // Start maintenance loop (heartbeat feeding, health monitoring, log flush)
        ::ShadowStrikeAppendBootTrace(L"impl-Start-MaintenanceThread-spawn");
        m_maintenanceThread = std::thread(&AntivirusServiceImpl::MaintenanceLoop, this);

        SS_LOG_INFO(LOG_CATEGORY, L"ShadowStrike NGAV Service is RUNNING");
        ::ShadowStrikeAppendBootTrace(L"impl-Start-leave-ok");
        return true;
    }

    void Stop() {
        std::unique_lock lock(m_mutex);
        if (!m_running) return;

        SS_LOG_INFO(LOG_CATEGORY, L"Stopping services...");

        // Signal maintenance loop to exit and join before any module teardown
        m_running = false;
        m_shutdownCv.notify_all();
        if (m_maintenanceThread.joinable()) {
            lock.unlock();
            m_maintenanceThread.join();
            lock.lock();
        }

        // Stop health monitoring before module teardown to prevent false hang alarms
        ServiceMonitor::Instance().StopMonitoring();

        // Shutdown in reverse order

        // Shut down product extension (e.g. PhantomHome orchestrator) FIRST while
        // PhantomCore subsystems (RealTimeProtection, IPC, Logger) are still live
        // so product modules can quiesce cleanly. No-op if no product registered.
        ProductExtensions::Instance().ShutdownProduct();

        // Shutdown Communication subsystems first (they depend on IPCManager)
        Communication::ServiceCommunication::Instance().Stop();
        Communication::ServiceCommunication::Instance().Shutdown();
        Communication::ReportGenerator::Instance().Shutdown();
        Communication::NotificationManager::Instance().Shutdown();
        Communication::TelemetryCollector::Instance().Shutdown();
        Communication::AlertSystem::Instance().Shutdown();

        Communication::IPCManager::Instance().Stop();

        // Shutdown UpdateManager (stop any pending downloads/installations)
        if (Update::UpdateManager::HasInstance() &&
            Update::UpdateManager::Instance().IsInitialized()) {
            Update::UpdateManager::Instance().Shutdown();
        }

        if (!Scripts::AMSIIntegration::Instance().UnregisterProvider()) {
            SS_LOG_WARN(LOG_CATEGORY, L"AMSI provider unregistration reported failure during shutdown");
        }
        Scripts::AMSIIntegration::Instance().Shutdown();

        RealTime::RealTimeProtection::Instance().Stop();

        // SelfDefense shutdown (stops watchdog/heartbeat first so it
        // doesn't trigger false recovery during orderly teardown)
        if (Security::SelfDefense::HasInstance() &&
            Security::SelfDefense::Instance().IsInitialized()) {
            Security::SelfDefense::Instance().Shutdown(
                Security::SelfDefense::Instance().GenerateAuthorizationToken("service_shutdown", 60));
        }

        // CertificateValidator shutdown
        if (Security::CertificateValidator::HasInstance() &&
            Security::CertificateValidator::Instance().IsInitialized()) {
            Security::CertificateValidator::Instance().Shutdown();
        }

        // DigitalSignatureValidator shutdown
        if (Security::DigitalSignatureValidator::HasInstance() &&
            Security::DigitalSignatureValidator::Instance().IsInitialized()) {
            Security::DigitalSignatureValidator::Instance().Shutdown();
        }

        // FileProtection shutdown
        if (Security::FileProtection::HasInstance() &&
            Security::FileProtection::Instance().IsInitialized()) {
            Security::FileProtection::Instance().Shutdown(
                Security::FileProtection::Instance().GenerateAuthorizationToken());
        }

        // RegistryMonitor shutdown - releases its registry fan-out subscription.
        // Order relative to RegistryProtection is NOT load-bearing: each
        // subscriber is removed BY NAME, so neither teardown can disturb the
        // other. That property is the fix from commit c65d6fc2, where a
        // teardown passed nullptr and cleared the entire feed, disabling kernel
        // registry dispatch for every remaining module.
        Core::Registry::RegistryMonitor::Instance().Shutdown();

        // RegistryProtection shutdown (before ProcessProtection so registry
        // tamper detection is still active during process handle cleanup)
        if (Security::RegistryProtection::HasInstance() &&
            Security::RegistryProtection::Instance().IsInitialized()) {
            Security::RegistryProtection::Instance().Shutdown(
                Security::RegistryProtection::Instance().GenerateAuthorizationToken());
        }

        // ProcessProtection shutdown (before TamperProtection so tamper hooks
        // are still active while we close protected handles)
        if (Security::ProcessProtection::HasInstance() &&
            Security::ProcessProtection::Instance().IsInitialized()) {
            Security::ProcessProtection::Instance().Shutdown(
                Security::ProcessProtection::Instance().GetInternalAuthToken());
        }

        // TamperProtection shutdown — authenticate via the runtime-issued
        // internal token, matching the pattern used by ProcessProtection /
        // MemoryProtection above. The previous "INTERNAL_SHUTDOWN" sentinel
        // string was an auth bypass usable by any in-process module.
        if (Security::TamperProtection::HasInstance() &&
            Security::TamperProtection::Instance().IsInitialized()) {
            Security::TamperProtection::Instance().Shutdown(
                Security::TamperProtection::Instance().GetInternalAuthToken());
        }

        // MemoryProtection shutdown (after TamperProtection so integrity
        // monitors are no longer checking our protected regions)
        if (Security::MemoryProtection::HasInstance() &&
            Security::MemoryProtection::Instance().IsInitialized()) {
            Security::MemoryProtection::Instance().Shutdown(
                Security::MemoryProtection::Instance().GetInternalAuthToken());
        }

        // AntiDebug shutdown
        if (Security::AntiDebug::HasInstance() &&
            Security::AntiDebug::Instance().IsInitialized()) {
            Security::AntiDebug::Instance().Shutdown();
        }

        // CryptoManager shutdown (last — other modules may need crypto
        // during their own shutdown for secure memory wiping)
        if (Security::CryptoManager::HasInstance() &&
            Security::CryptoManager::Instance().IsInitialized()) {
            Security::CryptoManager::Instance().Shutdown();
        }

        ThreatIntel::ThreatIntelManager::Instance().Bind(nullptr);
        if (m_threatIntelStore) {
            // Release our reference, do not shut the store down. This is the
            // process-wide instance now, so calling Shutdown() here would close
            // the database out from under RealTimeProtection and ScanEngine,
            // which hold the same object. The store tears itself down when the
            // last reference goes away.
            m_threatIntelStore.reset();
        }

        if (m_threadPool) {
            m_threadPool->Shutdown();
        }

        // ConfigManager shutdown (after all modules that read config are down)
        if (Config::ConfigManager::HasInstance()) {
            Config::ConfigManager::Instance().Shutdown();
        }

        m_initialized = false;
        SS_LOG_INFO(LOG_CATEGORY, L"ShadowStrike NGAV Service STOPPED");

        // Logger shutdown (last — flush all pending messages)
        Utils::Logger::Instance().ShutDown();
    }

    void Pause() {
        SS_LOG_INFO(LOG_CATEGORY, L"Pausing protection...");
        RealTime::RealTimeProtection::Instance().Pause();
        // We generally don't stop IPC during pause to allow admin commands
    }

    void Continue() {
        SS_LOG_INFO(LOG_CATEGORY, L"Resuming protection...");
        RealTime::RealTimeProtection::Instance().Resume();
    }

    [[nodiscard]] std::string GetStatusReport() const {
        std::stringstream ss;
        ss << "{";
        ss << "\"service\":\"ShadowStrike\",";
        ss << "\"status\":\"" << (m_running ? "running" : (m_initialized ? "stopped" : "uninitialized")) << "\",";

        // ServiceMonitor resource stats
        auto stats = ServiceMonitor::Instance().GetCurrentStats();
        ss << "\"health\":{";
        ss << "\"isHealthy\":" << (stats.isHealthy ? "true" : "false") << ",";
        ss << "\"cpuUsagePercent\":" << std::fixed << std::setprecision(1) << stats.cpuUsagePercent << ",";
        ss << "\"memoryUsageMB\":" << (stats.memoryUsageBytes / (1024 * 1024)) << ",";
        ss << "\"handleCount\":" << stats.handleCount << ",";
        ss << "\"uptimeSeconds\":" << stats.uptimeSeconds << ",";
        ss << "\"statusMessage\":\"" << stats.statusMessage << "\"";
        ss << "},";

        // Module status
        ss << "\"modules\":{";

        // Threat Intel
        ss << "\"threatIntel\":" << (ThreatIntel::ThreatIntelManager::Instance().IsInitialized() ? "true" : "false") << ",";

        // CryptoManager
        if (Security::CryptoManager::HasInstance()) {
            ss << "\"cryptoManager\":true,";
        } else {
            ss << "\"cryptoManager\":false,";
        }

        // TamperProtection
        if (Security::TamperProtection::HasInstance()) {
            ss << "\"tamperProtection\":true,";
        } else {
            ss << "\"tamperProtection\":false,";
        }

        // RealTimeProtection
        ss << "\"realTimeProtection\":{";
        ss << "\"active\":" << (RealTime::RealTimeProtection::Instance().IsActive() ? "true" : "false");
        ss << "},";

        // SelfDefense
        if (Security::SelfDefense::HasInstance() &&
            Security::SelfDefense::Instance().IsInitialized()) {
            ss << "\"selfDefense\":true,";
        } else {
            ss << "\"selfDefense\":false,";
        }

        // IPCManager
        if (Communication::IPCManager::HasInstance()) {
            ss << "\"ipcManager\":true,";
        } else {
            ss << "\"ipcManager\":false,";
        }

        // ServiceCommunication
        if (Communication::ServiceCommunication::HasInstance()) {
            ss << "\"serviceCommunication\":" << (Communication::ServiceCommunication::Instance().IsRunning() ? "true" : "false");
        } else {
            ss << "\"serviceCommunication\":false";
        }

        ss << "}"; // modules
        ss << "}"; // root
        return ss.str();
    }

    // Service Installation Helpers
    [[nodiscard]] bool InstallService() {
        SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
        if (!hSCManager) {
            SS_LOG_ERROR(LOG_CATEGORY, L"OpenSCManager failed: %u", GetLastError());
            return false;
        }

        // Get executable path
        wchar_t szPath[MAX_PATH];
        if (!GetModuleFileNameW(nullptr, szPath, MAX_PATH)) {
            CloseServiceHandle(hSCManager);
            return false;
        }

        // Quote path for security
        std::wstring binaryPath = L"\"";
        binaryPath += szPath;
        binaryPath += L"\"";

        SC_HANDLE hService = CreateServiceW(
            hSCManager,
            ServiceConstants::SERVICE_NAME,
            ServiceConstants::DISPLAY_NAME,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            binaryPath.c_str(),
            nullptr,
            nullptr,
            ServiceConstants::DEPENDENCIES,
            nullptr, // LocalSystem
            nullptr
        );

        if (!hService) {
            SS_LOG_ERROR(LOG_CATEGORY, L"CreateService failed: %u", GetLastError());
            CloseServiceHandle(hSCManager);
            return false;
        }

        // Set description
        SERVICE_DESCRIPTIONW sd;
        sd.lpDescription = const_cast<LPWSTR>(ServiceConstants::DESCRIPTION);
        ChangeServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, &sd);

        // Set recovery options
        SERVICE_FAILURE_ACTIONSW sfa;
        SC_ACTION actions[3];
        actions[0].Type = SC_ACTION_RESTART;
        actions[0].Delay = 60000; // 1 min
        actions[1].Type = SC_ACTION_RESTART;
        actions[1].Delay = 60000;
        actions[2].Type = SC_ACTION_NONE;
        actions[2].Delay = 0;

        sfa.dwResetPeriod = 86400; // 1 day
        sfa.lpRebootMsg = nullptr;
        sfa.lpCommand = nullptr;
        sfa.cActions = 3;
        sfa.lpsaActions = actions;

        ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa);

        SS_LOG_INFO(LOG_CATEGORY, L"Service installed successfully");

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return true;
    }

    [[nodiscard]] bool UninstallService() {
        SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!hSCManager) return false;

        SC_HANDLE hService = OpenServiceW(hSCManager, ServiceConstants::SERVICE_NAME, DELETE);
        if (!hService) {
            CloseServiceHandle(hSCManager);
            return false;
        }

        if (!DeleteService(hService)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"DeleteService failed: %u", GetLastError());
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return false;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Service uninstalled successfully");

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return true;
    }

private:
    std::recursive_mutex m_mutex;
    bool m_initialized = false;
    bool m_running = false;
    std::unique_ptr<Utils::ThreadPool> m_threadPool;
    std::shared_ptr<ThreatIntel::ThreatIntelStore> m_threatIntelStore;
    std::thread m_maintenanceThread;
    std::mutex m_shutdownMutex;
    std::condition_variable m_shutdownCv;

    void MaintenanceLoop() {
        SS_LOG_INFO(LOG_CATEGORY, L"Service maintenance loop started");

        constexpr auto LOOP_INTERVAL = std::chrono::seconds(5);

        while (m_running) {
            // 1. Feed ServiceMonitor heartbeat
            ServiceMonitor::Instance().UpdateHeartbeat();

            // 2. Feed SelfDefense heartbeat (proves service is alive to watchdog)
            if (Security::SelfDefense::HasInstance() &&
                Security::SelfDefense::Instance().IsInitialized()) {
                try {
                    Security::SelfDefense::Instance().SendHeartbeat("ServiceMain");
                } catch (...) {}
            }

            // 3. Check and log health degradation
            if (!ServiceMonitor::Instance().IsHealthy()) {
                auto stats = ServiceMonitor::Instance().GetCurrentStats();
                SS_LOG_WARN(LOG_CATEGORY, L"Service health degraded: %hs",
                            stats.statusMessage.c_str());
            }

            // 4. Periodic log flush
            Utils::Logger::Instance().Flush();

            // Sleep with cancellation support
            {
                std::unique_lock lock(m_shutdownMutex);
                if (m_shutdownCv.wait_for(lock, LOOP_INTERVAL, [this] { return !m_running; })) {
                    break;
                }
            }
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Service maintenance loop exited");
    }
};

// ============================================================================
// PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

AntivirusService& AntivirusService::Instance() noexcept {
    static AntivirusService instance;
    return instance;
}

AntivirusService::AntivirusService()
    : m_impl(std::make_unique<AntivirusServiceImpl>()) {
    // Manual-reset stop event; pre-created so ServiceCtrlHandler can signal
    // it the instant SCM delivers SERVICE_CONTROL_STOP, even if OnStart is
    // still mid-flight.
    m_stopEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    s_instanceCreated.store(true);
}

AntivirusService::~AntivirusService() {
    if (m_stopEvent != nullptr) {
        ::CloseHandle(m_stopEvent);
        m_stopEvent = nullptr;
    }
}

// ============================================================================
// SCM ENTRY POINTS
// ============================================================================

void WINAPI AntivirusService::ServiceMain(DWORD argc, LPWSTR* argv) {
    ::ShadowStrikeAppendBootTrace(L"ServiceMain-entry");
    Instance().OnStart(argc, argv);
    ::ShadowStrikeAppendBootTrace(L"ServiceMain-OnStart-returned");
}

DWORD WINAPI AntivirusService::ServiceCtrlHandler(DWORD control, DWORD eventType, LPVOID eventData, LPVOID context) {
    auto& service = Instance();

    switch (control) {
        case SERVICE_CONTROL_STOP:
            service.OnStop();
            return NO_ERROR;
        case SERVICE_CONTROL_PAUSE:
            service.OnPause();
            return NO_ERROR;
        case SERVICE_CONTROL_CONTINUE:
            service.OnContinue();
            return NO_ERROR;
        case SERVICE_CONTROL_SHUTDOWN:
            service.OnShutdown();
            return NO_ERROR;
        case SERVICE_CONTROL_SESSIONCHANGE:
            service.OnSessionChange(eventType, static_cast<WTSSESSION_NOTIFICATION*>(eventData));
            return NO_ERROR;
        case SERVICE_CONTROL_POWEREVENT:
            service.OnPowerEvent(eventType, static_cast<POWERBROADCAST_SETTING*>(eventData));
            return NO_ERROR;
        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

// ============================================================================
// SERVICE LOGIC
// ============================================================================

bool AntivirusService::Run() {
    ::ShadowStrikeAppendBootTrace(L"AntivirusService::Run-enter");

    SERVICE_TABLE_ENTRYW dispatchTable[] = {
        { const_cast<LPWSTR>(ServiceConstants::SERVICE_NAME),
          static_cast<LPSERVICE_MAIN_FUNCTIONW>(ServiceMain) },
        { nullptr, nullptr }
    };

    ::ShadowStrikeAppendBootTrace(L"pre-StartServiceCtrlDispatcherW");
    const BOOL dispatched = ::StartServiceCtrlDispatcherW(dispatchTable);
    const DWORD dispatchErr = dispatched ? ERROR_SUCCESS : ::GetLastError();
    {
        wchar_t tag[128] = {};
        (void)::_snwprintf_s(tag, _countof(tag), _TRUNCATE,
                             L"post-StartServiceCtrlDispatcherW rc=%d err=%lu",
                             dispatched ? 1 : 0, dispatchErr);
        ::ShadowStrikeAppendBootTrace(tag);
    }

    if (!dispatched) {
        if (dispatchErr == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            // Console-mode debug path (running outside SCM).
            ::ShadowStrikeAppendBootTrace(L"Run-console-mode");
            SS_LOG_INFO(LOG_CATEGORY, L"Running in console mode...");
            if (m_impl->Initialize()) {
                if (!m_impl->Start()) {
                    SS_LOG_FATAL(LOG_CATEGORY, L"Console-mode service start failed.");
                    return false;
                }

                SS_LOG_INFO(LOG_CATEGORY, L"Press Enter to stop...");
                getchar();

                m_impl->Stop();
                return true;
            }
            return false;
        }
        return false;
    }
    return true;
}

bool AntivirusService::Install() {
    return m_impl->InstallService();
}

bool AntivirusService::Uninstall() {
    return m_impl->UninstallService();
}

void AntivirusService::OnStart(DWORD argc, LPWSTR* argv) {
    ::ShadowStrikeAppendBootTrace(L"OnStart-enter");
    (void)argc;
    (void)argv;

    m_statusHandle = RegisterServiceCtrlHandlerExW(
        ServiceConstants::SERVICE_NAME,
        ServiceCtrlHandler,
        nullptr
    );

    if (!m_statusHandle) {
        const DWORD err = GetLastError();
        SS_LOG_FATAL(LOG_CATEGORY,
                     L"RegisterServiceCtrlHandlerExW failed for %ls (0x%08X).",
                     ServiceConstants::SERVICE_NAME,
                     err);
        ::ShadowStrikeAppendBootTrace(L"OnStart-RegisterServiceCtrlHandlerExW-FAIL");
        return;
    }
    ::ShadowStrikeAppendBootTrace(L"OnStart-StatusHandle-registered");

    // ------------------------------------------------------------------
    // PHASE 1 — MUST COMPLETE IN < 1 SECOND
    // ------------------------------------------------------------------
    // Report SERVICE_START_PENDING with a tight wait-hint, then transition
    // to SERVICE_RUNNING immediately. SCM marks autoload boot-critical
    // services as "started" only when they reach RUNNING; winlogon waits
    // on that for its Welcome → desktop transition under certain
    // installations. Heavy initialization (signature DBs, kernel IPC,
    // SHA-256 baselines, per-process/registry protection snapshots) is
    // deferred to a background thread to avoid pinning winlogon for tens
    // of seconds on slow VMs or cold disks.
    constexpr DWORD kPhase1WaitHintMs = 2000;
    SetServiceStatus(SERVICE_START_PENDING, NO_ERROR, kPhase1WaitHintMs);
    ::ShadowStrikeAppendBootTrace(L"OnStart-SCM-START_PENDING-set");

    // Transition to RUNNING IMMEDIATELY — before any subsystem init. The
    // ServiceCtrlHandler is already registered, the stop event is already
    // created (in the constructor), so we can honor SERVICE_CONTROL_STOP
    // even mid-init via OnStop signalling m_stopEvent.
    SetServiceStatus(SERVICE_RUNNING);
    ::ShadowStrikeAppendBootTrace(L"OnStart-SCM-RUNNING-set-early");

    // ------------------------------------------------------------------
    // PHASE 2 — BACKGROUND INITIALIZATION
    // ------------------------------------------------------------------
    // Spawn a dedicated init thread. ServiceMain owns process lifetime by
    // waiting on m_stopEvent below; the init thread does all heavy work.
    // If init fails the thread signals m_stopEvent and reports STOPPED.
    auto bootInitProc = [](LPVOID ctx) -> DWORD {
        ::ShadowStrikeAppendBootTrace(L"OnStart-bootInitThread-enter");
        auto* self = static_cast<AntivirusService*>(ctx);
        bool initOk = false;
        bool startOk = false;
        try {
            ::ShadowStrikeAppendBootTrace(L"OnStart-Initialize-call");
            initOk = self->m_impl->Initialize();
            ::ShadowStrikeAppendBootTrace(initOk ? L"OnStart-Initialize-returned-ok"
                                                 : L"OnStart-Initialize-returned-FAIL");
            if (initOk) {
                ::ShadowStrikeAppendBootTrace(L"OnStart-Start-call");
                startOk = self->m_impl->Start();
                ::ShadowStrikeAppendBootTrace(startOk ? L"OnStart-Start-returned-ok"
                                                      : L"OnStart-Start-returned-FAIL");
            }
        } catch (const std::exception& e) {
            SS_LOG_FATAL(LOG_CATEGORY,
                         L"Exception in background init: %hs", e.what());
            ::ShadowStrikeAppendBootTrace(L"OnStart-bootInitThread-EXCEPTION-std");
        } catch (...) {
            ::ShadowStrikeAppendBootTrace(L"OnStart-bootInitThread-EXCEPTION-unknown");
        }

        self->m_bootInitComplete.store(true, std::memory_order_release);

        if (!initOk || !startOk) {
            // Fatal background-init failure. Service has already reported
            // SERVICE_RUNNING to SCM, so we cannot SetServiceStatus(STOPPED)
            // straight from RUNNING without an explicit STOP_PENDING.
            // Signal the stop event; ServiceMain wakes, performs orderly
            // teardown, and reports STOPPED with ERROR_SERVICE_SPECIFIC_ERROR.
            ::ShadowStrikeAppendBootTrace(L"OnStart-bootInitThread-signal-stop-on-failure");
            self->m_serviceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
            self->m_serviceStatus.dwServiceSpecificExitCode = 1;
            if (self->m_stopEvent != nullptr) {
                ::SetEvent(self->m_stopEvent);
            }
        } else {
            ::ShadowStrikeAppendBootTrace(L"OnStart-bootInitThread-leave-ok");
        }
        return 0;
    };

    m_bootInitThread = ::CreateThread(nullptr, 0, bootInitProc, this, 0, nullptr);
    if (m_bootInitThread == nullptr) {
        const DWORD err = ::GetLastError();
        SS_LOG_FATAL(LOG_CATEGORY,
                     L"Failed to spawn background init thread: 0x%08X", err);
        ::ShadowStrikeAppendBootTrace(L"OnStart-bootInitThread-CreateThread-FAIL");
        // Inline fallback so the service does not stay up with no protection.
        bool initOk = false;
        try { initOk = m_impl->Initialize(); } catch (...) {}
        if (initOk) {
            try { (void)m_impl->Start(); } catch (...) {}
        }
        if (!initOk) {
            SetServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
            SetServiceStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
            return;
        }
    }

    // CRITICAL: block the ServiceMain worker thread on the stop event so the
    // process stays alive on a controlled signal, rather than depending on
    // background worker threads (maintenance loop, IPC pump, ...) remaining
    // alive. This is best-practice service hosting: if every worker thread
    // exits unexpectedly, ServiceMain still owns the process lifetime via
    // the stop event, and SCM never sees an unexplained STOPPED.
    if (m_stopEvent != nullptr) {
        ::ShadowStrikeAppendBootTrace(L"OnStart-wait-on-stop-event");
        (void)::WaitForSingleObject(m_stopEvent, INFINITE);
        ::ShadowStrikeAppendBootTrace(L"OnStart-stop-event-signalled");
    } else {
        ::ShadowStrikeAppendBootTrace(L"OnStart-stop-event-missing");
    }

    // Join background init thread before ServiceMain returns. After
    // m_stopEvent is signalled the init thread may still be inside
    // Initialize/Start; waiting prevents tearing down PIMPL while it's
    // still touching subsystem singletons.
    if (m_bootInitThread != nullptr) {
        ::ShadowStrikeAppendBootTrace(L"OnStart-bootInitThread-join-enter");
        (void)::WaitForSingleObject(m_bootInitThread, 30000);
        ::CloseHandle(m_bootInitThread);
        m_bootInitThread = nullptr;
        ::ShadowStrikeAppendBootTrace(L"OnStart-bootInitThread-join-leave");
    }
}

void AntivirusService::OnStop() {
    SetServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
    if (m_stopEvent != nullptr) {
        ::SetEvent(m_stopEvent);
    }
    m_impl->Stop();
    SetServiceStatus(SERVICE_STOPPED);
}

void AntivirusService::OnPause() {
    SetServiceStatus(SERVICE_PAUSE_PENDING, NO_ERROR, 1000);
    m_impl->Pause();
    SetServiceStatus(SERVICE_PAUSED);
}

void AntivirusService::OnContinue() {
    SetServiceStatus(SERVICE_CONTINUE_PENDING, NO_ERROR, 1000);
    m_impl->Continue();
    SetServiceStatus(SERVICE_RUNNING);
}

void AntivirusService::OnShutdown() {
    SetServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, ServiceConstants::SHUTDOWN_TIMEOUT_MS);
    if (m_stopEvent != nullptr) {
        ::SetEvent(m_stopEvent);
    }
    m_impl->Stop();
    SetServiceStatus(SERVICE_STOPPED);
}

void AntivirusService::OnSessionChange(DWORD eventType, WTSSESSION_NOTIFICATION* notification) {
    if (!notification) return;

    const DWORD sessionId = notification->dwSessionId;
    SS_LOG_INFO(LOG_CATEGORY, L"Session change event: type=%u sessionId=%u", eventType, sessionId);

    // Provision (or refresh) the per-session IPC auth token whenever a user
    // becomes interactively present. Logoff/lock events deliberately leave the
    // cache entry intact: a subsequent logon for the same sessionId rotates it
    // via EnsureForSession's first-writer-wins generator.
    switch (eventType) {
        case WTS_SESSION_LOGON:
        case WTS_CONSOLE_CONNECT:
        case WTS_REMOTE_CONNECT:
        case WTS_SESSION_UNLOCK:
            ProvisionIpcAuthToken(static_cast<std::uint32_t>(sessionId),
                                  L"session-change");
            break;
        default:
            break;
    }

    // Broadcast session event to connected GUI/tray clients via ServiceCommunication
    if (Communication::ServiceCommunication::HasInstance() &&
        Communication::ServiceCommunication::Instance().IsRunning()) {

        const char* eventName = "Unknown";
        switch (eventType) {
            case WTS_SESSION_LOGON:          eventName = "SessionLogon"; break;
            case WTS_SESSION_LOGOFF:         eventName = "SessionLogoff"; break;
            case WTS_SESSION_LOCK:           eventName = "SessionLock"; break;
            case WTS_SESSION_UNLOCK:         eventName = "SessionUnlock"; break;
            case WTS_REMOTE_CONNECT:         eventName = "RemoteConnect"; break;
            case WTS_REMOTE_DISCONNECT:      eventName = "RemoteDisconnect"; break;
            case WTS_CONSOLE_CONNECT:        eventName = "ConsoleConnect"; break;
            case WTS_CONSOLE_DISCONNECT:     eventName = "ConsoleDisconnect"; break;
            default: break;
        }

        try {
            Communication::ServiceCommunication::Instance().SendSystemAlert(
                "SessionChange",
                std::string("{\"event\":\"") + eventName +
                    "\",\"sessionId\":" + std::to_string(sessionId) + "}",
                1); // severity 1 = informational
        } catch (const std::exception& e) {
            SS_LOG_WARN(LOG_CATEGORY, L"Failed to broadcast session change: %hs", e.what());
        }
    }
}

void AntivirusService::OnPowerEvent(DWORD eventType, POWERBROADCAST_SETTING* setting) {
    (void)setting; // May be null for some event types

    switch (eventType) {
        case PBT_APMPOWERSTATUSCHANGE: {
            SYSTEM_POWER_STATUS sps{};
            if (GetSystemPowerStatus(&sps)) {
                if (sps.ACLineStatus == 0) { // Battery
                    SS_LOG_INFO(LOG_CATEGORY, L"Switched to battery power — reducing scan intensity");
                    RealTime::RealTimeProtection::Instance().Pause(0, L"Battery power conservation");
                } else { // AC power
                    SS_LOG_INFO(LOG_CATEGORY, L"AC power restored — resuming full protection");
                    RealTime::RealTimeProtection::Instance().Resume();
                }
            }
            break;
        }
        case PBT_APMSUSPEND:
            SS_LOG_INFO(LOG_CATEGORY, L"System entering sleep — flushing state");
            Utils::Logger::Instance().Flush();
            break;

        case PBT_APMRESUMESUSPEND:
        case PBT_APMRESUMEAUTOMATIC:
            SS_LOG_INFO(LOG_CATEGORY, L"System resumed from sleep — re-priming heartbeats");
            // Re-prime heartbeats after sleep to prevent false hang alarms
            ServiceMonitor::Instance().UpdateHeartbeat();
            if (Security::SelfDefense::HasInstance() &&
                Security::SelfDefense::Instance().IsInitialized()) {
                try {
                    Security::SelfDefense::Instance().SendHeartbeat("ServiceMain");
                } catch (...) {}
            }
            break;

        default:
            break;
    }
}

void AntivirusService::SetServiceStatus(DWORD currentState, DWORD win32ExitCode, DWORD waitHint) {
    static DWORD checkPoint = 1;

    m_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    m_serviceStatus.dwCurrentState = currentState;
    m_serviceStatus.dwWin32ExitCode = win32ExitCode;
    m_serviceStatus.dwWaitHint = waitHint;

    if (currentState == SERVICE_START_PENDING ||
        currentState == SERVICE_STOP_PENDING ||
        currentState == SERVICE_PAUSE_PENDING ||
        currentState == SERVICE_CONTINUE_PENDING) {
        m_serviceStatus.dwControlsAccepted = 0;
        m_serviceStatus.dwCheckPoint = checkPoint++;
    } else {
        m_serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP |
                                           SERVICE_ACCEPT_SHUTDOWN |
                                           SERVICE_ACCEPT_PAUSE_CONTINUE |
                                           SERVICE_ACCEPT_SESSIONCHANGE |
                                           SERVICE_ACCEPT_POWEREVENT;
        m_serviceStatus.dwCheckPoint = 0;
    }

    if (currentState == SERVICE_RUNNING || currentState == SERVICE_STOPPED) {
        m_serviceStatus.dwCheckPoint = 0;
    }

    ::SetServiceStatus(m_statusHandle, &m_serviceStatus);
}

std::string AntivirusService::GetStatusReport() const {
    return m_impl->GetStatusReport();
}

bool AntivirusService::IsHealthy() const noexcept {
    try {
        // Check ServiceMonitor resource health (CPU, memory, heartbeat)
        if (!ServiceMonitor::Instance().IsHealthy()) return false;

        // Check fatal-dependency modules (service cannot function without these)
        if (!ThreatIntel::ThreatIntelManager::Instance().IsInitialized()) return false;

        if (Security::CryptoManager::HasInstance() &&
            !Security::CryptoManager::Instance().IsInitialized()) return false;

        if (Security::TamperProtection::HasInstance() &&
            !Security::TamperProtection::Instance().IsInitialized()) return false;

        if (!RealTime::RealTimeProtection::Instance().IsActive()) return false;

        if (Communication::IPCManager::HasInstance() &&
            !Communication::IPCManager::Instance().IsInitialized()) return false;

        return true;
    } catch (...) {
        return false;
    }
}

} // namespace Service
} // namespace ShadowStrike

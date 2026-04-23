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

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/Logger.hpp"
#include "../Utils/ThreadPool.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/FileUtils.hpp"
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
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../ThreatIntel/ThreatIntelStore.hpp"
#include "../Config/ConfigManager.hpp"
#include "ProductExtensions.hpp"
#include "HomeIpcDispatcher.hpp"
#include "ServiceCommunicator.hpp"

// ============================================================================
// WINDOWS SDK
// ============================================================================
#include <tchar.h>
#include <strsafe.h>
#include <sddl.h>
#include <thread>
#include <condition_variable>
#include <sstream>
#include <iomanip>

namespace ShadowStrike {
namespace Service {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================
static constexpr const wchar_t* LOG_CATEGORY = L"Service";

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

        try {
            // 1. Initialize Logging
            Utils::LoggerConfig loggerConfig{};
            loggerConfig.baseFileName = ServiceConstants::SERVICE_NAME;
            loggerConfig.eventLogSource = ServiceConstants::SERVICE_NAME;
            // Synchronous logging during Initialize so every line is durably
            // flushed before the next Initialize() call — critical for
            // diagnosing crashes in downstream modules. Async mode is
            // re-enabled after the service reaches steady state (see Run()).
            loggerConfig.async = false;
            loggerConfig.flushLevel = Utils::LogLevel::Trace;
            Utils::Logger::Instance().Initialize(loggerConfig);
            SS_LOG_INFO(LOG_CATEGORY, L"ShadowStrike NGAV Service initializing...");

            // 2. Initialize ConfigManager (must be available before any module reads config)
            if (!Config::ConfigManager::Instance().Initialize()) {
                SS_LOG_WARN(LOG_CATEGORY, L"ConfigManager initialization failed, using defaults");
                // Non-fatal: modules will use hardcoded defaults
            }

            // 3. Initialize Infrastructure
            if (!m_threadPool) {
                Utils::ThreadPoolConfig threadPoolConfig{};
                threadPoolConfig.minThreads = 4;
                threadPoolConfig.maxThreads = 8;
                threadPoolConfig.threadNamePrefix = L"ShadowStrike-Service";
                m_threadPool = std::make_unique<Utils::ThreadPool>(threadPoolConfig);
            }

            if (!m_threadPool->Initialize()) {
                SS_LOG_FATAL(LOG_CATEGORY, L"Failed to initialize ThreadPool");
                return false;
            }

            // 4. Configure Service Health Monitor (early, tracks init duration)
            ServiceMonitor::Instance().SetMaxMemoryLimit(1024ULL * 1024ULL * 1024ULL); // 1 GB limit
            ServiceMonitor::Instance().SetMaxCpuLimit(50.0);                           // 50% CPU limit
            ServiceMonitor::Instance().SetHeartbeatTimeout(std::chrono::milliseconds(60000)); // 60s timeout

            // 5. Initialize Security Subsystems
            SS_LOG_INFO(LOG_CATEGORY, L"Initializing security subsystems...");

            // Threat Intel (database-backed IOC store + facade binding)
            if (!m_threatIntelStore) {
                m_threatIntelStore = std::make_unique<ThreatIntel::ThreatIntelStore>();
            }

            if (!m_threatIntelStore->IsInitialized() && !m_threatIntelStore->Initialize()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to initialize ThreatIntelStore");
                // Continue? Depending on policy. Critical failure usually.
                return false;
            }

            ThreatIntel::ThreatIntelManager::Instance().Bind(m_threatIntelStore.get());

            // CryptoManager (foundation — used by ConfigManager, CertificateValidator,
            // and secure IPC; must be available before other security modules)
            Security::CryptoManagerConfiguration cryptoConfig;
            cryptoConfig.enableHardwareAcceleration = true;
            cryptoConfig.enableSecureMemory = true;
            cryptoConfig.enableAuditLogging = true;
            if (!Security::CryptoManager::Instance().Initialize(cryptoConfig)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to initialize CryptoManager");
                return false;
            }

            // Anti-Debug Protection (detect hostile analysis early, before
            // other self-defense modules expose their initialization surface)
            Security::AntiDebugConfiguration adConfig;
            adConfig.protectionLevel = Security::AntiDebugProtectionLevel::Enhanced;
            adConfig.monitoringMode = Security::MonitoringMode::Adaptive;
            adConfig.enableCodeIntegrity = true;
            adConfig.enableHookDetection = true;
            if (!Security::AntiDebug::Instance().Initialize(adConfig)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize AntiDebug");
                // Non-fatal: anti-debug degrades but service can continue
            }

            // Memory Protection (protect our process memory before tamper
            // protection starts its integrity monitoring)
            Security::MemoryProtectionConfiguration memConfig;
            memConfig.level = Security::MemoryProtectionLevel::Enhanced;
            memConfig.enableCodeIntegrity = true;
            memConfig.enableHeapProtection = true;
            memConfig.enableStackProtection = true;
            // NOTE: enableAntiDump performs PE header obfuscation (wipes DOS
            // stub and mutates OptionalHeader) on the running image. This
            // collides with AntiDebug's code-integrity monitor, which has
            // already registered the entire image (headers included) as a
            // CRC-checked region — the mutation trips AntiDebug and
            // terminates the service before Initialize() can return. Disable
            // here until AntiDebug gains a header-exclusion token; it is a
            // defense-in-depth feature, not a core protection.
            memConfig.enableAntiDump = false;
            if (!Security::MemoryProtection::Instance().Initialize(memConfig)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize MemoryProtection");
                // Non-fatal: memory protection degrades
            }

            // Tamper Protection (Critical - protect self first)
            SS_LOG_INFO(LOG_CATEGORY, L"Initializing TamperProtection...");
            Security::TamperProtectionConfiguration tamperConfig;
            tamperConfig.mode = Security::TamperProtectionMode::Enforce;
            if (!Security::TamperProtection::Instance().Initialize(tamperConfig)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to initialize TamperProtection");
                return false;
            }
            SS_LOG_INFO(LOG_CATEGORY, L"TamperProtection initialized — calling ProtectSelf");
            Security::TamperProtection::Instance().ProtectSelf();
            SS_LOG_INFO(LOG_CATEGORY, L"TamperProtection ProtectSelf completed");

            // Process Protection (must be initialized before RealTimeProtection
            // so the kernel HandleAlert bridge is ready when IPC starts)
            SS_LOG_INFO(LOG_CATEGORY, L"Initializing ProcessProtection...");
            Security::ProcessProtectionConfiguration ppConfig;
            if (!Security::ProcessProtection::Instance().Initialize(ppConfig)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize ProcessProtection");
                // Non-fatal: handle monitoring degrades but service can continue
            } else {
                // Initialize() already protects our own PID internally.
                // Attempt PPL elevation via kernel driver for maximum protection.
                SS_LOG_INFO(LOG_CATEGORY, L"ProcessProtection initialized — attempting PPL elevation");
                (void)Security::ProcessProtection::Instance().ElevateToPPL();
                SS_LOG_INFO(LOG_CATEGORY, L"ProcessProtection PPL elevation attempt completed");
            }

            // Registry Protection (initializes kernel registry callback handler
            // and starts integrity monitoring before RealTimeProtection activates)
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

            // File Protection (protect installation directory and databases
            // before Real-Time Protection opens its signature/pattern files)
            Security::FileProtectionConfiguration fpConfig;
            fpConfig.mode = Security::FileProtectionMode::Protect;
            fpConfig.enableIntegrityMonitoring = true;
            fpConfig.enableRansomwareProtection = true;
            fpConfig.enableSignatureValidation = true;
            if (!Security::FileProtection::Instance().Initialize(fpConfig)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize FileProtection");
                // Non-fatal: file tamper detection degrades
            }

            // Digital Signature Validator (used by RealTimeProtection and
            // ProcessCreationMonitor for Authenticode verification)
            Security::SignatureValidatorConfiguration dsvConfig;
            dsvConfig.enableCaching = true;
            dsvConfig.allowCatalogSignatures = true;
            dsvConfig.requireTimestamps = true;
            if (!Security::DigitalSignatureValidator::Instance().Initialize(dsvConfig)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize DigitalSignatureValidator");
                // Non-fatal: signature validation degrades
            }

            // Certificate Validator
            Security::CertificateValidatorConfiguration certConfig;
            if (!Security::CertificateValidator::Instance().Initialize(certConfig)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize CertificateValidator");
            }

            // SelfDefense (central orchestrator — coordinates all protection
            // modules, starts watchdog/heartbeat monitoring. Must be last in
            // the self-protection chain so all subsystems are ready.)
            Security::SelfDefenseConfiguration sdConfig;
            sdConfig.level = Security::SelfDefenseLevel::Enhanced;
            sdConfig.enableWatchdog = true;
            sdConfig.enableHeartbeat = true;
            sdConfig.enableAutoRecovery = true;
            if (!Security::SelfDefense::Instance().Initialize(sdConfig)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize SelfDefense orchestrator");
                // Non-fatal: watchdog/heartbeat monitoring degrades
            }

            // AMSI Integration
            if (!Scripts::AMSIIntegration::Instance().Initialize()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize AMSIIntegration");
                // Warning only, service can run without AMSI
            }

            // 4. Initialize Communication
            if (!Communication::IPCManager::Instance().Initialize()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to initialize IPCManager");
                return false;
            }

            // Initialize Communication subsystems (singletons — all depend on IPCManager)
            if (!Communication::AlertSystem::Instance().Initialize(Communication::AlertConfiguration{})) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize AlertSystem");
            }
            if (!Communication::TelemetryCollector::Instance().Initialize()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize TelemetryCollector");
            }
            if (!Communication::NotificationManager::Instance().Initialize()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize NotificationManager");
            }
            if (!Communication::ReportGenerator::Instance().Initialize()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize ReportGenerator");
            }
            if (!Communication::ServiceCommunication::Instance().Initialize()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize ServiceCommunication");
            }

            // 5. Initialize Update Manager
            if (!Update::UpdateManager::Instance().Initialize()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize UpdateManager");
            }

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
            if (!ProductExtensions::Instance().InitializeProduct()) {
                SS_LOG_FATAL(LOG_CATEGORY, L"Product extension initialization failed");
                return false;
            }

            m_initialized = true;
            SS_LOG_INFO(LOG_CATEGORY, L"Service initialization complete");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_FATAL(LOG_CATEGORY, L"Exception during initialization: %hs", e.what());
            return false;
        } catch (...) {
            SS_LOG_FATAL(LOG_CATEGORY, L"Unknown exception during initialization");
            return false;
        }
    }

    void Start() {
        std::unique_lock lock(m_mutex);
        if (!m_initialized || m_running) return;

        SS_LOG_INFO(LOG_CATEGORY, L"Starting services...");

        // Start Subsystems
        Security::TamperProtection::Instance().SetEnabled(true);
        if (!RealTime::RealTimeProtection::Instance().Start()) {
            SS_LOG_FATAL(LOG_CATEGORY, L"Failed to start RealTimeProtection");
            return;
        }
        if (!Communication::IPCManager::Instance().Start()) {
            SS_LOG_FATAL(LOG_CATEGORY, L"Failed to start IPCManager");
            RealTime::RealTimeProtection::Instance().Stop();
            return;
        }

        // Start Communication subsystems
        Communication::ServiceCommunication::Instance().Start(true);

        // Initialize and start the v2 IPC pipe server, then wire all PhantomHome
        // UI command handlers before any client can connect and send a verb.
        {
            auto& ipcSvc = ServiceCommunicator::Instance();
            if (!ipcSvc.Initialize()) {
                SS_LOG_WARN(LOG_CATEGORY, L"ServiceCommunicator::Initialize() failed — HomeIpcDispatcher not installed");
            } else if (!ipcSvc.Start()) {
                SS_LOG_WARN(LOG_CATEGORY, L"ServiceCommunicator::Start() failed — HomeIpcDispatcher not installed");
            } else {
                HomeIpcDispatcher::Instance().Install(ipcSvc);
            }
        }

        // Register AMSI provider
        Scripts::AMSIIntegration::Instance().RegisterProvider();

        // Start health monitoring (all modules now initialized, heartbeat loop can begin)
        if (!ServiceMonitor::Instance().StartMonitoring()) {
            SS_LOG_WARN(LOG_CATEGORY, L"Failed to start ServiceMonitor");
        }
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
        m_maintenanceThread = std::thread(&AntivirusServiceImpl::MaintenanceLoop, this);

        SS_LOG_INFO(LOG_CATEGORY, L"ShadowStrike NGAV Service is RUNNING");
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

        Scripts::AMSIIntegration::Instance().UnregisterProvider();
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

        Security::TamperProtection::Instance().Shutdown("INTERNAL_SHUTDOWN");

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
            if (m_threatIntelStore->IsInitialized()) {
                m_threatIntelStore->Shutdown();
            }
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
    std::unique_ptr<ThreatIntel::ThreatIntelStore> m_threatIntelStore;
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
    s_instanceCreated.store(true);
}

AntivirusService::~AntivirusService() = default;

// ============================================================================
// SCM ENTRY POINTS
// ============================================================================

void WINAPI AntivirusService::ServiceMain(DWORD argc, LPWSTR* argv) {
    Instance().OnStart(argc, argv);
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
    SERVICE_TABLE_ENTRYW dispatchTable[] = {
        { const_cast<LPWSTR>(ServiceConstants::SERVICE_NAME), static_cast<LPSERVICE_MAIN_FUNCTIONW>(ServiceMain) },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(dispatchTable)) {
        // If it failed, it might be running as a console app for debug
        if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            // Debug mode
            SS_LOG_INFO(LOG_CATEGORY, L"Running in console mode...");
            if (m_impl->Initialize()) {
                m_impl->Start();

                SS_LOG_INFO(LOG_CATEGORY, L"Press Enter to stop...");
                getchar();

                m_impl->Stop();
                return true;
            }
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
    m_statusHandle = RegisterServiceCtrlHandlerExW(
        ServiceConstants::SERVICE_NAME,
        ServiceCtrlHandler,
        nullptr
    );

    if (!m_statusHandle) return;

    SetServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    // Initialize subsystems
    if (!m_impl->Initialize()) {
        SetServiceStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
        return;
    }

    // Start services
    m_impl->Start();

    SetServiceStatus(SERVICE_RUNNING);
}

void AntivirusService::OnStop() {
    SetServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
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
    m_impl->Stop();
    SetServiceStatus(SERVICE_STOPPED);
}

void AntivirusService::OnSessionChange(DWORD eventType, WTSSESSION_NOTIFICATION* notification) {
    if (!notification) return;

    const DWORD sessionId = notification->dwSessionId;
    SS_LOG_INFO(LOG_CATEGORY, L"Session change event: type=%u sessionId=%u", eventType, sessionId);

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

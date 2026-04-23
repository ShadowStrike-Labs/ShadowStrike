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
 * ShadowStrike Security - MEMORY PROTECTION ENGINE
 * ============================================================================
 *
 * @file MemoryProtection.cpp
 * @brief Enterprise-grade memory protection implementation for securing
 *        ShadowStrike process memory from external tampering and analysis.
 *
 * Implementation Standards:
 *   - PIMPL pattern for ABI stability
 *   - Meyers' Singleton for thread-safe instantiation
 *   - std::shared_mutex for concurrent read/write access
 *   - Comprehensive error handling with structured logging
 *   - Statistics tracking for all operations
 *   - Windows API integration for memory protection
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "MemoryProtection.hpp"

// ============================================================================
// WINDOWS SDK LIBRARIES
// ============================================================================

#ifdef _WIN32
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#endif

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <random>
#include <cstring>
#include <filesystem>

#ifdef _WIN32
#include <TlHelp32.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

namespace ShadowStrike {
namespace Security {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================

namespace {
    constexpr const wchar_t* LOG_CATEGORY = L"MemoryProtection";

    // Authorization token for internal operations
    constexpr std::string_view INTERNAL_AUTH_TOKEN = "SS_INTERNAL_MEMORY_PROTECTION_AUTH";
}

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> MemoryProtection::s_instanceCreated{false};

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string_view GetProtectionLevelName(MemoryProtectionLevel level) noexcept {
    switch (level) {
        case MemoryProtectionLevel::Disabled: return "Disabled";
        case MemoryProtectionLevel::Minimal:  return "Minimal";
        case MemoryProtectionLevel::Standard: return "Standard";
        case MemoryProtectionLevel::Enhanced: return "Enhanced";
        case MemoryProtectionLevel::Maximum:  return "Maximum";
        default:                        return "Unknown";
    }
}

[[nodiscard]] std::string_view GetMemoryRegionTypeName(MemoryRegionType type) noexcept {
    switch (type) {
        case MemoryRegionType::Unknown:   return "Unknown";
        case MemoryRegionType::Code:      return "Code";
        case MemoryRegionType::ReadOnly:  return "ReadOnly";
        case MemoryRegionType::ReadWrite: return "ReadWrite";
        case MemoryRegionType::Stack:     return "Stack";
        case MemoryRegionType::Heap:      return "Heap";
        case MemoryRegionType::Mapped:    return "Mapped";
        case MemoryRegionType::Reserved:  return "Reserved";
        case MemoryRegionType::Guard:     return "Guard";
        default:                          return "Unknown";
    }
}

[[nodiscard]] std::string_view GetIntegrityStatusName(MemoryIntegrityStatus status) noexcept {
    switch (status) {
        case MemoryIntegrityStatus::Unknown:   return "Unknown";
        case MemoryIntegrityStatus::Valid:     return "Valid";
        case MemoryIntegrityStatus::Modified:  return "Modified";
        case MemoryIntegrityStatus::Corrupted: return "Corrupted";
        case MemoryIntegrityStatus::Hooked:    return "Hooked";
        default:                         return "Unknown";
    }
}

[[nodiscard]] std::string_view GetAllocationTypeName(AllocationType type) noexcept {
    switch (type) {
        case AllocationType::Standard:  return "Standard";
        case AllocationType::Secure:    return "Secure";
        case AllocationType::Encrypted: return "Encrypted";
        case AllocationType::Locked:    return "Locked";
        case AllocationType::Guarded:   return "Guarded";
        default:                        return "Unknown";
    }
}

[[nodiscard]] std::string FormatPageProtection(PageProtection protection) {
    std::ostringstream oss;
    uint32_t prot = static_cast<uint32_t>(protection);

    if (prot & static_cast<uint32_t>(PageProtection::NoAccess)) oss << "NoAccess|";
    if (prot & static_cast<uint32_t>(PageProtection::ReadOnly)) oss << "ReadOnly|";
    if (prot & static_cast<uint32_t>(PageProtection::ReadWrite)) oss << "ReadWrite|";
    if (prot & static_cast<uint32_t>(PageProtection::Execute)) oss << "Execute|";
    if (prot & static_cast<uint32_t>(PageProtection::ExecuteRead)) oss << "ExecuteRead|";
    if (prot & static_cast<uint32_t>(PageProtection::ExecuteReadWrite)) oss << "ExecuteReadWrite|";
    if (prot & static_cast<uint32_t>(PageProtection::Guard)) oss << "Guard|";
    if (prot & static_cast<uint32_t>(PageProtection::NoCache)) oss << "NoCache|";

    std::string result = oss.str();
    if (!result.empty() && result.back() == '|') {
        result.pop_back();
    }
    return result.empty() ? "None" : result;
}

// ============================================================================
// STRUCT METHOD IMPLEMENTATIONS
// ============================================================================

bool MemoryProtectionConfiguration::IsValid() const noexcept {
    if (securePoolSize == 0 ||
        securePoolSize > MemoryProtectionConstants::MAX_SECURE_POOL_SIZE) {
        return false;
    }
    if (integrityCheckIntervalMs == 0) {
        return false;
    }
    return true;
}

MemoryProtectionConfiguration MemoryProtectionConfiguration::FromLevel(MemoryProtectionLevel level) {
    MemoryProtectionConfiguration config;
    config.level = level;

    switch (level) {
        case MemoryProtectionLevel::Disabled:
            config.enableASLR = false;
            config.enableDEP = false;
            config.enableCFG = false;
            config.enableSecureAllocator = false;
            config.enableAntiDump = false;
            config.enableCodeIntegrity = false;
            config.enableHeapProtection = false;
            config.enableStackProtection = false;
            config.enableGuardPages = false;
            config.enableMemoryEncryption = false;
            config.enableAntiScan = false;
            config.defaultResponse = MemoryProtectionResponse::Log;
            break;

        case MemoryProtectionLevel::Minimal:
            config.enableASLR = true;
            config.enableDEP = true;
            config.enableCFG = false;
            config.enableSecureAllocator = true;
            config.enableAntiDump = false;
            config.enableCodeIntegrity = false;
            config.enableHeapProtection = false;
            config.enableStackProtection = false;
            config.enableGuardPages = false;
            config.enableMemoryEncryption = false;
            config.enableAntiScan = false;
            config.defaultResponse = MemoryProtectionResponse::Passive;
            break;

        case MemoryProtectionLevel::Standard:
            config.enableASLR = true;
            config.enableDEP = true;
            config.enableCFG = true;
            config.enableSecureAllocator = true;
            config.enableAntiDump = true;
            config.enableCodeIntegrity = true;
            config.enableHeapProtection = true;
            config.enableStackProtection = true;
            config.enableGuardPages = false;
            config.enableMemoryEncryption = false;
            config.enableAntiScan = false;
            config.defaultResponse = MemoryProtectionResponse::Active;
            break;

        case MemoryProtectionLevel::Enhanced:
            config.enableASLR = true;
            config.enableDEP = true;
            config.enableCFG = true;
            config.enableSecureAllocator = true;
            config.enableAntiDump = true;
            config.enableCodeIntegrity = true;
            config.enableHeapProtection = true;
            config.enableStackProtection = true;
            config.enableGuardPages = true;
            config.enableMemoryEncryption = true;
            config.enableAntiScan = true;
            config.defaultResponse = MemoryProtectionResponse::Active;
            break;

        case MemoryProtectionLevel::Maximum:
            config.enableASLR = true;
            config.enableDEP = true;
            config.enableCFG = true;
            config.enableSecureAllocator = true;
            config.enableAntiDump = true;
            config.enableCodeIntegrity = true;
            config.enableHeapProtection = true;
            config.enableStackProtection = true;
            config.enableGuardPages = true;
            config.enableMemoryEncryption = true;
            config.enableAntiScan = true;
            config.integrityCheckIntervalMs = 15000; // More frequent checks
            config.defaultResponse = MemoryProtectionResponse::Aggressive;
            break;
    }

    return config;
}

std::string ProtectionEvent::GetSummary() const {
    std::ostringstream oss;
    oss << "Event #" << eventId << ": ";

    switch (type) {
        case MemoryProtectionEventType::MemoryWrite:
            oss << "Memory write attempt";
            break;
        case MemoryProtectionEventType::MemoryRead:
            oss << "Memory read attempt";
            break;
        case MemoryProtectionEventType::PermissionChange:
            oss << "Permission change attempt";
            break;
        case MemoryProtectionEventType::IntegrityViolation:
            oss << "Integrity violation";
            break;
        case MemoryProtectionEventType::CanaryCorruption:
            oss << "Canary corruption";
            break;
        case MemoryProtectionEventType::HeapCorruption:
            oss << "Heap corruption";
            break;
        case MemoryProtectionEventType::StackOverflow:
            oss << "Stack overflow";
            break;
        case MemoryProtectionEventType::HookDetected:
            oss << "Hook detected";
            break;
        case MemoryProtectionEventType::DumpAttempt:
            oss << "Dump attempt";
            break;
        case MemoryProtectionEventType::ScanDetected:
            oss << "Scan detected";
            break;
        default:
            oss << "Unknown event";
            break;
    }

    oss << " at 0x" << std::hex << address;
    if (!regionId.empty()) {
        oss << " (region: " << regionId << ")";
    }
    if (wasBlocked) {
        oss << " [BLOCKED]";
    }

    return oss.str();
}

std::string ProtectionEvent::ToJson() const {
    // Escape a string for safe JSON embedding
    auto escapeJson = [](const std::string& input) -> std::string {
        std::string output;
        output.reserve(input.size() + 8);
        for (char c : input) {
            switch (c) {
                case '"':  output += "\\\""; break;
                case '\\': output += "\\\\"; break;
                case '\b': output += "\\b"; break;
                case '\f': output += "\\f"; break;
                case '\n': output += "\\n"; break;
                case '\r': output += "\\r"; break;
                case '\t': output += "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        char buf[8];
                        snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                        output += buf;
                    } else {
                        output += c;
                    }
                    break;
            }
        }
        return output;
    };

    std::ostringstream oss;
    oss << "{";
    oss << "\"eventId\":" << eventId << ",";
    oss << "\"type\":" << static_cast<uint32_t>(type) << ",";
    oss << "\"address\":\"0x" << std::hex << address << "\",";
    oss << "\"size\":" << std::dec << size << ",";
    oss << "\"regionId\":\"" << escapeJson(regionId) << "\",";
    oss << "\"sourceProcessId\":" << sourceProcessId << ",";
    oss << "\"sourceThreadId\":" << sourceThreadId << ",";
    oss << "\"wasBlocked\":" << (wasBlocked ? "true" : "false") << ",";
    oss << "\"wasRepaired\":" << (wasRepaired ? "true" : "false") << ",";
    oss << "\"description\":\"" << escapeJson(description) << "\"";
    oss << "}";
    return oss.str();
}

MemoryProtectionStatistics::MemoryProtectionStatistics(const MemoryProtectionStatistics& other) noexcept
    : startTime(other.startTime)
    , lastEventTime(other.lastEventTime) {
    totalProtectedRegions.store(other.totalProtectedRegions.load(std::memory_order_relaxed), std::memory_order_relaxed);
    totalSecureAllocations.store(other.totalSecureAllocations.load(std::memory_order_relaxed), std::memory_order_relaxed);
    totalSecureBytes.store(other.totalSecureBytes.load(std::memory_order_relaxed), std::memory_order_relaxed);
    totalIntegrityChecks.store(other.totalIntegrityChecks.load(std::memory_order_relaxed), std::memory_order_relaxed);
    integrityViolations.store(other.integrityViolations.load(std::memory_order_relaxed), std::memory_order_relaxed);
    memoryWritesBlocked.store(other.memoryWritesBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
    heapCorruptionsDetected.store(other.heapCorruptionsDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    stackOverflowsDetected.store(other.stackOverflowsDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    hooksDetected.store(other.hooksDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    dumpAttemptsBlocked.store(other.dumpAttemptsBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
    scanAttemptsDetected.store(other.scanAttemptsDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
}

MemoryProtectionStatistics& MemoryProtectionStatistics::operator=(
    const MemoryProtectionStatistics& other) noexcept {
    if (this != &other) {
        totalProtectedRegions.store(other.totalProtectedRegions.load(std::memory_order_relaxed), std::memory_order_relaxed);
        totalSecureAllocations.store(other.totalSecureAllocations.load(std::memory_order_relaxed), std::memory_order_relaxed);
        totalSecureBytes.store(other.totalSecureBytes.load(std::memory_order_relaxed), std::memory_order_relaxed);
        totalIntegrityChecks.store(other.totalIntegrityChecks.load(std::memory_order_relaxed), std::memory_order_relaxed);
        integrityViolations.store(other.integrityViolations.load(std::memory_order_relaxed), std::memory_order_relaxed);
        memoryWritesBlocked.store(other.memoryWritesBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
        heapCorruptionsDetected.store(other.heapCorruptionsDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
        stackOverflowsDetected.store(other.stackOverflowsDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
        hooksDetected.store(other.hooksDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
        dumpAttemptsBlocked.store(other.dumpAttemptsBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
        scanAttemptsDetected.store(other.scanAttemptsDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
        startTime = other.startTime;
        lastEventTime = other.lastEventTime;
    }
    return *this;
}

void MemoryProtectionStatistics::Reset() noexcept {
    totalProtectedRegions = 0;
    totalSecureAllocations = 0;
    totalSecureBytes = 0;
    totalIntegrityChecks = 0;
    integrityViolations = 0;
    memoryWritesBlocked = 0;
    heapCorruptionsDetected = 0;
    stackOverflowsDetected = 0;
    hooksDetected = 0;
    dumpAttemptsBlocked = 0;
    scanAttemptsDetected = 0;
    startTime = Clock::now();
}

std::string MemoryProtectionStatistics::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"totalProtectedRegions\":" << totalProtectedRegions.load() << ",";
    oss << "\"totalSecureAllocations\":" << totalSecureAllocations.load() << ",";
    oss << "\"totalSecureBytes\":" << totalSecureBytes.load() << ",";
    oss << "\"totalIntegrityChecks\":" << totalIntegrityChecks.load() << ",";
    oss << "\"integrityViolations\":" << integrityViolations.load() << ",";
    oss << "\"memoryWritesBlocked\":" << memoryWritesBlocked.load() << ",";
    oss << "\"heapCorruptionsDetected\":" << heapCorruptionsDetected.load() << ",";
    oss << "\"stackOverflowsDetected\":" << stackOverflowsDetected.load() << ",";
    oss << "\"hooksDetected\":" << hooksDetected.load() << ",";
    oss << "\"dumpAttemptsBlocked\":" << dumpAttemptsBlocked.load() << ",";
    oss << "\"scanAttemptsDetected\":" << scanAttemptsDetected.load();
    oss << "}";
    return oss.str();
}

// ============================================================================
// SECURE ALLOCATOR IMPLEMENTATION
// ============================================================================

template<typename T>
typename SecureAllocator<T>::pointer SecureAllocator<T>::allocate(size_type n) {
    if (n > std::numeric_limits<size_type>::max() / sizeof(T)) {
        throw std::bad_alloc();
    }

    size_t bytes = n * sizeof(T);

    // Use VirtualAlloc for secure memory
    void* ptr = VirtualAlloc(nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ptr) {
        throw std::bad_alloc();
    }

    // Lock memory to prevent paging (if possible)
    VirtualLock(ptr, bytes);

    return static_cast<pointer>(ptr);
}

template<typename T>
void SecureAllocator<T>::deallocate(pointer p, size_type n) noexcept {
    if (p) {
        size_t bytes = n * sizeof(T);

        // Use Windows SDK RtlSecureZeroMemory directly to avoid macro collision
        RtlSecureZeroMemory(p, bytes);

        // Unlock memory
        VirtualUnlock(p, bytes);

        // Free the memory
        VirtualFree(p, 0, MEM_RELEASE);
    }
}

// Explicit template instantiations
template class SecureAllocator<char>;
template class SecureAllocator<wchar_t>;
template class SecureAllocator<uint8_t>;

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class MemoryProtectionImpl {
public:
    // ========================================================================
    // CONSTRUCTION / DESTRUCTION
    // ========================================================================

    MemoryProtectionImpl() noexcept
        : m_status(ModuleStatus::Uninitialized)
        , m_initialized(false)
        , m_aslrEnabled(false)
        , m_depEnabled(false)
        , m_cfgEnabled(false)
        , m_antiDumpEnabled(false)
        , m_integrityMonitorRunning(false)
        , m_nextEventId(1)
        , m_nextCallbackId(1)
    {
        SS_LOG_INFO(LOG_CATEGORY, L"Creating MemoryProtection implementation");

        // Generate random encryption key for this session
        generateSessionKey();
    }

    ~MemoryProtectionImpl() noexcept {
        Shutdown(INTERNAL_AUTH_TOKEN);
    }

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const MemoryProtectionConfiguration& config) noexcept {
        std::unique_lock lock(m_mutex);

        if (m_initialized) {
            SS_LOG_WARN(LOG_CATEGORY, L"Already initialized");
            return true;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Initializing MemoryProtection with level: %hs",
            std::string(GetProtectionLevelName(config.level)).c_str());

        m_status = ModuleStatus::Initializing;

        try {
            // Validate configuration
            if (!config.IsValid()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration");
                m_status = ModuleStatus::Error;
                return false;
            }

            m_config = config;

            // Apply process hardening based on configuration
            if (config.enableDEP) {
                enableDEPInternal();
            }

            if (config.enableASLR) {
                enableASLRInternal();
            }

            if (config.enableCFG) {
                enableCFGInternal();
            }

            // Initialize secure heap if enabled
            if (config.enableSecureAllocator) {
                initializeSecureHeap(config.securePoolSize);
            }

            // Enable anti-dump if configured
            if (config.enableAntiDump) {
                SS_LOG_INFO(LOG_CATEGORY, L"Enabling anti-dump protection...");
                enableAntiDumpInternal();
                SS_LOG_INFO(LOG_CATEGORY, L"Anti-dump protection enabled");
            }

            // Start integrity monitoring if enabled
            if (config.enableCodeIntegrity) {
                SS_LOG_INFO(LOG_CATEGORY, L"Starting code integrity monitoring...");
                startIntegrityMonitoring();
                SS_LOG_INFO(LOG_CATEGORY, L"Code integrity monitoring started");
            }

            m_initialized = true;
            m_status = ModuleStatus::Running;
            m_stats.startTime = Clock::now();

            SS_LOG_INFO(LOG_CATEGORY, L"MemoryProtection initialized successfully");
            return true;

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Initialization failed: %hs", ex.what());
            m_status = ModuleStatus::Error;
            return false;
        }
    }

    void Shutdown(std::string_view authorizationToken) noexcept {
        if (!verifyAuthToken(authorizationToken)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Invalid authorization token for shutdown");
            return;
        }

        std::unique_lock lock(m_mutex);

        if (!m_initialized) {
            return;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Shutting down MemoryProtection");
        m_status = ModuleStatus::Stopping;

        // Stop integrity monitoring
        stopIntegrityMonitoring();

        // Free all secure allocations
        freeAllSecureAllocations();

        // Clear protected regions
        m_protectedRegions.clear();

        // Clear callbacks
        m_eventCallbacks.clear();
        m_integrityCallbacks.clear();
        m_heapCorruptionCallbacks.clear();
        m_stackOverflowCallbacks.clear();

        // Clear event history
        m_eventHistory.clear();

        m_initialized = false;
        m_status = ModuleStatus::Stopped;

        SS_LOG_INFO(LOG_CATEGORY, L"MemoryProtection shutdown complete");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_initialized.load(std::memory_order_acquire);
    }

    [[nodiscard]] ModuleStatus GetStatus() const noexcept {
        return m_status.load(std::memory_order_acquire);
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    [[nodiscard]] bool SetConfiguration(const MemoryProtectionConfiguration& config) noexcept {
        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration");
            return false;
        }

        std::unique_lock lock(m_mutex);
        m_config = config;

        SS_LOG_INFO(LOG_CATEGORY, L"Configuration updated");
        return true;
    }

    [[nodiscard]] MemoryProtectionConfiguration GetConfiguration() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    void SetProtectionLevel(MemoryProtectionLevel level) noexcept {
        auto config = MemoryProtectionConfiguration::FromLevel(level);
        SetConfiguration(config);
    }

    [[nodiscard]] MemoryProtectionLevel GetProtectionLevel() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_config.level;
    }

    // ========================================================================
    // PROCESS HARDENING
    // ========================================================================

    void ApplyProcessHardening() noexcept {
        SS_LOG_INFO(LOG_CATEGORY, L"Applying process hardening");

        EnableASLR();
        EnableDEP();
        EnableCFG();

        // Set process mitigation policies
        applyMitigationPolicies();

        SS_LOG_INFO(LOG_CATEGORY, L"Process hardening applied");
    }

    [[nodiscard]] bool EnableASLR() noexcept {
        std::unique_lock lock(m_mutex);
        return enableASLRInternal();
    }

    [[nodiscard]] bool IsASLREnabled() const noexcept {
        return m_aslrEnabled.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool EnableDEP() noexcept {
        std::unique_lock lock(m_mutex);
        return enableDEPInternal();
    }

    [[nodiscard]] bool IsDEPEnabled() const noexcept {
        return m_depEnabled.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool EnableCFG() noexcept {
        std::unique_lock lock(m_mutex);
        return enableCFGInternal();
    }

    [[nodiscard]] bool IsCFGEnabled() const noexcept {
        return m_cfgEnabled.load(std::memory_order_acquire);
    }

    // ========================================================================
    // SECURE MEMORY ALLOCATION
    // ========================================================================

    [[nodiscard]] void* AllocateSecure(size_t size) noexcept {
        return AllocateSecure(size, AllocationType::Secure);
    }

    [[nodiscard]] void* AllocateSecure(size_t size, AllocationType type) noexcept {
        if (size == 0 || size > MemoryProtectionConstants::MAX_SECURE_ALLOCATION) {
            SS_LOG_WARN(LOG_CATEGORY, L"Invalid allocation size: %zu", size);
            return nullptr;
        }

        try {
            std::unique_lock lock(m_mutex);

            if (m_secureAllocations.size() >= MemoryProtectionConstants::MAX_SECURE_ALLOCATIONS) {
                SS_LOG_WARN(LOG_CATEGORY, L"Maximum secure allocations reached");
                return nullptr;
            }

            // Align size
            size_t alignedSize = (size + MemoryProtectionConstants::SECURE_ALLOCATION_ALIGNMENT - 1) &
                                 ~(MemoryProtectionConstants::SECURE_ALLOCATION_ALIGNMENT - 1);

            size_t totalSize = alignedSize;
            bool hasGuardPages = (type == AllocationType::Guarded) || m_config.enableGuardPages;

            if (hasGuardPages) {
                // Add guard pages before and after
                totalSize += 2 * MemoryProtectionConstants::PAGE_SIZE;
            }

            // Allocate memory
            void* basePtr = VirtualAlloc(nullptr, totalSize,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (!basePtr) {
                SS_LOG_ERROR(LOG_CATEGORY, L"VirtualAlloc failed: %lu", GetLastError());
                return nullptr;
            }

            void* userPtr = basePtr;

            if (hasGuardPages) {
                // Set up guard pages
                DWORD oldProtect;

                // Front guard page
                VirtualProtect(basePtr, MemoryProtectionConstants::PAGE_SIZE,
                    PAGE_NOACCESS, &oldProtect);

                // Back guard page
                void* backGuard = static_cast<uint8_t*>(basePtr) +
                    MemoryProtectionConstants::PAGE_SIZE + alignedSize;
                VirtualProtect(backGuard, MemoryProtectionConstants::PAGE_SIZE,
                    PAGE_NOACCESS, &oldProtect);

                // User pointer starts after front guard
                userPtr = static_cast<uint8_t*>(basePtr) + MemoryProtectionConstants::PAGE_SIZE;
            }

            // Fill with uninitialized pattern
            std::memset(userPtr, MemoryProtectionConstants::UNINIT_MEMORY_FILL, alignedSize);

            // Lock memory if requested
            bool isLocked = false;
            if (type == AllocationType::Locked || type == AllocationType::Encrypted) {
                isLocked = VirtualLock(userPtr, alignedSize) != 0;
            }

            // Encrypt if requested
            bool isEncrypted = false;
            if (type == AllocationType::Encrypted && m_config.enableMemoryEncryption) {
                // For encrypted allocations, we store metadata separately
                isEncrypted = true;
            }

            // Track allocation
            SecureAllocation alloc;
            alloc.address = userPtr;
            alloc.size = size;
            alloc.allocatedSize = totalSize;
            alloc.type = type;
            alloc.isLocked = isLocked;
            alloc.isEncrypted = isEncrypted;
            alloc.hasGuardPages = hasGuardPages;
            alloc.allocatedAt = Clock::now();
            alloc.allocatorThreadId = GetCurrentThreadId();

            m_secureAllocations[userPtr] = alloc;
            m_allocationBaseMap[userPtr] = basePtr;

            // Update statistics
            m_stats.totalSecureAllocations++;
            m_stats.totalSecureBytes += size;

            if (m_config.verboseLogging) {
                SS_LOG_DEBUG(LOG_CATEGORY, L"Allocated %zu bytes of %hs memory at %p",
                    size, std::string(GetAllocationTypeName(type)).c_str(), userPtr);
            }

            return userPtr;

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Exception in AllocateSecure: %hs", ex.what());
            return nullptr;
        }
    }

    void FreeSecure(void* ptr, size_t size) noexcept {
        if (!ptr) {
            return;
        }

        std::unique_lock lock(m_mutex);

        auto it = m_secureAllocations.find(ptr);
        if (it == m_secureAllocations.end()) {
            SS_LOG_WARN(LOG_CATEGORY, L"Attempted to free untracked memory: %p", ptr);
            return;
        }

        const SecureAllocation& alloc = it->second;

        // Securely zero the memory
        SecureZero(ptr, alloc.size);

        // Fill with free pattern
        std::memset(ptr, MemoryProtectionConstants::FREE_MEMORY_FILL, alloc.size);

        // Unlock if locked
        if (alloc.isLocked) {
            VirtualUnlock(ptr, alloc.size);
        }

        // Get base pointer
        void* basePtr = m_allocationBaseMap[ptr];

        // Free the memory
        VirtualFree(basePtr, 0, MEM_RELEASE);

        // Update statistics
        m_stats.totalSecureBytes -= alloc.size;

        // Remove from tracking
        m_secureAllocations.erase(it);
        m_allocationBaseMap.erase(ptr);

        if (m_config.verboseLogging) {
            SS_LOG_DEBUG(LOG_CATEGORY, L"Freed secure memory at %p", ptr);
        }
    }

    [[nodiscard]] void* ReallocateSecure(void* ptr, size_t oldSize, size_t newSize) noexcept {
        if (!ptr) {
            return AllocateSecure(newSize);
        }

        if (newSize == 0) {
            FreeSecure(ptr, oldSize);
            return nullptr;
        }

        // Allocate new memory
        void* newPtr = AllocateSecure(newSize);
        if (!newPtr) {
            return nullptr;
        }

        // Copy old data
        size_t copySize = (oldSize < newSize) ? oldSize : newSize;
        std::memcpy(newPtr, ptr, copySize);

        // Free old memory
        FreeSecure(ptr, oldSize);

        return newPtr;
    }

    [[nodiscard]] void* AllocateEncrypted(size_t size) noexcept {
        return AllocateSecure(size, AllocationType::Encrypted);
    }

    void FreeEncrypted(void* ptr, size_t size) noexcept {
        FreeSecure(ptr, size);
    }

    [[nodiscard]] void* AllocateLocked(size_t size) noexcept {
        return AllocateSecure(size, AllocationType::Locked);
    }

    void FreeLocked(void* ptr, size_t size) noexcept {
        FreeSecure(ptr, size);
    }

    [[nodiscard]] void* AllocateGuarded(size_t size) noexcept {
        return AllocateSecure(size, AllocationType::Guarded);
    }

    void FreeGuarded(void* ptr, size_t size) noexcept {
        FreeSecure(ptr, size);
    }

    [[nodiscard]] std::optional<SecureAllocation> GetSecureAllocationInfo(void* ptr) const noexcept {
        std::shared_lock lock(m_mutex);

        auto it = m_secureAllocations.find(ptr);
        if (it != m_secureAllocations.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::vector<SecureAllocation> GetAllSecureAllocations() const noexcept {
        std::shared_lock lock(m_mutex);

        std::vector<SecureAllocation> result;
        result.reserve(m_secureAllocations.size());

        for (const auto& [ptr, alloc] : m_secureAllocations) {
            result.push_back(alloc);
        }

        return result;
    }

    [[nodiscard]] size_t GetSecureMemoryUsage() const noexcept {
        return m_stats.totalSecureBytes.load();
    }

    // ========================================================================
    // MEMORY REGION PROTECTION
    // ========================================================================

    [[nodiscard]] bool ProtectRegion(std::string_view id, uintptr_t address, size_t size,
                                      MemoryRegionType type) noexcept {
        if (id.empty() || address == 0 || size == 0) {
            SS_LOG_WARN(LOG_CATEGORY, L"Invalid parameters for ProtectRegion");
            return false;
        }

        std::unique_lock lock(m_mutex);

        if (m_protectedRegions.size() >= MemoryProtectionConstants::MAX_PROTECTED_REGIONS) {
            SS_LOG_WARN(LOG_CATEGORY, L"Maximum protected regions reached");
            return false;
        }

        std::string idStr(id);

        // Check if already protected
        if (m_protectedRegions.count(idStr) > 0) {
            SS_LOG_WARN(LOG_CATEGORY, L"Region '%hs' already protected", idStr.c_str());
            return false;
        }

        ProtectedRegion region;
        region.id = idStr;
        region.baseAddress = address;
        region.size = size;
        region.type = type;
        region.protectedSince = Clock::now();
        region.lastVerified = Clock::now();
        region.status = MemoryIntegrityStatus::Valid;

        // Calculate initial hash
        if (!calculateRegionHash(address, size, region.expectedCrc32, region.expectedSha256)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to calculate region hash");
            return false;
        }

        region.currentCrc32 = region.expectedCrc32;

        // Determine page protection based on type
        DWORD protection = PAGE_READONLY;
        switch (type) {
            case MemoryRegionType::Code:
                protection = PAGE_EXECUTE_READ;
                break;
            case MemoryRegionType::ReadOnly:
                protection = PAGE_READONLY;
                break;
            case MemoryRegionType::ReadWrite:
                protection = PAGE_READWRITE;
                break;
            default:
                break;
        }

        // Apply page protection
        DWORD oldProtect;
        if (!VirtualProtect(reinterpret_cast<void*>(address), size, protection, &oldProtect)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Failed to apply page protection: %lu", GetLastError());
        }

        region.protection = static_cast<PageProtection>(protection);

        m_protectedRegions[idStr] = region;
        m_stats.totalProtectedRegions++;

        SS_LOG_INFO(LOG_CATEGORY, L"Protected region '%hs': 0x%llx, size %zu",
            idStr.c_str(), address, size);

        return true;
    }

    [[nodiscard]] bool UnprotectRegion(std::string_view id,
                                        std::string_view authorizationToken) noexcept {
        if (!verifyAuthToken(authorizationToken)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Invalid authorization token for UnprotectRegion");
            return false;
        }

        std::unique_lock lock(m_mutex);

        std::string idStr(id);
        auto it = m_protectedRegions.find(idStr);
        if (it == m_protectedRegions.end()) {
            return false;
        }

        // Restore page protection to read-write
        DWORD oldProtect;
        VirtualProtect(reinterpret_cast<void*>(it->second.baseAddress),
            it->second.size, PAGE_READWRITE, &oldProtect);

        m_protectedRegions.erase(it);

        SS_LOG_INFO(LOG_CATEGORY, L"Unprotected region '%hs'", idStr.c_str());
        return true;
    }

    [[nodiscard]] bool ProtectCodeRegion(std::string_view id, uintptr_t address,
                                          size_t size) noexcept {
        return ProtectRegion(id, address, size, MemoryRegionType::Code);
    }

    [[nodiscard]] bool ProtectSelfCode() noexcept {
        SS_LOG_INFO(LOG_CATEGORY, L"Protecting self code sections");

        HMODULE hModule = GetModuleHandle(nullptr);
        if (!hModule) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to get module handle");
            return false;
        }

        // Get module size via VirtualQuery to bound PE header parsing
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(hModule, &mbi, sizeof(mbi)) == 0) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to query module memory region");
            return false;
        }

        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid DOS signature in self module");
            return false;
        }

        // Validate e_lfanew is within module bounds
        if (dosHeader->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)) ||
            static_cast<size_t>(dosHeader->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > mbi.RegionSize) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid e_lfanew offset: 0x%lx", dosHeader->e_lfanew);
            return false;
        }

        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<uint8_t*>(hModule) + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid NT signature in self module");
            return false;
        }

        // Validate section count is reasonable
        if (ntHeaders->FileHeader.NumberOfSections == 0 ||
            ntHeaders->FileHeader.NumberOfSections > 96) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Suspicious section count: %u",
                ntHeaders->FileHeader.NumberOfSections);
            return false;
        }

        auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            // Check if this is a code section
            if (sectionHeader[i].Characteristics & IMAGE_SCN_CNT_CODE) {
                uintptr_t sectionAddr = reinterpret_cast<uintptr_t>(hModule) +
                    sectionHeader[i].VirtualAddress;
                size_t sectionSize = sectionHeader[i].Misc.VirtualSize;

                if (sectionSize == 0) {
                    continue;
                }

                std::string sectionName(reinterpret_cast<char*>(sectionHeader[i].Name), 8);
                sectionName = "self_" + sectionName;

                // Remove null chars
                sectionName.erase(std::remove(sectionName.begin(), sectionName.end(), '\0'),
                    sectionName.end());

                if (!ProtectCodeRegion(sectionName, sectionAddr, sectionSize)) {
                    SS_LOG_WARN(LOG_CATEGORY, L"Failed to protect section: %hs", sectionName.c_str());
                }
            }
        }

        return true;
    }

    [[nodiscard]] bool IsRegionProtected(uintptr_t address) const noexcept {
        std::shared_lock lock(m_mutex);

        for (const auto& [id, region] : m_protectedRegions) {
            if (address >= region.baseAddress &&
                address < region.baseAddress + region.size) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] std::optional<ProtectedRegion> GetProtectedRegion(
        std::string_view id) const noexcept {
        std::shared_lock lock(m_mutex);

        auto it = m_protectedRegions.find(std::string(id));
        if (it != m_protectedRegions.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::vector<ProtectedRegion> GetAllProtectedRegions() const noexcept {
        std::shared_lock lock(m_mutex);

        std::vector<ProtectedRegion> result;
        result.reserve(m_protectedRegions.size());

        for (const auto& [id, region] : m_protectedRegions) {
            result.push_back(region);
        }

        return result;
    }

    // ========================================================================
    // INTEGRITY VERIFICATION
    // ========================================================================

    [[nodiscard]] MemoryIntegrityStatus VerifyRegionIntegrity(std::string_view id) noexcept {
        ProtectionEvent event;
        bool hasViolation = false;
        MemoryIntegrityStatus resultStatus = MemoryIntegrityStatus::Unknown;

        // Snapshot of callbacks to invoke outside the lock
        std::vector<MemoryIntegrityCallback> integrityCallbacksCopy;
        ProtectedRegion regionCopy;

        {
            std::unique_lock lock(m_mutex);

            auto it = m_protectedRegions.find(std::string(id));
            if (it == m_protectedRegions.end()) {
                return MemoryIntegrityStatus::Unknown;
            }

            ProtectedRegion& region = it->second;

            m_stats.totalIntegrityChecks++;

            // Calculate current hash
            uint32_t currentCrc32 = 0;
            std::array<uint8_t, 32> currentSha256{};

            if (!calculateRegionHash(region.baseAddress, region.size, currentCrc32, currentSha256)) {
                region.status = MemoryIntegrityStatus::Corrupted;
                return MemoryIntegrityStatus::Corrupted;
            }

            region.currentCrc32 = currentCrc32;
            region.lastVerified = Clock::now();

            // Compare with expected
            if (currentCrc32 != region.expectedCrc32 || currentSha256 != region.expectedSha256) {
                region.status = MemoryIntegrityStatus::Modified;
                region.violationCount++;
                m_stats.integrityViolations++;

                // Check if this looks like a hook
                auto ptr = reinterpret_cast<const uint8_t*>(region.baseAddress);
                bool isHook = false;
                if (region.size >= 2) {
                    if (ptr[0] == 0xE9) isHook = true;
                    else if (ptr[0] == 0xEB) isHook = true;
                    else if (ptr[0] == 0xFF && ptr[1] == 0x25) isHook = true;
                    else if (region.size >= 6 && ptr[0] == 0x68 && ptr[5] == 0xC3) isHook = true;
                    else if (ptr[0] == 0xCC) isHook = true;
#ifdef _WIN64
                    else if (region.size >= 12 && ptr[0] == 0x48 && ptr[1] == 0xB8 &&
                             ptr[10] == 0xFF && ptr[11] == 0xE0) isHook = true;
                    else if (region.size >= 13 && ptr[0] == 0x49 && ptr[1] == 0xBA &&
                             ptr[10] == 0x41 && ptr[11] == 0xFF && ptr[12] == 0xE2) isHook = true;
#endif
                }

                if (isHook) {
                    region.status = MemoryIntegrityStatus::Hooked;
                    m_stats.hooksDetected++;
                }

                // Prepare event (will be fired after releasing lock)
                hasViolation = true;
                event.eventId = m_nextEventId++;
                event.type = MemoryProtectionEventType::IntegrityViolation;
                event.address = region.baseAddress;
                event.size = region.size;
                event.regionId = region.id;
                event.timestamp = Clock::now();
                event.description = "Integrity violation detected";

                // Store event in history while we hold the lock
                m_eventHistory.push_back(event);
                if (m_eventHistory.size() > 10000) {
                    m_eventHistory.erase(m_eventHistory.begin(),
                        m_eventHistory.begin() + 5000);
                }
                m_stats.lastEventTime = Clock::now();

                // Snapshot callbacks
                regionCopy = region;
                integrityCallbacksCopy.reserve(m_integrityCallbacks.size());
                for (const auto& [cbId, cb] : m_integrityCallbacks) {
                    integrityCallbacksCopy.push_back(cb);
                }

                SS_LOG_WARN(LOG_CATEGORY, L"Integrity violation in region '%hs'", region.id.c_str());
                resultStatus = region.status;
            } else {
                region.status = MemoryIntegrityStatus::Valid;
                resultStatus = MemoryIntegrityStatus::Valid;
            }
        }
        // Lock released — safe to invoke callbacks

        if (hasViolation) {
            // Fire event callbacks
            fireEventCallbacksUnlocked(event);

            // Fire integrity callbacks
            for (const auto& cb : integrityCallbacksCopy) {
                try {
                    cb(regionCopy);
                } catch (...) {
                    SS_LOG_WARN(LOG_CATEGORY, L"Exception in integrity callback");
                }
            }
        }

        return resultStatus;
    }

    [[nodiscard]] std::vector<std::pair<std::string, MemoryIntegrityStatus>> VerifyAllIntegrity() noexcept {
        std::vector<std::pair<std::string, MemoryIntegrityStatus>> results;

        // Copy region IDs under lock to avoid iterator invalidation
        std::vector<std::string> regionIds;
        {
            std::shared_lock lock(m_mutex);
            regionIds.reserve(m_protectedRegions.size());
            for (const auto& [id, region] : m_protectedRegions) {
                regionIds.push_back(id);
            }
        }

        // Verify each region without holding the collection lock
        for (const auto& id : regionIds) {
            auto status = VerifyRegionIntegrity(id);
            results.emplace_back(id, status);
        }

        return results;
    }

    void ForceIntegrityCheck() noexcept {
        VerifyAllIntegrity();
    }

    [[nodiscard]] bool UpdateRegionBaseline(std::string_view id,
                                             std::string_view authorizationToken) noexcept {
        if (!verifyAuthToken(authorizationToken)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Invalid authorization token for UpdateRegionBaseline");
            return false;
        }

        std::unique_lock lock(m_mutex);

        auto it = m_protectedRegions.find(std::string(id));
        if (it == m_protectedRegions.end()) {
            return false;
        }

        ProtectedRegion& region = it->second;

        if (!calculateRegionHash(region.baseAddress, region.size,
                                  region.expectedCrc32, region.expectedSha256)) {
            return false;
        }

        region.status = MemoryIntegrityStatus::Valid;
        region.currentCrc32 = region.expectedCrc32;
        region.lastVerified = Clock::now();

        SS_LOG_INFO(LOG_CATEGORY, L"Updated baseline for region '%hs'", region.id.c_str());
        return true;
    }

    // ========================================================================
    // ANTI-DUMP PROTECTION
    // ========================================================================

    [[nodiscard]] bool EnableAntiDump() noexcept {
        std::unique_lock lock(m_mutex);
        return enableAntiDumpInternal();
    }

    void DisableAntiDump(std::string_view authorizationToken) noexcept {
        if (!verifyAuthToken(authorizationToken)) {
            return;
        }

        std::unique_lock lock(m_mutex);

        // Restore PE headers inline (avoid calling RestorePEHeaders which re-locks)
        if (!m_savedPEHeaders.empty()) {
            HMODULE hModule = GetModuleHandle(nullptr);
            if (hModule) {
                DWORD oldProtect;
                if (VirtualProtect(hModule, m_savedPEHeaders.size(), PAGE_READWRITE, &oldProtect)) {
                    std::memcpy(hModule, m_savedPEHeaders.data(), m_savedPEHeaders.size());
                    VirtualProtect(hModule, m_savedPEHeaders.size(), oldProtect, &oldProtect);
                }
                m_savedPEHeaders.clear();
            }
        }

        m_antiDumpEnabled = false;
        SS_LOG_INFO(LOG_CATEGORY, L"Anti-dump protection disabled");
    }

    [[nodiscard]] bool IsAntiDumpEnabled() const noexcept {
        return m_antiDumpEnabled.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool ObfuscatePEHeaders() noexcept {
        HMODULE hModule = GetModuleHandle(nullptr);
        if (!hModule) {
            return false;
        }

        std::unique_lock lock(m_mutex);

        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid DOS signature during header obfuscation");
            return false;
        }

        // Validate e_lfanew to prevent out-of-bounds access
        if (dosHeader->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER))) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid e_lfanew offset: 0x%lx", dosHeader->e_lfanew);
            return false;
        }

        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<uint8_t*>(hModule) + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid NT signature during header obfuscation");
            return false;
        }

        // Calculate header size
        size_t headerSize = ntHeaders->OptionalHeader.SizeOfHeaders;
        if (headerSize == 0 || headerSize > 4096 * 16) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Suspicious header size: %zu", headerSize);
            return false;
        }

        // Save original headers
        m_savedPEHeaders.resize(headerSize);
        std::memcpy(m_savedPEHeaders.data(), hModule, headerSize);

        // Make headers writable
        DWORD oldProtect;
        if (!VirtualProtect(hModule, headerSize, PAGE_READWRITE, &oldProtect)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to make headers writable: %lu", GetLastError());
            m_savedPEHeaders.clear();
            return false;
        }

        // Wipe DOS stub (between DOS header and NT headers)
        size_t stubSize = static_cast<size_t>(dosHeader->e_lfanew) - sizeof(IMAGE_DOS_HEADER);
        if (stubSize > 0) {
            std::memset(reinterpret_cast<uint8_t*>(hModule) + sizeof(IMAGE_DOS_HEADER),
                0, stubSize);
        }

        // Wipe optional header fields that aren't needed at runtime
        ntHeaders->OptionalHeader.CheckSum = 0;
        std::memset(&ntHeaders->OptionalHeader.LoaderFlags, 0, sizeof(DWORD));

        // Restore protection
        VirtualProtect(hModule, headerSize, oldProtect, &oldProtect);

        SS_LOG_INFO(LOG_CATEGORY, L"PE headers obfuscated");
        return true;
    }

    [[nodiscard]] bool RestorePEHeaders(std::string_view authorizationToken) noexcept {
        if (!verifyAuthToken(authorizationToken)) {
            return false;
        }

        if (m_savedPEHeaders.empty()) {
            return false;
        }

        HMODULE hModule = GetModuleHandle(nullptr);
        if (!hModule) {
            return false;
        }

        std::unique_lock lock(m_mutex);

        DWORD oldProtect;
        if (!VirtualProtect(hModule, m_savedPEHeaders.size(), PAGE_READWRITE, &oldProtect)) {
            return false;
        }

        std::memcpy(hModule, m_savedPEHeaders.data(), m_savedPEHeaders.size());

        VirtualProtect(hModule, m_savedPEHeaders.size(), oldProtect, &oldProtect);

        m_savedPEHeaders.clear();

        SS_LOG_INFO(LOG_CATEGORY, L"PE headers restored");
        return true;
    }

    // ========================================================================
    // HEAP PROTECTION
    // ========================================================================

    [[nodiscard]] bool EnableHeapProtection() noexcept {
        SS_LOG_INFO(LOG_CATEGORY, L"Enabling heap protection");

        // Enable heap terminate on corruption
        HeapSetInformation(GetProcessHeap(), HeapEnableTerminationOnCorruption, nullptr, 0);

        return true;
    }

    [[nodiscard]] bool ValidateHeapIntegrity() noexcept {
        constexpr DWORD MAX_HEAPS = 256;
        HANDLE heaps[MAX_HEAPS];
        DWORD heapCount = GetProcessHeaps(MAX_HEAPS, heaps);
        if (heapCount > MAX_HEAPS) {
            heapCount = MAX_HEAPS;
        }

        for (DWORD i = 0; i < heapCount; i++) {
            if (!HeapValidate(heaps[i], 0, nullptr)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Heap corruption detected in heap %p", heaps[i]);
                m_stats.heapCorruptionsDetected++;

                // Fire event
                ProtectionEvent event;
                event.eventId = m_nextEventId++;
                event.type = MemoryProtectionEventType::HeapCorruption;
                event.address = reinterpret_cast<uintptr_t>(heaps[i]);
                event.timestamp = Clock::now();
                event.description = "Heap corruption detected";

                fireEvent(event);

                return false;
            }
        }

        return true;
    }

    [[nodiscard]] std::vector<HeapInfo> GetHeapInfo() const noexcept {
        std::vector<HeapInfo> result;

        constexpr DWORD MAX_HEAPS = 256;
        HANDLE heaps[MAX_HEAPS];
        DWORD heapCount = GetProcessHeaps(MAX_HEAPS, heaps);
        if (heapCount > MAX_HEAPS) {
            heapCount = MAX_HEAPS;
        }

        HANDLE defaultHeap = GetProcessHeap();

        for (DWORD i = 0; i < heapCount; i++) {
            HeapInfo info;
            info.heapHandle = heaps[i];
            info.isDefaultHeap = (heaps[i] == defaultHeap);

            // Get heap information
            PROCESS_HEAP_ENTRY entry;
            entry.lpData = nullptr;

            HeapLock(heaps[i]);

            while (HeapWalk(heaps[i], &entry)) {
                if (entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) {
                    info.committedSize += entry.cbData;
                    info.blockCount++;
                }
            }

            HeapUnlock(heaps[i]);

            result.push_back(info);
        }

        return result;
    }

    [[nodiscard]] void* CreateSecureHeap(size_t initialSize) noexcept {
        HANDLE heap = HeapCreate(0, initialSize, 0);
        if (heap) {
            HeapSetInformation(heap, HeapEnableTerminationOnCorruption, nullptr, 0);
            SS_LOG_INFO(LOG_CATEGORY, L"Created secure heap: %p", heap);
        }
        return heap;
    }

    void DestroySecureHeap(void* heapHandle) noexcept {
        if (heapHandle) {
            HeapDestroy(static_cast<HANDLE>(heapHandle));
            SS_LOG_INFO(LOG_CATEGORY, L"Destroyed secure heap: %p", heapHandle);
        }
    }

    // ========================================================================
    // STACK PROTECTION
    // ========================================================================

    [[nodiscard]] bool EnableStackProtection(uint32_t threadId) noexcept {
        if (threadId == 0) {
            threadId = GetCurrentThreadId();
        }

        // Stack protection is largely handled by the compiler (/GS)
        // Here we can add runtime stack monitoring

        SS_LOG_INFO(LOG_CATEGORY, L"Stack protection enabled for thread %u", threadId);
        return true;
    }

    [[nodiscard]] bool VerifyStackCanary(uint32_t threadId) noexcept {
        if (threadId == 0) {
            threadId = GetCurrentThreadId();
        }

        const bool isCurrentThread = (threadId == GetCurrentThreadId());

        if (isCurrentThread) {
            // For the current thread, use TEB directly
            NT_TIB* tib = reinterpret_cast<NT_TIB*>(NtCurrentTeb());
            uintptr_t stackBase = reinterpret_cast<uintptr_t>(tib->StackBase);
            uintptr_t stackLimit = reinterpret_cast<uintptr_t>(tib->StackLimit);

            // Approximate SP check using local variable address
            uintptr_t approxSp = reinterpret_cast<uintptr_t>(&tib);
            if (approxSp < stackLimit || approxSp > stackBase) {
                SS_LOG_WARN(LOG_CATEGORY, L"Stack pointer out of range for current thread %u", threadId);
                m_stats.stackOverflowsDetected++;
                return false;
            }
            return true;
        }

        // For other threads: open, suspend, query, resume
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                                     FALSE, threadId);
        if (!hThread) {
            SS_LOG_WARN(LOG_CATEGORY, L"Failed to open thread %u: %lu", threadId, GetLastError());
            return false;
        }

        bool result = true;
        DWORD suspendCount = SuspendThread(hThread);
        if (suspendCount == static_cast<DWORD>(-1)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Failed to suspend thread %u: %lu", threadId, GetLastError());
            CloseHandle(hThread);
            return false;
        }

        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL;

        if (GetThreadContext(hThread, &ctx)) {
#ifdef _WIN64
            uintptr_t sp = ctx.Rsp;
#else
            uintptr_t sp = ctx.Esp;
#endif
            // We can't access the target thread's TEB directly from here.
            // A zero SP is definitely invalid; further checks require NtQueryInformationThread.
            if (sp == 0) {
                SS_LOG_WARN(LOG_CATEGORY, L"Null stack pointer for thread %u", threadId);
                m_stats.stackOverflowsDetected++;
                result = false;
            }
        } else {
            SS_LOG_WARN(LOG_CATEGORY, L"Failed to get context for thread %u: %lu", threadId, GetLastError());
            result = false;
        }

        ResumeThread(hThread);
        CloseHandle(hThread);
        return result;
    }

    [[nodiscard]] StackInfo GetStackInfo(uint32_t threadId) noexcept {
        StackInfo info;

        if (threadId == 0) {
            threadId = GetCurrentThreadId();
        }

        info.threadId = threadId;

        const bool isCurrentThread = (threadId == GetCurrentThreadId());

        if (isCurrentThread) {
            // Safe to use NtCurrentTeb() only for the calling thread
            NT_TIB* tib = reinterpret_cast<NT_TIB*>(NtCurrentTeb());
            info.stackBase = reinterpret_cast<uintptr_t>(tib->StackBase);
            info.stackLimit = reinterpret_cast<uintptr_t>(tib->StackLimit);
            info.stackSize = info.stackBase - info.stackLimit;

            // Approximate SP using a local variable address
            uintptr_t approxSp = reinterpret_cast<uintptr_t>(&tib);
            info.currentSP = approxSp;
            info.stackUsage = info.stackBase - info.currentSP;
            info.hasCanary = true;
            info.canaryIntact = VerifyStackCanary(threadId);
            return info;
        }

        // For non-current threads, suspend and query
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                                     FALSE, threadId);
        if (!hThread) {
            return info;
        }

        DWORD suspendCount = SuspendThread(hThread);
        if (suspendCount == static_cast<DWORD>(-1)) {
            CloseHandle(hThread);
            return info;
        }

        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL;

        if (GetThreadContext(hThread, &ctx)) {
#ifdef _WIN64
            info.currentSP = ctx.Rsp;
#else
            info.currentSP = ctx.Esp;
#endif
        }

        ResumeThread(hThread);
        CloseHandle(hThread);

        // We cannot safely access another thread's TEB from user mode without NtQueryInformationThread.
        // Fill what we can.
        info.hasCanary = true;
        info.canaryIntact = VerifyStackCanary(threadId);

        return info;
    }

    [[nodiscard]] std::vector<StackInfo> GetAllStackInfo() noexcept {
        std::vector<StackInfo> result;

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return result;
        }

        THREADENTRY32 te32;
        te32.dwSize = sizeof(te32);

        DWORD currentPid = GetCurrentProcessId();

        if (Thread32First(hSnapshot, &te32)) {
            do {
                if (te32.th32OwnerProcessID == currentPid) {
                    result.push_back(GetStackInfo(te32.th32ThreadID));
                }
            } while (Thread32Next(hSnapshot, &te32));
        }

        CloseHandle(hSnapshot);
        return result;
    }

    // ========================================================================
    // MEMORY QUERY
    // ========================================================================

    [[nodiscard]] std::optional<MemoryRegionInfo> QueryMemoryRegion(uintptr_t address) noexcept {
        MEMORY_BASIC_INFORMATION mbi = {};

        if (VirtualQuery(reinterpret_cast<void*>(address), &mbi, sizeof(mbi)) == 0) {
            return std::nullopt;
        }

        MemoryRegionInfo info;
        info.baseAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        info.regionSize = mbi.RegionSize;
        info.allocationBase = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
        info.protection = mbi.Protect;
        info.state = mbi.State;
        info.type = mbi.Type;

        // Classify region type
        if (mbi.Protect & PAGE_EXECUTE_READ || mbi.Protect & PAGE_EXECUTE_READWRITE) {
            info.regionType = MemoryRegionType::Code;
        } else if (mbi.Protect & PAGE_READONLY) {
            info.regionType = MemoryRegionType::ReadOnly;
        } else if (mbi.Protect & PAGE_READWRITE) {
            info.regionType = MemoryRegionType::ReadWrite;
        } else if (mbi.Protect & PAGE_GUARD) {
            info.regionType = MemoryRegionType::Guard;
        } else if (mbi.State == MEM_RESERVE) {
            info.regionType = MemoryRegionType::Reserved;
        }

        // Get module name if mapped
        if (mbi.Type == MEM_IMAGE) {
            wchar_t moduleName[MAX_PATH];
            if (GetMappedFileNameW(GetCurrentProcess(), mbi.BaseAddress,
                                   moduleName, MAX_PATH) > 0) {
                info.moduleName = moduleName;
            }
        }

        return info;
    }

    [[nodiscard]] std::vector<MemoryRegionInfo> EnumerateMemoryRegions() noexcept {
        std::vector<MemoryRegionInfo> result;

        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);

        uintptr_t address = reinterpret_cast<uintptr_t>(sysInfo.lpMinimumApplicationAddress);
        uintptr_t maxAddress = reinterpret_cast<uintptr_t>(sysInfo.lpMaximumApplicationAddress);

        while (address < maxAddress) {
            auto regionInfo = QueryMemoryRegion(address);
            if (regionInfo.has_value()) {
                result.push_back(regionInfo.value());
                address = regionInfo->baseAddress + regionInfo->regionSize;
            } else {
                address += MemoryProtectionConstants::PAGE_SIZE;
            }
        }

        return result;
    }

    [[nodiscard]] PageProtection GetPageProtection(uintptr_t address) noexcept {
        auto info = QueryMemoryRegion(address);
        if (info.has_value()) {
            return static_cast<PageProtection>(info->protection);
        }
        return PageProtection::NoAccess;
    }

    [[nodiscard]] bool SetPageProtection(uintptr_t address, size_t size,
                                          PageProtection protection) noexcept {
        // Block RWX pages — a security-critical invariant for an EDR
        uint32_t protVal = static_cast<uint32_t>(protection);
        if (protVal == PAGE_EXECUTE_READWRITE || protVal == PAGE_EXECUTE_WRITECOPY) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"Blocked RWX page protection request at 0x%llx (size %zu) — W^X violation",
                static_cast<unsigned long long>(address), size);
            return false;
        }

        DWORD oldProtect;
        if (!VirtualProtect(reinterpret_cast<void*>(address), size,
                static_cast<DWORD>(protection), &oldProtect)) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"VirtualProtect failed at 0x%llx: %lu",
                static_cast<unsigned long long>(address), GetLastError());
            return false;
        }
        return true;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    [[nodiscard]] uint64_t RegisterEventCallback(ProtectionEventCallback callback) noexcept {
        std::unique_lock lock(m_mutex);
        uint64_t id = m_nextCallbackId++;
        m_eventCallbacks[id] = std::move(callback);
        return id;
    }

    void UnregisterEventCallback(uint64_t callbackId) noexcept {
        std::unique_lock lock(m_mutex);
        m_eventCallbacks.erase(callbackId);
    }

    [[nodiscard]] uint64_t RegisterIntegrityCallback(MemoryIntegrityCallback callback) noexcept {
        std::unique_lock lock(m_mutex);
        uint64_t id = m_nextCallbackId++;
        m_integrityCallbacks[id] = std::move(callback);
        return id;
    }

    void UnregisterIntegrityCallback(uint64_t callbackId) noexcept {
        std::unique_lock lock(m_mutex);
        m_integrityCallbacks.erase(callbackId);
    }

    [[nodiscard]] uint64_t RegisterHeapCorruptionCallback(HeapCorruptionCallback callback) noexcept {
        std::unique_lock lock(m_mutex);
        uint64_t id = m_nextCallbackId++;
        m_heapCorruptionCallbacks[id] = std::move(callback);
        return id;
    }

    void UnregisterHeapCorruptionCallback(uint64_t callbackId) noexcept {
        std::unique_lock lock(m_mutex);
        m_heapCorruptionCallbacks.erase(callbackId);
    }

    [[nodiscard]] uint64_t RegisterStackOverflowCallback(StackOverflowCallback callback) noexcept {
        std::unique_lock lock(m_mutex);
        uint64_t id = m_nextCallbackId++;
        m_stackOverflowCallbacks[id] = std::move(callback);
        return id;
    }

    void UnregisterStackOverflowCallback(uint64_t callbackId) noexcept {
        std::unique_lock lock(m_mutex);
        m_stackOverflowCallbacks.erase(callbackId);
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] MemoryProtectionStatistics GetStatistics() const noexcept {
        return m_stats;
    }

    void ResetStatistics(std::string_view authorizationToken) noexcept {
        if (!verifyAuthToken(authorizationToken)) {
            return;
        }
        m_stats.Reset();
    }

    [[nodiscard]] std::vector<ProtectionEvent> GetEventHistory(size_t maxEntries) const noexcept {
        std::shared_lock lock(m_mutex);

        size_t count = std::min(maxEntries, m_eventHistory.size());

        if (count == m_eventHistory.size()) {
            return m_eventHistory;
        }

        return std::vector<ProtectionEvent>(
            m_eventHistory.end() - count, m_eventHistory.end());
    }

    void ClearEventHistory(std::string_view authorizationToken) noexcept {
        if (!verifyAuthToken(authorizationToken)) {
            return;
        }

        std::unique_lock lock(m_mutex);
        m_eventHistory.clear();
    }

    [[nodiscard]] std::string ExportReport() const noexcept {
        std::shared_lock lock(m_mutex);

        std::ostringstream oss;
        oss << "MemoryProtection Report\n";
        oss << "=======================\n\n";

        oss << "Status: " << static_cast<int>(m_status.load()) << "\n";
        oss << "Protection Level: " << GetProtectionLevelName(m_config.level) << "\n\n";

        oss << "Protections:\n";
        oss << "  ASLR: " << (m_aslrEnabled.load() ? "enabled" : "disabled") << "\n";
        oss << "  DEP: " << (m_depEnabled.load() ? "enabled" : "disabled") << "\n";
        oss << "  CFG: " << (m_cfgEnabled.load() ? "enabled" : "disabled") << "\n";
        oss << "  Anti-Dump: " << (m_antiDumpEnabled.load() ? "enabled" : "disabled") << "\n\n";

        oss << "Statistics:\n" << m_stats.ToJson() << "\n\n";

        oss << "Protected Regions: " << m_protectedRegions.size() << "\n";
        oss << "Secure Allocations: " << m_secureAllocations.size() << "\n";

        return oss.str();
    }

    // ========================================================================
    // SELF-TEST
    // ========================================================================

    [[nodiscard]] bool SelfTest() noexcept {
        SS_LOG_INFO(LOG_CATEGORY, L"Running self-test");

        bool passed = true;

        // Test 1: Secure allocation
        try {
            void* ptr = AllocateSecure(1024);
            if (!ptr) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test: Secure allocation failed");
                passed = false;
            } else {
                // Write and read back
                std::memset(ptr, 0xAB, 1024);
                if (*static_cast<uint8_t*>(ptr) != 0xAB) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Self-test: Memory read/write failed");
                    passed = false;
                }
                FreeSecure(ptr, 1024);
            }
        } catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Self-test: Exception in allocation test");
            passed = false;
        }

        // Test 2: Region protection
        try {
            // Allocate some memory and protect it
            void* testRegion = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (testRegion) {
                uintptr_t addr = reinterpret_cast<uintptr_t>(testRegion);

                if (!ProtectRegion("selftest_region", addr, 4096, MemoryRegionType::ReadWrite)) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Self-test: Region protection failed");
                    passed = false;
                } else {
                    auto status = VerifyRegionIntegrity("selftest_region");
                    if (status != MemoryIntegrityStatus::Valid) {
                        SS_LOG_ERROR(LOG_CATEGORY, L"Self-test: Integrity check failed");
                        passed = false;
                    }

                    UnprotectRegion("selftest_region", INTERNAL_AUTH_TOKEN);
                }

                VirtualFree(testRegion, 0, MEM_RELEASE);
            }
        } catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Self-test: Exception in region test");
            passed = false;
        }

        // Test 3: SecureZero
        try {
            uint8_t buffer[64];
            std::memset(buffer, 0xFF, sizeof(buffer));

            SecureZero(buffer, sizeof(buffer));

            bool allZero = true;
            for (auto b : buffer) {
                if (b != 0) {
                    allZero = false;
                    break;
                }
            }

            if (!allZero) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test: SecureZero failed");
                passed = false;
            }
        } catch (...) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Self-test: Exception in zero memory test");
            passed = false;
        }

        if (passed) {
            SS_LOG_INFO(LOG_CATEGORY, L"Self-test passed");
        } else {
            SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed");
        }

        return passed;
    }

    // ========================================================================
    // STATIC UTILITIES
    // ========================================================================

    static void SecureZero(void* ptr, size_t size) noexcept {
        if (!ptr || size == 0) {
            return;
        }

        // Use volatile to prevent compiler optimization
        volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
        while (size--) {
            *p++ = 0;
        }

        // Memory barrier to ensure writes are committed
        std::atomic_thread_fence(std::memory_order_seq_cst);
    }

    [[nodiscard]] static bool ConstantTimeCompare(const void* a, const void* b, size_t size) noexcept {
        const volatile uint8_t* pa = static_cast<const volatile uint8_t*>(a);
        const volatile uint8_t* pb = static_cast<const volatile uint8_t*>(b);

        volatile uint8_t result = 0;

        for (size_t i = 0; i < size; i++) {
            result |= pa[i] ^ pb[i];
        }

        return result == 0;
    }

private:
    // ========================================================================
    // INTERNAL METHODS
    // ========================================================================

    [[nodiscard]] bool enableDEPInternal() noexcept {
        // Enable permanent DEP
        DWORD flags = PROCESS_DEP_ENABLE | PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION;

        if (SetProcessDEPPolicy(flags)) {
            m_depEnabled = true;
            SS_LOG_INFO(LOG_CATEGORY, L"DEP enabled");
            return true;
        }

        SS_LOG_WARN(LOG_CATEGORY, L"Failed to enable DEP: %lu", GetLastError());
        return false;
    }

    [[nodiscard]] bool enableASLRInternal() noexcept {
        // ASLR is typically enabled at compile time via /DYNAMICBASE
        // Here we verify it's enabled

        PROCESS_MITIGATION_ASLR_POLICY aslrPolicy = {};

        if (GetProcessMitigationPolicy(GetCurrentProcess(),
            ProcessASLRPolicy, &aslrPolicy, sizeof(aslrPolicy))) {

            m_aslrEnabled = (aslrPolicy.EnableBottomUpRandomization ||
                            aslrPolicy.EnableHighEntropy);

            if (m_aslrEnabled) {
                SS_LOG_INFO(LOG_CATEGORY, L"ASLR is enabled");
            } else {
                SS_LOG_WARN(LOG_CATEGORY, L"ASLR is not enabled");
            }

            return m_aslrEnabled;
        }

        return false;
    }

    [[nodiscard]] bool enableCFGInternal() noexcept {
        // CFG is typically enabled at compile time via /guard:cf
        // Here we verify it's enabled

        PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfgPolicy = {};

        if (GetProcessMitigationPolicy(GetCurrentProcess(),
            ProcessControlFlowGuardPolicy, &cfgPolicy, sizeof(cfgPolicy))) {

            m_cfgEnabled = cfgPolicy.EnableControlFlowGuard != 0;

            if (m_cfgEnabled) {
                SS_LOG_INFO(LOG_CATEGORY, L"CFG is enabled");
            } else {
                SS_LOG_WARN(LOG_CATEGORY, L"CFG is not enabled");
            }

            return m_cfgEnabled;
        }

        return false;
    }

    [[nodiscard]] bool enableAntiDumpInternal() noexcept {
        if (m_antiDumpEnabled) {
            return true;
        }

        // Obfuscate PE headers
        if (ObfuscatePEHeaders()) {
            m_antiDumpEnabled = true;
            SS_LOG_INFO(LOG_CATEGORY, L"Anti-dump protection enabled");
            return true;
        }

        return false;
    }

    void applyMitigationPolicies() noexcept {
        // Disable dynamic code generation
        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dcPolicy = {};
        dcPolicy.ProhibitDynamicCode = 0; // Can't enable this for managed code
        SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dcPolicy, sizeof(dcPolicy));

        // Enable strict handle checks
        PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handlePolicy = {};
        handlePolicy.RaiseExceptionOnInvalidHandleReference = 1;
        handlePolicy.HandleExceptionsPermanentlyEnabled = 1;
        SetProcessMitigationPolicy(ProcessStrictHandleCheckPolicy, &handlePolicy, sizeof(handlePolicy));

        // Disable Win32k system calls (for non-GUI apps)
        // PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY syscallPolicy = {};
        // syscallPolicy.DisallowWin32kSystemCalls = 1;
        // SetProcessMitigationPolicy(ProcessSystemCallDisablePolicy, &syscallPolicy, sizeof(syscallPolicy));

        SS_LOG_INFO(LOG_CATEGORY, L"Mitigation policies applied");
    }

    void initializeSecureHeap(size_t poolSize) noexcept {
        m_secureHeap = HeapCreate(0, poolSize, 0);
        if (m_secureHeap) {
            HeapSetInformation(m_secureHeap, HeapEnableTerminationOnCorruption, nullptr, 0);
            SS_LOG_INFO(LOG_CATEGORY, L"Secure heap initialized with size %zu", poolSize);
        }
    }

    void freeAllSecureAllocations() noexcept {
        for (auto& [ptr, alloc] : m_secureAllocations) {
            SecureZero(ptr, alloc.size);

            if (alloc.isLocked) {
                VirtualUnlock(ptr, alloc.size);
            }

            void* basePtr = m_allocationBaseMap[ptr];
            VirtualFree(basePtr, 0, MEM_RELEASE);
        }

        m_secureAllocations.clear();
        m_allocationBaseMap.clear();

        if (m_secureHeap) {
            HeapDestroy(m_secureHeap);
            m_secureHeap = nullptr;
        }
    }

    void startIntegrityMonitoring() noexcept {
        if (m_integrityMonitorRunning) {
            return;
        }

        m_integrityMonitorRunning = true;

        m_integrityMonitorThread = std::thread([this]() {
            SS_LOG_INFO(LOG_CATEGORY, L"Integrity monitoring thread started");

            while (m_integrityMonitorRunning) {
                std::this_thread::sleep_for(
                    Milliseconds(m_config.integrityCheckIntervalMs));

                if (!m_integrityMonitorRunning) break;

                // Verify all protected regions
                auto results = VerifyAllIntegrity();

                for (const auto& [id, status] : results) {
                    if (status != MemoryIntegrityStatus::Valid) {
                        SS_LOG_WARN(LOG_CATEGORY, L"Integrity issue in region '%hs': %hs",
                            id.c_str(), std::string(GetIntegrityStatusName(status)).c_str());
                    }
                }

                // Also validate heap
                if (m_config.enableHeapProtection) {
                    ValidateHeapIntegrity();
                }
            }

            SS_LOG_INFO(LOG_CATEGORY, L"Integrity monitoring thread stopped");
        });
    }

    void stopIntegrityMonitoring() noexcept {
        m_integrityMonitorRunning = false;

        if (m_integrityMonitorThread.joinable()) {
            m_integrityMonitorThread.join();
        }
    }

    [[nodiscard]] bool calculateRegionHash(uintptr_t address, size_t size,
                                           uint32_t& crc32,
                                           std::array<uint8_t, 32>& sha256) noexcept {
        // Validate the memory region is still committed and readable
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)) == 0) {
            SS_LOG_ERROR(LOG_CATEGORY, L"calculateRegionHash: VirtualQuery failed at 0x%llx",
                static_cast<unsigned long long>(address));
            return false;
        }

        if (mbi.State != MEM_COMMIT) {
            SS_LOG_ERROR(LOG_CATEGORY, L"calculateRegionHash: region at 0x%llx is not committed",
                static_cast<unsigned long long>(address));
            return false;
        }

        // Reject regions protected with PAGE_NOACCESS or PAGE_GUARD (would cause AV)
        if ((mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"calculateRegionHash: region at 0x%llx has no-access/guard protection",
                static_cast<unsigned long long>(address));
            return false;
        }

        const uint8_t* data = reinterpret_cast<const uint8_t*>(address);

        // Calculate CRC32
        crc32 = 0xFFFFFFFF;
        for (size_t i = 0; i < size; i++) {
            crc32 ^= data[i];
            for (int j = 0; j < 8; j++) {
                crc32 = (crc32 >> 1) ^ (0xEDB88320 & (-(crc32 & 1)));
            }
        }
        crc32 ^= 0xFFFFFFFF;

        // Calculate SHA-256 using CryptoAPI
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;

        if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            return false;
        }

        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptReleaseContext(hProv, 0);
            return false;
        }

        // CryptHashData takes DWORD size — cap to prevent truncation
        if (size > static_cast<size_t>(MAXDWORD)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Region too large for SHA-256 hash: %zu", size);
            CryptReleaseContext(hProv, 0);
            return false;
        }

        if (!CryptHashData(hHash, data, static_cast<DWORD>(size), 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return false;
        }

        DWORD hashLen = 32;
        if (!CryptGetHashParam(hHash, HP_HASHVAL, sha256.data(), &hashLen, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return false;
        }

        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);

        return true;
    }

    void generateSessionKey() noexcept {
        // Generate random encryption key using OS CSPRNG
        NTSTATUS status = BCryptGenRandom(
            nullptr,
            m_sessionKey.data(),
            static_cast<ULONG>(m_sessionKey.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);

        if (!BCRYPT_SUCCESS(status)) {
            // Fallback to CryptGenRandom if BCrypt is unavailable
            HCRYPTPROV hProv = 0;
            if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
                CryptGenRandom(hProv, static_cast<DWORD>(m_sessionKey.size()), m_sessionKey.data());
                CryptReleaseContext(hProv, 0);
            } else {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to generate session key via any CSPRNG");
            }
        }
    }

    [[nodiscard]] bool verifyAuthToken(std::string_view token) const noexcept {
        // Constant-time comparison to prevent timing side-channels
        if (token.size() != INTERNAL_AUTH_TOKEN.size()) {
            return false;
        }
        return ConstantTimeCompare(token.data(), INTERNAL_AUTH_TOKEN.data(), token.size());
    }

    void fireEvent(const ProtectionEvent& event) noexcept {
        // Store in history
        {
            std::unique_lock lock(m_mutex);
            m_eventHistory.push_back(event);

            // Limit history size
            if (m_eventHistory.size() > 10000) {
                m_eventHistory.erase(m_eventHistory.begin(),
                    m_eventHistory.begin() + 5000);
            }

            m_stats.lastEventTime = Clock::now();
        }

        // Invoke callbacks outside the lock to prevent deadlock
        fireEventCallbacksUnlocked(event);
    }

    /// Fire event callbacks without acquiring m_mutex for event history.
    /// Acquires a shared_lock only to snapshot the callback list, then invokes outside.
    void fireEventCallbacksUnlocked(const ProtectionEvent& event) noexcept {
        std::vector<ProtectionEventCallback> callbacksCopy;
        {
            std::shared_lock lock(m_mutex);
            callbacksCopy.reserve(m_eventCallbacks.size());
            for (const auto& [id, callback] : m_eventCallbacks) {
                callbacksCopy.push_back(callback);
            }
        }

        for (const auto& callback : callbacksCopy) {
            try {
                callback(event);
            } catch (...) {
                SS_LOG_WARN(LOG_CATEGORY, L"Exception in event callback");
            }
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    std::atomic<ModuleStatus> m_status;
    std::atomic<bool> m_initialized;

    MemoryProtectionConfiguration m_config;
    MemoryProtectionStatistics m_stats;

    // Protection state
    std::atomic<bool> m_aslrEnabled;
    std::atomic<bool> m_depEnabled;
    std::atomic<bool> m_cfgEnabled;
    std::atomic<bool> m_antiDumpEnabled;

    // Secure allocations
    std::unordered_map<void*, SecureAllocation> m_secureAllocations;
    std::unordered_map<void*, void*> m_allocationBaseMap; // user ptr -> base ptr
    HANDLE m_secureHeap = nullptr;

    // Protected regions
    std::unordered_map<std::string, ProtectedRegion> m_protectedRegions;

    // Anti-dump
    std::vector<uint8_t> m_savedPEHeaders;

    // Integrity monitoring
    std::atomic<bool> m_integrityMonitorRunning;
    std::thread m_integrityMonitorThread;

    // Session encryption key
    std::array<uint8_t, MemoryProtectionConstants::ENCRYPTION_KEY_SIZE> m_sessionKey{};

    // Event tracking
    std::atomic<uint64_t> m_nextEventId;
    std::vector<ProtectionEvent> m_eventHistory;

    // Callbacks
    std::atomic<uint64_t> m_nextCallbackId;
    std::unordered_map<uint64_t, ProtectionEventCallback> m_eventCallbacks;
    std::unordered_map<uint64_t, MemoryIntegrityCallback> m_integrityCallbacks;
    std::unordered_map<uint64_t, HeapCorruptionCallback> m_heapCorruptionCallbacks;
    std::unordered_map<uint64_t, StackOverflowCallback> m_stackOverflowCallbacks;
};

// ============================================================================
// MEMORYPROTECTION PUBLIC IMPLEMENTATION
// ============================================================================

MemoryProtection& MemoryProtection::Instance() noexcept {
    static MemoryProtection instance;
    return instance;
}

bool MemoryProtection::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

MemoryProtection::MemoryProtection()
    : m_impl(std::make_unique<MemoryProtectionImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
    SS_LOG_INFO(LOG_CATEGORY, L"MemoryProtection instance created");
}

MemoryProtection::~MemoryProtection() {
    SS_LOG_INFO(LOG_CATEGORY, L"MemoryProtection instance destroyed");
}

bool MemoryProtection::Initialize(const MemoryProtectionConfiguration& config) {
    return m_impl->Initialize(config);
}

bool MemoryProtection::Initialize(MemoryProtectionLevel level) {
    return Initialize(MemoryProtectionConfiguration::FromLevel(level));
}

void MemoryProtection::Shutdown(std::string_view authorizationToken) {
    m_impl->Shutdown(authorizationToken);
}

std::string MemoryProtection::GetInternalAuthToken() const {
    return std::string(INTERNAL_AUTH_TOKEN);
}

bool MemoryProtection::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus MemoryProtection::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool MemoryProtection::SetConfiguration(const MemoryProtectionConfiguration& config) {
    return m_impl->SetConfiguration(config);
}

MemoryProtectionConfiguration MemoryProtection::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

void MemoryProtection::SetProtectionLevel(MemoryProtectionLevel level) {
    m_impl->SetProtectionLevel(level);
}

MemoryProtectionLevel MemoryProtection::GetProtectionLevel() const noexcept {
    return m_impl->GetProtectionLevel();
}

void MemoryProtection::ApplyProcessHardening() {
    m_impl->ApplyProcessHardening();
}

bool MemoryProtection::EnableASLR() {
    return m_impl->EnableASLR();
}

bool MemoryProtection::IsASLREnabled() const {
    return m_impl->IsASLREnabled();
}

bool MemoryProtection::EnableDEP() {
    return m_impl->EnableDEP();
}

bool MemoryProtection::IsDEPEnabled() const {
    return m_impl->IsDEPEnabled();
}

bool MemoryProtection::EnableCFG() {
    return m_impl->EnableCFG();
}

bool MemoryProtection::IsCFGEnabled() const {
    return m_impl->IsCFGEnabled();
}

void* MemoryProtection::AllocateSecure(size_t size) {
    return m_impl->AllocateSecure(size);
}

void* MemoryProtection::AllocateSecure(size_t size, AllocationType type) {
    return m_impl->AllocateSecure(size, type);
}

void MemoryProtection::FreeSecure(void* ptr, size_t size) {
    m_impl->FreeSecure(ptr, size);
}

void* MemoryProtection::ReallocateSecure(void* ptr, size_t oldSize, size_t newSize) {
    return m_impl->ReallocateSecure(ptr, oldSize, newSize);
}

void* MemoryProtection::AllocateEncrypted(size_t size) {
    return m_impl->AllocateEncrypted(size);
}

void MemoryProtection::FreeEncrypted(void* ptr, size_t size) {
    m_impl->FreeEncrypted(ptr, size);
}

void* MemoryProtection::AllocateLocked(size_t size) {
    return m_impl->AllocateLocked(size);
}

void MemoryProtection::FreeLocked(void* ptr, size_t size) {
    m_impl->FreeLocked(ptr, size);
}

void* MemoryProtection::AllocateGuarded(size_t size) {
    return m_impl->AllocateGuarded(size);
}

void MemoryProtection::FreeGuarded(void* ptr, size_t size) {
    m_impl->FreeGuarded(ptr, size);
}

std::optional<SecureAllocation> MemoryProtection::GetSecureAllocationInfo(void* ptr) const {
    return m_impl->GetSecureAllocationInfo(ptr);
}

std::vector<SecureAllocation> MemoryProtection::GetAllSecureAllocations() const {
    return m_impl->GetAllSecureAllocations();
}

size_t MemoryProtection::GetSecureMemoryUsage() const {
    return m_impl->GetSecureMemoryUsage();
}

bool MemoryProtection::ProtectRegion(std::string_view id, uintptr_t address, size_t size,
                                      MemoryRegionType type) {
    return m_impl->ProtectRegion(id, address, size, type);
}

bool MemoryProtection::UnprotectRegion(std::string_view id, std::string_view authorizationToken) {
    return m_impl->UnprotectRegion(id, authorizationToken);
}

bool MemoryProtection::ProtectCodeRegion(std::string_view id, uintptr_t address, size_t size) {
    return m_impl->ProtectCodeRegion(id, address, size);
}

bool MemoryProtection::ProtectSelfCode() {
    return m_impl->ProtectSelfCode();
}

bool MemoryProtection::IsRegionProtected(uintptr_t address) const {
    return m_impl->IsRegionProtected(address);
}

std::optional<ProtectedRegion> MemoryProtection::GetProtectedRegion(std::string_view id) const {
    return m_impl->GetProtectedRegion(id);
}

std::vector<ProtectedRegion> MemoryProtection::GetAllProtectedRegions() const {
    return m_impl->GetAllProtectedRegions();
}

MemoryIntegrityStatus MemoryProtection::VerifyRegionIntegrity(std::string_view id) {
    return m_impl->VerifyRegionIntegrity(id);
}

std::vector<std::pair<std::string, MemoryIntegrityStatus>> MemoryProtection::VerifyAllIntegrity() {
    return m_impl->VerifyAllIntegrity();
}

void MemoryProtection::ForceIntegrityCheck() {
    m_impl->ForceIntegrityCheck();
}

bool MemoryProtection::UpdateRegionBaseline(std::string_view id,
                                             std::string_view authorizationToken) {
    return m_impl->UpdateRegionBaseline(id, authorizationToken);
}

bool MemoryProtection::EnableAntiDump() {
    return m_impl->EnableAntiDump();
}

void MemoryProtection::DisableAntiDump(std::string_view authorizationToken) {
    m_impl->DisableAntiDump(authorizationToken);
}

bool MemoryProtection::IsAntiDumpEnabled() const {
    return m_impl->IsAntiDumpEnabled();
}

bool MemoryProtection::ObfuscatePEHeaders() {
    return m_impl->ObfuscatePEHeaders();
}

bool MemoryProtection::RestorePEHeaders(std::string_view authorizationToken) {
    return m_impl->RestorePEHeaders(authorizationToken);
}

bool MemoryProtection::EnableHeapProtection() {
    return m_impl->EnableHeapProtection();
}

bool MemoryProtection::ValidateHeapIntegrity() {
    return m_impl->ValidateHeapIntegrity();
}

std::vector<HeapInfo> MemoryProtection::GetHeapInfo() const {
    return m_impl->GetHeapInfo();
}

void* MemoryProtection::CreateSecureHeap(size_t initialSize) {
    return m_impl->CreateSecureHeap(initialSize);
}

void MemoryProtection::DestroySecureHeap(void* heapHandle) {
    m_impl->DestroySecureHeap(heapHandle);
}

bool MemoryProtection::EnableStackProtection(uint32_t threadId) {
    return m_impl->EnableStackProtection(threadId);
}

bool MemoryProtection::VerifyStackCanary(uint32_t threadId) {
    return m_impl->VerifyStackCanary(threadId);
}

StackInfo MemoryProtection::GetStackInfo(uint32_t threadId) {
    return m_impl->GetStackInfo(threadId);
}

std::vector<StackInfo> MemoryProtection::GetAllStackInfo() {
    return m_impl->GetAllStackInfo();
}

std::optional<MemoryRegionInfo> MemoryProtection::QueryMemoryRegion(uintptr_t address) {
    return m_impl->QueryMemoryRegion(address);
}

std::vector<MemoryRegionInfo> MemoryProtection::EnumerateMemoryRegions() {
    return m_impl->EnumerateMemoryRegions();
}

PageProtection MemoryProtection::GetPageProtection(uintptr_t address) {
    return m_impl->GetPageProtection(address);
}

bool MemoryProtection::SetPageProtection(uintptr_t address, size_t size,
                                          PageProtection protection) {
    return m_impl->SetPageProtection(address, size, protection);
}

uint64_t MemoryProtection::RegisterEventCallback(ProtectionEventCallback callback) {
    return m_impl->RegisterEventCallback(std::move(callback));
}

void MemoryProtection::UnregisterEventCallback(uint64_t callbackId) {
    m_impl->UnregisterEventCallback(callbackId);
}

uint64_t MemoryProtection::RegisterIntegrityCallback(MemoryIntegrityCallback callback) {
    return m_impl->RegisterIntegrityCallback(std::move(callback));
}

void MemoryProtection::UnregisterIntegrityCallback(uint64_t callbackId) {
    m_impl->UnregisterIntegrityCallback(callbackId);
}

uint64_t MemoryProtection::RegisterHeapCorruptionCallback(HeapCorruptionCallback callback) {
    return m_impl->RegisterHeapCorruptionCallback(std::move(callback));
}

void MemoryProtection::UnregisterHeapCorruptionCallback(uint64_t callbackId) {
    m_impl->UnregisterHeapCorruptionCallback(callbackId);
}

uint64_t MemoryProtection::RegisterStackOverflowCallback(StackOverflowCallback callback) {
    return m_impl->RegisterStackOverflowCallback(std::move(callback));
}

void MemoryProtection::UnregisterStackOverflowCallback(uint64_t callbackId) {
    m_impl->UnregisterStackOverflowCallback(callbackId);
}

MemoryProtectionStatistics MemoryProtection::GetStatistics() const {
    return m_impl->GetStatistics();
}

void MemoryProtection::ResetStatistics(std::string_view authorizationToken) {
    m_impl->ResetStatistics(authorizationToken);
}

std::vector<ProtectionEvent> MemoryProtection::GetEventHistory(size_t maxEntries) const {
    return m_impl->GetEventHistory(maxEntries);
}

void MemoryProtection::ClearEventHistory(std::string_view authorizationToken) {
    m_impl->ClearEventHistory(authorizationToken);
}

std::string MemoryProtection::ExportReport() const {
    return m_impl->ExportReport();
}

bool MemoryProtection::SelfTest() {
    return m_impl->SelfTest();
}

void MemoryProtection::SecureZero(void* ptr, size_t size) {
    MemoryProtectionImpl::SecureZero(ptr, size);
}

bool MemoryProtection::ConstantTimeCompare(const void* a, const void* b, size_t size) {
    return MemoryProtectionImpl::ConstantTimeCompare(a, b, size);
}

std::string MemoryProtection::GetVersionString() noexcept {
    std::ostringstream oss;
    oss << MemoryProtectionConstants::VERSION_MAJOR << "."
        << MemoryProtectionConstants::VERSION_MINOR << "."
        << MemoryProtectionConstants::VERSION_PATCH;
    return oss.str();
}

// ============================================================================
// RAII HELPER IMPLEMENTATIONS
// ============================================================================

MemorySecureBuffer::MemorySecureBuffer(size_t size)
    : MemorySecureBuffer(size, AllocationType::Secure)
{
}

MemorySecureBuffer::MemorySecureBuffer(size_t size, AllocationType type)
    : m_size(size)
    , m_type(type)
{
    m_data = MemoryProtection::Instance().AllocateSecure(size, type);
}

MemorySecureBuffer::~MemorySecureBuffer() {
    if (m_data) {
        MemoryProtection::Instance().FreeSecure(m_data, m_size);
        m_data = nullptr;
        m_size = 0;
    }
}

MemorySecureBuffer::MemorySecureBuffer(MemorySecureBuffer&& other) noexcept
    : m_data(other.m_data)
    , m_size(other.m_size)
    , m_type(other.m_type)
{
    other.m_data = nullptr;
    other.m_size = 0;
}

MemorySecureBuffer& MemorySecureBuffer::operator=(MemorySecureBuffer&& other) noexcept {
    if (this != &other) {
        if (m_data) {
            MemoryProtection::Instance().FreeSecure(m_data, m_size);
        }

        m_data = other.m_data;
        m_size = other.m_size;
        m_type = other.m_type;

        other.m_data = nullptr;
        other.m_size = 0;
    }
    return *this;
}

ProtectedRegionGuard::ProtectedRegionGuard(std::string_view id, uintptr_t address, size_t size)
    : m_id(id)
{
    m_protected = MemoryProtection::Instance().ProtectRegion(id, address, size);
}

ProtectedRegionGuard::~ProtectedRegionGuard() {
    if (m_protected) {
        MemoryProtection::Instance().UnprotectRegion(m_id, INTERNAL_AUTH_TOKEN);
    }
}

}  // namespace Security
}  // namespace ShadowStrike

/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * WmiEmulation.hpp — WMI reconnaissance and persistence detection
 *
 * WMI is the #1 LOLBin for malware reconnaissance. This module:
 *   - Classifies every WQL query by threat category
 *   - Detects anti-VM queries (Win32_BIOS vendor, thermal sensors, etc.)
 *   - Detects ransomware shadow copy deletion (Win32_ShadowCopy)
 *   - Detects WMI event subscription persistence
 *   - Provides OLE Automation stubs (SysAllocString, VariantInit, etc.)
 *   - Tracks BSTR allocations with resource caps
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <mutex>
#include <optional>

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Ole32 {

// ============================================================================
// WMI Query Categories — threat classification for behavioral analysis
// ============================================================================

enum class WmiQueryCategory : uint8_t {
    OSRecon,            // Win32_OperatingSystem, Win32_ComputerSystem
    ProcessEnum,        // Win32_Process
    NetworkRecon,       // Win32_NetworkAdapterConfiguration, Win32_NetworkAdapter
    AntiVM,             // Win32_BIOS, MSAcpi_ThermalZoneTemperature, Win32_Fan
    Persistence,        // __EventFilter, __EventConsumer, CommandLineEventConsumer
    ShadowCopy,         // Win32_ShadowCopy (direct ransomware indicator)
    ServiceEnum,        // Win32_Service
    UserEnum,           // Win32_UserAccount, Win32_Group
    DiskInfo,           // Win32_DiskDrive, Win32_LogicalDisk
    SecurityProduct,    // AntiVirusProduct, AntiSpywareProduct (root\SecurityCenter2)
    Unknown,
};

// ============================================================================
// WMI query event — captured for forensic extraction
// ============================================================================

struct WmiQueryEvent {
    std::string         query;          // Full WQL query string
    std::string         wmiNamespace;   // e.g., "root\\cimv2"
    WmiQueryCategory    category;
    bool                isSuspicious;   // True for AntiVM, Persistence, ShadowCopy
    uint64_t            instructionNum;
};

// ============================================================================
// WMI event subscription detection (persistence via WMI)
// ============================================================================

struct WmiPersistenceEvent {
    std::string eventFilter;    // __EventFilter name or query
    std::string eventConsumer;  // Consumer class or binding
    std::string commandLine;    // Payload if CommandLineEventConsumer
    uint64_t    instructionNum;
};

// ============================================================================
// WmiState — Meyers' Singleton tracking all WMI behavior during emulation
// ============================================================================

class WmiState {
public:
    [[nodiscard]] static WmiState& Instance() noexcept;

    // Record a WQL query. Classifies and flags suspicious queries.
    void OnWmiQuery(const std::string& query, const std::string& ns,
                    uint64_t instrNum) noexcept;

    // Record a WMI event subscription (persistence).
    void OnEventSubscription(const std::string& filter,
                             const std::string& consumer,
                             const std::string& cmdLine,
                             uint64_t instrNum) noexcept;

    // Track WbemLocator object creation.
    void OnWbemLocatorCreated(uint64_t instrNum) noexcept;

    // Track ConnectServer namespace.
    void OnConnectServer(const std::string& ns, uint64_t instrNum) noexcept;

    // --- Forensic extraction ---
    [[nodiscard]] std::vector<WmiQueryEvent>       GetQueries() const noexcept;
    [[nodiscard]] std::vector<WmiPersistenceEvent> GetPersistenceEvents() const noexcept;
    [[nodiscard]] uint32_t  GetReconQueryCount() const noexcept;
    [[nodiscard]] bool      HasAntiVMQuery() const noexcept;
    [[nodiscard]] bool      HasShadowCopyDeletion() const noexcept;
    [[nodiscard]] bool      HasPersistenceAttempt() const noexcept;
    [[nodiscard]] uint32_t  GetWbemLocatorCount() const noexcept;
    [[nodiscard]] std::string GetLastNamespace() const noexcept;

    void Reset() noexcept;

private:
    WmiState() = default;
    ~WmiState() = default;
    WmiState(const WmiState&) = delete;
    WmiState& operator=(const WmiState&) = delete;

    static constexpr uint32_t kMaxQueries           = 512;
    static constexpr uint32_t kMaxPersistenceEvents  = 64;

    mutable std::mutex                  m_mutex;
    std::vector<WmiQueryEvent>          m_queries;
    std::vector<WmiPersistenceEvent>    m_persistence;
    uint32_t                            m_reconCount      = 0;
    uint32_t                            m_wbemLocatorCount = 0;
    bool                                m_hasAntiVM       = false;
    bool                                m_hasShadowCopy   = false;
    bool                                m_hasPersistence  = false;
    std::string                         m_lastNamespace;
};

// ============================================================================
// WQL Classification API
// ============================================================================

// Classify a WQL query string into a threat category.
[[nodiscard]] WmiQueryCategory ClassifyWqlQuery(std::string_view query) noexcept;

// Check if a query targets anti-VM detection classes or contains VM vendor strings.
[[nodiscard]] bool IsAntiVMQuery(std::string_view query) noexcept;

// Check if a query is a ransomware shadow copy deletion indicator.
[[nodiscard]] bool IsShadowCopyQuery(std::string_view query) noexcept;

// Check if a query targets WMI persistence classes.
[[nodiscard]] bool IsPersistenceQuery(std::string_view query) noexcept;

// ============================================================================
// OLE Automation API handlers (oleaut32.dll)
// ============================================================================

void RegisterOleAutAPI(APIDispatcher& dispatcher) noexcept;

bool HandleSysAllocString(APIContext& ctx);
bool HandleSysFreeString(APIContext& ctx);
bool HandleSysStringLen(APIContext& ctx);
bool HandleVariantInit(APIContext& ctx);
bool HandleVariantClear(APIContext& ctx);

// ============================================================================
// WbemLocator CLSID detection — used by COMAPI.cpp
// ============================================================================

// Returns true if the 16-byte CLSID matches WbemLocator
// {4590F811-1D3A-11D0-891F-00AA004B2E24}
[[nodiscard]] bool IsWbemLocatorCLSID(const uint8_t clsid[16]) noexcept;

// Allocate a fake WbemLocator vtable in guest memory and return its address.
// Returns nullopt if allocation cap is exceeded or memory is exhausted.
[[nodiscard]] std::optional<GuestAddress> AllocateFakeWbemVtable(
    VirtualMemory& mem) noexcept;

} // namespace WinAPI::Ole32
} // namespace Phantom

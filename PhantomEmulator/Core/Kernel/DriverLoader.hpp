/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * DriverLoader.hpp — Kernel-mode driver (.sys) loader for rootkit analysis
 *
 * Loads Windows kernel-mode drivers into the emulated kernel address space.
 * Parses PE/COFF headers, maps sections, processes relocations, resolves
 * kernel imports (ntoskrnl.exe, HAL.dll, ndis.sys), creates DRIVER_OBJECT
 * and DEVICE_OBJECT structures, and invokes DriverEntry. All loaded modules
 * are tracked for integrity verification and behavioral analysis.
 *
 * Thread-safe: shared_mutex protects all mutable state.
 * Singleton: Meyers' singleton — one loader per emulation session.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../../Common/Types.hpp"
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace Phantom {

// Forward declarations
class VirtualMemory;

// ============================================================================
// PE section info extracted from driver
// ============================================================================

struct DriverSection {
    std::string  name;
    GuestAddress virtualAddress;
    uint32_t     virtualSize;
    uint32_t     rawDataSize;
    uint32_t     characteristics;
    bool         isExecutable;
    bool         isWritable;
    bool         isDiscardable;
};

// ============================================================================
// Import entry resolved from the driver
// ============================================================================

struct DriverImport {
    std::string  moduleName;      // e.g., "ntoskrnl.exe"
    std::string  functionName;    // e.g., "ExAllocatePoolWithTag"
    uint16_t     ordinal;         // If imported by ordinal
    GuestAddress iatEntry;        // Guest address of IAT slot
    GuestAddress resolvedAddress; // Address of our stub/hook
    bool         resolved;
};

// ============================================================================
// Loaded driver module descriptor
// ============================================================================

struct LoadedDriver {
    std::string     name;
    std::string     fullPath;
    GuestAddress    imageBase;
    GuestSize       imageSize;
    GuestAddress    entryPoint;
    GuestAddress    driverObject;   // Emulated DRIVER_OBJECT
    std::vector<DriverSection> sections;
    std::vector<DriverImport>  imports;

    // Security analysis results
    bool hasDispatchCreate  = false;
    bool hasDispatchClose   = false;
    bool hasDispatchIOCTL   = false;
    bool hasDispatchRead    = false;
    bool hasDispatchWrite   = false;
    bool hasUnloadRoutine   = false;

    // Suspicious indicators
    bool accessesSSDT       = false;
    bool accessesIDT        = false;
    bool modifiesCR0        = false;
    bool disablesWP         = false;    // CR0.WP = 0
    bool usesMMAPIO         = false;
    bool usesDirectIO       = false;
    bool callsKeAttachProcess = false;
    bool manipulatesPEB     = false;

    uint32_t    relocCount  = 0;
    uint32_t    importCount = 0;
    uint64_t    loadTimestamp = 0;
};

// ============================================================================
// Kernel export stub for import resolution
// ============================================================================

struct KernelExport {
    std::string  moduleName;
    std::string  functionName;
    GuestAddress stubAddress;
    bool         isHooked;
};

// ============================================================================
// DriverLoader — Loads kernel-mode drivers into emulated kernel space
// ============================================================================

class DriverLoader {
public:
    static DriverLoader& Instance();
    void Reset();

    // Initialize with references to memory subsystem
    bool Initialize(VirtualMemory& memory);

    // Core loading API
    [[nodiscard]] std::optional<LoadedDriver> LoadDriver(
        std::span<const uint8_t> driverImage,
        const std::string& driverName,
        GuestAddress preferredBase = 0);

    // Unload a previously loaded driver
    bool UnloadDriver(const std::string& driverName);

    // Validate a PE is a valid kernel-mode driver
    [[nodiscard]] static bool IsValidKernelDriver(std::span<const uint8_t> image);

    // Query loaded drivers
    [[nodiscard]] const LoadedDriver* FindDriver(const std::string& name) const;
    [[nodiscard]] const LoadedDriver* FindDriverByAddress(GuestAddress addr) const;
    [[nodiscard]] std::vector<const LoadedDriver*> GetLoadedDrivers() const;
    [[nodiscard]] uint32_t GetDriverCount() const;

    // Kernel export resolution
    [[nodiscard]] std::optional<GuestAddress> ResolveKernelExport(
        const std::string& moduleName, const std::string& functionName) const;
    [[nodiscard]] const std::vector<KernelExport>& GetRegisteredExports() const;

    // Security analysis
    struct DriverSecurityReport {
        std::string driverName;
        uint32_t    unresolvedImports;
        bool        hasSuspiciousImports;
        bool        isPackedOrEncrypted;
        float       entropy;
        std::vector<std::string> suspiciousAPIs;
        std::vector<std::string> mitreTechniques;
    };
    [[nodiscard]] DriverSecurityReport AnalyzeDriverSecurity(const LoadedDriver& driver) const;

    // Register additional kernel exports (for custom module stubs)
    void RegisterKernelExport(const std::string& module, const std::string& function,
                              GuestAddress addr);

    // Statistics
    [[nodiscard]] GuestSize GetTotalMappedSize() const;
    [[nodiscard]] uint32_t GetTotalImportCount() const;

private:
    DriverLoader();
    ~DriverLoader();

    DriverLoader(const DriverLoader&) = delete;
    DriverLoader& operator=(const DriverLoader&) = delete;
    DriverLoader(DriverLoader&&) = delete;
    DriverLoader& operator=(DriverLoader&&) = delete;

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom

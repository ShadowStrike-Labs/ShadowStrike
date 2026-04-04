/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ServiceAPI.cpp — Advapi32 Service Control Manager API handler implementations
 *
 * Service creation is a major persistence IOC (MITRE T1543.003).
 * All service operations succeed and are recorded for behavioral analysis.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "ServiceAPI.hpp"
#include "../APIDispatcher.hpp"

#include <cstring>
#include <map>
#include <mutex>
#include <string>

namespace Phantom::WinAPI::Advapi32 {

// ============================================================================
// Win32 service constants (no windows.h dependency)
// ============================================================================

static constexpr uint32_t ERROR_SUCCESS            = 0;
static constexpr uint32_t ERROR_INVALID_HANDLE     = 6;
static constexpr uint32_t ERROR_INVALID_PARAMETER  = 87;
static constexpr uint32_t ERROR_SERVICE_DOES_NOT_EXIST = 1060;
static constexpr uint32_t ERROR_SERVICE_EXISTS     = 1073;

static constexpr uint32_t SC_MANAGER_ALL_ACCESS    = 0x000F003F;
static constexpr uint32_t SERVICE_ALL_ACCESS       = 0x000F01FF;

// ============================================================================
// Virtual Service Database
// ============================================================================

struct VirtualServiceEntry {
    std::wstring serviceName;
    std::wstring displayName;
    std::wstring binaryPath;
    uint32_t     serviceType  = 0x10; // SERVICE_WIN32_OWN_PROCESS
    uint32_t     startType    = 0x03; // SERVICE_DEMAND_START
    bool         running      = false;
};

class VirtualServiceDB {
public:
    static VirtualServiceDB& Instance() noexcept {
        static VirtualServiceDB s_instance;
        return s_instance;
    }

    [[nodiscard]] bool ServiceExists(const std::wstring& name) const noexcept {
        std::shared_lock lock(m_mutex);
        return m_services.contains(name);
    }

    [[nodiscard]] bool CreateService(const std::wstring& name, const std::wstring& display,
                                      const std::wstring& binary, uint32_t svcType,
                                      uint32_t startType) noexcept {
        std::unique_lock lock(m_mutex);
        if (m_services.contains(name)) return false;
        if (m_services.size() >= kMaxServices) return false;

        VirtualServiceEntry entry;
        entry.serviceName = name;
        entry.displayName = display;
        entry.binaryPath  = binary;
        entry.serviceType = svcType;
        entry.startType   = startType;
        m_services[name]  = std::move(entry);
        return true;
    }

    [[nodiscard]] bool StartService(const std::wstring& name) noexcept {
        std::unique_lock lock(m_mutex);
        auto it = m_services.find(name);
        if (it == m_services.end()) return false;
        it->second.running = true;
        return true;
    }

    [[nodiscard]] bool DeleteService(const std::wstring& name) noexcept {
        std::unique_lock lock(m_mutex);
        return m_services.erase(name) > 0;
    }

private:
    VirtualServiceDB() noexcept = default;

    static constexpr uint32_t kMaxServices = 4096;

    mutable std::shared_mutex                        m_mutex;
    std::map<std::wstring, VirtualServiceEntry>      m_services;
};

// ============================================================================
// Handle Data for SC_HANDLE: We store the service name in SyncObjectData.name
// HandleType::Event is used as a surrogate — SC_HANDLE has no dedicated type.
// ============================================================================

static std::wstring NarrowToWide(std::string_view s) noexcept {
    std::wstring w;
    w.reserve(s.size());
    for (char c : s) w.push_back(static_cast<wchar_t>(static_cast<uint8_t>(c)));
    return w;
}

// ============================================================================
// OpenSCManagerA/W
// ============================================================================

static bool OpenSCManagerImpl(APIContext& ctx, bool /*isWide*/) {
    // arg0 = lpMachineName (ignored — local only)
    // arg1 = lpDatabaseName (ignored)
    // arg2 = dwDesiredAccess

    SyncObjectData scmData;
    scmData.name     = L"SCManager";
    scmData.signaled = true;

    GuestHandle scmHandle = ctx.Handles().Create(HandleType::Event, std::move(scmData));

    ctx.SetReturnHandle(scmHandle);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

bool HandleOpenSCManagerA(APIContext& ctx) { return OpenSCManagerImpl(ctx, false); }
bool HandleOpenSCManagerW(APIContext& ctx) { return OpenSCManagerImpl(ctx, true); }

// ============================================================================
// CreateServiceA/W — MITRE T1543.003
// ============================================================================

static bool CreateServiceImpl(APIContext& ctx, bool isWide) {
    // arg0  = hSCManager
    // arg1  = lpServiceName
    // arg2  = lpDisplayName
    // arg3  = dwDesiredAccess
    // arg4  = dwServiceType
    // arg5  = dwStartType
    // arg6  = dwErrorControl
    // arg7  = lpBinaryPathName
    // arg8  = lpLoadOrderGroup
    // arg9  = lpdwTagId
    // arg10 = lpDependencies
    // arg11 = lpServiceStartName
    // arg12 = lpPassword

    GuestHandle hSCM = ctx.GetArg(0);
    if (!ctx.Handles().IsValid(hSCM)) {
        ctx.FailWithInvalidHandle(ERROR_INVALID_HANDLE);
        return true;
    }

    GuestAddress lpName    = ctx.GetArgPtr(1);
    GuestAddress lpDisplay = ctx.GetArgPtr(2);
    uint32_t svcType       = ctx.GetArg32(4);
    uint32_t startType     = ctx.GetArg32(5);
    GuestAddress lpBinary  = ctx.GetArgPtr(7);

    std::wstring svcName = isWide ? ctx.ReadWideString(lpName)
                                   : NarrowToWide(ctx.ReadAnsiString(lpName));
    std::wstring displayName = isWide ? ctx.ReadWideString(lpDisplay)
                                       : NarrowToWide(ctx.ReadAnsiString(lpDisplay));
    std::wstring binaryPath = isWide ? ctx.ReadWideString(lpBinary)
                                      : NarrowToWide(ctx.ReadAnsiString(lpBinary));

    if (svcName.empty()) {
        ctx.FailWithError(ERROR_INVALID_PARAMETER);
        return true;
    }

    if (VirtualServiceDB::Instance().ServiceExists(svcName)) {
        ctx.FailWithError(ERROR_SERVICE_EXISTS);
        return true;
    }

    VirtualServiceDB::Instance().CreateService(svcName, displayName, binaryPath,
                                                svcType, startType);

    // Create a handle for the new service
    SyncObjectData svcData;
    svcData.name     = svcName;
    svcData.signaled = false;

    GuestHandle svcHandle = ctx.Handles().Create(HandleType::Event, std::move(svcData));

    ctx.SetReturnHandle(svcHandle);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

bool HandleCreateServiceA(APIContext& ctx) { return CreateServiceImpl(ctx, false); }
bool HandleCreateServiceW(APIContext& ctx) { return CreateServiceImpl(ctx, true); }

// ============================================================================
// StartServiceA/W
// ============================================================================

static bool StartServiceImpl(APIContext& ctx, bool /*isWide*/) {
    // arg0 = hService
    // arg1 = dwNumServiceArgs
    // arg2 = lpServiceArgVectors

    GuestHandle hService = ctx.GetArg(0);

    auto entry = ctx.Handles().Lookup(hService);
    if (!entry.has_value()) {
        ctx.FailWithError(ERROR_INVALID_HANDLE);
        return true;
    }

    auto* syncData = std::get_if<SyncObjectData>(&entry->data);
    if (!syncData) {
        ctx.FailWithError(ERROR_INVALID_HANDLE);
        return true;
    }

    if (!VirtualServiceDB::Instance().StartService(syncData->name)) {
        ctx.FailWithError(ERROR_SERVICE_DOES_NOT_EXIST);
        return true;
    }

    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

bool HandleStartServiceA(APIContext& ctx) { return StartServiceImpl(ctx, false); }
bool HandleStartServiceW(APIContext& ctx) { return StartServiceImpl(ctx, true); }

// ============================================================================
// OpenServiceA/W
// ============================================================================

static bool OpenServiceImpl(APIContext& ctx, bool isWide) {
    // arg0 = hSCManager
    // arg1 = lpServiceName
    // arg2 = dwDesiredAccess

    GuestHandle hSCM = ctx.GetArg(0);
    if (!ctx.Handles().IsValid(hSCM)) {
        ctx.FailWithInvalidHandle(ERROR_INVALID_HANDLE);
        return true;
    }

    GuestAddress lpName = ctx.GetArgPtr(1);
    std::wstring svcName = isWide ? ctx.ReadWideString(lpName)
                                   : NarrowToWide(ctx.ReadAnsiString(lpName));

    if (!VirtualServiceDB::Instance().ServiceExists(svcName)) {
        ctx.FailWithInvalidHandle(ERROR_SERVICE_DOES_NOT_EXIST);
        return true;
    }

    SyncObjectData svcData;
    svcData.name     = svcName;
    svcData.signaled = false;

    GuestHandle svcHandle = ctx.Handles().Create(HandleType::Event, std::move(svcData));

    ctx.SetReturnHandle(svcHandle);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

bool HandleOpenServiceA(APIContext& ctx) { return OpenServiceImpl(ctx, false); }
bool HandleOpenServiceW(APIContext& ctx) { return OpenServiceImpl(ctx, true); }

// ============================================================================
// DeleteService
// ============================================================================

bool HandleDeleteService(APIContext& ctx) {
    // arg0 = hService

    GuestHandle hService = ctx.GetArg(0);

    auto entry = ctx.Handles().Lookup(hService);
    if (!entry.has_value()) {
        ctx.FailWithError(ERROR_INVALID_HANDLE);
        return true;
    }

    auto* syncData = std::get_if<SyncObjectData>(&entry->data);
    if (!syncData) {
        ctx.FailWithError(ERROR_INVALID_HANDLE);
        return true;
    }

    VirtualServiceDB::Instance().DeleteService(syncData->name);

    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// CloseServiceHandle
// ============================================================================

bool HandleCloseServiceHandle(APIContext& ctx) {
    // arg0 = hSCObject

    GuestHandle handle = ctx.GetArg(0);

    if (!ctx.Handles().Close(handle)) {
        ctx.FailWithError(ERROR_INVALID_HANDLE);
        return true;
    }

    ctx.SetReturnBool(true);
    ctx.SetLastError(ERROR_SUCCESS);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterServiceAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "advapi32.dll", "OpenSCManagerA",     HandleOpenSCManagerA,     3,  false },
        { "advapi32.dll", "OpenSCManagerW",     HandleOpenSCManagerW,     3,  false },
        { "advapi32.dll", "CreateServiceA",     HandleCreateServiceA,     13, false },
        { "advapi32.dll", "CreateServiceW",     HandleCreateServiceW,     13, false },
        { "advapi32.dll", "StartServiceA",      HandleStartServiceA,      3,  false },
        { "advapi32.dll", "StartServiceW",      HandleStartServiceW,      3,  false },
        { "advapi32.dll", "OpenServiceA",       HandleOpenServiceA,       3,  false },
        { "advapi32.dll", "OpenServiceW",       HandleOpenServiceW,       3,  false },
        { "advapi32.dll", "DeleteService",      HandleDeleteService,      1,  false },
        { "advapi32.dll", "CloseServiceHandle", HandleCloseServiceHandle, 1,  false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Advapi32

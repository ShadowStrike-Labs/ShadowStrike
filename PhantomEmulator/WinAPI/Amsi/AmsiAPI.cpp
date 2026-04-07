/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * AmsiAPI.cpp — AMSI antimalware scan interface emulation
 *
 * AMSI bypass is the #1 technique used by modern malware and red-team
 * tooling before payload execution. Every fileless attack (PowerShell,
 * VBScript, .NET assembly load) flows through AMSI. This module:
 *
 *   - Captures scan content submitted via AmsiScanBuffer / AmsiScanString
 *     for forensic extraction (the actual malicious script/shellcode)
 *   - Returns AMSI_RESULT_DETECTED, forcing malware to reveal its bypass
 *     logic before running the real payload
 *   - Tracks bypass patterns: memory patching of AmsiScanBuffer bytes,
 *     VirtualProtect on AMSI regions, amsiInitFailed flag manipulation,
 *     and DLL side-loading of a fake amsi.dll
 *   - Records the AMSI consumer identity (powershell.exe, wscript.exe,
 *     cscript.exe, etc.) for behavioral context
 *
 * Design decisions:
 *   - Scan content is capped at 64 KB per call (defense against hostile
 *     allocations; 99% of real AMSI submissions are under 16 KB)
 *   - Total captured scans capped at 256 (ring buffer not needed; malware
 *     that does 256+ AMSI scans is already fully profiled)
 *   - Pseudo-handle IDs use the 0xAM range to avoid collision with BCrypt
 *     (0xBC range) and kernel handles
 *   - No real antimalware scanning — we ARE the scanner
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "AmsiAPI.hpp"
#include "../APIDispatcher.hpp"

#include <atomic>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <algorithm>

namespace Phantom::WinAPI::Amsi {

// ============================================================================
// Internal emulator-side objects
// ============================================================================

struct EmulatedAmsiContext {
    uint32_t    id          = 0;
    std::string appName;                 // Consumer application name
    uint32_t    sessionCount = 0;        // Active sessions
    bool        active      = true;
};

struct EmulatedAmsiSession {
    uint32_t    id          = 0;
    uint32_t    contextId   = 0;         // Owning context
    uint32_t    scanCount   = 0;         // Scans performed in this session
    bool        active      = true;
};

// ============================================================================
// AmsiStateImpl — Internal state backing the Meyers' singleton
// ============================================================================

struct AmsiStateImpl {
    mutable std::mutex                                       mutex;
    std::unordered_map<uint32_t, EmulatedAmsiContext>         contexts;
    std::unordered_map<uint32_t, EmulatedAmsiSession>        sessions;
    std::vector<CapturedAmsiScan>                            capturedScans;
    std::vector<AmsiBypassEvent>                             bypassEvents;
    std::atomic<uint32_t>                                    nextId{ 0xA5100001 };
    std::atomic<uint32_t>                                    totalScans{ 0 };
    std::atomic<bool>                                        amsiPatched{ false };

    // Notification tracking
    std::atomic<uint32_t>                                    notifyCount{ 0 };

    [[nodiscard]] uint32_t AllocId() noexcept {
        return nextId.fetch_add(1, std::memory_order_relaxed);
    }
};

// Handle ID range 0xA510xxxx — disjoint from BCrypt (0xBC00xxxx) and kernel handles
static AmsiStateImpl& GetState() noexcept {
    static AmsiStateImpl s_state;
    return s_state;
}

// ============================================================================
// AmsiState singleton implementation
// ============================================================================

AmsiState& AmsiState::Instance() noexcept {
    static AmsiState s_instance;
    return s_instance;
}

std::vector<CapturedAmsiScan> AmsiState::GetCapturedScans() const noexcept {
    auto& st = GetState();
    std::lock_guard lock(st.mutex);
    return st.capturedScans;
}

std::vector<AmsiBypassEvent> AmsiState::GetBypassEvents() const noexcept {
    auto& st = GetState();
    std::lock_guard lock(st.mutex);
    return st.bypassEvents;
}

uint32_t AmsiState::GetScanCount() const noexcept {
    return GetState().totalScans.load(std::memory_order_relaxed);
}

bool AmsiState::WasAmsiPatched() const noexcept {
    return GetState().amsiPatched.load(std::memory_order_relaxed);
}

void AmsiState::RecordBypassEvent(AmsiBypassEvent::Type type, GuestAddress addr,
                                  uint64_t instrNum) noexcept {
    auto& st = GetState();
    std::lock_guard lock(st.mutex);

    if (st.bypassEvents.size() >= kMaxBypassEvents) {
        return;
    }

    AmsiBypassEvent evt;
    evt.type           = type;
    evt.address        = addr;
    evt.instructionNum = instrNum;
    st.bypassEvents.push_back(evt);

    if (type == AmsiBypassEvent::Type::PatchDetected) {
        st.amsiPatched.store(true, std::memory_order_relaxed);
    }
}

void AmsiState::Reset() noexcept {
    auto& st = GetState();
    std::lock_guard lock(st.mutex);
    st.contexts.clear();
    st.sessions.clear();
    st.capturedScans.clear();
    st.bypassEvents.clear();
    st.totalScans.store(0, std::memory_order_relaxed);
    st.amsiPatched.store(false, std::memory_order_relaxed);
    st.notifyCount.store(0, std::memory_order_relaxed);
    st.nextId.store(0xA5100001, std::memory_order_relaxed);
}

// ============================================================================
// Narrow-string helpers (no windows.h dependency)
// ============================================================================

static std::string WideToNarrow(const std::wstring& ws) noexcept {
    std::string s;
    s.reserve(ws.size());
    for (wchar_t wc : ws) {
        s.push_back(static_cast<char>(wc & 0x7F));
    }
    return s;
}

// ============================================================================
// Lookup helpers
// ============================================================================

static EmulatedAmsiContext* LookupContext(uint32_t id) noexcept {
    auto& st = GetState();
    auto it = st.contexts.find(id);
    if (it != st.contexts.end() && it->second.active) {
        return &it->second;
    }
    return nullptr;
}

static EmulatedAmsiSession* LookupSession(uint32_t id) noexcept {
    auto& st = GetState();
    auto it = st.sessions.find(id);
    if (it != st.sessions.end() && it->second.active) {
        return &it->second;
    }
    return nullptr;
}

// ============================================================================
// Scan content capture helper
// ============================================================================

static void CaptureScanContent(const std::string& appName,
                               const std::string& contentName,
                               const uint8_t* data, uint32_t dataSize,
                               uint32_t result, uint64_t instrNum) noexcept {
    auto& st = GetState();
    // Caller must hold st.mutex

    if (st.capturedScans.size() >= kMaxCapturedScans) {
        return;
    }

    CapturedAmsiScan scan;
    scan.appName        = appName;
    scan.contentName    = contentName;
    scan.originalSize   = dataSize;
    scan.result         = result;
    scan.instructionNum = instrNum;

    uint32_t captureSize = std::min(dataSize, kMaxScanContentCapture);
    scan.content.assign(data, data + captureSize);

    st.capturedScans.push_back(std::move(scan));
}

// ============================================================================
// AmsiInitialize
// ============================================================================
// HRESULT AmsiInitialize(LPCWSTR appName, HAMSICONTEXT *amsiContext)
//
// Creates an emulated AMSI context. Tracks the application identity
// (powershell.exe, wscript.exe, etc.) for behavioral profiling.

bool HandleAmsiInitialize(APIContext& ctx) {
    GuestAddress pAppName     = ctx.GetArgPtr(0);
    GuestAddress pAmsiContext = ctx.GetArgPtr(1);

    if (pAmsiContext == 0) {
        ctx.SetReturn(static_cast<uint64_t>(E_INVALIDARG));
        return true;
    }

    // Read application name — may be null (some callers pass nullptr)
    std::string appName;
    if (pAppName != 0) {
        std::wstring appNameWide = ctx.ReadWideString(pAppName, kMaxAppNameLen);
        appName = WideToNarrow(appNameWide);
    }

    auto& st = GetState();
    std::lock_guard lock(st.mutex);

    if (st.contexts.size() >= kMaxAmsiContexts) {
        ctx.SetReturn(static_cast<uint64_t>(E_OUTOFMEMORY));
        return true;
    }

    EmulatedAmsiContext amsiCtx;
    amsiCtx.id       = st.AllocId();
    amsiCtx.appName  = std::move(appName);
    amsiCtx.active   = true;

    uint32_t handleId = amsiCtx.id;
    st.contexts.emplace(handleId, std::move(amsiCtx));

    // Write pseudo-handle to guest output pointer
    if (ctx.Is64Bit()) {
        ctx.Memory().WriteU64(pAmsiContext, static_cast<uint64_t>(handleId));
    } else {
        ctx.Memory().WriteU32(pAmsiContext, handleId);
    }

    // AMSI initialization by a sample is noteworthy — many legitimate apps
    // call this, but in a sandbox context it reveals the sample acts as an
    // AMSI consumer (or is probing AMSI availability for bypass planning)
    ctx.AddBehaviorFlag(BehaviorFlag::DefenseEvasion);

    ctx.SetReturn(static_cast<uint64_t>(S_OK));
    return true;
}

// ============================================================================
// AmsiOpenSession
// ============================================================================
// HRESULT AmsiOpenSession(HAMSICONTEXT amsiContext, HAMSISESSION *session)

bool HandleAmsiOpenSession(APIContext& ctx) {
    uint32_t     contextId = ctx.GetArg32(0);
    GuestAddress pSession  = ctx.GetArgPtr(1);

    if (pSession == 0) {
        ctx.SetReturn(static_cast<uint64_t>(E_INVALIDARG));
        return true;
    }

    auto& st = GetState();
    std::lock_guard lock(st.mutex);

    EmulatedAmsiContext* amsiCtx = LookupContext(contextId);
    if (!amsiCtx) {
        ctx.SetReturn(static_cast<uint64_t>(E_NOT_VALID_STATE));
        return true;
    }

    if (amsiCtx->sessionCount >= kMaxSessionsPerContext) {
        ctx.SetReturn(static_cast<uint64_t>(E_OUTOFMEMORY));
        return true;
    }

    EmulatedAmsiSession session;
    session.id        = st.AllocId();
    session.contextId = contextId;
    session.active    = true;

    uint32_t sessionId = session.id;
    st.sessions.emplace(sessionId, std::move(session));
    amsiCtx->sessionCount++;

    if (ctx.Is64Bit()) {
        ctx.Memory().WriteU64(pSession, static_cast<uint64_t>(sessionId));
    } else {
        ctx.Memory().WriteU32(pSession, sessionId);
    }

    ctx.SetReturn(static_cast<uint64_t>(S_OK));
    return true;
}

// ============================================================================
// AmsiCloseSession
// ============================================================================
// void AmsiCloseSession(HAMSICONTEXT amsiContext, HAMSISESSION session)

bool HandleAmsiCloseSession(APIContext& ctx) {
    uint32_t contextId = ctx.GetArg32(0);
    uint32_t sessionId = ctx.GetArg32(1);

    auto& st = GetState();
    std::lock_guard lock(st.mutex);

    EmulatedAmsiContext* amsiCtx = LookupContext(contextId);
    auto sessIt = st.sessions.find(sessionId);

    if (sessIt != st.sessions.end() && sessIt->second.active) {
        sessIt->second.active = false;
        if (amsiCtx && amsiCtx->sessionCount > 0) {
            amsiCtx->sessionCount--;
        }
        st.sessions.erase(sessIt);
    }

    // AmsiCloseSession returns void — set return to 0 for the emulator
    ctx.SetReturn(0);
    return true;
}

// ============================================================================
// AmsiUninitialize
// ============================================================================
// void AmsiUninitialize(HAMSICONTEXT amsiContext)

bool HandleAmsiUninitialize(APIContext& ctx) {
    uint32_t contextId = ctx.GetArg32(0);

    auto& st = GetState();
    std::lock_guard lock(st.mutex);

    auto ctxIt = st.contexts.find(contextId);
    if (ctxIt != st.contexts.end()) {
        // Clean up all sessions owned by this context
        for (auto it = st.sessions.begin(); it != st.sessions.end(); ) {
            if (it->second.contextId == contextId) {
                it = st.sessions.erase(it);
            } else {
                ++it;
            }
        }
        st.contexts.erase(ctxIt);
    }

    // AmsiUninitialize returns void
    ctx.SetReturn(0);
    return true;
}

// ============================================================================
// AmsiScanBuffer — THE critical function
// ============================================================================
// HRESULT AmsiScanBuffer(
//     HAMSICONTEXT amsiContext,   // arg0
//     PVOID        buffer,        // arg1 — guest pointer to content
//     ULONG        length,        // arg2 — buffer size in bytes
//     LPCWSTR      contentName,   // arg3 — display name for content
//     HAMSISESSION amsiSession,   // arg4
//     AMSI_RESULT* result         // arg5 — output scan result
//     // arg6 is reserved in some calling conventions
// )
//
// This is the function malware patches to bypass AMSI. We:
// 1. Read the scan content from guest memory (forensic capture)
// 2. Store it for later extraction
// 3. Return AMSI_RESULT_DETECTED (simulating a blocking security product)
// 4. Flag DefenseEvasion behavior

bool HandleAmsiScanBuffer(APIContext& ctx) {
    uint32_t     contextId   = ctx.GetArg32(0);
    GuestAddress pBuffer     = ctx.GetArgPtr(1);
    uint32_t     length      = ctx.GetArg32(2);
    GuestAddress pContentName = ctx.GetArgPtr(3);
    uint32_t     sessionId   = ctx.GetArg32(4);
    GuestAddress pResult     = ctx.GetArgPtr(5);

    // Validate required output pointer
    if (pResult == 0) {
        ctx.SetReturn(static_cast<uint64_t>(E_INVALIDARG));
        return true;
    }

    // Validate buffer pointer and length
    if (pBuffer == 0 || length == 0) {
        // Write AMSI_RESULT_CLEAN for empty/null buffers (matches Windows behavior)
        ctx.Memory().WriteU32(pResult, AMSI_RESULT_CLEAN);
        ctx.SetReturn(static_cast<uint64_t>(E_INVALIDARG));
        return true;
    }

    auto& st = GetState();
    std::lock_guard lock(st.mutex);

    // Resolve context for app name attribution
    std::string appName;
    EmulatedAmsiContext* amsiCtx = LookupContext(contextId);
    if (amsiCtx) {
        appName = amsiCtx->appName;
    }

    // Read content name if provided
    std::string contentName;
    if (pContentName != 0) {
        std::wstring cnWide = ctx.ReadWideString(pContentName, kMaxContentNameLen);
        contentName = WideToNarrow(cnWide);
    }

    // Read scan content from guest memory — capped at kMaxScanContentCapture
    uint32_t readSize = std::min(length, kMaxScanContentCapture);
    std::vector<uint8_t> contentBuf(readSize);

    ErrorCode readErr = ctx.Memory().Read(pBuffer, contentBuf.data(), readSize);
    if (readErr != ErrorCode::Success) {
        // Memory read failed — guest provided bad pointer. Return error.
        ctx.Memory().WriteU32(pResult, AMSI_RESULT_CLEAN);
        ctx.SetReturn(static_cast<uint64_t>(E_INVALIDARG));
        return true;
    }

    // We return DETECTED — simulating a security product that blocks the content.
    // This forces malware to execute its bypass path (which we then detect).
    uint32_t scanResult = AMSI_RESULT_DETECTED;
    ctx.Memory().WriteU32(pResult, scanResult);

    // Capture the scan content for forensic extraction
    CaptureScanContent(appName, contentName, contentBuf.data(),
                       length, scanResult, 0);

    st.totalScans.fetch_add(1, std::memory_order_relaxed);

    // Update session scan count
    EmulatedAmsiSession* session = LookupSession(sessionId);
    if (session) {
        session->scanCount++;
    }

    // Every AMSI scan in a sandbox is significant — tag it
    ctx.AddBehaviorFlag(BehaviorFlag::DefenseEvasion);

    ctx.SetReturn(static_cast<uint64_t>(S_OK));
    return true;
}

// ============================================================================
// AmsiScanString
// ============================================================================
// HRESULT AmsiScanString(
//     HAMSICONTEXT amsiContext,   // arg0
//     LPCWSTR      string,        // arg1 — guest pointer to wide string
//     LPCWSTR      contentName,   // arg2
//     HAMSISESSION amsiSession,   // arg3
//     AMSI_RESULT* result         // arg4
// )
//
// Same as AmsiScanBuffer but for null-terminated wide strings.
// We read the string, convert to bytes, and capture it.

bool HandleAmsiScanString(APIContext& ctx) {
    uint32_t     contextId    = ctx.GetArg32(0);
    GuestAddress pString      = ctx.GetArgPtr(1);
    GuestAddress pContentName = ctx.GetArgPtr(2);
    uint32_t     sessionId    = ctx.GetArg32(3);
    GuestAddress pResult      = ctx.GetArgPtr(4);

    if (pResult == 0) {
        ctx.SetReturn(static_cast<uint64_t>(E_INVALIDARG));
        return true;
    }

    if (pString == 0) {
        ctx.Memory().WriteU32(pResult, AMSI_RESULT_CLEAN);
        ctx.SetReturn(static_cast<uint64_t>(E_INVALIDARG));
        return true;
    }

    auto& st = GetState();
    std::lock_guard lock(st.mutex);

    // Resolve context app name
    std::string appName;
    EmulatedAmsiContext* amsiCtx = LookupContext(contextId);
    if (amsiCtx) {
        appName = amsiCtx->appName;
    }

    // Read content name
    std::string contentName;
    if (pContentName != 0) {
        std::wstring cnWide = ctx.ReadWideString(pContentName, kMaxContentNameLen);
        contentName = WideToNarrow(cnWide);
    }

    // Read the wide string from guest memory
    // Cap at kMaxScanContentCapture / 2 chars to stay within capture limits
    uint32_t maxChars = kMaxScanContentCapture / sizeof(wchar_t);
    std::wstring wideStr = ctx.ReadWideString(pString, maxChars);

    // Convert wide string to raw bytes for forensic storage
    // Store as UTF-16LE bytes (preserving original encoding)
    uint32_t byteLen = static_cast<uint32_t>(wideStr.size() * sizeof(wchar_t));
    const auto* rawBytes = reinterpret_cast<const uint8_t*>(wideStr.data());

    uint32_t scanResult = AMSI_RESULT_DETECTED;
    ctx.Memory().WriteU32(pResult, scanResult);

    CaptureScanContent(appName, contentName, rawBytes, byteLen,
                       scanResult, 0);

    st.totalScans.fetch_add(1, std::memory_order_relaxed);

    EmulatedAmsiSession* session = LookupSession(sessionId);
    if (session) {
        session->scanCount++;
    }

    ctx.AddBehaviorFlag(BehaviorFlag::DefenseEvasion);

    ctx.SetReturn(static_cast<uint64_t>(S_OK));
    return true;
}

// ============================================================================
// AmsiResultIsMalware
// ============================================================================
// BOOL AmsiResultIsMalware(AMSI_RESULT result)
//
// Per the Windows SDK: result >= 32768 means malware detected.

bool HandleAmsiResultIsMalware(APIContext& ctx) {
    uint32_t result = ctx.GetArg32(0);

    // Windows SDK definition: AmsiResultIsMalware returns TRUE
    // when result >= AMSI_RESULT_DETECTED (32768)
    GuestBool isMalware = (result >= AMSI_RESULT_DETECTED) ? 1 : 0;
    ctx.SetReturn(static_cast<uint64_t>(isMalware));
    return true;
}

// ============================================================================
// AmsiNotifyOperation
// ============================================================================
// HRESULT AmsiNotifyOperation(
//     HAMSICONTEXT amsiContext,   // arg0
//     PVOID        buffer,        // arg1
//     ULONG        length,        // arg2
//     LPCWSTR      contentName,   // arg3
// )
//
// Notification-only path (no scan result output). We track the notification
// count and return S_OK. Content is captured identically to AmsiScanBuffer
// because malware may use this path to probe AMSI without triggering a scan.

bool HandleAmsiNotifyOperation(APIContext& ctx) {
    uint32_t     contextId    = ctx.GetArg32(0);
    GuestAddress pBuffer      = ctx.GetArgPtr(1);
    uint32_t     length       = ctx.GetArg32(2);
    GuestAddress pContentName = ctx.GetArgPtr(3);

    auto& st = GetState();
    std::lock_guard lock(st.mutex);

    st.notifyCount.fetch_add(1, std::memory_order_relaxed);

    // Capture notification content if a buffer is provided
    if (pBuffer != 0 && length > 0) {
        std::string appName;
        EmulatedAmsiContext* amsiCtx = LookupContext(contextId);
        if (amsiCtx) {
            appName = amsiCtx->appName;
        }

        std::string contentName;
        if (pContentName != 0) {
            std::wstring cnWide = ctx.ReadWideString(pContentName, kMaxContentNameLen);
            contentName = WideToNarrow(cnWide);
        }

        uint32_t readSize = std::min(length, kMaxScanContentCapture);
        std::vector<uint8_t> contentBuf(readSize);

        ErrorCode readErr = ctx.Memory().Read(pBuffer, contentBuf.data(), readSize);
        if (readErr == ErrorCode::Success) {
            CaptureScanContent(appName, contentName, contentBuf.data(),
                               length, AMSI_RESULT_CLEAN, 0);
        }
    }

    ctx.SetReturn(static_cast<uint64_t>(S_OK));
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterAmsiAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "amsi.dll", "AmsiInitialize",      HandleAmsiInitialize,      2, false },
        { "amsi.dll", "AmsiOpenSession",     HandleAmsiOpenSession,     2, false },
        { "amsi.dll", "AmsiCloseSession",    HandleAmsiCloseSession,    2, false },
        { "amsi.dll", "AmsiUninitialize",    HandleAmsiUninitialize,    1, false },
        { "amsi.dll", "AmsiScanBuffer",      HandleAmsiScanBuffer,      7, false },
        { "amsi.dll", "AmsiScanString",      HandleAmsiScanString,      5, false },
        { "amsi.dll", "AmsiResultIsMalware", HandleAmsiResultIsMalware, 1, false },
        { "amsi.dll", "AmsiNotifyOperation", HandleAmsiNotifyOperation, 4, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Amsi

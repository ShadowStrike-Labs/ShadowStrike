/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * WmiEmulation.cpp — WMI reconnaissance and persistence detection
 *
 * Implementation of WQL query classification, BSTR management, VARIANT
 * stubs, and WbemLocator fake vtable allocation. Every WMI query executed
 * by malware is captured, classified, and logged for behavioral analysis.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "WmiEmulation.hpp"
#include "../APIDispatcher.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Common/Types.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstring>
#include <mutex>
#include <string>

// DESIGN: Guest-memory writebacks (Read/Write/WriteU32/WriteU64) are
// [[nodiscard]] — a guest AV on writeback is a guest fault.
#pragma warning(push)
#pragma warning(disable : 4834 6031)

namespace Phantom::WinAPI::Ole32 {

// ============================================================================
// Internal Constants
// ============================================================================

// COM HRESULT codes (local to avoid cross-TU linkage issues)
static constexpr int32_t kS_OK          = 0x00000000;
static constexpr int32_t kE_OUTOFMEMORY = static_cast<int32_t>(0x8007000E);
static constexpr int32_t kE_INVALIDARG  = static_cast<int32_t>(0x80070057);
static constexpr int32_t kE_POINTER     = static_cast<int32_t>(0x80004003);

// BSTR layout: [4-byte length prefix][wchar_t data][null terminator]
// The returned pointer points to the start of the data, not the length prefix.
static constexpr uint32_t kBstrLenPrefixSize = 4;
static constexpr uint32_t kBstrNullTermSize  = 2; // sizeof(wchar_t)

// VARIANT is 16 bytes on both x86 and x64.
static constexpr uint32_t kVariantSize = 16;

// Resource caps — prevent malware from exhausting emulator memory
static constexpr uint32_t kMaxBstrAllocations   = 4096;
static constexpr uint64_t kMaxBstrTotalBytes     = 16ULL * 1024 * 1024; // 16 MB
static constexpr uint32_t kMaxBstrStringChars    = 65536;
static constexpr uint32_t kMaxFakeVtableAllocs   = 32;
static constexpr uint32_t kFakeVtableSlots       = 20;

// Fake vtable: 20 function pointer slots × 8 bytes each
static constexpr uint32_t kFakeVtableSizeBytes   = kFakeVtableSlots * sizeof(uint64_t);

// WQL query string max length we'll process
static constexpr uint32_t kMaxWqlQueryLen        = 8192;

// ============================================================================
// BSTR Allocation Tracker — thread-safe with atomic counters
// ============================================================================

namespace {

struct BstrTracker {
    std::atomic<uint32_t> allocCount{0};
    std::atomic<uint64_t> totalBytes{0};

    [[nodiscard]] bool CanAllocate(uint64_t bytes) const noexcept {
        return allocCount.load(std::memory_order_relaxed) < kMaxBstrAllocations
            && (totalBytes.load(std::memory_order_relaxed) + bytes) <= kMaxBstrTotalBytes;
    }

    void RecordAlloc(uint64_t bytes) noexcept {
        allocCount.fetch_add(1, std::memory_order_relaxed);
        totalBytes.fetch_add(bytes, std::memory_order_relaxed);
    }

    void RecordFree(uint64_t bytes) noexcept {
        // Underflow-safe: if somehow we free more than allocated, clamp to 0.
        uint32_t prevCount = allocCount.load(std::memory_order_relaxed);
        if (prevCount > 0) {
            allocCount.fetch_sub(1, std::memory_order_relaxed);
        }
        uint64_t prevBytes = totalBytes.load(std::memory_order_relaxed);
        if (prevBytes >= bytes) {
            totalBytes.fetch_sub(bytes, std::memory_order_relaxed);
        } else {
            totalBytes.store(0, std::memory_order_relaxed);
        }
    }

    void Reset() noexcept {
        allocCount.store(0, std::memory_order_relaxed);
        totalBytes.store(0, std::memory_order_relaxed);
    }
};

BstrTracker& GetBstrTracker() noexcept {
    static BstrTracker tracker;
    return tracker;
}

// Fake vtable allocation counter
std::atomic<uint32_t>& GetVtableAllocCount() noexcept {
    static std::atomic<uint32_t> count{0};
    return count;
}

} // anonymous namespace

// ============================================================================
// Case-insensitive substring search
// ============================================================================

namespace {

// Convert a character to lowercase (ASCII only — WQL is ASCII).
[[nodiscard]] char ToLowerAscii(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
}

// Case-insensitive string-in-string search.
[[nodiscard]] bool ContainsCaseInsensitive(std::string_view haystack,
                                           std::string_view needle) noexcept
{
    if (needle.empty()) return true;
    if (haystack.size() < needle.size()) return false;

    const auto limit = haystack.size() - needle.size();
    for (size_t i = 0; i <= limit; ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            if (ToLowerAscii(haystack[i + j]) != ToLowerAscii(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

// Convert std::wstring to std::string (ASCII range only, for WQL queries).
[[nodiscard]] std::string WideToNarrow(const std::wstring& wide) noexcept {
    std::string result;
    result.reserve(wide.size());
    for (wchar_t wc : wide) {
        if (wc > 0 && wc < 128) {
            result += static_cast<char>(wc);
        } else {
            result += '?';
        }
    }
    return result;
}

} // anonymous namespace

// ============================================================================
// WQL Query Classification — WMI class → threat category mapping
// ============================================================================

// Each entry maps a WMI class name (case-insensitive substring) to a category
// and suspiciousness flag.
namespace {

struct WqlClassMapping {
    const char*      className;
    WmiQueryCategory category;
    bool             isSuspicious;
};

// Order: most specific first, least specific last.
// Anti-VM classes are always suspicious. Persistence and ShadowCopy are always suspicious.
static constexpr WqlClassMapping kWqlClassMappings[] = {
    // Anti-VM detection classes
    { "msacpi_thermalzonetemperature",  WmiQueryCategory::AntiVM,          true  },
    { "win32_fan",                      WmiQueryCategory::AntiVM,          true  },
    { "win32_bios",                     WmiQueryCategory::AntiVM,          true  },
    { "win32_baseboard",                WmiQueryCategory::AntiVM,          true  },
    { "win32_computersystemproduct",    WmiQueryCategory::AntiVM,          true  },
    { "win32_physicalmemory",           WmiQueryCategory::AntiVM,          true  },
    { "win32_portconnector",            WmiQueryCategory::AntiVM,          true  },
    { "win32_pointingdevice",           WmiQueryCategory::AntiVM,          true  },
    { "cim_sensor",                     WmiQueryCategory::AntiVM,          true  },
    { "cim_numericsensor",              WmiQueryCategory::AntiVM,          true  },
    { "cim_temperaturesensor",          WmiQueryCategory::AntiVM,          true  },

    // Ransomware shadow copy deletion
    { "win32_shadowcopy",               WmiQueryCategory::ShadowCopy,      true  },
    { "win32_shadowstorage",            WmiQueryCategory::ShadowCopy,      true  },

    // WMI persistence
    { "commandlineeventconsumer",       WmiQueryCategory::Persistence,     true  },
    { "activescripteventconsumer",      WmiQueryCategory::Persistence,     true  },
    { "smtpeventconsumer",              WmiQueryCategory::Persistence,     true  },
    { "__eventfilter",                  WmiQueryCategory::Persistence,     true  },
    { "__eventconsumer",                WmiQueryCategory::Persistence,     true  },
    { "__filtertoconsumerbinding",      WmiQueryCategory::Persistence,     true  },

    // OS reconnaissance
    { "win32_operatingsystem",          WmiQueryCategory::OSRecon,         false },
    { "win32_computersystem",           WmiQueryCategory::OSRecon,         false },
    { "win32_processor",                WmiQueryCategory::OSRecon,         false },
    { "win32_timezone",                 WmiQueryCategory::OSRecon,         false },

    // Process enumeration
    { "win32_process",                  WmiQueryCategory::ProcessEnum,     false },
    { "win32_startupcommand",           WmiQueryCategory::ProcessEnum,     false },

    // Network reconnaissance
    { "win32_networkadapterconfiguration", WmiQueryCategory::NetworkRecon, false },
    { "win32_networkadapter",           WmiQueryCategory::NetworkRecon,    false },
    { "win32_networkconnection",        WmiQueryCategory::NetworkRecon,    false },
    { "win32_ip4routetable",            WmiQueryCategory::NetworkRecon,    false },

    // Service enumeration
    { "win32_service",                  WmiQueryCategory::ServiceEnum,     false },

    // User/group enumeration
    { "win32_useraccount",              WmiQueryCategory::UserEnum,        false },
    { "win32_group",                    WmiQueryCategory::UserEnum,        false },
    { "win32_groupuser",                WmiQueryCategory::UserEnum,        false },
    { "win32_logonsession",             WmiQueryCategory::UserEnum,        false },
    { "win32_loggedonuser",             WmiQueryCategory::UserEnum,        false },

    // Disk information
    { "win32_diskdrive",                WmiQueryCategory::DiskInfo,        false },
    { "win32_logicaldisk",              WmiQueryCategory::DiskInfo,        false },
    { "win32_diskpartition",            WmiQueryCategory::DiskInfo,        false },
    { "win32_volume",                   WmiQueryCategory::DiskInfo,        false },

    // Security product queries (from root\SecurityCenter2)
    { "antivirusproduct",               WmiQueryCategory::SecurityProduct, true  },
    { "antispywareproduct",             WmiQueryCategory::SecurityProduct, true  },
    { "firewallproduct",                WmiQueryCategory::SecurityProduct, true  },
};

static constexpr uint32_t kWqlClassMappingCount =
    static_cast<uint32_t>(sizeof(kWqlClassMappings) / sizeof(kWqlClassMappings[0]));

} // anonymous namespace

// ============================================================================
// WQL Classification Implementation
// ============================================================================

WmiQueryCategory ClassifyWqlQuery(std::string_view query) noexcept {
    if (query.empty() || query.size() > kMaxWqlQueryLen) {
        return WmiQueryCategory::Unknown;
    }

    for (uint32_t i = 0; i < kWqlClassMappingCount; ++i) {
        if (ContainsCaseInsensitive(query, kWqlClassMappings[i].className)) {
            return kWqlClassMappings[i].category;
        }
    }

    return WmiQueryCategory::Unknown;
}

bool IsAntiVMQuery(std::string_view query) noexcept {
    if (query.empty()) return false;

    // Check class-based anti-VM
    WmiQueryCategory cat = ClassifyWqlQuery(query);
    if (cat == WmiQueryCategory::AntiVM) return true;

    // Check for VM vendor strings in WHERE clauses or query body
    static constexpr const char* kVMIndicators[] = {
        "vmware",
        "virtualbox",
        "vbox",
        "virtual machine",
        "hyper-v",
        "xen",
        "qemu",
        "parallels",
        "bochs",
        "innotek",
        "red hat",
        "oracle",
    };

    for (const auto* indicator : kVMIndicators) {
        if (ContainsCaseInsensitive(query, indicator)) {
            return true;
        }
    }

    // Win32_ComputerSystem with Model check is anti-VM
    if (ContainsCaseInsensitive(query, "win32_computersystem")
        && ContainsCaseInsensitive(query, "model")) {
        return true;
    }

    // Win32_DiskDrive with Model check is anti-VM (VBOX HARDDISK)
    if (ContainsCaseInsensitive(query, "win32_diskdrive")
        && ContainsCaseInsensitive(query, "model")) {
        return true;
    }

    return false;
}

bool IsShadowCopyQuery(std::string_view query) noexcept {
    return ContainsCaseInsensitive(query, "win32_shadowcopy")
        || ContainsCaseInsensitive(query, "win32_shadowstorage");
}

bool IsPersistenceQuery(std::string_view query) noexcept {
    return ContainsCaseInsensitive(query, "__eventfilter")
        || ContainsCaseInsensitive(query, "__eventconsumer")
        || ContainsCaseInsensitive(query, "__filtertoconsumerbinding")
        || ContainsCaseInsensitive(query, "commandlineeventconsumer")
        || ContainsCaseInsensitive(query, "activescripteventconsumer")
        || ContainsCaseInsensitive(query, "smtpeventconsumer");
}

// ============================================================================
// WmiState — Meyers' Singleton Implementation
// ============================================================================

WmiState& WmiState::Instance() noexcept {
    static WmiState instance;
    return instance;
}

void WmiState::OnWmiQuery(const std::string& query, const std::string& ns,
                           uint64_t instrNum) noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_queries.size() >= kMaxQueries) {
        return; // Cap reached — drop silently (defense against query-flood)
    }

    WmiQueryCategory cat = ClassifyWqlQuery(query);
    bool suspicious = false;

    // Determine suspiciousness from the mapping table
    for (uint32_t i = 0; i < kWqlClassMappingCount; ++i) {
        if (ContainsCaseInsensitive(query, kWqlClassMappings[i].className)) {
            suspicious = kWqlClassMappings[i].isSuspicious;
            break;
        }
    }

    // Anti-VM queries via vendor string matching
    if (!suspicious && IsAntiVMQuery(query)) {
        suspicious = true;
        cat = WmiQueryCategory::AntiVM;
    }

    WmiQueryEvent evt;
    evt.query          = query;
    evt.wmiNamespace   = ns;
    evt.category       = cat;
    evt.isSuspicious   = suspicious;
    evt.instructionNum = instrNum;
    m_queries.push_back(std::move(evt));

    // Update aggregate counters
    if (cat != WmiQueryCategory::Unknown) {
        ++m_reconCount;
    }
    if (cat == WmiQueryCategory::AntiVM || IsAntiVMQuery(query)) {
        m_hasAntiVM = true;
    }
    if (cat == WmiQueryCategory::ShadowCopy) {
        m_hasShadowCopy = true;
    }
    if (cat == WmiQueryCategory::Persistence) {
        m_hasPersistence = true;
    }
}

void WmiState::OnEventSubscription(const std::string& filter,
                                    const std::string& consumer,
                                    const std::string& cmdLine,
                                    uint64_t instrNum) noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_persistence.size() >= kMaxPersistenceEvents) {
        return;
    }

    WmiPersistenceEvent evt;
    evt.eventFilter    = filter;
    evt.eventConsumer  = consumer;
    evt.commandLine    = cmdLine;
    evt.instructionNum = instrNum;
    m_persistence.push_back(std::move(evt));

    m_hasPersistence = true;
}

void WmiState::OnWbemLocatorCreated(uint64_t /*instrNum*/) noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    ++m_wbemLocatorCount;
}

void WmiState::OnConnectServer(const std::string& ns, uint64_t /*instrNum*/) noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_lastNamespace = ns;
}

std::vector<WmiQueryEvent> WmiState::GetQueries() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_queries;
}

std::vector<WmiPersistenceEvent> WmiState::GetPersistenceEvents() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_persistence;
}

uint32_t WmiState::GetReconQueryCount() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_reconCount;
}

bool WmiState::HasAntiVMQuery() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_hasAntiVM;
}

bool WmiState::HasShadowCopyDeletion() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_hasShadowCopy;
}

bool WmiState::HasPersistenceAttempt() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_hasPersistence;
}

uint32_t WmiState::GetWbemLocatorCount() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_wbemLocatorCount;
}

std::string WmiState::GetLastNamespace() const noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_lastNamespace;
}

void WmiState::Reset() noexcept {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_queries.clear();
    m_persistence.clear();
    m_reconCount       = 0;
    m_wbemLocatorCount = 0;
    m_hasAntiVM        = false;
    m_hasShadowCopy    = false;
    m_hasPersistence   = false;
    m_lastNamespace.clear();
    GetBstrTracker().Reset();
    GetVtableAllocCount().store(0, std::memory_order_relaxed);
}

// ============================================================================
// WbemLocator CLSID Detection
// ============================================================================

// {4590F811-1D3A-11D0-891F-00AA004B2E24}
// In-memory representation (little-endian Data1, Data2, Data3; big-endian Data4):
static constexpr uint8_t kWbemLocatorCLSID[16] = {
    0x11, 0xF8, 0x90, 0x45,   // Data1: 0x4590F811 LE
    0x3A, 0x1D,                // Data2: 0x1D3A LE
    0xD0, 0x11,                // Data3: 0x11D0 LE
    0x89, 0x1F,                // Data4[0..1]
    0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24  // Data4[2..7]
};

bool IsWbemLocatorCLSID(const uint8_t clsid[16]) noexcept {
    return std::memcmp(clsid, kWbemLocatorCLSID, 16) == 0;
}

// ============================================================================
// Fake WbemLocator Vtable Allocation
// ============================================================================
//
// When CoCreateInstance receives the WbemLocator CLSID, we allocate a page
// of guest memory, fill it with a fake vtable (20 slots of dummy addresses),
// and return the address. The vtable pointer structure is:
//   [ptr to vtable] → [slot0][slot1]...[slot19]
// We place both the vtable-pointer cell and the vtable array in the same page.

std::optional<GuestAddress> AllocateFakeWbemVtable(VirtualMemory& mem) noexcept {
    uint32_t current = GetVtableAllocCount().fetch_add(1, std::memory_order_relaxed);
    if (current >= kMaxFakeVtableAllocs) {
        GetVtableAllocCount().fetch_sub(1, std::memory_order_relaxed);
        return std::nullopt;
    }

    // We need: 8 bytes for the object (vtable pointer) + 160 bytes for 20 slots.
    // Allocate one page — more than enough, and ensures alignment.
    auto region = mem.Allocate(0, kPageSize, MemProt::RW);
    if (!region.has_value()) {
        GetVtableAllocCount().fetch_sub(1, std::memory_order_relaxed);
        return std::nullopt;
    }

    GuestAddress base = region.value();

    // Layout within the page:
    //   base + 0x00 : object (holds pointer to vtable at base + 0x10)
    //   base + 0x10 : vtable[0]  (QueryInterface)
    //   base + 0x18 : vtable[1]  (AddRef)
    //   base + 0x20 : vtable[2]  (Release)
    //   base + 0x28 : vtable[3]  (ConnectServer)
    //   ...etc
    //
    // Each vtable slot is filled with a sentinel address (0xDEADC0DE00000000 + slot index).
    // These addresses are in unmapped memory, so if the emulator hits them it will
    // trap cleanly rather than executing garbage.

    GuestAddress vtableAddr = base + 0x10;

    // Write the vtable pointer into the object
    if (mem.WriteU64(base, vtableAddr) != ErrorCode::Success) {
        GetVtableAllocCount().fetch_sub(1, std::memory_order_relaxed);
        return std::nullopt;
    }

    // Fill vtable slots with sentinel addresses
    static constexpr uint64_t kVtableSentinelBase = 0xDEADC0DE00000000ULL;
    for (uint32_t i = 0; i < kFakeVtableSlots; ++i) {
        uint64_t sentinel = kVtableSentinelBase | static_cast<uint64_t>(i);
        if (mem.WriteU64(vtableAddr + (i * 8), sentinel) != ErrorCode::Success) {
            GetVtableAllocCount().fetch_sub(1, std::memory_order_relaxed);
            return std::nullopt;
        }
    }

    return base;
}

// ============================================================================
// OLE Automation Handlers — oleaut32.dll
// ============================================================================

// ----------------------------------------------------------------------------
// SysAllocString — BSTR __stdcall SysAllocString(const OLECHAR *psz)
// ----------------------------------------------------------------------------
// Reads a wide string from guest memory, allocates a BSTR (length-prefixed
// wchar_t buffer), writes it into guest memory, returns pointer to string data.

bool HandleSysAllocString(APIContext& ctx) {
    const auto pszAddr = ctx.GetArgPtr(0);

    if (pszAddr == 0) {
        ctx.SetReturn(0); // NULL BSTR
        return true;
    }

    // Read the source wide string from guest memory
    std::wstring srcStr = ctx.ReadWideString(pszAddr, kMaxBstrStringChars);
    if (srcStr.empty()) {
        // Empty string: still allocate a valid BSTR with zero length
        srcStr = L"";
    }

    const uint32_t charCount = static_cast<uint32_t>(srcStr.size());
    const uint32_t dataBytes = charCount * sizeof(wchar_t);
    const uint32_t totalBytes = kBstrLenPrefixSize + dataBytes + kBstrNullTermSize;

    // Resource cap check
    auto& tracker = GetBstrTracker();
    if (!tracker.CanAllocate(totalBytes)) {
        ctx.SetReturn(0); // Out of BSTR budget
        return true;
    }

    // Allocate guest memory for the BSTR
    auto& mem = ctx.Memory();
    const uint64_t allocSize = AlignUp(totalBytes, kPageSize);
    auto region = mem.Allocate(0, allocSize, MemProt::RW);
    if (!region.has_value()) {
        ctx.SetReturn(0);
        return true;
    }

    GuestAddress bstrBase = region.value();

    // Write length prefix (byte count of string data, NOT including null terminator)
    if (mem.WriteU32(bstrBase, dataBytes) != ErrorCode::Success) {
        ctx.SetReturn(0);
        return true;
    }

    // Write string data after the length prefix
    GuestAddress dataAddr = bstrBase + kBstrLenPrefixSize;
    if (dataBytes > 0) {
        if (mem.Write(dataAddr, srcStr.data(), dataBytes) != ErrorCode::Success) {
            ctx.SetReturn(0);
            return true;
        }
    }

    // Write null terminator
    if (mem.WriteU16(dataAddr + dataBytes, 0) != ErrorCode::Success) {
        ctx.SetReturn(0);
        return true;
    }

    tracker.RecordAlloc(totalBytes);

    // Return pointer to string data (past the length prefix)
    ctx.SetReturn(dataAddr);
    return true;
}

// ----------------------------------------------------------------------------
// SysFreeString — void __stdcall SysFreeString(BSTR bstrString)
// ----------------------------------------------------------------------------
// We don't actually free guest memory (it's reclaimed at session end), but we
// track the deallocation for resource accounting.

bool HandleSysFreeString(APIContext& ctx) {
    const auto bstrAddr = ctx.GetArgPtr(0);

    if (bstrAddr == 0) {
        return true; // Freeing NULL is a no-op per spec
    }

    // Read the length prefix to update accounting
    auto& mem = ctx.Memory();
    GuestAddress lenAddr = bstrAddr - kBstrLenPrefixSize;
    uint32_t lenBytes = 0;
    if (mem.ReadU32(lenAddr, lenBytes) == ErrorCode::Success) {
        uint32_t totalBytes = kBstrLenPrefixSize + lenBytes + kBstrNullTermSize;
        GetBstrTracker().RecordFree(totalBytes);
    }

    return true;
}

// ----------------------------------------------------------------------------
// SysStringLen — UINT __stdcall SysStringLen(BSTR bstr)
// ----------------------------------------------------------------------------
// Returns the number of wide characters (not bytes).

bool HandleSysStringLen(APIContext& ctx) {
    const auto bstrAddr = ctx.GetArgPtr(0);

    if (bstrAddr == 0) {
        ctx.SetReturn32(0);
        return true;
    }

    auto& mem = ctx.Memory();
    GuestAddress lenAddr = bstrAddr - kBstrLenPrefixSize;
    uint32_t lenBytes = 0;
    if (mem.ReadU32(lenAddr, lenBytes) != ErrorCode::Success) {
        ctx.SetReturn32(0);
        return true;
    }

    // Length in wchars = byte length / sizeof(wchar_t)
    ctx.SetReturn32(lenBytes / sizeof(wchar_t));
    return true;
}

// ----------------------------------------------------------------------------
// VariantInit — void __stdcall VariantInit(VARIANTARG *pvarg)
// ----------------------------------------------------------------------------
// Zeroes out a 16-byte VARIANT structure (sets vt = VT_EMPTY = 0).

bool HandleVariantInit(APIContext& ctx) {
    const auto pvargAddr = ctx.GetArgPtr(0);

    if (pvargAddr == 0) {
        return true;
    }

    // Zero 16 bytes — this sets vt=VT_EMPTY, which is correct.
    uint8_t zeroes[kVariantSize] = {};
    ctx.Memory().Write(pvargAddr, zeroes, kVariantSize);

    return true;
}

// ----------------------------------------------------------------------------
// VariantClear — HRESULT __stdcall VariantClear(VARIANTARG *pvarg)
// ----------------------------------------------------------------------------
// Frees any contained BSTR/DISPATCH/etc and resets to VT_EMPTY.

bool HandleVariantClear(APIContext& ctx) {
    const auto pvargAddr = ctx.GetArgPtr(0);

    if (pvargAddr == 0) {
        ctx.SetReturn32(static_cast<uint32_t>(kE_INVALIDARG));
        return true;
    }

    // Read the variant type (first 2 bytes)
    auto& mem = ctx.Memory();
    uint16_t vt = 0;
    if (mem.ReadU16(pvargAddr, vt) != ErrorCode::Success) {
        ctx.SetReturn32(static_cast<uint32_t>(kE_POINTER));
        return true;
    }

    // VT_BSTR = 8: if the VARIANT holds a BSTR, free it
    static constexpr uint16_t kVT_BSTR = 8;
    if (vt == kVT_BSTR) {
        // BSTR is at offset 8 in the VARIANT structure
        uint64_t bstrPtr = 0;
        if (ctx.Is64Bit()) {
            mem.ReadU64(pvargAddr + 8, bstrPtr);
        } else {
            uint32_t ptr32 = 0;
            mem.ReadU32(pvargAddr + 8, ptr32);
            bstrPtr = ptr32;
        }
        if (bstrPtr != 0) {
            GuestAddress lenAddr = bstrPtr - kBstrLenPrefixSize;
            uint32_t lenBytes = 0;
            if (mem.ReadU32(lenAddr, lenBytes) == ErrorCode::Success) {
                uint32_t totalBytes = kBstrLenPrefixSize + lenBytes + kBstrNullTermSize;
                GetBstrTracker().RecordFree(totalBytes);
            }
        }
    }

    // Zero the VARIANT to VT_EMPTY
    uint8_t zeroes[kVariantSize] = {};
    mem.Write(pvargAddr, zeroes, kVariantSize);

    ctx.SetReturn32(static_cast<uint32_t>(kS_OK));
    return true;
}

// ============================================================================
// Registration — oleaut32.dll OLE Automation handlers
// ============================================================================

void RegisterOleAutAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "oleaut32.dll", "SysAllocString",
          HandleSysAllocString, 1, false },
        { "oleaut32.dll", "SysFreeString",
          HandleSysFreeString, 1, false },
        { "oleaut32.dll", "SysStringLen",
          HandleSysStringLen, 1, false },
        { "oleaut32.dll", "VariantInit",
          HandleVariantInit, 1, false },
        { "oleaut32.dll", "VariantClear",
          HandleVariantClear, 1, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Ole32

#pragma warning(pop)


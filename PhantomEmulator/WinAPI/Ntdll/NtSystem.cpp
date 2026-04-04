/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * NtSystem.cpp — Nt* system information, timing, and object syscall handlers
 *
 * ANTI-EVASION CRITICAL: Every response from NtQuerySystemInformation must
 * match a genuine Windows 10 Pro workstation. The fake process list, firmware
 * tables, and kernel debugger state are carefully crafted to defeat VM/sandbox
 * fingerprinting used by modern malware families.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "NtSystem.hpp"
#include "../APIDispatcher.hpp"

#include <algorithm>
#include <cstring>
#include <vector>

namespace Phantom::WinAPI::Ntdll {

// ============================================================================
// NT status codes not in the common header
// ============================================================================

static constexpr GuestNtStatus STATUS_NO_TOKEN = static_cast<int32_t>(0xC000007C);

// ============================================================================
// Staging buffer — builds NT structures before writing to guest memory
// ============================================================================

namespace {

class NtBuffer {
public:
    explicit NtBuffer(size_t initialSize = 0) : m_data(initialSize, 0) {}

    void Ensure(size_t offset, size_t count) {
        if (offset + count > m_data.size())
            m_data.resize(offset + count, 0);
    }

    void PutU8(size_t off, uint8_t v) {
        Ensure(off, 1);
        m_data[off] = v;
    }

    void PutU16(size_t off, uint16_t v) {
        Ensure(off, 2);
        std::memcpy(&m_data[off], &v, 2);
    }

    void PutU32(size_t off, uint32_t v) {
        Ensure(off, 4);
        std::memcpy(&m_data[off], &v, 4);
    }

    void PutU64(size_t off, uint64_t v) {
        Ensure(off, 8);
        std::memcpy(&m_data[off], &v, 8);
    }

    void PutI64(size_t off, int64_t v) {
        Ensure(off, 8);
        std::memcpy(&m_data[off], &v, 8);
    }

    void PutWideStr(size_t off, const wchar_t* str, size_t charCount) {
        size_t bytes = charCount * 2;
        Ensure(off, bytes + 2);
        std::memcpy(&m_data[off], str, bytes);
        m_data[off + bytes] = 0;
        m_data[off + bytes + 1] = 0;
    }

    void PutAnsiStr(size_t off, const char* str, size_t len) {
        Ensure(off, len + 1);
        std::memcpy(&m_data[off], str, len);
        m_data[off + len] = 0;
    }

    [[nodiscard]] ErrorCode WriteTo(VirtualMemory& mem, GuestAddress addr) const {
        if (m_data.empty()) return ErrorCode::Success;
        return mem.Write(addr, m_data.data(), static_cast<uint32_t>(m_data.size()));
    }

    [[nodiscard]] ErrorCode WriteTo(VirtualMemory& mem, GuestAddress addr, size_t count) const {
        if (count == 0 || m_data.empty()) return ErrorCode::Success;
        size_t actual = std::min(count, m_data.size());
        return mem.Write(addr, m_data.data(), static_cast<uint32_t>(actual));
    }

    [[nodiscard]] size_t Size() const { return m_data.size(); }

private:
    std::vector<uint8_t> m_data;
};

// ============================================================================
// Fake process list — realistic Windows 10 Pro workstation
// ============================================================================
// CRITICAL: No VM-related process names (no VBoxService, vmtoolsd, etc.)
// Process count must be in the 40-80 range to defeat sandbox detection.

struct FakeProcess {
    const wchar_t* name;
    uint32_t pid;
    uint32_t parentPid;
    uint8_t  threadCount;
    uint8_t  sessionId;
    int32_t  basePriority;
    uint32_t handleCount;
    uint64_t workingSetKB;
};

static constexpr FakeProcess kProcessList[] = {
    { L"",                               0,    0,   4, 0,  0,    0,      8 },
    { L"System",                         4,    0, 120, 0,  8, 3200,   1200 },
    { L"Registry",                      92,    4,   4, 0,  8,    0,  34000 },
    { L"smss.exe",                     200,    4,   2, 0, 11,   53,   1100 },
    { L"csrss.exe",                    400,  384,  12, 0, 13,  550,   4800 },
    { L"csrss.exe",                    424,  416,  14, 1, 13,  520,   5200 },
    { L"wininit.exe",                  500,  384,   1, 0, 13,  152,   5600 },
    { L"winlogon.exe",                 520,  416,   3, 1, 13,  229,   8200 },
    { L"services.exe",                 600,  500,   6, 0,  9,  648,  10400 },
    { L"lsass.exe",                    700,  500,   8, 0,  9,  966,  16800 },
    { L"svchost.exe",                  800,  600,  12, 0,  8,  580,  20400 },
    { L"svchost.exe",                  880,  600,   8, 0,  8,  398,  14200 },
    { L"svchost.exe",                  960,  600,  15, 0,  8, 1250,  29600 },
    { L"svchost.exe",                 1032,  600,   8, 0,  8,  380,  11200 },
    { L"svchost.exe",                 1100,  600,  20, 0,  8,  756,  32400 },
    { L"svchost.exe",                 1180,  600,   5, 0,  8,  168,   7600 },
    { L"svchost.exe",                 1260,  600,  10, 0,  8,  482,  15800 },
    { L"svchost.exe",                 1340,  600,   4, 0,  8,  156,   6000 },
    { L"svchost.exe",                 1420,  600,   7, 0,  8,  324,  12600 },
    { L"svchost.exe",                 1500,  600,   3, 0,  8,  120,   5200 },
    { L"svchost.exe",                 1580,  600,   6, 0,  8,  210,   9800 },
    { L"svchost.exe",                 1660,  600,   9, 0,  8,  340,  14400 },
    { L"fontdrvhost.exe",              548,  500,   5, 0,  8,   64,   3600 },
    { L"fontdrvhost.exe",              556,  520,   5, 1,  8,   64,   3200 },
    { L"dwm.exe",                      776,  520,  16, 1, 13,  890,  72400 },
    { L"spoolsv.exe",                 1800,  600,   7, 0,  8,  312,  15200 },
    { L"SearchIndexer.exe",           1900,  600,  14, 0,  8,  860,  28800 },
    { L"SecurityHealthService.exe",   2000,  600,   3, 0,  8,  146,  10200 },
    { L"MsMpEng.exe",                 2100,  600,  28, 0,  8, 1420, 204800 },
    { L"NisSrv.exe",                  2200,  600,   6, 0,  8,  180,  10400 },
    { L"dasHost.exe",                 2300,  600,   4, 0,  8,   98,   6400 },
    { L"dllhost.exe",                 2400,  600,   8, 0,  8,  230,  12200 },
    { L"msdtc.exe",                   2500,  600,   9, 0,  8,  165,   8400 },
    { L"WmiPrvSE.exe",               2700,  600,  11, 0,  8,  310,  18600 },
    { L"conhost.exe",                 2600, 2500,   4, 0,  8,   62,   9200 },
    { L"sihost.exe",                  3300,  960,   8, 1,  8,  410,  19200 },
    { L"taskhostw.exe",               3500,  960,   8, 1,  8,  276,  14600 },
    { L"ctfmon.exe",                  3400, 1100,   9, 1,  8,  234,  12400 },
    { L"explorer.exe",               1000,   520, 55, 1,  8, 2480, 108600 },
    { L"RuntimeBroker.exe",          2800, 1000,   3, 1,  8,  186,  16400 },
    { L"RuntimeBroker.exe",          2900, 1000,   6, 1,  8,  248,  19800 },
    { L"ShellExperienceHost.exe",    3000, 1000,  12, 1,  8,  540,  36200 },
    { L"StartMenuExperienceHost.exe",3100, 1000,   8, 1,  8,  360,  27400 },
    { L"SearchApp.exe",              3200, 1000,  25, 1,  8,  980,  86400 },
    { L"TextInputHost.exe",          3600, 1000,   7, 1,  8,  290,  22800 },
    { L"OneDrive.exe",               3800, 1000,  18, 1,  8,  640,  48200 },
    { L"smartscreen.exe",            3900, 1000,   4, 1,  8,  106,   8800 },
    { L"Widgets.exe",                4000, 1000,  10, 1,  8,  420,  32600 },
    { L"audiodg.exe",                4100, 1100,   5, 0,  8,  148,  16800 },
    { L"msedge.exe",                 4200, 1000,  30, 1,  8, 1100,  96400 },
    { L"msedge.exe",                 4250, 4200,  10, 1,  8,  380,  42600 },
    { L"cmd.exe",                    4300, 1000,   1, 1,  8,   42,   3400 },
    { L"sample.exe",                 4444, 4300,   1, 1,  8,   38,   4200 },
};

static constexpr size_t kProcessCount = sizeof(kProcessList) / sizeof(kProcessList[0]);

// x64 struct sizes
static constexpr size_t kProcessInfoBase = 0x100;  // SYSTEM_PROCESS_INFORMATION base
static constexpr size_t kThreadInfoSize  = 0x50;   // SYSTEM_THREAD_INFORMATION

// ============================================================================
// Fake kernel module list
// ============================================================================

struct FakeModule {
    const char*  path;
    uint16_t     fileNameOffset;
    uint64_t     imageBase;
    uint32_t     imageSize;
};

static constexpr FakeModule kModuleList[] = {
    { "\\SystemRoot\\system32\\ntoskrnl.exe",                   24, 0xFFFFF80050000000ULL, 0x00A28000 },
    { "\\SystemRoot\\system32\\hal.dll",                        24, 0xFFFFF80050A30000ULL, 0x0007C000 },
    { "\\SystemRoot\\system32\\kd.dll",                         24, 0xFFFFF80050AB0000ULL, 0x0001E000 },
    { "\\SystemRoot\\system32\\mcupdate_GenuineIntel.dll",      24, 0xFFFFF80050AD0000ULL, 0x00042000 },
    { "\\SystemRoot\\system32\\PSHED.dll",                      24, 0xFFFFF80050B20000ULL, 0x00022000 },
    { "\\SystemRoot\\system32\\BOOTVID.dll",                    24, 0xFFFFF80050B50000ULL, 0x0000C000 },
    { "\\SystemRoot\\system32\\CLFS.SYS",                       24, 0xFFFFF80050B60000ULL, 0x00058000 },
    { "\\SystemRoot\\system32\\CI.dll",                         24, 0xFFFFF80050BC0000ULL, 0x000BE000 },
    { "\\SystemRoot\\system32\\drivers\\Wdf01000.sys",          33, 0xFFFFF80050C80000ULL, 0x00092000 },
    { "\\SystemRoot\\system32\\drivers\\WDFLDR.SYS",            33, 0xFFFFF80050D20000ULL, 0x0001E000 },
    { "\\SystemRoot\\system32\\drivers\\acpiex.sys",            33, 0xFFFFF80050D40000ULL, 0x00018000 },
    { "\\SystemRoot\\system32\\drivers\\ACPI.sys",              33, 0xFFFFF80050D60000ULL, 0x0006A000 },
};

static constexpr size_t kModuleCount = sizeof(kModuleList) / sizeof(kModuleList[0]);
static constexpr size_t kModuleEntrySize = 0x128;  // RTL_PROCESS_MODULE_INFORMATION on x64

// ============================================================================
// SMBIOS firmware data — realistic Dell workstation, zero VM signatures
// ============================================================================

static std::vector<uint8_t> BuildSMBIOSData() {
    std::vector<uint8_t> data;

    // RawSMBIOSData header (8 bytes)
    data.push_back(0);    // Used20CallingMethod
    data.push_back(3);    // SMBIOSMajorVersion
    data.push_back(2);    // SMBIOSMinorVersion
    data.push_back(0);    // DmiRevision
    // Length placeholder (4 bytes, filled below)
    data.push_back(0); data.push_back(0); data.push_back(0); data.push_back(0);

    size_t tableStart = data.size();

    // --- Type 0: BIOS Information (length 26 = 0x1A) ---
    {
        size_t start = data.size();
        data.push_back(0);  data.push_back(26);
        data.push_back(0);  data.push_back(0);    // Handle 0
        data.push_back(1);                         // Vendor → string 1
        data.push_back(2);                         // BIOS Version → string 2
        data.push_back(0x00); data.push_back(0xF0);// Starting Address Segment
        data.push_back(3);                         // Release Date → string 3
        data.push_back(0xFF);                      // ROM Size (16 MB)
        // BIOS Characteristics (8 bytes)
        const uint8_t chars[] = { 0x90, 0xDE, 0xCB, 0x7F, 0x00, 0x00, 0x00, 0x00 };
        data.insert(data.end(), chars, chars + 8);
        data.push_back(0x03); data.push_back(0x0F); // Extension bytes
        data.push_back(2);  data.push_back(17);     // System BIOS v2.17
        data.push_back(0xFF); data.push_back(0xFF); // EC firmware
        while (data.size() < start + 26) data.push_back(0);

        // Strings
        auto pushStr = [&](const char* s) {
            data.insert(data.end(), s, s + std::strlen(s) + 1);
        };
        pushStr("Dell Inc.");
        pushStr("2.17.1246");
        pushStr("04/10/2023");
        data.push_back(0); // end-of-strings
    }

    // --- Type 1: System Information (length 27 = 0x1B) ---
    {
        size_t start = data.size();
        data.push_back(1);  data.push_back(27);
        data.push_back(1);  data.push_back(0);    // Handle 1
        data.push_back(1);                         // Manufacturer → string 1
        data.push_back(2);                         // Product Name → string 2
        data.push_back(3);                         // Version → string 3
        data.push_back(4);                         // Serial Number → string 4
        // UUID (16 bytes — realistic, no pattern)
        const uint8_t uuid[] = {
            0x4D, 0x7C, 0xA3, 0x18, 0x92, 0xF5, 0x6B, 0xD0,
            0x41, 0xE8, 0x73, 0x2A, 0x5F, 0xC6, 0x09, 0xB4
        };
        data.insert(data.end(), uuid, uuid + 16);
        data.push_back(6);                         // Wake-up Type (Power Switch)
        data.push_back(5);                         // SKU → string 5
        data.push_back(6);                         // Family → string 6
        while (data.size() < start + 27) data.push_back(0);

        auto pushStr = [&](const char* s) {
            data.insert(data.end(), s, s + std::strlen(s) + 1);
        };
        pushStr("Dell Inc.");
        pushStr("Precision 5570");
        pushStr("1.0");
        pushStr("7ABC1D3");
        pushStr("0A1B2C");
        pushStr("Precision");
        data.push_back(0);
    }

    // --- Type 2: Baseboard Information (length 15) ---
    {
        size_t start = data.size();
        data.push_back(2);  data.push_back(15);
        data.push_back(2);  data.push_back(0);    // Handle 2
        data.push_back(1);                         // Manufacturer → string 1
        data.push_back(2);                         // Product → string 2
        data.push_back(3);                         // Version → string 3
        data.push_back(4);                         // Serial → string 4
        data.push_back(5);                         // Asset Tag → string 5
        data.push_back(0x09);                      // Feature Flags
        data.push_back(6);                         // Location → string 6
        data.push_back(3);  data.push_back(0);    // Chassis Handle
        data.push_back(0x0A);                      // Board Type (Motherboard)
        data.push_back(0);                         // Contained Objects count
        while (data.size() < start + 15) data.push_back(0);

        auto pushStr = [&](const char* s) {
            data.insert(data.end(), s, s + std::strlen(s) + 1);
        };
        pushStr("Dell Inc.");
        pushStr("0R5P8G");
        pushStr("A01");
        pushStr("/7ABC1D3/CN129876543210/");
        pushStr("Not Specified");
        pushStr("Part Component");
        data.push_back(0);
    }

    // --- Type 3: Chassis Information (length 22) ---
    {
        size_t start = data.size();
        data.push_back(3);  data.push_back(22);
        data.push_back(3);  data.push_back(0);    // Handle 3
        data.push_back(1);                         // Manufacturer → string 1
        data.push_back(0x0A);                      // Chassis Type (Notebook)
        data.push_back(2);                         // Version → string 2
        data.push_back(3);                         // Serial → string 3
        data.push_back(4);                         // Asset Tag → string 4
        data.push_back(0x03);                      // Boot-up State (Safe)
        data.push_back(0x03);                      // Power Supply State
        data.push_back(0x03);                      // Thermal State
        data.push_back(0x03);                      // Security Status
        data.push_back(0); data.push_back(0);
        data.push_back(0); data.push_back(0);      // OEM-defined
        data.push_back(0);                         // Height
        data.push_back(1);                         // Number of Power Cords
        data.push_back(0);                         // Contained Elements count
        data.push_back(0);                         // Contained Element Record Length
        data.push_back(5);                         // SKU → string 5
        while (data.size() < start + 22) data.push_back(0);

        auto pushStr = [&](const char* s) {
            data.insert(data.end(), s, s + std::strlen(s) + 1);
        };
        pushStr("Dell Inc.");
        pushStr("1.0");
        pushStr("7ABC1D3");
        pushStr("Not Specified");
        pushStr("Notebook");
        data.push_back(0);
    }

    // --- Type 127: End of Table ---
    data.push_back(127); data.push_back(4);
    data.push_back(0xFF); data.push_back(0xFF);
    data.push_back(0); data.push_back(0);

    // Fill in table length
    uint32_t tableLen = static_cast<uint32_t>(data.size() - tableStart);
    std::memcpy(&data[4], &tableLen, 4);

    return data;
}

// ============================================================================
// Alignment helper
// ============================================================================

static constexpr size_t AlignUp8(size_t v) {
    return (v + 7) & ~static_cast<size_t>(7);
}

// ============================================================================
// Helper: write a UNICODE_STRING to the staging buffer (x64 layout)
// ============================================================================
// Offset+0: USHORT Length (byte count, excl null)
// Offset+2: USHORT MaximumLength (byte count, incl null)
// Offset+4: ULONG  pad
// Offset+8: PVOID  Buffer (guest address)

static void PutUnicodeString(NtBuffer& buf, size_t off,
                             uint16_t byteLen, GuestAddress bufferAddr) {
    buf.PutU16(off + 0, byteLen);
    buf.PutU16(off + 2, static_cast<uint16_t>(byteLen + 2));
    buf.PutU32(off + 4, 0);
    buf.PutU64(off + 8, bufferAddr);
}

// ============================================================================
// SystemBasicInformation (class 0)
// ============================================================================

static constexpr size_t kBasicInfoSize = 64;  // 0x40 on x64

static void BuildBasicInfo(NtBuffer& buf, const EmulationConfig& cfg) {
    uint32_t totalPages = static_cast<uint32_t>(cfg.totalPhysicalMem / 4096);

    buf.PutU32(0x00, 0);                  // Reserved
    buf.PutU32(0x04, 156250);             // TimerResolution (100ns units)
    buf.PutU32(0x08, 4096);               // PageSize
    buf.PutU32(0x0C, totalPages);         // NumberOfPhysicalPages
    buf.PutU32(0x10, 1);                  // LowestPhysicalPageNumber
    buf.PutU32(0x14, totalPages);         // HighestPhysicalPageNumber
    buf.PutU32(0x18, 65536);              // AllocationGranularity
    buf.PutU64(0x20, 0x0000000000010000); // MinimumUserModeAddress
    buf.PutU64(0x28, 0x00007FFFFFFEFFFF); // MaximumUserModeAddress (x64)
    uint64_t affinityMask = (1ULL << cfg.processorCount) - 1;
    buf.PutU64(0x30, affinityMask);       // ActiveProcessorsAffinityMask
    buf.PutU8(0x38, static_cast<uint8_t>(cfg.processorCount)); // NumberOfProcessors
}

// ============================================================================
// SystemProcessorInformation (class 1)
// ============================================================================

static constexpr size_t kProcessorInfoSize = 12;

static void BuildProcessorInfo(NtBuffer& buf) {
    buf.PutU16(0x00, 9);       // ProcessorArchitecture: PROCESSOR_ARCHITECTURE_AMD64
    buf.PutU16(0x02, 6);       // ProcessorLevel: P6 family
    buf.PutU16(0x04, 0x0A05);  // ProcessorRevision: Comet Lake stepping
    buf.PutU16(0x06, 16);      // MaximumProcessors (or Reserved)
    // ProcessorFeatureBits: SSE, SSE2, SSE3, SSSE3, SSE4.1, SSE4.2, AVX, AVX2, AESNI
    buf.PutU32(0x08, 0x7CDEFBBF);
}

// ============================================================================
// SystemPerformanceInformation (class 2)
// ============================================================================

static constexpr size_t kPerfInfoSize = 0x138;  // 312 bytes

static void BuildPerformanceInfo(NtBuffer& buf, const EmulationConfig& cfg) {
    uint32_t totalPages = static_cast<uint32_t>(cfg.totalPhysicalMem / 4096);
    uint32_t availPages = totalPages * 40 / 100;       // ~40% available (60% used)
    uint32_t commitLimit = totalPages * 3 / 2;          // 1.5x physical (with pagefile)
    uint32_t committed = commitLimit * 50 / 100;        // ~50% committed

    buf.PutI64(0x00, 85000000000LL);      // IdleProcessTime
    buf.PutI64(0x08, 42000000000LL);      // IoReadTransferCount
    buf.PutI64(0x10, 18000000000LL);      // IoWriteTransferCount
    buf.PutI64(0x18, 6000000000LL);       // IoOtherTransferCount
    buf.PutU32(0x20, 3200000);            // IoReadOperationCount
    buf.PutU32(0x24, 1800000);            // IoWriteOperationCount
    buf.PutU32(0x28, 4500000);            // IoOtherOperationCount
    buf.PutU32(0x2C, availPages);         // AvailablePages
    buf.PutU32(0x30, committed);          // CommittedPages
    buf.PutU32(0x34, commitLimit);        // CommitLimit
    buf.PutU32(0x38, committed + 200000); // PeakCommitment
    buf.PutU32(0x3C, 12500000);           // PageFaultCount
    buf.PutU32(0x70, 48000);              // PagedPoolPages
    buf.PutU32(0x74, 22000);              // NonPagedPoolPages
    buf.PutU32(0x128, 245000000);         // ContextSwitches
    buf.PutU32(0x134, 980000000);         // SystemCalls
}

// ============================================================================
// SystemTimeOfDayInformation (class 3)
// ============================================================================

static constexpr size_t kTimeOfDayInfoSize = 0x30;  // 48 bytes

// Windows FILETIME for ~Jan 15, 2025 14:00 UTC
static constexpr int64_t kFakeCurrentTime = 133'801'824'000'000'000LL;
static constexpr int64_t kEightHours100ns = 8LL * 3600 * 10'000'000;
static constexpr int64_t kFakeBootTime    = kFakeCurrentTime - kEightHours100ns;
static constexpr int64_t kTimeZoneBiasEST = 5LL * 3600 * 10'000'000; // UTC-5

static void BuildTimeOfDayInfo(NtBuffer& buf) {
    buf.PutI64(0x00, kFakeBootTime);      // BootTime
    buf.PutI64(0x08, kFakeCurrentTime);   // CurrentTime
    buf.PutI64(0x10, kTimeZoneBiasEST);   // TimeZoneBias
    buf.PutU32(0x18, 2);                  // TimeZoneId (2 = TIME_ZONE_ID_DAYLIGHT)
    buf.PutU32(0x1C, 0);                  // Reserved
    buf.PutU64(0x20, 0);                  // BootTimeBias
    buf.PutU64(0x28, 0);                  // SleepTimeBias
}

// ============================================================================
// SystemProcessInformation (class 5)
// ============================================================================

static size_t BuildProcessInfoList(NtBuffer& buf, GuestAddress guestBase) {
    size_t offset = 0;

    for (size_t i = 0; i < kProcessCount; ++i) {
        const auto& proc = kProcessList[i];
        size_t entryStart = offset;

        // Compute string data offset (after base struct + thread entries)
        size_t threadDataSize = proc.threadCount * kThreadInfoSize;
        size_t nameChars = std::wcslen(proc.name);
        size_t nameBytes = nameChars * 2;
        size_t stringOffset = entryStart + kProcessInfoBase + threadDataSize;

        // Compute entry size (aligned to 8)
        size_t entryEnd = stringOffset + nameBytes + 2; // +2 for null terminator
        size_t nextEntryOffset = AlignUp8(entryEnd);

        // Ensure buffer is big enough
        buf.Ensure(nextEntryOffset, 0);

        // --- SYSTEM_PROCESS_INFORMATION at entryStart ---
        // +0x00: NextEntryOffset
        if (i + 1 < kProcessCount)
            buf.PutU32(entryStart + 0x00, static_cast<uint32_t>(nextEntryOffset - entryStart));
        else
            buf.PutU32(entryStart + 0x00, 0); // last entry

        buf.PutU32(entryStart + 0x04, proc.threadCount);

        // CreateTime, UserTime, KernelTime — plausible values
        int64_t createTime = kFakeBootTime + static_cast<int64_t>(proc.pid) * 100'000'000LL;
        buf.PutI64(entryStart + 0x20, createTime);
        buf.PutI64(entryStart + 0x28, static_cast<int64_t>(proc.pid) * 50000LL);  // UserTime
        buf.PutI64(entryStart + 0x30, static_cast<int64_t>(proc.pid) * 30000LL);  // KernelTime

        // +0x38: ImageName UNICODE_STRING (16 bytes on x64)
        if (nameChars > 0) {
            GuestAddress nameAddr = guestBase + stringOffset;
            PutUnicodeString(buf, entryStart + 0x38,
                             static_cast<uint16_t>(nameBytes), nameAddr);
        } else {
            // System Idle Process: empty name
            buf.PutU16(entryStart + 0x38, 0);
            buf.PutU16(entryStart + 0x3A, 0);
            buf.PutU64(entryStart + 0x40, 0);
        }

        buf.PutU32(entryStart + 0x48, proc.basePriority);         // BasePriority
        buf.PutU64(entryStart + 0x50, proc.pid);                  // UniqueProcessId
        buf.PutU64(entryStart + 0x58, proc.parentPid);            // InheritedFromUniqueProcessId
        buf.PutU32(entryStart + 0x60, proc.handleCount);          // HandleCount
        buf.PutU32(entryStart + 0x64, proc.sessionId);            // SessionId
        buf.PutU64(entryStart + 0x70, proc.workingSetKB * 2048);  // PeakVirtualSize
        buf.PutU64(entryStart + 0x78, proc.workingSetKB * 1024);  // VirtualSize
        buf.PutU64(entryStart + 0x88, proc.workingSetKB * 1024);  // PeakWorkingSetSize
        buf.PutU64(entryStart + 0x90, proc.workingSetKB * 1024);  // WorkingSetSize
        buf.PutU64(entryStart + 0xB8, proc.workingSetKB * 512);   // PagefileUsage
        buf.PutU64(entryStart + 0xC8, proc.workingSetKB * 512);   // PrivatePageCount

        // --- Thread entries at entryStart + kProcessInfoBase ---
        for (uint8_t t = 0; t < proc.threadCount; ++t) {
            size_t tOff = entryStart + kProcessInfoBase + t * kThreadInfoSize;
            uint32_t tid = proc.pid * 4 + t;

            buf.PutI64(tOff + 0x00, static_cast<int64_t>(tid) * 5000LL); // KernelTime
            buf.PutI64(tOff + 0x08, static_cast<int64_t>(tid) * 3000LL); // UserTime
            buf.PutI64(tOff + 0x10, createTime);                          // CreateTime
            buf.PutU64(tOff + 0x28, proc.pid);    // ClientId.UniqueProcess
            buf.PutU64(tOff + 0x30, tid);          // ClientId.UniqueThread
            buf.PutU32(tOff + 0x38, static_cast<uint32_t>(proc.basePriority + 1)); // Priority
            buf.PutU32(tOff + 0x3C, proc.basePriority);   // BasePriority
            buf.PutU32(tOff + 0x44, 5);            // ThreadState (Waiting)
            buf.PutU32(tOff + 0x48, 6);            // WaitReason (UserRequest)
        }

        // --- Image name string data at stringOffset ---
        if (nameChars > 0) {
            buf.PutWideStr(stringOffset, proc.name, nameChars);
        }

        offset = nextEntryOffset;
    }

    return offset; // total bytes used
}

// ============================================================================
// SystemModuleInformation (class 11)
// ============================================================================

static size_t BuildModuleInfo(NtBuffer& buf) {
    // Header: ULONG NumberOfModules + 4 padding
    buf.PutU32(0x00, static_cast<uint32_t>(kModuleCount));
    buf.PutU32(0x04, 0); // padding for alignment

    size_t offset = 8;

    for (size_t i = 0; i < kModuleCount; ++i) {
        const auto& mod = kModuleList[i];
        size_t entryBase = offset + i * kModuleEntrySize;

        buf.PutU64(entryBase + 0x00, 0);                    // Section
        buf.PutU64(entryBase + 0x08, mod.imageBase);         // MappedBase
        buf.PutU64(entryBase + 0x10, mod.imageBase);         // ImageBase
        buf.PutU32(entryBase + 0x18, mod.imageSize);         // ImageSize
        buf.PutU32(entryBase + 0x1C, 0x08004000);            // Flags
        buf.PutU16(entryBase + 0x20, static_cast<uint16_t>(i)); // LoadOrderIndex
        buf.PutU16(entryBase + 0x22, static_cast<uint16_t>(i)); // InitOrderIndex
        buf.PutU16(entryBase + 0x24, 1);                    // LoadCount
        buf.PutU16(entryBase + 0x26, mod.fileNameOffset);    // OffsetToFileName

        // FullPathName[256] at +0x28
        size_t pathLen = std::strlen(mod.path);
        if (pathLen > 255) pathLen = 255;
        buf.PutAnsiStr(entryBase + 0x28, mod.path, pathLen);
    }

    return 8 + kModuleCount * kModuleEntrySize;
}

// ============================================================================
// SystemKernelDebuggerInformation (class 35)
// ============================================================================

static constexpr size_t kKernelDebuggerInfoSize = 2;

static void BuildKernelDebuggerInfo(NtBuffer& buf) {
    buf.PutU8(0x00, 0);  // KernelDebuggerEnabled = FALSE
    buf.PutU8(0x01, 1);  // KernelDebuggerNotPresent = TRUE
}

// ============================================================================
// SystemCodeIntegrityInformation (class 103)
// ============================================================================

static constexpr size_t kCodeIntegrityInfoSize = 8;

static void BuildCodeIntegrityInfo(NtBuffer& buf) {
    buf.PutU32(0x00, 8);     // Length
    buf.PutU32(0x04, 0x01);  // CodeIntegrityOptions: CODEINTEGRITY_OPTION_ENABLED
}

// ============================================================================
// Handle type → type name mapping (for NtQueryObject)
// ============================================================================

static const wchar_t* HandleTypeToName(HandleType type) {
    switch (type) {
        case HandleType::File:          return L"File";
        case HandleType::Directory:     return L"Directory";
        case HandleType::RegistryKey:   return L"Key";
        case HandleType::Process:       return L"Process";
        case HandleType::Thread:        return L"Thread";
        case HandleType::Mutex:         return L"Mutant";
        case HandleType::Event:         return L"Event";
        case HandleType::Semaphore:     return L"Semaphore";
        case HandleType::Section:       return L"Section";
        case HandleType::Token:         return L"Token";
        case HandleType::Pipe:          return L"File";
        case HandleType::Timer:         return L"Timer";
        case HandleType::Module:        return L"Section";
        case HandleType::Job:           return L"Job";
        default:                        return L"Unknown";
    }
}

} // anonymous namespace

// ============================================================================
// HandleNtQuerySystemInformation
// ============================================================================

bool HandleNtQuerySystemInformation(APIContext& ctx) {
    auto infoClass    = ctx.GetArg32(0);
    auto sysInfoAddr  = ctx.GetArgPtr(1);
    auto infoLength   = ctx.GetArg32(2);
    auto retLenAddr   = ctx.GetArgPtr(3);

    auto writeRetLen = [&](uint32_t len) {
        if (retLenAddr != 0)
            ctx.Memory().WriteU32(retLenAddr, len);
    };

    switch (infoClass) {
    // ------------------------------------------------------------------
    case 0: { // SystemBasicInformation
        if (infoLength < kBasicInfoSize) {
            writeRetLen(static_cast<uint32_t>(kBasicInfoSize));
            ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
            return true;
        }
        NtBuffer buf(kBasicInfoSize);
        BuildBasicInfo(buf, ctx.Config());
        buf.WriteTo(ctx.Memory(), sysInfoAddr);
        writeRetLen(static_cast<uint32_t>(kBasicInfoSize));
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // ------------------------------------------------------------------
    case 1: { // SystemProcessorInformation
        if (infoLength < kProcessorInfoSize) {
            writeRetLen(static_cast<uint32_t>(kProcessorInfoSize));
            ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
            return true;
        }
        NtBuffer buf(kProcessorInfoSize);
        BuildProcessorInfo(buf);
        buf.WriteTo(ctx.Memory(), sysInfoAddr);
        writeRetLen(static_cast<uint32_t>(kProcessorInfoSize));
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // ------------------------------------------------------------------
    case 2: { // SystemPerformanceInformation
        if (infoLength < kPerfInfoSize) {
            writeRetLen(static_cast<uint32_t>(kPerfInfoSize));
            ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
            return true;
        }
        NtBuffer buf(kPerfInfoSize);
        BuildPerformanceInfo(buf, ctx.Config());
        buf.WriteTo(ctx.Memory(), sysInfoAddr);
        writeRetLen(static_cast<uint32_t>(kPerfInfoSize));
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // ------------------------------------------------------------------
    case 3: { // SystemTimeOfDayInformation
        if (infoLength < kTimeOfDayInfoSize) {
            writeRetLen(static_cast<uint32_t>(kTimeOfDayInfoSize));
            ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
            return true;
        }
        NtBuffer buf(kTimeOfDayInfoSize);
        BuildTimeOfDayInfo(buf);
        buf.WriteTo(ctx.Memory(), sysInfoAddr);
        writeRetLen(static_cast<uint32_t>(kTimeOfDayInfoSize));
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // ------------------------------------------------------------------
    case 5: { // SystemProcessInformation
        // Build into staging buffer first to determine required size
        NtBuffer buf;
        size_t requiredSize = BuildProcessInfoList(buf, sysInfoAddr);

        writeRetLen(static_cast<uint32_t>(requiredSize));

        if (infoLength < requiredSize) {
            ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
            return true;
        }
        buf.WriteTo(ctx.Memory(), sysInfoAddr, requiredSize);
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // ------------------------------------------------------------------
    case 11: { // SystemModuleInformation
        NtBuffer buf;
        size_t requiredSize = BuildModuleInfo(buf);

        writeRetLen(static_cast<uint32_t>(requiredSize));

        if (infoLength < requiredSize) {
            ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
            return true;
        }
        buf.WriteTo(ctx.Memory(), sysInfoAddr, requiredSize);
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // ------------------------------------------------------------------
    case 35: { // SystemKernelDebuggerInformation — anti-debug critical
        if (infoLength < kKernelDebuggerInfoSize) {
            writeRetLen(static_cast<uint32_t>(kKernelDebuggerInfoSize));
            ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
            return true;
        }
        NtBuffer buf(kKernelDebuggerInfoSize);
        BuildKernelDebuggerInfo(buf);
        buf.WriteTo(ctx.Memory(), sysInfoAddr);
        writeRetLen(static_cast<uint32_t>(kKernelDebuggerInfoSize));
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // ------------------------------------------------------------------
    case 76: { // SystemFirmwareTableInformation — anti-VM critical
        if (infoLength < 16) {
            ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
            return true;
        }

        // Read input fields from guest buffer
        uint32_t provider = 0, action = 0;
        ctx.Memory().ReadU32(sysInfoAddr + 0x00, provider);
        ctx.Memory().ReadU32(sysInfoAddr + 0x04, action);

        // Only handle 'RSMB' provider, Get action (1)
        if (provider == 0x52534D42 && action == 1) {
            static const auto smbiosData = BuildSMBIOSData();
            uint32_t requiredSize = static_cast<uint32_t>(16 + smbiosData.size());

            writeRetLen(requiredSize);

            if (infoLength < requiredSize) {
                ctx.SetReturnNtStatus(NT::STATUS_BUFFER_TOO_SMALL);
                return true;
            }

            // Write TableBufferLength at +0x0C
            ctx.Memory().WriteU32(sysInfoAddr + 0x0C,
                                  static_cast<uint32_t>(smbiosData.size()));
            // Write SMBIOS data at +0x10
            ctx.Memory().Write(sysInfoAddr + 0x10, smbiosData.data(),
                               static_cast<uint32_t>(smbiosData.size()));
            ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        } else {
            ctx.SetReturnNtStatus(NT::STATUS_NOT_IMPLEMENTED);
        }
        return true;
    }

    // ------------------------------------------------------------------
    case 103: { // SystemCodeIntegrityInformation
        if (infoLength < kCodeIntegrityInfoSize) {
            writeRetLen(static_cast<uint32_t>(kCodeIntegrityInfoSize));
            ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
            return true;
        }
        NtBuffer buf(kCodeIntegrityInfoSize);
        BuildCodeIntegrityInfo(buf);
        buf.WriteTo(ctx.Memory(), sysInfoAddr);
        writeRetLen(static_cast<uint32_t>(kCodeIntegrityInfoSize));
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // ------------------------------------------------------------------
    default:
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_INFO_CLASS);
        return true;
    }
}

// ============================================================================
// HandleNtQueryPerformanceCounter
// ============================================================================

bool HandleNtQueryPerformanceCounter(APIContext& ctx) {
    auto counterAddr = ctx.GetArgPtr(0);
    auto freqAddr    = ctx.GetArgPtr(1);

    static constexpr uint64_t kQPCFrequency = 10'000'000ULL; // 10 MHz

    // Convert TSC to QPC units. TSC advances ~25 per instruction at ~3.8 GHz.
    // QPC = TSC * 10MHz / TSCFrequency
    uint64_t tsc = ctx.CPU().tsc;
    uint64_t freq = ctx.Config().fakeTSCFrequency;
    uint64_t counter = (freq > 0) ? (tsc * kQPCFrequency / freq) : tsc;

    // Ensure minimum plausible value (system has been running for hours)
    static constexpr uint64_t kMinCounter = kQPCFrequency * 3600ULL * 8; // 8 hours
    if (counter < kMinCounter) counter += kMinCounter;

    // Write LARGE_INTEGER PerformanceCounter
    if (counterAddr != 0)
        ctx.Memory().WriteU64(counterAddr, counter);

    // Write LARGE_INTEGER PerformanceFrequency
    if (freqAddr != 0)
        ctx.Memory().WriteU64(freqAddr, kQPCFrequency);

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// HandleNtDelayExecution
// ============================================================================

bool HandleNtDelayExecution(APIContext& ctx) {
    // Arg0: BOOLEAN Alertable (ignored for emulation)
    auto delayAddr = ctx.GetArgPtr(1);

    if (delayAddr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    int64_t delayInterval = 0;
    ctx.Memory().ReadValue(delayAddr, delayInterval);

    // Negative = relative delay in 100ns units. Positive = absolute time.
    // Convert to microseconds for advancing the emulated clock.
    int64_t delay100ns = (delayInterval < 0) ? -delayInterval : 0;

    // Timing acceleration: advance emulated time without actually sleeping.
    // TSC advance = delay_in_seconds * TSCFrequency
    if (delay100ns > 0) {
        uint64_t tscFreq = ctx.Config().fakeTSCFrequency;

        if (ctx.Config().enableTimingAcceleration) {
            // Advance TSC by the full delay amount (1000x acceleration:
            // malware perceives the full delay, we execute instantly).
            uint64_t tscAdvance = static_cast<uint64_t>(delay100ns) * tscFreq / 10'000'000ULL;
            ctx.CPU().tsc += tscAdvance;
        }
    }

    // Sandbox evasion detection: Sleep > 5 seconds is suspicious.
    // The dispatcher's behavioral analysis flags this via
    // BehaviorFlag::AntiAnalysis in the KnownAPIEntry metadata.
    // We don't need to set the flag here — it's automatic.

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// HandleNtDuplicateObject
// ============================================================================

bool HandleNtDuplicateObject(APIContext& ctx) {
    // Arg0: HANDLE SourceProcessHandle
    // Arg1: HANDLE SourceHandle
    // Arg2: HANDLE TargetProcessHandle
    // Arg3: PHANDLE TargetHandle (output)
    // Arg4: ACCESS_MASK DesiredAccess
    // Arg5: ULONG HandleAttributes
    // Arg6: ULONG Options

    auto sourceHandle  = ctx.GetArg(1);
    auto targetHndAddr = ctx.GetArgPtr(3);

    if (targetHndAddr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    auto newHandle = ctx.Handles().Duplicate(sourceHandle);
    if (!newHandle) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    ctx.Memory().WriteU64(targetHndAddr, *newHandle);
    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// HandleNtQueryObject
// ============================================================================

bool HandleNtQueryObject(APIContext& ctx) {
    auto handle          = ctx.GetArg(0);
    auto infoClass       = ctx.GetArg32(1);
    auto infoAddr        = ctx.GetArgPtr(2);
    auto infoLength      = ctx.GetArg32(3);
    auto retLenAddr      = ctx.GetArgPtr(4);

    auto writeRetLen = [&](uint32_t len) {
        if (retLenAddr != 0)
            ctx.Memory().WriteU32(retLenAddr, len);
    };

    auto entry = ctx.Handles().Lookup(handle);
    if (!entry && handle != kCurrentProcess && handle != kCurrentThread) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    HandleType hType = entry ? entry->type : HandleType::Process;

    switch (infoClass) {
    case 1: { // ObjectNameInformation
        // Structure: UNICODE_STRING (16 bytes on x64) + string data
        std::wstring objName;

        if (entry) {
            if (auto* fd = std::get_if<FileHandleData>(&entry->data))
                objName = fd->path;
            else if (auto* rd = std::get_if<RegistryKeyHandleData>(&entry->data))
                objName = rd->path;
            else if (auto* pd = std::get_if<ProcessHandleData>(&entry->data))
                objName = L"\\Device\\Process\\" + std::to_wstring(pd->pid);
        }

        uint16_t nameBytes = static_cast<uint16_t>(objName.size() * 2);
        uint32_t requiredSize = 16 + nameBytes + 2;
        writeRetLen(requiredSize);

        if (infoLength < requiredSize) {
            ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
            return true;
        }

        NtBuffer buf(requiredSize);
        GuestAddress bufAddr = infoAddr + 16; // string data follows UNICODE_STRING
        PutUnicodeString(buf, 0, nameBytes, bufAddr);
        if (!objName.empty()) {
            buf.PutWideStr(16, objName.c_str(), objName.size());
        }
        buf.WriteTo(ctx.Memory(), infoAddr);
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    case 2: { // ObjectTypeInformation
        const wchar_t* typeName = HandleTypeToName(hType);
        size_t nameChars = std::wcslen(typeName);
        uint16_t nameBytes = static_cast<uint16_t>(nameChars * 2);

        // OBJECT_TYPE_INFORMATION: UNICODE_STRING TypeName (16) +
        // remaining fields (~88 bytes on x64, we zero-fill) + string data
        uint32_t fixedSize = 104; // typical size of the fixed portion
        uint32_t requiredSize = fixedSize + nameBytes + 2;
        writeRetLen(requiredSize);

        if (infoLength < requiredSize) {
            ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
            return true;
        }

        NtBuffer buf(requiredSize);
        GuestAddress strAddr = infoAddr + fixedSize;
        PutUnicodeString(buf, 0, nameBytes, strAddr);

        // Fill some plausible type info fields
        buf.PutU32(0x10, 1);     // TotalNumberOfObjects
        buf.PutU32(0x14, 1);     // TotalNumberOfHandles
        buf.PutU32(0x5C, 0x100020); // ValidAccessMask

        if (nameChars > 0) {
            buf.PutWideStr(fixedSize, typeName, nameChars);
        }

        buf.WriteTo(ctx.Memory(), infoAddr);
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    default:
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_INFO_CLASS);
        return true;
    }
}

// ============================================================================
// Registration
// ============================================================================

void RegisterNtSystem(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration regs[] = {
        { "ntdll.dll", "NtQuerySystemInformation",  HandleNtQuerySystemInformation,  4, true  },
        { "ntdll.dll", "NtQueryPerformanceCounter",  HandleNtQueryPerformanceCounter, 2, true  },
        { "ntdll.dll", "NtDelayExecution",            HandleNtDelayExecution,          2, true  },
        { "ntdll.dll", "NtDuplicateObject",           HandleNtDuplicateObject,         7, false },
        { "ntdll.dll", "NtQueryObject",               HandleNtQueryObject,             5, false },
    };
    dispatcher.RegisterBatch(regs, static_cast<uint32_t>(std::size(regs)));
}

} // namespace Phantom::WinAPI::Ntdll

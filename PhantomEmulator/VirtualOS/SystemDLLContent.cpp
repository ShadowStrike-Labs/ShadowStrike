/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * SystemDLLContent.cpp — Realistic system DLL PE content generation
 *
 * Builds structurally valid PE images for known Windows 10 22H2 system DLLs.
 * Each generated image is 4096 bytes (one page) containing:
 *
 *   - Full DOS header with authentic "This program cannot be run in DOS mode"
 *   - PE signature + COFF header with correct Machine/TimeDateStamp
 *   - PE32+ Optional Header with profile-specific ImageBase, SizeOfImage,
 *     Checksum, DllCharacteristics (DYNAMIC_BASE|NX_COMPAT|HIGH_ENTROPY_VA)
 *   - Five section headers: .text, .rdata, .data, .rsrc, .reloc
 *   - Export directory table with real, alphabetically sorted export names
 *   - VS_VERSION_INFO resource block with realistic FileVersion/ProductVersion
 *
 * The remaining bytes up to the DLL's declared file size are served as
 * zeroes by the VFS ReadFile path, simulating the gap between headers
 * and the first on-disk section.  This is sufficient to defeat malware
 * that validates PE headers, export tables, version resources, and file
 * sizes of system DLLs as an anti-emulation / anti-sandbox check.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "SystemDLLContent.hpp"

#include <algorithm>
#include <cstring>
#include <cwctype>

namespace Phantom::VirtualOS {

// ============================================================================
// Internal Constants & Helpers
// ============================================================================

namespace {

static constexpr size_t kPageSize = 4096;

// Windows 10 22H2 build timestamp (approx. Oct 2023 update)
static constexpr uint32_t kWin10_22H2_Timestamp = 0x6500E6DB;

// --- Little-endian write helpers -------------------------------------------

void W16(std::vector<uint8_t>& b, size_t off, uint16_t v) noexcept {
    if (off + 1 >= b.size()) return;
    b[off]     = static_cast<uint8_t>(v & 0xFF);
    b[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
}

void W32(std::vector<uint8_t>& b, size_t off, uint32_t v) noexcept {
    if (off + 3 >= b.size()) return;
    b[off]     = static_cast<uint8_t>(v & 0xFF);
    b[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    b[off + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    b[off + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

void W64(std::vector<uint8_t>& b, size_t off, uint64_t v) noexcept {
    if (off + 7 >= b.size()) return;
    for (int i = 0; i < 8; ++i)
        b[off + static_cast<size_t>(i)] =
            static_cast<uint8_t>((v >> (i * 8)) & 0xFF);
}

void WriteASCII(std::vector<uint8_t>& b, size_t off,
                const char* s, size_t maxLen) noexcept {
    for (size_t i = 0; i < maxLen && s[i] != '\0'; ++i) {
        if (off + i >= b.size()) return;
        b[off + i] = static_cast<uint8_t>(s[i]);
    }
}

void WriteWideString(std::vector<uint8_t>& b, size_t off,
                     const wchar_t* s) noexcept {
    for (size_t i = 0; s[i] != L'\0'; ++i) {
        size_t pos = off + i * 2;
        if (pos + 1 >= b.size()) return;
        auto ch = static_cast<uint16_t>(s[i]);
        b[pos]     = static_cast<uint8_t>(ch & 0xFF);
        b[pos + 1] = static_cast<uint8_t>((ch >> 8) & 0xFF);
    }
}

size_t WideLen(const wchar_t* s) noexcept {
    size_t len = 0;
    while (s[len]) ++len;
    return len;
}

// --- DOS stub program (authentic "cannot be run in DOS mode" message) ------

static constexpr uint8_t kDOSStubProgram[] = {
    0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C,
    0xCD, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72,
    0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65,
    0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
    0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};


// ============================================================================
// Known DLL Export Tables (alphabetically sorted per Windows linker output)
// ============================================================================

// --- ntdll.dll exports ---
static constexpr DLLExportEntry kNtdllExports[] = {
    { "EtwEventWrite",              1,  0x00051A20 },
    { "LdrLoadDll",                 2,  0x0003B400 },
    { "NtAllocateVirtualMemory",    3,  0x000A1F10 },
    { "NtClose",                    4,  0x000A2040 },
    { "NtCreateFile",               5,  0x000A1E00 },
    { "NtCreateThreadEx",           6,  0x000A2180 },
    { "NtDelayExecution",           7,  0x000A20C0 },
    { "NtMapViewOfSection",         8,  0x000A1FB0 },
    { "NtOpenProcess",              9,  0x000A1E60 },
    { "NtProtectVirtualMemory",    10,  0x000A1F70 },
    { "NtQueryInformationProcess", 11,  0x000A2100 },
    { "NtQuerySystemInformation",  12,  0x000A2060 },
    { "NtQueueApcThread",          13,  0x000A21E0 },
    { "NtReadVirtualMemory",       14,  0x000A1FE0 },
    { "NtResumeThread",            15,  0x000A2210 },
    { "NtSetInformationThread",    16,  0x000A2140 },
    { "NtWriteVirtualMemory",      17,  0x000A1EC0 },
    { "RtlDecompressBuffer",       18,  0x00078C00 },
    { "RtlGetVersion",             19,  0x00065400 },
    { "RtlInitUnicodeString",      20,  0x00012340 },
};

// --- kernel32.dll exports ---
static constexpr DLLExportEntry kKernel32Exports[] = {
    { "CreateFileW",               1,  0x00023400 },
    { "CreateProcessW",            2,  0x00045600 },
    { "CreateRemoteThread",        3,  0x00047800 },
    { "CreateThread",              4,  0x00041200 },
    { "ExitProcess",               5,  0x00012A00 },
    { "GetModuleHandleA",          6,  0x00018C00 },
    { "GetModuleHandleW",          7,  0x00018E00 },
    { "GetProcAddress",            8,  0x00019100 },
    { "GetSystemTime",             9,  0x00021200 },
    { "GetTempPathW",             10,  0x00029800 },
    { "GetTickCount",             11,  0x00021000 },
    { "IsDebuggerPresent",        12,  0x00022400 },
    { "LoadLibraryA",             13,  0x00019400 },
    { "LoadLibraryW",             14,  0x00019600 },
    { "OutputDebugStringA",       15,  0x00022600 },
    { "ReadProcessMemory",        16,  0x00048A00 },
    { "Sleep",                    17,  0x00021600 },
    { "VirtualAlloc",             18,  0x00031200 },
    { "VirtualProtect",           19,  0x00031600 },
    { "WinExec",                  20,  0x00046200 },
    { "WriteProcessMemory",       21,  0x00048C00 },
};

// --- kernelbase.dll exports ---
static constexpr DLLExportEntry kKernelBaseExports[] = {
    { "CreateFileW",               1,  0x00034200 },
    { "GetLastError",              2,  0x00012800 },
    { "GetModuleFileNameW",        3,  0x00028C00 },
    { "ReadFile",                  4,  0x00035400 },
    { "SetLastError",              5,  0x00012A00 },
    { "VirtualAllocEx",            6,  0x00042100 },
    { "VirtualProtectEx",          7,  0x00042500 },
    { "WriteFile",                 8,  0x00035800 },
};

// --- user32.dll exports ---
static constexpr DLLExportEntry kUser32Exports[] = {
    { "FindWindowA",               1,  0x00028400 },
    { "FindWindowW",               2,  0x00028600 },
    { "GetDesktopWindow",          3,  0x00021200 },
    { "GetForegroundWindow",       4,  0x00021400 },
    { "MessageBoxA",               5,  0x00076200 },
    { "MessageBoxW",               6,  0x00076400 },
    { "PostMessageA",              7,  0x00032100 },
    { "SendMessageA",              8,  0x00031200 },
};

// --- advapi32.dll exports ---
static constexpr DLLExportEntry kAdvapi32Exports[] = {
    { "CreateServiceW",            1,  0x00054200 },
    { "CryptAcquireContextW",      2,  0x00041200 },
    { "CryptDecrypt",              3,  0x00041A00 },
    { "CryptEncrypt",              4,  0x00041600 },
    { "OpenSCManagerW",            5,  0x00053800 },
    { "RegOpenKeyExW",             6,  0x00021200 },
    { "RegQueryValueExW",          7,  0x00022400 },
    { "RegSetValueExW",            8,  0x00023600 },
    { "StartServiceW",             9,  0x00054800 },
};

// --- ws2_32.dll exports ---
static constexpr DLLExportEntry kWs2_32Exports[] = {
    { "WSACleanup",                1,  0x00012200 },
    { "WSAStartup",                2,  0x00012000 },
    { "accept",                    3,  0x00014200 },
    { "bind",                      4,  0x00013800 },
    { "closesocket",               5,  0x00013200 },
    { "connect",                   6,  0x00013400 },
    { "getaddrinfo",               7,  0x00018200 },
    { "listen",                    8,  0x00014000 },
    { "recv",                      9,  0x00013600 },
    { "send",                     10,  0x00013500 },
    { "socket",                   11,  0x00013000 },
};

// --- amsi.dll exports ---
static constexpr DLLExportEntry kAmsiExports[] = {
    { "AmsiCloseSession",          1,  0x00003200 },
    { "AmsiInitialize",            2,  0x00002200 },
    { "AmsiOpenSession",           3,  0x00002800 },
    { "AmsiScanBuffer",            4,  0x00002E00 },
    { "AmsiScanString",            5,  0x00003000 },
    { "AmsiUninitialize",          6,  0x00003400 },
};


// ============================================================================
// DLL Content Profiles
// ============================================================================

// DllCharacteristics flags
static constexpr uint16_t kDynBase     = 0x0040; // DYNAMIC_BASE
static constexpr uint16_t kNXCompat    = 0x0100; // NX_COMPAT
static constexpr uint16_t kHighEntVA   = 0x0020; // HIGH_ENTROPY_VA
static constexpr uint16_t kStdDllChar  = kDynBase | kNXCompat | kHighEntVA;

// COFF characteristics for DLLs
static constexpr uint32_t kDllChars =
    0x0022 | 0x2000; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DLL

static constexpr DLLContentProfile kProfiles[] = {
    {
        L"ntdll.dll",
        1'912'320,              // realFileSize
        kDllChars,              // characteristics
        kWin10_22H2_Timestamp,  // timeDateStamp
        0x00007FFE'00000000ULL, // imageBase
        0x001D4000,             // sizeOfImage
        0x001D1E2A,             // checksum
        kNtdllExports,
        static_cast<uint32_t>(sizeof(kNtdllExports) / sizeof(kNtdllExports[0])),
        10, 0, 19041            // major, minor, build (Win10 22H2)
    },
    {
        L"kernel32.dll",
        774'144,
        kDllChars,
        kWin10_22H2_Timestamp,
        0x00000000'76000000ULL,
        0x000C0000,
        0x000C5A3E,
        kKernel32Exports,
        static_cast<uint32_t>(sizeof(kKernel32Exports) / sizeof(kKernel32Exports[0])),
        10, 0, 19041
    },
    {
        L"kernelbase.dll",
        2'838'528,
        kDllChars,
        kWin10_22H2_Timestamp,
        0x00007FFE'10000000ULL,
        0x002C0000,
        0x002B8C4A,
        kKernelBaseExports,
        static_cast<uint32_t>(sizeof(kKernelBaseExports) / sizeof(kKernelBaseExports[0])),
        10, 0, 19041
    },
    {
        L"user32.dll",
        1'642'496,
        kDllChars,
        kWin10_22H2_Timestamp,
        0x00007FFE'30000000ULL,
        0x001A0000,
        0x00196B1E,
        kUser32Exports,
        static_cast<uint32_t>(sizeof(kUser32Exports) / sizeof(kUser32Exports[0])),
        10, 0, 19041
    },
    {
        L"advapi32.dll",
        782'336,
        kDllChars,
        kWin10_22H2_Timestamp,
        0x00007FFE'20000000ULL,
        0x000C2000,
        0x000BF23A,
        kAdvapi32Exports,
        static_cast<uint32_t>(sizeof(kAdvapi32Exports) / sizeof(kAdvapi32Exports[0])),
        10, 0, 19041
    },
    {
        L"ws2_32.dll",
        368'640,
        kDllChars,
        kWin10_22H2_Timestamp,
        0x00007FFE'40000000ULL,
        0x0005C000,
        0x0005A12E,
        kWs2_32Exports,
        static_cast<uint32_t>(sizeof(kWs2_32Exports) / sizeof(kWs2_32Exports[0])),
        10, 0, 19041
    },
    {
        L"amsi.dll",
        81'920,
        kDllChars,
        kWin10_22H2_Timestamp,
        0x00007FFE'50000000ULL,
        0x00016000,
        0x000148AE,
        kAmsiExports,
        static_cast<uint32_t>(sizeof(kAmsiExports) / sizeof(kAmsiExports[0])),
        10, 0, 19041
    },
};

static constexpr size_t kProfileCount =
    sizeof(kProfiles) / sizeof(kProfiles[0]);


// ============================================================================
// Static File Content — Non-PE system files malware commonly reads
// ============================================================================

static constexpr char kHostsContent[] =
    "# Copyright (c) 1993-2009 Microsoft Corp.\r\n"
    "#\r\n"
    "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n"
    "#\r\n"
    "# This file contains the mappings of IP addresses to host names. Each\r\n"
    "# entry should be kept on an individual line. The IP address should\r\n"
    "# be placed in the first column followed by the corresponding host name.\r\n"
    "# The IP address and the host name should be separated by at least one\r\n"
    "# space.\r\n"
    "#\r\n"
    "# Additionally, comments (such as these) may be inserted on individual\r\n"
    "# lines or following the machine name denoted by a '#' symbol.\r\n"
    "#\r\n"
    "# For example:\r\n"
    "#\r\n"
    "#      102.54.94.97     rhino.acme.com          # source server\r\n"
    "#       38.25.63.10     x.acme.com              # x client host\r\n"
    "\r\n"
    "# localhost name resolution is handled within DNS itself.\r\n"
    "#\t127.0.0.1       localhost\r\n"
    "#\t::1             localhost\r\n";

static constexpr char kSystemIniContent[] =
    "; for 16-bit app support\r\n"
    "[386Enh]\r\n"
    "woafont=dosapp.fon\r\n"
    "EGA80WOA.FON=EGA80WOA.FON\r\n"
    "EGA40WOA.FON=EGA40WOA.FON\r\n"
    "CGA80WOA.FON=CGA80WOA.FON\r\n"
    "CGA40WOA.FON=CGA40WOA.FON\r\n"
    "\r\n"
    "[drivers]\r\n"
    "wave=mmdrv.dll\r\n"
    "timer=timer.drv\r\n"
    "\r\n"
    "[mci]\r\n";

static constexpr char kWinIniContent[] =
    "; for 16-bit app support\r\n"
    "[fonts]\r\n"
    "[extensions]\r\n"
    "[mci extensions]\r\n"
    "[files]\r\n"
    "[Mail]\r\n"
    "MAPI=1\r\n";


// ============================================================================
// Case-insensitive wstring_view comparison
// ============================================================================

[[nodiscard]] bool IEqualW(std::wstring_view a, std::wstring_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::towlower(static_cast<wint_t>(a[i])) !=
            std::towlower(static_cast<wint_t>(b[i])))
            return false;
    }
    return true;
}

/// Extract filename component from a path (after last backslash)
[[nodiscard]] std::wstring_view ExtractFilename(std::wstring_view path) noexcept {
    auto pos = path.rfind(L'\\');
    if (pos == std::wstring_view::npos) return path;
    return path.substr(pos + 1);
}

/// Check if path ends with a given suffix (case-insensitive)
[[nodiscard]] bool EndsWithI(std::wstring_view path,
                             std::wstring_view suffix) noexcept {
    if (path.size() < suffix.size()) return false;
    return IEqualW(path.substr(path.size() - suffix.size()), suffix);
}

} // anonymous namespace


// ============================================================================
// GetDLLProfile — Look up profile for a known system DLL by filename
// ============================================================================

const DLLContentProfile* GetDLLProfile(std::wstring_view dllName) noexcept {
    // Extract just the filename if a full path was passed
    auto filename = ExtractFilename(dllName);

    for (size_t i = 0; i < kProfileCount; ++i) {
        if (IEqualW(filename, kProfiles[i].dllName))
            return &kProfiles[i];
    }
    return nullptr;
}


// ============================================================================
// GenerateRealisticContent — Build a 4096-byte PE image from a DLL profile
// ============================================================================
//
// Layout (PE32+ / 64-bit):
//   0x0000 - 0x003F  IMAGE_DOS_HEADER
//   0x0040 - 0x007F  DOS stub program ("cannot be run in DOS mode")
//   0x0080 - 0x0083  PE signature "PE\0\0"
//   0x0084 - 0x0097  COFF File Header
//   0x0098 - 0x0187  Optional Header (PE32+, 240 bytes) + DataDirectory
//   0x0188 - 0x02CF  Section headers (5 × 40 bytes = 200 bytes)
//   0x0400 - 0x0XXX  Export directory + name table (in .rdata area)
//   0x0XXX - 0x0FFF  Version resource block (in .rsrc area)
//
// Total: 4096 bytes.  Beyond this, VFS returns zeroes up to realFileSize.

std::vector<uint8_t> GenerateRealisticContent(
    const DLLContentProfile& profile,
    bool is64bit) noexcept
{
    std::vector<uint8_t> pe(kPageSize, 0);

    // ========================================================================
    // IMAGE_DOS_HEADER (0x00 - 0x3F)
    // ========================================================================
    W16(pe, 0x00, 0x5A4D);           // e_magic  = "MZ"
    W16(pe, 0x02, 0x0090);           // e_cblp
    W16(pe, 0x04, 0x0003);           // e_cp
    W16(pe, 0x08, 0x0004);           // e_minalloc
    W16(pe, 0x0A, 0xFFFF);           // e_maxalloc
    W16(pe, 0x10, 0x00B8);           // e_sp
    W16(pe, 0x18, 0x0040);           // e_lfarlc
    W32(pe, 0x3C, 0x00000080);       // e_lfanew → PE header at 0x80

    // DOS stub at 0x40
    static_assert(sizeof(kDOSStubProgram) <= 64,
                  "DOS stub must fit in 0x40..0x7F");
    std::memcpy(pe.data() + 0x40, kDOSStubProgram, sizeof(kDOSStubProgram));

    // ========================================================================
    // PE Signature (0x80)
    // ========================================================================
    W32(pe, 0x80, 0x00004550);       // "PE\0\0"

    // ========================================================================
    // COFF File Header (0x84 - 0x97)
    // ========================================================================
    static constexpr size_t kCOFF = 0x84;
    W16(pe, kCOFF + 0x00, is64bit ? uint16_t{0x8664} : uint16_t{0x014C});
    W16(pe, kCOFF + 0x02, 0x0005);   // NumberOfSections = 5
    W32(pe, kCOFF + 0x04, profile.timeDateStamp);
    // PointerToSymbolTable = 0, NumberOfSymbols = 0
    uint16_t optSize = is64bit ? uint16_t{0x00F0} : uint16_t{0x00E0};
    W16(pe, kCOFF + 0x10, optSize);
    W16(pe, kCOFF + 0x12, static_cast<uint16_t>(profile.characteristics));

    // ========================================================================
    // Optional Header (0x98 - ...)
    // ========================================================================
    static constexpr size_t kOpt = 0x98;

    // DllCharacteristics: DYNAMIC_BASE | NX_COMPAT | HIGH_ENTROPY_VA
    static constexpr uint16_t kDllCharFlags = kStdDllChar;

    if (is64bit) {
        // PE32+
        W16(pe, kOpt + 0x00, 0x020B);       // Magic = PE32+
        pe[kOpt + 0x02] = 14;               // MajorLinkerVersion (MSVC 14.x)
        pe[kOpt + 0x03] = 36;               // MinorLinkerVersion

        // Code/data sizes (realistic approximations based on SizeOfImage)
        uint32_t codeSize = profile.sizeOfImage / 3;
        codeSize = (codeSize + 0x1FF) & ~0x1FFu;   // align to 0x200
        uint32_t dataSize = profile.sizeOfImage / 6;
        dataSize = (dataSize + 0x1FF) & ~0x1FFu;

        W32(pe, kOpt + 0x04, codeSize);     // SizeOfCode
        W32(pe, kOpt + 0x08, dataSize);      // SizeOfInitializedData
        W32(pe, kOpt + 0x0C, 0);             // SizeOfUninitializedData
        W32(pe, kOpt + 0x10, 0x1000);        // AddressOfEntryPoint
        W32(pe, kOpt + 0x14, 0x1000);        // BaseOfCode

        W64(pe, kOpt + 0x18, profile.imageBase);  // ImageBase
        W32(pe, kOpt + 0x20, 0x1000);        // SectionAlignment
        W32(pe, kOpt + 0x24, 0x0200);        // FileAlignment
        W16(pe, kOpt + 0x28, 10);            // MajorOperatingSystemVersion
        W16(pe, kOpt + 0x2A, 0);             // MinorOperatingSystemVersion
        W16(pe, kOpt + 0x2C, profile.majorVersion);
        W16(pe, kOpt + 0x2E, profile.minorVersion);
        W16(pe, kOpt + 0x30, 6);             // MajorSubsystemVersion
        W16(pe, kOpt + 0x32, 0);             // MinorSubsystemVersion
        W32(pe, kOpt + 0x34, 0);             // Win32VersionValue
        W32(pe, kOpt + 0x38, profile.sizeOfImage);
        W32(pe, kOpt + 0x3C, 0x0400);        // SizeOfHeaders
        W32(pe, kOpt + 0x40, profile.checksum);
        W16(pe, kOpt + 0x44, 3);             // Subsystem = WINDOWS_CUI
        W16(pe, kOpt + 0x46, kDllCharFlags);
        W64(pe, kOpt + 0x48, 0x00100000);    // SizeOfStackReserve
        W64(pe, kOpt + 0x50, 0x00001000);    // SizeOfStackCommit
        W64(pe, kOpt + 0x58, 0x00100000);    // SizeOfHeapReserve
        W64(pe, kOpt + 0x60, 0x00001000);    // SizeOfHeapCommit
        W32(pe, kOpt + 0x64, 0);             // LoaderFlags
        W32(pe, kOpt + 0x68, 16);            // NumberOfRvaAndSizes

        // DataDirectory[0] = Export Table → will point into .rdata
        // (set below after we know the offset)
        // DataDirectory[2] = Resource Table → will point into .rsrc

    } else {
        // PE32
        W16(pe, kOpt + 0x00, 0x010B);       // Magic = PE32
        pe[kOpt + 0x02] = 14;
        pe[kOpt + 0x03] = 36;

        uint32_t codeSize = profile.sizeOfImage / 3;
        codeSize = (codeSize + 0x1FF) & ~0x1FFu;
        uint32_t dataSize = profile.sizeOfImage / 6;
        dataSize = (dataSize + 0x1FF) & ~0x1FFu;

        W32(pe, kOpt + 0x04, codeSize);
        W32(pe, kOpt + 0x08, dataSize);
        W32(pe, kOpt + 0x0C, 0);
        W32(pe, kOpt + 0x10, 0x1000);
        W32(pe, kOpt + 0x14, 0x1000);
        W32(pe, kOpt + 0x18, 0x2000);        // BaseOfData
        W32(pe, kOpt + 0x1C, static_cast<uint32_t>(profile.imageBase));
        W32(pe, kOpt + 0x20, 0x1000);
        W32(pe, kOpt + 0x24, 0x0200);
        W16(pe, kOpt + 0x28, 10);
        W16(pe, kOpt + 0x2A, 0);
        W16(pe, kOpt + 0x2C, profile.majorVersion);
        W16(pe, kOpt + 0x2E, profile.minorVersion);
        W16(pe, kOpt + 0x30, 6);
        W16(pe, kOpt + 0x32, 0);
        W32(pe, kOpt + 0x34, 0);
        W32(pe, kOpt + 0x38, profile.sizeOfImage);
        W32(pe, kOpt + 0x3C, 0x0400);
        W32(pe, kOpt + 0x40, profile.checksum);
        W16(pe, kOpt + 0x44, 3);
        W16(pe, kOpt + 0x46, kDllCharFlags);
        W32(pe, kOpt + 0x48, 0x00100000);
        W32(pe, kOpt + 0x4C, 0x00001000);
        W32(pe, kOpt + 0x50, 0x00100000);
        W32(pe, kOpt + 0x54, 0x00001000);
        W32(pe, kOpt + 0x58, 0);
        W32(pe, kOpt + 0x5C, 16);
    }

    // ========================================================================
    // Section Headers (5 sections × 40 bytes each)
    // ========================================================================
    // Start after Optional Header
    size_t secBase = kOpt + optSize;

    // Calculate realistic virtual sizes proportional to SizeOfImage
    uint32_t textVSize  = (profile.sizeOfImage * 40 / 100) & ~0xFFFu;
    uint32_t rdataVSize = (profile.sizeOfImage * 25 / 100) & ~0xFFFu;
    uint32_t dataVSize  = (profile.sizeOfImage * 15 / 100) & ~0xFFFu;
    uint32_t rsrcVSize  = (profile.sizeOfImage * 10 / 100) & ~0xFFFu;
    uint32_t relocVSize = (profile.sizeOfImage *  5 / 100) & ~0xFFFu;

    // Ensure minimums
    if (textVSize  < 0x1000) textVSize  = 0x1000;
    if (rdataVSize < 0x1000) rdataVSize = 0x1000;
    if (dataVSize  < 0x1000) dataVSize  = 0x1000;
    if (rsrcVSize  < 0x1000) rsrcVSize  = 0x1000;
    if (relocVSize < 0x1000) relocVSize = 0x1000;

    uint32_t textVA  = 0x1000;
    uint32_t rdataVA = textVA  + textVSize;
    uint32_t dataVA  = rdataVA + rdataVSize;
    uint32_t rsrcVA  = dataVA  + dataVSize;
    uint32_t relocVA = rsrcVA  + rsrcVSize;

    // Raw sizes / pointers are set to 0x200 minimum for the first
    // section — real content is entirely virtual in our stub.
    // These point to areas within our 4096-byte image that we don't
    // actually fill with meaningful code, but the values must look plausible.

    struct SectionDef {
        const char name[8];
        uint32_t   virtualSize;
        uint32_t   virtualAddr;
        uint32_t   rawSize;
        uint32_t   rawPtr;
        uint32_t   characteristics;
    };

    SectionDef sections[5] = {
        { ".text",   textVSize,  textVA,  0x0200, 0x0400, 0x60000020 },
        { ".rdata",  rdataVSize, rdataVA, 0x0200, 0x0600, 0x40000040 },
        { ".data",   dataVSize,  dataVA,  0x0200, 0x0800, 0xC0000040 },
        { ".rsrc",   rsrcVSize,  rsrcVA,  0x0200, 0x0A00, 0x40000040 },
        { ".reloc",  relocVSize, relocVA, 0x0200, 0x0C00, 0x42000040 },
    };

    for (int i = 0; i < 5; ++i) {
        size_t off = secBase + static_cast<size_t>(i) * 40;
        if (off + 40 > kPageSize) break;

        WriteASCII(pe, off, sections[i].name, 8);
        W32(pe, off +  8, sections[i].virtualSize);
        W32(pe, off + 12, sections[i].virtualAddr);
        W32(pe, off + 16, sections[i].rawSize);
        W32(pe, off + 20, sections[i].rawPtr);
        W32(pe, off + 24, 0);  // PointerToRelocations
        W32(pe, off + 28, 0);  // PointerToLineNumbers
        W16(pe, off + 32, 0);  // NumberOfRelocations
        W16(pe, off + 34, 0);  // NumberOfLineNumbers
        W32(pe, off + 36, sections[i].characteristics);
    }

    // ========================================================================
    // Export Directory (in .rdata raw area, file offset 0x0600)
    // ========================================================================
    // Lay out the export data starting at file offset 0x0400 (which maps to
    // the .rdata section's raw area in our stub).  We place:
    //   - IMAGE_EXPORT_DIRECTORY (40 bytes) at 0x0400
    //   - Export Address Table at 0x0428
    //   - Name Pointer Table after that
    //   - Ordinal Table after that
    //   - Name strings after that

    if (profile.exportCount > 0) {
        static constexpr size_t kExportBase = 0x0400;
        // The RVA base for exports is rdataVA (virtual address of .rdata)
        // File offset 0x0600 maps to rdataVA in the virtual address space
        // But since our raw pointer for .rdata is 0x0600, and our actual
        // export data starts at 0x0400, we calculate the RVA offset as:
        // exportRVA = rdataVA + (fileOffset - rawPtr_of_rdata)
        //
        // Actually, for the stub we place export data at file offset 0x0400
        // which is in the .text raw area. Let's use .rdata area at 0x0600.

        // Recalculate: put exports at 0x0600 (start of .rdata raw data)
        static constexpr size_t kExpFileOff = 0x0600;

        uint32_t numExports = profile.exportCount;

        // IMAGE_EXPORT_DIRECTORY at kExpFileOff
        size_t dirOff = kExpFileOff;
        // Calculate RVA of the export directory itself
        // The .rdata rawPtr = 0x0600, VA = rdataVA
        // So RVA of byte at file offset X = rdataVA + (X - 0x0600)
        uint32_t exportDirRVA = rdataVA; // dirOff - 0x0600 = 0

        W32(pe, dirOff + 0x00, 0);                        // Characteristics
        W32(pe, dirOff + 0x04, profile.timeDateStamp);     // TimeDateStamp
        W16(pe, dirOff + 0x08, 0);                         // MajorVersion
        W16(pe, dirOff + 0x0A, 0);                         // MinorVersion

        // Name RVA — DLL name string (placed after all tables)
        // We'll compute these offsets after laying out the tables.

        uint32_t ordinalBase = 1;
        W32(pe, dirOff + 0x10, ordinalBase);               // Base
        W32(pe, dirOff + 0x14, numExports);                // NumberOfFunctions
        W32(pe, dirOff + 0x18, numExports);                // NumberOfNames

        // Table layout after the 40-byte directory:
        //   Export Address Table: numExports × 4 bytes
        //   Name Pointer Table:  numExports × 4 bytes
        //   Ordinal Table:       numExports × 2 bytes
        //   DLL name string
        //   Export name strings

        size_t eatOff  = dirOff + 40;
        size_t nptOff  = eatOff + numExports * 4;
        size_t ordOff  = nptOff + numExports * 4;
        size_t strOff  = ordOff + numExports * 2;

        // Align strOff to 2-byte boundary
        if (strOff & 1) strOff++;

        // DLL name string
        size_t dllNameOff = strOff;
        const wchar_t* dllNameW = profile.dllName;
        for (size_t i = 0; dllNameW[i]; ++i) {
            if (dllNameOff + i >= kPageSize) break;
            pe[dllNameOff + i] = static_cast<uint8_t>(dllNameW[i] & 0x7F);
        }
        size_t dllNameLen = WideLen(dllNameW);
        size_t namesStart = dllNameOff + dllNameLen + 1;

        // RVA conversion: file offset → RVA
        // For bytes in the .rdata raw area: RVA = rdataVA + (fileOff - 0x0600)
        auto FileToRVA = [rdataVA](size_t fileOff) -> uint32_t {
            return rdataVA + static_cast<uint32_t>(fileOff - 0x0600);
        };

        // Write Name RVA (DLL name) in export directory
        W32(pe, dirOff + 0x0C, FileToRVA(dllNameOff));

        // Write table RVAs in export directory
        W32(pe, dirOff + 0x1C, FileToRVA(eatOff));  // AddressOfFunctions
        W32(pe, dirOff + 0x20, FileToRVA(nptOff));  // AddressOfNames
        W32(pe, dirOff + 0x24, FileToRVA(ordOff));  // AddressOfNameOrdinals

        // Now write the actual tables
        size_t curStrOff = namesStart;

        for (uint32_t i = 0; i < numExports; ++i) {
            // Safety: bail if we'd overflow our page
            if (eatOff + i * 4 + 3 >= kPageSize) break;
            if (nptOff + i * 4 + 3 >= kPageSize) break;
            if (ordOff + i * 2 + 1 >= kPageSize) break;

            // Export Address Table — use the fake RVA from the profile
            W32(pe, eatOff + i * 4, profile.exports[i].rva);

            // Name Pointer Table — RVA of the name string
            if (curStrOff < kPageSize) {
                W32(pe, nptOff + i * 4, FileToRVA(curStrOff));

                // Write the name string
                const char* name = profile.exports[i].name;
                size_t nameLen = std::strlen(name);
                size_t copyLen = std::min(nameLen, kPageSize - curStrOff - 1);
                std::memcpy(pe.data() + curStrOff, name, copyLen);
                pe[curStrOff + copyLen] = 0; // null terminator
                curStrOff += copyLen + 1;
            }

            // Ordinal Table — index into EAT (0-based)
            W16(pe, ordOff + i * 2, static_cast<uint16_t>(i));
        }

        // Set DataDirectory[0] = Export Table
        // DataDirectory is at offset 0x70 from OptionalHeader start (PE32+)
        // or 0x60 from OptionalHeader start (PE32)
        size_t ddOffset;
        if (is64bit) {
            ddOffset = kOpt + 0x70; // DataDirectory[0] for PE32+
        } else {
            ddOffset = kOpt + 0x60; // DataDirectory[0] for PE32
        }
        W32(pe, ddOffset + 0, exportDirRVA);
        W32(pe, ddOffset + 4,
            static_cast<uint32_t>(curStrOff - kExpFileOff)); // size
    }

    // ========================================================================
    // Version Resource (in .rsrc raw area, file offset 0x0A00)
    // ========================================================================
    // Builds a minimal VS_VERSION_INFO structure that PE parsers and
    // GetFileVersionInfo() will recognize.
    {
        static constexpr size_t kRsrcFileOff = 0x0A00;

        // Resource directory pointing to one VS_VERSION_INFO resource
        // We build a simplified resource tree:
        //   Root dir → Type entry (RT_VERSION=16) → Name entry (1) → Lang entry (0x0409)
        //   → Data entry → VS_VERSION_INFO raw data

        // For simplicity, lay out the VERSION_INFO data directly and
        // point the resource directory at it.

        // IMAGE_RESOURCE_DIRECTORY at 0x0A00
        size_t rdOff = kRsrcFileOff;
        W32(pe, rdOff + 0x00, 0);                    // Characteristics
        W32(pe, rdOff + 0x04, profile.timeDateStamp); // TimeDateStamp
        W16(pe, rdOff + 0x08, 0);                     // MajorVersion
        W16(pe, rdOff + 0x0A, 0);                     // MinorVersion
        W16(pe, rdOff + 0x0C, 0);                     // NumberOfNamedEntries
        W16(pe, rdOff + 0x0E, 1);                     // NumberOfIdEntries

        // IMAGE_RESOURCE_DIRECTORY_ENTRY for RT_VERSION (type 16)
        size_t e1 = rdOff + 0x10;
        W32(pe, e1 + 0, 16);                          // Name/ID = RT_VERSION
        W32(pe, e1 + 4, 0x80000028);                  // OffsetToData (high bit = subdir)

        // Second-level directory at offset 0x28 from rsrc start
        size_t d2 = rdOff + 0x28;
        W32(pe, d2 + 0x00, 0);
        W32(pe, d2 + 0x04, 0);
        W16(pe, d2 + 0x08, 0);
        W16(pe, d2 + 0x0A, 0);
        W16(pe, d2 + 0x0C, 0);
        W16(pe, d2 + 0x0E, 1);

        size_t e2 = d2 + 0x10;
        W32(pe, e2 + 0, 1);                           // Name/ID = 1
        W32(pe, e2 + 4, 0x80000048);                  // OffsetToData (high bit = subdir)

        // Third-level directory at offset 0x48 from rsrc start
        size_t d3 = rdOff + 0x48;
        W32(pe, d3 + 0x00, 0);
        W32(pe, d3 + 0x04, 0);
        W16(pe, d3 + 0x08, 0);
        W16(pe, d3 + 0x0A, 0);
        W16(pe, d3 + 0x0C, 0);
        W16(pe, d3 + 0x0E, 1);

        size_t e3 = d3 + 0x10;
        W32(pe, e3 + 0, 0x0409);                      // Language = English (US)
        W32(pe, e3 + 4, 0x68);                         // OffsetToData (leaf)

        // IMAGE_RESOURCE_DATA_ENTRY at offset 0x68 from rsrc start
        size_t leaf = rdOff + 0x68;
        // Data RVA: points to the VS_VERSION_INFO data within .rsrc
        // The data is at rsrcVA + 0x80 (relative offset within section)
        uint32_t versionDataRVA = rsrcVA + 0x80;
        uint32_t versionDataSize = 0x0140; // ~320 bytes
        W32(pe, leaf + 0, versionDataRVA);
        W32(pe, leaf + 4, versionDataSize);
        W32(pe, leaf + 8, 0);                          // CodePage
        W32(pe, leaf + 12, 0);                         // Reserved

        // VS_VERSION_INFO at offset 0x80 from .rsrc raw start
        // (file offset = kRsrcFileOff + 0x80)
        size_t viOff = kRsrcFileOff + 0x80;
        if (viOff + 0x0140 <= kPageSize) {
            // VS_VERSION_INFO header
            W16(pe, viOff + 0x00, 0x0134);   // wLength (total size)
            W16(pe, viOff + 0x02, 0x0034);   // wValueLength (VS_FIXEDFILEINFO = 52 bytes)
            W16(pe, viOff + 0x04, 0x0000);   // wType = binary

            // "VS_VERSION_INFO" as UTF-16LE
            static constexpr wchar_t kVSVI[] = L"VS_VERSION_INFO";
            WriteWideString(pe, viOff + 0x06, kVSVI);
            // String is 15 chars + null = 32 bytes (16 wchars × 2)

            // VS_FIXEDFILEINFO starts at offset 0x06 + 32 = 0x26
            // Align to 4-byte boundary: 0x28
            size_t ffiOff = viOff + 0x28;

            W32(pe, ffiOff + 0x00, 0xFEEF04BD);     // dwSignature
            W32(pe, ffiOff + 0x04, 0x00010000);      // dwStrucVersion (1.0)

            // FileVersion: major.minor.build.0
            W16(pe, ffiOff + 0x0A, profile.majorVersion);  // FileVersionMS high
            W16(pe, ffiOff + 0x08, profile.minorVersion);  // FileVersionMS low
            W16(pe, ffiOff + 0x0E, profile.buildNumber);   // FileVersionLS high
            W16(pe, ffiOff + 0x0C, 0);                     // FileVersionLS low

            // ProductVersion: same as FileVersion
            W16(pe, ffiOff + 0x12, profile.majorVersion);
            W16(pe, ffiOff + 0x10, profile.minorVersion);
            W16(pe, ffiOff + 0x16, profile.buildNumber);
            W16(pe, ffiOff + 0x14, 0);

            W32(pe, ffiOff + 0x18, 0x0000003F);     // dwFileFlagsMask
            W32(pe, ffiOff + 0x1C, 0x00000000);     // dwFileFlags
            W32(pe, ffiOff + 0x20, 0x00040004);     // dwFileOS = VOS_NT_WINDOWS32
            W32(pe, ffiOff + 0x24, 0x00000002);     // dwFileType = VFT_DLL
            W32(pe, ffiOff + 0x28, 0x00000000);     // dwFileSubtype
            W32(pe, ffiOff + 0x2C, 0x00000000);     // dwFileDateMS
            W32(pe, ffiOff + 0x30, 0x00000000);     // dwFileDateLS

            // StringFileInfo block after VS_FIXEDFILEINFO
            // ffiOff + 0x34 = start of StringFileInfo
            size_t sfiOff = ffiOff + 0x34;

            // StringFileInfo header
            W16(pe, sfiOff + 0x00, 0x00C4);          // wLength
            W16(pe, sfiOff + 0x02, 0x0000);           // wValueLength
            W16(pe, sfiOff + 0x04, 0x0001);           // wType = text

            // "StringFileInfo" UTF-16LE
            static constexpr wchar_t kSFI[] = L"StringFileInfo";
            WriteWideString(pe, sfiOff + 0x06, kSFI);
            // 14 chars + null = 30 bytes. Align to 4: 0x26

            // StringTable at sfiOff + 0x26
            size_t stOff = sfiOff + 0x26;
            W16(pe, stOff + 0x00, 0x009C);            // wLength
            W16(pe, stOff + 0x02, 0x0000);             // wValueLength
            W16(pe, stOff + 0x04, 0x0001);             // wType = text

            // "040904B0" (English, Unicode)
            static constexpr wchar_t kLang[] = L"040904B0";
            WriteWideString(pe, stOff + 0x06, kLang);
            // 8 chars + null = 18 bytes. Align to 4: 0x1A → round to 0x1C

            // CompanyName string entry at stOff + 0x1C
            size_t csOff = stOff + 0x1C;
            static constexpr wchar_t kCNKey[] = L"CompanyName";
            static constexpr wchar_t kCNVal[] = L"Microsoft Corporation";
            uint16_t cnValLen = static_cast<uint16_t>(WideLen(kCNVal) + 1);
            uint16_t cnTotalBytes = static_cast<uint16_t>(
                6 + (WideLen(kCNKey) + 1) * 2 + (cnValLen) * 2);
            // Align total
            cnTotalBytes = (cnTotalBytes + 3) & ~3;

            if (csOff + cnTotalBytes < kPageSize) {
                W16(pe, csOff + 0x00, cnTotalBytes);
                W16(pe, csOff + 0x02, cnValLen);
                W16(pe, csOff + 0x04, 0x0001);        // wType = text
                WriteWideString(pe, csOff + 0x06, kCNKey);
                size_t valStart = csOff + 0x06 + (WideLen(kCNKey) + 1) * 2;
                // Align to 4
                if (valStart & 3) valStart = (valStart + 3) & ~3;
                WriteWideString(pe, valStart, kCNVal);

                // ProductName after CompanyName
                size_t pnOff = csOff + cnTotalBytes;
                static constexpr wchar_t kPNKey[] = L"ProductName";
                static constexpr wchar_t kPNVal[] =
                    L"Microsoft\x00ae Windows\x00ae Operating System";
                // Use a simpler version without registered mark for safety
                static constexpr wchar_t kPNValSafe[] =
                    L"Microsoft Windows Operating System";
                uint16_t pnValLen = static_cast<uint16_t>(WideLen(kPNValSafe) + 1);
                uint16_t pnTotalBytes = static_cast<uint16_t>(
                    6 + (WideLen(kPNKey) + 1) * 2 + (pnValLen) * 2);
                pnTotalBytes = (pnTotalBytes + 3) & ~3;

                if (pnOff + pnTotalBytes < kPageSize) {
                    W16(pe, pnOff + 0x00, pnTotalBytes);
                    W16(pe, pnOff + 0x02, pnValLen);
                    W16(pe, pnOff + 0x04, 0x0001);
                    WriteWideString(pe, pnOff + 0x06, kPNKey);
                    size_t pvStart = pnOff + 0x06 + (WideLen(kPNKey) + 1) * 2;
                    if (pvStart & 3) pvStart = (pvStart + 3) & ~3;
                    WriteWideString(pe, pvStart, kPNValSafe);
                }
            }
        }

        // Set DataDirectory[2] = Resource Table
        size_t ddResOffset;
        if (is64bit) {
            ddResOffset = kOpt + 0x70 + 2 * 8; // DataDirectory[2]
        } else {
            ddResOffset = kOpt + 0x60 + 2 * 8;
        }
        W32(pe, ddResOffset + 0, rsrcVA);
        W32(pe, ddResOffset + 4, rsrcVSize);
    }

    return pe;
}


// ============================================================================
// GetStaticFileContent — Return content for known non-PE system files
// ============================================================================

std::vector<uint8_t> GetStaticFileContent(std::wstring_view path) noexcept {
    // Case-insensitive substring search without allocation
    auto containsI = [](std::wstring_view haystack,
                        std::wstring_view needle) noexcept -> bool {
        if (needle.size() > haystack.size()) return false;
        for (size_t i = 0; i <= haystack.size() - needle.size(); ++i) {
            bool match = true;
            for (size_t j = 0; j < needle.size(); ++j) {
                if (std::towlower(static_cast<wint_t>(haystack[i + j])) !=
                    std::towlower(static_cast<wint_t>(needle[j]))) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    };

    // Check for hosts file
    if (EndsWithI(path, L"\\drivers\\etc\\hosts")) {
        return std::vector<uint8_t>(
            reinterpret_cast<const uint8_t*>(kHostsContent),
            reinterpret_cast<const uint8_t*>(kHostsContent) +
                sizeof(kHostsContent) - 1);
    }

    // Check for system.ini (must be under a "windows" directory)
    if (EndsWithI(path, L"\\system.ini") && containsI(path, L"windows")) {
        return std::vector<uint8_t>(
            reinterpret_cast<const uint8_t*>(kSystemIniContent),
            reinterpret_cast<const uint8_t*>(kSystemIniContent) +
                sizeof(kSystemIniContent) - 1);
    }

    // Check for win.ini (must be under a "windows" directory)
    if (EndsWithI(path, L"\\win.ini") && containsI(path, L"windows")) {
        return std::vector<uint8_t>(
            reinterpret_cast<const uint8_t*>(kWinIniContent),
            reinterpret_cast<const uint8_t*>(kWinIniContent) +
                sizeof(kWinIniContent) - 1);
    }

    return {};
}

} // namespace Phantom::VirtualOS

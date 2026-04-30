/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * YaraScanner.cpp — YARA rule scanner implementation
 *
 * Runtime-loads libyara to avoid a hard compile-time dependency. If the
 * library is absent the scanner degrades to built-in masked-pattern matching
 * covering 30+ high-value malware families.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "YaraScanner.hpp"
#include "../Core/Memory/VirtualMemory.hpp"
#include "../Common/Types.hpp"
#include "../Common/Errors.hpp"
#include "../Common/Platform.hpp"

#ifdef PHANTOM_WINDOWS
    #include <windows.h>
#else
    #include <dlfcn.h>
#endif

#include <algorithm>
#include <atomic>
#include <cstring>
#include <mutex>

namespace Phantom {

// ============================================================================
// YARA opaque forward declarations (mirrors libyara internal types)
// ============================================================================

struct YR_RULES;
struct YR_COMPILER;
struct YR_RULE;
struct YR_STRING;
struct YR_MATCH;
struct YR_META;
struct YR_SCAN_CONTEXT;

// YARA callback message constants
static constexpr int YR_CALLBACK_MSG_RULE_MATCHING     = 1;
static constexpr int YR_CALLBACK_MSG_RULE_NOT_MATCHING = 2;
static constexpr int YR_CALLBACK_MSG_SCAN_FINISHED     = 3;
static constexpr int YR_CALLBACK_MSG_IMPORT_MODULE     = 4;

static constexpr int YR_CALLBACK_CONTINUE = 0;
static constexpr int YR_CALLBACK_ABORT    = 1;

static constexpr int YR_ERROR_SUCCESS               = 0;
static constexpr int YR_ERROR_INSUFFICIENT_MEMORY   = 1;
static constexpr int YR_ERROR_COULD_NOT_OPEN_FILE   = 12;
static constexpr int YR_ERROR_SCAN_TIMEOUT          = 32;

// YARA scan flags
static constexpr int SCAN_FLAGS_FAST_MODE = 2;

// ============================================================================
// YARA function pointer typedefs
// ============================================================================

using yr_initialize_fn          = int(*)();
using yr_finalize_fn            = int(*)();
using yr_compiler_create_fn     = int(*)(YR_COMPILER**);
using yr_compiler_destroy_fn    = void(*)(YR_COMPILER*);
using yr_compiler_add_string_fn = int(*)(YR_COMPILER*, const char*, const char*);
using yr_compiler_add_file_fn   = int(*)(YR_COMPILER*, void*, const char*, const char*);
using yr_compiler_get_rules_fn  = int(*)(YR_COMPILER*, YR_RULES**);
using yr_rules_destroy_fn       = int(*)(YR_RULES*);
using yr_rules_scan_mem_fn      = int(*)(YR_RULES*, const uint8_t*, size_t,
                                         int, void* /*callback*/, void* /*user_data*/,
                                         int /*timeout*/);
using yr_rules_load_fn          = int(*)(const char*, YR_RULES**);
using yr_rules_save_fn          = int(*)(YR_RULES*, const char*);

// ============================================================================
// Built-in Pattern Definition
// ============================================================================

struct BuiltinPattern {
    const char*              name;
    const char*              description;
    const char*              severity;
    std::vector<uint8_t>     pattern;
    std::vector<uint8_t>     mask;     // 0xFF = exact, 0x00 = wildcard
    std::vector<std::string> mitreTags;
    const char*              family;
};

// ============================================================================
// PIMPL Implementation
// ============================================================================

struct YaraScanner::Impl {

    // --- Library handle -----------------------------------------------------

#ifdef PHANTOM_WINDOWS
    HMODULE libraryHandle = nullptr;
#else
    void* libraryHandle = nullptr;
#endif

    // --- YARA function pointers ---------------------------------------------

    yr_initialize_fn          fn_yr_initialize          = nullptr;
    yr_finalize_fn            fn_yr_finalize            = nullptr;
    yr_compiler_create_fn     fn_yr_compiler_create     = nullptr;
    yr_compiler_destroy_fn    fn_yr_compiler_destroy    = nullptr;
    yr_compiler_add_string_fn fn_yr_compiler_add_string = nullptr;
    yr_compiler_get_rules_fn  fn_yr_compiler_get_rules  = nullptr;
    yr_rules_destroy_fn       fn_yr_rules_destroy       = nullptr;
    yr_rules_scan_mem_fn      fn_yr_rules_scan_mem      = nullptr;
    yr_rules_load_fn          fn_yr_rules_load          = nullptr;

    // --- State --------------------------------------------------------------

    YR_RULES* rules         = nullptr;
    bool      yaraInited    = false;
    bool      available     = false;

    // --- Statistics (atomic for thread-safe reads) ---------------------------

    std::atomic<uint32_t> ruleCount   { 0 };
    std::atomic<uint32_t> totalScans  { 0 };
    std::atomic<uint32_t> totalMatches{ 0 };
    std::atomic<uint32_t> scanErrors  { 0 };

    // --- Built-in patterns --------------------------------------------------

    std::vector<BuiltinPattern> builtinPatterns;
    std::mutex                  scanMutex; // Protects YARA rule compilation

    // ========================================================================
    // Helpers
    // ========================================================================

    void LoadLibrarySymbols() noexcept;
    void InitializeBuiltinPatterns() noexcept;
    void AddPattern(const char* name, const char* desc, const char* sev,
                    std::vector<uint8_t> pat, std::vector<uint8_t> msk,
                    std::vector<std::string> mitre, const char* fam) noexcept;
    void Cleanup() noexcept;
};

// ============================================================================
// Symbol resolution helpers
// ============================================================================

#ifdef PHANTOM_WINDOWS
static void* ResolveSymbol(HMODULE lib, const char* sym) noexcept {
    return reinterpret_cast<void*>(::GetProcAddress(lib, sym));
}
#else
static void* ResolveSymbol(void* lib, const char* sym) noexcept {
    return ::dlsym(lib, sym);
}
#endif

void YaraScanner::Impl::LoadLibrarySymbols() noexcept {
    if (!libraryHandle) return;

    fn_yr_initialize          = reinterpret_cast<yr_initialize_fn>(ResolveSymbol(libraryHandle, "yr_initialize"));
    fn_yr_finalize            = reinterpret_cast<yr_finalize_fn>(ResolveSymbol(libraryHandle, "yr_finalize"));
    fn_yr_compiler_create     = reinterpret_cast<yr_compiler_create_fn>(ResolveSymbol(libraryHandle, "yr_compiler_create"));
    fn_yr_compiler_destroy    = reinterpret_cast<yr_compiler_destroy_fn>(ResolveSymbol(libraryHandle, "yr_compiler_destroy"));
    fn_yr_compiler_add_string = reinterpret_cast<yr_compiler_add_string_fn>(ResolveSymbol(libraryHandle, "yr_compiler_add_string"));
    fn_yr_compiler_get_rules  = reinterpret_cast<yr_compiler_get_rules_fn>(ResolveSymbol(libraryHandle, "yr_compiler_get_rules"));
    fn_yr_rules_destroy       = reinterpret_cast<yr_rules_destroy_fn>(ResolveSymbol(libraryHandle, "yr_rules_destroy"));
    fn_yr_rules_scan_mem      = reinterpret_cast<yr_rules_scan_mem_fn>(ResolveSymbol(libraryHandle, "yr_rules_scan_mem"));
    fn_yr_rules_load          = reinterpret_cast<yr_rules_load_fn>(ResolveSymbol(libraryHandle, "yr_rules_load"));
}

void YaraScanner::Impl::Cleanup() noexcept {
    if (rules && fn_yr_rules_destroy) {
        fn_yr_rules_destroy(rules);
        rules = nullptr;
    }
    if (yaraInited && fn_yr_finalize) {
        fn_yr_finalize();
        yaraInited = false;
    }
#ifdef PHANTOM_WINDOWS
    if (libraryHandle) {
        ::FreeLibrary(libraryHandle);
        libraryHandle = nullptr;
    }
#else
    if (libraryHandle) {
        ::dlclose(libraryHandle);
        libraryHandle = nullptr;
    }
#endif
    available = false;
}

// ============================================================================
// AddPattern — register a single built-in pattern
// ============================================================================

void YaraScanner::Impl::AddPattern(
    const char* name, const char* desc, const char* sev,
    std::vector<uint8_t> pat, std::vector<uint8_t> msk,
    std::vector<std::string> mitre, const char* fam) noexcept
{
    if (pat.empty() || pat.size() != msk.size()) return;

    builtinPatterns.push_back(BuiltinPattern{
        name, desc, sev,
        std::move(pat), std::move(msk),
        std::move(mitre), fam
    });
}

// ============================================================================
// InitializeBuiltinPatterns — 35 high-value malware / shellcode signatures
// ============================================================================

void YaraScanner::Impl::InitializeBuiltinPatterns() noexcept {
    builtinPatterns.clear();
    builtinPatterns.reserve(40);

    // Helper lambda: produce a mask of all-0xFF matching the pattern length
    auto ExactMask = [](size_t len) -> std::vector<uint8_t> {
        return std::vector<uint8_t>(len, 0xFF);
    };

    // ------------------------------------------------------------------
    // 1. Metasploit reverse_tcp stager (x86)
    // ------------------------------------------------------------------
    AddPattern("Meterpreter_ReverseTCP_x86",
        "Metasploit reverse TCP stager (x86)",
        "malicious",
        {0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00, 0x60, 0x89, 0xE5},
        ExactMask(9),
        {"T1059.001", "T1071.001"}, "Metasploit");

    // ------------------------------------------------------------------
    // 2. Metasploit reverse_tcp stager (x64)
    // ------------------------------------------------------------------
    AddPattern("Meterpreter_ReverseTCP_x64",
        "Metasploit reverse TCP stager (x64)",
        "malicious",
        {0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8},
        ExactMask(6),
        {"T1059.001", "T1071.001"}, "Metasploit");

    // ------------------------------------------------------------------
    // 3. Cobalt Strike beacon config block
    // ------------------------------------------------------------------
    AddPattern("CobaltStrike_Beacon_Config",
        "Cobalt Strike beacon configuration",
        "critical",
        {0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02},
        ExactMask(10),
        {"T1071.001", "T1573.002"}, "CobaltStrike");

    // ------------------------------------------------------------------
    // 4. Cobalt Strike named-pipe stager
    // ------------------------------------------------------------------
    AddPattern("CobaltStrike_PipeStager",
        "Cobalt Strike SMB named-pipe stager",
        "critical",
        // "\\\\.\\pipe\\MSSE-" as ASCII bytes
        {0x5C, 0x5C, 0x2E, 0x5C, 0x70, 0x69, 0x70, 0x65, 0x5C, 0x4D, 0x53, 0x53, 0x45, 0x2D},
        ExactMask(14),
        {"T1570", "T1071.001"}, "CobaltStrike");

    // ------------------------------------------------------------------
    // 5. Mimikatz "sekurlsa" string
    // ------------------------------------------------------------------
    AddPattern("Mimikatz_Sekurlsa",
        "Mimikatz credential dumper (sekurlsa module)",
        "critical",
        {0x73, 0x65, 0x6B, 0x75, 0x72, 0x6C, 0x73, 0x61},
        ExactMask(8),
        {"T1003.001"}, "Mimikatz");

    // ------------------------------------------------------------------
    // 6. Mimikatz "kerberos" credential string
    // ------------------------------------------------------------------
    AddPattern("Mimikatz_Kerberos",
        "Mimikatz Kerberos ticket extraction",
        "critical",
        // "kerberos::list" ASCII
        {0x6B, 0x65, 0x72, 0x62, 0x65, 0x72, 0x6F, 0x73, 0x3A, 0x3A, 0x6C, 0x69, 0x73, 0x74},
        ExactMask(14),
        {"T1558.003"}, "Mimikatz");

    // ------------------------------------------------------------------
    // 7. NOP sled (16 bytes)
    // ------------------------------------------------------------------
    AddPattern("NOP_Sled_16",
        "16-byte NOP sled indicating potential shellcode",
        "suspicious",
        {0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
         0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90},
        ExactMask(16),
        {"T1055"}, "");

    // ------------------------------------------------------------------
    // 8. API hash resolution (ROR13): mov edi, <hash>; xor edx,edx
    // ------------------------------------------------------------------
    AddPattern("API_Hash_ROR13",
        "API hash-based import resolution (ROR13 pattern)",
        "suspicious",
        {0xBF, 0x00, 0x00, 0x00, 0x00, 0x33, 0xD2, 0x52, 0x52},
        {0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF},
        {"T1027.007", "T1106"}, "");

    // ------------------------------------------------------------------
    // 9. WannaCry ransomware file extension marker
    // ------------------------------------------------------------------
    AddPattern("WannaCry_Extension",
        "WannaCry ransomware file extension marker",
        "critical",
        // ".WNCRY" ASCII
        {0x2E, 0x57, 0x4E, 0x43, 0x52, 0x59},
        ExactMask(6),
        {"T1486"}, "WannaCry");

    // ------------------------------------------------------------------
    // 10. Generic ransomware note indicator (ASCII)
    //     "YOUR FILES HAVE BEEN ENCRYPTED"
    // ------------------------------------------------------------------
    {
        const char* note = "YOUR FILES HAVE BEEN ENCRYPTED";
        std::vector<uint8_t> p(note, note + 30);
        AddPattern("Ransomware_Note_Generic",
            "Generic ransomware note string",
            "malicious",
            std::move(p), ExactMask(30),
            {"T1486"}, "");
    }

    // ------------------------------------------------------------------
    // 11. Reflective DLL injection (MZ header in non-standard memory)
    //     "ReflectiveLoader" string
    // ------------------------------------------------------------------
    {
        const char* s = "ReflectiveLoader";
        std::vector<uint8_t> p(s, s + 16);
        AddPattern("ReflectiveDLL_Loader",
            "Reflective DLL injection loader string",
            "malicious",
            std::move(p), ExactMask(16),
            {"T1055.001"}, "");
    }

    // ------------------------------------------------------------------
    // 12. EternalBlue exploit: SMB transaction header signature
    // ------------------------------------------------------------------
    AddPattern("EternalBlue_SMB_Signature",
        "EternalBlue SMB exploit transaction signature",
        "critical",
        {0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00, 0x00, 0x00, 0x00},
        ExactMask(9),
        {"T1210"}, "EternalBlue");

    // ------------------------------------------------------------------
    // 13. Process hollowing: NtUnmapViewOfSection + NtWriteVirtualMemory
    //     x64 syscall-based pattern: mov r10,rcx; mov eax,<syscall#>
    // ------------------------------------------------------------------
    AddPattern("Syscall_Direct_Invoke",
        "Direct syscall invocation (syscall stub pattern)",
        "suspicious",
        {0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05},
        {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF},
        {"T1055.012", "T1106"}, "");

    // ------------------------------------------------------------------
    // 14. Emotet dropper epoch pattern
    // ------------------------------------------------------------------
    AddPattern("Emotet_Epoch_Marker",
        "Emotet banking trojan dropper marker",
        "critical",
        // "Epoch" followed by version digits
        {0x45, 0x70, 0x6F, 0x63, 0x68, 0x00, 0x00},
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00},
        {"T1547.001", "T1059.005"}, "Emotet");

    // ------------------------------------------------------------------
    // 15. AgentTesla keylogger (common C# string)
    // ------------------------------------------------------------------
    {
        const char* s = "AgentTesla";
        std::vector<uint8_t> p(s, s + 10);
        AddPattern("AgentTesla_Marker",
            "AgentTesla keylogger/stealer string",
            "malicious",
            std::move(p), ExactMask(10),
            {"T1056.001", "T1555"}, "AgentTesla");
    }

    // ------------------------------------------------------------------
    // 16. PowerShell encoded command indicator (-EncodedCommand)
    // ------------------------------------------------------------------
    {
        const char* s = "-EncodedCommand";
        std::vector<uint8_t> p(s, s + 15);
        AddPattern("PowerShell_Encoded",
            "PowerShell encoded command execution",
            "suspicious",
            std::move(p), ExactMask(15),
            {"T1059.001", "T1027"}, "");
    }

    // ------------------------------------------------------------------
    // 17. PowerShell IEX (Invoke-Expression) download cradle
    // ------------------------------------------------------------------
    {
        const char* s = "IEX(New-Object";
        std::vector<uint8_t> p(s, s + 14);
        AddPattern("PowerShell_IEX_Cradle",
            "PowerShell Invoke-Expression download cradle",
            "malicious",
            std::move(p), ExactMask(14),
            {"T1059.001", "T1105"}, "");
    }

    // ------------------------------------------------------------------
    // 18. Heaven's Gate (32→64 bit transition via retf to 0x33 segment)
    //     push 0x33; push <addr>; retf
    // ------------------------------------------------------------------
    AddPattern("HeavensGate_Retf",
        "Heaven's Gate 32-to-64-bit code segment transition",
        "suspicious",
        {0x6A, 0x33, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x05, 0xCB},
        {0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        {"T1055", "T1027.009"}, "");

    // ------------------------------------------------------------------
    // 19. Shellcode PEB walk: mov eax,[fs:0x30] (x86) / mov rax,[gs:0x60] (x64)
    //     x86 variant: 64 A1 30 00 00 00
    // ------------------------------------------------------------------
    AddPattern("Shellcode_PEB_Walk_x86",
        "x86 PEB access via FS segment (shellcode indicator)",
        "suspicious",
        {0x64, 0xA1, 0x30, 0x00, 0x00, 0x00},
        ExactMask(6),
        {"T1055", "T1106"}, "");

    // ------------------------------------------------------------------
    // 20. Shellcode PEB walk x64: 65 48 8B 04 25 60 00 00 00
    // ------------------------------------------------------------------
    AddPattern("Shellcode_PEB_Walk_x64",
        "x64 PEB access via GS segment (shellcode indicator)",
        "suspicious",
        {0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00},
        ExactMask(9),
        {"T1055", "T1106"}, "");

    // ------------------------------------------------------------------
    // 21. QakBot / QBot banking trojan marker
    // ------------------------------------------------------------------
    {
        const char* s = "qbot";
        std::vector<uint8_t> p(s, s + 4);
        AddPattern("QakBot_Marker",
            "QakBot/QBot banking trojan marker",
            "malicious",
            std::move(p), ExactMask(4),
            {"T1071.001", "T1547.001"}, "QakBot");
    }

    // ------------------------------------------------------------------
    // 22. Remcos RAT identification string
    // ------------------------------------------------------------------
    {
        const char* s = "Remcos_Mutex_";
        std::vector<uint8_t> p(s, s + 13);
        AddPattern("Remcos_RAT_Mutex",
            "Remcos RAT mutex identification",
            "critical",
            std::move(p), ExactMask(13),
            {"T1219"}, "Remcos");
    }

    // ------------------------------------------------------------------
    // 23. AsyncRAT marker
    // ------------------------------------------------------------------
    {
        const char* s = "AsyncClient";
        std::vector<uint8_t> p(s, s + 11);
        AddPattern("AsyncRAT_Client",
            "AsyncRAT client identification string",
            "malicious",
            std::move(p), ExactMask(11),
            {"T1219"}, "AsyncRAT");
    }

    // ------------------------------------------------------------------
    // 24. DarkComet RAT marker
    // ------------------------------------------------------------------
    {
        const char* s = "DarkComet";
        std::vector<uint8_t> p(s, s + 9);
        AddPattern("DarkComet_RAT",
            "DarkComet RAT identification string",
            "malicious",
            std::move(p), ExactMask(9),
            {"T1219"}, "DarkComet");
    }

    // ------------------------------------------------------------------
    // 25. njRAT mutex pattern
    // ------------------------------------------------------------------
    {
        const char* s = "njRAT";
        std::vector<uint8_t> p(s, s + 5);
        AddPattern("njRAT_Marker",
            "njRAT remote access trojan marker",
            "malicious",
            std::move(p), ExactMask(5),
            {"T1219"}, "njRAT");
    }

    // ------------------------------------------------------------------
    // 26. PE header in non-standard memory (reflective injection)
    //     MZ + PE\0\0 at offset field
    // ------------------------------------------------------------------
    AddPattern("MZ_Header_InMemory",
        "PE MZ header found in memory (possible reflective load)",
        "suspicious",
        {0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00},
        {0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0x00, 0x00, 0x00},
        {"T1055.001", "T1620"}, "");

    // ------------------------------------------------------------------
    // 27. Common packer: UPX section header "UPX0"
    // ------------------------------------------------------------------
    {
        const char* s = "UPX0";
        std::vector<uint8_t> p(s, s + 4);
        AddPattern("UPX_Packer",
            "UPX packer section header",
            "info",
            std::move(p), ExactMask(4),
            {"T1027.002"}, "");
    }

    // ------------------------------------------------------------------
    // 28. Themida/WinLicense packer marker
    // ------------------------------------------------------------------
    {
        const char* s = ".themida";
        std::vector<uint8_t> p(s, s + 8);
        AddPattern("Themida_Packer",
            "Themida/WinLicense packer section",
            "suspicious",
            std::move(p), ExactMask(8),
            {"T1027.002"}, "");
    }

    // ------------------------------------------------------------------
    // 29. VirtualAlloc + WriteProcessMemory injection pattern (x64)
    //     Common shellcode: sub rsp,0x28; call [rax+VirtualAlloc]
    // ------------------------------------------------------------------
    AddPattern("Injection_Stack_Setup_x64",
        "x64 shellcode injection stack setup pattern",
        "suspicious",
        {0x48, 0x83, 0xEC, 0x28, 0xFF},
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        {"T1055"}, "");

    // ------------------------------------------------------------------
    // 30. Trickbot module marker
    // ------------------------------------------------------------------
    {
        const char* s = "<moduleconfig>";
        std::vector<uint8_t> p(s, s + 14);
        AddPattern("TrickBot_ModuleConfig",
            "TrickBot module configuration XML marker",
            "critical",
            std::move(p), ExactMask(14),
            {"T1547.001", "T1071.001"}, "TrickBot");
    }

    // ------------------------------------------------------------------
    // 31. IcedID / BokBot loader beacon
    // ------------------------------------------------------------------
    {
        const char* s = "Cookie: __gads=";
        std::vector<uint8_t> p(s, s + 15);
        AddPattern("IcedID_Beacon_Cookie",
            "IcedID/BokBot C2 beacon cookie pattern",
            "malicious",
            std::move(p), ExactMask(15),
            {"T1071.001"}, "IcedID");
    }

    // ------------------------------------------------------------------
    // 32. SilverC2 / Sliver implant marker
    // ------------------------------------------------------------------
    {
        const char* s = "sliver";
        std::vector<uint8_t> p(s, s + 6);
        AddPattern("Sliver_Implant",
            "Sliver C2 framework implant identifier",
            "critical",
            std::move(p), ExactMask(6),
            {"T1071.001", "T1573"}, "Sliver");
    }

    // ------------------------------------------------------------------
    // 33. BruteRatel C4 badger marker
    // ------------------------------------------------------------------
    {
        const char* s = "badger_";
        std::vector<uint8_t> p(s, s + 7);
        AddPattern("BruteRatel_Badger",
            "Brute Ratel C4 badger payload marker",
            "critical",
            std::move(p), ExactMask(7),
            {"T1071.001", "T1055"}, "BruteRatel");
    }

    // ------------------------------------------------------------------
    // 34. AMSI bypass: amsi.dll patch pattern (mov eax,0x80070057; ret)
    //     Common AMSI bypass shellcode
    // ------------------------------------------------------------------
    AddPattern("AMSI_Bypass_Patch",
        "AMSI bypass patch (amsi.dll AmsiScanBuffer hook)",
        "malicious",
        {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3},
        ExactMask(6),
        {"T1562.001"}, "");

    // ------------------------------------------------------------------
    // 35. ETW bypass: ntdll!EtwEventWrite patch (xor eax,eax; ret)
    // ------------------------------------------------------------------
    AddPattern("ETW_Bypass_Patch",
        "ETW bypass patch (ntdll EtwEventWrite hook)",
        "malicious",
        {0x33, 0xC0, 0xC3, 0x90, 0x90},
        ExactMask(5),
        {"T1562.006"}, "");

    // ------------------------------------------------------------------
    // 36. Common shellcode: int 0x80 (Linux syscall in x86)
    //     Appears in cross-platform shellcode payloads
    // ------------------------------------------------------------------
    AddPattern("Linux_Syscall_Int80",
        "Linux int 0x80 syscall instruction (shellcode indicator)",
        "suspicious",
        {0xCD, 0x80},
        ExactMask(2),
        {"T1059"}, "");

    // ------------------------------------------------------------------
    // 37. REvil / Sodinokibi ransomware config marker
    // ------------------------------------------------------------------
    {
        const char* s = "{\"pk\":\"";
        std::vector<uint8_t> p(s, s + 7);
        AddPattern("REvil_Config",
            "REvil/Sodinokibi ransomware configuration JSON",
            "critical",
            std::move(p), ExactMask(7),
            {"T1486"}, "REvil");
    }

    // ------------------------------------------------------------------
    // 38. LockBit ransomware extension marker
    // ------------------------------------------------------------------
    {
        const char* s = ".lockbit";
        std::vector<uint8_t> p(s, s + 8);
        AddPattern("LockBit_Extension",
            "LockBit ransomware file extension",
            "critical",
            std::move(p), ExactMask(8),
            {"T1486"}, "LockBit");
    }

    // ------------------------------------------------------------------
    // 39. BlackCat / ALPHV ransomware marker
    // ------------------------------------------------------------------
    {
        const char* s = "access-token";
        std::vector<uint8_t> p(s, s + 12);
        AddPattern("BlackCat_Token",
            "BlackCat/ALPHV ransomware access-token parameter",
            "malicious",
            std::move(p), ExactMask(12),
            {"T1486"}, "BlackCat");
    }

    // ------------------------------------------------------------------
    // 40. Havoc C2 Demon implant marker
    // ------------------------------------------------------------------
    {
        const char* s = "HavocDemon";
        std::vector<uint8_t> p(s, s + 10);
        AddPattern("Havoc_Demon",
            "Havoc C2 framework Demon implant identifier",
            "critical",
            std::move(p), ExactMask(10),
            {"T1071.001", "T1573"}, "Havoc");
    }
}

// ============================================================================
// Ctor / Dtor / Move
// ============================================================================

YaraScanner::YaraScanner() noexcept
    : m_impl(std::make_unique<Impl>())
{}

YaraScanner::~YaraScanner() noexcept {
    if (m_impl) {
        m_impl->Cleanup();
    }
}

YaraScanner::YaraScanner(YaraScanner&&) noexcept = default;
YaraScanner& YaraScanner::operator=(YaraScanner&&) noexcept = default;

// ============================================================================
// Initialize — load libyara at runtime, then always populate built-in patterns
// ============================================================================

bool YaraScanner::Initialize() noexcept {
    if (!m_impl) return false;

    // Attempt to load the YARA shared library
#ifdef PHANTOM_WINDOWS
    m_impl->libraryHandle = ::LoadLibraryA("yara.dll");
    if (!m_impl->libraryHandle) {
        m_impl->libraryHandle = ::LoadLibraryA("libyara.dll");
    }
    if (!m_impl->libraryHandle) {
        // Try subdirectory commonly used for third-party DLLs
        m_impl->libraryHandle = ::LoadLibraryA("plugins\\yara.dll");
    }
#else
    m_impl->libraryHandle = ::dlopen("libyara.so", RTLD_LAZY);
    if (!m_impl->libraryHandle) {
        m_impl->libraryHandle = ::dlopen("libyara.so.4", RTLD_LAZY);
    }
#endif

    if (m_impl->libraryHandle) {
        m_impl->LoadLibrarySymbols();

        // Verify minimum required symbols
        if (m_impl->fn_yr_initialize &&
            m_impl->fn_yr_compiler_create &&
            m_impl->fn_yr_compiler_add_string &&
            m_impl->fn_yr_compiler_get_rules &&
            m_impl->fn_yr_rules_scan_mem &&
            m_impl->fn_yr_rules_destroy)
        {
            int rc = m_impl->fn_yr_initialize();
            if (rc == YR_ERROR_SUCCESS) {
                m_impl->yaraInited = true;
                m_impl->available  = true;
            }
        }

        // If we failed to initialize, unload the library
        if (!m_impl->available) {
#ifdef PHANTOM_WINDOWS
            ::FreeLibrary(m_impl->libraryHandle);
#else
            ::dlclose(m_impl->libraryHandle);
#endif
            m_impl->libraryHandle = nullptr;
        }
    }

    // Built-in patterns are always available
    m_impl->InitializeBuiltinPatterns();

    return m_impl->available;
}

// ============================================================================
// IsAvailable
// ============================================================================

bool YaraScanner::IsAvailable() const noexcept {
    return m_impl && m_impl->available;
}

// ============================================================================
// LoadRulesFromFile
// ============================================================================

bool YaraScanner::LoadRulesFromFile(const std::filesystem::path& path) noexcept {
    if (!m_impl || !m_impl->available) return false;

    std::lock_guard<std::mutex> lock(m_impl->scanMutex);

    // First try loading as pre-compiled rules
    if (m_impl->fn_yr_rules_load) {
        // Destroy previous rules
        if (m_impl->rules && m_impl->fn_yr_rules_destroy) {
            m_impl->fn_yr_rules_destroy(m_impl->rules);
            m_impl->rules = nullptr;
            m_impl->ruleCount.store(0, std::memory_order_relaxed);
        }

        std::string pathStr = path.string();
        int rc = m_impl->fn_yr_rules_load(pathStr.c_str(), &m_impl->rules);
        if (rc == YR_ERROR_SUCCESS && m_impl->rules) {
            return true;
        }
        // If failed, fall through to try source compilation
    }

    // Try to compile from source file
    if (!m_impl->fn_yr_compiler_create ||
        !m_impl->fn_yr_compiler_get_rules) {
        return false;
    }

    // Read file contents
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || ec) return false;

    auto fileSize = std::filesystem::file_size(path, ec);
    if (ec || fileSize == 0 || fileSize > 64ULL * 1024 * 1024) return false;

    FILE* fp = nullptr;
#ifdef PHANTOM_WINDOWS
    if (fopen_s(&fp, path.string().c_str(), "r") != 0 || !fp) return false;
#else
    fp = std::fopen(path.string().c_str(), "r");
    if (!fp) return false;
#endif

    std::vector<char> content(static_cast<size_t>(fileSize) + 1, 0);
    size_t bytesRead = std::fread(content.data(), 1, static_cast<size_t>(fileSize), fp);
    std::fclose(fp);

    if (bytesRead == 0) return false;
    content[bytesRead] = '\0';

    return LoadRulesFromString(std::string_view(content.data(), bytesRead));
}

// ============================================================================
// LoadRulesFromString
// ============================================================================

bool YaraScanner::LoadRulesFromString(std::string_view ruleSource) noexcept {
    if (!m_impl || !m_impl->available) return false;
    if (ruleSource.empty()) return false;

    std::lock_guard<std::mutex> lock(m_impl->scanMutex);

    // Destroy previous rules
    if (m_impl->rules && m_impl->fn_yr_rules_destroy) {
        m_impl->fn_yr_rules_destroy(m_impl->rules);
        m_impl->rules = nullptr;
        m_impl->ruleCount.store(0, std::memory_order_relaxed);
    }

    YR_COMPILER* compiler = nullptr;
    int rc = m_impl->fn_yr_compiler_create(&compiler);
    if (rc != YR_ERROR_SUCCESS || !compiler) return false;

    // YARA expects null-terminated string; ruleSource may not be, so copy
    std::string sourceStr(ruleSource);

    rc = m_impl->fn_yr_compiler_add_string(compiler, sourceStr.c_str(), nullptr);
    if (rc != 0) {
        // rc is the number of errors
        m_impl->fn_yr_compiler_destroy(compiler);
        m_impl->scanErrors.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    rc = m_impl->fn_yr_compiler_get_rules(compiler, &m_impl->rules);
    m_impl->fn_yr_compiler_destroy(compiler);

    if (rc != YR_ERROR_SUCCESS || !m_impl->rules) {
        m_impl->scanErrors.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    return true;
}

// ============================================================================
// LoadCompiledRules — load from in-memory binary blob via temp path
// ============================================================================

bool YaraScanner::LoadCompiledRules(std::span<const uint8_t> data) noexcept {
    if (!m_impl || !m_impl->available || !m_impl->fn_yr_rules_load) return false;
    if (data.empty() || data.size() > 256ULL * 1024 * 1024) return false;

    std::lock_guard<std::mutex> lock(m_impl->scanMutex);

    // YARA's yr_rules_load only accepts a file path, so we must write a
    // temporary file.
    //
    // DESIGN (Tier 4 — CWE-377 insecure temp file, CWE-367 TOCTOU,
    // CWE-59 symlink-following): the previous implementation wrote
    // "yara_compiled_rules.bin" in std::filesystem::current_path() using
    // a deterministic filename. That gave any local non-privileged user
    // (including the emulated guest's host counterpart) a race window to
    // pre-plant a junction or hardlink at the path before the fopen, or
    // to swap the file between fwrite and yr_rules_load. Mitigations:
    //   1. Place the file under the system temp directory, not the
    //      current working directory which can be attacker-controlled.
    //   2. Embed PID + a high-resolution counter in the filename so two
    //      concurrent emulator instances cannot collide and a pre-planted
    //      file at a guessed path cannot be racing the legitimate write.
    //   3. On Windows, open with CREATE_NEW + FILE_FLAG_DELETE_ON_CLOSE
    //      and FILE_SHARE_READ only, so an existing file at the path
    //      causes failure rather than overwrite, and the file is removed
    //      automatically even on crash. yr_rules_load opens the path by
    //      name so we keep the handle open across the load and rely on
    //      Windows' name-locking to prevent swap.
    std::error_code ec;
    auto tempDir = std::filesystem::temp_directory_path(ec);
    if (ec) return false;

    static std::atomic<uint64_t> s_counter{0};
    const uint64_t seq = s_counter.fetch_add(1, std::memory_order_relaxed);
#ifdef PHANTOM_WINDOWS
    const auto pid = static_cast<uint64_t>(::GetCurrentProcessId());
#else
    const auto pid = static_cast<uint64_t>(::getpid());
#endif
    char nameBuf[96];
    std::snprintf(nameBuf, sizeof(nameBuf),
                  "phantom_yara_%llu_%llu.bin",
                  static_cast<unsigned long long>(pid),
                  static_cast<unsigned long long>(seq));
    auto tempPath = tempDir / nameBuf;

#ifdef PHANTOM_WINDOWS
    // CREATE_NEW fails if the path already exists — defeats pre-plant races.
    HANDLE hFile = ::CreateFileA(
        tempPath.string().c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE,
        nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD totalWritten = 0;
    while (totalWritten < data.size()) {
        const auto remaining = data.size() - totalWritten;
        const DWORD chunk = remaining > 0x40000000u
                                ? 0x40000000u
                                : static_cast<DWORD>(remaining);
        DWORD wroteNow = 0;
        if (!::WriteFile(hFile, data.data() + totalWritten, chunk,
                         &wroteNow, nullptr) || wroteNow == 0) {
            ::CloseHandle(hFile);
            return false;
        }
        totalWritten += wroteNow;
    }
    if (!::FlushFileBuffers(hFile)) {
        ::CloseHandle(hFile);
        return false;
    }
#else
    // POSIX: O_CREAT|O_EXCL gives the same anti-race property; mode 0600
    // restricts to the owning user.
    int fd = ::open(tempPath.string().c_str(),
                    O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return false;
    size_t totalWrittenP = 0;
    while (totalWrittenP < data.size()) {
        ssize_t w = ::write(fd, data.data() + totalWrittenP,
                            data.size() - totalWrittenP);
        if (w <= 0) { ::close(fd); ::unlink(tempPath.string().c_str()); return false; }
        totalWrittenP += static_cast<size_t>(w);
    }
    ::close(fd);
#endif

    // Destroy previous rules
    if (m_impl->rules && m_impl->fn_yr_rules_destroy) {
        m_impl->fn_yr_rules_destroy(m_impl->rules);
        m_impl->rules = nullptr;
        m_impl->ruleCount.store(0, std::memory_order_relaxed);
    }

    int rc = m_impl->fn_yr_rules_load(tempPath.string().c_str(), &m_impl->rules);

#ifdef PHANTOM_WINDOWS
    // FILE_FLAG_DELETE_ON_CLOSE removes the file once the handle closes.
    ::CloseHandle(hFile);
#else
    std::filesystem::remove(tempPath, ec);
#endif

    if (rc != YR_ERROR_SUCCESS || !m_impl->rules) {
        m_impl->scanErrors.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    return true;
}

// ============================================================================
// YARA scan callback (used by ScanBuffer with libyara)
// ============================================================================

namespace {

struct YaraScanContext {
    std::vector<YaraMatch>* results;
    uint32_t matchLimit;
};

// YARA callback receives opaque rule pointer. We only process
// CALLBACK_MSG_RULE_MATCHING. Because we define our own YR_RULE struct layout
// we cannot dereference members. Instead, we create a minimal match entry.
// Full metadata extraction requires YARA header structures which we avoid to
// keep the runtime dependency optional.
int YaraScanCallback(void* /*context*/, int message,
                     void* /*message_data*/, void* user_data) noexcept
{
    if (!user_data) return YR_CALLBACK_ABORT;

    auto* ctx = static_cast<YaraScanContext*>(user_data);
    if (!ctx->results) return YR_CALLBACK_ABORT;

    if (message == YR_CALLBACK_MSG_RULE_MATCHING) {
        if (ctx->results->size() >= ctx->matchLimit) {
            return YR_CALLBACK_ABORT;
        }

        YaraMatch match;
        match.ruleName    = "yara_rule_match";
        match.severity    = "malicious";
        match.description = "YARA rule matched (runtime-loaded library)";
        ctx->results->push_back(std::move(match));
    }

    if (message == YR_CALLBACK_MSG_SCAN_FINISHED) {
        return YR_CALLBACK_CONTINUE;
    }

    return YR_CALLBACK_CONTINUE;
}

} // anonymous namespace

// ============================================================================
// ScanBuffer — scan raw bytes with libyara rules
// ============================================================================

std::vector<YaraMatch> YaraScanner::ScanBuffer(
    std::span<const uint8_t> buffer, uint32_t timeoutSeconds) noexcept
{
    std::vector<YaraMatch> results;
    if (!m_impl) return results;

    m_impl->totalScans.fetch_add(1, std::memory_order_relaxed);

    if (buffer.empty()) return results;
    if (buffer.size() > kMaxScanSize) return results;

    if (m_impl->available && m_impl->rules && m_impl->fn_yr_rules_scan_mem) {
        YaraScanContext ctx{ &results, 1000 };

        // yr_rules_scan_mem signature:
        //   (rules, buffer, bufsize, flags, callback, user_data, timeout)
        int rc = m_impl->fn_yr_rules_scan_mem(
            m_impl->rules,
            buffer.data(),
            buffer.size(),
            0,                                                       // flags
            reinterpret_cast<void*>(&YaraScanCallback),              // callback
            &ctx,
            static_cast<int>(timeoutSeconds));

        if (rc != YR_ERROR_SUCCESS && rc != YR_ERROR_SCAN_TIMEOUT) {
            m_impl->scanErrors.fetch_add(1, std::memory_order_relaxed);
        }
    }

    if (!results.empty()) {
        m_impl->totalMatches.fetch_add(
            static_cast<uint32_t>(results.size()), std::memory_order_relaxed);
    }

    return results;
}

// ============================================================================
// ScanGuestMemory — read guest memory page-by-page, then scan
// ============================================================================

std::vector<YaraMatch> YaraScanner::ScanGuestMemory(
    VirtualMemory& memory,
    GuestAddress startAddr,
    GuestSize size,
    uint32_t timeoutSeconds) noexcept
{
    std::vector<YaraMatch> results;
    if (!m_impl) return results;

    // Cap size to prevent excessive host memory allocation
    if (size == 0) return results;
    if (size > kMaxScanSize) size = kMaxScanSize;

    // Allocate contiguous host buffer
    std::vector<uint8_t> buffer;
    try {
        buffer.resize(static_cast<size_t>(size), 0);
    } catch (...) {
        m_impl->scanErrors.fetch_add(1, std::memory_order_relaxed);
        return results;
    }

    // Read page-by-page; unmapped pages remain zero-filled
    GuestSize offset = 0;
    while (offset < size) {
        auto chunkSize = static_cast<uint32_t>(
            std::min<GuestSize>(kPageSize, size - offset));

        ErrorCode err = memory.Read(startAddr + offset,
                                    buffer.data() + offset,
                                    chunkSize);
        if (err != ErrorCode::Success) {
            // Page not mapped or inaccessible — leave zero-filled
            std::memset(buffer.data() + offset, 0, chunkSize);
        }
        offset += chunkSize;
    }

    // Scan with libyara if available
    if (m_impl->available && m_impl->rules) {
        auto yaraResults = ScanBuffer({buffer.data(), buffer.size()}, timeoutSeconds);
        results.insert(results.end(),
                       std::make_move_iterator(yaraResults.begin()),
                       std::make_move_iterator(yaraResults.end()));
    }

    // Always run built-in pattern matching
    auto builtinResults = ScanWithBuiltinRules({buffer.data(), buffer.size()});
    results.insert(results.end(),
                   std::make_move_iterator(builtinResults.begin()),
                   std::make_move_iterator(builtinResults.end()));

    return results;
}

// ============================================================================
// ScanAllGuestMemory — enumerate all allocated pages and scan
// ============================================================================

std::vector<YaraMatch> YaraScanner::ScanAllGuestMemory(
    VirtualMemory& memory,
    uint32_t timeoutSeconds) noexcept
{
    std::vector<YaraMatch> results;
    if (!m_impl) return results;

    // The VirtualMemory API exposes GetAllocatedBytes()/GetMaxMemory() but
    // no iterator over allocated ranges. Scan from address 0 up to the max
    // guest memory in kMaxScanSize-sized chunks to stay within our buffer cap.

    GuestSize totalMemory = memory.GetMaxMemory();
    if (totalMemory > kMaxGuestMemory) totalMemory = kMaxGuestMemory;

    // Process in chunks to respect kMaxScanSize
    GuestAddress addr = 0;
    while (addr < totalMemory) {
        GuestSize chunkSize = std::min<GuestSize>(kMaxScanSize, totalMemory - addr);

        // Probe first page to avoid allocating buffer for entirely empty ranges
        uint8_t probe = 0;
        ErrorCode err = memory.Read(addr, &probe, 1);
        if (err == ErrorCode::Success) {
            auto chunkResults = ScanGuestMemory(memory, addr, chunkSize, timeoutSeconds);
            results.insert(results.end(),
                           std::make_move_iterator(chunkResults.begin()),
                           std::make_move_iterator(chunkResults.end()));
        }

        addr += chunkSize;
        // Guard against overflow
        if (addr < chunkSize) break;
    }

    return results;
}

// ============================================================================
// ScanWithBuiltinRules — masked pattern matching (always available)
// ============================================================================

std::vector<YaraMatch> YaraScanner::ScanWithBuiltinRules(
    std::span<const uint8_t> buffer) noexcept
{
    std::vector<YaraMatch> results;
    if (!m_impl || buffer.empty()) return results;

    m_impl->totalScans.fetch_add(1, std::memory_order_relaxed);

    for (const auto& pattern : m_impl->builtinPatterns) {
        const size_t patLen = pattern.pattern.size();
        if (patLen == 0 || patLen > buffer.size()) continue;

        const size_t searchEnd = buffer.size() - patLen;
        const uint8_t* patData  = pattern.pattern.data();
        const uint8_t* maskData = pattern.mask.data();
        const uint8_t* bufData  = buffer.data();

        bool matched = false;
        size_t matchOffset = 0;

        for (size_t i = 0; i <= searchEnd; ++i) {
            bool hit = true;
            for (size_t j = 0; j < patLen; ++j) {
                if ((bufData[i + j] & maskData[j]) !=
                    (patData[j]     & maskData[j])) {
                    hit = false;
                    break;
                }
            }
            if (hit) {
                matched = true;
                matchOffset = i;
                break;  // One match per rule is sufficient
            }
        }

        if (matched) {
            YaraMatch match;
            match.ruleName    = pattern.name;
            match.ruleNamespace = "builtin";
            match.description = pattern.description;
            match.severity    = pattern.severity;
            match.mitreTags   = pattern.mitreTags;
            match.family      = pattern.family;

            YaraMatch::StringMatch sm;
            sm.identifier = pattern.name;
            sm.offset     = static_cast<GuestAddress>(matchOffset);
            sm.length     = static_cast<uint32_t>(patLen);
            match.strings.push_back(std::move(sm));

            results.push_back(std::move(match));
        }
    }

    if (!results.empty()) {
        m_impl->totalMatches.fetch_add(
            static_cast<uint32_t>(results.size()), std::memory_order_relaxed);
    }

    return results;
}

// ============================================================================
// Statistics
// ============================================================================

uint32_t YaraScanner::GetRuleCount() const noexcept {
    if (!m_impl) return 0;
    uint32_t count = static_cast<uint32_t>(m_impl->builtinPatterns.size());
    count += m_impl->ruleCount.load(std::memory_order_relaxed);
    return count;
}

uint32_t YaraScanner::GetTotalScans() const noexcept {
    return m_impl ? m_impl->totalScans.load(std::memory_order_relaxed) : 0;
}

uint32_t YaraScanner::GetTotalMatches() const noexcept {
    return m_impl ? m_impl->totalMatches.load(std::memory_order_relaxed) : 0;
}

uint32_t YaraScanner::GetScanErrors() const noexcept {
    return m_impl ? m_impl->scanErrors.load(std::memory_order_relaxed) : 0;
}

void YaraScanner::Reset() noexcept {
    if (!m_impl) return;
    m_impl->totalScans.store(0, std::memory_order_relaxed);
    m_impl->totalMatches.store(0, std::memory_order_relaxed);
    m_impl->scanErrors.store(0, std::memory_order_relaxed);
}

} // namespace Phantom

/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * DotNetAnalyzer.cpp — .NET/CLR malware analysis orchestrator
 *
 * Full implementation of the managed-code analysis pipeline: PE/COR20
 * parsing, metadata inspection, MSIL disassembly/interpretation,
 * obfuscation fingerprinting, P/Invoke classification, reflective
 * loading detection, payload extraction, and threat scoring.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "DotNetAnalyzer.hpp"

#include "../Core/CLR/MetadataParser.hpp"
#include "../Core/CLR/MSILDisassembler.hpp"
#include "../Core/CLR/MSILInterpreter.hpp"
#include "../Core/Memory/VirtualMemory.hpp"
#include "../Core/Loader/PEStructures.hpp"
#include "../Common/Types.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace Phantom::CLR {

// ============================================================================
// Internal Helpers (anonymous namespace)
// ============================================================================

namespace {

// ----------------------------------------------------------------------------
// Const-safe guest memory reader via GetHostReadPtr (page-granular)
// ----------------------------------------------------------------------------

[[nodiscard]] bool ReadGuestMemory(VirtualMemory& mem,
                                   GuestAddress addr,
                                   void* dst,
                                   uint32_t size) noexcept
{
    if (size == 0) return true;

    auto* out = static_cast<uint8_t*>(dst);
    uint32_t remaining = size;
    GuestAddress cur = addr;

    while (remaining > 0) {
        const uint8_t* hostPtr = mem.GetHostReadPtr(cur);
        if (!hostPtr) return false;

        const uint32_t pageOffset =
            static_cast<uint32_t>(cur & (kPageSize - 1));
        const uint32_t availableInPage =
            static_cast<uint32_t>(kPageSize) - pageOffset;
        const uint32_t toRead = std::min(remaining, availableInPage);

        std::memcpy(out, hostPtr, toRead);
        out       += toRead;
        cur       += toRead;
        remaining -= toRead;
    }
    return true;
}

// ----------------------------------------------------------------------------
// Shannon entropy of a byte buffer (bits per byte, 0.0–8.0)
// ----------------------------------------------------------------------------

[[nodiscard]] double ComputeShannonEntropy(const uint8_t* data,
                                           uint32_t size) noexcept
{
    if (size == 0) return 0.0;

    std::array<uint32_t, 256> freq{};
    for (uint32_t i = 0; i < size; ++i) freq[data[i]]++;

    const double dsize = static_cast<double>(size);
    double entropy = 0.0;
    for (auto count : freq) {
        if (count == 0) continue;
        const double p = static_cast<double>(count) / dsize;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

// ----------------------------------------------------------------------------
// String helpers
// ----------------------------------------------------------------------------

[[nodiscard]] bool HasNonAsciiOrUnprintable(std::string_view s) noexcept
{
    for (unsigned char c : s) {
        if (c > 127 || (c < 0x20 && c != 0)) return true;
    }
    return false;
}

[[nodiscard]] bool CaseInsensitiveEquals(std::string_view a,
                                          std::string_view b) noexcept
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char ca = (a[i] >= 'A' && a[i] <= 'Z') ? static_cast<char>(a[i] + 32) : a[i];
        char cb = (b[i] >= 'A' && b[i] <= 'Z') ? static_cast<char>(b[i] + 32) : b[i];
        if (ca != cb) return false;
    }
    return true;
}

[[nodiscard]] bool ContainsSubstring(std::string_view haystack,
                                     std::string_view needle) noexcept
{
    return haystack.find(needle) != std::string_view::npos;
}

[[nodiscard]] bool ContainsSubstringCI(std::string_view haystack,
                                        std::string_view needle) noexcept
{
    if (needle.size() > haystack.size()) return false;
    for (size_t i = 0; i <= haystack.size() - needle.size(); ++i) {
        if (CaseInsensitiveEquals(haystack.substr(i, needle.size()), needle))
            return true;
    }
    return false;
}

// ----------------------------------------------------------------------------
// PE header parsing — extract CLR directory RVA from a loaded PE image
// ----------------------------------------------------------------------------

struct PEInfo {
    bool     valid                = false;
    bool     isPE64               = false;
    uint32_t numberOfRvaAndSizes  = 0;
    uint32_t clrRVA               = 0;
    uint32_t clrSize              = 0;
};

[[nodiscard]] PEInfo ParsePEHeaders(VirtualMemory& mem,
                                    GuestAddress imageBase) noexcept
{
    PEInfo info;

    PE::DOSHeader dos{};
    if (!ReadGuestMemory(mem, imageBase, &dos, sizeof(dos))) return info;
    if (dos.e_magic != PE::kDOSMagic) return info;
    if (dos.e_lfanew < 0 ||
        static_cast<uint32_t>(dos.e_lfanew) > 0x10000) return info;

    const GuestAddress ntAddr =
        imageBase + static_cast<uint32_t>(dos.e_lfanew);

    uint32_t ntSig = 0;
    if (!ReadGuestMemory(mem, ntAddr, &ntSig, sizeof(ntSig))) return info;
    if (ntSig != PE::kNTSignature) return info;

    const GuestAddress fhAddr = ntAddr + sizeof(uint32_t);
    PE::FileHeader fh{};
    if (!ReadGuestMemory(mem, fhAddr, &fh, sizeof(fh))) return info;
    if (fh.SizeOfOptionalHeader < 2) return info;

    const GuestAddress optAddr = fhAddr + sizeof(PE::FileHeader);
    uint16_t magic = 0;
    if (!ReadGuestMemory(mem, optAddr, &magic, sizeof(magic))) return info;

    if (magic == PE::kPE64Magic) {
        info.isPE64 = true;
        PE::OptionalHeader64 opt{};
        const uint32_t readSize =
            std::min(static_cast<uint32_t>(fh.SizeOfOptionalHeader),
                     static_cast<uint32_t>(sizeof(opt)));
        if (readSize < offsetof(PE::OptionalHeader64, NumberOfRvaAndSizes)
                       + sizeof(opt.NumberOfRvaAndSizes))
            return info;
        if (!ReadGuestMemory(mem, optAddr, &opt, readSize)) return info;
        info.numberOfRvaAndSizes =
            std::min(opt.NumberOfRvaAndSizes, PE::kMaxDataDirectories);
        if (info.numberOfRvaAndSizes > PE::kDirCLRRuntime) {
            info.clrRVA  = opt.DataDirectories[PE::kDirCLRRuntime].VirtualAddress;
            info.clrSize = opt.DataDirectories[PE::kDirCLRRuntime].Size;
        }
    } else if (magic == PE::kPE32Magic) {
        PE::OptionalHeader32 opt{};
        const uint32_t readSize =
            std::min(static_cast<uint32_t>(fh.SizeOfOptionalHeader),
                     static_cast<uint32_t>(sizeof(opt)));
        if (readSize < offsetof(PE::OptionalHeader32, NumberOfRvaAndSizes)
                       + sizeof(opt.NumberOfRvaAndSizes))
            return info;
        if (!ReadGuestMemory(mem, optAddr, &opt, readSize)) return info;
        info.numberOfRvaAndSizes =
            std::min(opt.NumberOfRvaAndSizes, PE::kMaxDataDirectories);
        if (info.numberOfRvaAndSizes > PE::kDirCLRRuntime) {
            info.clrRVA  = opt.DataDirectories[PE::kDirCLRRuntime].VirtualAddress;
            info.clrSize = opt.DataDirectories[PE::kDirCLRRuntime].Size;
        }
    } else {
        return info;
    }

    info.valid = true;
    return info;
}

// ----------------------------------------------------------------------------
// API classification rule table
// ----------------------------------------------------------------------------

struct APIRule {
    const char*       fullTypeName;   // "Namespace.ClassName"
    const char*       methodName;     // nullptr → any method on this type
    DotNetAPICategory category;
};

// Comprehensive classification covering all 26 DotNetAPICategory values.
// Ordered by detection priority within each category.
static const APIRule kAPIRules[] = {
    // ---- Assembly Loading ----
    {"System.Reflection.Assembly", "Load",                  DotNetAPICategory::AssemblyLoad},
    {"System.Reflection.Assembly", "LoadFrom",              DotNetAPICategory::AssemblyLoad},
    {"System.Reflection.Assembly", "LoadFile",              DotNetAPICategory::AssemblyLoad},
    {"System.Reflection.Assembly", "LoadWithPartialName",   DotNetAPICategory::AssemblyLoad},
    {"System.Reflection.Assembly", "UnsafeLoadFrom",        DotNetAPICategory::AssemblyLoad},

    // ---- Reflection Invocation ----
    {"System.Reflection.MethodInfo",       "Invoke",         DotNetAPICategory::ReflectionInvoke},
    {"System.Reflection.MethodBase",       "Invoke",         DotNetAPICategory::ReflectionInvoke},
    {"System.Reflection.ConstructorInfo",  "Invoke",         DotNetAPICategory::ReflectionInvoke},
    {"System.Delegate",                    "DynamicInvoke",  DotNetAPICategory::ReflectionInvoke},
    {"System.Activator",                   "CreateInstance", DotNetAPICategory::ReflectionInvoke},
    {"System.Type",                        "InvokeMember",   DotNetAPICategory::ReflectionInvoke},

    // ---- Dynamic Compilation / Code Generation ----
    {"Microsoft.CSharp.CSharpCodeProvider",          "CompileAssemblyFromSource", DotNetAPICategory::DynamicCompile},
    {"System.CodeDom.Compiler.CodeDomProvider",      "CompileAssemblyFromSource", DotNetAPICategory::DynamicCompile},
    {"System.Reflection.Emit.AssemblyBuilder",       nullptr,                     DotNetAPICategory::DynamicCompile},
    {"System.Reflection.Emit.ModuleBuilder",         nullptr,                     DotNetAPICategory::DynamicCompile},
    {"System.Reflection.Emit.TypeBuilder",           nullptr,                     DotNetAPICategory::DynamicCompile},
    {"System.Reflection.Emit.MethodBuilder",         nullptr,                     DotNetAPICategory::DynamicCompile},
    {"System.Reflection.Emit.ILGenerator",           nullptr,                     DotNetAPICategory::DynamicCompile},
    {"System.Reflection.Emit.DynamicMethod",         nullptr,                     DotNetAPICategory::DynamicCompile},

    // ---- Process Execution ----
    {"System.Diagnostics.Process",          "Start",   DotNetAPICategory::ProcessStart},
    {"System.Diagnostics.Process",          "Kill",    DotNetAPICategory::ProcessStart},
    {"System.Diagnostics.ProcessStartInfo", nullptr,   DotNetAPICategory::ProcessStart},

    // ---- File I/O — Read ----
    {"System.IO.File",         "ReadAllBytes",  DotNetAPICategory::FileRead},
    {"System.IO.File",         "ReadAllText",   DotNetAPICategory::FileRead},
    {"System.IO.File",         "ReadAllLines",  DotNetAPICategory::FileRead},
    {"System.IO.File",         "Open",          DotNetAPICategory::FileRead},
    {"System.IO.File",         "OpenRead",      DotNetAPICategory::FileRead},
    {"System.IO.FileStream",   "Read",          DotNetAPICategory::FileRead},
    {"System.IO.StreamReader", "ReadToEnd",     DotNetAPICategory::FileRead},
    {"System.IO.BinaryReader", "ReadBytes",     DotNetAPICategory::FileRead},

    // ---- File I/O — Write ----
    {"System.IO.File",         "WriteAllBytes",  DotNetAPICategory::FileWrite},
    {"System.IO.File",         "WriteAllText",   DotNetAPICategory::FileWrite},
    {"System.IO.File",         "WriteAllLines",  DotNetAPICategory::FileWrite},
    {"System.IO.File",         "Create",         DotNetAPICategory::FileWrite},
    {"System.IO.File",         "AppendAllText",  DotNetAPICategory::FileWrite},
    {"System.IO.FileStream",   "Write",          DotNetAPICategory::FileWrite},
    {"System.IO.StreamWriter", "Write",          DotNetAPICategory::FileWrite},
    {"System.IO.BinaryWriter", "Write",          DotNetAPICategory::FileWrite},

    // ---- File I/O — Delete ----
    {"System.IO.File",      "Delete",  DotNetAPICategory::FileDelete},
    {"System.IO.Directory", "Delete",  DotNetAPICategory::FileDelete},
    {"System.IO.File",      "Move",    DotNetAPICategory::FileDelete},

    // ---- Path Manipulation ----
    {"System.IO.Path", "GetTempPath",     DotNetAPICategory::PathManipulation},
    {"System.IO.Path", "GetTempFileName", DotNetAPICategory::PathManipulation},
    {"System.IO.Path", "Combine",         DotNetAPICategory::PathManipulation},

    // ---- Network — Download ----
    {"System.Net.WebClient",          "DownloadString",     DotNetAPICategory::WebDownload},
    {"System.Net.WebClient",          "DownloadData",       DotNetAPICategory::WebDownload},
    {"System.Net.WebClient",          "DownloadFile",       DotNetAPICategory::WebDownload},
    {"System.Net.WebClient",          "OpenRead",           DotNetAPICategory::WebDownload},
    {"System.Net.WebClient",          "UploadString",       DotNetAPICategory::WebDownload},
    {"System.Net.WebClient",          "UploadData",         DotNetAPICategory::WebDownload},
    {"System.Net.Http.HttpClient",    "GetAsync",           DotNetAPICategory::WebDownload},
    {"System.Net.Http.HttpClient",    "PostAsync",          DotNetAPICategory::WebDownload},
    {"System.Net.Http.HttpClient",    "SendAsync",          DotNetAPICategory::WebDownload},
    {"System.Net.Http.HttpClient",    "GetStringAsync",     DotNetAPICategory::WebDownload},
    {"System.Net.Http.HttpClient",    "GetByteArrayAsync",  DotNetAPICategory::WebDownload},
    {"System.Net.WebRequest",         "Create",             DotNetAPICategory::WebDownload},
    {"System.Net.HttpWebRequest",     "GetResponse",        DotNetAPICategory::WebDownload},

    // ---- Network — Socket ----
    {"System.Net.Sockets.TcpClient",  "Connect",       DotNetAPICategory::SocketConnect},
    {"System.Net.Sockets.TcpClient",  "ConnectAsync",  DotNetAPICategory::SocketConnect},
    {"System.Net.Sockets.Socket",     "Connect",       DotNetAPICategory::SocketConnect},
    {"System.Net.Sockets.Socket",     "Send",          DotNetAPICategory::SocketConnect},
    {"System.Net.Sockets.Socket",     "Receive",       DotNetAPICategory::SocketConnect},
    {"System.Net.Sockets.UdpClient",  "Send",          DotNetAPICategory::SocketConnect},

    // ---- DNS ----
    {"System.Net.Dns", "GetHostAddresses",  DotNetAPICategory::DnsResolve},
    {"System.Net.Dns", "GetHostEntry",      DotNetAPICategory::DnsResolve},
    {"System.Net.Dns", "Resolve",           DotNetAPICategory::DnsResolve},

    // ---- Crypto — Symmetric ----
    {"System.Security.Cryptography.Aes",                        "Create",             DotNetAPICategory::SymmetricEncrypt},
    {"System.Security.Cryptography.AesManaged",                 nullptr,              DotNetAPICategory::SymmetricEncrypt},
    {"System.Security.Cryptography.AesCryptoServiceProvider",   nullptr,              DotNetAPICategory::SymmetricEncrypt},
    {"System.Security.Cryptography.RijndaelManaged",            nullptr,              DotNetAPICategory::SymmetricEncrypt},
    {"System.Security.Cryptography.DES",                        "Create",             DotNetAPICategory::SymmetricEncrypt},
    {"System.Security.Cryptography.DESCryptoServiceProvider",   nullptr,              DotNetAPICategory::SymmetricEncrypt},
    {"System.Security.Cryptography.TripleDES",                  "Create",             DotNetAPICategory::SymmetricEncrypt},
    {"System.Security.Cryptography.RC2",                        "Create",             DotNetAPICategory::SymmetricEncrypt},
    {"System.Security.Cryptography.SymmetricAlgorithm",         "CreateEncryptor",    DotNetAPICategory::SymmetricEncrypt},
    {"System.Security.Cryptography.SymmetricAlgorithm",         "CreateDecryptor",    DotNetAPICategory::SymmetricEncrypt},
    {"System.Security.Cryptography.ICryptoTransform",           "TransformBlock",     DotNetAPICategory::SymmetricEncrypt},
    {"System.Security.Cryptography.ICryptoTransform",           "TransformFinalBlock",DotNetAPICategory::SymmetricEncrypt},
    {"System.Security.Cryptography.CryptoStream",               nullptr,              DotNetAPICategory::SymmetricEncrypt},

    // ---- Crypto — Asymmetric ----
    {"System.Security.Cryptography.RSA",                      "Create",   DotNetAPICategory::AsymmetricEncrypt},
    {"System.Security.Cryptography.RSACryptoServiceProvider",  nullptr,   DotNetAPICategory::AsymmetricEncrypt},
    {"System.Security.Cryptography.DSA",                      "Create",   DotNetAPICategory::AsymmetricEncrypt},
    {"System.Security.Cryptography.ECDsa",                    "Create",   DotNetAPICategory::AsymmetricEncrypt},

    // ---- Crypto — Hashing ----
    {"System.Security.Cryptography.SHA256",        "Create",       DotNetAPICategory::HashCompute},
    {"System.Security.Cryptography.SHA256Managed", nullptr,        DotNetAPICategory::HashCompute},
    {"System.Security.Cryptography.SHA1",          "Create",       DotNetAPICategory::HashCompute},
    {"System.Security.Cryptography.SHA1Managed",   nullptr,        DotNetAPICategory::HashCompute},
    {"System.Security.Cryptography.MD5",           "Create",       DotNetAPICategory::HashCompute},
    {"System.Security.Cryptography.SHA512",        "Create",       DotNetAPICategory::HashCompute},
    {"System.Security.Cryptography.HashAlgorithm", "ComputeHash",  DotNetAPICategory::HashCompute},
    {"System.Security.Cryptography.HMACSHA256",    nullptr,        DotNetAPICategory::HashCompute},

    // ---- Crypto — Random ----
    {"System.Security.Cryptography.RNGCryptoServiceProvider", nullptr,     DotNetAPICategory::RandomGenerate},
    {"System.Security.Cryptography.RandomNumberGenerator",    "Create",    DotNetAPICategory::RandomGenerate},
    {"System.Security.Cryptography.RandomNumberGenerator",    "GetBytes",  DotNetAPICategory::RandomGenerate},

    // ---- Registry — Read ----
    {"Microsoft.Win32.Registry",    "GetValue",    DotNetAPICategory::RegistryRead},
    {"Microsoft.Win32.RegistryKey", "OpenSubKey",  DotNetAPICategory::RegistryRead},
    {"Microsoft.Win32.RegistryKey", "GetValue",    DotNetAPICategory::RegistryRead},

    // ---- Registry — Write ----
    {"Microsoft.Win32.Registry",    "SetValue",     DotNetAPICategory::RegistryWrite},
    {"Microsoft.Win32.RegistryKey", "SetValue",     DotNetAPICategory::RegistryWrite},
    {"Microsoft.Win32.RegistryKey", "CreateSubKey", DotNetAPICategory::RegistryWrite},

    // ---- WMI ----
    {"System.Management.ManagementObjectSearcher", nullptr, DotNetAPICategory::WmiQuery},
    {"System.Management.ManagementObject",         nullptr, DotNetAPICategory::WmiQuery},
    {"System.Management.WqlObjectQuery",           nullptr, DotNetAPICategory::WmiQuery},
    {"System.Management.ManagementClass",          nullptr, DotNetAPICategory::WmiQuery},

    // ---- Marshal / Interop ----
    {"System.Runtime.InteropServices.Marshal", "Copy",                           DotNetAPICategory::MarshalCopy},
    {"System.Runtime.InteropServices.Marshal", "AllocHGlobal",                   DotNetAPICategory::MarshalCopy},
    {"System.Runtime.InteropServices.Marshal", "FreeHGlobal",                    DotNetAPICategory::MarshalCopy},
    {"System.Runtime.InteropServices.Marshal", "PtrToStructure",                 DotNetAPICategory::MarshalCopy},
    {"System.Runtime.InteropServices.Marshal", "StructureToPtr",                 DotNetAPICategory::MarshalCopy},
    {"System.Runtime.InteropServices.Marshal", "ReadByte",                       DotNetAPICategory::MarshalCopy},
    {"System.Runtime.InteropServices.Marshal", "ReadInt32",                      DotNetAPICategory::MarshalCopy},
    {"System.Runtime.InteropServices.Marshal", "WriteByte",                      DotNetAPICategory::MarshalCopy},
    {"System.Runtime.InteropServices.Marshal", "WriteInt32",                     DotNetAPICategory::MarshalCopy},
    {"System.Runtime.InteropServices.Marshal", "GetDelegateForFunctionPointer",  DotNetAPICategory::MarshalCopy},

    // ---- Sleep / Delay ----
    {"System.Threading.Thread",      "Sleep",  DotNetAPICategory::SleepDelay},
    {"System.Threading.Tasks.Task",  "Delay",  DotNetAPICategory::SleepDelay},

    // ---- Environment ----
    {"System.Environment", "get_MachineName",         DotNetAPICategory::EnvironmentQuery},
    {"System.Environment", "get_UserName",            DotNetAPICategory::EnvironmentQuery},
    {"System.Environment", "get_UserDomainName",      DotNetAPICategory::EnvironmentQuery},
    {"System.Environment", "get_OSVersion",           DotNetAPICategory::EnvironmentQuery},
    {"System.Environment", "GetEnvironmentVariable",  DotNetAPICategory::EnvironmentQuery},
    {"System.Environment", "GetFolderPath",           DotNetAPICategory::EnvironmentQuery},
    {"System.Environment", "get_ProcessorCount",      DotNetAPICategory::EnvironmentQuery},
    {"System.Environment", "GetLogicalDrives",        DotNetAPICategory::EnvironmentQuery},

    // ---- Anti-Debug ----
    {"System.Diagnostics.Debugger", "get_IsAttached", DotNetAPICategory::AntiDebug},
    {"System.Diagnostics.Debugger", "IsLogging",      DotNetAPICategory::AntiDebug},
    {"System.Diagnostics.Debugger", "Break",          DotNetAPICategory::AntiDebug},
};

static constexpr size_t kAPIRuleCount =
    sizeof(kAPIRules) / sizeof(kAPIRules[0]);

// ----------------------------------------------------------------------------
// P/Invoke suspicious function table
// ----------------------------------------------------------------------------

struct PInvokeRule {
    const char* dllName;      // case-insensitive
    const char* funcName;     // case-sensitive
    const char* description;
};

static const PInvokeRule kSuspiciousPInvokes[] = {
    // Process injection
    {"kernel32.dll", "VirtualAlloc",           "Memory Allocation"},
    {"kernel32.dll", "VirtualAllocEx",         "Remote Memory Allocation"},
    {"kernel32.dll", "VirtualProtect",         "Memory Protection Change"},
    {"kernel32.dll", "VirtualProtectEx",       "Remote Memory Protection Change"},
    {"kernel32.dll", "WriteProcessMemory",     "Remote Process Memory Write"},
    {"kernel32.dll", "ReadProcessMemory",      "Remote Process Memory Read"},
    {"kernel32.dll", "CreateRemoteThread",     "Remote Thread Creation"},
    {"kernel32.dll", "CreateRemoteThreadEx",   "Remote Thread Creation"},
    {"kernel32.dll", "QueueUserAPC",           "APC Injection"},
    {"kernel32.dll", "OpenProcess",            "Process Handle Acquisition"},
    // Direct syscalls
    {"ntdll.dll",    "NtCreateThreadEx",           "Direct Syscall Thread Creation"},
    {"ntdll.dll",    "NtQueueApcThread",           "Direct Syscall APC Injection"},
    {"ntdll.dll",    "NtAllocateVirtualMemory",    "Direct Syscall Memory Allocation"},
    {"ntdll.dll",    "NtWriteVirtualMemory",       "Direct Syscall Memory Write"},
    {"ntdll.dll",    "NtMapViewOfSection",         "Section Mapping"},
    {"ntdll.dll",    "NtUnmapViewOfSection",       "Process Hollowing"},
    {"ntdll.dll",    "NtCreateSection",            "Section Creation"},
    {"ntdll.dll",    "RtlCreateUserThread",        "User Thread Creation"},
    // Keylogging
    {"user32.dll",   "GetAsyncKeyState",     "Keylogging"},
    {"user32.dll",   "GetKeyState",          "Keylogging"},
    {"user32.dll",   "SetWindowsHookExA",    "Hook Installation"},
    {"user32.dll",   "SetWindowsHookExW",    "Hook Installation"},
    {"user32.dll",   "keybd_event",          "Keyboard Simulation"},
    // Privilege escalation
    {"advapi32.dll", "OpenProcessToken",         "Token Manipulation"},
    {"advapi32.dll", "AdjustTokenPrivileges",    "Privilege Escalation"},
    {"advapi32.dll", "DuplicateTokenEx",         "Token Duplication"},
    {"advapi32.dll", "ImpersonateLoggedOnUser",  "Impersonation"},
    {"advapi32.dll", "CreateProcessAsUserA",     "Impersonated Process Creation"},
    {"advapi32.dll", "CreateProcessAsUserW",     "Impersonated Process Creation"},
    // C2 communication
    {"wininet.dll",  "InternetOpenA",       "HTTP C2 Communication"},
    {"wininet.dll",  "InternetOpenW",       "HTTP C2 Communication"},
    {"wininet.dll",  "InternetConnectA",    "HTTP C2 Communication"},
    {"wininet.dll",  "InternetOpenUrlA",    "HTTP C2 Communication"},
    {"wininet.dll",  "HttpOpenRequestA",    "HTTP C2 Communication"},
    {"wininet.dll",  "HttpSendRequestA",    "HTTP C2 Communication"},
    {"winhttp.dll",  "WinHttpOpen",         "HTTP C2 Communication"},
    {"winhttp.dll",  "WinHttpConnect",      "HTTP C2 Communication"},
    {"winhttp.dll",  "WinHttpOpenRequest",  "HTTP C2 Communication"},
    {"ws2_32.dll",   "connect",             "Socket Communication"},
    {"ws2_32.dll",   "send",               "Socket Communication"},
    {"ws2_32.dll",   "WSAStartup",         "Socket Initialization"},
    // Crypto
    {"crypt32.dll",  "CryptEncrypt",        "Native Crypto"},
    {"crypt32.dll",  "CryptDecrypt",        "Native Crypto"},
    {"crypt32.dll",  "CryptProtectData",    "DPAPI Usage"},
    {"crypt32.dll",  "CryptUnprotectData",  "DPAPI Usage"},
    {"bcrypt.dll",   "BCryptEncrypt",       "Native Crypto"},
    {"bcrypt.dll",   "BCryptDecrypt",       "Native Crypto"},
    // AMSI
    {"amsi.dll",     "AmsiScanBuffer",   "AMSI Bypass Attempt"},
    {"amsi.dll",     "AmsiInitialize",   "AMSI Interaction"},
};

static constexpr size_t kPInvokeRuleCount =
    sizeof(kSuspiciousPInvokes) / sizeof(kSuspiciousPInvokes[0]);

// ----------------------------------------------------------------------------
// Scoring constants
// ----------------------------------------------------------------------------

constexpr float kWeightAssemblyLoadRaw       = 0.20f;
constexpr float kWeightAssemblyLoad          = 0.05f;
constexpr float kWeightReflectionInvoke      = 0.10f;
constexpr float kWeightDynamicCompile        = 0.12f;
constexpr float kWeightProcessStart          = 0.08f;
constexpr float kWeightNetworkIO             = 0.05f;
constexpr float kWeightMarshalCopy           = 0.05f;
constexpr float kWeightAntiDebug             = 0.06f;
constexpr float kWeightCryptoUsage           = 0.03f;
constexpr float kWeightObfuscationBase       = 0.15f;
constexpr float kWeightObfuscationMultiple   = 0.10f;
constexpr float kWeightInjectionCombo        = 0.15f;
constexpr float kWeightInjectionFull         = 0.10f;
constexpr float kWeightNonAsciiNames         = 0.10f;
constexpr float kWeightHighEntropyResource   = 0.10f;
constexpr float kWeightKeylogging            = 0.08f;
constexpr float kWeightAMSI                  = 0.12f;
constexpr float kWeightStringDecryption      = 0.07f;
constexpr float kWeightNativeEntryEmpty      = 0.10f;

constexpr double kHighEntropyThreshold       = 7.0;
constexpr uint32_t kLargeResourceThreshold   = 10 * 1024;   // 10 KB
constexpr uint32_t kLargeILBodyThreshold     = 10 * 1024;   // 10 KB
constexpr uint32_t kMaxMethodReadSize        = 128 * 1024;   // 128 KB per method body
constexpr uint32_t kMaxResourceScan          = 4 * 1024 * 1024; // 4 MB resource blob cap
constexpr uint32_t kMaxOutputTypes           = 200;

} // anonymous namespace

// ============================================================================
// Impl — Private implementation state
// ============================================================================

struct DotNetAnalyzer::Impl {
    // ---- Configuration ----
    uint32_t maxMethodsToAnalyze    = 500;
    bool     enableStringDecryption = true;
    bool     enablePayloadExtraction = true;

    // ---- Last analysis output ----
    DotNetAnalysisResult   lastResult{};
    float                  lastThreatScore  = 0.0f;
    std::vector<std::string> lastMITREIDs;

    // ---- Working state (reset per Analyze() call) ----
    std::vector<DotNetAPICall> collectedAPICalls;

    // Obfuscation analysis accumulators
    uint32_t nonAsciiTypeCount       = 0;
    uint32_t shortNameTypeCount      = 0;
    uint32_t totalTypeCount          = 0;
    uint32_t switchHeavyMethodCount  = 0;
    uint32_t totalAnalyzedMethods    = 0;
    uint32_t emptyILMethodCount      = 0;
    uint32_t totalMethodsWithRVA     = 0;
    uint32_t largeILMethodCount      = 0;
    uint64_t totalSwitchTargets      = 0;
    uint32_t switchMethodCount       = 0;
    uint32_t singleCharMethodCount   = 0;
    uint32_t totalMethodNameCount    = 0;
    bool     hasCctorStringDecrypt   = false;
    bool     hasModuleTypeManyMethods = false;

    // P/Invoke combo flags
    bool hasPInvokeVirtualAlloc           = false;
    bool hasPInvokeVirtualAllocEx         = false;
    bool hasPInvokeWriteProcessMemory     = false;
    bool hasPInvokeCreateRemoteThread     = false;
    bool hasPInvokeNtCreateThreadEx       = false;
    bool hasPInvokeGetAsyncKeyState       = false;
    bool hasPInvokeNtUnmapViewOfSection   = false;
    bool hasAmsiReference                 = false;

    // COR20 header cache
    COR20Header cor20{};

    void ResetWorking() noexcept {
        lastResult       = DotNetAnalysisResult{};
        lastThreatScore  = 0.0f;
        lastMITREIDs.clear();
        collectedAPICalls.clear();

        nonAsciiTypeCount       = 0;
        shortNameTypeCount      = 0;
        totalTypeCount          = 0;
        switchHeavyMethodCount  = 0;
        totalAnalyzedMethods    = 0;
        emptyILMethodCount      = 0;
        totalMethodsWithRVA     = 0;
        largeILMethodCount      = 0;
        totalSwitchTargets      = 0;
        switchMethodCount       = 0;
        singleCharMethodCount   = 0;
        totalMethodNameCount    = 0;
        hasCctorStringDecrypt   = false;
        hasModuleTypeManyMethods = false;

        hasPInvokeVirtualAlloc           = false;
        hasPInvokeVirtualAllocEx         = false;
        hasPInvokeWriteProcessMemory     = false;
        hasPInvokeCreateRemoteThread     = false;
        hasPInvokeNtCreateThreadEx       = false;
        hasPInvokeGetAsyncKeyState       = false;
        hasPInvokeNtUnmapViewOfSection   = false;
        hasAmsiReference                 = false;

        cor20 = COR20Header{};
    }
};

// ============================================================================
// Constructor / Destructor / Singleton
// ============================================================================

DotNetAnalyzer::DotNetAnalyzer() noexcept
    : m_impl(std::make_unique<Impl>())
{}

DotNetAnalyzer::~DotNetAnalyzer() noexcept = default;

DotNetAnalyzer& DotNetAnalyzer::Instance() noexcept {
    static DotNetAnalyzer instance;
    return instance;
}

void DotNetAnalyzer::Reset() noexcept {
    if (m_impl) m_impl->ResetWorking();
}

// ============================================================================
// IsDotNetAssembly — static predicate
// ============================================================================

bool DotNetAnalyzer::IsDotNetAssembly(
    VirtualMemory& memory,
    GuestAddress imageBase) noexcept
{
    const auto pe = ParsePEHeaders(memory, imageBase);
    return pe.valid &&
           pe.clrRVA  != 0 &&
           pe.clrSize >= sizeof(COR20Header);
}

// ============================================================================
// Analyze — orchestrate the full pipeline
// ============================================================================

DotNetAnalysisResult DotNetAnalyzer::Analyze(
    VirtualMemory& memory,
    GuestAddress imageBase) noexcept
{
    m_impl->ResetWorking();
    auto& result = m_impl->lastResult;

    // --- Step 1: Validate PE and locate COR20 directory ---
    const auto pe = ParsePEHeaders(memory, imageBase);
    if (!pe.valid || pe.clrRVA == 0 || pe.clrSize < sizeof(COR20Header))
        return result;

    if (!ReadGuestMemory(memory, imageBase + pe.clrRVA,
                         &m_impl->cor20, sizeof(COR20Header)))
        return result;

    const auto& cor20 = m_impl->cor20;
    if (cor20.cb < sizeof(COR20Header) ||
        cor20.metadataRVA == 0 || cor20.metadataSize == 0)
        return result;

    // --- Step 2: Parse metadata tables ---
    MetadataParser parser;
    if (!parser.Parse(memory, imageBase))
        return result;   // corrupt metadata — return empty

    // --- Steps 3–9: analysis pipeline ---
    try {
        AnalyzeMetadata(parser);
        AnalyzeMethods(parser, memory, imageBase);
        DetectObfuscation(parser);
        ExtractPInvokes(parser);
        ClassifyAPICalls();
        DetectPayloadEmbedding(parser, memory, imageBase);
        ComputeThreatScore();
    } catch (...) {
        // Corrupt metadata mid-stream — return partial results.
    }

    return result;
}

// ============================================================================
// AnalyzeMetadata — assembly identity, counts, references
// ============================================================================

void DotNetAnalyzer::AnalyzeMetadata(const MetadataParser& parser) noexcept {
    try {
        auto& result = m_impl->lastResult;
        const auto& cor20 = m_impl->cor20;

        // COR20 flags
        result.isILOnly          = (cor20.flags & COR20Flags::ILOnly) != 0;
        result.is32BitPreferred  = (cor20.flags & COR20Flags::Prefers32Bit) != 0;

        // Assembly identity
        const auto assembly = parser.GetAssembly();
        if (assembly) {
            result.assemblyName = assembly->name;
            result.assemblyVersion =
                std::to_string(assembly->majorVersion) + "." +
                std::to_string(assembly->minorVersion) + "." +
                std::to_string(assembly->buildNumber)  + "." +
                std::to_string(assembly->revisionNumber);
        }

        // Metadata counts
        const auto& typeDefs    = parser.GetTypeDefs();
        const auto& methodDefs  = parser.GetMethodDefs();
        const auto& memberRefs  = parser.GetMemberRefs();
        const auto& asmRefs     = parser.GetAssemblyRefs();

        result.typeDefCount    = static_cast<uint32_t>(typeDefs.size());
        result.methodDefCount  = static_cast<uint32_t>(methodDefs.size());
        result.memberRefCount  = static_cast<uint32_t>(memberRefs.size());
        result.assemblyRefCount = static_cast<uint32_t>(asmRefs.size());

        // Referenced assemblies & framework detection
        result.referencedAssemblies.reserve(asmRefs.size());
        for (const auto& aref : asmRefs) {
            result.referencedAssemblies.push_back(aref.name);

            if (aref.name == "mscorlib") {
                result.targetFramework =
                    ".NET Framework " +
                    std::to_string(aref.majorVersion) + "." +
                    std::to_string(aref.minorVersion);
            } else if (aref.name == "System.Runtime" &&
                       result.targetFramework.empty()) {
                result.targetFramework =
                    ".NET " +
                    std::to_string(aref.majorVersion) + "." +
                    std::to_string(aref.minorVersion);
            }
        }

        // Defined types (capped)
        const uint32_t typeLimit =
            std::min(result.typeDefCount, kMaxOutputTypes);
        result.definedTypes.reserve(typeLimit);
        for (uint32_t i = 0; i < typeLimit; ++i) {
            const auto& td = typeDefs[i];
            std::string full = td.typeNamespace.empty()
                ? td.typeName
                : (td.typeNamespace + "." + td.typeName);
            result.definedTypes.push_back(std::move(full));
        }

        // Entry point method
        MetadataToken entryTok{ cor20.entryPointToken };
        if (entryTok.Row() != 0 &&
            entryTok.Table() == MetadataTableId::MethodDef)
        {
            const uint32_t row = entryTok.Row();
            if (row > 0 && row <= static_cast<uint32_t>(methodDefs.size()))
                result.entryPointMethod = methodDefs[row - 1].name;
        }

        // Obfuscation pre-scan: type name statistics
        m_impl->totalTypeCount = result.typeDefCount;
        for (const auto& td : typeDefs) {
            if (HasNonAsciiOrUnprintable(td.typeName))
                ++m_impl->nonAsciiTypeCount;
            if (!td.typeName.empty() && td.typeName.size() < 3)
                ++m_impl->shortNameTypeCount;

            // Detect <Module> with excessive method count (ConfuserEx indicator)
            if (td.typeName == "<Module>" && td.methodList > 0) {
                // Count methods belonging to <Module>: all methods from
                // methodList to the next TypeDef's methodList (or end).
                const uint32_t idx =
                    static_cast<uint32_t>(&td - typeDefs.data());
                uint32_t nextMethodList =
                    static_cast<uint32_t>(methodDefs.size()) + 1;
                if (idx + 1 < typeDefs.size())
                    nextMethodList = typeDefs[idx + 1].methodList;
                if (nextMethodList > td.methodList &&
                    (nextMethodList - td.methodList) > 20) {
                    m_impl->hasModuleTypeManyMethods = true;
                }
            }
        }

        // Method name statistics
        m_impl->totalMethodNameCount =
            static_cast<uint32_t>(methodDefs.size());
        for (const auto& md : methodDefs) {
            if (md.name.size() == 1) ++m_impl->singleCharMethodCount;
        }

    } catch (...) {
        // Partial metadata — continue with what we have.
    }
}

// ============================================================================
// AnalyzeMethods — disassemble IL, optionally interpret key methods
// ============================================================================

void DotNetAnalyzer::AnalyzeMethods(
    const MetadataParser& parser,
    VirtualMemory& memory,
    GuestAddress imageBase) noexcept
{
    try {
        auto& impl    = *m_impl;
        auto& result  = impl.lastResult;

        const auto& methodDefs = parser.GetMethodDefs();
        const auto& typeRefs   = parser.GetTypeRefs();
        const auto& memberRefs = parser.GetMemberRefs();

        const uint32_t methodLimit =
            std::min(static_cast<uint32_t>(methodDefs.size()),
                     impl.maxMethodsToAnalyze);

        // Build a quick lookup: TypeRef index → "Namespace.TypeName"
        std::vector<std::string> typeRefNames;
        typeRefNames.reserve(typeRefs.size());
        for (const auto& tr : typeRefs) {
            typeRefNames.push_back(
                tr.typeNamespace.empty()
                    ? tr.typeName
                    : (tr.typeNamespace + "." + tr.typeName));
        }

        // Resolve MemberRef parent indices into full type names.
        // MemberRefParent coded index: 3-bit tag, remaining bits = row.
        // Tag 0x01 = TypeRef (most common for external calls).
        auto resolveMemberRefParent =
            [&](uint32_t codedIndex) -> std::string_view {
            const uint32_t tag = codedIndex & 0x07;
            const uint32_t row = (codedIndex >> 3);
            if (tag == 0x01 && row > 0 && row <= typeRefNames.size())
                return typeRefNames[row - 1];
            return {};
        };

        // Optional interpreter for string decryption
        std::unique_ptr<MSILInterpreter> interp;
        if (impl.enableStringDecryption) {
            interp = std::make_unique<MSILInterpreter>(parser);
        }

        for (uint32_t i = 0; i < methodLimit; ++i) {
            const auto& md = methodDefs[i];
            if (md.rva == 0) continue;
            ++impl.totalMethodsWithRVA;

            const GuestAddress bodyVA = imageBase + md.rva;

            // Read the method header (max 12 bytes for fat header)
            uint8_t headerBuf[12]{};
            if (!ReadGuestMemory(memory, bodyVA, headerBuf, sizeof(headerBuf)))
                continue;

            const auto headerOpt =
                MSILDisassembler::ParseMethodHeader(headerBuf, sizeof(headerBuf));
            if (!headerOpt) continue;

            const auto& hdr = *headerOpt;

            // Compute safe read size
            uint32_t bodySize = hdr.codeOffset + hdr.codeSize;
            if (hdr.hasMoreSections)
                bodySize = ((bodySize + 3u) & ~3u) + 4096u; // generous EH buffer
            bodySize = std::min(bodySize, kMaxMethodReadSize);

            if (bodySize > kMaxILMethodBodySize) {
                ++impl.largeILMethodCount;
                continue;
            }

            // Detect oversized IL bodies (Eazfuscator indicator)
            if (hdr.codeSize > kLargeILBodyThreshold)
                ++impl.largeILMethodCount;

            // Read full method body
            std::vector<uint8_t> body(bodySize);
            if (!ReadGuestMemory(memory, bodyVA, body.data(), bodySize))
                continue;

            // Disassemble
            auto disasm = MSILDisassembler::DisassembleMethod(
                body.data(), bodySize);
            if (!disasm.valid) continue;
            ++impl.totalAnalyzedMethods;

            // Empty IL detection (DNGuard indicator: nop+ret only)
            if (disasm.instructions.size() <= 2) {
                bool allTrivial = true;
                for (const auto& instr : disasm.instructions) {
                    if (instr.opcode != MSILOpcode::Nop &&
                        instr.opcode != MSILOpcode::Ret) {
                        allTrivial = false;
                        break;
                    }
                }
                if (allTrivial) ++impl.emptyILMethodCount;
            }

            // Switch target counting (control flow obfuscation metric)
            uint32_t methodSwitchTargets = 0;
            for (const auto& instr : disasm.instructions) {
                if (instr.opcode == MSILOpcode::Switch) {
                    methodSwitchTargets +=
                        static_cast<uint32_t>(instr.switchTargets.size());
                }
            }
            if (methodSwitchTargets > 0) {
                impl.totalSwitchTargets += methodSwitchTargets;
                ++impl.switchMethodCount;
                if (methodSwitchTargets > 10)
                    ++impl.switchHeavyMethodCount;
            }

            // Track all call/callvirt/newobj targets
            for (const auto& instr : disasm.instructions) {
                if (instr.opcode != MSILOpcode::Call &&
                    instr.opcode != MSILOpcode::Callvirt &&
                    instr.opcode != MSILOpcode::Newobj)
                    continue;

                const uint32_t token = instr.operand.token;
                const MetadataToken mtok{token};

                // MemberRef token → resolve parent type + method name
                if (mtok.Table() == MetadataTableId::MemberRef) {
                    const uint32_t row = mtok.Row();
                    if (row == 0 || row > memberRefs.size()) continue;
                    const auto& mr = memberRefs[row - 1];

                    const std::string_view parentType =
                        resolveMemberRefParent(mr.classCodedIndex);
                    if (parentType.empty()) continue;

                    DotNetAPICall apiCall;
                    apiCall.className  = std::string(parentType);
                    apiCall.methodName = mr.name;
                    apiCall.token      = mtok;
                    apiCall.ilOffset   = instr.offset;
                    apiCall.resolvedTarget =
                        std::string(parentType) + "::" + mr.name;
                    apiCall.category   = DotNetAPICategory::Unknown;

                    if (impl.collectedAPICalls.size() < kMaxParsedMethods)
                        impl.collectedAPICalls.push_back(std::move(apiCall));
                }
            }

            // Heuristic: interpret selected methods via MSILInterpreter
            if (interp) {
                bool shouldInterpret = false;

                // Static constructors (.cctor) — primary string decryption vector
                if (md.name == ".cctor") shouldInterpret = true;

                // Main / entry point
                if (md.name == "Main") shouldInterpret = true;

                // High cyclomatic complexity (many switches)
                if (methodSwitchTargets > 10) shouldInterpret = true;

                if (shouldInterpret) {
                    const auto interpResult = interp->Execute(
                        disasm.instructions,
                        MetadataToken::Make(MetadataTableId::MethodDef, i + 1));

                    // Collect decrypted strings
                    for (const auto& ws : interpResult.decryptedStrings) {
                        // Convert u16string to UTF-8 string
                        std::string utf8;
                        utf8.reserve(ws.size());
                        for (char16_t ch : ws) {
                            if (ch < 0x80) {
                                utf8.push_back(static_cast<char>(ch));
                            } else if (ch < 0x800) {
                                utf8.push_back(static_cast<char>(0xC0 | (ch >> 6)));
                                utf8.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
                            } else {
                                utf8.push_back(static_cast<char>(0xE0 | (ch >> 12)));
                                utf8.push_back(static_cast<char>(0x80 | ((ch >> 6) & 0x3F)));
                                utf8.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
                            }
                        }
                        if (!utf8.empty() &&
                            result.extractedStrings.size() < kMaxExtractedStrings)
                        {
                            result.extractedStrings.push_back(std::move(utf8));
                        }
                    }

                    // Merge interpreter API calls
                    for (auto& apiCall : interpResult.apiCalls) {
                        if (impl.collectedAPICalls.size() < kMaxParsedMethods)
                            impl.collectedAPICalls.push_back(std::move(apiCall));
                    }

                    // Detect .cctor-based string decryption
                    if (md.name == ".cctor" &&
                        !interpResult.decryptedStrings.empty()) {
                        impl.hasCctorStringDecrypt = true;
                    }
                }
            }
        }

    } catch (...) {
        // Partial IL analysis — continue with what we have.
    }
}

// ============================================================================
// DetectObfuscation — heuristic detection of 10 obfuscation families
// ============================================================================

void DotNetAnalyzer::DetectObfuscation(const MetadataParser& parser) noexcept {
    try {
        auto& impl   = *m_impl;
        auto& result = impl.lastResult;
        const auto& typeRefs = parser.GetTypeRefs();

        auto addObfuscation = [&](DotNetObfuscation kind) {
            // Deduplicate
            for (auto existing : result.obfuscationIndicators) {
                if (existing == kind) return;
            }
            result.obfuscationIndicators.push_back(kind);
        };

        // ------------------------------------------------------------------
        // 1. ConfuserEx — <Module> with many methods, Unicode names,
        //    koi-prefixed resources, large .cctor switches
        // ------------------------------------------------------------------
        {
            bool confuserScore = false;
            if (impl.hasModuleTypeManyMethods) confuserScore = true;
            if (impl.nonAsciiTypeCount > 5)    confuserScore = true;
            if (impl.hasCctorStringDecrypt && impl.switchHeavyMethodCount > 0)
                confuserScore = true;

            // Check resources for "koi" prefix (ConfuserEx signature)
            for (const auto& res : result.resources) {
                if (res.name.size() >= 3 &&
                    res.name.substr(0, 3) == "koi") {
                    confuserScore = true;
                    break;
                }
            }

            if (confuserScore) {
                addObfuscation(DotNetObfuscation::NameObfuscation);
                addObfuscation(DotNetObfuscation::ControlFlowFlattening);
                addObfuscation(DotNetObfuscation::StringEncryption);
                result.detectedObfuscator = "ConfuserEx";
            }
        }

        // ------------------------------------------------------------------
        // 2. Dotfuscator — DotfuscatorAttribute, single-char method names
        // ------------------------------------------------------------------
        {
            bool dotfuscatorDetected = false;

            for (const auto& tr : typeRefs) {
                if (ContainsSubstring(tr.typeName, "DotfuscatorAttribute") ||
                    ContainsSubstring(tr.typeNamespace, "PreEmptive")) {
                    dotfuscatorDetected = true;
                    break;
                }
            }

            if (!dotfuscatorDetected && impl.totalMethodNameCount > 20) {
                const float singleCharRatio =
                    static_cast<float>(impl.singleCharMethodCount) /
                    static_cast<float>(impl.totalMethodNameCount);
                if (singleCharRatio > 0.4f) dotfuscatorDetected = true;
            }

            if (dotfuscatorDetected) {
                addObfuscation(DotNetObfuscation::NameObfuscation);
                if (result.detectedObfuscator.empty())
                    result.detectedObfuscator = "Dotfuscator";
            }
        }

        // ------------------------------------------------------------------
        // 3. SmartAssembly — type names with { or },
        //    SmartAssembly.Attributes namespace
        // ------------------------------------------------------------------
        {
            bool smartAsmDetected = false;

            for (const auto& tr : typeRefs) {
                if (ContainsSubstring(tr.typeNamespace,
                                      "SmartAssembly.Attributes")) {
                    smartAsmDetected = true;
                    break;
                }
            }

            if (!smartAsmDetected) {
                const auto& typeDefs = parser.GetTypeDefs();
                for (const auto& td : typeDefs) {
                    if (td.typeName.find('{') != std::string::npos ||
                        td.typeName.find('}') != std::string::npos) {
                        smartAsmDetected = true;
                        break;
                    }
                }
            }

            if (smartAsmDetected) {
                addObfuscation(DotNetObfuscation::NameObfuscation);
                addObfuscation(DotNetObfuscation::ResourceEncryption);
                if (result.detectedObfuscator.empty())
                    result.detectedObfuscator = "SmartAssembly";
            }
        }

        // ------------------------------------------------------------------
        // 4. Eazfuscator — very large IL bodies with massive switches,
        //    delegate-based string decryption
        // ------------------------------------------------------------------
        {
            if (impl.largeILMethodCount > 0 &&
                impl.switchHeavyMethodCount > 0)
            {
                addObfuscation(DotNetObfuscation::VirtualizationProtect);
                addObfuscation(DotNetObfuscation::ControlFlowFlattening);
                if (result.detectedObfuscator.empty())
                    result.detectedObfuscator = "Eazfuscator.NET";
            }
        }

        // ------------------------------------------------------------------
        // 5. Babel — BabelObfuscatorAttribute or "Babel" in assembly name
        // ------------------------------------------------------------------
        {
            bool babelDetected = false;

            for (const auto& tr : typeRefs) {
                if (ContainsSubstring(tr.typeName,
                                      "BabelObfuscatorAttribute")) {
                    babelDetected = true;
                    break;
                }
            }

            if (!babelDetected &&
                ContainsSubstringCI(result.assemblyName, "Babel")) {
                babelDetected = true;
            }

            if (babelDetected) {
                addObfuscation(DotNetObfuscation::MethodBodyEncryption);
                if (result.detectedObfuscator.empty())
                    result.detectedObfuscator = "Babel Obfuscator";
            }
        }

        // ------------------------------------------------------------------
        // 6. DNGuard — native entry point + many empty IL methods (HVM)
        // ------------------------------------------------------------------
        {
            const bool nativeEntry =
                (impl.cor20.flags & COR20Flags::NativeEntryPoint) != 0;

            if (nativeEntry && impl.totalMethodsWithRVA > 0) {
                const float emptyRatio =
                    static_cast<float>(impl.emptyILMethodCount) /
                    static_cast<float>(impl.totalMethodsWithRVA);
                if (emptyRatio > 0.5f) {
                    addObfuscation(DotNetObfuscation::VirtualizationProtect);
                    addObfuscation(DotNetObfuscation::MethodBodyEncryption);
                    if (result.detectedObfuscator.empty())
                        result.detectedObfuscator = "DNGuard HVM";
                }
            }
        }

        // ------------------------------------------------------------------
        // 7. .NET Reactor — ReactorHelper type, embedded native code
        // ------------------------------------------------------------------
        {
            bool reactorDetected = false;
            const auto& typeDefs = parser.GetTypeDefs();
            for (const auto& td : typeDefs) {
                if (ContainsSubstring(td.typeName, "ReactorHelper") ||
                    ContainsSubstring(td.typeName, "CryptoObfuscator")) {
                    reactorDetected = true;
                    break;
                }
            }
            for (const auto& tr : typeRefs) {
                if (ContainsSubstring(tr.typeName, "ReactorHelper")) {
                    reactorDetected = true;
                    break;
                }
            }

            if (reactorDetected) {
                addObfuscation(DotNetObfuscation::MethodBodyEncryption);
                addObfuscation(DotNetObfuscation::AntiTamper);
                if (result.detectedObfuscator.empty())
                    result.detectedObfuscator = ".NET Reactor";
            }
        }

        // ------------------------------------------------------------------
        // 8. Generic name mangling — >50% non-ASCII type names
        // ------------------------------------------------------------------
        {
            if (impl.totalTypeCount > 10) {
                const float nonAsciiRatio =
                    static_cast<float>(impl.nonAsciiTypeCount) /
                    static_cast<float>(impl.totalTypeCount);
                if (nonAsciiRatio > 0.5f)
                    addObfuscation(DotNetObfuscation::NameObfuscation);
            }
        }

        // ------------------------------------------------------------------
        // 9. Control flow obfuscation — average switch targets > 10
        // ------------------------------------------------------------------
        {
            if (impl.switchMethodCount > 0) {
                const double avgTargets =
                    static_cast<double>(impl.totalSwitchTargets) /
                    static_cast<double>(impl.switchMethodCount);
                if (avgTargets > 10.0)
                    addObfuscation(DotNetObfuscation::ControlFlowFlattening);
            }
        }

        // ------------------------------------------------------------------
        // 10. String encryption — .cctor methods that decrypt strings
        //     via complex computation (detected in AnalyzeMethods)
        // ------------------------------------------------------------------
        {
            if (impl.hasCctorStringDecrypt)
                addObfuscation(DotNetObfuscation::StringEncryption);
        }

        // Mixed-mode assembly (C++/CLI)
        if (!result.isILOnly) {
            addObfuscation(DotNetObfuscation::MixedModeAssembly);
        }

    } catch (...) {
        // Partial detection — continue.
    }
}

// ============================================================================
// ExtractPInvokes — collect all DllImport / P/Invoke declarations
// ============================================================================

void DotNetAnalyzer::ExtractPInvokes(const MetadataParser& parser) noexcept {
    try {
        auto& impl   = *m_impl;
        auto& result = impl.lastResult;

        const auto& implMaps   = parser.GetImplMaps();
        const auto& moduleRefs = parser.GetModuleRefs();
        const auto& methodDefs = parser.GetMethodDefs();

        result.pInvokeImports.reserve(
            std::min(static_cast<uint32_t>(implMaps.size()),
                     kMaxPInvokeImports));

        for (const auto& im : implMaps) {
            if (result.pInvokeImports.size() >= kMaxPInvokeImports) break;

            DotNetPInvoke entry;
            entry.importName = im.importName;

            // Resolve DLL name from ModuleRef table
            // ImplMapRow.importScopeIndex is 1-based into ModuleRef
            if (im.importScopeIndex > 0 &&
                im.importScopeIndex <= moduleRefs.size())
            {
                entry.moduleName = moduleRefs[im.importScopeIndex - 1].name;
            }

            // Resolve managed method name from MemberForwarded coded index.
            // MemberForwarded tag: 0 = Field, 1 = MethodDef.
            const uint32_t tag = im.memberForwardedIndex & 0x01;
            const uint32_t row = im.memberForwardedIndex >> 1;
            if (tag == 1 && row > 0 && row <= methodDefs.size()) {
                entry.managedName = methodDefs[row - 1].name;
                entry.methodToken =
                    MetadataToken::Make(MetadataTableId::MethodDef, row);
            }

            // Set P/Invoke combo flags for threat scoring
            const std::string_view dll = entry.moduleName;
            const std::string_view func = entry.importName;

            if (CaseInsensitiveEquals(dll, "kernel32.dll") ||
                CaseInsensitiveEquals(dll, "kernel32"))
            {
                if (func == "VirtualAlloc")         impl.hasPInvokeVirtualAlloc = true;
                if (func == "VirtualAllocEx")        impl.hasPInvokeVirtualAllocEx = true;
                if (func == "WriteProcessMemory")    impl.hasPInvokeWriteProcessMemory = true;
                if (func == "CreateRemoteThread" ||
                    func == "CreateRemoteThreadEx")  impl.hasPInvokeCreateRemoteThread = true;
            }
            else if (CaseInsensitiveEquals(dll, "ntdll.dll") ||
                     CaseInsensitiveEquals(dll, "ntdll"))
            {
                if (func == "NtCreateThreadEx")      impl.hasPInvokeNtCreateThreadEx = true;
                if (func == "NtUnmapViewOfSection")  impl.hasPInvokeNtUnmapViewOfSection = true;
            }
            else if (CaseInsensitiveEquals(dll, "user32.dll") ||
                     CaseInsensitiveEquals(dll, "user32"))
            {
                if (func == "GetAsyncKeyState" ||
                    func == "GetKeyState")           impl.hasPInvokeGetAsyncKeyState = true;
            }
            else if (CaseInsensitiveEquals(dll, "amsi.dll") ||
                     CaseInsensitiveEquals(dll, "amsi"))
            {
                impl.hasAmsiReference = true;
            }

            // Flag P/Invoke as suspicious based on rule table
            for (size_t r = 0; r < kPInvokeRuleCount; ++r) {
                if (CaseInsensitiveEquals(dll, kSuspiciousPInvokes[r].dllName) &&
                    func == kSuspiciousPInvokes[r].funcName)
                {
                    result.hasPInvokeSuspicious = true;
                    break;
                }
            }

            result.pInvokeImports.push_back(std::move(entry));
        }

    } catch (...) {
        // Partial P/Invoke extraction — continue.
    }
}

// ============================================================================
// ClassifyAPICalls — categorize all collected MemberRef call targets
// ============================================================================

void DotNetAnalyzer::ClassifyAPICalls() noexcept {
    try {
        auto& impl   = *m_impl;
        auto& result = impl.lastResult;

        std::unordered_set<uint8_t> seenCategories;

        for (auto& apiCall : impl.collectedAPICalls) {
            // Match against the classification rule table
            for (size_t r = 0; r < kAPIRuleCount; ++r) {
                const auto& rule = kAPIRules[r];

                if (apiCall.className != rule.fullTypeName) continue;
                if (rule.methodName != nullptr &&
                    apiCall.methodName != rule.methodName) continue;

                apiCall.category = rule.category;
                break;
            }

            // Assembly.Load overload detection: if the method is "Load" on
            // Assembly and we already classified it as AssemblyLoad, check
            // for byte[] overload (raw loading).  Heuristic: any
            // Assembly.Load call in an assembly with obfuscation or large
            // byte arrays is considered raw loading (conservative approach).
            if (apiCall.category == DotNetAPICategory::AssemblyLoad &&
                apiCall.methodName == "Load")
            {
                if (!result.obfuscationIndicators.empty() ||
                    !result.resources.empty())
                {
                    apiCall.category = DotNetAPICategory::AssemblyLoadRaw;
                }
            }

            // Only track classified (suspicious) APIs in the result
            if (apiCall.category != DotNetAPICategory::Unknown) {
                seenCategories.insert(
                    static_cast<uint8_t>(apiCall.category));
                if (result.suspiciousAPICalls.size() < kMaxParsedMethods)
                    result.suspiciousAPICalls.push_back(apiCall);
            }
        }

        // Set high-level threat indicator flags from categories
        for (uint8_t cat : seenCategories) {
            switch (static_cast<DotNetAPICategory>(cat)) {
            case DotNetAPICategory::AssemblyLoadRaw:
                result.hasReflectionLoading = true;
                break;
            case DotNetAPICategory::ReflectionInvoke:
                result.hasDynamicInvocation = true;
                break;
            case DotNetAPICategory::ProcessStart:
                result.hasProcessCreation = true;
                break;
            case DotNetAPICategory::WebDownload:
            case DotNetAPICategory::SocketConnect:
            case DotNetAPICategory::DnsResolve:
                result.hasNetworkActivity = true;
                break;
            case DotNetAPICategory::SymmetricEncrypt:
            case DotNetAPICategory::AsymmetricEncrypt:
            case DotNetAPICategory::HashCompute:
                result.hasCryptoUsage = true;
                break;
            case DotNetAPICategory::AntiDebug:
            case DotNetAPICategory::AntiVM:
                result.hasAntiAnalysis = true;
                break;
            default:
                break;
            }
        }

    } catch (...) {
        // Partial classification — continue.
    }
}

// ============================================================================
// DetectPayloadEmbedding — high-entropy resources, large FieldRVA arrays
// ============================================================================

void DotNetAnalyzer::DetectPayloadEmbedding(
    const MetadataParser& parser,
    VirtualMemory& memory,
    GuestAddress imageBase) noexcept
{
    try {
        auto& impl   = *m_impl;
        auto& result = impl.lastResult;

        if (!impl.enablePayloadExtraction) return;

        const auto& cor20 = impl.cor20;

        // --- .NET resource blob (ManifestResource data) ---
        if (cor20.resourcesRVA != 0 && cor20.resourcesSize > 0) {
            const GuestAddress resBase = imageBase + cor20.resourcesRVA;
            const uint32_t scanLimit =
                std::min(cor20.resourcesSize, kMaxResourceScan);

            // Walk the resource blob: each entry is [uint32_t length][data…]
            uint32_t offset = 0;
            uint32_t resIndex = 0;
            while (offset + sizeof(uint32_t) <= scanLimit &&
                   resIndex < kMaxResources)
            {
                uint32_t entryLen = 0;
                if (!ReadGuestMemory(memory, resBase + offset,
                                     &entryLen, sizeof(entryLen)))
                    break;

                offset += sizeof(uint32_t);

                // Validate entry length
                if (entryLen == 0 || offset + entryLen > scanLimit) break;

                // For entropy analysis, read a sample of the entry
                constexpr uint32_t kEntropySampleSize = 4096;
                const uint32_t sampleSize =
                    std::min(entryLen, kEntropySampleSize);

                std::vector<uint8_t> sample(sampleSize);
                if (!ReadGuestMemory(memory, resBase + offset,
                                     sample.data(), sampleSize))
                    break;

                const double entropy =
                    ComputeShannonEntropy(sample.data(), sampleSize);

                DotNetResource resEntry;
                resEntry.name     = "Resource_" + std::to_string(resIndex);
                resEntry.offset   = offset - static_cast<uint32_t>(sizeof(uint32_t));
                resEntry.size     = entryLen;
                resEntry.entropy  = entropy;
                resEntry.isEncrypted = (entropy > kHighEntropyThreshold);

                result.resources.push_back(std::move(resEntry));
                ++resIndex;

                offset += entryLen;
            }

            result.resourceCount = resIndex;
        }

        // --- FieldRVA table: large initialized byte arrays ---
        const auto& fieldRVAs = parser.GetFieldRVAs();
        for (const auto& frva : fieldRVAs) {
            if (frva.rva == 0) continue;

            // Probe for large initialized data. We don't know the exact
            // field size from FieldRVA alone (it requires resolving the
            // Field's signature for the array element type and count).
            // Heuristic: read up to 64 KB and check entropy.
            constexpr uint32_t kFieldRVAProbeSize = 64 * 1024;

            // Verify the address is readable
            const GuestAddress fieldVA = imageBase + frva.rva;
            if (!memory.IsAccessible(fieldVA, MemProt::Read)) continue;

            std::vector<uint8_t> probe(kFieldRVAProbeSize);
            uint32_t actualRead = 0;
            for (uint32_t p = 0; p < kFieldRVAProbeSize; p += kPageSize) {
                const uint8_t* ptr =
                    memory.GetHostReadPtr(fieldVA + p);
                if (!ptr) break;
                const uint32_t chunk =
                    std::min(kPageSize, static_cast<GuestSize>(kFieldRVAProbeSize - p));
                std::memcpy(probe.data() + p, ptr,
                            static_cast<size_t>(chunk));
                actualRead += chunk;
            }

            if (actualRead < kLargeResourceThreshold) continue;

            const double entropy =
                ComputeShannonEntropy(probe.data(), actualRead);

            if (entropy > kHighEntropyThreshold) {
                DotNetResource fieldRes;
                fieldRes.name   = "FieldRVA_0x" +
                    ([&]() -> std::string {
                        char buf[16];
                        std::snprintf(buf, sizeof(buf), "%08X", frva.rva);
                        return buf;
                    })();
                fieldRes.offset     = frva.rva;
                fieldRes.size       = actualRead;
                fieldRes.entropy    = entropy;
                fieldRes.isEncrypted = true;

                if (result.resources.size() < kMaxResources)
                    result.resources.push_back(std::move(fieldRes));
            }
        }

    } catch (...) {
        // Partial payload detection — continue.
    }
}

// ============================================================================
// ComputeThreatScore — aggregate all signals into 0.0–1.0 score + MITRE IDs
// ============================================================================

void DotNetAnalyzer::ComputeThreatScore() noexcept {
    try {
        auto& impl   = *m_impl;
        auto& result = impl.lastResult;
        float score  = 0.0f;

        // Collect which API categories are present
        std::unordered_set<uint8_t> seenCats;
        for (const auto& api : result.suspiciousAPICalls)
            seenCats.insert(static_cast<uint8_t>(api.category));

        auto hasCat = [&](DotNetAPICategory cat) -> bool {
            return seenCats.count(static_cast<uint8_t>(cat)) > 0;
        };

        // ---- API-based scoring ----

        if (hasCat(DotNetAPICategory::AssemblyLoadRaw)) {
            score += kWeightAssemblyLoadRaw;
            impl.lastMITREIDs.push_back("T1620");   // Reflective Code Loading
        }
        if (hasCat(DotNetAPICategory::AssemblyLoad)) {
            score += kWeightAssemblyLoad;
        }
        if (hasCat(DotNetAPICategory::ReflectionInvoke)) {
            score += kWeightReflectionInvoke;
        }
        if (hasCat(DotNetAPICategory::DynamicCompile)) {
            score += kWeightDynamicCompile;
            impl.lastMITREIDs.push_back("T1027.010"); // Command Obfuscation
        }
        if (hasCat(DotNetAPICategory::ProcessStart)) {
            score += kWeightProcessStart;
            impl.lastMITREIDs.push_back("T1059.001"); // PowerShell execution
        }
        if (hasCat(DotNetAPICategory::WebDownload) ||
            hasCat(DotNetAPICategory::SocketConnect))
        {
            score += kWeightNetworkIO;
        }
        if (hasCat(DotNetAPICategory::MarshalCopy)) {
            score += kWeightMarshalCopy;
        }
        if (hasCat(DotNetAPICategory::AntiDebug) ||
            hasCat(DotNetAPICategory::AntiVM))
        {
            score += kWeightAntiDebug;
        }
        if (hasCat(DotNetAPICategory::SymmetricEncrypt) ||
            hasCat(DotNetAPICategory::AsymmetricEncrypt))
        {
            score += kWeightCryptoUsage;
        }
        if (hasCat(DotNetAPICategory::EnvironmentQuery)) {
            impl.lastMITREIDs.push_back("T1082"); // System Information Discovery
        }

        // ---- Obfuscation scoring ----

        if (!result.obfuscationIndicators.empty()) {
            score += kWeightObfuscationBase;
            impl.lastMITREIDs.push_back("T1027"); // Obfuscated Files

            // Check for packing-class obfuscators
            for (auto obf : result.obfuscationIndicators) {
                if (obf == DotNetObfuscation::VirtualizationProtect ||
                    obf == DotNetObfuscation::MethodBodyEncryption)
                {
                    impl.lastMITREIDs.push_back("T1027.002"); // Software Packing
                    break;
                }
            }
        }
        if (result.obfuscationIndicators.size() > 2) {
            score += kWeightObfuscationMultiple;
        }

        // String decryption detected
        if (impl.hasCctorStringDecrypt) {
            score += kWeightStringDecryption;
            impl.lastMITREIDs.push_back("T1140"); // Deobfuscate/Decode Files
        }

        // ---- P/Invoke combo scoring ----

        if (impl.hasPInvokeVirtualAlloc && impl.hasPInvokeWriteProcessMemory) {
            score += kWeightInjectionCombo;

            if (impl.hasPInvokeCreateRemoteThread) {
                score += kWeightInjectionFull;
                impl.lastMITREIDs.push_back("T1055.001"); // Process Injection: DLL
            }
        }

        if (impl.hasPInvokeVirtualAllocEx && impl.hasPInvokeNtUnmapViewOfSection) {
            impl.lastMITREIDs.push_back("T1055.012"); // Process Hollowing
            score += kWeightInjectionCombo;
        }

        if (impl.hasPInvokeNtCreateThreadEx) {
            score += 0.05f;
        }

        if (impl.hasPInvokeGetAsyncKeyState) {
            score += kWeightKeylogging;
            impl.lastMITREIDs.push_back("T1056.001"); // Keylogging
        }

        if (impl.hasAmsiReference) {
            score += kWeightAMSI;
        }

        // ---- Name obfuscation scoring ----

        if (impl.totalTypeCount > 10) {
            const float nonAsciiRatio =
                static_cast<float>(impl.nonAsciiTypeCount) /
                static_cast<float>(impl.totalTypeCount);
            if (nonAsciiRatio > 0.5f)
                score += kWeightNonAsciiNames;
        }

        // ---- DNGuard-style HVM (native entry + empty IL) ----

        if (impl.totalMethodsWithRVA > 0) {
            const float emptyRatio =
                static_cast<float>(impl.emptyILMethodCount) /
                static_cast<float>(impl.totalMethodsWithRVA);
            if (emptyRatio > 0.5f && !result.isILOnly)
                score += kWeightNativeEntryEmpty;
        }

        // ---- High-entropy embedded resources ----

        for (const auto& res : result.resources) {
            if (res.isEncrypted && res.size > kLargeResourceThreshold) {
                score += kWeightHighEntropyResource;
                break;  // Count once
            }
        }

        // ---- Deduplicate MITRE IDs ----

        {
            std::unordered_set<std::string> seen;
            std::vector<std::string> deduped;
            deduped.reserve(impl.lastMITREIDs.size());
            for (auto& id : impl.lastMITREIDs) {
                if (seen.insert(id).second)
                    deduped.push_back(std::move(id));
            }
            impl.lastMITREIDs = std::move(deduped);
        }

        impl.lastThreatScore = std::clamp(score, 0.0f, 1.0f);

    } catch (...) {
        // Scoring failure — leave score at 0.0.
    }
}

// ============================================================================
// Accessors
// ============================================================================

const DotNetAnalysisResult& DotNetAnalyzer::GetLastResult() const noexcept {
    return m_impl->lastResult;
}

float DotNetAnalyzer::GetLastThreatScore() const noexcept {
    return m_impl->lastThreatScore;
}

const std::vector<std::string>& DotNetAnalyzer::GetLastMITREIDs() const noexcept {
    return m_impl->lastMITREIDs;
}

// ============================================================================
// Configuration
// ============================================================================

void DotNetAnalyzer::SetMaxMethodsToAnalyze(uint32_t max) noexcept {
    m_impl->maxMethodsToAnalyze =
        std::min(max, kMaxParsedMethods);
}

void DotNetAnalyzer::SetEnableStringDecryption(bool enable) noexcept {
    m_impl->enableStringDecryption = enable;
}

void DotNetAnalyzer::SetEnablePayloadExtraction(bool enable) noexcept {
    m_impl->enablePayloadExtraction = enable;
}

} // namespace Phantom::CLR

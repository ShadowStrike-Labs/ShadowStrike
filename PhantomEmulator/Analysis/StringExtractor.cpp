/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#include "StringExtractor.hpp"
#include "../Core/Memory/VirtualMemory.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <exception>
#include <limits>
#include <new>
#include <unordered_map>
#include <unordered_set>

namespace Phantom {

// ============================================================================
// Hard Caps — prevent resource exhaustion during string analysis
// ============================================================================

static constexpr uint32_t kMaxStrings              = 100'000;
static constexpr uint32_t kMaxDedupEntries         = 100'000;
static constexpr uint32_t kMaxStackRegions         = 1024;
static constexpr uint32_t kMaxStackBytesPerRegion  = 4096;
static constexpr uint32_t kMinAsciiStringLength    = 4;
static constexpr uint32_t kMinWideStringLength     = 4;
static constexpr uint32_t kMaxStringLength         = 8192;
static constexpr uint32_t kMinBase64Length          = 16;
static constexpr uint32_t kMinXORBlockSize         = 32;
static constexpr uint32_t kMaxXORSampleBytes       = 256;
static constexpr float    kHighEntropyThreshold    = 5.0f;
static constexpr float    kPrintableRatioThreshold = 0.6f;
static constexpr uint32_t kSEPageSize                = 4096;
static constexpr uint32_t kMaxPagesPerScan         = 131072; // 512 MB / 4 KB
static constexpr GuestAddress kMaxScanAddress      = 512ULL * 1024 * 1024;
static constexpr uint32_t kMaxDecodedStringLength  = 8192;

// ============================================================================
// Internal Helpers — anonymous namespace
// ============================================================================

namespace {

// ---- Character classification (no locale, no windows.h) -------------------

[[nodiscard]] bool IsPrintableAscii(uint8_t c) noexcept {
    return (c >= 0x20 && c <= 0x7E);
}

[[nodiscard]] bool IsStringByte(uint8_t c) noexcept {
    return IsPrintableAscii(c) || c == 0x09 || c == 0x0A || c == 0x0D;
}

[[nodiscard]] bool IsBase64Char(uint8_t c) noexcept {
    return (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == '+' || c == '/' || c == '=';
}

[[nodiscard]] bool IsAlphaLower(char c) noexcept {
    return c >= 'a' && c <= 'z';
}

[[nodiscard]] bool IsAlphaUpper(char c) noexcept {
    return c >= 'A' && c <= 'Z';
}

[[nodiscard]] bool IsAlpha(char c) noexcept {
    return IsAlphaLower(c) || IsAlphaUpper(c);
}

[[nodiscard]] bool IsDigit(char c) noexcept {
    return c >= '0' && c <= '9';
}

[[nodiscard]] char ToLower(char c) noexcept {
    if (IsAlphaUpper(c)) return static_cast<char>(c + ('a' - 'A'));
    return c;
}

// ---- Case-insensitive string helpers --------------------------------------

[[nodiscard]] bool CaseInsensitiveEqual(const std::string& a, const std::string& b) noexcept {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (ToLower(a[i]) != ToLower(b[i])) return false;
    }
    return true;
}

[[nodiscard]] bool ContainsCaseInsensitive(const std::string& haystack, const char* needle) noexcept {
    const size_t needleLen = std::strlen(needle);
    if (needleLen == 0 || haystack.size() < needleLen) return false;
    for (size_t i = 0; i <= haystack.size() - needleLen; ++i) {
        bool match = true;
        for (size_t j = 0; j < needleLen; ++j) {
            if (ToLower(haystack[i + j]) != ToLower(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

[[nodiscard]] bool StartsWithCaseInsensitive(const std::string& str, const char* prefix) noexcept {
    const size_t prefixLen = std::strlen(prefix);
    if (str.size() < prefixLen) return false;
    for (size_t i = 0; i < prefixLen; ++i) {
        if (ToLower(str[i]) != ToLower(prefix[i])) return false;
    }
    return true;
}

[[nodiscard]] bool EndsWithCaseInsensitive(const std::string& str, const char* suffix) noexcept {
    const size_t suffixLen = std::strlen(suffix);
    if (str.size() < suffixLen) return false;
    const size_t offset = str.size() - suffixLen;
    for (size_t i = 0; i < suffixLen; ++i) {
        if (ToLower(str[offset + i]) != ToLower(suffix[i])) return false;
    }
    return true;
}

// ---- Shannon Entropy ------------------------------------------------------

[[nodiscard]] float ComputeEntropy(const uint8_t* data, size_t len) noexcept {
    if (len == 0) return 0.0f;

    uint32_t freq[256] = {};
    for (size_t i = 0; i < len; ++i) {
        freq[data[i]]++;
    }

    float entropy = 0.0f;
    const float fLen = static_cast<float>(len);
    for (uint32_t i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        const float p = static_cast<float>(freq[i]) / fLen;
        entropy -= p * std::log2f(p);
    }
    return entropy;
}

// ---- Printable ratio for a byte buffer ------------------------------------

[[nodiscard]] float PrintableRatio(const uint8_t* data, size_t len) noexcept {
    if (len == 0) return 0.0f;
    uint32_t printable = 0;
    for (size_t i = 0; i < len; ++i) {
        if (IsStringByte(data[i])) ++printable;
    }
    return static_cast<float>(printable) / static_cast<float>(len);
}

// ---- Base64 Decode (full implementation, no dependencies) -----------------

static constexpr uint8_t kBase64Invalid = 0xFF;

[[nodiscard]] std::array<uint8_t, 256> BuildBase64DecodeTable() noexcept {
    std::array<uint8_t, 256> table{};
    table.fill(kBase64Invalid);
    for (uint8_t i = 0; i < 26; ++i) {
        table[static_cast<uint8_t>('A') + i] = i;
        table[static_cast<uint8_t>('a') + i] = i + 26;
    }
    for (uint8_t i = 0; i < 10; ++i) {
        table[static_cast<uint8_t>('0') + i] = i + 52;
    }
    table[static_cast<uint8_t>('+')] = 62;
    table[static_cast<uint8_t>('/')] = 63;
    return table;
}

static const auto kBase64DecodeTable = BuildBase64DecodeTable();

// Returns decoded bytes, or empty vector on invalid input.
[[nodiscard]] std::vector<uint8_t> Base64Decode(const std::string& input) noexcept {
    std::vector<uint8_t> result;
    if (input.size() < 4) return result;

    // Strip trailing whitespace and determine padding
    size_t len = input.size();
    while (len > 0 && (input[len - 1] == '\n' || input[len - 1] == '\r' ||
                       input[len - 1] == ' ')) {
        --len;
    }
    if (len == 0 || (len % 4) != 0) return result;

    const size_t outputLen = (len / 4) * 3;
    if (outputLen > kMaxDecodedStringLength) return result;

    try {
        result.reserve(outputLen);
    } catch (const std::exception&) {
        return result;
    }

    for (size_t i = 0; i < len; i += 4) {
        const uint8_t c0 = static_cast<uint8_t>(input[i]);
        const uint8_t c1 = static_cast<uint8_t>(input[i + 1]);
        const uint8_t c2 = static_cast<uint8_t>(input[i + 2]);
        const uint8_t c3 = static_cast<uint8_t>(input[i + 3]);

        const uint8_t d0 = kBase64DecodeTable[c0];
        const uint8_t d1 = kBase64DecodeTable[c1];

        // First two chars must always be valid base64
        if (d0 == kBase64Invalid || d1 == kBase64Invalid) {
            result.clear();
            return result;
        }

        if (c2 == '=' && c3 == '=') {
            // Two padding chars: one output byte
            const uint32_t triple = (static_cast<uint32_t>(d0) << 18) |
                                    (static_cast<uint32_t>(d1) << 12);
            result.push_back(static_cast<uint8_t>((triple >> 16) & 0xFF));
        } else if (c3 == '=') {
            // One padding char: two output bytes
            const uint8_t d2 = kBase64DecodeTable[c2];
            if (d2 == kBase64Invalid) { result.clear(); return result; }
            const uint32_t triple = (static_cast<uint32_t>(d0) << 18) |
                                    (static_cast<uint32_t>(d1) << 12) |
                                    (static_cast<uint32_t>(d2) << 6);
            result.push_back(static_cast<uint8_t>((triple >> 16) & 0xFF));
            result.push_back(static_cast<uint8_t>((triple >> 8) & 0xFF));
        } else {
            // No padding: three output bytes
            const uint8_t d2 = kBase64DecodeTable[c2];
            const uint8_t d3 = kBase64DecodeTable[c3];
            if (d2 == kBase64Invalid || d3 == kBase64Invalid) {
                result.clear();
                return result;
            }
            const uint32_t triple = (static_cast<uint32_t>(d0) << 18) |
                                    (static_cast<uint32_t>(d1) << 12) |
                                    (static_cast<uint32_t>(d2) << 6) |
                                    static_cast<uint32_t>(d3);
            result.push_back(static_cast<uint8_t>((triple >> 16) & 0xFF));
            result.push_back(static_cast<uint8_t>((triple >> 8) & 0xFF));
            result.push_back(static_cast<uint8_t>(triple & 0xFF));
        }
    }
    return result;
}

// ---- Index of Coincidence (for multi-byte XOR key length guessing) --------

[[nodiscard]] float IndexOfCoincidence(const uint8_t* data, size_t len,
                                       uint32_t keyLen, uint32_t position) noexcept {
    if (len < keyLen * 2) return 0.0f;

    uint32_t freq[256] = {};
    uint32_t count = 0;
    for (size_t i = position; i < len; i += keyLen) {
        freq[data[i]]++;
        ++count;
    }
    if (count < 2) return 0.0f;

    float ic = 0.0f;
    const float denom = static_cast<float>(count) * static_cast<float>(count - 1);
    for (uint32_t i = 0; i < 256; ++i) {
        if (freq[i] > 1) {
            ic += static_cast<float>(freq[i]) * static_cast<float>(freq[i] - 1);
        }
    }
    return ic / denom;
}

// ---- Hex formatting for encoding strings ----------------------------------

[[nodiscard]] char HexNibble(uint8_t v) noexcept {
    return (v < 10) ? static_cast<char>('0' + v) : static_cast<char>('A' + v - 10);
}

[[nodiscard]] std::string ByteToHex(uint8_t b) noexcept {
    std::string s;
    try {
        s.resize(2, '0');
    } catch (const std::exception&) {
        return {};
    }
    s[0] = HexNibble((b >> 4) & 0x0F);
    s[1] = HexNibble(b & 0x0F);
    return s;
}

[[nodiscard]] GuestAddress AddGuestOffset(GuestAddress base, size_t offset) noexcept {
    const GuestAddress guestOffset =
        offset > static_cast<size_t>(std::numeric_limits<GuestAddress>::max())
            ? std::numeric_limits<GuestAddress>::max()
            : static_cast<GuestAddress>(offset);
    return (std::numeric_limits<GuestAddress>::max() - base < guestOffset)
        ? std::numeric_limits<GuestAddress>::max()
        : base + guestOffset;
}

void NormalizeExtractedText(std::string& value) noexcept {
    for (char& c : value) {
        const unsigned char ch = static_cast<unsigned char>(c);
        if (ch == '\r' || ch == '\n' || ch == '\t' || ch < 0x20U) {
            c = ' ';
        }
    }
    if (value.size() > kMaxStringLength) {
        value.resize(kMaxStringLength);
    }
}

// ---- IP address parser (manual, no regex) ---------------------------------

[[nodiscard]] bool IsValidIPAddress(const std::string& str) noexcept {
    // Must be in form N.N.N.N where each N is 0-255
    uint32_t octets = 0;
    uint32_t currentValue = 0;
    uint32_t digitCount = 0;

    for (size_t i = 0; i < str.size(); ++i) {
        const char c = str[i];
        if (IsDigit(c)) {
            currentValue = currentValue * 10 + static_cast<uint32_t>(c - '0');
            ++digitCount;
            if (digitCount > 3 || currentValue > 255) return false;
        } else if (c == '.') {
            if (digitCount == 0) return false;
            ++octets;
            if (octets > 3) return false;
            currentValue = 0;
            digitCount = 0;
        } else {
            return false;
        }
    }
    // Must end with a valid digit group and have exactly 4 octets
    return (octets == 3 && digitCount > 0 && currentValue <= 255);
}

// Check if a URL contains a raw IP address (not a domain name)
[[nodiscard]] bool URLContainsRawIP(const std::string& url) {
    // Find "://" and then extract host portion
    size_t schemeEnd = 0;
    for (size_t i = 0; i + 2 < url.size(); ++i) {
        if (url[i] == ':' && url[i + 1] == '/' && url[i + 2] == '/') {
            schemeEnd = i + 3;
            break;
        }
    }
    if (schemeEnd == 0) return false;

    // Extract host (up to '/', ':', or end)
    std::string host;
    for (size_t i = schemeEnd; i < url.size(); ++i) {
        if (url[i] == '/' || url[i] == ':') break;
        host.push_back(url[i]);
    }
    return IsValidIPAddress(host);
}

// Check if a URL contains an unusual port (not 80 or 443)
[[nodiscard]] bool URLHasUnusualPort(const std::string& url) noexcept {
    size_t schemeEnd = 0;
    for (size_t i = 0; i + 2 < url.size(); ++i) {
        if (url[i] == ':' && url[i + 1] == '/' && url[i + 2] == '/') {
            schemeEnd = i + 3;
            break;
        }
    }
    if (schemeEnd == 0) return false;

    // Find host:port boundary (skip past host)
    size_t colonPos = 0;
    for (size_t i = schemeEnd; i < url.size(); ++i) {
        if (url[i] == '/') break;
        if (url[i] == ':') {
            colonPos = i;
            break;
        }
    }
    if (colonPos == 0) return false;

    // Parse port number
    uint32_t port = 0;
    uint32_t digits = 0;
    for (size_t i = colonPos + 1; i < url.size(); ++i) {
        if (url[i] == '/') break;
        if (!IsDigit(url[i])) return false;
        if (port > 6553U || (port == 6553U && static_cast<uint32_t>(url[i] - '0') > 5U)) {
            return false;
        }
        port = port * 10 + static_cast<uint32_t>(url[i] - '0');
        ++digits;
        if (port > 65535) return false;
    }
    if (digits == 0) return false;
    return (port != 80 && port != 443);
}

// ---- Known suspicious keywords for Caesar/ROT detection -------------------

static constexpr std::array<const char*, 12> kRotKeywords = {{
    "http",
    "cmd",
    ".exe",
    "powershell",
    ".dll",
    "shell",
    "download",
    "invoke",
    "script",
    "eval",
    "socket",
    "connect",
}};

// ---- Known C2 / malware keywords for scoring ------------------------------

static constexpr std::array<const char*, 20> kC2Keywords = {{
    "beacon",
    "callback",
    "c2",
    "exfil",
    "botnet",
    "backdoor",
    "payload",
    "dropper",
    "shellcode",
    "exploit",
    "cobalt",
    "meterpreter",
    "reverse_tcp",
    "bind_shell",
    "stage",
    "loader",
    "injector",
    "keylog",
    "credential",
    "mimikatz",
}};

// ---- Known Win32 API names (~100 entries) ---------------------------------

static constexpr std::array<const char*, 116> kKnownAPIs = {{
    "VirtualAlloc", "VirtualAllocEx", "VirtualFree", "VirtualProtect",
    "VirtualProtectEx", "VirtualQuery", "VirtualQueryEx",
    "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "CloseHandle",
    "CreateProcessA", "CreateProcessW", "OpenProcess", "TerminateProcess",
    "CreateThread", "CreateRemoteThread", "CreateRemoteThreadEx",
    "ResumeThread", "SuspendThread", "GetThreadContext", "SetThreadContext",
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "GetModuleHandleA", "GetModuleHandleW",
    "GetModuleFileNameA", "GetModuleFileNameW",
    "RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW",
    "RegQueryValueExA", "RegQueryValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
    "RegDeleteKeyA", "RegDeleteKeyW", "RegDeleteValueA", "RegDeleteValueW",
    "HeapAlloc", "HeapFree", "HeapCreate", "HeapDestroy",
    "GlobalAlloc", "GlobalFree", "LocalAlloc", "LocalFree",
    "MapViewOfFile", "UnmapViewOfFile", "CreateFileMappingA", "CreateFileMappingW",
    "WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
    "URLDownloadToFileA", "URLDownloadToFileW",
    "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
    "InternetConnectA", "InternetConnectW", "InternetReadFile",
    "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW",
    "WSAStartup", "WSACleanup", "socket", "connect", "send", "recv",
    "bind", "listen", "accept", "closesocket",
    "GetSystemInfo", "GetVersionExA", "GetVersionExW",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "NtQuerySystemInformation",
    "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
    "NtWriteVirtualMemory", "NtReadVirtualMemory",
    "NtCreateThreadEx", "NtMapViewOfSection", "NtUnmapViewOfSection",
    "RtlDecompressBuffer", "RtlMoveMemory", "RtlCopyMemory",
    "WriteProcessMemory", "ReadProcessMemory",
    "CryptEncrypt", "CryptDecrypt", "CryptHashData",
    "CryptAcquireContextA", "CryptAcquireContextW",
    "FindFirstFileA", "FindFirstFileW", "FindNextFileA", "FindNextFileW",
    "GetTempPathA", "GetTempPathW",
    "SetWindowsHookExA", "SetWindowsHookExW",
}};

// ---- Domain validation (character-by-character, no regex) ------------------

[[nodiscard]] bool IsValidDomain(const std::string& str) noexcept {
    // Pattern: [a-z0-9.-]+\.[a-z]{2,}
    // Must contain at least one dot, TLD at least 2 alpha chars
    if (str.size() < 4) return false;

    // Find last dot
    size_t lastDot = std::string::npos;
    for (size_t i = str.size(); i > 0; --i) {
        if (str[i - 1] == '.') {
            lastDot = i - 1;
            break;
        }
    }
    if (lastDot == std::string::npos || lastDot == 0) return false;
    if (lastDot >= str.size() - 2) return false; // TLD must be >= 2

    // Validate body (before last dot): [a-z0-9.-]
    for (size_t i = 0; i < lastDot; ++i) {
        const char c = ToLower(str[i]);
        if (!IsAlphaLower(c) && !IsDigit(c) && c != '.' && c != '-') return false;
    }

    // Validate TLD (after last dot): [a-z]{2,}
    for (size_t i = lastDot + 1; i < str.size(); ++i) {
        if (!IsAlpha(str[i])) return false;
    }

    // Reject if it looks like an IP
    if (IsValidIPAddress(str)) return false;

    // Must not start or end with dash/dot (besides structure)
    if (str[0] == '-' || str[0] == '.') return false;
    if (str[lastDot - 1] == '-') return false;

    return true;
}

// ---- Credential-like detection --------------------------------------------

[[nodiscard]] bool LooksLikeCredential(const std::string& str) noexcept {
    return ContainsCaseInsensitive(str, "password") ||
           ContainsCaseInsensitive(str, "passwd") ||
           ContainsCaseInsensitive(str, "secret") ||
           ContainsCaseInsensitive(str, "token") ||
           ContainsCaseInsensitive(str, "api_key") ||
           ContainsCaseInsensitive(str, "apikey") ||
           ContainsCaseInsensitive(str, "auth_token") ||
           ContainsCaseInsensitive(str, "access_key") ||
           ContainsCaseInsensitive(str, "private_key");
}

// ---- Registry run key detection -------------------------------------------

[[nodiscard]] bool IsRegistryRunKey(const std::string& str) noexcept {
    return ContainsCaseInsensitive(str, "\\run\\") ||
           ContainsCaseInsensitive(str, "\\runonce\\") ||
           ContainsCaseInsensitive(str, "\\run\"") ||
           ContainsCaseInsensitive(str, "\\runonce\"") ||
           (ContainsCaseInsensitive(str, "currentversion\\run") &&
            !ContainsCaseInsensitive(str, "runtime"));
}

} // anonymous namespace

// ============================================================================
// StringExtractor::Impl — PIMPL body
// ============================================================================

struct StringExtractor::Impl {
    // Configuration reference (immutable after construction)
    bool iocExtractionEnabled = true;

    // Primary results store (capped at kMaxStrings)
    std::vector<ExtractedString> strings;

    // Deduplication map: string value → index into strings vector
    std::unordered_map<std::string, uint32_t> dedup;

    // Stack string tracking: page-aligned rsp_base → accumulated bytes (offset → byte)
    struct StackRegion {
        std::unordered_map<uint32_t, uint8_t> bytes; // offset within region → byte
        uint64_t lastInstrCount = 0;
    };
    std::unordered_map<GuestAddress, StackRegion> stackRegions;

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    explicit Impl(const EmulationConfig& config)
        : iocExtractionEnabled(config.enableIOCExtraction)
    {
        strings.reserve(1024);
    }

    // -----------------------------------------------------------------------
    // Deduplication and insertion
    // -----------------------------------------------------------------------

    bool AddString(ExtractedString&& es) {
        if (strings.size() >= kMaxStrings) return false;
        if (es.value.empty()) return false;
        NormalizeExtractedText(es.value);
        if (es.value.empty()) return false;

        auto it = dedup.find(es.value);
        if (it != dedup.end()) {
            // Already exists: increment occurrences
            if (it->second < strings.size()) {
                if (strings[it->second].occurrences < std::numeric_limits<uint32_t>::max()) {
                    ++strings[it->second].occurrences;
                }
            }
            return true;
        }

        if (dedup.size() >= kMaxDedupEntries) return false;

        const uint32_t idx = static_cast<uint32_t>(strings.size());
        std::string key = es.value;
        try {
            auto [inserted, didInsert] = dedup.emplace(key, idx);
            (void)inserted;
            if (!didInsert) {
                return true;
            }
            strings.push_back(std::move(es));
        } catch (const std::bad_alloc&) {
            dedup.erase(key);
            return false;
        } catch (const std::exception&) {
            dedup.erase(key);
            return false;
        }
        return true;
    }

    // -----------------------------------------------------------------------
    // ASCII string extraction
    // -----------------------------------------------------------------------

    void ExtractAsciiStrings(const uint8_t* data, size_t size,
                             GuestAddress base) {
        if (!data || size == 0) return;

        size_t runStart = 0;
        bool inRun = false;

        for (size_t i = 0; i < size; ++i) {
            if (IsStringByte(data[i])) {
                if (!inRun) {
                    runStart = i;
                    inRun = true;
                }
            } else {
                if (inRun) {
                    const size_t runLen = i - runStart;
                    if (runLen >= kMinAsciiStringLength && runLen <= kMaxStringLength) {
                        ExtractedString es;
                        es.value.assign(
                            reinterpret_cast<const char*>(data + runStart), runLen);
                        es.address = AddGuestOffset(base, runStart);
                        es.isWide = false;
                        es.encoding = "ascii";
                        AddString(std::move(es));
                    }
                    inRun = false;
                }
            }
        }
        // Handle string at end of buffer
        if (inRun) {
            const size_t runLen = size - runStart;
            if (runLen >= kMinAsciiStringLength && runLen <= kMaxStringLength) {
                ExtractedString es;
                es.value.assign(
                    reinterpret_cast<const char*>(data + runStart), runLen);
                es.address = AddGuestOffset(base, runStart);
                es.isWide = false;
                es.encoding = "ascii";
                AddString(std::move(es));
            }
        }
    }

    // -----------------------------------------------------------------------
    // UTF-16LE string extraction
    // -----------------------------------------------------------------------

    void ExtractWideStrings(const uint8_t* data, size_t size,
                            GuestAddress base) {
        if (!data || size < 2) return;

        std::string accumulated;
        size_t runStartByte = 0;
        bool inRun = false;

        for (size_t i = 0; i + 1 < size; i += 2) {
            const uint8_t lo = data[i];
            const uint8_t hi = data[i + 1];

            // Printable ASCII as UTF-16LE: lo is printable, hi is 0x00
            const bool isWideChar = (IsPrintableAscii(lo) || lo == 0x09 ||
                                     lo == 0x0A || lo == 0x0D) && hi == 0x00;

            if (isWideChar) {
                if (!inRun) {
                    runStartByte = i;
                    inRun = true;
                    accumulated.clear();
                }
                accumulated.push_back(static_cast<char>(lo));
                if (accumulated.size() > kMaxStringLength) {
                    // Truncate run — emit what we have and reset
                    ExtractedString es;
                    es.value = std::move(accumulated);
                    es.address = AddGuestOffset(base, runStartByte);
                    es.isWide = true;
                    es.encoding = "utf16le";
                    AddString(std::move(es));
                    accumulated.clear();
                    inRun = false;
                }
            } else {
                if (inRun) {
                    if (accumulated.size() >= kMinWideStringLength) {
                        ExtractedString es;
                        es.value = std::move(accumulated);
                        es.address = AddGuestOffset(base, runStartByte);
                        es.isWide = true;
                        es.encoding = "utf16le";
                        AddString(std::move(es));
                    }
                    accumulated.clear();
                    inRun = false;
                }
            }
        }
        // Handle string at end of buffer
        if (inRun && accumulated.size() >= kMinWideStringLength) {
            ExtractedString es;
            es.value = std::move(accumulated);
            es.address = AddGuestOffset(base, runStartByte);
            es.isWide = true;
            es.encoding = "utf16le";
            AddString(std::move(es));
        }
    }

    // -----------------------------------------------------------------------
    // Base64 detection and decode
    // -----------------------------------------------------------------------

    void DetectBase64Strings() {
        // Work on a snapshot of current string count to avoid infinite growth
        const size_t count = strings.size();
        for (size_t idx = 0; idx < count; ++idx) {
            if (strings.size() >= kMaxStrings) break;

            const auto& str = strings[idx];
            if (str.isDecoded) continue;
            if (str.value.size() < kMinBase64Length) continue;

            // Check if all characters are valid Base64
            bool allBase64 = true;
            uint32_t padCount = 0;
            for (size_t i = 0; i < str.value.size(); ++i) {
                const uint8_t c = static_cast<uint8_t>(str.value[i]);
                if (!IsBase64Char(c)) {
                    allBase64 = false;
                    break;
                }
                if (c == '=') ++padCount;
            }
            if (!allBase64) continue;
            if (padCount > 2) continue;
            if ((str.value.size() % 4) != 0) continue;

            // Validate padding is only at end
            if (padCount > 0) {
                bool padOk = true;
                const size_t len = str.value.size();
                if (padCount == 1) {
                    padOk = (str.value[len - 1] == '=') &&
                            (str.value[len - 2] != '=');
                } else if (padCount == 2) {
                    padOk = (str.value[len - 1] == '=') &&
                            (str.value[len - 2] == '=') &&
                            (len >= 3 && str.value[len - 3] != '=');
                }
                if (!padOk) continue;
            }

            // Check character distribution — reject if too uniform
            // (pure A's or pure padding is not real base64)
            uint32_t charClasses = 0;
            bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;
            for (const char c : str.value) {
                if (c >= 'A' && c <= 'Z') hasUpper = true;
                else if (c >= 'a' && c <= 'z') hasLower = true;
                else if (c >= '0' && c <= '9') hasDigit = true;
                else if (c == '+' || c == '/') hasSpecial = true;
            }
            if (hasUpper) ++charClasses;
            if (hasLower) ++charClasses;
            if (hasDigit) ++charClasses;
            if (hasSpecial) ++charClasses;
            if (charClasses < 2) continue;

            // Attempt decode
            auto decoded = Base64Decode(str.value);
            if (decoded.empty()) continue;

            // Check if decoded content has >60% printable characters
            const float ratio = PrintableRatio(decoded.data(), decoded.size());
            if (ratio > kPrintableRatioThreshold) {
                // Build printable string from decoded data
                std::string decodedStr;
                decodedStr.reserve(decoded.size());
                for (uint8_t b : decoded) {
                    if (IsStringByte(b)) {
                        decodedStr.push_back(static_cast<char>(b));
                    }
                }
                if (decodedStr.size() >= kMinAsciiStringLength) {
                    ExtractedString es;
                    es.value = std::move(decodedStr);
                    es.address = str.address;
                    es.isDecoded = true;
                    es.encoding = "base64";
                    es.category = StringCategory::Base64Data;
                    AddString(std::move(es));
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Single-byte XOR detection
    // -----------------------------------------------------------------------

    void DetectSingleByteXOR(const uint8_t* data, size_t size,
                             GuestAddress base) {
        if (!data || size < kMinXORBlockSize) return;

        // Scan in blocks to find high-entropy regions
        static constexpr uint32_t kBlockSize = 256;
        for (size_t offset = 0; offset + kBlockSize <= size;
             offset += kBlockSize) {
            if (strings.size() >= kMaxStrings) break;

            const uint8_t* block = data + offset;
            const size_t blockLen = std::min<size_t>(kBlockSize, size - offset);
            if (blockLen < kMinXORBlockSize) break;

            const float entropy = ComputeEntropy(block, blockLen);
            if (entropy < kHighEntropyThreshold) continue;

            // Try each single-byte XOR key (0x01-0xFF)
            const size_t sampleLen = std::min<size_t>(blockLen, kMaxXORSampleBytes);
            std::array<uint8_t, kMaxXORSampleBytes> decoded{};

            for (uint32_t key = 0x01; key <= 0xFF; ++key) {
                for (size_t i = 0; i < sampleLen; ++i) {
                    decoded[i] = block[i] ^ static_cast<uint8_t>(key);
                }

                const float ratio = PrintableRatio(decoded.data(), sampleLen);
                if (ratio > kPrintableRatioThreshold) {
                    // Extract the printable string
                    std::string result;
                    result.reserve(sampleLen);
                    for (size_t i = 0; i < sampleLen; ++i) {
                        if (IsStringByte(decoded[i])) {
                            result.push_back(static_cast<char>(decoded[i]));
                        } else if (!result.empty()) {
                            break; // Stop at first non-printable
                        }
                    }
                    if (result.size() >= kMinAsciiStringLength) {
                        ExtractedString es;
                        es.value = std::move(result);
                        es.address = AddGuestOffset(base, offset);
                        es.isDecoded = true;
                        es.encoding = "xor_0x" + ByteToHex(static_cast<uint8_t>(key));
                        AddString(std::move(es));
                    }
                    break; // Found a working key for this block
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Multi-byte XOR detection (2, 4, 8 byte keys)
    // -----------------------------------------------------------------------

    void DetectMultiByteXOR(const uint8_t* data, size_t size,
                            GuestAddress base) {
        if (!data || size < kMinXORBlockSize) return;

        static constexpr uint32_t kBlockSize = 256;
        static constexpr uint32_t kKeyLengths[] = { 2, 4, 8 };

        for (size_t offset = 0; offset + kBlockSize <= size;
             offset += kBlockSize) {
            if (strings.size() >= kMaxStrings) break;

            const uint8_t* block = data + offset;
            const size_t blockLen = std::min<size_t>(kBlockSize, size - offset);
            if (blockLen < kMinXORBlockSize) break;

            const float entropy = ComputeEntropy(block, blockLen);
            if (entropy < kHighEntropyThreshold) continue;

            const size_t sampleLen = std::min<size_t>(blockLen, kMaxXORSampleBytes);

            for (const uint32_t keyLen : kKeyLengths) {
                if (sampleLen < keyLen * 2) continue;

                // Compute average IC across positions to validate key length
                float avgIC = 0.0f;
                for (uint32_t pos = 0; pos < keyLen; ++pos) {
                    avgIC += IndexOfCoincidence(block, sampleLen, keyLen, pos);
                }
                avgIC /= static_cast<float>(keyLen);

                // English-like text has IC ~0.065, random ~0.0039
                // Threshold at ~0.01 to catch XOR-encrypted text
                if (avgIC < 0.01f) continue;

                // For each position modulo key_length, find most common byte
                // (likely XOR of space 0x20 or null 0x00)
                std::array<uint8_t, 8> candidateKey{};
                for (uint32_t pos = 0; pos < keyLen; ++pos) {
                    uint32_t freq[256] = {};
                    for (size_t i = pos; i < sampleLen; i += keyLen) {
                        freq[block[i]]++;
                    }
                    // Find most common byte
                    uint8_t mostCommon = 0;
                    uint32_t maxFreq = 0;
                    for (uint32_t b = 0; b < 256; ++b) {
                        if (freq[b] > maxFreq) {
                            maxFreq = freq[b];
                            mostCommon = static_cast<uint8_t>(b);
                        }
                    }

                    // Try XOR with space (0x20) first, then null (0x00)
                    candidateKey[pos] = mostCommon ^ 0x20;
                }

                // Try decoding with candidate key (space-based)
                std::array<uint8_t, kMaxXORSampleBytes> decoded{};
                for (size_t i = 0; i < sampleLen; ++i) {
                    decoded[i] = block[i] ^ candidateKey[i % keyLen];
                }
                float ratio = PrintableRatio(decoded.data(), sampleLen);

                // If space-based key didn't work well, try null-based
                if (ratio <= kPrintableRatioThreshold) {
                    for (uint32_t pos = 0; pos < keyLen; ++pos) {
                        uint32_t freq[256] = {};
                        for (size_t i = pos; i < sampleLen; i += keyLen) {
                            freq[block[i]]++;
                        }
                        uint8_t mostCommon = 0;
                        uint32_t maxFreq2 = 0;
                        for (uint32_t b = 0; b < 256; ++b) {
                            if (freq[b] > maxFreq2) {
                                maxFreq2 = freq[b];
                                mostCommon = static_cast<uint8_t>(b);
                            }
                        }
                        candidateKey[pos] = mostCommon ^ 0x00;
                    }

                    for (size_t i = 0; i < sampleLen; ++i) {
                        decoded[i] = block[i] ^ candidateKey[i % keyLen];
                    }
                    ratio = PrintableRatio(decoded.data(), sampleLen);
                }

                if (ratio > kPrintableRatioThreshold) {
                    std::string result;
                    result.reserve(sampleLen);
                    for (size_t i = 0; i < sampleLen; ++i) {
                        if (IsStringByte(decoded[i])) {
                            result.push_back(static_cast<char>(decoded[i]));
                        } else if (!result.empty()) {
                            break;
                        }
                    }
                    if (result.size() >= kMinAsciiStringLength) {
                        // Build encoding string like "xor_multi_4142"
                        std::string enc = "xor_multi_";
                        for (uint32_t k = 0; k < keyLen; ++k) {
                            enc += ByteToHex(candidateKey[k]);
                        }

                        ExtractedString es;
                        es.value = std::move(result);
                        es.address = AddGuestOffset(base, offset);
                        es.isDecoded = true;
                        es.encoding = std::move(enc);
                        AddString(std::move(es));
                    }
                    break; // Found a working key for this block
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // ROT13 / Caesar shift detection
    // -----------------------------------------------------------------------

    void DetectCaesarStrings() {
        const size_t count = strings.size();
        for (size_t idx = 0; idx < count; ++idx) {
            if (strings.size() >= kMaxStrings) break;

            const auto& str = strings[idx];
            if (str.isDecoded) continue;
            if (str.value.size() < kMinAsciiStringLength) continue;

            // Only try on strings that are purely ASCII alpha-ish
            bool hasAlpha = false;
            for (const char c : str.value) {
                if (IsAlpha(c)) { hasAlpha = true; break; }
            }
            if (!hasAlpha) continue;

            for (uint32_t shift = 1; shift <= 25; ++shift) {
                // Apply Caesar shift
                std::string shifted;
                shifted.reserve(str.value.size());
                for (const char c : str.value) {
                    if (IsAlphaUpper(c)) {
                        shifted.push_back(static_cast<char>(
                            'A' + ((c - 'A' + static_cast<int>(shift)) % 26)));
                    } else if (IsAlphaLower(c)) {
                        shifted.push_back(static_cast<char>(
                            'a' + ((c - 'a' + static_cast<int>(shift)) % 26)));
                    } else {
                        shifted.push_back(c);
                    }
                }

                // Check if shifted version contains >= 2 known suspicious keywords
                uint32_t matchCount = 0;
                for (const char* keyword : kRotKeywords) {
                    if (ContainsCaseInsensitive(shifted, keyword)) {
                        ++matchCount;
                        if (matchCount >= 2) break;
                    }
                }

                if (matchCount >= 2) {
                    ExtractedString es;
                    es.value = std::move(shifted);
                    es.address = str.address;
                    es.isDecoded = true;
                    es.encoding = "rot_" + std::to_string(shift);
                    AddString(std::move(es));
                    break; // Don't try more shifts for this string
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Stack string extraction from tracked writes
    // -----------------------------------------------------------------------

    void ExtractStackString(GuestAddress regionBase) {
        auto it = stackRegions.find(regionBase);
        if (it == stackRegions.end()) return;

        const auto& region = it->second;
        if (region.bytes.empty()) return;

        // Find the range of offsets written
        uint32_t minOff = UINT32_MAX;
        uint32_t maxOff = 0;
        for (const auto& [off, _] : region.bytes) {
            if (off < minOff) minOff = off;
            if (off > maxOff) maxOff = off;
        }
        if (minOff > maxOff) return;

        const uint32_t spanLen = maxOff - minOff + 1;
        if (spanLen > kMaxStackBytesPerRegion || spanLen < kMinAsciiStringLength) return;

        // Reconstruct the string from tracked bytes
        std::string result;
        result.reserve(spanLen);
        for (uint32_t off = minOff; off <= maxOff; ++off) {
            auto byteIt = region.bytes.find(off);
            if (byteIt == region.bytes.end()) break;
            const uint8_t b = byteIt->second;
            if (b == 0x00) break; // Null terminator
            if (!IsStringByte(b)) break;
            result.push_back(static_cast<char>(b));
        }

        if (result.size() >= kMinAsciiStringLength) {
            ExtractedString es;
            es.value = std::move(result);
            es.address = AddGuestOffset(regionBase, minOff);
            es.isDecoded = false;
            es.encoding = "stack";
            AddString(std::move(es));
        }
    }

    // -----------------------------------------------------------------------
    // String categorization
    // -----------------------------------------------------------------------

    void CategorizeString(ExtractedString& es) const {
        const std::string& val = es.value;
        if (val.empty()) return;

        // Already categorized as Base64Data from decoder
        if (es.category == StringCategory::Base64Data) return;

        // -- URL --
        if (StartsWithCaseInsensitive(val, "http://") ||
            StartsWithCaseInsensitive(val, "https://") ||
            StartsWithCaseInsensitive(val, "ftp://")) {
            es.category = StringCategory::URL;
            return;
        }

        // -- Registry Key --
        if (StartsWithCaseInsensitive(val, "HKEY_") ||
            StartsWithCaseInsensitive(val, "HKLM\\") ||
            StartsWithCaseInsensitive(val, "HKCU\\") ||
            StartsWithCaseInsensitive(val, "SOFTWARE\\")) {
            es.category = StringCategory::RegistryKey;
            return;
        }

        // -- Suspicious Command --
        if (ContainsCaseInsensitive(val, "-enc") ||
            ContainsCaseInsensitive(val, "IEX") ||
            ContainsCaseInsensitive(val, "DownloadString") ||
            ContainsCaseInsensitive(val, "Invoke-") ||
            ContainsCaseInsensitive(val, "-nop -w hidden") ||
            ContainsCaseInsensitive(val, "bypass") ||
            ContainsCaseInsensitive(val, "-ExecutionPolicy")) {
            es.category = StringCategory::SuspiciousCommand;
            return;
        }

        // -- Command Line --
        if (StartsWithCaseInsensitive(val, "cmd") ||
            StartsWithCaseInsensitive(val, "powershell") ||
            StartsWithCaseInsensitive(val, "wmic") ||
            StartsWithCaseInsensitive(val, "schtasks") ||
            StartsWithCaseInsensitive(val, "net ") ||
            StartsWithCaseInsensitive(val, "reg ") ||
            StartsWithCaseInsensitive(val, "sc ")) {
            es.category = StringCategory::CommandLine;
            return;
        }

        // -- Mutex Name --
        if (StartsWithCaseInsensitive(val, "Global\\") ||
            StartsWithCaseInsensitive(val, "Local\\")) {
            es.category = StringCategory::MutexName;
            return;
        }

        // -- User-Agent --
        if (ContainsCaseInsensitive(val, "Mozilla/") ||
            ContainsCaseInsensitive(val, "Chrome/") ||
            ContainsCaseInsensitive(val, "Firefox/") ||
            ContainsCaseInsensitive(val, "Safari/") ||
            ContainsCaseInsensitive(val, "MSIE")) {
            es.category = StringCategory::UserAgent;
            return;
        }

        // -- IP Address --
        if (IsValidIPAddress(val)) {
            es.category = StringCategory::IPAddress;
            return;
        }

        // -- Email Address --
        {
            // Contains "@" and "." with characters before/after @
            size_t atPos = std::string::npos;
            for (size_t i = 1; i < val.size(); ++i) {
                if (val[i] == '@') { atPos = i; break; }
            }
            if (atPos != std::string::npos && atPos < val.size() - 1) {
                // Check for dot after @
                bool hasDot = false;
                for (size_t i = atPos + 2; i < val.size(); ++i) {
                    if (val[i] == '.') { hasDot = true; break; }
                }
                if (hasDot) {
                    es.category = StringCategory::EmailAddress;
                    return;
                }
            }
        }

        // -- DLL Name --
        if (EndsWithCaseInsensitive(val, ".dll")) {
            es.category = StringCategory::DLLName;
            return;
        }

        // -- API Name --
        for (const char* api : kKnownAPIs) {
            if (CaseInsensitiveEqual(val, api)) {
                es.category = StringCategory::APIName;
                return;
            }
        }

        // -- File Path --
        {
            bool isPath = false;
            // Drive letter: e.g. "C:\..."
            if (val.size() >= 3 && IsAlpha(val[0]) && val[1] == ':' &&
                (val[2] == '\\' || val[2] == '/')) {
                isPath = true;
            }
            // Env var paths: "%APPDATA%\..."
            if (!isPath && val.size() >= 2 && val[0] == '%') {
                isPath = true;
            }
            // UNC paths
            if (!isPath && val.size() >= 2 && val[0] == '\\' && val[1] == '\\') {
                isPath = true;
            }
            // Contains backslash or forward slash with known folder patterns
            if (!isPath) {
                bool hasSlash = false;
                for (const char c : val) {
                    if (c == '\\' || c == '/') { hasSlash = true; break; }
                }
                if (hasSlash) {
                    if (ContainsCaseInsensitive(val, "windows") ||
                        ContainsCaseInsensitive(val, "system32") ||
                        ContainsCaseInsensitive(val, "program files") ||
                        ContainsCaseInsensitive(val, "appdata") ||
                        ContainsCaseInsensitive(val, "temp") ||
                        ContainsCaseInsensitive(val, "users") ||
                        ContainsCaseInsensitive(val, "documents")) {
                        isPath = true;
                    }
                }
            }
            if (isPath) {
                es.category = StringCategory::FilePath;
                return;
            }
        }

        // -- Credential --
        if (LooksLikeCredential(val)) {
            es.category = StringCategory::Credential;
            return;
        }

        // -- Domain --
        if (IsValidDomain(val)) {
            es.category = StringCategory::Domain;
            return;
        }

        // -- Crypto Key (heuristic: long hex string or known crypto patterns) --
        {
            if (val.size() >= 32) {
                bool allHex = true;
                for (const char c : val) {
                    const char lc = ToLower(c);
                    if (!((lc >= '0' && lc <= '9') || (lc >= 'a' && lc <= 'f'))) {
                        allHex = false;
                        break;
                    }
                }
                if (allHex) {
                    es.category = StringCategory::CryptoKey;
                    return;
                }
            }
        }

        // -- Benign heuristic: common benign patterns --
        if (ContainsCaseInsensitive(val, "copyright") ||
            ContainsCaseInsensitive(val, "version") ||
            ContainsCaseInsensitive(val, "microsoft") ||
            ContainsCaseInsensitive(val, "license") ||
            ContainsCaseInsensitive(val, "all rights reserved")) {
            es.category = StringCategory::BenignString;
            return;
        }

        // Default: Unknown
        es.category = StringCategory::Unknown;
    }

    // -----------------------------------------------------------------------
    // Suspiciousness scoring
    // -----------------------------------------------------------------------

    void ScoreString(ExtractedString& es) const {
        switch (es.category) {
            case StringCategory::SuspiciousCommand:
                es.suspiciousness = 0.85f;
                break;

            case StringCategory::URL:
                if (URLContainsRawIP(es.value)) {
                    es.suspiciousness = 0.75f;
                } else if (URLHasUnusualPort(es.value)) {
                    es.suspiciousness = 0.70f;
                } else {
                    es.suspiciousness = 0.35f;
                }
                break;

            case StringCategory::Base64Data:
                // Check if decoded content is suspicious
                if (es.isDecoded) {
                    es.suspiciousness = 0.80f;
                } else {
                    es.suspiciousness = 0.40f;
                }
                break;

            case StringCategory::RegistryKey:
                if (IsRegistryRunKey(es.value)) {
                    es.suspiciousness = 0.65f;
                } else {
                    es.suspiciousness = 0.30f;
                }
                break;

            case StringCategory::Credential:
                es.suspiciousness = 0.70f;
                break;

            case StringCategory::CommandLine:
                es.suspiciousness = 0.50f;
                break;

            case StringCategory::IPAddress:
                es.suspiciousness = 0.40f;
                break;

            case StringCategory::Domain:
                es.suspiciousness = 0.35f;
                break;

            case StringCategory::UserAgent:
                es.suspiciousness = 0.30f;
                break;

            case StringCategory::MutexName:
                es.suspiciousness = 0.35f;
                break;

            case StringCategory::EmailAddress:
                es.suspiciousness = 0.30f;
                break;

            case StringCategory::CryptoKey:
                es.suspiciousness = 0.50f;
                break;

            case StringCategory::APIName:
                es.suspiciousness = 0.20f;
                break;

            case StringCategory::DLLName:
                es.suspiciousness = 0.15f;
                break;

            case StringCategory::FilePath:
                es.suspiciousness = 0.10f;
                break;

            case StringCategory::BenignString:
                es.suspiciousness = 0.05f;
                break;

            case StringCategory::Unknown:
                es.suspiciousness = 0.20f;
                break;
        }

        // Boost score for XOR-decoded content regardless of category
        if (es.isDecoded && es.encoding.size() >= 3 &&
            es.encoding[0] == 'x' && es.encoding[1] == 'o' && es.encoding[2] == 'r') {
            es.suspiciousness = std::max(es.suspiciousness, 0.75f);
        }

        // Boost for known C2 keywords
        for (const char* keyword : kC2Keywords) {
            if (ContainsCaseInsensitive(es.value, keyword)) {
                es.suspiciousness = std::max(es.suspiciousness, 0.80f);
                break;
            }
        }

        // Clamp to [0.0, 1.0]
        if (es.suspiciousness > 1.0f) es.suspiciousness = 1.0f;
        if (es.suspiciousness < 0.0f) es.suspiciousness = 0.0f;
    }

    // -----------------------------------------------------------------------
    // Full categorization and scoring pass
    // -----------------------------------------------------------------------

    void CategorizeAndScoreAll() {
        for (auto& es : strings) {
            CategorizeString(es);
            ScoreString(es);
        }
    }

    // -----------------------------------------------------------------------
    // Full region scan pipeline
    // -----------------------------------------------------------------------

    void ScanRegionImpl(const uint8_t* data, size_t size,
                        GuestAddress base) {
        if (!data || size == 0) return;
        if (!iocExtractionEnabled) return;

        // Phase 1: Extract raw ASCII strings
        ExtractAsciiStrings(data, size, base);

        // Phase 2: Extract UTF-16LE strings
        ExtractWideStrings(data, size, base);

        // Phase 3: Detect single-byte XOR encoded content
        DetectSingleByteXOR(data, size, base);

        // Phase 4: Detect multi-byte XOR encoded content
        DetectMultiByteXOR(data, size, base);
    }

    // -----------------------------------------------------------------------
    // Post-extraction analysis (Base64, ROT, categorize, score)
    // -----------------------------------------------------------------------

    void RunPostAnalysis() {
        DetectBase64Strings();
        DetectCaesarStrings();
        CategorizeAndScoreAll();
    }
};

// ============================================================================
// StringExtractor — Public API (delegates to Impl)
// ============================================================================

StringExtractor::StringExtractor(const EmulationConfig& config) noexcept {
    try {
        m_impl = std::make_unique<Impl>(config);
    } catch (const std::bad_alloc&) {
        m_impl.reset();
    } catch (const std::exception&) {
        // Allocation failure — m_impl remains null
        m_impl.reset();
    }
}

StringExtractor::~StringExtractor() noexcept = default;

StringExtractor::StringExtractor(StringExtractor&&) noexcept = default;
StringExtractor& StringExtractor::operator=(StringExtractor&&) noexcept = default;

// ---- ScanRegion -----------------------------------------------------------

void StringExtractor::ScanRegion(const uint8_t* data, size_t size,
                                 GuestAddress base) noexcept {
    if (!m_impl) return;
    if (!data || size == 0) return;

    // Cap scan size to prevent resource exhaustion
    static constexpr size_t kMaxScanSize = 64ULL * 1024 * 1024; // 64 MB
    if (size > kMaxScanSize) size = kMaxScanSize;

    try {
        m_impl->ScanRegionImpl(data, size, base);
        m_impl->RunPostAnalysis();
    } catch (const std::exception&) {
        return;
    }
}

// ---- ScanAll --------------------------------------------------------------

void StringExtractor::ScanAll(const VirtualMemory& memory) noexcept {
    if (!m_impl) return;
    if (!m_impl->iocExtractionEnabled) return;

    // Iterate through all possible pages in the guest address space.
    // Use GetHostReadPtr to check if a page is mapped and readable.
    // Pages are 4096 bytes, guest space is capped at kMaxScanAddress.

    try {
        uint32_t pagesScanned = 0;
        for (GuestAddress addr = 0; addr < kMaxScanAddress; addr += kSEPageSize) {
            if (pagesScanned >= kMaxPagesPerScan) break;
            if (m_impl->strings.size() >= kMaxStrings) break;

            const uint8_t* hostPtr = memory.GetHostReadPtr(addr);
            if (!hostPtr) continue;

            // Scan this page for strings (ASCII, wide, XOR)
            m_impl->ScanRegionImpl(hostPtr, kSEPageSize, addr);
            ++pagesScanned;
        }

        // Run post-extraction analysis once after scanning all pages
        m_impl->RunPostAnalysis();
    } catch (const std::exception&) {
        return;
    }
}

// ---- OnStackWrite ---------------------------------------------------------

void StringExtractor::OnStackWrite(GuestAddress rsp, uint8_t byte,
                                   uint64_t instrCount) noexcept {
    if (!m_impl) return;
    if (!m_impl->iocExtractionEnabled) return;
    try {

    // Page-align the rsp to get the stack region base
    const GuestAddress regionBase = PageBase(rsp);
    const uint32_t offset = static_cast<uint32_t>(rsp - regionBase);

    auto it = m_impl->stackRegions.find(regionBase);
    if (it == m_impl->stackRegions.end()) {
        // New stack region — check cap
        if (m_impl->stackRegions.size() >= kMaxStackRegions) return;

        Impl::StackRegion region;
        region.lastInstrCount = instrCount;
        region.bytes[offset] = byte;
        m_impl->stackRegions.emplace(regionBase, std::move(region));
    } else {
        auto& region = it->second;

        // Cap bytes tracked per region
        if (region.bytes.size() >= kMaxStackBytesPerRegion) return;

        region.bytes[offset] = byte;
        region.lastInstrCount = instrCount;

        // If a null byte is written, attempt to extract the accumulated string
        if (byte == 0x00) {
            m_impl->ExtractStackString(regionBase);
        }
    }
    } catch (const std::exception&) {
        return;
    }
}

// ---- GetStrings -----------------------------------------------------------

const std::vector<ExtractedString>& StringExtractor::GetStrings() const noexcept {
    static const std::vector<ExtractedString> kEmpty;
    if (!m_impl) return kEmpty;
    try {
        thread_local std::vector<ExtractedString> snapshot;
        snapshot = m_impl->strings;
        return snapshot;
    } catch (const std::exception&) {
        return kEmpty;
    }
}

// ---- GetByCategory --------------------------------------------------------

std::vector<const ExtractedString*> StringExtractor::GetByCategory(
    StringCategory cat) const noexcept {
    std::vector<const ExtractedString*> result;
    if (!m_impl) return result;

    try {
        thread_local std::vector<ExtractedString> snapshot;
        snapshot.clear();
        for (const auto& es : m_impl->strings) {
            if (es.category == cat) {
                snapshot.push_back(es);
            }
        }
        result.reserve(snapshot.size());
        for (const auto& es : snapshot) {
            result.push_back(&es);
        }
    } catch (const std::exception&) {
        return {};
    }
    return result;
}

// ---- GetStringCount -------------------------------------------------------

uint32_t StringExtractor::GetStringCount() const noexcept {
    if (!m_impl) return 0;
    return static_cast<uint32_t>(m_impl->strings.size());
}

// ---- GetSuspiciousStrings -------------------------------------------------

std::vector<const ExtractedString*> StringExtractor::GetSuspiciousStrings(
    float minScore) const noexcept {
    std::vector<const ExtractedString*> result;
    if (!m_impl) return result;
    if (!std::isfinite(minScore)) {
        minScore = 0.5f;
    }

    try {
        thread_local std::vector<ExtractedString> snapshot;
        snapshot.clear();
        for (const auto& es : m_impl->strings) {
            if (es.suspiciousness >= minScore) {
                snapshot.push_back(es);
            }
        }
        result.reserve(snapshot.size());
        for (const auto& es : snapshot) {
            result.push_back(&es);
        }
    } catch (const std::exception&) {
        return {};
    }
    return result;
}

// ---- Reset ----------------------------------------------------------------

void StringExtractor::Reset() noexcept {
    if (!m_impl) return;
    try {
        m_impl->strings.clear();
        m_impl->dedup.clear();
        m_impl->stackRegions.clear();
    } catch (const std::exception&) {
        return;
    }
}

} // namespace Phantom

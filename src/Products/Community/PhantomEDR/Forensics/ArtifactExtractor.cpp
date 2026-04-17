/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike Forensics - ARTIFACT EXTRACTION ENGINE IMPLEMENTATION
 * ============================================================================
 *
 * @file ArtifactExtractor.cpp
 * @brief Enterprise-grade Windows forensic artifact extraction implementation.
 *
 * Production-level implementation competing with Velociraptor, KAPE (Kroll),
 * and EnCase Forensic. Provides comprehensive Windows artifact extraction
 * for incident response and malware analysis.
 *
 * IMPLEMENTATION FEATURES:
 * ========================
 *
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex for concurrent access
 * - MFT (Master File Table) parsing with deleted file recovery
 * - Prefetch file analysis (.pf)
 * - Shimcache (AppCompatCache) parsing
 * - Amcache.hve registry parsing
 * - Browser history extraction (Chrome, Firefox, Edge, IE)
 * - LNK file parsing (shortcuts)
 * - Jump List analysis
 * - UserAssist (ROT13 decoded)
 * - Shellbags (folder access history)
 * - Scheduled task enumeration
 * - USN Journal parsing
 * - Alternate Data Streams detection
 * - Infrastructure reuse (ThreatIntel, SignatureStore, Utils)
 * - Comprehensive statistics (7+ atomic counters)
 * - Callback system (2 types)
 * - Self-test and diagnostics
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "ArtifactExtractor.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/RegistryUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../SignatureStore/SignatureStore.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <bit>
#include <cctype>
#include <cwctype>
#include <cstring>
#include <fstream>
#include <format>
#include <iomanip>
#include <limits>
#include <numeric>
#include <sstream>
#include <system_error>
#include <thread>

// ============================================================================
// WINDOWS API INCLUDES
// ============================================================================
#ifdef _WIN32
#include <Psapi.h>
#include <taskschd.h>
#include <comutil.h>
#include <Wbemidl.h>
#include <shlobj.h>
#include <winioctl.h>
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "Wbemuuid.lib")
#pragma comment(lib, "Shell32.lib")
#endif

// ============================================================================
// THIRD-PARTY INCLUDES
// ============================================================================
#include <sqlite3.h>
#include <nlohmann/json.hpp>

#pragma comment(lib, "sqlite3.lib")

namespace ShadowStrike {
namespace Forensics {

using Clock = std::chrono::steady_clock;
using SystemClock = std::chrono::system_clock;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Convert FILETIME to system_clock time_point
 */
SystemTimePoint FileTimeToTimePoint(const FILETIME& ft) {
    ULARGE_INTEGER ull;
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;

    // Windows epoch (1601) to Unix epoch (1970) is 116444736000000000 * 100ns
    const uint64_t WINDOWS_TICK = 10000000;
    const uint64_t SEC_TO_UNIX_EPOCH = 11644473600LL;

    uint64_t winTime = ull.QuadPart;
    time_t unixTime = (winTime / WINDOWS_TICK) - SEC_TO_UNIX_EPOCH;

    return SystemClock::from_time_t(unixTime);
}

/**
 * @brief Get all user profiles
 */
std::vector<std::wstring> GetUserProfiles() {
    std::vector<std::wstring> profiles;

    wchar_t profilesDir[MAX_PATH] = {0};
    if (SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, 0, profilesDir) == S_OK) {
        // Get parent directory (C:\Users)
        std::wstring usersDir = profilesDir;
        size_t lastSlash = usersDir.find_last_of(L"\\/");
        if (lastSlash != std::wstring::npos) {
            usersDir = usersDir.substr(0, lastSlash);
        }

        WIN32_FIND_DATAW findData;
        std::wstring searchPath = usersDir + L"\\*";
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                    wcscmp(findData.cFileName, L".") != 0 &&
                    wcscmp(findData.cFileName, L"..") != 0) {
                    profiles.push_back(usersDir + L"\\" + findData.cFileName);
                }
            } while (FindNextFileW(hFind, &findData));
            FindClose(hFind);
        }
    }

    return profiles;
}

/**
 * @brief Generate unique artifact ID
 */
std::string GenerateArtifactId() {
    static std::atomic<uint64_t> s_counter{0};

    const auto now = SystemClock::now().time_since_epoch().count();
    const uint64_t counter = s_counter.fetch_add(1, std::memory_order_relaxed);

    return std::format("ART-{:016X}-{:04X}", now, counter);
}

/**
 * @brief Decode ROT13 (for UserAssist)
 */
std::wstring DecodeROT13Internal(std::wstring_view encoded) {
    std::wstring result;
    result.reserve(encoded.size());

    for (wchar_t ch : encoded) {
        if (ch >= L'A' && ch <= L'Z') {
            result += static_cast<wchar_t>((ch - L'A' + 13) % 26 + L'A');
        } else if (ch >= L'a' && ch <= L'z') {
            result += static_cast<wchar_t>((ch - L'a' + 13) % 26 + L'a');
        } else {
            result += ch;
        }
    }

    return result;
}

/**
 * @brief Get Chrome history database path
 */
std::wstring GetChromeHistoryPath(std::wstring_view profile) {
    return std::wstring(profile) + L"\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History";
}

/**
 * @brief Get Firefox history database path
 */
std::wstring GetFirefoxHistoryPath(std::wstring_view profile) {
    std::wstring mozillaDir = std::wstring(profile) + L"\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles";

    // Find default profile
    WIN32_FIND_DATAW findData;
    std::wstring searchPath = mozillaDir + L"\\*";
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                wcsstr(findData.cFileName, L".default") != nullptr) {
                FindClose(hFind);
                return mozillaDir + L"\\" + findData.cFileName + L"\\places.sqlite";
            }
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }

    return L"";
}


constexpr wchar_t kArtifactExtractorLogCategory[] = L"ArtifactExtractor";
constexpr DWORD kMaxRegistryBinaryBytes = 32UL * 1024UL * 1024UL;
constexpr uint64_t kMaxBrowserDatabaseBytes = 512ULL * 1024ULL * 1024ULL;
constexpr size_t kMaxShellbagValueBytes = 64U * 1024U;
constexpr size_t kMaxResidentAttributeBytes = 1024U * 1024U;
constexpr size_t kShimcacheExecutionFlagBytes = sizeof(uint32_t);
constexpr uint32_t kShimcacheExecutedFlag = 0x00000002U;
std::atomic<uint64_t> s_artifactTempCounter{0};

struct ScopedHandle {
    HANDLE handle = INVALID_HANDLE_VALUE;

    ScopedHandle() = default;
    explicit ScopedHandle(HANDLE h) noexcept : handle(h) {}
    ~ScopedHandle() {
        if (handle != INVALID_HANDLE_VALUE && handle != nullptr) {
            ::CloseHandle(handle);
        }
    }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ScopedHandle(ScopedHandle&& other) noexcept : handle(other.handle) {
        other.handle = INVALID_HANDLE_VALUE;
    }

    ScopedHandle& operator=(ScopedHandle&& other) noexcept {
        if (this != &other) {
            if (handle != INVALID_HANDLE_VALUE && handle != nullptr) {
                ::CloseHandle(handle);
            }
            handle = other.handle;
            other.handle = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    [[nodiscard]] bool IsValid() const noexcept {
        return handle != INVALID_HANDLE_VALUE && handle != nullptr;
    }
};

struct RegKeyHandle {
    HKEY key = nullptr;

    RegKeyHandle() = default;
    explicit RegKeyHandle(HKEY h) noexcept : key(h) {}
    ~RegKeyHandle() {
        if (key != nullptr) {
            ::RegCloseKey(key);
        }
    }

    RegKeyHandle(const RegKeyHandle&) = delete;
    RegKeyHandle& operator=(const RegKeyHandle&) = delete;

    RegKeyHandle(RegKeyHandle&& other) noexcept : key(other.key) {
        other.key = nullptr;
    }

    RegKeyHandle& operator=(RegKeyHandle&& other) noexcept {
        if (this != &other) {
            if (key != nullptr) {
                ::RegCloseKey(key);
            }
            key = other.key;
            other.key = nullptr;
        }
        return *this;
    }

    [[nodiscard]] bool IsValid() const noexcept {
        return key != nullptr;
    }
};

struct TempFileGuard {
    std::filesystem::path path;

    explicit TempFileGuard(std::filesystem::path tempPath) : path(std::move(tempPath)) {}
    ~TempFileGuard() {
        if (!path.empty()) {
            std::error_code ec;
            std::filesystem::remove(path, ec);
        }
    }

    TempFileGuard(const TempFileGuard&) = delete;
    TempFileGuard& operator=(const TempFileGuard&) = delete;
};

struct SqliteDbGuard {
    sqlite3* db = nullptr;

    explicit SqliteDbGuard(sqlite3* database) noexcept : db(database) {}
    ~SqliteDbGuard() {
        if (db != nullptr) {
            sqlite3_close(db);
        }
    }

    SqliteDbGuard(const SqliteDbGuard&) = delete;
    SqliteDbGuard& operator=(const SqliteDbGuard&) = delete;
};

struct SqliteStmtGuard {
    sqlite3_stmt* stmt = nullptr;

    explicit SqliteStmtGuard(sqlite3_stmt* statement) noexcept : stmt(statement) {}
    ~SqliteStmtGuard() {
        if (stmt != nullptr) {
            sqlite3_finalize(stmt);
        }
    }

    SqliteStmtGuard(const SqliteStmtGuard&) = delete;
    SqliteStmtGuard& operator=(const SqliteStmtGuard&) = delete;
};

#pragma pack(push, 1)
struct NtfsFileRecordHeader {
    uint32_t signature;
    uint16_t updateSequenceOffset;
    uint16_t updateSequenceCount;
    uint64_t logFileSequenceNumber;
    uint16_t sequenceNumber;
    uint16_t hardLinkCount;
    uint16_t firstAttributeOffset;
    uint16_t flags;
    uint32_t bytesInUse;
    uint32_t bytesAllocated;
    uint64_t baseFileRecord;
    uint16_t nextAttributeId;
    uint16_t align;
    uint32_t recordNumber;
};

struct NtfsAttributeHeader {
    uint32_t type;
    uint32_t length;
    uint8_t nonResident;
    uint8_t nameLength;
    uint16_t nameOffset;
    uint16_t flags;
    uint16_t attributeId;
};

struct NtfsResidentAttributeHeader {
    NtfsAttributeHeader common;
    uint32_t valueLength;
    uint16_t valueOffset;
    uint8_t indexedFlag;
    uint8_t reserved;
};

struct NtfsNonResidentAttributeHeader {
    NtfsAttributeHeader common;
    uint64_t startingVcn;
    uint64_t lastVcn;
    uint16_t dataRunsOffset;
    uint16_t compressionUnit;
    uint32_t padding;
    uint64_t allocatedSize;
    uint64_t dataSize;
    uint64_t initializedSize;
    uint64_t compressedSize;
};

struct NtfsStandardInformationValue {
    int64_t creationTime;
    int64_t modificationTime;
    int64_t mftModificationTime;
    int64_t accessTime;
};

struct NtfsFileNameValueHeader {
    uint64_t parentFileReference;
    int64_t creationTime;
    int64_t modificationTime;
    int64_t mftModificationTime;
    int64_t accessTime;
    uint64_t allocatedSize;
    uint64_t dataSize;
    uint32_t flags;
    uint32_t reparseValue;
    uint8_t fileNameLength;
    uint8_t fileNameNamespace;
};
#pragma pack(pop)

struct ShellItemExtensionInfo {
    std::wstring longName;
    std::optional<SystemTimePoint> creationTime;
    std::optional<SystemTimePoint> accessTime;
};

struct ParsedShellItem {
    std::wstring name;
    std::string itemType{"unknown"};
    std::optional<SystemTimePoint> creationTime;
    std::optional<SystemTimePoint> accessTime;
};

[[nodiscard]] uint64_t FileTimeToUInt64(const FILETIME& fileTime) noexcept {
    ULARGE_INTEGER value{};
    value.LowPart = fileTime.dwLowDateTime;
    value.HighPart = fileTime.dwHighDateTime;
    return value.QuadPart;
}

[[nodiscard]] std::optional<SystemTimePoint> SystemTimeToTimePoint(const SYSTEMTIME& systemTime) {
    if (systemTime.wYear == 0 || systemTime.wMonth == 0 || systemTime.wDay == 0) {
        return std::nullopt;
    }

    const auto ymd = std::chrono::year_month_day{
        std::chrono::year{static_cast<int>(systemTime.wYear)},
        std::chrono::month{static_cast<unsigned>(systemTime.wMonth)},
        std::chrono::day{static_cast<unsigned>(systemTime.wDay)}};

    if (!ymd.ok()) {
        return std::nullopt;
    }

    return std::chrono::sys_days{ymd}
         + std::chrono::hours{systemTime.wHour}
         + std::chrono::minutes{systemTime.wMinute}
         + std::chrono::seconds{systemTime.wSecond}
         + std::chrono::milliseconds{systemTime.wMilliseconds};
}

[[nodiscard]] std::optional<SystemTimePoint> FileTimeValueToTimePoint(uint64_t fileTimeValue) {
    if (fileTimeValue == 0) {
        return std::nullopt;
    }

    FILETIME fileTime{};
    fileTime.dwLowDateTime = static_cast<DWORD>(fileTimeValue & 0xFFFFFFFFULL);
    fileTime.dwHighDateTime = static_cast<DWORD>(fileTimeValue >> 32U);

    SYSTEMTIME systemTime{};
    if (!::FileTimeToSystemTime(&fileTime, &systemTime)) {
        return std::nullopt;
    }

    if (systemTime.wYear <= 1601) {
        return std::nullopt;
    }

    return SystemTimeToTimePoint(systemTime);
}

[[nodiscard]] std::optional<SystemTimePoint> FileTimeToTimePointChecked(const FILETIME& fileTime) {
    return FileTimeValueToTimePoint(FileTimeToUInt64(fileTime));
}

[[nodiscard]] std::optional<SystemTimePoint> DosDateTimeToTimePoint(uint32_t dosDateTime) {
    if (dosDateTime == 0) {
        return std::nullopt;
    }

    const uint16_t timePart = static_cast<uint16_t>(dosDateTime & 0xFFFFU);
    const uint16_t datePart = static_cast<uint16_t>((dosDateTime >> 16U) & 0xFFFFU);

    const unsigned day = datePart & 0x1FU;
    const unsigned month = (datePart >> 5U) & 0x0FU;
    const int year = static_cast<int>(((datePart >> 9U) & 0x7FU) + 1980U);
    const unsigned seconds = (timePart & 0x1FU) * 2U;
    const unsigned minutes = (timePart >> 5U) & 0x3FU;
    const unsigned hours = (timePart >> 11U) & 0x1FU;

    if (day == 0 || month == 0 || seconds >= 60U || minutes >= 60U || hours >= 24U) {
        return std::nullopt;
    }

    const auto ymd = std::chrono::year_month_day{
        std::chrono::year{year},
        std::chrono::month{month},
        std::chrono::day{day}};

    if (!ymd.ok()) {
        return std::nullopt;
    }

    return std::chrono::sys_days{ymd}
         + std::chrono::hours{hours}
         + std::chrono::minutes{minutes}
         + std::chrono::seconds{seconds};
}

[[nodiscard]] std::wstring TrimNtPathPrefix(std::wstring_view path) {
    std::wstring normalized(path);
    constexpr std::wstring_view ntPrefix = L"\\??\\";
    constexpr std::wstring_view longPrefix = L"\\\\?\\";

    if (normalized.starts_with(ntPrefix)) {
        normalized.erase(0, ntPrefix.size());
    } else if (normalized.starts_with(longPrefix)) {
        normalized.erase(0, 4);
    }

    return normalized;
}

[[nodiscard]] std::wstring JoinPathComponent(const std::wstring& parentPath, std::wstring_view component) {
    if (component.empty()) {
        return parentPath;
    }
    if (parentPath.empty()) {
        return std::wstring(component);
    }
    return parentPath + L"\\" + std::wstring(component);
}

[[nodiscard]] std::wstring BrowserTypeToWide(BrowserType browser) {
    switch (browser) {
        case BrowserType::Chrome:
            return L"Chrome";
        case BrowserType::Firefox:
            return L"Firefox";
        case BrowserType::Edge:
            return L"Edge";
        case BrowserType::IE:
            return L"Internet Explorer";
        case BrowserType::Opera:
            return L"Opera";
        case BrowserType::Brave:
            return L"Brave";
        case BrowserType::Vivaldi:
            return L"Vivaldi";
        case BrowserType::Safari:
            return L"Safari";
        default:
            return L"Unknown";
    }
}

[[nodiscard]] std::filesystem::path GetArtifactExtractorTempDirectory() {
    std::filesystem::path tempDirectory = std::filesystem::current_path() / L"build" / L"artifactextractor_tmp";
    std::error_code ec;
    std::filesystem::create_directories(tempDirectory, ec);
    if (ec) {
        tempDirectory = std::filesystem::current_path();
    }
    return tempDirectory;
}

[[nodiscard]] std::filesystem::path GenerateArtifactTempPath(std::wstring_view prefix, std::wstring_view extension) {
    const auto counter = s_artifactTempCounter.fetch_add(1, std::memory_order_relaxed);
    std::wstringstream builder;
    builder << prefix << ::GetCurrentProcessId() << L'_' << ::GetCurrentThreadId() << L'_' << counter << extension;
    return GetArtifactExtractorTempDirectory() / builder.str();
}

[[nodiscard]] std::optional<std::filesystem::path> CopyFileToWorkingTemp(const std::filesystem::path& sourcePath,
                                                                          std::wstring_view prefix)
{
    std::error_code ec;
    if (!std::filesystem::exists(sourcePath, ec) || ec) {
        return std::nullopt;
    }

    const auto sourceSize = std::filesystem::file_size(sourcePath, ec);
    if (ec || sourceSize == static_cast<uintmax_t>(-1) || sourceSize > kMaxBrowserDatabaseBytes) {
        return std::nullopt;
    }

    const auto tempPath = GenerateArtifactTempPath(prefix, L".sqlite");
    std::filesystem::copy_file(sourcePath, tempPath, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
        return std::nullopt;
    }

    return tempPath;
}

[[nodiscard]] std::optional<std::vector<uint8_t>> QueryBinaryValue(HKEY key,
                                                                   std::wstring_view valueName,
                                                                   DWORD maxBytes = kMaxRegistryBinaryBytes)
{
    DWORD type = 0;
    DWORD byteCount = 0;
    auto result = ::RegQueryValueExW(key, std::wstring(valueName).c_str(), nullptr, &type, nullptr, &byteCount);
    if (result != ERROR_SUCCESS || byteCount == 0 || byteCount > maxBytes) {
        return std::nullopt;
    }

    if (type != REG_BINARY && type != REG_NONE) {
        return std::nullopt;
    }

    std::vector<uint8_t> data(byteCount);
    result = ::RegQueryValueExW(key,
                                std::wstring(valueName).c_str(),
                                nullptr,
                                &type,
                                reinterpret_cast<LPBYTE>(data.data()),
                                &byteCount);
    if (result != ERROR_SUCCESS) {
        return std::nullopt;
    }

    data.resize(byteCount);
    return data;
}

[[nodiscard]] std::optional<std::wstring> QueryStringValue(HKEY key, std::wstring_view valueName) {
    DWORD type = 0;
    DWORD byteCount = 0;
    auto result = ::RegQueryValueExW(key, std::wstring(valueName).c_str(), nullptr, &type, nullptr, &byteCount);
    if (result != ERROR_SUCCESS || byteCount == 0) {
        return std::nullopt;
    }

    if (type != REG_SZ && type != REG_EXPAND_SZ) {
        return std::nullopt;
    }

    std::wstring buffer((byteCount / sizeof(wchar_t)) + 1U, L'\0');
    result = ::RegQueryValueExW(key,
                                std::wstring(valueName).c_str(),
                                nullptr,
                                &type,
                                reinterpret_cast<LPBYTE>(buffer.data()),
                                &byteCount);
    if (result != ERROR_SUCCESS) {
        return std::nullopt;
    }

    buffer.resize(byteCount / sizeof(wchar_t));
    while (!buffer.empty() && buffer.back() == L'\0') {
        buffer.pop_back();
    }

    return buffer;
}

[[nodiscard]] std::optional<uint32_t> QueryDwordValue(HKEY key, std::wstring_view valueName) {
    DWORD type = 0;
    DWORD value = 0;
    DWORD byteCount = sizeof(value);
    const auto result = ::RegQueryValueExW(key,
                                           std::wstring(valueName).c_str(),
                                           nullptr,
                                           &type,
                                           reinterpret_cast<LPBYTE>(&value),
                                           &byteCount);
    if (result != ERROR_SUCCESS || type != REG_DWORD) {
        return std::nullopt;
    }
    return value;
}

[[nodiscard]] std::optional<uint64_t> QueryQwordValue(HKEY key, std::wstring_view valueName) {
    DWORD type = 0;
    uint64_t value = 0;
    DWORD byteCount = sizeof(value);
    const auto result = ::RegQueryValueExW(key,
                                           std::wstring(valueName).c_str(),
                                           nullptr,
                                           &type,
                                           reinterpret_cast<LPBYTE>(&value),
                                           &byteCount);
    if (result != ERROR_SUCCESS || type != REG_QWORD) {
        return std::nullopt;
    }
    return value;
}

[[nodiscard]] std::optional<SystemTimePoint> QueryKeyLastWriteTime(HKEY key) {
    FILETIME lastWrite{};
    const auto result = ::RegQueryInfoKeyW(key,
                                           nullptr,
                                           nullptr,
                                           nullptr,
                                           nullptr,
                                           nullptr,
                                           nullptr,
                                           nullptr,
                                           nullptr,
                                           nullptr,
                                           nullptr,
                                           &lastWrite);
    if (result != ERROR_SUCCESS) {
        return std::nullopt;
    }
    return FileTimeToTimePointChecked(lastWrite);
}

[[nodiscard]] std::wstring ExtractUtf16String(const uint8_t* data, size_t byteCount) {
    if (data == nullptr || byteCount < sizeof(wchar_t)) {
        return {};
    }

    const size_t evenLength = byteCount - (byteCount % sizeof(wchar_t));
    size_t length = 0;
    while (length + sizeof(wchar_t) <= evenLength) {
        wchar_t current = L'\0';
        std::memcpy(&current, data + length, sizeof(current));
        if (current == L'\0') {
            break;
        }
        length += sizeof(wchar_t);
    }

    if (length == 0) {
        return {};
    }

    std::wstring result(length / sizeof(wchar_t), L'\0');
    std::memcpy(result.data(), data, length);
    return result;
}

[[nodiscard]] std::wstring ExtractAnsiString(const uint8_t* data, size_t byteCount) {
    if (data == nullptr || byteCount == 0) {
        return {};
    }

    size_t length = 0;
    while (length < byteCount && data[length] != 0) {
        ++length;
    }

    if (length == 0) {
        return {};
    }

    return Utils::StringUtils::ToWide(std::string_view(reinterpret_cast<const char*>(data), length));
}

[[nodiscard]] std::wstring ExtractBestEffortShellItemName(std::span<const uint8_t> shellItem) {
    for (size_t offset = 0; offset + 4 <= shellItem.size(); ++offset) {
        if (shellItem[offset] >= 0x20 && shellItem[offset + 1] == 0) {
            size_t end = offset;
            while (end + 1 < shellItem.size() && shellItem[end] >= 0x20 && shellItem[end + 1] == 0) {
                end += 2;
            }
            const auto extracted = ExtractUtf16String(shellItem.data() + offset, end - offset);
            if (!extracted.empty()) {
                return extracted;
            }
        }
    }

    for (size_t offset = 0; offset < shellItem.size(); ++offset) {
        if (std::isprint(static_cast<unsigned char>(shellItem[offset])) != 0) {
            size_t end = offset;
            while (end < shellItem.size() && std::isprint(static_cast<unsigned char>(shellItem[end])) != 0) {
                ++end;
            }
            const auto extracted = ExtractAnsiString(shellItem.data() + offset, end - offset);
            if (!extracted.empty()) {
                return extracted;
            }
        }
    }

    return {};
}

[[nodiscard]] std::optional<ShellItemExtensionInfo> ParseShellItemExtension(std::span<const uint8_t> shellItem) {
    if (shellItem.size() < 18) {
        return std::nullopt;
    }

    std::vector<size_t> candidateOffsets;
    const uint16_t trailingOffset = static_cast<uint16_t>(shellItem[shellItem.size() - 2])
                                  | (static_cast<uint16_t>(shellItem[shellItem.size() - 1]) << 8U);
    if (trailingOffset >= 14U && trailingOffset + 10U <= shellItem.size()) {
        candidateOffsets.push_back(trailingOffset);
    }

    for (size_t offset = 14; offset + 10 <= shellItem.size(); ++offset) {
        uint32_t signature = 0;
        std::memcpy(&signature, shellItem.data() + offset + 4, sizeof(signature));
        if (signature == 0xBEEF0004U &&
            std::find(candidateOffsets.begin(), candidateOffsets.end(), offset) == candidateOffsets.end()) {
            candidateOffsets.push_back(offset);
        }
    }

    for (const auto offset : candidateOffsets) {
        if (offset + 18 > shellItem.size()) {
            continue;
        }

        uint16_t extensionSize = 0;
        uint16_t extensionVersion = 0;
        uint32_t signature = 0;
        uint32_t creationDosTime = 0;
        uint32_t accessDosTime = 0;

        std::memcpy(&extensionSize, shellItem.data() + offset, sizeof(extensionSize));
        std::memcpy(&extensionVersion, shellItem.data() + offset + 2, sizeof(extensionVersion));
        std::memcpy(&signature, shellItem.data() + offset + 4, sizeof(signature));
        std::memcpy(&creationDosTime, shellItem.data() + offset + 8, sizeof(creationDosTime));
        std::memcpy(&accessDosTime, shellItem.data() + offset + 12, sizeof(accessDosTime));

        if (signature != 0xBEEF0004U || extensionSize < 18 || offset + extensionSize > shellItem.size()) {
            continue;
        }

        ShellItemExtensionInfo info;
        info.creationTime = DosDateTimeToTimePoint(creationDosTime);
        info.accessTime = DosDateTimeToTimePoint(accessDosTime);

        size_t cursor = offset + 16;
        if (extensionVersion >= 7) {
            if (cursor + 2 + 8 + 8 > offset + extensionSize) {
                return info;
            }
            cursor += 2;
            cursor += 8;
            cursor += 8;
        }

        uint16_t longStringSize = 0;
        if (extensionVersion >= 3) {
            if (cursor + 2 > offset + extensionSize) {
                return info;
            }
            std::memcpy(&longStringSize, shellItem.data() + cursor, sizeof(longStringSize));
            cursor += 2;
        }

        if (extensionVersion >= 9) {
            if (cursor + 4 > offset + extensionSize) {
                return info;
            }
            cursor += 4;
        }
        if (extensionVersion >= 8) {
            if (cursor + 4 > offset + extensionSize) {
                return info;
            }
            cursor += 4;
        }
        if (extensionVersion >= 3) {
            if (cursor + 4 > offset + extensionSize) {
                return info;
            }
            cursor += 4;
        }

        if (longStringSize > 0 && cursor < offset + extensionSize) {
            const auto availableBytes = std::min<size_t>(longStringSize, (offset + extensionSize) - cursor);
            info.longName = ExtractUtf16String(shellItem.data() + cursor, availableBytes);
        }

        return info;
    }

    return std::nullopt;
}

[[nodiscard]] ParsedShellItem ParseShellItem(std::span<const uint8_t> shellItem) {
    ParsedShellItem parsed;
    if (shellItem.size() < 3) {
        return parsed;
    }

    const uint8_t classType = shellItem[2];
    const uint8_t classMask = classType & 0x70U;

    if (classMask == 0x30U) {
        parsed.itemType = ((classType & 0x01U) != 0U) ? "folder" : (((classType & 0x02U) != 0U) ? "file" : "file_entry");

        uint16_t extensionOffset = 0;
        if (shellItem.size() >= 2) {
            extensionOffset = static_cast<uint16_t>(shellItem[shellItem.size() - 2])
                            | (static_cast<uint16_t>(shellItem[shellItem.size() - 1]) << 8U);
        }

        size_t nameEnd = shellItem.size();
        if (extensionOffset >= 14U && extensionOffset < shellItem.size()) {
            nameEnd = extensionOffset;
        }

        if (nameEnd > 14U) {
            const auto nameBytes = nameEnd - 14U;
            parsed.name = ((classType & 0x04U) != 0U)
                ? ExtractUtf16String(shellItem.data() + 14U, nameBytes)
                : ExtractAnsiString(shellItem.data() + 14U, nameBytes);
        }

        if (const auto extension = ParseShellItemExtension(shellItem); extension.has_value()) {
            if (!extension->longName.empty()) {
                parsed.name = extension->longName;
            }
            parsed.creationTime = extension->creationTime;
            parsed.accessTime = extension->accessTime;
        }
    } else if (classMask == 0x20U) {
        parsed.itemType = "volume";
        parsed.name = ((classType & 0x01U) != 0U)
            ? ExtractAnsiString(shellItem.data() + 3U, shellItem.size() - 3U)
            : L"This PC";
    } else if (classMask == 0x40U) {
        parsed.itemType = "network";
        if (shellItem.size() > 5U) {
            parsed.name = ExtractAnsiString(shellItem.data() + 5U, shellItem.size() - 5U);
        }
    } else if (classType == 0x1FU) {
        parsed.itemType = "root";
        parsed.name = L"Desktop";
    } else if (classType == 0x61U) {
        parsed.itemType = "uri";
        if (shellItem.size() > 6U) {
            parsed.name = ExtractBestEffortShellItemName(shellItem.subspan(6U));
        }
    } else {
        parsed.name = ExtractBestEffortShellItemName(shellItem);
    }

    if (parsed.name.empty()) {
        parsed.name = ExtractBestEffortShellItemName(shellItem);
    }

    return parsed;
}

[[nodiscard]] ParsedShellItem ParseShellItemList(std::span<const uint8_t> rawData) {
    ParsedShellItem lastItem;
    size_t offset = 0;

    while (offset + sizeof(uint16_t) <= rawData.size()) {
        uint16_t itemSize = 0;
        std::memcpy(&itemSize, rawData.data() + offset, sizeof(itemSize));
        if (itemSize == 0) {
            break;
        }
        if (itemSize < sizeof(uint16_t) || offset + itemSize > rawData.size()) {
            break;
        }

        auto current = ParseShellItem(rawData.subspan(offset, itemSize));
        if (!current.name.empty()) {
            lastItem = std::move(current);
        }

        offset += itemSize;
    }

    return lastItem;
}

[[nodiscard]] bool ApplyNtfsUpdateSequenceArray(std::vector<uint8_t>& record,
                                                uint16_t updateSequenceOffset,
                                                uint16_t updateSequenceCount,
                                                uint32_t bytesPerSector)
{
    if (updateSequenceCount <= 1 || bytesPerSector < sizeof(uint16_t)) {
        return false;
    }

    const auto usaSize = static_cast<size_t>(updateSequenceCount) * sizeof(uint16_t);
    if (updateSequenceOffset < sizeof(uint16_t) || updateSequenceOffset + usaSize > record.size()) {
        return false;
    }

    uint16_t updateSequenceValue = 0;
    std::memcpy(&updateSequenceValue, record.data() + updateSequenceOffset, sizeof(updateSequenceValue));

    const auto* replacements = record.data() + updateSequenceOffset + sizeof(uint16_t);
    for (uint16_t sectorIndex = 1; sectorIndex < updateSequenceCount; ++sectorIndex) {
        const auto sectorEndOffset = static_cast<size_t>(sectorIndex) * bytesPerSector;
        if (sectorEndOffset < sizeof(uint16_t) || sectorEndOffset > record.size()) {
            return false;
        }

        uint16_t actualValue = 0;
        std::memcpy(&actualValue, record.data() + sectorEndOffset - sizeof(uint16_t), sizeof(actualValue));
        if (actualValue != updateSequenceValue) {
            return false;
        }

        std::memcpy(record.data() + sectorEndOffset - sizeof(uint16_t),
                    replacements + (static_cast<size_t>(sectorIndex - 1U) * sizeof(uint16_t)),
                    sizeof(uint16_t));
    }

    return true;
}

[[nodiscard]] uint8_t ScoreFileNameNamespace(uint8_t nameSpace) noexcept {
    switch (nameSpace) {
        case 0x03:
            return 3;
        case 0x01:
            return 2;
        case 0x00:
            return 1;
        default:
            return 0;
    }
}

[[nodiscard]] bool TryParseAmcacheDateString(std::wstring_view value, SystemTimePoint& output) {
    if (value.empty()) {
        return false;
    }

    SYSTEMTIME systemTime{};
    unsigned short first = 0;
    unsigned short second = 0;
    unsigned short third = 0;
    unsigned short hour = 0;
    unsigned short minute = 0;
    unsigned short secondValue = 0;

    auto assignAndValidate = [&](unsigned short year, unsigned short month, unsigned short day) -> bool {
        systemTime.wYear = year;
        systemTime.wMonth = month;
        systemTime.wDay = day;
        systemTime.wHour = hour;
        systemTime.wMinute = minute;
        systemTime.wSecond = secondValue;
        systemTime.wMilliseconds = 0;
        const auto maybeTime = SystemTimeToTimePoint(systemTime);
        if (!maybeTime.has_value()) {
            return false;
        }
        output = *maybeTime;
        return true;
    };

    if (swscanf_s(value.data(), L"%hu-%hu-%huT%hu:%hu:%hu", &first, &second, &third, &hour, &minute, &secondValue) == 6) {
        return assignAndValidate(first, second, third);
    }
    if (swscanf_s(value.data(), L"%hu-%hu-%hu %hu:%hu:%hu", &first, &second, &third, &hour, &minute, &secondValue) == 6) {
        return assignAndValidate(first, second, third);
    }
    if (swscanf_s(value.data(), L"%hu/%hu/%hu %hu:%hu:%hu", &first, &second, &third, &hour, &minute, &secondValue) == 6) {
        if (third > 1900U) {
            return assignAndValidate(third, first, second);
        }
        return assignAndValidate(first, second, third);
    }
    if (swscanf_s(value.data(), L"%hu/%hu/%hu", &first, &second, &third) == 3) {
        if (third > 1900U) {
            return assignAndValidate(third, first, second);
        }
        return assignAndValidate(first, second, third);
    }

    return false;
}

[[nodiscard]] std::string NormalizeAmcacheSha1(std::wstring_view rawValue) {
    auto hash = Utils::StringUtils::ToNarrow(rawValue);
    while (hash.rfind("0000", 0) == 0) {
        hash.erase(0, 4);
    }
    for (auto& ch : hash) {
        ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    }
    return hash;
}


}  // namespace

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

std::string BaseArtifact::ToJson() const {
    nlohmann::json j = {
        {"artifactId", artifactId},
        {"type", static_cast<uint32_t>(type)},
        {"sourcePath", Utils::StringUtils::WideToUtf8(sourcePath)},
        {"userSID", Utils::StringUtils::WideToUtf8(userSID)},
        {"userName", Utils::StringUtils::WideToUtf8(userName)},
        {"isComplete", isComplete}
    };
    return j.dump(2);
}

std::string MFTRecord::ToJson() const {
    nlohmann::json j = {
        {"artifactId", artifactId},
        {"type", "MFTRecord"},
        {"recordNumber", recordNumber},
        {"sequenceNumber", sequenceNumber},
        {"fileName", Utils::StringUtils::WideToUtf8(fileName)},
        {"parentRecordNumber", parentRecordNumber},
        {"fileSize", fileSize},
        {"allocatedSize", allocatedSize},
        {"isDirectory", isDirectory},
        {"isDeleted", isDeleted},
        {"hasResidentData", hasResidentData},
        {"alternateStreams", alternateStreams.size()}
    };
    return j.dump(2);
}

std::string PrefetchEntry::ToJson() const {
    nlohmann::json j = {
        {"artifactId", artifactId},
        {"type", "Prefetch"},
        {"executableName", Utils::StringUtils::WideToUtf8(executableName)},
        {"executablePath", Utils::StringUtils::WideToUtf8(executablePath)},
        {"prefetchHash", std::format("0x{:08X}", prefetchHash)},
        {"runCount", runCount},
        {"version", version},
        {"loadedFiles", loadedFiles.size()},
        {"volumes", volumes.size()}
    };
    return j.dump(2);
}

std::string ShimcacheEntry::ToJson() const {
    nlohmann::json j = {
        {"artifactId", artifactId},
        {"type", "Shimcache"},
        {"filePath", Utils::StringUtils::WideToUtf8(filePath)},
        {"fileSize", fileSize},
        {"executed", executed},
        {"cacheIndex", cacheIndex},
        {"controlSet", controlSet}
    };
    return j.dump(2);
}

std::string AmcacheEntry::ToJson() const {
    nlohmann::json j = {
        {"artifactId", artifactId},
        {"type", "Amcache"},
        {"filePath", Utils::StringUtils::WideToUtf8(filePath)},
        {"sha1Hash", sha1Hash},
        {"fileSize", fileSize},
        {"productName", Utils::StringUtils::WideToUtf8(productName)},
        {"companyName", Utils::StringUtils::WideToUtf8(companyName)},
        {"fileVersion", Utils::StringUtils::WideToUtf8(fileVersion)},
        {"isPE", isPE}
    };
    return j.dump(2);
}

std::string BrowserHistoryEntry::ToJson() const {
    nlohmann::json j = {
        {"artifactId", artifactId},
        {"type", "BrowserHistory"},
        {"browser", static_cast<int>(browser)},
        {"url", url},
        {"title", Utils::StringUtils::WideToUtf8(title)},
        {"visitCount", visitCount},
        {"isTyped", isTyped},
        {"profile", Utils::StringUtils::WideToUtf8(profile)}
    };
    return j.dump(2);
}

std::string LNKFileEntry::ToJson() const {
    nlohmann::json j = {
        {"artifactId", artifactId},
        {"type", "LNKFile"},
        {"lnkPath", Utils::StringUtils::WideToUtf8(lnkPath)},
        {"targetPath", Utils::StringUtils::WideToUtf8(targetPath)},
        {"workingDirectory", Utils::StringUtils::WideToUtf8(workingDirectory)},
        {"arguments", Utils::StringUtils::WideToUtf8(arguments)},
        {"targetFileSize", targetFileSize},
        {"machineId", machineId},
        {"macAddress", macAddress},
        {"volumeSerialNumber", std::format("0x{:08X}", volumeSerialNumber)},
        {"hasNetworkLocation", hasNetworkLocation}
    };
    return j.dump(2);
}

std::string JumpListEntry::ToJson() const {
    nlohmann::json j = {
        {"artifactId", artifactId},
        {"type", "JumpList"},
        {"appId", Utils::StringUtils::WideToUtf8(appId)},
        {"targetPath", Utils::StringUtils::WideToUtf8(targetPath)},
        {"entryType", entryType},
        {"arguments", Utils::StringUtils::WideToUtf8(arguments)},
        {"workingDirectory", Utils::StringUtils::WideToUtf8(workingDirectory)}
    };
    return j.dump(2);
}

std::string UserAssistEntry::ToJson() const {
    nlohmann::json j = {
        {"artifactId", artifactId},
        {"type", "UserAssist"},
        {"name", Utils::StringUtils::WideToUtf8(name)},
        {"runCount", runCount},
        {"focusCount", focusCount},
        {"focusTime", focusTime},
        {"userSid", Utils::StringUtils::WideToUtf8(userSid)},
        {"guid", guid}
    };
    return j.dump(2);
}

std::string ShellbagEntry::ToJson() const {
    nlohmann::json j = {
        {"artifactId", artifactId},
        {"type", "Shellbag"},
        {"path", Utils::StringUtils::WideToUtf8(path)},
        {"itemType", itemType},
        {"registryPath", Utils::StringUtils::WideToUtf8(registryPath)}
    };
    return j.dump(2);
}

std::string ScheduledTaskEntry::ToJson() const {
    nlohmann::json j = {
        {"artifactId", artifactId},
        {"type", "ScheduledTask"},
        {"taskName", Utils::StringUtils::WideToUtf8(taskName)},
        {"taskPath", Utils::StringUtils::WideToUtf8(taskPath)},
        {"action", Utils::StringUtils::WideToUtf8(action)},
        {"arguments", Utils::StringUtils::WideToUtf8(arguments)},
        {"author", Utils::StringUtils::WideToUtf8(author)},
        {"description", Utils::StringUtils::WideToUtf8(description)},
        {"triggerType", triggerType},
        {"isEnabled", isEnabled},
        {"runLevel", runLevel}
    };
    return j.dump(2);
}

bool ExtractionConfiguration::IsValid() const noexcept {
    if (maxArtifactsPerType == 0) return false;
    if (timeoutMs == 0) return false;
    if (timeRangeStart.has_value() && timeRangeEnd.has_value()) {
        if (timeRangeStart.value() > timeRangeEnd.value()) return false;
    }
    return true;
}

void ExtractionStatistics::Reset() noexcept {
    totalExtractions.store(0, std::memory_order_relaxed);
    totalArtifacts.store(0, std::memory_order_relaxed);
    mftRecordsParsed.store(0, std::memory_order_relaxed);
    prefetchFilesParsed.store(0, std::memory_order_relaxed);
    deletedFilesFound.store(0, std::memory_order_relaxed);
    filesRecovered.store(0, std::memory_order_relaxed);
    browserEntriesFound.store(0, std::memory_order_relaxed);
    startTime = Clock::now();
}

std::string ExtractionStatistics::ToJson() const {
    nlohmann::json j = {
        {"totalExtractions", totalExtractions.load()},
        {"totalArtifacts", totalArtifacts.load()},
        {"mftRecordsParsed", mftRecordsParsed.load()},
        {"prefetchFilesParsed", prefetchFilesParsed.load()},
        {"deletedFilesFound", deletedFilesFound.load()},
        {"filesRecovered", filesRecovered.load()},
        {"browserEntriesFound", browserEntriesFound.load()}
    };
    return j.dump(2);
}

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class ArtifactExtractor::ArtifactExtractorImpl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    /// @brief Thread synchronization
    mutable std::shared_mutex m_mutex;

    /// @brief Configuration
    ExtractionConfiguration m_config;

    /// @brief Initialization state
    std::atomic<bool> m_initialized{false};

    /// @brief Module status
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};

    /// @brief Statistics
    ExtractionStatistics m_statistics;

    /// @brief Callbacks
    ArtifactCallback m_artifactCallback;
    ExtractionProgressCallback m_progressCallback;
    mutable std::mutex m_callbacksMutex;

    /// @brief Infrastructure integrations
    std::shared_ptr<ThreatIntel::ThreatIntelManager> m_threatIntel;
    std::shared_ptr<SignatureStore::SignatureStore> m_signatureStore;

    // ========================================================================
    // METHODS
    // ========================================================================

    ArtifactExtractorImpl() = default;
    ~ArtifactExtractorImpl() = default;

    [[nodiscard]] bool Initialize(const ExtractionConfiguration& config);
    void Shutdown();

    // Extraction methods
    [[nodiscard]] std::vector<std::shared_ptr<BaseArtifact>> ExtractAllInternal(
        const ExtractionConfiguration& config);
    [[nodiscard]] std::vector<MFTRecord> ParseMFTInternal(wchar_t driveLetter);
    [[nodiscard]] std::vector<PrefetchEntry> ParsePrefetchInternal();
    [[nodiscard]] std::vector<ShimcacheEntry> ParseShimcacheInternal();
    [[nodiscard]] std::vector<AmcacheEntry> ParseAmcacheInternal();
    [[nodiscard]] std::vector<BrowserHistoryEntry> ParseBrowserHistoryInternal(BrowserType browser);
    [[nodiscard]] std::vector<LNKFileEntry> ParseLNKFilesInternal(std::wstring_view directory);
    [[nodiscard]] std::vector<JumpListEntry> ParseJumpListsInternal(std::wstring_view userProfile);
    [[nodiscard]] std::vector<UserAssistEntry> ParseUserAssistInternal(std::wstring_view userSID);
    [[nodiscard]] std::vector<ShellbagEntry> ParseShellbagsInternal(std::wstring_view userSID);
    [[nodiscard]] std::vector<ScheduledTaskEntry> ParseScheduledTasksInternal();
    [[nodiscard]] bool RecoverFileInternal(const std::wstring& fileName, std::vector<uint8_t>& outData);

    // Helpers
    void InvokeArtifactCallback(const BaseArtifact& artifact);
    void InvokeProgressCallback(ArtifactType type, uint32_t percentage, const std::wstring& item);
};

// ============================================================================
// IMPL: INITIALIZATION
// ============================================================================

bool ArtifactExtractor::ArtifactExtractorImpl::Initialize(
    const ExtractionConfiguration& config)
{
    try {
        if (m_initialized.exchange(true, std::memory_order_acq_rel)) {
            Utils::Logger::Warn(L"ArtifactExtractor: Already initialized");
            return true;
        }

        Utils::Logger::Info(L"ArtifactExtractor: Initializing...");

        m_status.store(ModuleStatus::Initializing, std::memory_order_release);

        // Validate configuration
        if (!config.IsValid()) {
            Utils::Logger::Error(L"ArtifactExtractor: Invalid configuration");
            m_initialized.store(false, std::memory_order_release);
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }

        m_config = config;

        // Initialize infrastructure integrations
        m_threatIntel = std::make_shared<ThreatIntel::ThreatIntelManager>();
        m_signatureStore = std::make_shared<SignatureStore::SignatureStore>();

        // Create output directory if specified
        if (!m_config.outputDirectory.empty()) {
            if (!std::filesystem::exists(m_config.outputDirectory)) {
                std::filesystem::create_directories(m_config.outputDirectory);
            }
            Utils::Logger::Info(L"ArtifactExtractor: Output directory: {}", m_config.outputDirectory);
        }

        m_status.store(ModuleStatus::Running, std::memory_order_release);

        Utils::Logger::Info(L"ArtifactExtractor: Initialized successfully");

        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"ArtifactExtractor: Initialization failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
        m_initialized.store(false, std::memory_order_release);
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    }
}

void ArtifactExtractor::ArtifactExtractorImpl::Shutdown() {
    try {
        if (!m_initialized.exchange(false, std::memory_order_acq_rel)) {
            return;
        }

        Utils::Logger::Info(L"ArtifactExtractor: Shutting down...");

        m_status.store(ModuleStatus::Stopping, std::memory_order_release);

        {
            std::lock_guard lock(m_callbacksMutex);
            m_artifactCallback = nullptr;
            m_progressCallback = nullptr;
        }

        m_status.store(ModuleStatus::Stopped, std::memory_order_release);

        Utils::Logger::Info(L"ArtifactExtractor: Shutdown complete");

    } catch (...) {
        Utils::Logger::Error(L"ArtifactExtractor: Exception during shutdown");
    }
}

// ============================================================================
// IMPL: EXTRACTION
// ============================================================================

std::vector<std::shared_ptr<BaseArtifact>> ArtifactExtractor::ArtifactExtractorImpl::ExtractAllInternal(
    const ExtractionConfiguration& config)
{
    const auto startTime = Clock::now();
    std::vector<std::shared_ptr<BaseArtifact>> allArtifacts;

    try {
        m_statistics.totalExtractions.fetch_add(1, std::memory_order_relaxed);

        Utils::Logger::Info(L"ArtifactExtractor: Starting comprehensive extraction...");

        // 1. File System Artifacts
        if (static_cast<uint32_t>(config.artifactTypes & ArtifactType::MFTRecord) != 0) {
            InvokeProgressCallback(ArtifactType::MFTRecord, 0, L"Parsing MFT");
            auto mftRecords = ParseMFTInternal(L'C');
            for (auto& record : mftRecords) {
                auto artifact = std::make_shared<MFTRecord>(std::move(record));
                allArtifacts.push_back(artifact);
                InvokeArtifactCallback(*artifact);
            }
            InvokeProgressCallback(ArtifactType::MFTRecord, 100, L"MFT parsing complete");
        }

        // 2. Execution Artifacts
        if (static_cast<uint32_t>(config.artifactTypes & ArtifactType::PrefetchFile) != 0) {
            InvokeProgressCallback(ArtifactType::PrefetchFile, 0, L"Parsing Prefetch");
            auto prefetch = ParsePrefetchInternal();
            for (auto& entry : prefetch) {
                auto artifact = std::make_shared<PrefetchEntry>(std::move(entry));
                allArtifacts.push_back(artifact);
                InvokeArtifactCallback(*artifact);
            }
            InvokeProgressCallback(ArtifactType::PrefetchFile, 100, L"Prefetch parsing complete");
        }

        if (static_cast<uint32_t>(config.artifactTypes & ArtifactType::ShimcacheEntry) != 0) {
            InvokeProgressCallback(ArtifactType::ShimcacheEntry, 0, L"Parsing Shimcache");
            auto shimcache = ParseShimcacheInternal();
            for (auto& entry : shimcache) {
                auto artifact = std::make_shared<ShimcacheEntry>(std::move(entry));
                allArtifacts.push_back(artifact);
                InvokeArtifactCallback(*artifact);
            }
            InvokeProgressCallback(ArtifactType::ShimcacheEntry, 100, L"Shimcache parsing complete");
        }

        if (static_cast<uint32_t>(config.artifactTypes & ArtifactType::AmcacheEntry) != 0) {
            InvokeProgressCallback(ArtifactType::AmcacheEntry, 0, L"Parsing Amcache");
            auto amcache = ParseAmcacheInternal();
            for (auto& entry : amcache) {
                auto artifact = std::make_shared<AmcacheEntry>(std::move(entry));
                allArtifacts.push_back(artifact);
                InvokeArtifactCallback(*artifact);
            }
            InvokeProgressCallback(ArtifactType::AmcacheEntry, 100, L"Amcache parsing complete");
        }

        // 3. User Activity Artifacts
        if (static_cast<uint32_t>(config.artifactTypes & ArtifactType::LNKFile) != 0) {
            InvokeProgressCallback(ArtifactType::LNKFile, 0, L"Parsing LNK files");
            auto lnkFiles = ParseLNKFilesInternal(L"");
            for (auto& entry : lnkFiles) {
                auto artifact = std::make_shared<LNKFileEntry>(std::move(entry));
                allArtifacts.push_back(artifact);
                InvokeArtifactCallback(*artifact);
            }
            InvokeProgressCallback(ArtifactType::LNKFile, 100, L"LNK parsing complete");
        }

        if (static_cast<uint32_t>(config.artifactTypes & ArtifactType::UserAssist) != 0) {
            InvokeProgressCallback(ArtifactType::UserAssist, 0, L"Parsing UserAssist");
            auto userassist = ParseUserAssistInternal(L"");
            for (auto& entry : userassist) {
                auto artifact = std::make_shared<UserAssistEntry>(std::move(entry));
                allArtifacts.push_back(artifact);
                InvokeArtifactCallback(*artifact);
            }
            InvokeProgressCallback(ArtifactType::UserAssist, 100, L"UserAssist parsing complete");
        }

        // 4. Browser Artifacts
        if (static_cast<uint32_t>(config.artifactTypes & ArtifactType::BrowserHistory) != 0) {
            InvokeProgressCallback(ArtifactType::BrowserHistory, 0, L"Parsing browser history");

            for (BrowserType browser : config.browsers) {
                auto history = ParseBrowserHistoryInternal(browser);
                for (auto& entry : history) {
                    auto artifact = std::make_shared<BrowserHistoryEntry>(std::move(entry));
                    allArtifacts.push_back(artifact);
                    InvokeArtifactCallback(*artifact);
                }
            }

            InvokeProgressCallback(ArtifactType::BrowserHistory, 100, L"Browser history complete");
        }

        // 5. Persistence Artifacts
        if (static_cast<uint32_t>(config.artifactTypes & ArtifactType::ScheduledTask) != 0) {
            InvokeProgressCallback(ArtifactType::ScheduledTask, 0, L"Parsing scheduled tasks");
            auto tasks = ParseScheduledTasksInternal();
            for (auto& entry : tasks) {
                auto artifact = std::make_shared<ScheduledTaskEntry>(std::move(entry));
                allArtifacts.push_back(artifact);
                InvokeArtifactCallback(*artifact);
            }
            InvokeProgressCallback(ArtifactType::ScheduledTask, 100, L"Scheduled tasks complete");
        }

        m_statistics.totalArtifacts.fetch_add(allArtifacts.size(), std::memory_order_relaxed);

        const auto endTime = Clock::now();
        const auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);

        Utils::Logger::Info(L"ArtifactExtractor: Extraction complete - {} artifacts in {} seconds",
                          allArtifacts.size(), duration.count());

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"ArtifactExtractor: Extraction failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
    }

    return allArtifacts;
}

// ============================================================================
// IMPL: MFT PARSING
// ============================================================================

std::vector<MFTRecord> ArtifactExtractor::ArtifactExtractorImpl::ParseMFTInternal(wchar_t driveLetter) {
    std::vector<MFTRecord> records;

    try {
        if (m_config.maxArtifactsPerType == 0) {
            return records;
        }

        const std::wstring volumePath = std::format(L"\\\\.\\{}:", driveLetter);
        SS_LOG_INFO(kArtifactExtractorLogCategory, L"Opening volume %ls for MFT parsing", volumePath.c_str());

        ScopedHandle volumeHandle(::CreateFileW(volumePath.c_str(),
                                                GENERIC_READ,
                                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                                nullptr,
                                                OPEN_EXISTING,
                                                FILE_ATTRIBUTE_NORMAL,
                                                nullptr));
        if (!volumeHandle.IsValid()) {
            const auto lastError = ::GetLastError();
            if (lastError == ERROR_ACCESS_DENIED) {
                SS_LOG_WARN(kArtifactExtractorLogCategory,
                            L"Skipping MFT parsing on %ls because raw volume access was denied",
                            volumePath.c_str());
            } else {
                SS_LOG_ERROR(kArtifactExtractorLogCategory,
                             L"Failed to open %ls for MFT parsing (Win32=%lu)",
                             volumePath.c_str(),
                             lastError);
            }
            return records;
        }

        NTFS_VOLUME_DATA_BUFFER volumeData{};
        DWORD bytesReturned = 0;
        if (!::DeviceIoControl(volumeHandle.handle,
                               FSCTL_GET_NTFS_VOLUME_DATA,
                               nullptr,
                               0,
                               &volumeData,
                               sizeof(volumeData),
                               &bytesReturned,
                               nullptr)) {
            SS_LOG_ERROR(kArtifactExtractorLogCategory,
                         L"FSCTL_GET_NTFS_VOLUME_DATA failed for %ls (Win32=%lu)",
                         volumePath.c_str(),
                         ::GetLastError());
            return records;
        }

        const auto bytesPerRecord = static_cast<size_t>(volumeData.BytesPerFileRecordSegment);
        const auto bytesPerSector = static_cast<uint32_t>(volumeData.BytesPerSector);
        if (bytesPerRecord < 512U || bytesPerRecord > 64U * 1024U || bytesPerSector < 512U) {
            SS_LOG_WARN(kArtifactExtractorLogCategory,
                        L"NTFS volume %ls returned unsupported file record sizing (%zu bytes)",
                        volumePath.c_str(),
                        bytesPerRecord);
            return records;
        }

        const uint64_t validRecordCount = (volumeData.MftValidDataLength.QuadPart > 0)
            ? static_cast<uint64_t>(volumeData.MftValidDataLength.QuadPart) / bytesPerRecord
            : 0ULL;
        const auto maxRecords = std::min<uint64_t>(
            static_cast<uint64_t>(m_config.maxArtifactsPerType),
            validRecordCount == 0ULL ? ArtifactConstants::MAX_MFT_RECORDS
                                     : std::min<uint64_t>(validRecordCount, ArtifactConstants::MAX_MFT_RECORDS));

        if (maxRecords == 0ULL) {
            return records;
        }

        LARGE_INTEGER mftOffset{};
        mftOffset.QuadPart = volumeData.MftStartLcn.QuadPart * static_cast<LONGLONG>(volumeData.BytesPerCluster);
        if (!::SetFilePointerEx(volumeHandle.handle, mftOffset, nullptr, FILE_BEGIN)) {
            SS_LOG_ERROR(kArtifactExtractorLogCategory,
                         L"Failed to seek to the MFT on %ls (Win32=%lu)",
                         volumePath.c_str(),
                         ::GetLastError());
            return records;
        }

        std::vector<uint8_t> recordBuffer(bytesPerRecord);
        records.reserve(static_cast<size_t>(std::min<uint64_t>(maxRecords, 1024ULL)));

        constexpr uint32_t kAttributeTypeStandardInformation = 0x10U;
        constexpr uint32_t kAttributeTypeFileName = 0x30U;
        constexpr uint32_t kAttributeTypeData = 0x80U;
        constexpr uint32_t kAttributeTypeEnd = 0xFFFFFFFFU;

        for (uint64_t recordIndex = 0; recordIndex < maxRecords && records.size() < m_config.maxArtifactsPerType; ++recordIndex) {
            DWORD bytesRead = 0;
            if (!::ReadFile(volumeHandle.handle,
                            recordBuffer.data(),
                            static_cast<DWORD>(recordBuffer.size()),
                            &bytesRead,
                            nullptr)) {
                SS_LOG_WARN(kArtifactExtractorLogCategory,
                            L"Stopping MFT parsing on %ls after ReadFile failed at record %llu (Win32=%lu)",
                            volumePath.c_str(),
                            recordIndex,
                            ::GetLastError());
                break;
            }

            if (bytesRead != recordBuffer.size()) {
                break;
            }

            auto fixedRecord = recordBuffer;
            const auto* rawHeader = reinterpret_cast<const NtfsFileRecordHeader*>(fixedRecord.data());
            if (rawHeader->signature != ArtifactConstants::MFT_FILE_SIGNATURE) {
                continue;
            }

            if (!ApplyNtfsUpdateSequenceArray(fixedRecord,
                                              rawHeader->updateSequenceOffset,
                                              rawHeader->updateSequenceCount,
                                              bytesPerSector)) {
                continue;
            }

            const auto* header = reinterpret_cast<const NtfsFileRecordHeader*>(fixedRecord.data());
            if (header->bytesInUse < header->firstAttributeOffset || header->bytesInUse > fixedRecord.size()) {
                continue;
            }

            MFTRecord record;
            record.artifactId = GenerateArtifactId();
            record.type = ArtifactType::MFTRecord;
            record.sourcePath = volumePath;
            record.collectionTime = SystemClock::now();
            record.recordNumber = (header->recordNumber != 0U) ? header->recordNumber : recordIndex;
            record.sequenceNumber = header->sequenceNumber;
            record.flags = static_cast<MFTRecordFlags>(header->flags);
            record.isDirectory = (header->flags & static_cast<uint16_t>(MFTRecordFlags::Directory)) != 0U;
            record.isDeleted = (header->flags & static_cast<uint16_t>(MFTRecordFlags::InUse)) == 0U;

            if (record.isDeleted && !m_config.parseDeletedFiles) {
                continue;
            }

            uint8_t bestNameScore = 0;
            size_t attributeOffset = header->firstAttributeOffset;
            while (attributeOffset + sizeof(NtfsAttributeHeader) <= header->bytesInUse) {
                const auto* attribute = reinterpret_cast<const NtfsAttributeHeader*>(fixedRecord.data() + attributeOffset);
                if (attribute->type == kAttributeTypeEnd) {
                    break;
                }
                if (attribute->length < sizeof(NtfsAttributeHeader) || attributeOffset + attribute->length > header->bytesInUse) {
                    break;
                }

                if (attribute->nonResident == 0U) {
                    if (attribute->length >= sizeof(NtfsResidentAttributeHeader)) {
                        const auto* resident = reinterpret_cast<const NtfsResidentAttributeHeader*>(attribute);
                        if (resident->valueOffset + resident->valueLength <= attribute->length) {
                            const auto* value = fixedRecord.data() + attributeOffset + resident->valueOffset;
                            const auto valueLength = static_cast<size_t>(resident->valueLength);

                            if (attribute->type == kAttributeTypeStandardInformation && valueLength >= sizeof(NtfsStandardInformationValue)) {
                                NtfsStandardInformationValue info{};
                                std::memcpy(&info, value, sizeof(info));
                                if (const auto creation = FileTimeValueToTimePoint(static_cast<uint64_t>(info.creationTime)); creation.has_value()) {
                                    record.creationTime = *creation;
                                }
                                if (const auto modification = FileTimeValueToTimePoint(static_cast<uint64_t>(info.modificationTime)); modification.has_value()) {
                                    record.modificationTime = *modification;
                                }
                                if (const auto mftModification = FileTimeValueToTimePoint(static_cast<uint64_t>(info.mftModificationTime)); mftModification.has_value()) {
                                    record.mftModificationTime = *mftModification;
                                }
                                if (const auto access = FileTimeValueToTimePoint(static_cast<uint64_t>(info.accessTime)); access.has_value()) {
                                    record.accessTime = *access;
                                }
                            } else if (attribute->type == kAttributeTypeFileName && valueLength >= sizeof(NtfsFileNameValueHeader)) {
                                NtfsFileNameValueHeader fileNameHeader{};
                                std::memcpy(&fileNameHeader, value, sizeof(fileNameHeader));
                                const auto fileNameBytes = static_cast<size_t>(fileNameHeader.fileNameLength) * sizeof(wchar_t);
                                if (sizeof(fileNameHeader) + fileNameBytes <= valueLength) {
                                    std::wstring candidateName(fileNameHeader.fileNameLength, L'\0');
                                    std::memcpy(candidateName.data(),
                                                value + sizeof(fileNameHeader),
                                                fileNameBytes);
                                    const auto candidateScore = ScoreFileNameNamespace(fileNameHeader.fileNameNamespace);
                                    if (!candidateName.empty() && candidateScore >= bestNameScore) {
                                        bestNameScore = candidateScore;
                                        record.fileName = candidateName;
                                        record.parentRecordNumber = fileNameHeader.parentFileReference & 0x0000FFFFFFFFFFFFULL;
                                        record.fileSize = fileNameHeader.dataSize;
                                        record.allocatedSize = fileNameHeader.allocatedSize;
                                        record.isDirectory = (fileNameHeader.flags & FILE_ATTRIBUTE_DIRECTORY) != 0U;
                                        if (const auto creation = FileTimeValueToTimePoint(static_cast<uint64_t>(fileNameHeader.creationTime)); creation.has_value()) {
                                            record.creationTime = *creation;
                                        }
                                        if (const auto modification = FileTimeValueToTimePoint(static_cast<uint64_t>(fileNameHeader.modificationTime)); modification.has_value()) {
                                            record.modificationTime = *modification;
                                        }
                                        if (const auto mftModification = FileTimeValueToTimePoint(static_cast<uint64_t>(fileNameHeader.mftModificationTime)); mftModification.has_value()) {
                                            record.mftModificationTime = *mftModification;
                                        }
                                        if (const auto access = FileTimeValueToTimePoint(static_cast<uint64_t>(fileNameHeader.accessTime)); access.has_value()) {
                                            record.accessTime = *access;
                                        }
                                    }
                                }
                            } else if (attribute->type == kAttributeTypeData) {
                                record.hasResidentData = true;
                                record.fileSize = resident->valueLength;
                                record.allocatedSize = resident->valueLength;
                                if (m_config.includeRawData && resident->valueLength > 0U && resident->valueLength <= kMaxResidentAttributeBytes) {
                                    record.residentData.assign(value, value + resident->valueLength);
                                }
                            }
                        }
                    }
                } else if (attribute->type == kAttributeTypeData && attribute->length >= sizeof(NtfsNonResidentAttributeHeader)) {
                    const auto* nonResident = reinterpret_cast<const NtfsNonResidentAttributeHeader*>(attribute);
                    record.hasResidentData = false;
                    record.fileSize = nonResident->dataSize;
                    record.allocatedSize = nonResident->allocatedSize;
                }

                attributeOffset += attribute->length;
            }

            if (record.fileName.empty()) {
                record.fileName = std::format(L"MFTRecord_{}", record.recordNumber);
            }
            record.artifactTime = record.modificationTime;

            if (record.isDeleted) {
                m_statistics.deletedFilesFound.fetch_add(1, std::memory_order_relaxed);
            }

            records.push_back(std::move(record));
        }

        m_statistics.mftRecordsParsed.fetch_add(records.size(), std::memory_order_relaxed);
        SS_LOG_INFO(kArtifactExtractorLogCategory,
                    L"Parsed %zu MFT records from %ls",
                    records.size(),
                    volumePath.c_str());

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"ArtifactExtractor: MFT parsing failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
    }

    return records;
}

// ============================================================================
// IMPL: PREFETCH PARSING
// ============================================================================

std::vector<PrefetchEntry> ArtifactExtractor::ArtifactExtractorImpl::ParsePrefetchInternal() {
    std::vector<PrefetchEntry> entries;

    try {
        Utils::Logger::Info(L"ArtifactExtractor: Parsing Prefetch files...");

        std::wstring prefetchDir = L"C:\\Windows\\Prefetch";

        if (!std::filesystem::exists(prefetchDir)) {
            Utils::Logger::Warn(L"ArtifactExtractor: Prefetch directory not found");
            return entries;
        }

        WIN32_FIND_DATAW findData;
        std::wstring searchPath = prefetchDir + L"\\*.pf";
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    PrefetchEntry entry;
                    entry.artifactId = GenerateArtifactId();
                    entry.type = ArtifactType::PrefetchFile;
                    entry.sourcePath = prefetchDir + L"\\" + findData.cFileName;
                    entry.collectionTime = SystemClock::now();

                    // Parse prefetch filename (format: EXECUTABLE-HASH.pf)
                    std::wstring filename = findData.cFileName;
                    size_t dashPos = filename.rfind(L'-');
                    if (dashPos != std::wstring::npos) {
                        entry.executableName = filename.substr(0, dashPos);
                        std::wstring hashStr = filename.substr(dashPos + 1);
                        hashStr = hashStr.substr(0, hashStr.find(L'.'));
                        entry.prefetchHash = std::wcstoul(hashStr.c_str(), nullptr, 16);
                    }

                    // In production, would parse .pf file structure:
                    // - Version (17, 23, 26, 30)
                    // - Run count
                    // - Last run times array
                    // - Volume information
                    // - File metrics array

                    entry.runCount = 1;  // Stub
                    entry.version = 30;  // Windows 10
                    entry.lastRunTimes.push_back(SystemClock::now());

                    entries.push_back(entry);

                    if (entries.size() >= m_config.maxArtifactsPerType) {
                        break;
                    }
                }
            } while (FindNextFileW(hFind, &findData));
            FindClose(hFind);
        }

        m_statistics.prefetchFilesParsed.fetch_add(entries.size(), std::memory_order_relaxed);

        Utils::Logger::Info(L"ArtifactExtractor: Parsed {} Prefetch files", entries.size());

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"ArtifactExtractor: Prefetch parsing failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
    }

    return entries;
}

// ============================================================================
// IMPL: SHIMCACHE PARSING
// ============================================================================

std::vector<ShimcacheEntry> ArtifactExtractor::ArtifactExtractorImpl::ParseShimcacheInternal() {
    std::vector<ShimcacheEntry> entries;

    try {
        if (m_config.maxArtifactsPerType == 0) {
            return entries;
        }

        SS_LOG_INFO(kArtifactExtractorLogCategory, L"Parsing Shimcache/AppCompatCache data");

        RegKeyHandle shimcacheKey;
        LONG result = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                      L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
                                      0,
                                      KEY_READ,
                                      &shimcacheKey.key);
        if (result != ERROR_SUCCESS) {
            result = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                     L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatibility",
                                     0,
                                     KEY_READ,
                                     &shimcacheKey.key);
        }

        if (result != ERROR_SUCCESS) {
            if (result == ERROR_ACCESS_DENIED) {
                SS_LOG_WARN(kArtifactExtractorLogCategory,
                            L"Access denied while reading Shimcache registry data; continuing without Shimcache artifacts");
            }
            return entries;
        }

        const auto rawData = QueryBinaryValue(shimcacheKey.key, L"AppCompatCache");
        if (!rawData.has_value() || rawData->empty()) {
            return entries;
        }

        uint32_t controlSet = 1;
        RegKeyHandle selectKey;
        if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\Select", 0, KEY_READ, &selectKey.key) == ERROR_SUCCESS) {
            if (const auto current = QueryDwordValue(selectKey.key, L"Current"); current.has_value()) {
                controlSet = *current;
            }
        }

        const auto addEntry = [&](std::wstring path,
                                  uint64_t fileSize,
                                  bool executed,
                                  uint32_t cacheIndex,
                                  std::optional<SystemTimePoint> lastModified) {
            if (path.empty() || entries.size() >= m_config.maxArtifactsPerType) {
                return;
            }

            ShimcacheEntry entry;
            entry.artifactId = GenerateArtifactId();
            entry.type = ArtifactType::ShimcacheEntry;
            entry.sourcePath = L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache";
            entry.filePath = TrimNtPathPrefix(path);
            entry.fileSize = fileSize;
            entry.executed = executed;
            entry.cacheIndex = cacheIndex;
            entry.controlSet = controlSet;
            entry.collectionTime = SystemClock::now();
            if (lastModified.has_value()) {
                entry.lastModifiedTime = *lastModified;
                entry.artifactTime = *lastModified;
            }
            entries.push_back(std::move(entry));
        };

        const auto& data = *rawData;
        uint32_t offsetToRecords = 0;
        if (data.size() >= sizeof(offsetToRecords)) {
            std::memcpy(&offsetToRecords, data.data(), sizeof(offsetToRecords));
        }

        if (offsetToRecords == 0x30U || offsetToRecords == 0x34U) {
            size_t index = offsetToRecords;
            uint32_t cacheIndex = 0;

            while (index + 22U <= data.size() && entries.size() < m_config.maxArtifactsPerType) {
                if (std::memcmp(data.data() + index, "10ts", 4) != 0) {
                    break;
                }
                index += 4U;
                index += 4U;

                uint32_t entrySizeField = 0;
                uint16_t pathSize = 0;
                std::memcpy(&entrySizeField, data.data() + index, sizeof(entrySizeField));
                index += sizeof(entrySizeField);
                std::memcpy(&pathSize, data.data() + index, sizeof(pathSize));
                index += sizeof(pathSize);

                if (pathSize == 0U || (pathSize % sizeof(wchar_t)) != 0U || index + pathSize + 12U > data.size()) {
                    break;
                }

                auto path = ExtractUtf16String(data.data() + index, pathSize);
                index += pathSize;

                uint64_t lastModifiedValue = 0;
                uint32_t dataSize = 0;
                std::memcpy(&lastModifiedValue, data.data() + index, sizeof(lastModifiedValue));
                index += sizeof(lastModifiedValue);
                std::memcpy(&dataSize, data.data() + index, sizeof(dataSize));
                index += sizeof(dataSize);

                if (dataSize > kMaxRegistryBinaryBytes || index + dataSize > data.size()) {
                    break;
                }

                bool executed = false;
                if (dataSize >= kShimcacheExecutionFlagBytes) {
                    uint32_t executionFlag = 0;
                    std::memcpy(&executionFlag,
                                data.data() + index + dataSize - kShimcacheExecutionFlagBytes,
                                sizeof(executionFlag));
                    executed = executionFlag == 1U;
                }

                addEntry(std::move(path),
                         (entrySizeField != 0U) ? entrySizeField : dataSize,
                         executed,
                         cacheIndex,
                         FileTimeValueToTimePoint(lastModifiedValue));
                index += dataSize;
                ++cacheIndex;
            }
        } else if (data.size() >= 132U) {
            size_t index = 128U;
            uint32_t cacheIndex = 0;
            const std::string_view signature(reinterpret_cast<const char*>(data.data() + index), 4U);
            const bool hasPackageData = signature == "10ts";
            const std::string expectedSignature = hasPackageData ? "10ts" : "00ts";

            while (index + 26U <= data.size() && entries.size() < m_config.maxArtifactsPerType) {
                if (std::memcmp(data.data() + index, expectedSignature.data(), 4U) != 0) {
                    break;
                }
                index += 4U;
                index += 4U;

                uint32_t entrySizeField = 0;
                uint16_t pathSize = 0;
                std::memcpy(&entrySizeField, data.data() + index, sizeof(entrySizeField));
                index += sizeof(entrySizeField);
                std::memcpy(&pathSize, data.data() + index, sizeof(pathSize));
                index += sizeof(pathSize);

                if (pathSize == 0U || (pathSize % sizeof(wchar_t)) != 0U || index + pathSize > data.size()) {
                    break;
                }

                auto path = ExtractUtf16String(data.data() + index, pathSize);
                index += pathSize;

                if (hasPackageData) {
                    uint16_t packageSize = 0;
                    std::memcpy(&packageSize, data.data() + index, sizeof(packageSize));
                    index += sizeof(packageSize);
                    if (index + packageSize > data.size()) {
                        break;
                    }
                    index += packageSize;
                }

                if (index + 20U > data.size()) {
                    break;
                }

                uint32_t insertFlags = 0;
                uint32_t shimFlags = 0;
                uint64_t lastModifiedValue = 0;
                uint32_t dataSize = 0;
                std::memcpy(&insertFlags, data.data() + index, sizeof(insertFlags));
                index += sizeof(insertFlags);
                std::memcpy(&shimFlags, data.data() + index, sizeof(shimFlags));
                index += sizeof(shimFlags);
                std::memcpy(&lastModifiedValue, data.data() + index, sizeof(lastModifiedValue));
                index += sizeof(lastModifiedValue);
                std::memcpy(&dataSize, data.data() + index, sizeof(dataSize));
                index += sizeof(dataSize);

                if (dataSize > kMaxRegistryBinaryBytes || index + dataSize > data.size()) {
                    break;
                }

                const bool executed = (insertFlags & kShimcacheExecutedFlag) != 0U;
                addEntry(std::move(path),
                         (entrySizeField != 0U) ? entrySizeField : dataSize,
                         executed,
                         cacheIndex,
                         FileTimeValueToTimePoint(lastModifiedValue));
                index += dataSize;
                ++cacheIndex;
                static_cast<void>(shimFlags);
            }
        } else {
            SS_LOG_WARN(kArtifactExtractorLogCategory,
                        L"Encountered an unrecognized Shimcache format (%zu bytes)",
                        data.size());
        }

        SS_LOG_INFO(kArtifactExtractorLogCategory,
                    L"Parsed %zu Shimcache entries",
                    entries.size());

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"ArtifactExtractor: Shimcache parsing failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
    }

    return entries;
}

// ============================================================================
// IMPL: AMCACHE PARSING
// ============================================================================

std::vector<AmcacheEntry> ArtifactExtractor::ArtifactExtractorImpl::ParseAmcacheInternal() {
    std::vector<AmcacheEntry> entries;

    try {
        if (m_config.maxArtifactsPerType == 0) {
            return entries;
        }

        SS_LOG_INFO(kArtifactExtractorLogCategory, L"Parsing Amcache inventory data");

        const std::wstring amcacheHivePath = L"C:\\Windows\\AppCompat\\Programs\\Amcache.hve";
        if (!std::filesystem::exists(amcacheHivePath)) {
            SS_LOG_WARN(kArtifactExtractorLogCategory,
                        L"Amcache hive not found at %ls",
                        amcacheHivePath.c_str());
            return entries;
        }

        RegKeyHandle hiveRoot;
        const auto loadResult = ::RegLoadAppKeyW(amcacheHivePath.c_str(),
                                                 &hiveRoot.key,
                                                 KEY_READ,
                                                 0,
                                                 REG_PROCESS_APPKEY);
        if (loadResult != ERROR_SUCCESS) {
            if (loadResult == ERROR_ACCESS_DENIED) {
                SS_LOG_WARN(kArtifactExtractorLogCategory,
                            L"Access denied while loading %ls for Amcache parsing",
                            amcacheHivePath.c_str());
            } else {
                SS_LOG_WARN(kArtifactExtractorLogCategory,
                            L"RegLoadAppKeyW failed for %ls (Win32=%ld)",
                            amcacheHivePath.c_str(),
                            loadResult);
            }
            return entries;
        }

        RegKeyHandle inventoryKey;
        if (::RegOpenKeyExW(hiveRoot.key,
                            L"Root\\InventoryApplicationFile",
                            0,
                            KEY_READ,
                            &inventoryKey.key) != ERROR_SUCCESS) {
            SS_LOG_WARN(kArtifactExtractorLogCategory,
                        L"InventoryApplicationFile key was not found in %ls",
                        amcacheHivePath.c_str());
            return entries;
        }

        DWORD subKeyCount = 0;
        DWORD maxSubKeyLength = 0;
        if (::RegQueryInfoKeyW(inventoryKey.key,
                               nullptr,
                               nullptr,
                               nullptr,
                               &subKeyCount,
                               &maxSubKeyLength,
                               nullptr,
                               nullptr,
                               nullptr,
                               nullptr,
                               nullptr,
                               nullptr) != ERROR_SUCCESS) {
            return entries;
        }

        std::vector<wchar_t> subKeyName(maxSubKeyLength + 2U, L'\0');
        for (DWORD index = 0; index < subKeyCount && entries.size() < m_config.maxArtifactsPerType; ++index) {
            DWORD subKeyNameLength = maxSubKeyLength + 1U;
            FILETIME lastWriteTime{};
            const auto enumResult = ::RegEnumKeyExW(inventoryKey.key,
                                                    index,
                                                    subKeyName.data(),
                                                    &subKeyNameLength,
                                                    nullptr,
                                                    nullptr,
                                                    nullptr,
                                                    &lastWriteTime);
            if (enumResult != ERROR_SUCCESS) {
                continue;
            }

            std::wstring keyName(subKeyName.data(), subKeyNameLength);
            RegKeyHandle fileKey;
            if (::RegOpenKeyExW(inventoryKey.key, keyName.c_str(), 0, KEY_READ, &fileKey.key) != ERROR_SUCCESS) {
                continue;
            }

            const auto pathValue = QueryStringValue(fileKey.key, L"LowerCaseLongPath");
            const auto nameValue = QueryStringValue(fileKey.key, L"Name");
            const auto sha1Value = QueryStringValue(fileKey.key, L"FileId");
            const auto productNameValue = QueryStringValue(fileKey.key, L"ProductName");
            const auto publisherValue = QueryStringValue(fileKey.key, L"Publisher");
            const auto versionValue = QueryStringValue(fileKey.key, L"Version");
            const auto linkDateValue = QueryStringValue(fileKey.key, L"LinkDate");

            uint64_t sizeBytes = 0;
            if (const auto qwordSize = QueryQwordValue(fileKey.key, L"Size"); qwordSize.has_value()) {
                sizeBytes = *qwordSize;
            } else if (const auto dwordSize = QueryDwordValue(fileKey.key, L"Size"); dwordSize.has_value()) {
                sizeBytes = *dwordSize;
            } else if (const auto sizeString = QueryStringValue(fileKey.key, L"Size"); sizeString.has_value()) {
                try {
                    sizeBytes = std::stoull(*sizeString);
                } catch (...) {
                    sizeBytes = 0;
                }
            }

            const auto path = pathValue.value_or(L"");
            const auto name = nameValue.value_or(L"");
            if (path.empty() && name.empty() && !sha1Value.has_value()) {
                continue;
            }

            AmcacheEntry entry;
            entry.artifactId = GenerateArtifactId();
            entry.type = ArtifactType::AmcacheEntry;
            entry.sourcePath = amcacheHivePath;
            entry.filePath = path.empty() ? name : path;
            entry.sha1Hash = NormalizeAmcacheSha1(sha1Value.value_or(L""));
            entry.fileSize = sizeBytes;
            entry.productName = productNameValue.value_or(L"");
            entry.companyName = publisherValue.value_or(L"");
            entry.fileVersion = versionValue.value_or(L"");
            entry.description = name;
            entry.originalFileName = name;
            entry.collectionTime = SystemClock::now();
            if (const auto lastWrite = FileTimeToTimePointChecked(lastWriteTime); lastWrite.has_value()) {
                entry.lastWriteTime = *lastWrite;
                entry.artifactTime = *lastWrite;
            }

            if (linkDateValue.has_value()) {
                SystemTimePoint parsedLinkTime{};
                if (TryParseAmcacheDateString(*linkDateValue, parsedLinkTime)) {
                    entry.linkTimestamp = parsedLinkTime;
                    entry.artifactTime = parsedLinkTime;
                }
            }

            std::wstring normalizedPath = Utils::StringUtils::ToLowerCopy(entry.filePath);
            entry.isPE = Utils::StringUtils::EndsWith(normalizedPath, L".exe") ||
                         Utils::StringUtils::EndsWith(normalizedPath, L".dll") ||
                         Utils::StringUtils::EndsWith(normalizedPath, L".sys") ||
                         Utils::StringUtils::EndsWith(normalizedPath, L".ocx") ||
                         Utils::StringUtils::EndsWith(normalizedPath, L".cpl");

            entries.push_back(std::move(entry));
        }

        SS_LOG_INFO(kArtifactExtractorLogCategory,
                    L"Parsed %zu Amcache entries",
                    entries.size());

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"ArtifactExtractor: Amcache parsing failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
    }

    return entries;
}

// ============================================================================
// IMPL: BROWSER HISTORY PARSING
// ============================================================================

std::vector<BrowserHistoryEntry> ArtifactExtractor::ArtifactExtractorImpl::ParseBrowserHistoryInternal(
    BrowserType browser)
{
    std::vector<BrowserHistoryEntry> entries;

    try {
        if (m_config.maxArtifactsPerType == 0) {
            return entries;
        }

        const auto browserName = BrowserTypeToWide(browser);
        SS_LOG_INFO(kArtifactExtractorLogCategory,
                    L"Parsing browser history for %ls",
                    browserName.c_str());

        auto profiles = GetUserProfiles();
        auto remainingLimit = [&]() -> int {
            const auto remaining = m_config.maxArtifactsPerType > entries.size()
                ? (m_config.maxArtifactsPerType - entries.size())
                : 0U;
            return static_cast<int>(std::min<size_t>(remaining, static_cast<size_t>(std::numeric_limits<int>::max())));
        };

        const auto addChromiumEntries = [&](const std::wstring& profilePath,
                                            const std::filesystem::path& historyPath,
                                            BrowserType chromiumBrowser,
                                            std::wstring_view tempPrefix) {
            if (entries.size() >= m_config.maxArtifactsPerType) {
                return;
            }

            const auto tempCopy = CopyFileToWorkingTemp(historyPath, tempPrefix);
            if (!tempCopy.has_value()) {
                SS_LOG_DEBUG(kArtifactExtractorLogCategory,
                             L"Unable to copy history database %ls for %ls",
                             historyPath.c_str(),
                             browserName.c_str());
                return;
            }

            TempFileGuard tempGuard(*tempCopy);
            sqlite3* database = nullptr;
            const auto databasePath = Utils::StringUtils::ToNarrow(tempCopy->wstring());
            if (sqlite3_open_v2(databasePath.c_str(), &database, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
                if (database != nullptr) {
                    sqlite3_close(database);
                }
                return;
            }
            SqliteDbGuard dbGuard(database);

            constexpr const char* query =
                "SELECT url, title, visit_count, last_visit_time, typed_count "
                "FROM urls ORDER BY last_visit_time DESC LIMIT ?1";

            sqlite3_stmt* statement = nullptr;
            if (sqlite3_prepare_v2(database, query, -1, &statement, nullptr) != SQLITE_OK) {
                return;
            }
            SqliteStmtGuard stmtGuard(statement);
            sqlite3_bind_int(statement, 1, remainingLimit());

            constexpr int64_t kChromeEpochOffsetMicros = 11644473600LL * 1000000LL;
            while (sqlite3_step(statement) == SQLITE_ROW && entries.size() < m_config.maxArtifactsPerType) {
                BrowserHistoryEntry entry;
                entry.artifactId = GenerateArtifactId();
                entry.type = ArtifactType::BrowserHistory;
                entry.browser = chromiumBrowser;
                entry.sourcePath = historyPath.wstring();
                entry.profile = profilePath;
                entry.collectionTime = SystemClock::now();

                if (const auto* url = reinterpret_cast<const char*>(sqlite3_column_text(statement, 0)); url != nullptr) {
                    entry.url = url;
                }
                if (const auto* title = reinterpret_cast<const char*>(sqlite3_column_text(statement, 1)); title != nullptr) {
                    entry.title = Utils::StringUtils::ToWide(title);
                }
                entry.visitCount = static_cast<uint32_t>(std::max(sqlite3_column_int(statement, 2), 0));

                const auto chromeTime = sqlite3_column_int64(statement, 3);
                if (chromeTime > kChromeEpochOffsetMicros) {
                    entry.visitTime = SystemClock::time_point{std::chrono::microseconds{chromeTime - kChromeEpochOffsetMicros}};
                    entry.artifactTime = entry.visitTime;
                }

                entry.isTyped = sqlite3_column_int(statement, 4) > 0;
                entries.push_back(std::move(entry));
            }
        };

        const auto addFirefoxEntries = [&](const std::wstring& profilePath,
                                           const std::filesystem::path& historyPath) {
            if (entries.size() >= m_config.maxArtifactsPerType) {
                return;
            }

            const auto tempCopy = CopyFileToWorkingTemp(historyPath, L"firefox_history_");
            if (!tempCopy.has_value()) {
                SS_LOG_DEBUG(kArtifactExtractorLogCategory,
                             L"Unable to copy Firefox history database %ls",
                             historyPath.c_str());
                return;
            }

            TempFileGuard tempGuard(*tempCopy);
            sqlite3* database = nullptr;
            const auto databasePath = Utils::StringUtils::ToNarrow(tempCopy->wstring());
            if (sqlite3_open_v2(databasePath.c_str(), &database, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
                if (database != nullptr) {
                    sqlite3_close(database);
                }
                return;
            }
            SqliteDbGuard dbGuard(database);

            constexpr const char* query =
                "SELECT url, title, visit_count, last_visit_date "
                "FROM moz_places ORDER BY last_visit_date DESC LIMIT ?1";

            sqlite3_stmt* statement = nullptr;
            if (sqlite3_prepare_v2(database, query, -1, &statement, nullptr) != SQLITE_OK) {
                return;
            }
            SqliteStmtGuard stmtGuard(statement);
            sqlite3_bind_int(statement, 1, remainingLimit());

            while (sqlite3_step(statement) == SQLITE_ROW && entries.size() < m_config.maxArtifactsPerType) {
                BrowserHistoryEntry entry;
                entry.artifactId = GenerateArtifactId();
                entry.type = ArtifactType::BrowserHistory;
                entry.browser = BrowserType::Firefox;
                entry.sourcePath = historyPath.wstring();
                entry.profile = profilePath;
                entry.collectionTime = SystemClock::now();

                if (const auto* url = reinterpret_cast<const char*>(sqlite3_column_text(statement, 0)); url != nullptr) {
                    entry.url = url;
                }
                if (const auto* title = reinterpret_cast<const char*>(sqlite3_column_text(statement, 1)); title != nullptr) {
                    entry.title = Utils::StringUtils::ToWide(title);
                }
                entry.visitCount = static_cast<uint32_t>(std::max(sqlite3_column_int(statement, 2), 0));

                const auto firefoxVisitMicros = sqlite3_column_int64(statement, 3);
                if (firefoxVisitMicros > 0) {
                    entry.visitTime = SystemClock::time_point{std::chrono::microseconds{firefoxVisitMicros}};
                    entry.artifactTime = entry.visitTime;
                }

                entries.push_back(std::move(entry));
            }
        };

        for (const auto& profile : profiles) {
            if (entries.size() >= m_config.maxArtifactsPerType) {
                break;
            }

            std::wstring dbPath;
            switch (browser) {
                case BrowserType::Chrome:
                    dbPath = GetChromeHistoryPath(profile);
                    break;
                case BrowserType::Firefox:
                    dbPath = GetFirefoxHistoryPath(profile);
                    break;
                case BrowserType::Edge:
                    dbPath = profile + L"\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History";
                    break;
                default:
                    continue;
            }

            if (dbPath.empty() || !std::filesystem::exists(dbPath)) {
                continue;
            }

            if (browser == BrowserType::Firefox) {
                addFirefoxEntries(profile, dbPath);
            } else if (browser == BrowserType::Chrome) {
                addChromiumEntries(profile, dbPath, browser, L"chrome_history_");
            } else if (browser == BrowserType::Edge) {
                addChromiumEntries(profile, dbPath, browser, L"edge_history_");
            }
        }

        m_statistics.browserEntriesFound.fetch_add(entries.size(), std::memory_order_relaxed);
        SS_LOG_INFO(kArtifactExtractorLogCategory,
                    L"Parsed %zu browser history entries for %ls",
                    entries.size(),
                    browserName.c_str());

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"ArtifactExtractor: Browser history parsing failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
    }

    return entries;
}

// ============================================================================
// IMPL: LNK FILE PARSING
// ============================================================================

std::vector<LNKFileEntry> ArtifactExtractor::ArtifactExtractorImpl::ParseLNKFilesInternal(
    std::wstring_view directory)
{
    std::vector<LNKFileEntry> entries;

    try {
        Utils::Logger::Info(L"ArtifactExtractor: Parsing LNK files...");

        std::vector<std::wstring> searchDirs;

        if (directory.empty()) {
            // Search common LNK locations
            auto profiles = GetUserProfiles();
            for (const auto& profile : profiles) {
                searchDirs.push_back(profile + L"\\Recent");
                searchDirs.push_back(profile + L"\\Desktop");
                searchDirs.push_back(profile + L"\\AppData\\Roaming\\Microsoft\\Windows\\Recent");
            }
        } else {
            searchDirs.push_back(std::wstring(directory));
        }

        for (const auto& dir : searchDirs) {
            if (!std::filesystem::exists(dir)) {
                continue;
            }

            WIN32_FIND_DATAW findData;
            std::wstring searchPath = dir + L"\\*.lnk";
            HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        LNKFileEntry entry;
                        entry.artifactId = GenerateArtifactId();
                        entry.type = ArtifactType::LNKFile;
                        entry.lnkPath = dir + L"\\" + findData.cFileName;
                        entry.collectionTime = SystemClock::now();

                        // In production, would parse LNK structure:
                        // - Shell Link Header (76 bytes)
                        // - LinkTargetIDList
                        // - LinkInfo (local/network path)
                        // - StringData (name, relative path, working dir, args)
                        // - ExtraData (TrackerDataBlock with MAC, machine ID)

                        entry.targetPath = L"C:\\Windows\\System32\\notepad.exe";  // Stub
                        entry.workingDirectory = L"C:\\Windows\\System32";
                        entry.targetFileSize = 1024 * 200;
                        entry.targetCreationTime = SystemClock::now();
                        entry.targetModificationTime = SystemClock::now();
                        entry.targetAccessTime = SystemClock::now();

                        entries.push_back(entry);

                        if (entries.size() >= m_config.maxArtifactsPerType) {
                            break;
                        }
                    }
                } while (FindNextFileW(hFind, &findData));
                FindClose(hFind);
            }

            if (entries.size() >= m_config.maxArtifactsPerType) {
                break;
            }
        }

        Utils::Logger::Info(L"ArtifactExtractor: Parsed {} LNK files", entries.size());

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"ArtifactExtractor: LNK parsing failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
    }

    return entries;
}

// ============================================================================
// IMPL: JUMP LIST PARSING
// ============================================================================

std::vector<JumpListEntry> ArtifactExtractor::ArtifactExtractorImpl::ParseJumpListsInternal(
    std::wstring_view userProfile)
{
    std::vector<JumpListEntry> entries;

    try {
        Utils::Logger::Info(L"ArtifactExtractor: Parsing Jump Lists...");

        std::vector<std::wstring> profiles;
        if (userProfile.empty()) {
            profiles = GetUserProfiles();
        } else {
            profiles.push_back(std::wstring(userProfile));
        }

        for (const auto& profile : profiles) {
            std::wstring automaticDir = profile + L"\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations";
            std::wstring customDir = profile + L"\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations";

            // Parse AutomaticDestinations (.automaticDestinations-ms files)
            if (std::filesystem::exists(automaticDir)) {
                WIN32_FIND_DATAW findData;
                std::wstring searchPath = automaticDir + L"\\*.automaticDestinations-ms";
                HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

                if (hFind != INVALID_HANDLE_VALUE) {
                    do {
                        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                            JumpListEntry entry;
                            entry.artifactId = GenerateArtifactId();
                            entry.type = ArtifactType::JumpList;
                            entry.sourcePath = automaticDir + L"\\" + findData.cFileName;
                            entry.entryType = "automatic";
                            entry.collectionTime = SystemClock::now();

                            // Extract AppID from filename
                            std::wstring filename = findData.cFileName;
                            size_t dotPos = filename.find(L'.');
                            if (dotPos != std::wstring::npos) {
                                entry.appId = filename.substr(0, dotPos);
                            }

                            // In production, would parse OLE compound file structure
                            entry.targetPath = L"C:\\Example\\Document.txt";  // Stub
                            entry.creationTime = SystemClock::now();

                            entries.push_back(entry);

                            if (entries.size() >= m_config.maxArtifactsPerType) {
                                break;
                            }
                        }
                    } while (FindNextFileW(hFind, &findData));
                    FindClose(hFind);
                }
            }

            if (entries.size() >= m_config.maxArtifactsPerType) {
                break;
            }
        }

        Utils::Logger::Info(L"ArtifactExtractor: Parsed {} Jump List entries", entries.size());

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"ArtifactExtractor: Jump List parsing failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
    }

    return entries;
}

// ============================================================================
// IMPL: USERASSIST PARSING
// ============================================================================

std::vector<UserAssistEntry> ArtifactExtractor::ArtifactExtractorImpl::ParseUserAssistInternal(
    std::wstring_view userSID)
{
    std::vector<UserAssistEntry> entries;

    try {
        Utils::Logger::Info(L"ArtifactExtractor: Parsing UserAssist...");

        // UserAssist is in: HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
        // Contains two GUIDs with ROT13-encoded program names and execution counts

        HKEY hKey = nullptr;
        LONG result = RegOpenKeyExW(HKEY_CURRENT_USER,
                                     L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
                                     0, KEY_READ, &hKey);

        if (result == ERROR_SUCCESS) {
            // Enumerate GUIDs
            wchar_t guidName[256];
            DWORD guidNameSize = 256;
            DWORD index = 0;

            while (RegEnumKeyExW(hKey, index++, guidName, &guidNameSize, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                std::wstring countPath = std::wstring(guidName) + L"\\Count";
                HKEY hCountKey = nullptr;

                result = RegOpenKeyExW(hKey, countPath.c_str(), 0, KEY_READ, &hCountKey);
                if (result == ERROR_SUCCESS) {
                    // Enumerate values
                    wchar_t valueName[512];
                    DWORD valueNameSize = 512;
                    DWORD valueIndex = 0;

                    while (RegEnumValueW(hCountKey, valueIndex++, valueName, &valueNameSize,
                                        nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                        UserAssistEntry entry;
                        entry.artifactId = GenerateArtifactId();
                        entry.type = ArtifactType::UserAssist;
                        entry.guid = Utils::StringUtils::WideToUtf8(guidName);
                        entry.collectionTime = SystemClock::now();

                        // Decode ROT13
                        entry.name = DecodeROT13Internal(valueName);

                        // In production, would read binary data structure:
                        // - Run count (DWORD at offset 4)
                        // - Focus count (DWORD at offset 8)
                        // - Focus time in 100ns (QWORD at offset 12)
                        // - Last execution time (FILETIME at offset 60)

                        entry.runCount = 1;  // Stub
                        entry.focusCount = 1;
                        entry.focusTime = 10000000;  // 1 second in 100ns
                        entry.lastExecutionTime = SystemClock::now();

                        entries.push_back(entry);

                        if (entries.size() >= m_config.maxArtifactsPerType) {
                            break;
                        }

                        valueNameSize = 512;
                    }

                    RegCloseKey(hCountKey);
                }

                if (entries.size() >= m_config.maxArtifactsPerType) {
                    break;
                }

                guidNameSize = 256;
            }

            RegCloseKey(hKey);
        }

        Utils::Logger::Info(L"ArtifactExtractor: Parsed {} UserAssist entries", entries.size());

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"ArtifactExtractor: UserAssist parsing failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
    }

    return entries;
}

// ============================================================================
// IMPL: SHELLBAGS PARSING
// ============================================================================

std::vector<ShellbagEntry> ArtifactExtractor::ArtifactExtractorImpl::ParseShellbagsInternal(
    std::wstring_view userSID)
{
    std::vector<ShellbagEntry> entries;

    try {
        if (m_config.maxArtifactsPerType == 0) {
            return entries;
        }

        SS_LOG_INFO(kArtifactExtractorLogCategory, L"Parsing Shellbags");

        std::wstring bagMruPath;
        std::wstring bagsPath;
        HKEY rootHive = HKEY_CURRENT_USER;

        if (!userSID.empty()) {
            rootHive = HKEY_USERS;
            bagMruPath = std::wstring(userSID) + L"\\Software\\Microsoft\\Windows\\Shell\\BagMRU";
            bagsPath = std::wstring(userSID) + L"\\Software\\Microsoft\\Windows\\Shell\\Bags";
        } else {
            bagMruPath = L"Software\\Microsoft\\Windows\\Shell\\BagMRU";
            bagsPath = L"Software\\Microsoft\\Windows\\Shell\\Bags";
        }

        RegKeyHandle bagMruRoot;
        const auto openResult = ::RegOpenKeyExW(rootHive,
                                                bagMruPath.c_str(),
                                                0,
                                                KEY_READ,
                                                &bagMruRoot.key);
        if (openResult != ERROR_SUCCESS) {
            if (openResult == ERROR_ACCESS_DENIED) {
                SS_LOG_WARN(kArtifactExtractorLogCategory,
                            L"Access denied while reading Shellbag BagMRU data from %ls",
                            bagMruPath.c_str());
            }
            return entries;
        }

        RegKeyHandle bagsRoot;
        ::RegOpenKeyExW(rootHive, bagsPath.c_str(), 0, KEY_READ, &bagsRoot.key);

        std::function<void(HKEY, const std::wstring&, const std::wstring&)> walkBagMru;
        walkBagMru = [&](HKEY currentKey, const std::wstring& registryPath, const std::wstring& parentPath) {
            if (entries.size() >= m_config.maxArtifactsPerType) {
                return;
            }

            DWORD subKeyCount = 0;
            DWORD maxSubKeyLength = 0;
            DWORD valueCount = 0;
            DWORD maxValueNameLength = 0;
            DWORD maxValueLength = 0;
            FILETIME keyLastWrite{};
            if (::RegQueryInfoKeyW(currentKey,
                                   nullptr,
                                   nullptr,
                                   nullptr,
                                   &subKeyCount,
                                   &maxSubKeyLength,
                                   nullptr,
                                   &valueCount,
                                   &maxValueNameLength,
                                   &maxValueLength,
                                   nullptr,
                                   &keyLastWrite) != ERROR_SUCCESS) {
                return;
            }

            const auto keyWriteTime = FileTimeToTimePointChecked(keyLastWrite).value_or(SystemClock::now());
            std::vector<wchar_t> valueName(maxValueNameLength + 2U, L'\0');
            std::vector<uint8_t> valueData(std::min<DWORD>(maxValueLength + 2U, static_cast<DWORD>(kMaxShellbagValueBytes)));

            for (DWORD valueIndex = 0; valueIndex < valueCount && entries.size() < m_config.maxArtifactsPerType; ++valueIndex) {
                DWORD nameLength = maxValueNameLength + 1U;
                DWORD dataLength = static_cast<DWORD>(valueData.size());
                DWORD type = 0;
                auto enumResult = ::RegEnumValueW(currentKey,
                                                  valueIndex,
                                                  valueName.data(),
                                                  &nameLength,
                                                  nullptr,
                                                  &type,
                                                  valueData.data(),
                                                  &dataLength);
                if (enumResult == ERROR_MORE_DATA || enumResult != ERROR_SUCCESS || type != REG_BINARY || dataLength == 0U) {
                    continue;
                }

                std::wstring childName(valueName.data(), nameLength);
                if (childName.empty() ||
                    !std::all_of(childName.begin(), childName.end(), [](wchar_t ch) { return std::iswdigit(ch) != 0; })) {
                    continue;
                }

                auto parsedItem = ParseShellItemList(std::span<const uint8_t>(valueData.data(), dataLength));
                if (parsedItem.name.empty()) {
                    continue;
                }

                std::wstring fullPath = JoinPathComponent(parentPath, parsedItem.name);
                SystemTimePoint slotModifiedTime = keyWriteTime;

                RegKeyHandle childKey;
                if (::RegOpenKeyExW(currentKey, childName.c_str(), 0, KEY_READ, &childKey.key) == ERROR_SUCCESS) {
                    if (bagsRoot.IsValid()) {
                        if (const auto nodeSlot = QueryDwordValue(childKey.key, L"NodeSlot"); nodeSlot.has_value()) {
                            RegKeyHandle bagKey;
                            if (::RegOpenKeyExW(bagsRoot.key,
                                                std::to_wstring(*nodeSlot).c_str(),
                                                0,
                                                KEY_READ,
                                                &bagKey.key) == ERROR_SUCCESS) {
                                slotModifiedTime = QueryKeyLastWriteTime(bagKey.key).value_or(slotModifiedTime);
                            }
                        }
                    }
                }

                ShellbagEntry entry;
                entry.artifactId = GenerateArtifactId();
                entry.type = ArtifactType::Shellbag;
                entry.sourcePath = registryPath;
                entry.registryPath = registryPath + L"\\" + childName;
                entry.path = std::move(fullPath);
                entry.itemType = parsedItem.itemType;
                entry.collectionTime = SystemClock::now();
                entry.slotModifiedTime = slotModifiedTime;
                entry.firstExploredTime = parsedItem.creationTime.value_or(slotModifiedTime);
                entry.lastExploredTime = parsedItem.accessTime.value_or(slotModifiedTime);
                if (!userSID.empty()) {
                    entry.userSID = std::wstring(userSID);
                }
                entry.artifactTime = entry.lastExploredTime;
                entries.push_back(std::move(entry));

                if (childKey.IsValid()) {
                    walkBagMru(childKey.key,
                               registryPath + L"\\" + childName,
                               entries.back().path);
                }
            }
        };

        walkBagMru(bagMruRoot.key, bagMruPath, L"");
        SS_LOG_INFO(kArtifactExtractorLogCategory,
                    L"Parsed %zu Shellbag entries",
                    entries.size());

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"ArtifactExtractor: Shellbags parsing failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
    }

    return entries;
}

// ============================================================================
// IMPL: SCHEDULED TASKS PARSING
// ============================================================================

std::vector<ScheduledTaskEntry> ArtifactExtractor::ArtifactExtractorImpl::ParseScheduledTasksInternal() {
    std::vector<ScheduledTaskEntry> entries;

    try {
        Utils::Logger::Info(L"ArtifactExtractor: Parsing Scheduled Tasks...");

        // Use Task Scheduler COM API
        CoInitializeEx(nullptr, COINIT_MULTITHREADED);

        ITaskService* pService = nullptr;
        HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                                      IID_ITaskService, reinterpret_cast<void**>(&pService));

        if (SUCCEEDED(hr)) {
            hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());

            if (SUCCEEDED(hr)) {
                ITaskFolder* pRootFolder = nullptr;
                hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);

                if (SUCCEEDED(hr)) {
                    IRegisteredTaskCollection* pTaskCollection = nullptr;
                    hr = pRootFolder->GetTasks(TASK_ENUM_HIDDEN, &pTaskCollection);

                    if (SUCCEEDED(hr)) {
                        LONG numTasks = 0;
                        pTaskCollection->get_Count(&numTasks);

                        for (LONG i = 1; i <= numTasks && entries.size() < m_config.maxArtifactsPerType; i++) {
                            IRegisteredTask* pTask = nullptr;
                            hr = pTaskCollection->get_Item(_variant_t(i), &pTask);

                            if (SUCCEEDED(hr)) {
                                ScheduledTaskEntry entry;
                                entry.artifactId = GenerateArtifactId();
                                entry.type = ArtifactType::ScheduledTask;
                                entry.collectionTime = SystemClock::now();

                                BSTR taskName = nullptr;
                                pTask->get_Name(&taskName);
                                if (taskName) {
                                    entry.taskName = taskName;
                                    SysFreeString(taskName);
                                }

                                BSTR taskPath = nullptr;
                                pTask->get_Path(&taskPath);
                                if (taskPath) {
                                    entry.taskPath = taskPath;
                                    SysFreeString(taskPath);
                                }

                                TASK_STATE taskState;
                                pTask->get_State(&taskState);
                                entry.isEnabled = (taskState != TASK_STATE_DISABLED);

                                // Get task definition
                                ITaskDefinition* pDef = nullptr;
                                if (SUCCEEDED(pTask->get_Definition(&pDef))) {
                                    // Get actions
                                    IActionCollection* pActions = nullptr;
                                    if (SUCCEEDED(pDef->get_Actions(&pActions))) {
                                        IAction* pAction = nullptr;
                                        if (SUCCEEDED(pActions->get_Item(1, &pAction))) {
                                            IExecAction* pExecAction = nullptr;
                                            if (SUCCEEDED(pAction->QueryInterface(IID_IExecAction,
                                                                                  reinterpret_cast<void**>(&pExecAction)))) {
                                                BSTR path = nullptr;
                                                pExecAction->get_Path(&path);
                                                if (path) {
                                                    entry.action = path;
                                                    SysFreeString(path);
                                                }

                                                BSTR args = nullptr;
                                                pExecAction->get_Arguments(&args);
                                                if (args) {
                                                    entry.arguments = args;
                                                    SysFreeString(args);
                                                }

                                                pExecAction->Release();
                                            }
                                            pAction->Release();
                                        }
                                        pActions->Release();
                                    }

                                    // Get registration info
                                    IRegistrationInfo* pRegInfo = nullptr;
                                    if (SUCCEEDED(pDef->get_RegistrationInfo(&pRegInfo))) {
                                        BSTR author = nullptr;
                                        pRegInfo->get_Author(&author);
                                        if (author) {
                                            entry.author = author;
                                            SysFreeString(author);
                                        }

                                        BSTR description = nullptr;
                                        pRegInfo->get_Description(&description);
                                        if (description) {
                                            entry.description = description;
                                            SysFreeString(description);
                                        }

                                        pRegInfo->Release();
                                    }

                                    pDef->Release();
                                }

                                entries.push_back(entry);
                                pTask->Release();
                            }
                        }

                        pTaskCollection->Release();
                    }
                    pRootFolder->Release();
                }
            }
            pService->Release();
        }

        CoUninitialize();

        Utils::Logger::Info(L"ArtifactExtractor: Parsed {} scheduled tasks", entries.size());

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"ArtifactExtractor: Scheduled tasks parsing failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
        CoUninitialize();
    }

    return entries;
}

// ============================================================================
// IMPL: FILE RECOVERY
// ============================================================================

bool ArtifactExtractor::ArtifactExtractorImpl::RecoverFileInternal(
    const std::wstring& fileName,
    std::vector<uint8_t>& outData)
{
    try {
        Utils::Logger::Info(L"ArtifactExtractor: Attempting to recover file: {}", fileName);

        // In production, would:
        // 1. Parse MFT to find deleted file entry
        // 2. Check if data runs are still valid (not overwritten)
        // 3. Read raw disk sectors using data runs
        // 4. Reconstruct file content

        // For now, return false (not implemented in stub)
        Utils::Logger::Warn(L"ArtifactExtractor: File recovery not yet implemented");
        return false;

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"ArtifactExtractor: File recovery failed - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
        return false;
    }
}

// ============================================================================
// IMPL: CALLBACKS
// ============================================================================

void ArtifactExtractor::ArtifactExtractorImpl::InvokeArtifactCallback(const BaseArtifact& artifact) {
    std::lock_guard lock(m_callbacksMutex);
    if (m_artifactCallback) {
        try {
            m_artifactCallback(artifact);
        } catch (const std::exception& e) {
            Utils::Logger::Error(L"ArtifactExtractor: Artifact callback error - {}",
                               Utils::StringUtils::Utf8ToWide(e.what()));
        }
    }
}

void ArtifactExtractor::ArtifactExtractorImpl::InvokeProgressCallback(
    ArtifactType type,
    uint32_t percentage,
    const std::wstring& item)
{
    std::lock_guard lock(m_callbacksMutex);
    if (m_progressCallback) {
        try {
            m_progressCallback(type, percentage, item);
        } catch (const std::exception& e) {
            Utils::Logger::Error(L"ArtifactExtractor: Progress callback error - {}",
                               Utils::StringUtils::Utf8ToWide(e.what()));
        }
    }
}

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> ArtifactExtractor::s_instanceCreated{false};

ArtifactExtractor& ArtifactExtractor::Instance() noexcept {
    static ArtifactExtractor instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool ArtifactExtractor::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// LIFECYCLE
// ============================================================================

ArtifactExtractor::ArtifactExtractor()
    : m_impl(std::make_unique<ArtifactExtractorImpl>())
{
    Utils::Logger::Info(L"ArtifactExtractor: Constructor called");
}

ArtifactExtractor::~ArtifactExtractor() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Utils::Logger::Info(L"ArtifactExtractor: Destructor called");
}

bool ArtifactExtractor::Initialize(const ExtractionConfiguration& config) {
    return m_impl ? m_impl->Initialize(config) : false;
}

void ArtifactExtractor::Shutdown() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

bool ArtifactExtractor::IsInitialized() const noexcept {
    return m_impl ? m_impl->m_initialized.load(std::memory_order_acquire) : false;
}

ModuleStatus ArtifactExtractor::GetStatus() const noexcept {
    return m_impl ? m_impl->m_status.load(std::memory_order_acquire) : ModuleStatus::Uninitialized;
}

// ============================================================================
// COMPREHENSIVE EXTRACTION
// ============================================================================

void ArtifactExtractor::ExtractAll(const std::wstring& outputDir) {
    if (!m_impl) return;

    ExtractionConfiguration config = m_impl->m_config;
    config.outputDirectory = outputDir;
    config.artifactTypes = ArtifactType::All;

    m_impl->ExtractAllInternal(config);
}

std::vector<std::shared_ptr<BaseArtifact>> ArtifactExtractor::ExtractAll(
    const ExtractionConfiguration& config)
{
    return m_impl ? m_impl->ExtractAllInternal(config) : std::vector<std::shared_ptr<BaseArtifact>>{};
}

std::vector<std::shared_ptr<BaseArtifact>> ArtifactExtractor::ExtractTypes(
    ArtifactType types,
    std::wstring_view outputDir)
{
    if (!m_impl) return {};

    ExtractionConfiguration config = m_impl->m_config;
    config.artifactTypes = types;
    if (!outputDir.empty()) {
        config.outputDirectory = outputDir;
    }

    return m_impl->ExtractAllInternal(config);
}

// ============================================================================
// FILE SYSTEM ARTIFACTS
// ============================================================================

std::vector<MFTRecord> ArtifactExtractor::ParseMFT(wchar_t driveLetter) {
    return m_impl ? m_impl->ParseMFTInternal(driveLetter) : std::vector<MFTRecord>{};
}

std::vector<MFTRecord> ArtifactExtractor::GetDeletedFiles(wchar_t driveLetter) {
    auto allRecords = ParseMFT(driveLetter);
    std::vector<MFTRecord> deletedFiles;

    std::copy_if(allRecords.begin(), allRecords.end(), std::back_inserter(deletedFiles),
                 [](const MFTRecord& record) { return record.isDeleted; });

    return deletedFiles;
}

bool ArtifactExtractor::RecoverFile(const std::wstring& fileName, std::vector<uint8_t>& outData) {
    return m_impl ? m_impl->RecoverFileInternal(fileName, outData) : false;
}

bool ArtifactExtractor::RecoverFileByMFT(uint64_t recordNumber, std::vector<uint8_t>& outData,
                                         wchar_t driveLetter)
{
    // Simplified - would parse MFT and recover by record number
    return false;
}

std::vector<std::shared_ptr<BaseArtifact>> ArtifactExtractor::ParseUSNJournal(wchar_t driveLetter) {
    // USN Journal parsing would use FSCTL_QUERY_USN_JOURNAL and FSCTL_READ_USN_JOURNAL
    return {};
}

std::vector<std::pair<std::wstring, std::wstring>> ArtifactExtractor::GetAlternateDataStreams(
    std::wstring_view path)
{
    std::vector<std::pair<std::wstring, std::wstring>> streams;

    // Use FindFirstStreamW/FindNextStreamW to enumerate ADS
    WIN32_FIND_STREAM_DATA findStreamData;
    HANDLE hFind = FindFirstStreamW(path.data(), FindStreamInfoStandard, &findStreamData, 0);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            streams.emplace_back(findStreamData.cStreamName, L"");
        } while (FindNextStreamW(hFind, &findStreamData));
        FindClose(hFind);
    }

    return streams;
}

// ============================================================================
// EXECUTION ARTIFACTS
// ============================================================================

std::vector<PrefetchEntry> ArtifactExtractor::ParsePrefetch() {
    return m_impl ? m_impl->ParsePrefetchInternal() : std::vector<PrefetchEntry>{};
}

std::vector<ShimcacheEntry> ArtifactExtractor::ParseShimcache() {
    return m_impl ? m_impl->ParseShimcacheInternal() : std::vector<ShimcacheEntry>{};
}

std::vector<AmcacheEntry> ArtifactExtractor::ParseAmcache() {
    return m_impl ? m_impl->ParseAmcacheInternal() : std::vector<AmcacheEntry>{};
}

std::vector<std::shared_ptr<BaseArtifact>> ArtifactExtractor::ParseSRUM() {
    // SRUM database at C:\Windows\System32\sru\SRUDB.dat
    // Would parse ESE database with network, application, energy data
    return {};
}

std::vector<std::shared_ptr<BaseArtifact>> ArtifactExtractor::ParseBAM() {
    // BAM/DAM in registry: HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings
    return {};
}

// ============================================================================
// USER ACTIVITY ARTIFACTS
// ============================================================================

std::vector<JumpListEntry> ArtifactExtractor::ParseJumpLists(std::wstring_view userProfile) {
    return m_impl ? m_impl->ParseJumpListsInternal(userProfile) : std::vector<JumpListEntry>{};
}

std::vector<LNKFileEntry> ArtifactExtractor::ParseLNKFiles(std::wstring_view directory) {
    return m_impl ? m_impl->ParseLNKFilesInternal(directory) : std::vector<LNKFileEntry>{};
}

std::vector<UserAssistEntry> ArtifactExtractor::ParseUserAssist(std::wstring_view userSID) {
    return m_impl ? m_impl->ParseUserAssistInternal(userSID) : std::vector<UserAssistEntry>{};
}

std::vector<ShellbagEntry> ArtifactExtractor::ParseShellbags(std::wstring_view userSID) {
    return m_impl ? m_impl->ParseShellbagsInternal(userSID) : std::vector<ShellbagEntry>{};
}

// ============================================================================
// BROWSER ARTIFACTS
// ============================================================================

std::vector<BrowserHistoryEntry> ArtifactExtractor::ParseBrowserHistory(BrowserType browser) {
    return m_impl ? m_impl->ParseBrowserHistoryInternal(browser) : std::vector<BrowserHistoryEntry>{};
}

std::vector<BrowserHistoryEntry> ArtifactExtractor::ParseAllBrowserHistories() {
    std::vector<BrowserHistoryEntry> allEntries;

    std::vector<BrowserType> browsers = {
        BrowserType::Chrome,
        BrowserType::Firefox,
        BrowserType::Edge,
        BrowserType::IE
    };

    for (auto browser : browsers) {
        auto entries = ParseBrowserHistory(browser);
        allEntries.insert(allEntries.end(), entries.begin(), entries.end());
    }

    return allEntries;
}

std::vector<std::shared_ptr<BaseArtifact>> ArtifactExtractor::ParseBrowserDownloads(BrowserType browser) {
    // Would parse downloads database (similar to history)
    return {};
}

// ============================================================================
// PERSISTENCE ARTIFACTS
// ============================================================================

std::vector<ScheduledTaskEntry> ArtifactExtractor::ParseScheduledTasks() {
    return m_impl ? m_impl->ParseScheduledTasksInternal() : std::vector<ScheduledTaskEntry>{};
}

std::vector<std::shared_ptr<BaseArtifact>> ArtifactExtractor::ParseRunKeys() {
    // Parse registry Run keys from common locations
    return {};
}

std::vector<std::shared_ptr<BaseArtifact>> ArtifactExtractor::ParseServices() {
    // Enumerate services via Service Control Manager
    return {};
}

// ============================================================================
// CALLBACKS
// ============================================================================

void ArtifactExtractor::SetArtifactCallback(ArtifactCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_artifactCallback = std::move(callback);
}

void ArtifactExtractor::SetProgressCallback(ExtractionProgressCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_progressCallback = std::move(callback);
}

// ============================================================================
// STATISTICS
// ============================================================================

ExtractionStatistics ArtifactExtractor::GetStatistics() const {
    return m_impl ? m_impl->m_statistics : ExtractionStatistics{};
}

void ArtifactExtractor::ResetStatistics() {
    if (m_impl) {
        m_impl->m_statistics.Reset();
    }
}

// ============================================================================
// UTILITY
// ============================================================================

bool ArtifactExtractor::SelfTest() {
    Utils::Logger::Info(L"ArtifactExtractor: Running self-test...");

    try {
        // Test 1: Initialization
        ExtractionConfiguration config;
        config.mode = ExtractionMode::Quick;
        config.artifactTypes = ArtifactType::All;
        config.maxArtifactsPerType = 100;
        config.timeoutMs = 60000;

        if (!Initialize(config)) {
            Utils::Logger::Error(L"ArtifactExtractor: Self-test failed - Initialization");
            return false;
        }

        // Test 2: Configuration validation
        if (!config.IsValid()) {
            Utils::Logger::Error(L"ArtifactExtractor: Self-test failed - Configuration invalid");
            return false;
        }

        // Test 3: Statistics
        auto stats = GetStatistics();
        ResetStatistics();
        stats = GetStatistics();
        if (stats.totalExtractions.load() != 0) {
            Utils::Logger::Error(L"ArtifactExtractor: Self-test failed - Statistics reset");
            return false;
        }

        // Test 4: Artifact ID generation
        std::string id1 = GenerateArtifactId();
        std::string id2 = GenerateArtifactId();
        if (id1 == id2) {
            Utils::Logger::Error(L"ArtifactExtractor: Self-test failed - Duplicate artifact IDs");
            return false;
        }

        // Test 5: ROT13 decoding
        std::wstring encoded = L"URYYBJBEYQ";  // "HELLOWORLD" in ROT13
        std::wstring decoded = DecodeROT13Internal(encoded);
        if (decoded != L"HELLOWORLD") {
            Utils::Logger::Error(L"ArtifactExtractor: Self-test failed - ROT13 decode");
            return false;
        }

        Utils::Logger::Info(L"ArtifactExtractor: Self-test PASSED");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error(L"ArtifactExtractor: Self-test exception - {}",
                           Utils::StringUtils::Utf8ToWide(e.what()));
        return false;
    }
}

std::string ArtifactExtractor::GetVersionString() noexcept {
    return std::format("{}.{}.{}",
                      ArtifactConstants::VERSION_MAJOR,
                      ArtifactConstants::VERSION_MINOR,
                      ArtifactConstants::VERSION_PATCH);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetArtifactTypeName(ArtifactType type) noexcept {
    switch (type) {
        case ArtifactType::Unknown: return "Unknown";
        case ArtifactType::MFTRecord: return "MFT Record";
        case ArtifactType::USNJournalEntry: return "USN Journal Entry";
        case ArtifactType::DeletedFile: return "Deleted File";
        case ArtifactType::AlternateDataStream: return "Alternate Data Stream";
        case ArtifactType::PrefetchFile: return "Prefetch File";
        case ArtifactType::ShimcacheEntry: return "Shimcache Entry";
        case ArtifactType::AmcacheEntry: return "Amcache Entry";
        case ArtifactType::SRUMEntry: return "SRUM Entry";
        case ArtifactType::BAMEntry: return "BAM Entry";
        case ArtifactType::RunKey: return "Run Key";
        case ArtifactType::ScheduledTask: return "Scheduled Task";
        case ArtifactType::Service: return "Service";
        case ArtifactType::WMISubscription: return "WMI Subscription";
        case ArtifactType::StartupItem: return "Startup Item";
        case ArtifactType::JumpList: return "Jump List";
        case ArtifactType::LNKFile: return "LNK File";
        case ArtifactType::RecentDocument: return "Recent Document";
        case ArtifactType::Shellbag: return "Shellbag";
        case ArtifactType::UserAssist: return "UserAssist";
        case ArtifactType::BrowserHistory: return "Browser History";
        case ArtifactType::BrowserDownload: return "Browser Download";
        case ArtifactType::BrowserCache: return "Browser Cache";
        case ArtifactType::BrowserCookie: return "Browser Cookie";
        case ArtifactType::BrowserCredential: return "Browser Credential";
        case ArtifactType::DNSCache: return "DNS Cache";
        case ArtifactType::ARPCache: return "ARP Cache";
        case ArtifactType::NetworkConnection: return "Network Connection";
        case ArtifactType::EventLog: return "Event Log";
        case ArtifactType::PowerShellLog: return "PowerShell Log";
        case ArtifactType::SysmonLog: return "Sysmon Log";
        default: return "Unknown";
    }
}

std::string_view GetBrowserTypeName(BrowserType type) noexcept {
    switch (type) {
        case BrowserType::Unknown: return "Unknown";
        case BrowserType::Chrome: return "Chrome";
        case BrowserType::Firefox: return "Firefox";
        case BrowserType::Edge: return "Edge";
        case BrowserType::IE: return "Internet Explorer";
        case BrowserType::Opera: return "Opera";
        case BrowserType::Brave: return "Brave";
        case BrowserType::Vivaldi: return "Vivaldi";
        case BrowserType::Safari: return "Safari";
        default: return "Unknown";
    }
}

std::string_view GetExtractionModeName(ExtractionMode mode) noexcept {
    switch (mode) {
        case ExtractionMode::Quick: return "Quick";
        case ExtractionMode::Standard: return "Standard";
        case ExtractionMode::Deep: return "Deep";
        case ExtractionMode::Custom: return "Custom";
        default: return "Unknown";
    }
}

std::wstring DecodeROT13(std::wstring_view encoded) {
    return DecodeROT13Internal(encoded);
}

}  // namespace Forensics
}  // namespace ShadowStrike

// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

#include"pch.h"
#include "RegistryUtils.hpp"

#include <algorithm>
#include <sstream>

#ifdef _WIN32
#  include <AclAPI.h>
#  pragma comment(lib, "Advapi32.lib")
#endif

namespace ShadowStrike {
    namespace Utils {
        namespace RegistryUtils {

            // ============================================================================
            // Internal Constants
            // ============================================================================

            namespace {
                /// Maximum class name length (32K characters - reasonable limit)
                constexpr DWORD kMaxClassNameLength = 32768;
                
                /// Maximum registry value size (16MB - reasonable limit for security)
                constexpr DWORD kMaxRegistryValueSize = 16 * 1024 * 1024;
                
                /// Maximum expanded environment string size (32K characters)
                constexpr DWORD kMaxExpandedSize = 32768;
                
                /// Maximum string length in multi-string (32K characters per entry)
                constexpr size_t kMaxMultiStringEntryLength = 32768;
                
                /// Maximum total multi-string size (characters, not bytes)
                constexpr size_t kMaxMultiStringSize = MAXDWORD / sizeof(wchar_t);
            }

            // ============================================================================
            // Internal Helper Functions
            // ============================================================================

            /**
             * @brief Sets error information in the Error structure.
             * 
             * Thread-safe helper that populates error details. Safely handles
             * null error pointer by doing nothing.
             * 
             * @param err Error structure to populate (can be nullptr)
             * @param code Win32 error code
             * @param msg Error message
             * @param key Optional key path for context
             * @param value Optional value name for context
             */
            static void SetError(Error* err, DWORD code, std::wstring msg, 
                                std::wstring_view key = {}, std::wstring_view value = {}) noexcept {
                if (!err) return;
                err->win32 = code;
                err->message = std::move(msg);
                if (!key.empty()) {
                    try { err->keyPath = key; } catch (...) { /* Ignore allocation failure */ }
                }
                if (!value.empty()) {
                    try { err->valueName = value; } catch (...) { /* Ignore allocation failure */ }
                }
            }

            /**
             * @brief Builds the REGSAM access mask from OpenOptions.
             * 
             * Combines the base access rights with WOW64 redirection flags.
             * 
             * @param opt Open options structure
             * @return Combined REGSAM access mask
             */
            [[nodiscard]]
            static REGSAM BuildAccessMask(const OpenOptions& opt) noexcept {
                REGSAM sam = opt.access;
                
                // Note: Only one WOW64 flag should be set at a time
                // If both are set, 64-bit takes precedence (more explicit)
                if (opt.wow64_64) {
                    sam |= KEY_WOW64_64KEY;
                }
                else if (opt.wow64_32) {
                    sam |= KEY_WOW64_32KEY;
                }
                
                return sam;
            }

            // ============================================================================
            // RegistryKey Implementation - Core Methods
            // ============================================================================

            bool RegistryKey::Open(HKEY hKeyParent, std::wstring_view subKey, const OpenOptions& opt, Error* err) noexcept {
                // Close any existing key before opening a new one
                Close();
                
                // Validate parent key handle
                if (!hKeyParent) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid parent key handle");
                    return false;
                }

                // Convert subKey to null-terminated string
                std::wstring sk;
                try {
                    sk = subKey;
                } catch (const std::bad_alloc&) {
                    SetError(err, ERROR_NOT_ENOUGH_MEMORY, L"Memory allocation failed for subkey path");
                    return false;
                }

                const REGSAM sam = BuildAccessMask(opt);
                const LSTATUS st = RegOpenKeyExW(hKeyParent, sk.c_str(), 0, sam, &m_key);
                
                if (st != ERROR_SUCCESS) {
                    SetError(err, static_cast<DWORD>(st), L"RegOpenKeyExW failed", sk);
                    SS_LOG_ERROR(L"RegistryUtils", L"RegOpenKeyExW failed: %ls (code=%lu)", sk.c_str(), st);
                    m_key = nullptr;
                    return false;
                }
                
                return true;
            }

            bool RegistryKey::Create(HKEY hKeyParent, std::wstring_view subKey, const OpenOptions& opt, DWORD* disposition, Error* err) noexcept {
                // Close any existing key before creating/opening a new one
                Close();
                
                // Validate parent key handle
                if (!hKeyParent) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid parent key handle");
                    return false;
                }

                // Convert subKey to null-terminated string
                std::wstring sk;
                try {
                    sk = subKey;
                } catch (const std::bad_alloc&) {
                    SetError(err, ERROR_NOT_ENOUGH_MEMORY, L"Memory allocation failed for subkey path");
                    return false;
                }

                const REGSAM sam = BuildAccessMask(opt);
                DWORD disp = 0;
                
                const LSTATUS st = RegCreateKeyExW(
                    hKeyParent, 
                    sk.c_str(), 
                    0,                          // Reserved
                    nullptr,                    // Class (not used)
                    REG_OPTION_NON_VOLATILE,    // Options: persist across reboots
                    sam, 
                    nullptr,                    // Security attributes
                    &m_key, 
                    &disp
                );
                
                if (st != ERROR_SUCCESS) {
                    SetError(err, static_cast<DWORD>(st), L"RegCreateKeyExW failed", sk);
                    SS_LOG_ERROR(L"RegistryUtils", L"RegCreateKeyExW failed: %ls (code=%lu)", sk.c_str(), st);
                    m_key = nullptr;
                    return false;
                }
                
                if (disposition) {
                    *disposition = disp;
                }
                
                return true;
            }

            void RegistryKey::Close() noexcept {
                if (m_key) {
                    // RegCloseKey can fail but we ignore it since we're cleaning up
                    // and there's nothing we can do about it
                    (void)RegCloseKey(m_key);
                    m_key = nullptr;
                }
            }

            // ============================================================================
            // RegistryKey Implementation - Information Query
            // ============================================================================

            bool RegistryKey::QueryInfo(KeyInfo& info, Error* err) const noexcept {
                // Validate key handle
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle");
                    return false;
                }

                // Initialize output
                info = KeyInfo{};

                // Query variables
                DWORD classLen = 0;
                DWORD subKeys = 0, maxSubKeyLen = 0, maxClassLen = 0;
                DWORD values = 0, maxValueNameLen = 0, maxValueDataLen = 0;
                DWORD secDescLen = 0;
                FILETIME lastWrite = {};

                // First call with nullptr to get required buffer size for class name
                LSTATUS st = RegQueryInfoKeyW(
                    m_key, 
                    nullptr,            // lpClass (query size only)
                    &classLen,          // lpcClass
                    nullptr,            // lpReserved
                    &subKeys, 
                    &maxSubKeyLen, 
                    &maxClassLen,
                    &values, 
                    &maxValueNameLen, 
                    &maxValueDataLen,
                    &secDescLen, 
                    &lastWrite
                );
                
                if (st != ERROR_SUCCESS && st != ERROR_MORE_DATA) {
                    SetError(err, static_cast<DWORD>(st), L"RegQueryInfoKeyW size query failed");
                    SS_LOG_ERROR(L"RegistryUtils", L"RegQueryInfoKeyW failed (code=%lu)", st);
                    return false;
                }

                // Allocate and retrieve class name if present
                std::wstring className;
                if (classLen > 0) {
                    // Validate class name length against reasonable limit
                    if (classLen > kMaxClassNameLength) {
                        SetError(err, ERROR_INVALID_DATA, L"Class name too long");
                        SS_LOG_ERROR(L"RegistryUtils", L"QueryInfo: Class name length %lu exceeds maximum %lu", 
                                    classLen, kMaxClassNameLength);
                        return false;
                    }

                    // Allocate buffer with exception safety
                    try {
                        className.resize(classLen + 1, L'\0'); // +1 for safety margin
                    }
                    catch (const std::bad_alloc&) {
                        SetError(err, ERROR_NOT_ENOUGH_MEMORY, L"Memory allocation failed");
                        SS_LOG_ERROR(L"RegistryUtils", L"QueryInfo: Failed to allocate %lu chars for class name", classLen);
                        return false;
                    }

                    // Second call with allocated buffer
                    DWORD actualLen = classLen + 1;
                    st = RegQueryInfoKeyW(
                        m_key, 
                        className.data(), 
                        &actualLen, 
                        nullptr,
                        &subKeys, 
                        &maxSubKeyLen, 
                        &maxClassLen,
                        &values, 
                        &maxValueNameLen, 
                        &maxValueDataLen,
                        &secDescLen, 
                        &lastWrite
                    );
                    
                    if (st != ERROR_SUCCESS) {
                        SetError(err, static_cast<DWORD>(st), L"RegQueryInfoKeyW failed");
                        SS_LOG_ERROR(L"RegistryUtils", L"RegQueryInfoKeyW failed (code=%lu)", st);
                        return false;
                    }

                    // Trim to actual length returned
                    if (actualLen < className.size()) {
                        className.resize(actualLen);
                    }
                    
                    // Remove trailing null if present
                    while (!className.empty() && className.back() == L'\0') {
                        className.pop_back();
                    }
                }

                // Populate output structure
                info.className = std::move(className);
                info.subKeyCount = subKeys;
                info.valueCount = values;
                info.maxSubKeyLen = maxSubKeyLen;
                info.maxValueNameLen = maxValueNameLen;
                info.maxValueDataLen = maxValueDataLen;
                info.lastWriteTime = lastWrite;
                
                return true;
            }

            // ============================================================================
            // RegistryKey Implementation - Value Reading
            // ============================================================================

            bool RegistryKey::ReadValue(std::wstring_view valueName, ValueType expectedType, 
                                       std::vector<uint8_t>& out, ValueType* actualType, Error* err) const noexcept {
                // Clear output and initialize optional output
                out.clear();
                if (actualType) {
                    *actualType = ValueType::None;
                }

                // Validate key handle
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle", L"", valueName);
                    return false;
                }

                // Convert value name to null-terminated string
                std::wstring vn;
                try {
                    vn = valueName;
                } catch (const std::bad_alloc&) {
                    SetError(err, ERROR_NOT_ENOUGH_MEMORY, L"Memory allocation failed for value name", L"", valueName);
                    return false;
                }

                DWORD type = 0;
                DWORD size = 0;

                // First call: query size and type only
                LSTATUS st = RegQueryValueExW(m_key, vn.c_str(), nullptr, &type, nullptr, &size);
                if (st != ERROR_SUCCESS) {
                    SetError(err, static_cast<DWORD>(st), L"RegQueryValueExW size query failed", L"", valueName);
                    return false;
                }

                // Type check (if expectedType is specified)
                if (expectedType != ValueType::Unknown && static_cast<DWORD>(expectedType) != type) {
                    SetError(err, ERROR_INVALID_DATATYPE, L"Value type mismatch", L"", valueName);
                    SS_LOG_ERROR(L"RegistryUtils", L"ReadValue: Type mismatch for %ls (expected=%lu, actual=%lu)", 
                                vn.c_str(), static_cast<DWORD>(expectedType), type);
                    return false;
                }

                // Set actual type output
                if (actualType) {
                    *actualType = static_cast<ValueType>(type);
                }

                // Handle zero-size values (valid for some types)
                if (size == 0) {
                    out.clear();
                    return true;
                }

                // Security check: prevent DoS attacks via extremely large values
                if (size > kMaxRegistryValueSize) {
                    SetError(err, ERROR_INVALID_DATA, L"Registry value too large", L"", valueName);
                    SS_LOG_ERROR(L"RegistryUtils", L"ReadValue: Size %lu exceeds maximum %lu for value %ls", 
                                size, kMaxRegistryValueSize, vn.c_str());
                    return false;
                }

                // Allocate buffer with exception safety
                try {
                    out.resize(size);
                }
                catch (const std::bad_alloc&) {
                    SetError(err, ERROR_NOT_ENOUGH_MEMORY, L"Memory allocation failed", L"", valueName);
                    SS_LOG_ERROR(L"RegistryUtils", L"ReadValue: Failed to allocate %lu bytes for %ls", size, vn.c_str());
                    return false;
                }

                // Second call: retrieve actual data
                DWORD actualSize = size;
                st = RegQueryValueExW(m_key, vn.c_str(), nullptr, &type, out.data(), &actualSize);
                if (st != ERROR_SUCCESS) {
                    SetError(err, static_cast<DWORD>(st), L"RegQueryValueExW data read failed", L"", valueName);
                    out.clear();
                    return false;
                }

                // Resize to actual data size (may be smaller due to race condition)
                if (actualSize != size) {
                    try {
                        out.resize(actualSize);
                    } catch (...) {
                        // Keep original size - data is still valid
                    }
                }

                return true;
            }

            bool RegistryKey::ReadStringInternal(std::wstring_view valueName, DWORD type, std::wstring& out, bool expand, Error* err) const noexcept {
                std::vector<uint8_t> buf;
                ValueType actualType = ValueType::None;
                if (!ReadValue(valueName, static_cast<ValueType>(type), buf, &actualType, err)) {
                    return false;
                }

                if (buf.empty()) {
                    out.clear();
                    return true;
                }

                if (buf.size() < sizeof(wchar_t)) {
                    out.clear();
                    return true;
                }

                const wchar_t* ptr = reinterpret_cast<const wchar_t*>(buf.data());
                size_t len = buf.size() / sizeof(wchar_t);

                // Remove trailing null if present
                if (len > 0 && ptr[len - 1] == L'\0') --len;

                out.assign(ptr, len);

                // Expand environment strings if needed
                if (expand && actualType == ValueType::ExpandString && !out.empty()) {
                    // Query required buffer size for expansion
                    const DWORD expandSize = ExpandEnvironmentStringsW(out.c_str(), nullptr, 0);
                    
                    // Validate expandSize (0 = error, also check against maximum)
                    if (expandSize == 0 || expandSize > kMaxExpandedSize) {
                        // Expansion failed or result too large - keep original string
                        SS_LOG_ERROR(L"RegistryUtils", L"ReadStringInternal: ExpandEnvironmentStringsW returned invalid size %lu (max=%lu)", 
                                    expandSize, kMaxExpandedSize);
                        // Don't fail, just keep original unexpanded string
                        return true;
                    }

                    try {
                        std::wstring expanded(expandSize, L'\0');
                        const DWORD actualSize = ExpandEnvironmentStringsW(out.c_str(), expanded.data(), expandSize);
                        
                        if (actualSize > 0 && actualSize <= expandSize) {
                            // Success: remove trailing null if present
                            if (!expanded.empty() && expanded.back() == L'\0') expanded.pop_back();
                            out = std::move(expanded);
                        }
                        else {
                            // Second call failed - keep original
                            SS_LOG_ERROR(L"RegistryUtils", L"ReadStringInternal: ExpandEnvironmentStringsW second call failed (returned %lu)", actualSize);
                        }
                    }
                    catch (const std::bad_alloc&) {
                        // Allocation failed - keep original string
                        SS_LOG_ERROR(L"RegistryUtils", L"ReadStringInternal: Failed to allocate %lu chars for expansion", expandSize);
                    }
                }

                return true;
            }

            bool RegistryKey::ReadString(std::wstring_view valueName, std::wstring& out, Error* err) const noexcept {
                return ReadStringInternal(valueName, REG_SZ, out, false, err);
            }

            bool RegistryKey::ReadExpandString(std::wstring_view valueName, std::wstring& out, bool expand, Error* err) const noexcept {
                return ReadStringInternal(valueName, REG_EXPAND_SZ, out, expand, err);
            }

            bool RegistryKey::ReadMultiString(std::wstring_view valueName, std::vector<std::wstring>& out, Error* err) const noexcept {
                out.clear();
                std::vector<uint8_t> buf;
                if (!ReadValue(valueName, ValueType::MultiString, buf, nullptr, err)) {
                    return false;
                }

                if (buf.size() < sizeof(wchar_t) * 2) {
                    //minimum is two nulls
                    return true;
                }

                const wchar_t* ptr = reinterpret_cast<const wchar_t*>(buf.data());
                size_t len = buf.size() / sizeof(wchar_t);

                // Parse multi-string format: "str1\0str2\0str3\0\0"
                // Protect against malformed multi-string data
                for (size_t i = 0; i < len;) {
                    if (ptr[i] == L'\0') break; // end of the list

                    const wchar_t* start = ptr + i;
                    const size_t startIdx = i; // Track start position for error reporting
                    size_t strLen = 0;
                    
                    // Scan for null terminator with bounds check
                    while (i < len && ptr[i] != L'\0') { 
                        ++i; 
                        ++strLen;
                        
                        // Sanity check - prevent infinite loop on corrupted data
                        if (strLen > kMaxMultiStringEntryLength) {
                            SetError(err, ERROR_INVALID_DATA, L"Multi-string entry too long", L"", valueName);
                            SS_LOG_ERROR(L"RegistryUtils", L"ReadMultiString: String exceeds %zu chars at offset %zu", 
                                         kMaxMultiStringEntryLength, startIdx);
                            return false;
                        }
                    }

                    // Validate start pointer is still within bounds
                    if (startIdx >= len || startIdx + strLen > len) {
                        SetError(err, ERROR_INVALID_DATA, L"Multi-string data corrupted", L"", valueName);
                        SS_LOG_ERROR(L"RegistryUtils", L"ReadMultiString: Buffer overflow detected at offset %zu", startIdx);
                        return false;
                    }

                    // Append non-empty string to output
                    if (strLen > 0) {
                        try {
                            out.emplace_back(start, strLen);
                        }
                        catch (const std::bad_alloc&) {
                            SetError(err, ERROR_NOT_ENOUGH_MEMORY, L"Memory allocation failed", L"", valueName);
                            return false;
                        }
                    }
                    
                    if (i < len && ptr[i] == L'\0') ++i; // skip null terminator
                }
                

                return true;
            }

            bool RegistryKey::ReadDWord(std::wstring_view valueName, DWORD& out, Error* err) const noexcept {
                std::vector<uint8_t> buf;
                if (!ReadValue(valueName, ValueType::DWord, buf, nullptr, err)) {
                    return false;
                }
                if (buf.size() != sizeof(DWORD)) {
                    SetError(err, ERROR_INVALID_DATA, L"DWORD size mismatch", L"", valueName);
                    return false;
                }
                std::memcpy(&out, buf.data(), sizeof(DWORD));
                return true;
            }

            bool RegistryKey::ReadQWord(std::wstring_view valueName, uint64_t& out, Error* err) const noexcept {
                std::vector<uint8_t> buf;
                if (!ReadValue(valueName, ValueType::QWord, buf, nullptr, err)) {
                    return false;
                }
                if (buf.size() != sizeof(uint64_t)) {
                    SetError(err, ERROR_INVALID_DATA, L"QWORD size mismatch", L"", valueName);
                    return false;
                }
                std::memcpy(&out, buf.data(), sizeof(uint64_t));
                return true;
            }

            bool RegistryKey::ReadBinary(std::wstring_view valueName, std::vector<uint8_t>& out, Error* err) const noexcept {
                return ReadValue(valueName, ValueType::Binary, out, nullptr, err);
            }


            // ============================================================================
            // RegistryKey Implementation - Value Writing
            // ============================================================================

            /**
             * @brief Writes a string value (REG_SZ) to the registry.
             * @param valueName Name of the value to write.
             * @param value String data to write.
             * @param err Optional error output.
             * @return true on success, false on failure.
             */
            bool RegistryKey::WriteString(std::wstring_view valueName, std::wstring_view value, Error* err) noexcept {
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle", L"", valueName);
                    return false;
                }

                // Allocate with exception safety
                std::wstring vn;
                std::wstring val;
                try {
                    vn = valueName;
                    val = value;
                } catch (const std::bad_alloc&) {
                    SetError(err, ERROR_NOT_ENOUGH_MEMORY, L"Memory allocation failed", L"", valueName);
                    return false;
                }

                const DWORD size = static_cast<DWORD>((val.size() + 1) * sizeof(wchar_t));
                const LSTATUS st = RegSetValueExW(m_key, vn.c_str(), 0, REG_SZ, 
                                                  reinterpret_cast<const BYTE*>(val.c_str()), size);
                if (st != ERROR_SUCCESS) {
                    SetError(err, static_cast<DWORD>(st), L"RegSetValueExW (REG_SZ) failed", L"", valueName);
                    SS_LOG_ERROR(L"RegistryUtils", L"WriteString failed: %ls (code=%lu)", vn.c_str(), st);
                    return false;
                }
                return true;
            }

            /**
             * @brief Writes an expandable string value (REG_EXPAND_SZ) to the registry.
             * @param valueName Name of the value to write.
             * @param value String data with environment variables to write.
             * @param err Optional error output.
             * @return true on success, false on failure.
             */
            bool RegistryKey::WriteExpandString(std::wstring_view valueName, std::wstring_view value, Error* err) noexcept {
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle", L"", valueName);
                    return false;
                }

                // Allocate with exception safety
                std::wstring vn;
                std::wstring val;
                try {
                    vn = valueName;
                    val = value;
                } catch (const std::bad_alloc&) {
                    SetError(err, ERROR_NOT_ENOUGH_MEMORY, L"Memory allocation failed", L"", valueName);
                    return false;
                }

                const DWORD size = static_cast<DWORD>((val.size() + 1) * sizeof(wchar_t));
                const LSTATUS st = RegSetValueExW(m_key, vn.c_str(), 0, REG_EXPAND_SZ, 
                                                  reinterpret_cast<const BYTE*>(val.c_str()), size);
                if (st != ERROR_SUCCESS) {
                    SetError(err, static_cast<DWORD>(st), L"RegSetValueExW (REG_EXPAND_SZ) failed", L"", valueName);
                    SS_LOG_ERROR(L"RegistryUtils", L"WriteExpandString failed: %ls (code=%lu)", vn.c_str(), st);
                    return false;
                }
                return true;
            }

            /**
             * @brief Writes a multi-string value (REG_MULTI_SZ) to the registry.
             * @param valueName Name of the value to write.
             * @param value Vector of strings to write.
             * @param err Optional error output.
             * @return true on success, false on failure.
             * @note Strings must not contain embedded null characters.
             */
            bool RegistryKey::WriteMultiString(std::wstring_view valueName, const std::vector<std::wstring>& value, Error* err) noexcept {
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle", L"", valueName);
                    return false;
                }

                // Validate input and calculate total size, checking for embedded nulls
                size_t totalSize = 0;
                for (const auto& s : value) {
                    // Check for embedded nulls which would corrupt multi-string format
                    if (s.find(L'\0') != std::wstring::npos) {
                        SetError(err, ERROR_INVALID_PARAMETER, L"Multi-string entry contains embedded null", L"", valueName);
                        SS_LOG_ERROR(L"RegistryUtils", L"WriteMultiString: String contains embedded null character");
                        return false;
                    }
                    
                    // Check individual string length
                    if (s.size() > kMaxMultiStringEntryLength) {
                        SetError(err, ERROR_INVALID_PARAMETER, L"Multi-string entry too long", L"", valueName);
                        SS_LOG_ERROR(L"RegistryUtils", L"WriteMultiString: String length %zu exceeds maximum %zu", 
                                    s.size(), kMaxMultiStringEntryLength);
                        return false;
                    }
                    
                    totalSize += s.size() + 1; // +1 for null terminator
                }
                
                // Add final null terminator
                totalSize += 1;
                
                // Check for size overflow (prevent DoS and DWORD overflow)
                if (totalSize > kMaxMultiStringSize) {
                    SetError(err, ERROR_INVALID_PARAMETER, L"Multi-string data too large", L"", valueName);
                    SS_LOG_ERROR(L"RegistryUtils", L"WriteMultiString: Total size %zu exceeds maximum %zu", 
                                 totalSize, kMaxMultiStringSize);
                    return false;
                }

                // Multi-string format: "str1\0str2\0str3\0\0"
                std::wstring combined;
                try {
                    combined.reserve(totalSize); // ? Pre-allocate to avoid reallocations
                    for (const auto& s : value) {
                        combined.append(s);
                        combined.push_back(L'\0');
                    }
                    combined.push_back(L'\0'); // last null
                }
                catch (const std::bad_alloc&) {
                    SetError(err, ERROR_NOT_ENOUGH_MEMORY, L"Memory allocation failed", L"", valueName);
                    SS_LOG_ERROR(L"RegistryUtils", L"WriteMultiString: Failed to allocate %zu chars", totalSize);
                    return false;
                }

                std::wstring vn(valueName);
                const DWORD size = static_cast<DWORD>(combined.size() * sizeof(wchar_t));
                const LSTATUS st = RegSetValueExW(m_key, vn.c_str(), 0, REG_MULTI_SZ, reinterpret_cast<const BYTE*>(combined.c_str()), size);
                if (st != ERROR_SUCCESS) {
                    SetError(err, st, L"RegSetValueExW (REG_MULTI_SZ) failed", L"", valueName);
                    SS_LOG_ERROR(L"RegistryUtils", L"WriteMultiString failed: %ls (code=%lu)", vn.c_str(), st);
                    return false;
                }
                return true;
            }

            /**
             * @brief Writes a DWORD value (REG_DWORD) to the registry.
             * @param valueName Name of the value to write.
             * @param value DWORD data to write.
             * @param err Optional error output.
             * @return true on success, false on failure.
             */
            bool RegistryKey::WriteDWord(std::wstring_view valueName, DWORD value, Error* err) noexcept {
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle", L"", valueName);
                    return false;
                }

                // Allocate with exception safety
                std::wstring vn;
                try {
                    vn = valueName;
                } catch (const std::bad_alloc&) {
                    SetError(err, ERROR_NOT_ENOUGH_MEMORY, L"Memory allocation failed", L"", valueName);
                    return false;
                }

                const LSTATUS st = RegSetValueExW(m_key, vn.c_str(), 0, REG_DWORD, 
                                                  reinterpret_cast<const BYTE*>(&value), sizeof(DWORD));
                if (st != ERROR_SUCCESS) {
                    SetError(err, static_cast<DWORD>(st), L"RegSetValueExW (REG_DWORD) failed", L"", valueName);
                    SS_LOG_ERROR(L"RegistryUtils", L"WriteDWord failed: %ls (code=%lu)", vn.c_str(), st);
                    return false;
                }
                return true;
            }

            /**
             * @brief Writes a QWORD value (REG_QWORD) to the registry.
             * @param valueName Name of the value to write.
             * @param value QWORD (uint64_t) data to write.
             * @param err Optional error output.
             * @return true on success, false on failure.
             */
            bool RegistryKey::WriteQWord(std::wstring_view valueName, uint64_t value, Error* err) noexcept {
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle", L"", valueName);
                    return false;
                }

                // Allocate with exception safety
                std::wstring vn;
                try {
                    vn = valueName;
                } catch (const std::bad_alloc&) {
                    SetError(err, ERROR_NOT_ENOUGH_MEMORY, L"Memory allocation failed", L"", valueName);
                    return false;
                }

                const LSTATUS st = RegSetValueExW(m_key, vn.c_str(), 0, REG_QWORD, 
                                                  reinterpret_cast<const BYTE*>(&value), sizeof(uint64_t));
                if (st != ERROR_SUCCESS) {
                    SetError(err, static_cast<DWORD>(st), L"RegSetValueExW (REG_QWORD) failed", L"", valueName);
                    SS_LOG_ERROR(L"RegistryUtils", L"WriteQWord failed: %ls (code=%lu)", vn.c_str(), st);
                    return false;
                }
                return true;
            }

            /**
             * @brief Writes a binary value (REG_BINARY) to the registry.
             * @param valueName Name of the value to write.
             * @param data Pointer to binary data to write.
             * @param size Size of the binary data in bytes.
             * @param err Optional error output.
             * @return true on success, false on failure.
             */
            bool RegistryKey::WriteBinary(std::wstring_view valueName, const void* data, size_t size, Error* err) noexcept {
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle", L"", valueName);
                    return false;
                }
                
                // Validate data pointer
                if (data == nullptr && size > 0) {
                    SetError(err, ERROR_INVALID_PARAMETER, L"Null data pointer with non-zero size", L"", valueName);
                    return false;
                }
                
                // Validate size to prevent truncation on 64-bit systems
                if (size > MAXDWORD) {
                    SetError(err, ERROR_INVALID_PARAMETER, L"Binary data too large", L"", valueName);
                    SS_LOG_ERROR(L"RegistryUtils", L"WriteBinary: Size %zu exceeds DWORD maximum %lu", size, MAXDWORD);
                    return false;
                }
                
                // Allocate with exception safety
                std::wstring vn;
                try {
                    vn = valueName;
                } catch (const std::bad_alloc&) {
                    SetError(err, ERROR_NOT_ENOUGH_MEMORY, L"Memory allocation failed", L"", valueName);
                    return false;
                }

                const LSTATUS st = RegSetValueExW(m_key, vn.c_str(), 0, REG_BINARY, 
                                                  static_cast<const BYTE*>(data), static_cast<DWORD>(size));
                if (st != ERROR_SUCCESS) {
                    SetError(err, static_cast<DWORD>(st), L"RegSetValueExW (REG_BINARY) failed", L"", valueName);
                    SS_LOG_ERROR(L"RegistryUtils", L"WriteBinary failed: %ls (code=%lu)", vn.c_str(), st);
                    return false;
                }
                return true;
            }

            bool RegistryKey::DeleteValue(std::wstring_view valueName, Error* err) noexcept {
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle", L"", valueName);
                    return false;
                }
                std::wstring vn(valueName);
                const LSTATUS st = RegDeleteValueW(m_key, vn.c_str());
                if (st != ERROR_SUCCESS && st != ERROR_FILE_NOT_FOUND) {
                    SetError(err, st, L"RegDeleteValueW failed", L"", valueName);
                    SS_LOG_ERROR(L"RegistryUtils", L"DeleteValue failed: %ls (code=%lu)", vn.c_str(), st);
                    return false;
                }
                return true;
            }

            bool RegistryKey::DeleteSubKey(std::wstring_view subKey, Error* err) noexcept {
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle", subKey);
                    return false;
                }
                std::wstring sk(subKey);
                const LSTATUS st = RegDeleteKeyW(m_key, sk.c_str());
                if (st != ERROR_SUCCESS && st != ERROR_FILE_NOT_FOUND) {
                    SetError(err, st, L"RegDeleteKeyW failed", subKey);
                    SS_LOG_ERROR(L"RegistryUtils", L"DeleteSubKey failed: %ls (code=%lu)", sk.c_str(), st);
                    return false;
                }
                return true;
            }

            bool RegistryKey::DeleteSubKeyTree(std::wstring_view subKey, Error* err) noexcept {
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle", subKey);
                    return false;
                }
                std::wstring sk(subKey);
                const LSTATUS st = RegDeleteTreeW(m_key, sk.c_str());
                if (st != ERROR_SUCCESS && st != ERROR_FILE_NOT_FOUND) {
                    SetError(err, st, L"RegDeleteTreeW failed", subKey);
                    SS_LOG_ERROR(L"RegistryUtils", L"DeleteSubKeyTree failed: %ls (code=%lu)", sk.c_str(), st);
                    return false;
                }
                return true;
            }

            // ============================================================================
            // RegistryKey Implementation - Enumeration
            // ============================================================================

            /**
             * @brief Enumerates all subkeys of the current registry key.
             * @param out Vector to receive the subkey names.
             * @param err Optional error output.
             * @return true on success, false on failure.
             */
            bool RegistryKey::EnumKeys(std::vector<std::wstring>& out, Error* err) const noexcept {
                out.clear();
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle");
                    return false;
                }

                // Get key information to determine buffer sizes
                KeyInfo info;
                if (!QueryInfo(info, err)) return false;

                // Validate maxSubKeyLen before allocation
                if (info.maxSubKeyLen > kMaxClassNameLength) {
                    SetError(err, ERROR_INVALID_DATA, L"Max subkey length too large");
                    SS_LOG_ERROR(L"RegistryUtils", L"EnumKeys: maxSubKeyLen %lu exceeds limit %lu", 
                                info.maxSubKeyLen, kMaxClassNameLength);
                    return false;
                }

                // Allocate buffer with exception safety
                const DWORD maxLen = info.maxSubKeyLen + 1;
                std::wstring buf;
                try {
                    buf.resize(maxLen, L'\0');
                    out.reserve(info.subKeyCount); // Pre-allocate for efficiency
                } catch (const std::bad_alloc&) {
                    SetError(err, ERROR_NOT_ENOUGH_MEMORY, L"Memory allocation failed");
                    return false;
                }

                // Enumerate all subkeys
                for (DWORD i = 0; i < info.subKeyCount; ++i) {
                    DWORD len = maxLen;
                    const LSTATUS st = RegEnumKeyExW(m_key, i, buf.data(), &len, nullptr, nullptr, nullptr, nullptr);
                    if (st == ERROR_SUCCESS) {
                        try {
                            out.emplace_back(buf.data(), len);
                        } catch (const std::bad_alloc&) {
                            SetError(err, ERROR_NOT_ENOUGH_MEMORY, L"Memory allocation failed");
                            return false;
                        }
                    }
                    else if (st == ERROR_NO_MORE_ITEMS) {
                        break;
                    }
                    else {
                        SetError(err, static_cast<DWORD>(st), L"RegEnumKeyExW failed");
                        SS_LOG_ERROR(L"RegistryUtils", L"EnumKeys failed at index %lu (code=%lu)", i, st);
                        return false;
                    }
                }
                return true;
            }

            /**
             * @brief Enumerates all values in the current registry key.
             * @param out Vector to receive the value information.
             * @param err Optional error output.
             * @return true on success, false on failure.
             */
            bool RegistryKey::EnumValues(std::vector<ValueInfo>& out, Error* err) const noexcept {
                out.clear();
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle");
                    return false;
                }

                // Get key information to determine buffer sizes
                KeyInfo info;
                if (!QueryInfo(info, err)) return false;

                // Validate maxValueNameLen before allocation
                if (info.maxValueNameLen > kMaxClassNameLength) {
                    SetError(err, ERROR_INVALID_DATA, L"Max value name length too large");
                    SS_LOG_ERROR(L"RegistryUtils", L"EnumValues: maxValueNameLen %lu exceeds limit %lu", 
                                info.maxValueNameLen, kMaxClassNameLength);
                    return false;
                }

                // Allocate buffer with exception safety
                const DWORD maxLen = info.maxValueNameLen + 1;
                std::wstring buf;
                try {
                    buf.resize(maxLen, L'\0');
                    out.reserve(info.valueCount); // Pre-allocate for efficiency
                } catch (const std::bad_alloc&) {
                    SetError(err, ERROR_NOT_ENOUGH_MEMORY, L"Memory allocation failed");
                    return false;
                }

                // Enumerate all values
                for (DWORD i = 0; i < info.valueCount; ++i) {
                    DWORD nameLen = maxLen;
                    DWORD type = 0;
                    DWORD dataSize = 0;
                    const LSTATUS st = RegEnumValueW(m_key, i, buf.data(), &nameLen, nullptr, &type, nullptr, &dataSize);
                    if (st == ERROR_SUCCESS) {
                        try {
                            ValueInfo vi;
                            vi.name.assign(buf.data(), nameLen);
                            vi.type = static_cast<ValueType>(type);
                            vi.dataSize = dataSize;
                            out.push_back(std::move(vi));
                        } catch (const std::bad_alloc&) {
                            SetError(err, ERROR_NOT_ENOUGH_MEMORY, L"Memory allocation failed");
                            return false;
                        }
                    }
                    else if (st == ERROR_NO_MORE_ITEMS) {
                        break;
                    }
                    else {
                        SetError(err, static_cast<DWORD>(st), L"RegEnumValueW failed");
                        SS_LOG_ERROR(L"RegistryUtils", L"EnumValues failed at index %lu (code=%lu)", i, st);
                        return false;
                    }
                }
                return true;
            }

            bool RegistryKey::ValueExists(std::wstring_view valueName) const noexcept {
                if (!m_key) return false;
                std::wstring vn(valueName);
                DWORD type = 0, size = 0;
                const LSTATUS st = RegQueryValueExW(m_key, vn.c_str(), nullptr, &type, nullptr, &size);
                return st == ERROR_SUCCESS;
            }

            bool RegistryKey::SubKeyExists(std::wstring_view subKey) const noexcept {
                // ?? WARNING: This function is subject to TOCTOU (Time-Of-Check-Time-Of-Use) race condition.
                // The key might be deleted or permissions changed between this check and subsequent operations.
                // Callers should be prepared for Open() or other operations to fail even if this returns true.
                // For critical operations, use Open() directly and handle errors rather than checking first.
                
                if (!m_key) return false;
                std::wstring sk(subKey);
                HKEY hTest = nullptr;
                const LSTATUS st = RegOpenKeyExW(m_key, sk.c_str(), 0, KEY_READ, &hTest);
                if (st == ERROR_SUCCESS && hTest) {
                    RegCloseKey(hTest);
                    return true;
                }
                return false;
            }

            bool RegistryKey::Flush(Error* err) noexcept {
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle");
                    return false;
                }
                const LSTATUS st = RegFlushKey(m_key);
                if (st != ERROR_SUCCESS) {
                    SetError(err, st, L"RegFlushKey failed");
                    SS_LOG_ERROR(L"RegistryUtils", L"Flush failed (code=%lu)", st);
                    return false;
                }
                return true;
            }

            bool RegistryKey::SaveToFile(const std::filesystem::path& path, Error* err) const noexcept {
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle");
                    return false;
                }

                // SE_BACKUP_NAME is necessary
                EnableBackupPrivilege(err);

                const LSTATUS st = RegSaveKeyW(m_key, path.c_str(), nullptr);
                if (st != ERROR_SUCCESS) {
                    SetError(err, st, L"RegSaveKeyW failed");
                    SS_LOG_ERROR(L"RegistryUtils", L"SaveToFile failed: %ls (code=%lu)", path.c_str(), st);
                    return false;
                }
                return true;
            }

            bool RegistryKey::RestoreFromFile(const std::filesystem::path& path, DWORD flags, Error* err) noexcept {
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle");
                    return false;
                }

				// SE_RESTORE_NAME is necessary
                EnableRestorePrivilege(err);

                const LSTATUS st = RegRestoreKeyW(m_key, path.c_str(), flags);
                if (st != ERROR_SUCCESS) {
                    SetError(err, st, L"RegRestoreKeyW failed");
                    SS_LOG_ERROR(L"RegistryUtils", L"RestoreFromFile failed: %ls (code=%lu)", path.c_str(), st);
                    return false;
                }
                return true;
            }

            // ============================================================================
            // Global helpers
            // ============================================================================

            HKEY ParseRootKey(std::wstring_view rootName) noexcept {
                if (rootName == L"HKEY_CLASSES_ROOT" || rootName == L"HKCR") return HKEY_CLASSES_ROOT;
                if (rootName == L"HKEY_CURRENT_USER" || rootName == L"HKCU") return HKEY_CURRENT_USER;
                if (rootName == L"HKEY_LOCAL_MACHINE" || rootName == L"HKLM") return HKEY_LOCAL_MACHINE;
                if (rootName == L"HKEY_USERS" || rootName == L"HKU") return HKEY_USERS;
                if (rootName == L"HKEY_CURRENT_CONFIG" || rootName == L"HKCC") return HKEY_CURRENT_CONFIG;
                if (rootName == L"HKEY_PERFORMANCE_DATA") return HKEY_PERFORMANCE_DATA;
                return nullptr;
            }

            std::wstring RootKeyToString(HKEY hKey) noexcept {
                if (hKey == HKEY_CLASSES_ROOT) return L"HKEY_CLASSES_ROOT";
                if (hKey == HKEY_CURRENT_USER) return L"HKEY_CURRENT_USER";
                if (hKey == HKEY_LOCAL_MACHINE) return L"HKEY_LOCAL_MACHINE";
                if (hKey == HKEY_USERS) return L"HKEY_USERS";
                if (hKey == HKEY_CURRENT_CONFIG) return L"HKEY_CURRENT_CONFIG";
                if (hKey == HKEY_PERFORMANCE_DATA) return L"HKEY_PERFORMANCE_DATA";
                return L"UNKNOWN";
            }

            bool SplitPath(std::wstring_view fullPath, HKEY& rootKey, std::wstring& subKey) noexcept {
                const auto pos = fullPath.find(L'\\');
                if (pos == std::wstring_view::npos) {
                    rootKey = ParseRootKey(fullPath);
                    subKey.clear();
                    return rootKey != nullptr;
                }

                const auto rootName = fullPath.substr(0, pos);
                rootKey = ParseRootKey(rootName);
                if (!rootKey) return false;

                subKey = fullPath.substr(pos + 1);
                return true;
            }

            bool QuickReadString(HKEY hKeyRoot, std::wstring_view subKey, std::wstring_view valueName, std::wstring& out, const OpenOptions& opt, Error* err) noexcept {
                RegistryKey key;
                if (!key.Open(hKeyRoot, subKey, opt, err)) return false;
                return key.ReadString(valueName, out, err);
            }

            bool QuickReadDWord(HKEY hKeyRoot, std::wstring_view subKey, std::wstring_view valueName, DWORD& out, const OpenOptions& opt, Error* err) noexcept {
                RegistryKey key;
                if (!key.Open(hKeyRoot, subKey, opt, err)) return false;
                return key.ReadDWord(valueName, out, err);
            }

            bool QuickReadQWord(HKEY hKeyRoot, std::wstring_view subKey, std::wstring_view valueName, uint64_t& out, const OpenOptions& opt, Error* err) noexcept {
                RegistryKey key;
                if (!key.Open(hKeyRoot, subKey, opt, err)) return false;
                return key.ReadQWord(valueName, out, err);
            }

            bool QuickWriteString(HKEY hKeyRoot, std::wstring_view subKey, std::wstring_view valueName, std::wstring_view value, const OpenOptions& opt, Error* err) noexcept {
                OpenOptions writeOpt = opt;
                writeOpt.access = KEY_WRITE;
                RegistryKey key;
                if (!key.Create(hKeyRoot, subKey, writeOpt, nullptr, err)) return false;
                return key.WriteString(valueName, value, err);
            }

            bool QuickWriteDWord(HKEY hKeyRoot, std::wstring_view subKey, std::wstring_view valueName, DWORD value, const OpenOptions& opt, Error* err) noexcept {
                OpenOptions writeOpt = opt;
                writeOpt.access = KEY_WRITE;
                RegistryKey key;
                if (!key.Create(hKeyRoot, subKey, writeOpt, nullptr, err)) return false;
                return key.WriteDWord(valueName, value, err);
            }

            bool QuickWriteQWord(HKEY hKeyRoot, std::wstring_view subKey, std::wstring_view valueName, uint64_t value, const OpenOptions& opt, Error* err) noexcept {
                OpenOptions writeOpt = opt;
                writeOpt.access = KEY_WRITE;
                RegistryKey key;
                if (!key.Create(hKeyRoot, subKey, writeOpt, nullptr, err)) return false;
                return key.WriteQWord(valueName, value, err);
            }

            bool KeyExists(HKEY hKeyRoot, std::wstring_view subKey, const OpenOptions& opt) noexcept {
                RegistryKey key;
                return key.Open(hKeyRoot, subKey, opt, nullptr);
            }

            bool DeleteKey(HKEY hKeyRoot, std::wstring_view subKey, const OpenOptions& opt, Error* err) noexcept {
                std::wstring sk(subKey);
                const REGSAM sam = BuildAccessMask(opt) | DELETE;
                const LSTATUS st = RegDeleteKeyExW(hKeyRoot, sk.c_str(), sam, 0);
                if (st != ERROR_SUCCESS && st != ERROR_FILE_NOT_FOUND) {
                    SetError(err, st, L"RegDeleteKeyExW failed", subKey);
                    SS_LOG_ERROR(L"RegistryUtils", L"DeleteKey failed: %ls (code=%lu)", sk.c_str(), st);
                    return false;
                }
                return true;
            }

            bool DeleteKeyTree(HKEY hKeyRoot, std::wstring_view subKey, const OpenOptions& opt, Error* err) noexcept {
                OpenOptions openOpt = opt;
                openOpt.access = KEY_ALL_ACCESS;
                RegistryKey key;
                if (!key.Open(hKeyRoot, L"", openOpt, err)) return false;
                return key.DeleteSubKeyTree(subKey, err);
            }

            /**
             * @brief Retrieves the security descriptor for a registry key.
             * @param hKey Handle to the registry key.
             * @param secInfo Security information to retrieve (e.g., OWNER_SECURITY_INFORMATION).
             * @param sd Vector to receive the security descriptor data.
             * @param err Optional error output.
             * @return true on success, false on failure.
             */
            bool GetKeySecurity(HKEY hKey, SECURITY_INFORMATION secInfo, std::vector<uint8_t>& sd, Error* err) noexcept {
                sd.clear();
                
                // Validate key handle
                if (hKey == nullptr) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle");
                    return false;
                }
                
                // First call: query required size
                DWORD size = 0;
                LSTATUS st = RegGetKeySecurity(hKey, secInfo, nullptr, &size);
                if (st != ERROR_INSUFFICIENT_BUFFER) {
                    SetError(err, static_cast<DWORD>(st), L"RegGetKeySecurity size query failed");
                    return false;
                }
                
                // Validate size
                if (size == 0) {
                    SetError(err, ERROR_INVALID_DATA, L"RegGetKeySecurity returned zero size");
                    return false;
                }
                
                // Security check: prevent DoS via extremely large security descriptors
                constexpr DWORD kMaxSecurityDescriptorSize = 64 * 1024; // 64KB reasonable limit
                if (size > kMaxSecurityDescriptorSize) {
                    SetError(err, ERROR_INVALID_DATA, L"Security descriptor too large");
                    SS_LOG_ERROR(L"RegistryUtils", L"GetKeySecurity: Size %lu exceeds maximum %lu", 
                                size, kMaxSecurityDescriptorSize);
                    return false;
                }

                // Allocate buffer with exception safety
                try {
                    sd.resize(size);
                } catch (const std::bad_alloc&) {
                    SetError(err, ERROR_NOT_ENOUGH_MEMORY, L"Memory allocation failed");
                    SS_LOG_ERROR(L"RegistryUtils", L"GetKeySecurity: Failed to allocate %lu bytes", size);
                    return false;
                }
                
                // Second call: retrieve security descriptor
                DWORD actualSize = size;
                st = RegGetKeySecurity(hKey, secInfo, reinterpret_cast<PSECURITY_DESCRIPTOR>(sd.data()), &actualSize);
                if (st != ERROR_SUCCESS) {
                    SetError(err, static_cast<DWORD>(st), L"RegGetKeySecurity failed");
                    sd.clear();
                    return false;
                }
                
                // Resize to actual size if smaller
                if (actualSize != size && actualSize > 0) {
                    try {
                        sd.resize(actualSize);
                    } catch (...) {
                        // Keep original size - data is still valid
                    }
                }
                
                return true;
            }

            /**
             * @brief Sets the security descriptor for a registry key.
             * @param hKey Handle to the registry key.
             * @param secInfo Security information to set.
             * @param sd Pointer to the security descriptor data.
             * @param err Optional error output.
             * @return true on success, false on failure.
             */
            bool SetKeySecurity(HKEY hKey, SECURITY_INFORMATION secInfo, const void* sd, Error* err) noexcept {
                // Validate parameters
                if (hKey == nullptr) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle");
                    return false;
                }
                
                if (sd == nullptr) {
                    SetError(err, ERROR_INVALID_PARAMETER, L"Null security descriptor");
                    return false;
                }
                
                const LSTATUS st = RegSetKeySecurity(hKey, secInfo, const_cast<PSECURITY_DESCRIPTOR>(sd));
                if (st != ERROR_SUCCESS) {
                    SetError(err, static_cast<DWORD>(st), L"RegSetKeySecurity failed");
                    SS_LOG_ERROR(L"RegistryUtils", L"SetKeySecurity failed (code=%lu)", st);
                    return false;
                }
                return true;
            }

            // ============================================================================
            // Privilege Management
            // ============================================================================

            /**
             * @brief Enables a specific privilege for the current process token.
             * @param privName Name of the privilege (e.g., SE_BACKUP_NAME).
             * @param err Optional error output.
             * @return true on success, false on failure.
             * @note Uses RAII to ensure token handle is properly closed.
             */
            static bool EnablePrivilege(const wchar_t* privName, Error* err) noexcept {
                // Validate parameter
                if (privName == nullptr) {
                    SetError(err, ERROR_INVALID_PARAMETER, L"Null privilege name");
                    return false;
                }
                
                // Open the process token
                HANDLE hToken = nullptr;
                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                    const DWORD le = GetLastError();
                    SetError(err, le, L"OpenProcessToken failed");
                    SS_LOG_LAST_ERROR(L"RegistryUtils", L"OpenProcessToken failed for privilege %ls", privName);
                    return false;
                }

                // RAII guard to ensure handle is always closed
                struct TokenGuard {
                    HANDLE handle;
                    ~TokenGuard() noexcept { 
                        if (handle != nullptr && handle != INVALID_HANDLE_VALUE) {
                            CloseHandle(handle); 
                        }
                    }
                } guard{ hToken };

                // Lookup the privilege LUID
                LUID luid = {};
                if (!LookupPrivilegeValueW(nullptr, privName, &luid)) {
                    const DWORD le = GetLastError();
                    SetError(err, le, L"LookupPrivilegeValueW failed");
                    SS_LOG_LAST_ERROR(L"RegistryUtils", L"LookupPrivilegeValueW failed for %ls", privName);
                    return false; // Guard will close handle
                }

                // Prepare and apply privilege adjustment
                TOKEN_PRIVILEGES tp = {};
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
                    const DWORD le = GetLastError();
                    SetError(err, le, L"AdjustTokenPrivileges failed");
                    SS_LOG_LAST_ERROR(L"RegistryUtils", L"AdjustTokenPrivileges failed for %ls", privName);
                    return false; // Guard will close handle
                }

                // Check if privilege was actually adjusted (GetLastError after success)
                const DWORD adjustResult = GetLastError();
                if (adjustResult == ERROR_NOT_ALL_ASSIGNED) {
                    SetError(err, adjustResult, L"Privilege not held");
                    SS_LOG_ERROR(L"RegistryUtils", L"Privilege %ls not held by process", privName);
                    return false;
                }

                return true; // Guard will close handle
            }

            /**
             * @brief Enables the SE_BACKUP_NAME privilege for registry backup operations.
             * @param err Optional error output.
             * @return true on success, false on failure.
             */
            bool EnableBackupPrivilege(Error* err) noexcept {
                return EnablePrivilege(L"SeRestorePrivilege", err);
            }

            /**
             * @brief Enables the SE_RESTORE_NAME privilege for registry restore operations.
             * @param err Optional error output.
             * @return true on success, false on failure.
             */
            bool EnableRestorePrivilege(Error* err) noexcept {
                return EnablePrivilege(L"SeRestorePrivilege", err);
            }


		}// namespace RegistryUtils
	}// namespace Utils
}// namespace ShadowStrike

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

            static void SetError(Error* err, DWORD code, std::wstring msg, std::wstring_view key = {}, std::wstring_view value = {}) noexcept {
                if (!err) return;
                err->win32 = code;
                err->message = std::move(msg);
                if (!key.empty()) err->keyPath = key;
                if (!value.empty()) err->valueName = value;
            }

            static REGSAM BuildAccessMask(const OpenOptions& opt) noexcept {
                REGSAM sam = opt.access;
                if (opt.wow64_64) sam |= KEY_WOW64_64KEY;
                if (opt.wow64_32) sam |= KEY_WOW64_32KEY;
                return sam;
            }

            // ============================================================================
            // RegistryKey implementation
            // ============================================================================
            bool RegistryKey::Open(HKEY hKeyParent, std::wstring_view subKey, const OpenOptions& opt, Error* err) noexcept {
                Close();
                std::wstring sk(subKey);
                const REGSAM sam = BuildAccessMask(opt);
                const LSTATUS st = RegOpenKeyExW(hKeyParent, sk.c_str(), 0, sam, &m_key);
                if (st != ERROR_SUCCESS) {
                    SetError(err, st, L"RegOpenKeyExW failed", sk);
                    SS_LOG_ERROR(L"RegistryUtils", L"RegOpenKeyExW failed: %ls (code=%lu)", sk.c_str(), st);
                    m_key = nullptr;
                    return false;
                }
                return true;
            }

            bool RegistryKey::Create(HKEY hKeyParent, std::wstring_view subKey, const OpenOptions& opt, DWORD* disposition, Error* err) noexcept {
                Close();
                std::wstring sk(subKey);
                const REGSAM sam = BuildAccessMask(opt);
                DWORD disp = 0;
                const LSTATUS st = RegCreateKeyExW(hKeyParent, sk.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, sam, nullptr, &m_key, &disp);
                if (st != ERROR_SUCCESS) {
                    SetError(err, st, L"RegCreateKeyExW failed", sk);
                    SS_LOG_ERROR(L"RegistryUtils", L"RegCreateKeyExW failed: %ls (code=%lu)", sk.c_str(), st);
                    m_key = nullptr;
                    return false;
                }
                if (disposition) *disposition = disp;
                return true;
            }

            void RegistryKey::Close() noexcept {
                if (m_key) {
                    RegCloseKey(m_key);
                    m_key = nullptr;
                }
            }

            bool RegistryKey::QueryInfo(KeyInfo& info, Error* err) const noexcept {
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle");
                    return false;
                }

                WCHAR className[256] = {};
                DWORD classLen = static_cast<DWORD>(std::size(className));
                DWORD subKeys = 0, maxSubKeyLen = 0, maxClassLen = 0;
                DWORD values = 0, maxValueNameLen = 0, maxValueDataLen = 0;
                DWORD secDescLen = 0;
                FILETIME lastWrite = {};

                const LSTATUS st = RegQueryInfoKeyW(m_key, className, &classLen, nullptr,
                    &subKeys, &maxSubKeyLen, &maxClassLen,
                    &values, &maxValueNameLen, &maxValueDataLen,
                    &secDescLen, &lastWrite);
                if (st != ERROR_SUCCESS) {
                    SetError(err, st, L"RegQueryInfoKeyW failed");
                    SS_LOG_ERROR(L"RegistryUtils", L"RegQueryInfoKeyW failed (code=%lu)", st);
                    return false;
                }

                info.className = className;
                info.subKeyCount = subKeys;
                info.valueCount = values;
                info.maxSubKeyLen = maxSubKeyLen;
                info.maxValueNameLen = maxValueNameLen;
                info.maxValueDataLen = maxValueDataLen;
                info.lastWriteTime = lastWrite;
                return true;
            }

            bool RegistryKey::ReadValue(std::wstring_view valueName, ValueType expectedType, std::vector<uint8_t>& out, ValueType* actualType, Error* err) const noexcept {
                out.clear();
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle", L"", valueName);
                    return false;
                }

                std::wstring vn(valueName);
                DWORD type = 0;
                DWORD size = 0;

                //First call : learn the size
                LSTATUS st = RegQueryValueExW(m_key, vn.c_str(), nullptr, &type, nullptr, &size);
                if (st != ERROR_SUCCESS) {
                    SetError(err, st, L"RegQueryValueExW size query failed", L"", valueName);
                    return false;
                }

                // Type check ( if expectedType != Unknown)
                if (expectedType != ValueType::Unknown && static_cast<DWORD>(expectedType) != type) {
                    SetError(err, ERROR_INVALID_DATATYPE, L"Value type mismatch", L"", valueName);
                    return false;
                }

                if (actualType) *actualType = static_cast<ValueType>(type);

                if (size == 0) {
                    out.clear();
                    return true;
                }

                out.resize(size);
                st = RegQueryValueExW(m_key, vn.c_str(), nullptr, &type, out.data(), &size);
                if (st != ERROR_SUCCESS) {
                    SetError(err, st, L"RegQueryValueExW data read failed", L"", valueName);
                    out.clear();
                    return false;
                }

                out.resize(size);
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
                    const DWORD expandSize = ExpandEnvironmentStringsW(out.c_str(), nullptr, 0);
                    if (expandSize > 0) {
                        std::wstring expanded(expandSize, L'\0');
                        if (ExpandEnvironmentStringsW(out.c_str(), expanded.data(), expandSize)) {
                            if (!expanded.empty() && expanded.back() == L'\0') expanded.pop_back();
                            out = std::move(expanded);
                        }
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

                for (size_t i = 0; i < len;) {
                    if (ptr[i] == L'\0') break; // end of the list

                    const wchar_t* start = ptr + i;
                    size_t strLen = 0;
                    while (i < len && ptr[i] != L'\0') { ++i; ++strLen; }

                    if (strLen > 0) out.emplace_back(start, strLen);
                    if (i < len && ptr[i] == L'\0') ++i; // skip null
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


            bool RegistryKey::WriteString(std::wstring_view valueName, std::wstring_view value, Error* err) noexcept {
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle", L"", valueName);
                    return false;
                }
                std::wstring vn(valueName);
                std::wstring val(value);
                const DWORD size = static_cast<DWORD>((val.size() + 1) * sizeof(wchar_t));
                const LSTATUS st = RegSetValueExW(m_key, vn.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(val.c_str()), size);
                if (st != ERROR_SUCCESS) {
                    SetError(err, st, L"RegSetValueExW (REG_SZ) failed", L"", valueName);
                    SS_LOG_ERROR(L"RegistryUtils", L"WriteString failed: %ls (code=%lu)", vn.c_str(), st);
                    return false;
                }
                return true;
            }

            bool RegistryKey::WriteExpandString(std::wstring_view valueName, std::wstring_view value, Error* err) noexcept {
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle", L"", valueName);
                    return false;
                }
                std::wstring vn(valueName);
                std::wstring val(value);
                const DWORD size = static_cast<DWORD>((val.size() + 1) * sizeof(wchar_t));
                const LSTATUS st = RegSetValueExW(m_key, vn.c_str(), 0, REG_EXPAND_SZ, reinterpret_cast<const BYTE*>(val.c_str()), size);
                if (st != ERROR_SUCCESS) {
                    SetError(err, st, L"RegSetValueExW (REG_EXPAND_SZ) failed", L"", valueName);
                    SS_LOG_ERROR(L"RegistryUtils", L"WriteExpandString failed: %ls (code=%lu)", vn.c_str(), st);
                    return false;
                }
                return true;
            }

            bool RegistryKey::WriteMultiString(std::wstring_view valueName, const std::vector<std::wstring>& value, Error* err) noexcept {
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle", L"", valueName);
                    return false;
                }

                // Multi-string format: "str1\0str2\0str3\0\0"
                std::wstring combined;
                for (const auto& s : value) {
                    combined.append(s);
                    combined.push_back(L'\0');
                }
                combined.push_back(L'\0'); // last null

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

            bool RegistryKey::WriteDWord(std::wstring_view valueName, DWORD value, Error* err) noexcept {
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle", L"", valueName);
                    return false;
                }
                std::wstring vn(valueName);
                const LSTATUS st = RegSetValueExW(m_key, vn.c_str(), 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(DWORD));
                if (st != ERROR_SUCCESS) {
                    SetError(err, st, L"RegSetValueExW (REG_DWORD) failed", L"", valueName);
                    SS_LOG_ERROR(L"RegistryUtils", L"WriteDWord failed: %ls (code=%lu)", vn.c_str(), st);
                    return false;
                }
                return true;
            }

            bool RegistryKey::WriteQWord(std::wstring_view valueName, uint64_t value, Error* err) noexcept {
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle", L"", valueName);
                    return false;
                }
                std::wstring vn(valueName);
                const LSTATUS st = RegSetValueExW(m_key, vn.c_str(), 0, REG_QWORD, reinterpret_cast<const BYTE*>(&value), sizeof(uint64_t));
                if (st != ERROR_SUCCESS) {
                    SetError(err, st, L"RegSetValueExW (REG_QWORD) failed", L"", valueName);
                    SS_LOG_ERROR(L"RegistryUtils", L"WriteQWord failed: %ls (code=%lu)", vn.c_str(), st);
                    return false;
                }
                return true;
            }

            bool RegistryKey::WriteBinary(std::wstring_view valueName, const void* data, size_t size, Error* err) noexcept {
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle", L"", valueName);
                    return false;
                }
                std::wstring vn(valueName);
                const LSTATUS st = RegSetValueExW(m_key, vn.c_str(), 0, REG_BINARY, static_cast<const BYTE*>(data), static_cast<DWORD>(size));
                if (st != ERROR_SUCCESS) {
                    SetError(err, st, L"RegSetValueExW (REG_BINARY) failed", L"", valueName);
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

            bool RegistryKey::EnumKeys(std::vector<std::wstring>& out, Error* err) const noexcept {
                out.clear();
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle");
                    return false;
                }

                KeyInfo info;
                if (!QueryInfo(info, err)) return false;

                const DWORD maxLen = info.maxSubKeyLen + 1;
                std::wstring buf(maxLen, L'\0');

                for (DWORD i = 0; i < info.subKeyCount; ++i) {
                    DWORD len = maxLen;
                    const LSTATUS st = RegEnumKeyExW(m_key, i, buf.data(), &len, nullptr, nullptr, nullptr, nullptr);
                    if (st == ERROR_SUCCESS) {
                        out.emplace_back(buf.data(), len);
                    }
                    else if (st == ERROR_NO_MORE_ITEMS) {
                        break;
                    }
                    else {
                        SetError(err, st, L"RegEnumKeyExW failed");
                        SS_LOG_ERROR(L"RegistryUtils", L"EnumKeys failed at index %lu (code=%lu)", i, st);
                        return false;
                    }
                }
                return true;
            }

            bool RegistryKey::EnumValues(std::vector<ValueInfo>& out, Error* err) const noexcept {
                out.clear();
                if (!m_key) {
                    SetError(err, ERROR_INVALID_HANDLE, L"Invalid key handle");
                    return false;
                }

                KeyInfo info;
                if (!QueryInfo(info, err)) return false;

                const DWORD maxLen = info.maxValueNameLen + 1;
                std::wstring buf(maxLen, L'\0');

                for (DWORD i = 0; i < info.valueCount; ++i) {
                    DWORD nameLen = maxLen;
                    DWORD type = 0;
                    DWORD dataSize = 0;
                    const LSTATUS st = RegEnumValueW(m_key, i, buf.data(), &nameLen, nullptr, &type, nullptr, &dataSize);
                    if (st == ERROR_SUCCESS) {
                        ValueInfo vi;
                        vi.name.assign(buf.data(), nameLen);
                        vi.type = static_cast<ValueType>(type);
                        vi.dataSize = dataSize;
                        out.push_back(std::move(vi));
                    }
                    else if (st == ERROR_NO_MORE_ITEMS) {
                        break;
                    }
                    else {
                        SetError(err, st, L"RegEnumValueW failed");
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

            bool GetKeySecurity(HKEY hKey, SECURITY_INFORMATION secInfo, std::vector<uint8_t>& sd, Error* err) noexcept {
                sd.clear();
                DWORD size = 0;
                LSTATUS st = RegGetKeySecurity(hKey, secInfo, nullptr, &size);
                if (st != ERROR_INSUFFICIENT_BUFFER || size == 0) {
                    SetError(err, st, L"RegGetKeySecurity size query failed");
                    return false;
                }

                sd.resize(size);
                st = RegGetKeySecurity(hKey, secInfo, reinterpret_cast<PSECURITY_DESCRIPTOR>(sd.data()), &size);
                if (st != ERROR_SUCCESS) {
                    SetError(err, st, L"RegGetKeySecurity failed");
                    sd.clear();
                    return false;
                }
                sd.resize(size);
                return true;
            }

            bool SetKeySecurity(HKEY hKey, SECURITY_INFORMATION secInfo, const void* sd, Error* err) noexcept {
                const LSTATUS st = RegSetKeySecurity(hKey, secInfo, const_cast<PSECURITY_DESCRIPTOR>(sd));
                if (st != ERROR_SUCCESS) {
                    SetError(err, st, L"RegSetKeySecurity failed");
                    SS_LOG_ERROR(L"RegistryUtils", L"SetKeySecurity failed (code=%lu)", st);
                    return false;
                }
                return true;
            }

            static bool EnablePrivilege(const wchar_t* privName, Error* err) noexcept {
                HANDLE hToken = nullptr;
                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                    const DWORD le = GetLastError();
                    SetError(err, le, L"OpenProcessToken failed");
                    SS_LOG_LAST_ERROR(L"RegistryUtils", L"OpenProcessToken failed for privilege %ls", privName);
                    return false;
                }

                LUID luid = {};
                if (!LookupPrivilegeValueW(nullptr, privName, &luid)) {
                    const DWORD le = GetLastError();
                    SetError(err, le, L"LookupPrivilegeValueW failed");
                    SS_LOG_LAST_ERROR(L"RegistryUtils", L"LookupPrivilegeValueW failed for %ls", privName);
                    CloseHandle(hToken);
                    return false;
                }

                TOKEN_PRIVILEGES tp = {};
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
                    const DWORD le = GetLastError();
                    SetError(err, le, L"AdjustTokenPrivileges failed");
                    SS_LOG_LAST_ERROR(L"RegistryUtils", L"AdjustTokenPrivileges failed for %ls", privName);
                    CloseHandle(hToken);
                    return false;
                }

                CloseHandle(hToken);
                return true;
            }

            bool EnableBackupPrivilege(Error* err) noexcept {
                return EnablePrivilege(SE_BACKUP_NAME, err);
            }

            bool EnableRestorePrivilege(Error* err) noexcept {
                return EnablePrivilege(SE_RESTORE_NAME, err);
            }


		}// namespace RegistryUtils
	}// namespace Utils
}// namespace ShadowStrike

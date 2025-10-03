

#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <cstdint>
#include <filesystem>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#endif

#include "Logger.hpp"

namespace ShadowStrike {
	namespace Utils {
		namespace RegistryUtils {

            struct Error {
                DWORD win32 = ERROR_SUCCESS;
                std::wstring message;
                std::wstring keyPath;
                std::wstring valueName;
            };

            // Registry data types
            enum class ValueType : DWORD {
                None = REG_NONE,
                String = REG_SZ,
                ExpandString = REG_EXPAND_SZ,
                Binary = REG_BINARY,
                DWord = REG_DWORD,
                DWordBigEndian = REG_DWORD_BIG_ENDIAN,
                Link = REG_LINK,
                MultiString = REG_MULTI_SZ,
                QWord = REG_QWORD,
                Unknown = 0xFFFFFFFF
            };

            // Registry value informations
            struct ValueInfo {
                std::wstring name;
                ValueType type = ValueType::None;
                DWORD dataSize = 0;  // bytes
            };

            // Registry key informations
            struct KeyInfo {
                std::wstring name;
                std::wstring className;
                DWORD subKeyCount = 0;
                DWORD valueCount = 0;
                DWORD maxSubKeyLen = 0;
                DWORD maxValueNameLen = 0;
                DWORD maxValueDataLen = 0;
                FILETIME lastWriteTime = {};
            };

			//Options for opening a registry key
            struct OpenOptions {
                REGSAM access = KEY_READ;
                bool wow64_64 = false;  // KEY_WOW64_64KEY
                bool wow64_32 = false;  // KEY_WOW64_32KEY
            };


            class RegistryKey {
            public:
                RegistryKey() noexcept = default;
                ~RegistryKey() noexcept { Close(); }

                // Move semantics
                RegistryKey(RegistryKey&& other) noexcept : m_key(other.m_key) { other.m_key = nullptr; }
                RegistryKey& operator=(RegistryKey&& other) noexcept {
                    if (this != &other) {
                        Close();
                        m_key = other.m_key;
                        other.m_key = nullptr;
                    }
                    return *this;
                }

                // No copy
                RegistryKey(const RegistryKey&) = delete;
                RegistryKey& operator=(const RegistryKey&) = delete;

				//Open/Create
                bool Open(HKEY hKeyParent, std::wstring_view subKey, const OpenOptions& opt = {}, Error* err = nullptr) noexcept;
                bool Create(HKEY hKeyParent, std::wstring_view subKey, const OpenOptions& opt = {}, DWORD* disposition = nullptr, Error* err = nullptr) noexcept;

                void Close() noexcept;

                bool IsValid() const noexcept { return m_key != nullptr; }
                HKEY Handle() const noexcept { return m_key; }

				// information query
                bool QueryInfo(KeyInfo& info, Error* err = nullptr) const noexcept;

				// Reading values
                bool ReadString(std::wstring_view valueName, std::wstring& out, Error* err = nullptr) const noexcept;
                bool ReadExpandString(std::wstring_view valueName, std::wstring& out, bool expand = true, Error* err = nullptr) const noexcept;
                bool ReadMultiString(std::wstring_view valueName, std::vector<std::wstring>& out, Error* err = nullptr) const noexcept;
                bool ReadDWord(std::wstring_view valueName, DWORD& out, Error* err = nullptr) const noexcept;
                bool ReadQWord(std::wstring_view valueName, uint64_t& out, Error* err = nullptr) const noexcept;
                bool ReadBinary(std::wstring_view valueName, std::vector<uint8_t>& out, Error* err = nullptr) const noexcept;

                // Generic read (with type check)
                bool ReadValue(std::wstring_view valueName, ValueType expectedType, std::vector<uint8_t>& out, ValueType* actualType = nullptr, Error* err = nullptr) const noexcept;

                // Write value
                bool WriteString(std::wstring_view valueName, std::wstring_view value, Error* err = nullptr) noexcept;
                bool WriteExpandString(std::wstring_view valueName, std::wstring_view value, Error* err = nullptr) noexcept;
                bool WriteMultiString(std::wstring_view valueName, const std::vector<std::wstring>& value, Error* err = nullptr) noexcept;
                bool WriteDWord(std::wstring_view valueName, DWORD value, Error* err = nullptr) noexcept;
                bool WriteQWord(std::wstring_view valueName, uint64_t value, Error* err = nullptr) noexcept;
                bool WriteBinary(std::wstring_view valueName, const void* data, size_t size, Error* err = nullptr) noexcept;

                //Delete value
                bool DeleteValue(std::wstring_view valueName, Error* err = nullptr) noexcept;

				//Delete subkey
                bool DeleteSubKey(std::wstring_view subKey, Error* err = nullptr) noexcept;
                bool DeleteSubKeyTree(std::wstring_view subKey, Error* err = nullptr) noexcept;

                // Enumeration
                bool EnumKeys(std::vector<std::wstring>& out, Error* err = nullptr) const noexcept;
                bool EnumValues(std::vector<ValueInfo>& out, Error* err = nullptr) const noexcept;

                // is there any value?
                bool ValueExists(std::wstring_view valueName) const noexcept;

				// is there any subkey?
                bool SubKeyExists(std::wstring_view subKey) const noexcept;

                // Flush (write to disk)
                bool Flush(Error* err = nullptr) noexcept;

				//Backup/Restore
                bool SaveToFile(const std::filesystem::path& path, Error* err = nullptr) const noexcept;
                bool RestoreFromFile(const std::filesystem::path& path, DWORD flags = 0, Error* err = nullptr) noexcept;

            private:
                HKEY m_key = nullptr;

                bool ReadStringInternal(std::wstring_view valueName, DWORD type, std::wstring& out, bool expand, Error* err) const noexcept;
            };

           

			// Global helper functions(Working with HKEY directly)

           //string parse for predefined keys
            HKEY ParseRootKey(std::wstring_view rootName) noexcept;
            std::wstring RootKeyToString(HKEY hKey) noexcept;

            // Path split: "HKEY_LOCAL_MACHINE\\Software\\Test" -> (HKLM, "Software\\Test")
            bool SplitPath(std::wstring_view fullPath, HKEY& rootKey, std::wstring& subKey) noexcept;

			// Quick read/write helpers (open, read/write, close)
            bool QuickReadString(HKEY hKeyRoot, std::wstring_view subKey, std::wstring_view valueName, std::wstring& out, const OpenOptions& opt = {}, Error* err = nullptr) noexcept;
            bool QuickReadDWord(HKEY hKeyRoot, std::wstring_view subKey, std::wstring_view valueName, DWORD& out, const OpenOptions& opt = {}, Error* err = nullptr) noexcept;
            bool QuickReadQWord(HKEY hKeyRoot, std::wstring_view subKey, std::wstring_view valueName, uint64_t& out, const OpenOptions& opt = {}, Error* err = nullptr) noexcept;

            bool QuickWriteString(HKEY hKeyRoot, std::wstring_view subKey, std::wstring_view valueName, std::wstring_view value, const OpenOptions& opt = {}, Error* err = nullptr) noexcept;
            bool QuickWriteDWord(HKEY hKeyRoot, std::wstring_view subKey, std::wstring_view valueName, DWORD value, const OpenOptions& opt = {}, Error* err = nullptr) noexcept;
            bool QuickWriteQWord(HKEY hKeyRoot, std::wstring_view subKey, std::wstring_view valueName, uint64_t value, const OpenOptions& opt = {}, Error* err = nullptr) noexcept;

			// Key existence check
            bool KeyExists(HKEY hKeyRoot, std::wstring_view subKey, const OpenOptions& opt = {}) noexcept;

			//Delete key(use with caution!)
            bool DeleteKey(HKEY hKeyRoot, std::wstring_view subKey, const OpenOptions& opt = {}, Error* err = nullptr) noexcept;
            bool DeleteKeyTree(HKEY hKeyRoot, std::wstring_view subKey, const OpenOptions& opt = {}, Error* err = nullptr) noexcept;

            // Security descriptor management
            bool GetKeySecurity(HKEY hKey, SECURITY_INFORMATION secInfo, std::vector<uint8_t>& sd, Error* err = nullptr) noexcept;
            bool SetKeySecurity(HKEY hKey, SECURITY_INFORMATION secInfo, const void* sd, Error* err = nullptr) noexcept;

            // Privilege helpers
            bool EnableBackupPrivilege(Error* err = nullptr) noexcept;
            bool EnableRestorePrivilege(Error* err = nullptr) noexcept;



		}// namespace RegistryUtils
	}// namespace Utils
}// namespace ShadowStrike
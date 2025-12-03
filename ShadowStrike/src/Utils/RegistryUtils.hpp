

#pragma once

/**
 * @file RegistryUtils.hpp
 * @brief Windows Registry access utilities for ShadowStrike.
 * 
 * Provides a comprehensive, type-safe C++ wrapper around the Windows Registry API.
 * Features include:
 * - RAII-based registry key management (RegistryKey class)
 * - Type-safe value read/write operations
 * - Multi-string and expand-string support with proper expansion
 * - Key enumeration and existence checking
 * - Security descriptor management
 * - Backup/Restore functionality with privilege management
 * 
 * @note This module is Windows-specific and requires linking with Advapi32.lib.
 * @warning Registry operations can affect system stability. Use with care.
 * 
 * @copyright ShadowStrike Security Suite
 */

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

            // ============================================================================
            // Error Handling
            // ============================================================================

            /**
             * @brief Error information structure for registry operations.
             * 
             * Contains detailed error information including Win32 error code,
             * descriptive message, and context about the key/value involved.
             */
            struct Error {
                DWORD win32 = ERROR_SUCCESS;    ///< Win32 error code from the operation
                std::wstring message;            ///< Human-readable error description
                std::wstring keyPath;            ///< Registry key path involved (if applicable)
                std::wstring valueName;          ///< Value name involved (if applicable)
                
                /** @brief Check if an error occurred */
                [[nodiscard]] bool HasError() const noexcept { return win32 != ERROR_SUCCESS; }
                
                /** @brief Reset error state to success */
                void Clear() noexcept { 
                    win32 = ERROR_SUCCESS; 
                    message.clear(); 
                    keyPath.clear(); 
                    valueName.clear(); 
                }
            };

            // ============================================================================
            // Registry Data Types
            // ============================================================================

            /**
             * @brief Registry value type enumeration.
             * 
             * Maps directly to Windows REG_* constants for type safety.
             */
            enum class ValueType : DWORD {
                None = REG_NONE,                    ///< No type defined
                String = REG_SZ,                    ///< Null-terminated string
                ExpandString = REG_EXPAND_SZ,       ///< String with environment variable references
                Binary = REG_BINARY,                ///< Binary data
                DWord = REG_DWORD,                  ///< 32-bit unsigned integer
                DWordBigEndian = REG_DWORD_BIG_ENDIAN, ///< 32-bit big-endian integer
                Link = REG_LINK,                    ///< Symbolic link
                MultiString = REG_MULTI_SZ,         ///< Array of null-terminated strings
                QWord = REG_QWORD,                  ///< 64-bit unsigned integer
                Unknown = 0xFFFFFFFF                ///< Unknown or any type (for queries)
            };

            // ============================================================================
            // Information Structures
            // ============================================================================

            /**
             * @brief Information about a registry value.
             */
            struct ValueInfo {
                std::wstring name;              ///< Value name
                ValueType type = ValueType::None; ///< Value type
                DWORD dataSize = 0;             ///< Data size in bytes
            };

            /**
             * @brief Information about a registry key.
             */
            struct KeyInfo {
                std::wstring name;              ///< Key name
                std::wstring className;         ///< Key class name
                DWORD subKeyCount = 0;          ///< Number of subkeys
                DWORD valueCount = 0;           ///< Number of values
                DWORD maxSubKeyLen = 0;         ///< Maximum subkey name length
                DWORD maxValueNameLen = 0;      ///< Maximum value name length
                DWORD maxValueDataLen = 0;      ///< Maximum value data size
                FILETIME lastWriteTime = {};    ///< Last modification timestamp
            };

            /**
             * @brief Options for opening a registry key.
             */
            struct OpenOptions {
                REGSAM access = KEY_READ;       ///< Desired access rights
                bool wow64_64 = false;          ///< Force 64-bit registry view (KEY_WOW64_64KEY)
                bool wow64_32 = false;          ///< Force 32-bit registry view (KEY_WOW64_32KEY)
            };


            // ============================================================================
            // RegistryKey Class - RAII Registry Key Wrapper
            // ============================================================================

            /**
             * @brief RAII wrapper for Windows registry keys.
             * 
             * Provides automatic cleanup of registry key handles and a type-safe
             * interface for common registry operations. The class is movable but
             * not copyable to ensure single ownership of the underlying handle.
             * 
             * @example
             * @code
             * RegistryKey key;
             * if (key.Open(HKEY_LOCAL_MACHINE, L"SOFTWARE\\MyApp")) {
             *     std::wstring value;
             *     if (key.ReadString(L"InstallPath", value)) {
             *         // Use value
             *     }
             * } // Key automatically closed here
             * @endcode
             */
            class RegistryKey {
            public:
                /** @brief Default constructor - creates an invalid key */
                RegistryKey() noexcept = default;
                
                /** @brief Destructor - automatically closes the key */
                ~RegistryKey() noexcept { Close(); }

                // Move semantics - transfer ownership
                RegistryKey(RegistryKey&& other) noexcept : m_key(other.m_key) { other.m_key = nullptr; }
                RegistryKey& operator=(RegistryKey&& other) noexcept {
                    if (this != &other) {
                        Close();
                        m_key = other.m_key;
                        other.m_key = nullptr;
                    }
                    return *this;
                }

                // No copy - single ownership semantics
                RegistryKey(const RegistryKey&) = delete;
                RegistryKey& operator=(const RegistryKey&) = delete;

                // ----------------------------------------------------------------
                // Key Management
                // ----------------------------------------------------------------

                /**
                 * @brief Opens an existing registry key.
                 * @param hKeyParent Parent key handle (e.g., HKEY_LOCAL_MACHINE)
                 * @param subKey Subkey path relative to parent
                 * @param opt Open options (access rights, WOW64 flags)
                 * @param err Optional error output
                 * @return true on success, false on failure
                 */
                [[nodiscard]] bool Open(HKEY hKeyParent, std::wstring_view subKey, 
                                       const OpenOptions& opt = {}, Error* err = nullptr) noexcept;

                /**
                 * @brief Creates or opens a registry key.
                 * @param hKeyParent Parent key handle
                 * @param subKey Subkey path to create/open
                 * @param opt Open options
                 * @param disposition Output: REG_CREATED_NEW_KEY or REG_OPENED_EXISTING_KEY
                 * @param err Optional error output
                 * @return true on success, false on failure
                 */
                [[nodiscard]] bool Create(HKEY hKeyParent, std::wstring_view subKey, 
                                         const OpenOptions& opt = {}, DWORD* disposition = nullptr, 
                                         Error* err = nullptr) noexcept;

                /** @brief Closes the registry key handle */
                void Close() noexcept;

                /** @brief Check if the key is valid (open) */
                [[nodiscard]] bool IsValid() const noexcept { return m_key != nullptr; }
                
                /** @brief Get the raw HKEY handle */
                [[nodiscard]] HKEY Handle() const noexcept { return m_key; }

                /** @brief Explicit bool conversion for validity check */
                explicit operator bool() const noexcept { return IsValid(); }

                // ----------------------------------------------------------------
                // Information Query
                // ----------------------------------------------------------------

                /**
                 * @brief Queries key information (subkey count, value count, etc.)
                 * @param info Output structure for key information
                 * @param err Optional error output
                 * @return true on success, false on failure
                 */
                [[nodiscard]] bool QueryInfo(KeyInfo& info, Error* err = nullptr) const noexcept;

                // ----------------------------------------------------------------
                // Value Reading
                // ----------------------------------------------------------------

                /**
                 * @brief Reads a REG_SZ string value.
                 * @param valueName Name of the value to read
                 * @param out Output string
                 * @param err Optional error output
                 * @return true on success, false on failure
                 */
                [[nodiscard]] bool ReadString(std::wstring_view valueName, std::wstring& out, 
                                             Error* err = nullptr) const noexcept;

                /**
                 * @brief Reads a REG_EXPAND_SZ value with optional environment expansion.
                 * @param valueName Name of the value to read
                 * @param out Output string (expanded if requested)
                 * @param expand If true, expands environment variables
                 * @param err Optional error output
                 * @return true on success, false on failure
                 */
                [[nodiscard]] bool ReadExpandString(std::wstring_view valueName, std::wstring& out, 
                                                   bool expand = true, Error* err = nullptr) const noexcept;

                /**
                 * @brief Reads a REG_MULTI_SZ value.
                 * @param valueName Name of the value to read
                 * @param out Output vector of strings
                 * @param err Optional error output
                 * @return true on success, false on failure
                 */
                [[nodiscard]] bool ReadMultiString(std::wstring_view valueName, 
                                                  std::vector<std::wstring>& out, 
                                                  Error* err = nullptr) const noexcept;

                /** @brief Reads a REG_DWORD value */
                [[nodiscard]] bool ReadDWord(std::wstring_view valueName, DWORD& out, 
                                            Error* err = nullptr) const noexcept;

                /** @brief Reads a REG_QWORD value */
                [[nodiscard]] bool ReadQWord(std::wstring_view valueName, uint64_t& out, 
                                            Error* err = nullptr) const noexcept;

                /** @brief Reads a REG_BINARY value */
                [[nodiscard]] bool ReadBinary(std::wstring_view valueName, std::vector<uint8_t>& out, 
                                             Error* err = nullptr) const noexcept;

                /**
                 * @brief Generic value read with type checking.
                 * @param valueName Name of the value to read
                 * @param expectedType Expected type (ValueType::Unknown to accept any)
                 * @param out Output buffer
                 * @param actualType Output: actual value type
                 * @param err Optional error output
                 * @return true on success, false on failure
                 */
                [[nodiscard]] bool ReadValue(std::wstring_view valueName, ValueType expectedType, 
                                            std::vector<uint8_t>& out, ValueType* actualType = nullptr, 
                                            Error* err = nullptr) const noexcept;

                // ----------------------------------------------------------------
                // Value Writing
                // ----------------------------------------------------------------

                /** @brief Writes a REG_SZ string value */
                [[nodiscard]] bool WriteString(std::wstring_view valueName, std::wstring_view value, 
                                              Error* err = nullptr) noexcept;

                /** @brief Writes a REG_EXPAND_SZ string value */
                [[nodiscard]] bool WriteExpandString(std::wstring_view valueName, std::wstring_view value, 
                                                    Error* err = nullptr) noexcept;

                /** @brief Writes a REG_MULTI_SZ value */
                [[nodiscard]] bool WriteMultiString(std::wstring_view valueName, 
                                                   const std::vector<std::wstring>& value, 
                                                   Error* err = nullptr) noexcept;

                /** @brief Writes a REG_DWORD value */
                [[nodiscard]] bool WriteDWord(std::wstring_view valueName, DWORD value, 
                                             Error* err = nullptr) noexcept;

                /** @brief Writes a REG_QWORD value */
                [[nodiscard]] bool WriteQWord(std::wstring_view valueName, uint64_t value, 
                                             Error* err = nullptr) noexcept;

                /** @brief Writes a REG_BINARY value */
                [[nodiscard]] bool WriteBinary(std::wstring_view valueName, const void* data, 
                                              size_t size, Error* err = nullptr) noexcept;

                // ----------------------------------------------------------------
                // Deletion
                // ----------------------------------------------------------------

                /** @brief Deletes a value from the key */
                [[nodiscard]] bool DeleteValue(std::wstring_view valueName, Error* err = nullptr) noexcept;

                /** @brief Deletes a subkey (must be empty) */
                [[nodiscard]] bool DeleteSubKey(std::wstring_view subKey, Error* err = nullptr) noexcept;

                /** @brief Recursively deletes a subkey and all its contents */
                [[nodiscard]] bool DeleteSubKeyTree(std::wstring_view subKey, Error* err = nullptr) noexcept;

                // ----------------------------------------------------------------
                // Enumeration
                // ----------------------------------------------------------------

                /** @brief Enumerates all subkey names */
                [[nodiscard]] bool EnumKeys(std::vector<std::wstring>& out, Error* err = nullptr) const noexcept;

                /** @brief Enumerates all value names and types */
                [[nodiscard]] bool EnumValues(std::vector<ValueInfo>& out, Error* err = nullptr) const noexcept;

                // ----------------------------------------------------------------
                // Existence Checks
                // ----------------------------------------------------------------

                /**
                 * @brief Checks if a value exists.
                 * @warning Subject to TOCTOU race conditions.
                 */
                [[nodiscard]] bool ValueExists(std::wstring_view valueName) const noexcept;

                /**
                 * @brief Checks if a subkey exists.
                 * @warning Subject to TOCTOU race conditions. Prefer Open() with error handling.
                 */
                [[nodiscard]] bool SubKeyExists(std::wstring_view subKey) const noexcept;

                // ----------------------------------------------------------------
                // Persistence
                // ----------------------------------------------------------------

                /** @brief Flushes changes to disk */
                [[nodiscard]] bool Flush(Error* err = nullptr) noexcept;

                /** @brief Saves key to a file (requires SE_BACKUP_NAME privilege) */
                [[nodiscard]] bool SaveToFile(const std::filesystem::path& path, 
                                             Error* err = nullptr) const noexcept;

                /** @brief Restores key from a file (requires SE_RESTORE_NAME privilege) */
                [[nodiscard]] bool RestoreFromFile(const std::filesystem::path& path, 
                                                  DWORD flags = 0, Error* err = nullptr) noexcept;

            private:
                HKEY m_key = nullptr;  ///< Underlying registry key handle

                /** @brief Internal helper for reading string values */
                [[nodiscard]] bool ReadStringInternal(std::wstring_view valueName, DWORD type, 
                                                     std::wstring& out, bool expand, Error* err) const noexcept;
            };

            // ============================================================================
            // Global Helper Functions
            // ============================================================================

            /**
             * @brief Parses a root key name string to HKEY.
             * @param rootName Root key name (e.g., "HKEY_LOCAL_MACHINE" or "HKLM")
             * @return HKEY constant, or nullptr if not recognized
             */
            [[nodiscard]] HKEY ParseRootKey(std::wstring_view rootName) noexcept;

            /**
             * @brief Converts HKEY to string representation.
             * @param hKey Root key handle
             * @return String name of the root key, or "UNKNOWN"
             */
            [[nodiscard]] std::wstring RootKeyToString(HKEY hKey) noexcept;

            /**
             * @brief Splits a full registry path into root key and subkey.
             * @param fullPath Full path (e.g., "HKEY_LOCAL_MACHINE\\SOFTWARE\\Test")
             * @param rootKey Output: root key handle
             * @param subKey Output: subkey path
             * @return true on success, false if root key not recognized
             */
            [[nodiscard]] bool SplitPath(std::wstring_view fullPath, HKEY& rootKey, std::wstring& subKey) noexcept;

            // ============================================================================
            // Quick Access Functions
            // ============================================================================

            /** @brief Opens a key, reads a string value, and closes the key */
            [[nodiscard]] bool QuickReadString(HKEY hKeyRoot, std::wstring_view subKey, 
                                              std::wstring_view valueName, std::wstring& out, 
                                              const OpenOptions& opt = {}, Error* err = nullptr) noexcept;

            /** @brief Opens a key, reads a DWORD value, and closes the key */
            [[nodiscard]] bool QuickReadDWord(HKEY hKeyRoot, std::wstring_view subKey, 
                                             std::wstring_view valueName, DWORD& out, 
                                             const OpenOptions& opt = {}, Error* err = nullptr) noexcept;

            /** @brief Opens a key, reads a QWORD value, and closes the key */
            [[nodiscard]] bool QuickReadQWord(HKEY hKeyRoot, std::wstring_view subKey, 
                                             std::wstring_view valueName, uint64_t& out, 
                                             const OpenOptions& opt = {}, Error* err = nullptr) noexcept;

            /** @brief Creates/opens a key, writes a string value, and closes the key */
            [[nodiscard]] bool QuickWriteString(HKEY hKeyRoot, std::wstring_view subKey, 
                                               std::wstring_view valueName, std::wstring_view value, 
                                               const OpenOptions& opt = {}, Error* err = nullptr) noexcept;

            /** @brief Creates/opens a key, writes a DWORD value, and closes the key */
            [[nodiscard]] bool QuickWriteDWord(HKEY hKeyRoot, std::wstring_view subKey, 
                                              std::wstring_view valueName, DWORD value, 
                                              const OpenOptions& opt = {}, Error* err = nullptr) noexcept;

            /** @brief Creates/opens a key, writes a QWORD value, and closes the key */
            [[nodiscard]] bool QuickWriteQWord(HKEY hKeyRoot, std::wstring_view subKey, 
                                              std::wstring_view valueName, uint64_t value, 
                                              const OpenOptions& opt = {}, Error* err = nullptr) noexcept;

            // ============================================================================
            // Key Operations
            // ============================================================================

            /**
             * @brief Checks if a registry key exists.
             * @warning Subject to TOCTOU race conditions.
             */
            [[nodiscard]] bool KeyExists(HKEY hKeyRoot, std::wstring_view subKey, 
                                        const OpenOptions& opt = {}) noexcept;

            /**
             * @brief Deletes a registry key (must be empty).
             * @warning Use with extreme caution - can affect system stability.
             */
            [[nodiscard]] bool DeleteKey(HKEY hKeyRoot, std::wstring_view subKey, 
                                        const OpenOptions& opt = {}, Error* err = nullptr) noexcept;

            /**
             * @brief Recursively deletes a registry key and all subkeys/values.
             * @warning Use with extreme caution - can affect system stability.
             */
            [[nodiscard]] bool DeleteKeyTree(HKEY hKeyRoot, std::wstring_view subKey, 
                                            const OpenOptions& opt = {}, Error* err = nullptr) noexcept;

            // ============================================================================
            // Security Functions
            // ============================================================================

            /**
             * @brief Retrieves the security descriptor of a registry key.
             * @param hKey Open key handle with READ_CONTROL access
             * @param secInfo Security information to retrieve
             * @param sd Output buffer for security descriptor
             * @param err Optional error output
             * @return true on success, false on failure
             */
            [[nodiscard]] bool GetKeySecurity(HKEY hKey, SECURITY_INFORMATION secInfo, 
                                             std::vector<uint8_t>& sd, Error* err = nullptr) noexcept;

            /**
             * @brief Sets the security descriptor of a registry key.
             * @param hKey Open key handle with WRITE_DAC or WRITE_OWNER access
             * @param secInfo Security information to set
             * @param sd Security descriptor to apply
             * @param err Optional error output
             * @return true on success, false on failure
             */
            [[nodiscard]] bool SetKeySecurity(HKEY hKey, SECURITY_INFORMATION secInfo, 
                                             const void* sd, Error* err = nullptr) noexcept;

            // ============================================================================
            // Privilege Management
            // ============================================================================

            /**
             * @brief Enables SE_BACKUP_NAME privilege for the current process.
             * Required for SaveToFile operations.
             */
            [[nodiscard]] bool EnableBackupPrivilege(Error* err = nullptr) noexcept;

            /**
             * @brief Enables SE_RESTORE_NAME privilege for the current process.
             * Required for RestoreFromFile operations.
             */
            [[nodiscard]] bool EnableRestorePrivilege(Error* err = nullptr) noexcept;

		}// namespace RegistryUtils
	}// namespace Utils
}// namespace ShadowStrike
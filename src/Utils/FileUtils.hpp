#pragma once
/**
 * @file FileUtils.hpp
 * @brief Secure file system utility functions for ShadowStrike Security Suite.
 *
 * Provides hardened Windows file operations including:
 * - Long path support (\\?\) for paths exceeding MAX_PATH
 * - Atomic file writes with crash-safe semantics
 * - Secure file erasure with multiple overwrite passes
 * - Directory walking with symlink loop detection
 * - Alternate data stream (ADS) enumeration
 * - SHA-256 file hashing using Windows BCrypt
 *
 * @note All functions use Win32 API for maximum compatibility and control.
 * @warning Security-critical: handles sensitive file operations.
 */

#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <cstdint>
#include <optional>
#include <functional>
#include <atomic>
#include <span>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

#include "Logger.hpp"

namespace ShadowStrike {

	namespace Utils {

		namespace FileUtils {

			/// Long path prefix for extended-length paths (\\?\)
			inline constexpr std::wstring_view LONG_PATH_PREFIX = L"\\\\?\\";
			/// Long path prefix for UNC paths (\\?\UNC\)
			inline constexpr std::wstring_view LONG_PATH_PREFIX_UNC = L"\\\\?\\UNC\\";

			/// Maximum reasonable path length to prevent DoS via extremely long paths
			inline constexpr size_t MAX_REASONABLE_PATH_LENGTH = 32767;

			/// Maximum file size for in-memory operations (1GB default)
			inline constexpr uint64_t MAX_READ_FILE_SIZE = 1ULL * 1024 * 1024 * 1024;

			/**
			 * @brief Error information structure for file operations.
			 * 
			 * Captures both Win32 error code and human-readable message.
			 */
			struct Error {
				DWORD win32 = 0;            ///< Win32 error code from GetLastError()
				std::string message;        ///< Human-readable error description

				/// @brief Check if error is set
				[[nodiscard]] constexpr bool hasError() const noexcept { return win32 != 0; }
				
				/// @brief Clear the error state
				constexpr void clear() noexcept { win32 = 0; message.clear(); }
			};

			/**
			 * @brief File statistics and metadata.
			 * 
			 * Contains comprehensive file information from Win32 API.
			 */
			struct FileStat {
				bool exists = false;            ///< File exists
				bool isDirectory = false;       ///< Is a directory
				bool isReparsePoint = false;    ///< Is a reparse point (junction/symlink)
				bool isHidden = false;          ///< Has hidden attribute
				bool isSystem = false;          ///< Has system attribute
				uint64_t size = 0;              ///< File size in bytes
				FILETIME creation{};            ///< Creation timestamp
				FILETIME lastAccess{};          ///< Last access timestamp
				FILETIME lastWrite{};           ///< Last modification timestamp
				DWORD attributes = 0;           ///< Raw Win32 attributes
			};


			/**
			 * @brief Alternate Data Stream (ADS) information.
			 * 
			 * NTFS files can have multiple named data streams beyond the default $DATA stream.
			 */
			struct AlternateStreamInfo {
				std::wstring name;      ///< Stream name (e.g., ":stream:$DATA")
				uint64_t size = 0;      ///< Stream size in bytes
			};
			
			/**
			 * @brief Options for directory traversal operations.
			 * 
			 * Controls recursive walking, filtering, and cancellation.
			 */
			struct WalkOptions {
				bool recursive = true;              ///< Recurse into subdirectories
				bool followReparsePoints = false;   ///< Follow junctions/symlinks (risk of loops)
				bool includeDirs = false;           ///< Include directories in callback
				bool skipHidden = false;            ///< Skip files with hidden attribute
				bool skipSystem = false;            ///< Skip files with system attribute
				size_t maxDepth = SIZE_MAX;         ///< Maximum recursion depth
				const std::atomic<bool>* cancelFlag = nullptr;  ///< Optional cancellation flag
			};

			/**
			 * @brief Unique file identifier for loop detection.
			 * 
			 * Uses volume serial and file index to uniquely identify files,
			 * allowing detection of symlink loops during directory walking.
			 */
			struct FileId {
				DWORD volumeSerial = 0;     ///< Volume serial number
				uint64_t fileIndex = 0;     ///< File index (high<<32 | low)
				
				[[nodiscard]] bool operator==(const FileId& o) const noexcept {
					return volumeSerial == o.volumeSerial && fileIndex == o.fileIndex;
				}
			};

			/**
			 * @brief Hash functor for FileId (for use in unordered containers).
			 */
			struct FileIdHasher {
				[[nodiscard]] size_t operator()(const FileId& id) const noexcept {
					return std::hash<uint64_t>{}((static_cast<uint64_t>(id.volumeSerial) << 32) ^ id.fileIndex);
				}
			};

			// ============================================================================
			// Path Helpers
			// ============================================================================

			/**
			 * @brief Add long path prefix (\\?\) to enable paths > MAX_PATH.
			 * @param path Input path (may already have prefix)
			 * @return Path with long path prefix
			 */
			[[nodiscard]] std::wstring AddLongPathPrefix(std::wstring_view path);

			/**
			 * @brief Normalize and optionally resolve a path to its final form.
			 * @param path Input path to normalize
			 * @param resolveFinal If true, resolve symlinks to final target
			 * @param err Optional error output
			 * @return Normalized path, or empty string on error
			 */
			[[nodiscard]] std::wstring NormalizePath(std::wstring_view path, bool resolveFinal = false, Error* err = nullptr);

			// ============================================================================
			// File Existence and Status
			// ============================================================================

			/**
			 * @brief Check if a file or directory exists.
			 * @param path Path to check
			 * @param err Optional error output
			 * @return true if exists, false otherwise
			 */
			[[nodiscard]] bool Exists(std::wstring_view path, Error* err = nullptr);

			/**
			 * @brief Check if path is a directory.
			 * @param path Path to check
			 * @param err Optional error output
			 * @return true if directory, false otherwise
			 */
			[[nodiscard]] bool IsDirectory(std::wstring_view path, Error* err = nullptr);

			/**
			 * @brief Get detailed file statistics.
			 * @param path Path to stat
			 * @param out Output stat structure
			 * @param err Optional error output
			 * @return true on success
			 */
			[[nodiscard]] bool Stat(std::wstring_view path, FileStat& out, Error* err = nullptr);

			// ============================================================================
			// File Reading/Writing
			// ============================================================================

			/**
			 * @brief Read entire file contents into memory.
			 * @param path File path
			 * @param out Output buffer
			 * @param err Optional error output
			 * @return true on success
			 * @warning Limited to MAX_READ_FILE_SIZE to prevent memory exhaustion
			 */
			[[nodiscard]] bool ReadAllBytes(std::wstring_view path, std::vector<std::byte>& out, Error* err = nullptr);

			/**
			 * @brief Read file as UTF-8 text.
			 * @param path File path
			 * @param out Output string
			 * @param err Optional error output
			 * @return true on success
			 */
			[[nodiscard]] bool ReadAllTextUtf8(std::wstring_view path, std::string& out, Error* err = nullptr);

			/**
			 * @brief Write data atomically (write to temp, then rename).
			 * @param path Target file path
			 * @param data Data to write
			 * @param len Data length
			 * @param err Optional error output
			 * @return true on success
			 */
			[[nodiscard]] bool WriteAllBytesAtomic(std::wstring_view path, const std::byte* data, size_t len, Error* err = nullptr);

			/**
			 * @brief Write data atomically (vector overload).
			 * @param path Target file path
			 * @param data Data to write
			 * @param err Optional error output
			 * @return true on success
			 */
			[[nodiscard]] bool WriteAllBytesAtomic(std::wstring_view path, const std::vector<std::byte>& data, Error* err = nullptr);

			/**
			 * @brief Write UTF-8 text atomically.
			 * @param path Target file path
			 * @param utf8 Text to write
			 * @param err Optional error output
			 * @return true on success
			 */
			[[nodiscard]] bool WriteAllTextUtf8Atomic(std::wstring_view path, std::string_view utf8, Error* err = nullptr);

			// ============================================================================
			// Atomic Operations
			// ============================================================================

			/**
			 * @brief Atomically replace destination file with source file.
			 * @param srcPath Source file path
			 * @param dstPath Destination file path
			 * @param err Optional error output
			 * @return true on success
			 */
			[[nodiscard]] bool ReplaceFileAtomic(std::wstring_view srcPath, std::wstring_view dstPath, Error* err = nullptr);

			// ============================================================================
			// Directory Operations
			// ============================================================================

			/**
			 * @brief Create directory and all parent directories.
			 * @param dir Directory path to create
			 * @param err Optional error output
			 * @return true on success (or if already exists)
			 */
			[[nodiscard]] bool CreateDirectories(std::wstring_view dir, Error* err = nullptr);

			/**
			 * @brief Remove a single file.
			 * @param path File path
			 * @param err Optional error output
			 * @return true on success
			 */
			[[nodiscard]] bool RemoveFile(std::wstring_view path, Error* err = nullptr);

			/**
			 * @brief Recursively remove a directory and all contents.
			 * @param dir Directory path
			 * @param err Optional error output
			 * @return true on success
			 * @warning Cannot be undone - use with caution
			 */
			[[nodiscard]] bool RemoveDirectoryRecursive(std::wstring_view dir, Error* err = nullptr);

			// ============================================================================
			// Directory Walking
			// ============================================================================

			/**
			 * @brief Callback for directory walking.
			 * @return false to stop walking, true to continue
			 */
			using WalkCallback = std::function<bool(const std::wstring& fullPath, const WIN32_FIND_DATAW& fd)>;

			/**
			 * @brief Walk directory tree with callback.
			 * @param root Root directory to start walking
			 * @param opts Walk options (recursion, filtering, cancellation)
			 * @param cb Callback for each file/directory found
			 * @param err Optional error output
			 * @return true on success (even if cancelled)
			 */
			[[nodiscard]] bool WalkDirectory(std::wstring_view root, const WalkOptions& opts, const WalkCallback& cb, Error* err = nullptr);

			// ============================================================================
			// Alternate Data Streams
			// ============================================================================

			/**
			 * @brief List alternate data streams on a file.
			 * @param path File path
			 * @param out Output vector of stream info
			 * @param err Optional error output
			 * @return true on success
			 */
			[[nodiscard]] bool ListAlternateStreams(std::wstring_view path, std::vector<AlternateStreamInfo>& out, Error* err = nullptr);

			// ============================================================================
			// Cryptographic Operations
			// ============================================================================

			/**
			 * @brief Compute SHA-256 hash of file contents.
			 * @param path File path
			 * @param outHash Output 32-byte hash
			 * @param err Optional error output
			 * @return true on success
			 */
			[[nodiscard]] bool ComputeFileSHA256(std::wstring_view path, std::array<uint8_t, 32>& outHash, Error* err = nullptr);

			// ============================================================================
			// Secure Deletion
			// ============================================================================

			/**
			 * @brief Secure erase mode specifying number of overwrite passes.
			 */
			enum class SecureEraseMode : uint8_t { 
				SinglePassZero = 1,     ///< Single pass of zeros (fast)
				TriplePass = 3          ///< Three passes: random, complement, random (DoD-ish)
			};

			/**
			 * @brief Securely erase a file by overwriting before deletion.
			 * @param path File path
			 * @param mode Overwrite pass mode
			 * @param err Optional error output
			 * @return true on success
			 * @note Does not guarantee secure erasure on SSDs or journaling filesystems
			 */
			[[nodiscard]] bool SecureEraseFile(std::wstring_view path, SecureEraseMode mode = SecureEraseMode::SinglePassZero, Error* err = nullptr);

			// ============================================================================
			// File Handle Operations
			// ============================================================================

			/**
			 * @brief Open file with exclusive access.
			 * @param path File path
			 * @param err Optional error output
			 * @return Valid handle or INVALID_HANDLE_VALUE on error
			 * @warning Caller must close handle with CloseHandle()
			 */
			[[nodiscard]] HANDLE OpenFileExclusive(std::wstring_view path, Error* err = nullptr);

			// ============================================================================
			// Time Operations
			// ============================================================================

			/**
			 * @brief Get file timestamps.
			 * @param path File path
			 * @param creation Output creation time
			 * @param lastAccess Output last access time
			 * @param lastWrite Output last write time
			 * @param err Optional error output
			 * @return true on success
			 */
			[[nodiscard]] bool GetTimes(std::wstring_view path, FILETIME& creation, FILETIME& lastAccess, FILETIME& lastWrite, Error* err = nullptr);

		}//namespace FileUtils
	}//namespace Utils
}//namespace ShadowStrike
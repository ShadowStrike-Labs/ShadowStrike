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

			/// Share mode a SCANNER must use when it opens a file only to read it.
			///
			/// A scanner is an observer. It must never deny the file's owner the right
			/// to keep writing, and must never block a delete: for as long as our
			/// handle is open, a restrictive share mode makes every write or delete by
			/// anyone else fail with ERROR_SHARING_VIOLATION.
			///
			/// MEASURED CONSEQUENCE, 1.0.103 field run over 803 seconds. The
			/// memory-mapping helper opened C:\Windows\System32\catroot2\edb.log - the
			/// write-ahead transaction log of the ESE database behind the Windows
			/// catalog store - with FILE_SHARE_READ, which locked ESE out of its own
			/// log for the whole scan. CryptSvc stalled; our own signature
			/// verification then waited on CryptSvc for 35.0 seconds per call, ten
			/// times over, 283 seconds of blocking in total; winlogon and Explorer
			/// queued behind the same service and the desktop never composed.
			///
			/// THIS REPLACES AN EXPLICIT BUT MISTAKEN RATIONALE, restated here so it
			/// is not reinstated. MemoryUtils::OpenFileForMap carried the comment
			/// "Read-only: deny concurrent writes to prevent TOCTOU during scanning".
			/// Denying writes does not prevent that TOCTOU: the substitution can happen
			/// the instant our handle closes and before the verdict is consumed. The
			/// product already defends against it where the defence actually belongs,
			/// by re-reading size and last-write time before publishing a cached
			/// verdict and by keying the verdict cache on that identity. What the
			/// restrictive share mode bought was not integrity; it was the ability to
			/// freeze other processes.
			///
			/// It was also self-defeating. The same scan reads the same bytes through
			/// HashUtils::ComputeFile and FileUtils::ReadAllBytes, and both of those
			/// already pass full sharing, so the restriction never covered a whole
			/// scan - it only ever added a way to stall the file's owner.
			///
			/// RESIDUAL, STATED RATHER THAN HIDDEN: a concurrent write can now give a
			/// torn read, which is a possibly wrong verdict on one file instead of a
			/// stalled machine. Truncation cannot fault a mapped view, because a
			/// section object blocks SetEndOfFile while it exists, and the file is
			/// re-examined when its last handle closes.
			inline constexpr DWORD SCANNER_READ_SHARE_MODE =
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

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
				void clear() noexcept { win32 = 0; message.clear(); }
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
			 * @brief Whether a file's CONTENT is resident on this machine.
			 *
			 * A cloud placeholder (OneDrive Files On-Demand, and any other
			 * provider built on the Cloud Filter API) is a real directory entry
			 * with a real size and real timestamps whose DATA may not be on this
			 * volume at all. Reading it is what triggers the download.
			 *
			 * WHY THIS EXISTS AT ALL — this is a platform constraint, not a
			 * defect we can code around. A process running as a SERVICE, in
			 * session 0, cannot hydrate a placeholder: the open fails with
			 * ERROR_CLOUD_FILE_ACCESS_DENIED (395) instead of fetching the
			 * content. Microsoft reproduced this on their own CloudMirror sample
			 * and it is unresolved. Admin rights do not change it and neither
			 * does any CreateFileW flag combination. Our scan service is exactly
			 * that kind of process, so for a dehydrated file the read cannot be
			 * made to succeed from where we are standing.
			 *
			 * In the 1.0.94 field run this was not theoretical: eicar.com and
			 * eicar_com.zip were both sitting on the user's Desktop, both inside
			 * OneDrive, and every attempt to read either returned 395. A known
			 * malicious file was physically present and could not be examined.
			 *
			 * DO NOT "FIX" THIS WITH FILE_FLAG_OPEN_NO_RECALL. That flag means
			 * "do not fetch the data", so on a dehydrated file it leaves nothing
			 * to read. The open would start succeeding while the scan examined no
			 * real content, and the file would be reported clean. That converts a
			 * visible failure into a silent false negative, which is strictly
			 * worse than the error it replaces.
			 *
			 * Attributes, unlike content, ARE readable from a service — which is
			 * what makes this probe possible.
			 */
			enum class ContentLocality : uint8_t {
				/// Content is resident and can be read normally. DELIBERATELY the
				/// zero value: an uninitialised or undetermined answer must lead
				/// to a full read attempt, never to a skip.
				Local = 0,
				/// A placeholder whose data is not resident. Reading it from a
				/// service cannot succeed, so attempting it wastes a syscall and
				/// produces an error that means something quite specific.
				NotLocal,
				/// The state could not be determined. Callers MUST treat this
				/// exactly like Local and attempt the read; it exists so the
				/// undetermined case can be counted separately from the known-good
				/// one rather than hidden inside it.
				Unknown
			};

			/**
			 * @brief Determine whether a file's content is resident locally.
			 *
			 * Uses GetFileAttributesExW, which takes NO handle. That matters
			 * twice over: it cannot itself trigger a hydration, and it does not
			 * re-enter our own minifilter, so it is safe to call from a thread
			 * that owes the kernel a scan verdict. The trust-determination worker
			 * already relies on the same property of the same API.
			 *
			 * @param path Absolute path to test. Long-path prefixed internally.
			 * @return Local, NotLocal, or Unknown. Never throws.
			 */
			[[nodiscard]] ContentLocality GetContentLocality(std::wstring_view path) noexcept;

			/**
			 * @brief True if a Win32 error means "the content is not local".
			 *
			 * Centralised so the three read helpers and the scan-result mapping
			 * cannot drift on which codes carry this meaning.
			 */
			[[nodiscard]] bool IsContentNotLocalError(DWORD win32Error) noexcept;


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

			/**
			 * @brief Resolve a kernel NT device path to an openable Win32 DOS path.
			 *
			 * Maps "\Device\HarddiskVolumeN\..." (as delivered by the minifilter) to
			 * its DOS form "X:\..." via QueryDosDevice, with a "\\?\GLOBALROOT"
			 * fallback for letterless volumes. Non-device paths are returned
			 * unchanged. TRUSTED kernel-originated paths only — unlike NormalizePath
			 * it intentionally accepts the device namespace so scanners can open the
			 * file the kernel asked about.
			 *
			 * @param ntPath NT device path from a kernel scan request.
			 * @return An openable Win32 path, or the input unchanged if not a device path.
			 */
			[[nodiscard]] std::wstring DevicePathToDosPath(std::wstring_view ntPath);

			/**
			 * @brief Verify that a path resides within an expected root directory.
			 * 
			 * SECURITY: This function provides protection against path traversal attacks.
			 * It normalizes both the path and root, then verifies the path is a descendant
			 * of the root directory. This should be used after NormalizePath to ensure
			 * user-supplied paths don't escape their intended directory scope.
			 * 
			 * @param path The path to validate (will be normalized)
			 * @param root The root directory the path must reside within (will be normalized)
			 * @param resolveSymlinks If true, resolve symlinks before comparison
			 * @param err Optional error output
			 * @return true if path is under root, false otherwise (including on any error)
			 * 
			 * @example
			 * @code
			 *   // Validate user input stays within data directory
			 *   if (!IsPathUnderRoot(userPath, L"C:\\AppData\\MyApp", true, &err)) {
			 *       // Reject the path - potential traversal attack
			 *   }
			 * @endcode
			 */
			[[nodiscard]] bool IsPathUnderRoot(std::wstring_view path, std::wstring_view root, 
			                                   bool resolveSymlinks = true, Error* err = nullptr);

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
			 *
			 * @note ERROR CONTRACT, and it is specific to this function. When err is
			 *       supplied it is CLEARED on entry, and every failure path leaves it
			 *       holding a non-zero win32 code AND a non-empty message naming the
			 *       file. So for this function - and not yet for the rest of this
			 *       module - err.hasError() is exactly equivalent to a returned false,
			 *       and a caller may report err.message without first checking whether
			 *       there is anything in it. Callers that pass nullptr still get the
			 *       return value but no reason, which is why the on-access scan path
			 *       passes an Error.
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

			/**
			 * @brief Create a NEW file and write it in place, without a temp-and-rename.
			 *
			 * WHY THIS EXISTS ALONGSIDE WriteAllBytesAtomic. The atomic writer exists to
			 * REPLACE the contents of a file that may already exist, and it earns its
			 * atomicity by writing a sibling temp file and renaming it over the target.
			 * For a file that must NOT already exist there is nothing to replace, so the
			 * rename buys no atomicity and costs two extra filesystem operations - a
			 * rename and, on failure, a delete.
			 *
			 * That distinction stopped being academic in the 1.0.99 field run. Eleven
			 * ransomware decoys failed to deploy into the user's Downloads and Pictures
			 * folders because the rename was denied with ERROR_ACCESS_DENIED and the
			 * cleanup delete was denied too - while the temp file CREATION had
			 * succeeded. The result was eleven undeletable .~*.tmp files left in the
			 * user's own folders. Creating the file directly uses only the operation
			 * that was observed to work and leaves nothing behind when it does not.
			 *
			 * SECURITY PROPERTIES ARE THE SAME ONES THE TEMP OPEN RELIES ON, and they
			 * are the reason this is not simply CreateFileW at the call site: CREATE_NEW
			 * so an existing file is never overwritten, and FILE_FLAG_OPEN_REPARSE_POINT
			 * so a pre-planted reparse point cannot redirect the write to a victim path.
			 * A partially written file is removed, and if that removal is itself denied
			 * the leftover is reported rather than left silent.
			 *
			 * NOT a substitute for WriteAllBytesAtomic. A reader can observe this file
			 * while it is still being written, which is acceptable only when no reader
			 * depends on its contents.
			 *
			 * @param path Target file path. Must not already exist.
			 * @param data Data to write
			 * @param len  Byte count
			 * @param err  Optional error output
			 * @return true on success. ERROR_FILE_EXISTS if the path is already present.
			 */
			[[nodiscard]] bool WriteNewFileExclusive(std::wstring_view path, const std::byte* data, size_t len, Error* err = nullptr);

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
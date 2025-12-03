#include "FileUtils.hpp"
#include <algorithm>
#include <memory>
#include<string>
#include<stdexcept>
#include <exception>
#include <unordered_set>
#include <cstdio>
#include <Aclapi.h>
#include <winioctl.h>
#include <bcrypt.h>
#include <winternl.h>
#include <objbase.h>  // For CoCreateGuid

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ole32.lib")  // For CoCreateGuid

// NT_SUCCESS macro is not available in standard Windows SDK headers
// It's defined in ntdef.h (DDK) but we define it here for portability
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace ShadowStrike {
	namespace Utils {

		namespace FileUtils {

			// ============================================================================
			// Internal Helper Functions
			// ============================================================================

			/**
			 * @brief Convert wide string view to wide string.
			 * @param s Input string view
			 * @return Copy as std::wstring
			 */
			[[nodiscard]] static inline std::wstring ToW(std::wstring_view s) noexcept {
				try {
					return std::wstring(s.data(), s.size());
				}
				catch (...) {
					return std::wstring();
				}
			}

			/**
			 * @brief Check if walk operation should be cancelled.
			 * @param opts Walk options containing cancel flag
			 * @return true if cancellation requested
			 */
			[[nodiscard]] static inline bool IsCancel(const WalkOptions& opts) noexcept {
				return (opts.cancelFlag != nullptr && opts.cancelFlag->load(std::memory_order_acquire));
			}

			/**
			 * @brief Validate path for dangerous patterns (path traversal, null bytes).
			 * @param path Path to validate
			 * @return true if path is safe, false if potentially malicious
			 */
			[[nodiscard]] static bool ValidatePath(std::wstring_view path) noexcept {
				// Reject empty paths
				if (path.empty()) return false;

				// Reject paths with embedded null bytes (could be truncation attack)
				if (path.find(L'\0') != std::wstring_view::npos) return false;

				// Reject excessively long paths (DoS prevention)
				if (path.size() > MAX_REASONABLE_PATH_LENGTH) return false;

				return true;
			}


			// ============================================================================
			// Path Operations
			// ============================================================================



			/**
			 * @brief Add long path prefix (\\?\) to enable paths exceeding MAX_PATH.
			 * 
			 * Windows has a legacy 260 character path limit. Using the \\?\ prefix
			 * bypasses this limitation for paths up to ~32767 characters.
			 *
			 * @param path Input path (may already have prefix)
			 * @return Path with long path prefix, or empty on error
			 */
            std::wstring AddLongPathPrefix(std::wstring_view path) {
                // Validate input
                if (path.empty()) {
                    return std::wstring();
                }

                // Reject excessively long paths
                if (path.size() > MAX_REASONABLE_PATH_LENGTH) {
                    SS_LOG_ERROR(L"FileUtils", L"AddLongPathPrefix: Path exceeds maximum length: %zu", path.size());
                    return std::wstring();
                }

                // Already has long path prefix
                if (path.size() >= LONG_PATH_PREFIX.size() &&
                    path.substr(0, LONG_PATH_PREFIX.size()) == LONG_PATH_PREFIX) {
                    return ToW(path);
                }

                // Handle UNC paths (\\server\share)
                if (path.size() >= 2 && path[0] == L'\\' && path[1] == L'\\') {
                    // UNC path -> \\?\UNC\server\share
                    std::wstring out;
                    try {
                        out.reserve(LONG_PATH_PREFIX_UNC.size() + path.size());
                        out.append(LONG_PATH_PREFIX_UNC);
                        out.append(path.substr(2));  // Skip leading 
                    }
                    catch (const std::bad_alloc&) {
                        SS_LOG_ERROR(L"FileUtils", L"AddLongPathPrefix: Memory allocation failed for UNC path");
                        return std::wstring();
                    }
                    return out;
                    }

                // Regular path -> \\?\path
                std::wstring out;
                try {
                    out.reserve(LONG_PATH_PREFIX.size() + path.size());
                    out.append(LONG_PATH_PREFIX);
                    out.append(path);
                }
                catch (const std::exception&) {
                    SS_LOG_ERROR(L"FileUtils", L"AddLongPathPrefix: Memory allocation failed");
                    return std::wstring();
                }
                return out;
            }
            


            /**
             * @brief Normalize path and optionally resolve to final target.
             * 
             * Validates input for dangerous patterns, resolves relative paths,
             * and optionally resolves symbolic links/junctions to final target.
             *
             * @param path Input path
             * @param resolveFinal If true, resolve symlinks to actual target
             * @param err Optional error output
             * @return Normalized path, or empty string on error
             */
            std::wstring NormalizePath(std::wstring_view path, bool resolveFinal, Error* err) {
                // Input validation
                if (!ValidatePath(path)) {
                    if (err) {
                        err->win32 = ERROR_INVALID_PARAMETER;
                        err->message = "Invalid or empty path";
                    }
                    return std::wstring();
                }

                std::wstring input = ToW(path);
                if (input.empty()) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return std::wstring();
                }

                // Windows forbidden filename characters (except colon for drive letters)
                constexpr wchar_t invalidChars[] = L"<>|?*\"";
                if (input.find_first_of(invalidChars) != std::wstring::npos) {
                    if (err) {
                        err->win32 = ERROR_INVALID_NAME;
                        err->message = "Path contains invalid characters";
                    }
                    return std::wstring();
                }

                // Validate colon placement (only valid at position 1 for drive letter)
                const size_t colonPos = input.find(L':');
                if (colonPos != std::wstring::npos && colonPos != 1) {
                    if (err) {
                        err->win32 = ERROR_INVALID_NAME;
                        err->message = "Invalid colon position in path";
                    }
                    return std::wstring();
                }

                // Get required buffer size for full path
                const DWORD need = GetFullPathNameW(input.c_str(), 0, nullptr, nullptr);
                if (need == 0) {
                    if (err) err->win32 = GetLastError();
                    return std::wstring();
                }

                // Sanity check on required size
                if (need > MAX_REASONABLE_PATH_LENGTH) {
                    if (err) {
                        err->win32 = ERROR_BUFFER_OVERFLOW;
                        err->message = "Resolved path would exceed maximum length";
                    }
                    return std::wstring();
                }

                std::wstring full;
                try {
                    full.resize(need);
                }
                catch (const std::bad_alloc&) {
                    if (err) err->win32 = ERROR_NOT_ENOUGH_MEMORY;
                    return std::wstring();
                }

                const DWORD got = GetFullPathNameW(input.c_str(), need, &full[0], nullptr);
                if (got == 0) {
                    if (err) err->win32 = GetLastError();
                    return std::wstring();
                }

                // Remove trailing null if present
                while (!full.empty() && full.back() == L'\0') {
                    full.pop_back();
                }

                // Return full path if not resolving final target
                if (!resolveFinal) {
                    return full;
                }

                // Resolve final path through handle (resolves symlinks/junctions)
                const std::wstring longp = AddLongPathPrefix(full);
                HANDLE h = CreateFileW(
                    longp.c_str(),
                    FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,  // Required for directories
                    nullptr
                );

                if (h == INVALID_HANDLE_VALUE) {
                    if (err) err->win32 = GetLastError();
                    return full;  // Return full path as fallback
                }

                // RAII handle cleanup
                struct HandleGuard {
                    HANDLE h;
                    ~HandleGuard() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
                } guard{ h };

                // Get required buffer size for final path
                const DWORD sz = GetFinalPathNameByHandleW(h, nullptr, 0, FILE_NAME_NORMALIZED);
                if (sz == 0) {
                    if (err) err->win32 = GetLastError();
                    return full;  // Return full path as fallback
                }

                // Sanity check
                if (sz > MAX_REASONABLE_PATH_LENGTH) {
                    if (err) {
                        err->win32 = ERROR_BUFFER_OVERFLOW;
                        err->message = "Final path exceeds maximum length";
                    }
                    return full;
                }

                std::wstring finalPath;
                try {
                    finalPath.resize(sz);
                }
                catch (const std::bad_alloc&) {
                    if (err) err->win32 = ERROR_NOT_ENOUGH_MEMORY;
                    return full;
                }

                const DWORD sz2 = GetFinalPathNameByHandleW(h, &finalPath[0], sz, FILE_NAME_NORMALIZED);
                if (sz2 == 0 || sz2 >= sz) {
                    if (err) err->win32 = GetLastError();
                    return full;
                }

                // Resize to actual length and remove trailing null
                finalPath.resize(sz2);
                while (!finalPath.empty() && finalPath.back() == L'\0') {
                    finalPath.pop_back();
                }

                return finalPath;
            }


            // ============================================================================
            // File Existence and Status Operations
            // ============================================================================

            bool Exists(std::wstring_view path, Error* err) {
                if (!ValidatePath(path)) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                WIN32_FILE_ATTRIBUTE_DATA fad{};
                const std::wstring longp = AddLongPathPrefix(path);
                if (longp.empty()) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                if (!GetFileAttributesExW(longp.c_str(), GetFileExInfoStandard, &fad)) {
                    const DWORD lastErr = GetLastError();
                    if (err) err->win32 = lastErr;
                    return false;
                }
                return true;
            }

            bool IsDirectory(std::wstring_view path, Error* err) {
                if (!ValidatePath(path)) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                WIN32_FILE_ATTRIBUTE_DATA fad{};
                const std::wstring longp = AddLongPathPrefix(path);
                if (longp.empty()) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                if (!GetFileAttributesExW(longp.c_str(), GetFileExInfoStandard, &fad)) {
                    const DWORD lastErr = GetLastError();
                    if (err) err->win32 = lastErr;
                    return false;
                }
                return (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            }


            bool Stat(std::wstring_view path, FileStat& out, Error* err) {
                // Initialize output
                out = FileStat{};

                if (!ValidatePath(path)) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                WIN32_FILE_ATTRIBUTE_DATA fad{};
                const std::wstring longp = AddLongPathPrefix(path);
                if (longp.empty()) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                if (!GetFileAttributesExW(longp.c_str(), GetFileExInfoStandard, &fad)) {
                    const DWORD lastErr = GetLastError();
                    if (err) err->win32 = lastErr;
                    out.exists = false;
                    return false;
                }

                out.exists = true;
                out.isDirectory = (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                out.isReparsePoint = (fad.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
                out.isHidden = (fad.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) != 0;
                out.isSystem = (fad.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) != 0;
                out.attributes = fad.dwFileAttributes;
                out.creation = fad.ftCreationTime;
                out.lastAccess = fad.ftLastAccessTime;
                out.lastWrite = fad.ftLastWriteTime;

                // Calculate size (0 for directories)
                if (!out.isDirectory) {
                    out.size = (static_cast<uint64_t>(fad.nFileSizeHigh) << 32) | fad.nFileSizeLow;
                }
                else {
                    out.size = 0;
                }
                return true;
            }

            /**
             * @brief Get file size if it exists and is not a directory.
             * @param path File path
             * @param err Optional error output
             * @return File size or nullopt on error
             */
            [[nodiscard]] std::optional<uint64_t> FileSize(std::wstring_view path, Error* err) {
                FileStat st{};
                if (!Stat(path, st, err) || !st.exists || st.isDirectory) {
                    return std::nullopt;
                }
                return st.size;
            }

            // ============================================================================
            // File Reading Operations
            // ============================================================================

            /**
             * @brief Internal implementation to read file contents into vector.
             * 
             * Reads file in chunks to handle large files and avoid DWORD overflow.
             *
             * @param h Valid file handle opened for reading
             * @param out Output vector to receive data
             * @param fileSize Expected file size
             * @param err Optional error output
             * @return true on success
             */
            [[nodiscard]] static bool ReadAllBytesImpl(HANDLE h, std::vector<std::byte>& out, uint64_t fileSize, Error* err) {
                out.clear();

                // Limit maximum file size to prevent memory exhaustion attacks
                // Note: Using header constant MAX_READ_FILE_SIZE would be better for consistency
                constexpr uint64_t MAX_FILE_SIZE = 64ULL * 1024 * 1024 * 1024;  // 64 GB max
                
                if (fileSize > SIZE_MAX || fileSize > MAX_FILE_SIZE) {
                    if (err) {
                        err->win32 = ERROR_FILE_TOO_LARGE;
                        err->message = "File exceeds maximum allowed size";
                    }
                    return false;
                }

                try {
                    out.resize(static_cast<size_t>(fileSize));
                }
                catch (const std::bad_alloc&) {
                    if (err) err->win32 = ERROR_NOT_ENOUGH_MEMORY;
                    SS_LOG_ERROR(L"FileUtils", L"Memory allocation failed for size: %llu", fileSize);
                    return false;
                }

                uint8_t* ptr = reinterpret_cast<uint8_t*>(out.data());
                size_t toRead = out.size();
                size_t offset = 0;

                // Read in 4MB chunks to avoid DWORD overflow and allow cancellation
                constexpr DWORD MAX_CHUNK_SIZE = 4 * 1024 * 1024;

                while (toRead > 0) {
                    DWORD thisRead = 0;
                    const DWORD askSize = (toRead > MAX_CHUNK_SIZE) ? MAX_CHUNK_SIZE : static_cast<DWORD>(toRead);
                    
                    if (!ReadFile(h, ptr + offset, askSize, &thisRead, nullptr)) {
                        if (err) err->win32 = GetLastError();
                        return false;
                    }
                    
                    // EOF reached
                    if (thisRead == 0) break;
                    
                    offset += thisRead;
                    toRead -= thisRead;
                }
                
                // Resize to actual bytes read
                out.resize(offset);
                return true;
            }

            bool ReadAllBytes(std::wstring_view path, std::vector<std::byte>& out, Error* err) {
                out.clear();

                if (!ValidatePath(path)) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                const std::wstring longp = AddLongPathPrefix(path);
                if (longp.empty()) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                HANDLE h = CreateFileW(
                    longp.c_str(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_SEQUENTIAL_SCAN,
                    nullptr
                );

                if (h == INVALID_HANDLE_VALUE) {
                    const DWORD lastError = GetLastError();
                    if (err) err->win32 = lastError;
                    // Don't log for expected errors (file not found)
                    if (lastError != ERROR_FILE_NOT_FOUND && lastError != ERROR_PATH_NOT_FOUND) {
                        SS_LOG_LAST_ERROR(L"FileUtils", L"ReadAllBytes: CreateFileW failed: %s", longp.c_str());
                    }
                    return false;
                }

                // RAII cleanup for handle
                struct HandleGuard {
                    HANDLE h;
                    ~HandleGuard() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
                } guard{ h };

                LARGE_INTEGER sz{};
                if (!GetFileSizeEx(h, &sz)) {
                    if (err) err->win32 = GetLastError();
                    return false;
                }
                
                return ReadAllBytesImpl(h, out, static_cast<uint64_t>(sz.QuadPart), err);
            }

            bool ReadAllTextUtf8(std::wstring_view path, std::string& out, Error* err) {
                out.clear();
                std::vector<std::byte> bytes;
                if (!ReadAllBytes(path, bytes, err)) {
                    return false;
                }
                out.assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
                return true;
            }

            // ============================================================================
            // File Writing Operations
            // ============================================================================

            /**
             * @brief Generate a unique temporary filename in the same directory.
             * 
             * Creates a sibling temp file name using a GUID for uniqueness.
             * Format: .~original_name_GUID.tmp
             *
             * @param dstPath Original destination path
             * @return Unique temp file path, or empty on error
             */
            [[nodiscard]] static std::wstring MakeTempSibling(std::wstring_view dstPath) {
                if (dstPath.empty()) {
                    return std::wstring();
                }

                std::wstring p(dstPath);
                const auto pos = p.find_last_of(L"\\/");
                const std::wstring dir = (pos == std::wstring::npos) ? L"" : p.substr(0, pos);
                const std::wstring file = (pos == std::wstring::npos) ? p : p.substr(pos + 1);

                // Create unique file name using GUID
                GUID guid{};
                const HRESULT hr = CoCreateGuid(&guid);
                if (FAILED(hr)) {
                    SS_LOG_ERROR(L"FileUtils", L"MakeTempSibling: CoCreateGuid failed with HRESULT: 0x%08lX", hr);
                    // Fallback: use timestamp + counter for uniqueness
                    static std::atomic<uint32_t> counter{ 0 };
                    const uint64_t ts = GetTickCount64();
                    const uint32_t cnt = counter.fetch_add(1, std::memory_order_relaxed);
                    
                    std::wstring tmp;
                    try {
                        tmp.reserve(p.size() + 32);
                        if (!dir.empty()) {
                            tmp.append(dir);
                            tmp.push_back(L'\\');
                        }
                        tmp.append(L".~");
                        tmp.append(file);
                        tmp.append(L"_");
                        wchar_t fallbackStr[32];
                        swprintf_s(fallbackStr, L"%llX_%08X", ts, cnt);
                        tmp.append(fallbackStr);
                        tmp.append(L".tmp");
                    }
                    catch (const std::exception&) {
                        return std::wstring();
                    }
                    return tmp;
                }

                wchar_t guidStr[40];
                swprintf_s(guidStr, L"%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                    guid.Data1, guid.Data2, guid.Data3,
                    guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
                    guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);

                std::wstring tmp;
                try {
                    tmp.reserve(p.size() + 64);
                    if (!dir.empty()) {
                        tmp.append(dir);
                        tmp.push_back(L'\\');
                    }
                    tmp.append(L".~");
                    tmp.append(file);
                    tmp.append(L"_");
                    tmp.append(guidStr);
                    tmp.append(L".tmp");
                }
                catch (const std::exception&) {
                    return std::wstring();
                }
                return tmp;
            }


            bool WriteAllBytesAtomic(std::wstring_view path, const std::byte* data, size_t len, Error* err) {
                // Validate parameters
                if (!data && len != 0) {
                    if (err) {
                        err->win32 = ERROR_INVALID_PARAMETER;
                        err->message = "Null data pointer with non-zero length";
                    }
                    return false;
                }

                if (!ValidatePath(path)) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                const std::wstring dst = ToW(path);
                if (dst.empty()) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                const std::wstring tmp = MakeTempSibling(dst);
                if (tmp.empty()) {
                    if (err) {
                        err->win32 = ERROR_OUTOFMEMORY;
                        err->message = "Failed to generate temp filename";
                    }
                    return false;
                }

                // Create parent directories if needed
                const auto lastSep = dst.find_last_of(L"\\/");
                if (lastSep != std::wstring::npos) {
                    if (!CreateDirectories(dst.substr(0, lastSep), err)) {
                        SS_LOG_LAST_ERROR(L"FileUtils", L"Creating directories failed: %s", dst.c_str());
                        return false;
                    }
                }

                const std::wstring longTmp = AddLongPathPrefix(tmp);
                if (longTmp.empty()) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                HANDLE h = CreateFileW(
                    longTmp.c_str(),
                    GENERIC_WRITE,
                    FILE_SHARE_READ,
                    nullptr,
                    CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                    nullptr
                );

                if (h == INVALID_HANDLE_VALUE) {
                    if (err) err->win32 = GetLastError();
                    SS_LOG_LAST_ERROR(L"FileUtils", L"WriteAllBytesAtomic: CreateFileW failed: %s", longTmp.c_str());
                    return false;
                }

                // RAII for temp file cleanup on error
                bool success = false;
                struct TempFileGuard {
                    HANDLE& h;
                    const std::wstring& tmp;
                    bool& success;
                    ~TempFileGuard() {
                        if (h != INVALID_HANDLE_VALUE) {
                            CloseHandle(h);
                            h = INVALID_HANDLE_VALUE;
                        }
                        if (!success) {
                            RemoveFile(tmp);
                        }
                    }
                } guard{ h, tmp, success };

                const uint8_t* ptr = reinterpret_cast<const uint8_t*>(data);
                size_t toWrite = len;
                size_t offset = 0;
                constexpr DWORD MAX_CHUNK_SIZE = 4 * 1024 * 1024;  // 4MB chunks

                while (toWrite > 0) {
                    DWORD thisWrite = 0;
                    const DWORD chunk = (toWrite > MAX_CHUNK_SIZE) ? MAX_CHUNK_SIZE : static_cast<DWORD>(toWrite);
                    
                    if (!WriteFile(h, ptr + offset, chunk, &thisWrite, nullptr)) {
                        if (err) err->win32 = GetLastError();
                        return false;
                    }
                    
                    // No progress indicates error
                    if (thisWrite == 0) {
                        if (err) {
                            err->win32 = ERROR_WRITE_FAULT;
                            err->message = "WriteFile returned zero bytes";
                        }
                        return false;
                    }
                    
                    offset += thisWrite;
                    toWrite -= thisWrite;
                }

                // Ensure data is flushed to disk before rename
                if (!FlushFileBuffers(h)) {
                    if (err) err->win32 = GetLastError();
                    SS_LOG_LAST_ERROR(L"FileUtils", L"WriteAllBytesAtomic: FlushFileBuffers failed");
                    return false;
                }

                // Close handle before rename
                CloseHandle(h);
                h = INVALID_HANDLE_VALUE;

                // Atomic replace
                if (!ReplaceFileAtomic(tmp, dst, err)) {
                    return false;
                }

                success = true;
                return true;
            }


            bool WriteAllBytesAtomic(std::wstring_view path, const std::vector<std::byte>& data, Error* err) {
                return WriteAllBytesAtomic(path, data.data(), data.size(), err);
            }

            bool WriteAllTextUtf8Atomic(std::wstring_view path, std::string_view utf8, Error* err) {
                return WriteAllBytesAtomic(path, reinterpret_cast<const std::byte*>(utf8.data()), utf8.size(), err);
            }

            // ============================================================================
            // Atomic File Operations
            // ============================================================================

            bool ReplaceFileAtomic(std::wstring_view srcPath, std::wstring_view dstPath, Error* err) {
                if (!ValidatePath(srcPath) || !ValidatePath(dstPath)) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                const std::wstring longSrc = AddLongPathPrefix(srcPath);
                const std::wstring longDst = AddLongPathPrefix(dstPath);
                if (!MoveFileExW(longSrc.c_str(), longDst.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                    if (err) err->win32 = GetLastError();
                    SS_LOG_LAST_ERROR(L"FileUtils", L"ReplaceFileAtomic: MoveFileExW failed: %s -> %s", longSrc.c_str(), longDst.c_str());
                    return false;
                }
                return true;
            }
            // ============================================================================
            // Directory Operations
            // ============================================================================

            /**
             * @brief Create directory and all parent directories recursively.
             * 
             * Similar to "mkdir -p" on Unix. Creates all intermediate directories
             * as needed. Returns success if directory already exists.
             *
             * @param dir Directory path to create
             * @param err Optional error output
             * @return true on success or if directory already exists
             */
            bool CreateDirectories(std::wstring_view dir, Error* err) {
                if (dir.empty()) return true;

                if (!ValidatePath(dir)) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                std::wstring d = ToW(dir);
                if (d.empty()) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                // Path traversal attack prevention - reject ".." components
                // This prevents directory escape attacks
                if (d.find(L"..") != std::wstring::npos) {
                    if (err) {
                        err->win32 = ERROR_INVALID_PARAMETER;
                        err->message = "Path contains '..' component";
                    }
                    SS_LOG_ERROR(L"FileUtils", L"CreateDirectories: Path contains ..: %s", d.c_str());
                    return false;
                }

                // Windows invalid filename characters
                constexpr wchar_t invalidChars[] = L"<>\"|?*";
                if (d.find_first_of(invalidChars) != std::wstring::npos) {
                    if (err) err->win32 = ERROR_INVALID_NAME;
                    return false;
                }

                // Validate colon placement (only valid at position 1 for drive letter)
                size_t colonPos = d.find(L':');
                while (colonPos != std::wstring::npos) {
                    if (colonPos != 1) {
                        if (err) {
                            err->win32 = ERROR_INVALID_NAME;
                            err->message = "Invalid colon position in path";
                        }
                        SS_LOG_ERROR(L"FileUtils", L"CreateDirectories: Invalid colon position in path");
                        return false;
                    }
                    colonPos = d.find(L':', colonPos + 1);
                }

                std::wstring cur;
                try {
                    // Reserve space for long path prefix
                    cur.reserve(d.size() + LONG_PATH_PREFIX.size() + 8);
                }
                catch (const std::bad_alloc&) {
                    if (err) err->win32 = ERROR_NOT_ENOUGH_MEMORY;
                    return false;
                }

                for (size_t i = 0; i < d.size(); ++i) {
                    wchar_t c = d[i];
                    // Normalize separators
                    if (c == L'/') c = L'\\';
                    cur.push_back(c);

                    // Create intermediate directories (skip drive root like "C:\")
                    if (c == L'\\' && cur.size() > 3) {
                        const std::wstring longp = AddLongPathPrefix(cur);
                        if (!CreateDirectoryW(longp.c_str(), nullptr)) {
                            const DWORD ec = GetLastError();
                            if (ec != ERROR_ALREADY_EXISTS) {
                                if (err) err->win32 = ec;
                                SS_LOG_LAST_ERROR(L"FileUtils", L"CreateDirectories failed for: %s", cur.c_str());
                                return false;
                            }
                        }
                    }
                }

                // Create final directory
                const std::wstring longp = AddLongPathPrefix(d);
                if (!CreateDirectoryW(longp.c_str(), nullptr)) {
                    const DWORD ec = GetLastError();
                    if (ec != ERROR_ALREADY_EXISTS) {
                        if (err) err->win32 = ec;
                        SS_LOG_LAST_ERROR(L"FileUtils", L"CreateDirectories final failed: %s", d.c_str());
                        return false;
                    }
                }

                return true;
            }

            bool RemoveFile(std::wstring_view path, Error* err) {
                if (!ValidatePath(path)) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                const std::wstring longp = AddLongPathPrefix(path);
                if (longp.empty()) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                if (!DeleteFileW(longp.c_str())) {
                    const DWORD ec = GetLastError();
                    // File not found is not an error for removal
                    if (ec == ERROR_FILE_NOT_FOUND) return true;
                    if (err) err->win32 = ec;
                    SS_LOG_LAST_ERROR(L"FileUtils", L"RemoveFile: DeleteFileW failed: %s", longp.c_str());
                    return false;
                }
                return true;
            }

            // ============================================================================
            // Directory Walking
            // ============================================================================

            /**
             * @brief Get unique file identifier from handle.
             * 
             * Uses volume serial and file index to uniquely identify files
             * across symlinks/hardlinks for loop detection.
             *
             * @param h Valid file handle
             * @param id Output file identifier
             * @return true on success
             */
            [[nodiscard]] static bool GetFileIdFromHandle(HANDLE h, FileId& id) noexcept {
                BY_HANDLE_FILE_INFORMATION info{};
                if (!GetFileInformationByHandle(h, &info)) {
                    return false;
                }
                id.volumeSerial = info.dwVolumeSerialNumber;
                id.fileIndex = (static_cast<uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
                return true;
            }

            /**
             * @brief Check if directory entry should be skipped based on options.
             * @param fd Find data for the entry
             * @param opts Walk options
             * @return true if entry should be skipped
             */
            [[nodiscard]] static bool ShouldSkip(const WIN32_FIND_DATAW& fd, const WalkOptions& opts) noexcept {
                if (opts.skipHidden && (fd.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)) return true;
                if (opts.skipSystem && (fd.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)) return true;
                return false;
            }

            /**
             * @brief Walk a directory tree with callback.
             * 
             * Iterates over files in a directory tree, calling the callback for each.
             * Features:
             * - Symlink loop detection using file IDs
             * - Maximum depth limiting
             * - Cancellation support via atomic flag
             * - Hidden/system file filtering
             *
             * @param root Root directory to start walking
             * @param opts Walk options
             * @param cb Callback for each file (return false to stop)
             * @param err Optional error output
             * @return true on success (including cancellation)
             */
            bool WalkDirectory(std::wstring_view root, const WalkOptions& opts, const WalkCallback& cb, Error* err) {
                // Maximum recursion depth to prevent stack overflow from deeply nested directories
                constexpr size_t MAX_ABSOLUTE_DEPTH = 256;
                // Maximum symlink chain length to prevent infinite loops
                constexpr size_t MAX_SYMLINK_CHAIN = 40;

                if (!ValidatePath(root)) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                std::wstring base = ToW(root);
                if (base.empty()) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                // Verify root is a directory
                Error dirErr{};
                if (!IsDirectory(base, &dirErr)) {
                    if (err) {
                        err->win32 = dirErr.win32 ? dirErr.win32 : ERROR_DIRECTORY;
                        err->message = "Root path is not a directory";
                    }
                    return false;
                }

                // Set of visited directories (by file ID) for loop detection
                std::unordered_set<FileId, FileIdHasher> visited;
                
                // Stack for iterative traversal: (path, depth)
                std::vector<std::pair<std::wstring, size_t>> stack;
                try {
                    stack.reserve(64);  // Pre-allocate for typical directory depth
                    stack.emplace_back(std::move(base), 0);
                }
                catch (const std::bad_alloc&) {
                    if (err) err->win32 = ERROR_NOT_ENOUGH_MEMORY;
                    return false;
                }

                while (!stack.empty()) {
                    // Check for cancellation
                    if (IsCancel(opts)) {
                        // Cancellation is a clean exit, not an error
                        return true;
                    }

                    auto [cur, depth] = std::move(stack.back());
                    stack.pop_back();

                    // Check absolute depth limit (prevents stack overflow)
                    if (depth > MAX_ABSOLUTE_DEPTH) {
                        if (err) {
                            err->win32 = ERROR_CANT_RESOLVE_FILENAME;
                            err->message = "Maximum directory depth exceeded";
                        }
                        SS_LOG_ERROR(L"FileUtils", L"WalkDirectory: Maximum depth exceeded: %s", cur.c_str());
                        return false;
                    }

                    // Check symlink chain limit
                    if (depth > MAX_SYMLINK_CHAIN && opts.followReparsePoints) {
                        SS_LOG_WARN(L"FileUtils", L"WalkDirectory: Symlink chain limit reached: %s", cur.c_str());
                        continue;  // Skip but continue walking
                    }

                    // Get file ID for loop detection
                    {
                        const std::wstring longp = AddLongPathPrefix(cur);
                        HANDLE dh = CreateFileW(
                            longp.c_str(),
                            FILE_READ_ATTRIBUTES,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr,
                            OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS,
                            nullptr
                        );

                        if (dh != INVALID_HANDLE_VALUE) {
                            FileId fid{};
                            const bool gotId = GetFileIdFromHandle(dh, fid);
                            CloseHandle(dh);

                            if (gotId) {
                                if (!visited.insert(fid).second) {
                                    // Already visited - symlink loop detected
                                    SS_LOG_WARN(L"FileUtils", L"Symlink loop detected at: %s", cur.c_str());
                                    continue;
                                }
                            }
                        }
                    }

                    // Build search pattern
                    std::wstring pattern = cur;
                    if (!pattern.empty() && pattern.back() != L'\\') {
                        pattern.push_back(L'\\');
                    }
                    pattern.append(L"*");

                    const std::wstring longPattern = AddLongPathPrefix(pattern);
                    WIN32_FIND_DATAW fd{};
                    HANDLE hFind = FindFirstFileExW(
                        longPattern.c_str(),
                        FindExInfoBasic,
                        &fd,
                        FindExSearchNameMatch,
                        nullptr,
                        FIND_FIRST_EX_LARGE_FETCH
                    );

                    if (hFind == INVALID_HANDLE_VALUE) {
                        const DWORD ec = GetLastError();
                        // Empty directory is not an error
                        if (ec == ERROR_FILE_NOT_FOUND || ec == ERROR_NO_MORE_FILES) {
                            continue;
                        }
                        if (err) err->win32 = ec;
                        SS_LOG_LAST_ERROR(L"FileUtils", L"WalkDirectory: FindFirstFileExW failed: %s", longPattern.c_str());
                        return false;
                    }

                    // RAII for find handle
                    struct FindGuard {
                        HANDLE h;
                        ~FindGuard() { if (h != INVALID_HANDLE_VALUE) FindClose(h); }
                    } findGuard{ hFind };

                    do {
                        // Check for cancellation
                        if (IsCancel(opts)) {
                            return true;
                        }

                        // Skip . and .. entries
                        const std::wstring_view name = fd.cFileName;
                        if (name == L"." || name == L"..") continue;

                        // Apply skip filters
                        if (ShouldSkip(fd, opts)) continue;

                        // Build full child path
                        std::wstring child = cur;
                        if (!child.empty() && child.back() != L'\\') {
                            child.push_back(L'\\');
                        }
                        child.append(fd.cFileName);

                        const bool isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                        const bool isReparse = (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;

                        if (isDir) {
                            // Call callback for directories if requested
                            if (opts.includeDirs) {
                                if (!cb(child, fd)) {
                                    return true;  // Callback requested stop
                                }
                            }

                            // Queue for recursive processing if enabled
                            if (opts.recursive) {
                                // Skip reparse points unless explicitly following them
                                if (isReparse && !opts.followReparsePoints) {
                                    continue;
                                }

                                // Check user's max depth setting
                                if (depth + 1 <= opts.maxDepth) {
                                    try {
                                        stack.emplace_back(std::move(child), depth + 1);
                                    }
                                    catch (const std::bad_alloc&) {
                                        if (err) err->win32 = ERROR_NOT_ENOUGH_MEMORY;
                                        return false;
                                    }
                                }
                            }
                        }
                        else {
                            // Call callback for files
                            if (!cb(child, fd)) {
                                return true;  // Callback requested stop
                            }
                        }
                    } while (FindNextFileW(hFind, &fd));

                    // Check for errors from FindNextFileW
                    const DWORD lastErr = GetLastError();
                    if (lastErr != ERROR_NO_MORE_FILES) {
                        if (err) err->win32 = lastErr;
                        SS_LOG_LAST_ERROR(L"FileUtils", L"WalkDirectory: FindNextFileW failed");
                        return false;
                    }
                }

                return true;
            }

            // ============================================================================
            // Alternate Data Streams
            // ============================================================================

            /**
             * @brief List alternate data streams on a file.
             * 
             * NTFS files can have multiple named data streams in addition to the
             * default unnamed data stream. This function enumerates them.
             *
             * @param path File path
             * @param out Output vector of stream info
             * @param err Optional error output
             * @return true on success
             */
            bool ListAlternateStreams(std::wstring_view path,
                std::vector<AlternateStreamInfo>& out,
                Error* err) {
                out.clear();

                if (!ValidatePath(path)) {
                    if (err) {
                        err->win32 = ERROR_INVALID_PARAMETER;
                        err->message = "Invalid path";
                    }
                    return false;
                }

                const std::wstring longp = AddLongPathPrefix(path);
                if (longp.empty()) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                WIN32_FIND_STREAM_DATA findStreamData{};
                HANDLE hFind = FindFirstStreamW(longp.c_str(), FindStreamInfoStandard, &findStreamData, 0);

                if (hFind == INVALID_HANDLE_VALUE) {
                    const DWORD le = GetLastError();
                    if (err) err->win32 = le;
                    // Don't log for expected errors
                    if (le != ERROR_FILE_NOT_FOUND && le != ERROR_PATH_NOT_FOUND && le != ERROR_HANDLE_EOF) {
                        SS_LOG_LAST_ERROR(L"FileUtils", L"ListAlternateStreams: FindFirstStreamW failed: %s", longp.c_str());
                    }
                    return false;
                }

                // RAII for find handle
                struct FindGuard {
                    HANDLE h;
                    ~FindGuard() { if (h != INVALID_HANDLE_VALUE) FindClose(h); }
                } guard{ hFind };

                // Process streams
                do {
                    std::wstring streamName = findStreamData.cStreamName;

                    // Filter out main stream (unnamed or "::$DATA")
                    bool isMainStream = false;
                    if (streamName.empty() || streamName == L"::$DATA") {
                        isMainStream = true;
                    }
                    else {
                        // Main stream variants
                        const size_t colonCount = std::count(streamName.begin(), streamName.end(), L':');
                        if (colonCount <= 1) {
                            isMainStream = true;
                        }
                    }

                    if (!isMainStream) {
                        // Clean stream name: remove leading ':' and trailing ':$DATA'
                        if (!streamName.empty() && streamName[0] == L':') {
                            streamName = streamName.substr(1);
                        }

                        const size_t dataPos = streamName.find(L":$DATA");
                        if (dataPos != std::wstring::npos) {
                            streamName = streamName.substr(0, dataPos);
                        }

                        // Security: reject embedded nulls (could indicate attack)
                        if (streamName.find(L'\0') != std::wstring::npos) {
                            if (err && err->win32 == 0) {
                                err->win32 = ERROR_INVALID_DATA;
                                err->message = "Stream name contains embedded NUL";
                            }
                            return false;
                        }

                        // Add to output
                        try {
                            AlternateStreamInfo info{};
                            info.name = L":" + streamName;  // Keep ':' prefix for consistency
                            info.size = static_cast<uint64_t>(findStreamData.StreamSize.QuadPart);
                            out.emplace_back(std::move(info));
                        }
                        catch (const std::bad_alloc&) {
                            if (err) err->win32 = ERROR_NOT_ENOUGH_MEMORY;
                            return false;
                        }
                    }
                } while (FindNextStreamW(hFind, &findStreamData));

                const DWORD lastErr = GetLastError();

                // ERROR_HANDLE_EOF is normal end condition
                if (lastErr != ERROR_HANDLE_EOF && lastErr != ERROR_SUCCESS) {
                    if (err) err->win32 = lastErr;
                    return false;
                }

                return true;
            }

            // ============================================================================
            // Cryptographic File Operations
            // ============================================================================

            /**
             * @brief Compute SHA-256 hash of file contents.
             * 
             * Uses Windows BCrypt API for hashing. Reads file in chunks
             * to handle large files efficiently.
             *
             * @param path File path
             * @param outHash Output 32-byte hash
             * @param err Optional error output
             * @return true on success
             */
            bool ComputeFileSHA256(std::wstring_view path, std::array<uint8_t, 32>& outHash, Error* err) {
                // Clear output
                outHash.fill(0);

                if (!ValidatePath(path)) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                const std::wstring longp = AddLongPathPrefix(path);
                if (longp.empty()) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                // Open file for reading
                HANDLE h = CreateFileW(
                    longp.c_str(),
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_SEQUENTIAL_SCAN,
                    nullptr
                );

                if (h == INVALID_HANDLE_VALUE) {
                    const DWORD lastError = GetLastError();
                    if (err) err->win32 = lastError;
                    // Don't log for non-existent files
                    if (lastError != ERROR_FILE_NOT_FOUND && lastError != ERROR_PATH_NOT_FOUND) {
                        SS_LOG_LAST_ERROR(L"FileUtils", L"ComputeFileSHA256: CreateFileW failed: %s", longp.c_str());
                    }
                    return false;
                }

                // RAII for all resources
                BCRYPT_ALG_HANDLE alg = nullptr;
                BCRYPT_HASH_HANDLE hash = nullptr;

                // Cleanup guard for all resources
                struct ResourceGuard {
                    HANDLE& fileHandle;
                    BCRYPT_ALG_HANDLE& algHandle;
                    BCRYPT_HASH_HANDLE& hashHandle;
                    ~ResourceGuard() {
                        if (hashHandle) BCryptDestroyHash(hashHandle);
                        if (algHandle) BCryptCloseAlgorithmProvider(algHandle, 0);
                        if (fileHandle != INVALID_HANDLE_VALUE) CloseHandle(fileHandle);
                    }
                } guard{ h, alg, hash };

                // Open algorithm provider
                NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
                if (!NT_SUCCESS(st)) {
                    if (err) err->win32 = RtlNtStatusToDosError(st);
                    return false;
                }

                // Get hash object size
                DWORD objLen = 0;
                DWORD cbRes = 0;
                st = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                    reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen), &cbRes, 0);
                if (!NT_SUCCESS(st)) {
                    if (err) err->win32 = RtlNtStatusToDosError(st);
                    return false;
                }

                // Allocate hash object buffer
                std::vector<uint8_t> hashObj;
                try {
                    hashObj.resize(objLen);
                }
                catch (const std::bad_alloc&) {
                    if (err) err->win32 = ERROR_NOT_ENOUGH_MEMORY;
                    return false;
                }

                // Create hash object
                st = BCryptCreateHash(alg, &hash, hashObj.data(), objLen, nullptr, 0, 0);
                if (!NT_SUCCESS(st)) {
                    if (err) err->win32 = RtlNtStatusToDosError(st);
                    return false;
                }

                // Read and hash file in 1MB chunks
                constexpr size_t CHUNK_SIZE = 1 << 20;  // 1MB
                std::vector<uint8_t> buf;
                try {
                    buf.resize(CHUNK_SIZE);
                }
                catch (const std::bad_alloc&) {
                    if (err) err->win32 = ERROR_NOT_ENOUGH_MEMORY;
                    return false;
                }

                DWORD bytesRead = 0;
                while (ReadFile(h, buf.data(), static_cast<DWORD>(buf.size()), &bytesRead, nullptr) && bytesRead > 0) {
                    st = BCryptHashData(hash, buf.data(), bytesRead, 0);
                    if (!NT_SUCCESS(st)) {
                        if (err) err->win32 = RtlNtStatusToDosError(st);
                        return false;
                    }
                }

                // Check for read errors
                const DWORD readErr = GetLastError();
                if (readErr != ERROR_SUCCESS && bytesRead == 0) {
                    // Only error if we didn't reach EOF normally
                    if (err) err->win32 = readErr;
                    return false;
                }

                // Finalize hash
                st = BCryptFinishHash(hash, outHash.data(), static_cast<ULONG>(outHash.size()), 0);
                if (!NT_SUCCESS(st)) {
                    if (err) err->win32 = RtlNtStatusToDosError(st);
                    return false;
                }

                return true;
            }


            // ============================================================================
            // Secure File Deletion
            // ============================================================================

            /**
             * @brief Securely erase a file by overwriting contents before deletion.
             * 
             * Overwrites file contents with patterns to make recovery more difficult:
             * - SinglePassZero: One pass of zeros
             * - TriplePass: Zeros, then 0xFF, then random data
             *
             * @warning This does NOT guarantee secure erasure on:
             * - SSDs (wear leveling, TRIM)
             * - Journaling filesystems (journal may contain old data)
             * - Copy-on-write filesystems
             * - RAID arrays with parity
             *
             * @param path File path (not directories)
             * @param mode Erase mode (pass count)
             * @param err Optional error output
             * @return true on success
             */
            bool SecureEraseFile(std::wstring_view path, SecureEraseMode mode, Error* err) {
                if (!ValidatePath(path)) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                // Pre-check: reject directories (TOCTOU safe check follows)
                Error dirErr{};
                if (IsDirectory(path, &dirErr)) {
                    if (err) {
                        err->win32 = ERROR_ACCESS_DENIED;
                        err->message = "Cannot secure-erase directories";
                    }
                    return false;
                }

                const std::wstring longp = AddLongPathPrefix(path);
                if (longp.empty()) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                // Open with exclusive access and delete-on-close
                // This prevents race conditions where file could be swapped
                HANDLE h = CreateFileW(
                    longp.c_str(),
                    GENERIC_READ | GENERIC_WRITE | DELETE,
                    0,  // Exclusive access - no sharing
                    nullptr,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE,
                    nullptr
                );

                if (h == INVALID_HANDLE_VALUE) {
                    const DWORD lastError = GetLastError();
                    if (err) err->win32 = lastError;
                    // Don't log for non-existent files
                    if (lastError != ERROR_FILE_NOT_FOUND && lastError != ERROR_PATH_NOT_FOUND) {
                        SS_LOG_LAST_ERROR(L"FileUtils", L"SecureEraseFile: CreateFileW failed: %s", longp.c_str());
                    }
                    return false;
                }

                // RAII guard for handle
                struct HandleGuard {
                    HANDLE h;
                    ~HandleGuard() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
                } guard{ h };

                // Verify it's actually a file (not directory) using handle
                // This is TOCTOU-safe since we have exclusive access
                BY_HANDLE_FILE_INFORMATION fileInfo{};
                if (!GetFileInformationByHandle(h, &fileInfo)) {
                    if (err) err->win32 = GetLastError();
                    return false;
                }

                if (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    if (err) {
                        err->win32 = ERROR_ACCESS_DENIED;
                        err->message = "Target is a directory";
                    }
                    return false;
                }

                // Get file size
                LARGE_INTEGER sz{};
                if (!GetFileSizeEx(h, &sz)) {
                    if (err) err->win32 = GetLastError();
                    return false;
                }

                const int passCount = (mode == SecureEraseMode::TriplePass) ? 3 : 1;

                // Allocate overwrite buffer (1MB)
                constexpr size_t BUFFER_SIZE = 1 << 20;
                std::vector<uint8_t> buf;
                try {
                    buf.resize(BUFFER_SIZE);
                }
                catch (const std::bad_alloc&) {
                    if (err) err->win32 = ERROR_NOT_ENOUGH_MEMORY;
                    return false;
                }

                for (int pass = 0; pass < passCount; ++pass) {
                    // Generate pattern for this pass
                    if (pass == 0) {
                        // Pass 0: zeros
                        std::fill(buf.begin(), buf.end(), static_cast<uint8_t>(0x00));
                    }
                    else if (pass == 1) {
                        // Pass 1: all ones
                        std::fill(buf.begin(), buf.end(), static_cast<uint8_t>(0xFF));
                    }
                    else {
                        // Pass 2+: cryptographically secure random data
                        NTSTATUS st = BCryptGenRandom(
                            nullptr,
                            buf.data(),
                            static_cast<ULONG>(buf.size()),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG
                        );

                        if (!NT_SUCCESS(st)) {
                            // BCrypt failed - this is a security issue, abort
                            if (err) {
                                err->win32 = RtlNtStatusToDosError(st);
                                err->message = "Failed to generate secure random data";
                            }
                            SS_LOG_ERROR(L"FileUtils", L"SecureEraseFile: BCryptGenRandom failed");
                            return false;
                        }
                    }

                    // Seek to beginning
                    LARGE_INTEGER pos{};
                    pos.QuadPart = 0;
                    if (!SetFilePointerEx(h, pos, nullptr, FILE_BEGIN)) {
                        if (err) err->win32 = GetLastError();
                        return false;
                    }

                    // Overwrite entire file
                    uint64_t remaining = static_cast<uint64_t>(sz.QuadPart);
                    while (remaining > 0) {
                        const DWORD chunk = static_cast<DWORD>(
                            std::min<uint64_t>(buf.size(), remaining)
                        );
                        DWORD written = 0;

                        if (!WriteFile(h, buf.data(), chunk, &written, nullptr)) {
                            if (err) err->win32 = GetLastError();
                            return false;
                        }

                        if (written == 0) {
                            // No progress - treat as error
                            if (err) {
                                err->win32 = ERROR_WRITE_FAULT;
                                err->message = "WriteFile returned zero bytes during erase";
                            }
                            return false;
                        }

                        remaining -= written;
                    }

                    // Flush to disk after each pass
                    if (!FlushFileBuffers(h)) {
                        // Log but continue - flush failure isn't critical
                        SS_LOG_WARN(L"FileUtils", L"SecureEraseFile: FlushFileBuffers failed");
                    }
                }

                // Clear the buffer before it's destroyed (defense in depth)
                SecureZeroMemory(buf.data(), buf.size());

                // Set delete disposition (more reliable than FILE_FLAG_DELETE_ON_CLOSE alone)
                FILE_DISPOSITION_INFO_EX dispEx{};
                dispEx.Flags = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS;
                BOOL deleteOk = SetFileInformationByHandle(h, FileDispositionInfoEx, &dispEx, sizeof(dispEx));

                if (!deleteOk) {
                    // Fallback for older Windows versions (pre-RS1)
                    FILE_DISPOSITION_INFO disp{};
                    disp.DeleteFile = TRUE;
                    deleteOk = SetFileInformationByHandle(h, FileDispositionInfo, &disp, sizeof(disp));
                }

                if (!deleteOk) {
                    if (err) err->win32 = GetLastError();
                    SS_LOG_LAST_ERROR(L"FileUtils", L"SecureEraseFile: SetFileInformationByHandle failed");
                    return false;
                }

                return true;
            }

            // ============================================================================
            // File Handle Operations
            // ============================================================================

            HANDLE OpenFileExclusive(std::wstring_view path, Error* err) {
                if (!ValidatePath(path)) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return INVALID_HANDLE_VALUE;
                }

                const std::wstring longp = AddLongPathPrefix(path);
                if (longp.empty()) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return INVALID_HANDLE_VALUE;
                }

                HANDLE h = CreateFileW(
                    longp.c_str(),
                    GENERIC_READ,
                    0,  // Exclusive - no sharing
                    nullptr,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr
                );

                if (h == INVALID_HANDLE_VALUE) {
                    const DWORD lastError = GetLastError();
                    if (err) err->win32 = lastError;
                    // Don't log for non-existent files
                    if (lastError != ERROR_FILE_NOT_FOUND && lastError != ERROR_PATH_NOT_FOUND) {
                        SS_LOG_LAST_ERROR(L"FileUtils", L"OpenFileExclusive: CreateFileW failed: %s", longp.c_str());
                    }
                }
                return h;
            }

            // ============================================================================
            // File Time Operations
            // ============================================================================

            bool GetTimes(std::wstring_view path, FILETIME& creation, FILETIME& lastAccess, FILETIME& lastWrite, Error* err) {
                // Zero output
                creation = {};
                lastAccess = {};
                lastWrite = {};

                if (!ValidatePath(path)) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                const std::wstring longp = AddLongPathPrefix(path);
                if (longp.empty()) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                HANDLE h = CreateFileW(
                    longp.c_str(),
                    FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr
                );

                if (h == INVALID_HANDLE_VALUE) {
                    if (err) err->win32 = GetLastError();
                    return false;
                }

                // RAII for handle
                struct HandleGuard {
                    HANDLE h;
                    ~HandleGuard() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
                } guard{ h };

                if (!GetFileTime(h, &creation, &lastAccess, &lastWrite)) {
                    if (err) err->win32 = GetLastError();
                    return false;
                }

                return true;
            }

            // ============================================================================
            // Recursive Directory Removal
            // ============================================================================

            /**
             * @brief Internal implementation for recursive directory removal.
             * 
             * Uses two-pass approach:
             * 1. Remove all files
             * 2. Remove directories deepest-first
             *
             * @param dir Directory to remove
             * @param err Optional error output
             * @return true on success
             */
            [[nodiscard]] static bool RemoveDirectoryRecursiveImpl(const std::wstring& dir, Error* err) {
                // First pass: remove all files
                WalkOptions opts{};
                opts.recursive = true;
                opts.includeDirs = true;
                opts.followReparsePoints = false;

                bool walkOk = WalkDirectory(dir, opts,
                    [](const std::wstring& path, const WIN32_FIND_DATAW& fd) -> bool {
                        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                            // Skip directories in first pass
                            return true;
                        }
                        else {
                            // Remove file
                            Error fileErr{};
                            if (!RemoveFile(path, &fileErr)) {
                                SS_LOG_WARN(L"FileUtils", L"RemoveDirectoryRecursive: Failed to remove file: %s", path.c_str());
                            }
                            return true;  // Continue even on failure
                        }
                    }, err);

                if (!walkOk) {
                    return false;
                }

                // Second pass: collect directories for removal
                std::vector<std::wstring> dirs;
                try {
                    dirs.reserve(64);  // Pre-allocate for typical case
                }
                catch (const std::bad_alloc&) {
                    if (err) err->win32 = ERROR_NOT_ENOUGH_MEMORY;
                    return false;
                }

                WalkDirectory(dir, opts,
                    [&dirs](const std::wstring& path, const WIN32_FIND_DATAW& fd) -> bool {
                        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                            try {
                                dirs.emplace_back(path);
                            }
                            catch (const std::bad_alloc&) {
                                return false;  // Stop on allocation failure
                            }
                        }
                        return true;
                    }, nullptr);

                // Sort by path length descending (deepest first)
                std::sort(dirs.begin(), dirs.end(),
                    [](const std::wstring& a, const std::wstring& b) {
                        return a.size() > b.size();
                    });

                // Remove directories deepest-first
                for (const auto& d : dirs) {
                    const std::wstring longp = AddLongPathPrefix(d);
                    if (!longp.empty() && !RemoveDirectoryW(longp.c_str())) {
                        const DWORD ec = GetLastError();
                        if (ec != ERROR_DIR_NOT_EMPTY && ec != ERROR_PATH_NOT_FOUND) {
                            SS_LOG_WARN(L"FileUtils", L"RemoveDirectoryRecursive: Failed to remove directory: %s (error %lu)", d.c_str(), ec);
                        }
                    }
                }

                // Remove the root directory
                const std::wstring longp = AddLongPathPrefix(dir);
                if (!longp.empty() && !RemoveDirectoryW(longp.c_str())) {
                    const DWORD ec = GetLastError();
                    if (ec != ERROR_DIR_NOT_EMPTY && ec != ERROR_PATH_NOT_FOUND && ec != ERROR_FILE_NOT_FOUND) {
                        if (err) err->win32 = ec;
                        return false;
                    }
                }

                return true;
            }

            /**
             * @brief Recursively remove a directory and all its contents.
             * 
             * @warning This cannot be undone. Use with extreme caution.
             *
             * @param dir Directory path
             * @param err Optional error output
             * @return true on success
             */
            bool RemoveDirectoryRecursive(std::wstring_view dir, Error* err) {
                if (!ValidatePath(dir)) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return false;
                }

                // Check if it's actually a directory
                Error dirErr{};
                if (!IsDirectory(dir, &dirErr)) {
                    // Not a directory - could be file or non-existent
                    // Non-existent is success, file is error
                    if (Exists(dir, nullptr)) {
                        if (err) {
                            err->win32 = ERROR_DIRECTORY;
                            err->message = "Path is not a directory";
                        }
                        return false;
                    }
                    return true;  // Non-existent directory = success
                }

                return RemoveDirectoryRecursiveImpl(ToW(dir), err);
            }

		}  // namespace FileUtils

	}  // namespace Utils
}  // namespace ShadowStrike
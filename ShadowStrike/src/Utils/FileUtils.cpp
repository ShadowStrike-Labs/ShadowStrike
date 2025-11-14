#include "FileUtils.hpp"
#include <algorithm>
#include <memory>
#include <unordered_set>
#include <cstdio>
#include <Aclapi.h>
#include <winioctl.h>
#include <bcrypt.h>
#include<winternl.h>

#pragma comment(lib, "bcrypt.lib")

namespace ShadowStrike {
	namespace Utils{

		namespace FileUtils {

       

			//Helpers to convert string types
			static inline std::wstring ToW(std::wstring_view s) {
				return std::wstring(s.data(), s.size());
			}

			static inline bool IsCancel(const WalkOptions& opts) {
				return (opts.cancelFlag && opts.cancelFlag->load(std::memory_order_relaxed));
			}


            std::wstring AddLongPathPrefix(std::wstring_view path) {
                if (path.empty()) return std::wstring();
                const std::wstring_view p = path;
                if (p.rfind(LONG_PATH_PREFIX, 0) == 0) return ToW(p);
                if (p.rfind(L"\\\\", 0) == 0) {
                    // UNC path -> \\?\UNC\ + (\\ after)
                    std::wstring out;
                    out.reserve(LONG_PATH_PREFIX_UNC.size() + p.size());
                    out.append(LONG_PATH_PREFIX_UNC);
                    out.append(p.substr(2));
                    return out;
                }
                std::wstring out;
                out.reserve(LONG_PATH_PREFIX.size() + p.size());
                out.append(LONG_PATH_PREFIX);
                out.append(p);
                return out;
            }

            //Normalizes the file path. if resolveFinal = true, gets the real path for reparse/shortname solution with handle
            std::wstring NormalizePath(std::wstring_view path, bool resolveFinal, Error* err) {
                std::wstring input = ToW(path);
                if (input.empty()) {
                    if (err) err->win32 = ERROR_INVALID_PARAMETER;
                    return std::wstring();
                }

               
                const wchar_t invalidChars[] = L"<>|?*\""; // Windows forbidden filename chars
                if (input.find_first_of(invalidChars) != std::wstring::npos) {
                    if (err) err->win32 = ERROR_INVALID_NAME;
                    return std::wstring();
                }

                size_t colonPos = input.find(L':');
                if (colonPos != std::wstring::npos && colonPos != 1) {
                    // Colon found but not at position 1 (C:)
                    if (err) err->win32 = ERROR_INVALID_NAME;
                    return std::wstring();
                }

                // Full path
                DWORD need = GetFullPathNameW(input.c_str(), 0, nullptr, nullptr);
                if (need == 0) {
                    if (err) err->win32 = GetLastError();
                    return std::wstring();
                }
                std::wstring full;
                full.resize(need);
                DWORD got = GetFullPathNameW(input.c_str(), need, &full[0], nullptr);
                if (got == 0) {
                    if (err) err->win32 = GetLastError();
                    return std::wstring();
                }
                if (!full.empty() && full.back() == L'\0') full.pop_back();

				//Final real path if requested
                if (!resolveFinal) {
                    return full;
                }

                std::wstring longp = AddLongPathPrefix(full);
                HANDLE h = CreateFileW(longp.c_str(), FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS, nullptr);
                if (h == INVALID_HANDLE_VALUE) {
                    if (err) err->win32 = GetLastError();
                    return full; // full path as fallback
                }

                DWORD sz = GetFinalPathNameByHandleW(h, nullptr, 0, FILE_NAME_NORMALIZED);
                std::wstring finalPath;
                if (sz) {
                    finalPath.resize(sz);
                    DWORD sz2 = GetFinalPathNameByHandleW(h, &finalPath[0], sz, FILE_NAME_NORMALIZED);
                    if (sz2 && !finalPath.empty()) {
                        if (finalPath.back() == L'\0') finalPath.pop_back();
                        CloseHandle(h);
                  
                        return finalPath;
                    }
                }
                if (err) err->win32 = GetLastError();
                CloseHandle(h);
                return full;
            }


            bool Exists(std::wstring_view path,Error* err) {
                WIN32_FILE_ATTRIBUTE_DATA fad{};

				std::wstring longp = AddLongPathPrefix(path);
                if(!GetFileAttributesExW(longp.c_str(), GetFileExInfoStandard, &fad)) {
					if (err) err->win32 = GetLastError();
                    return false;
                }
				return true;
            }

            bool IsDirectory(std::wstring_view path,Error* err) {
                WIN32_FILE_ATTRIBUTE_DATA fad{};
                std::wstring longp = AddLongPathPrefix(path);
                if (!GetFileAttributesExW(longp.c_str(), GetFileExInfoStandard, &fad)) {
					if (err) err->win32 = GetLastError();
                    return false;
                }
                return (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            }


            bool Stat(std::wstring_view path, FileStat& out, Error* err) {
                WIN32_FILE_ATTRIBUTE_DATA fad{};
                std::wstring longp = AddLongPathPrefix(path);
                if (!GetFileAttributesExW(longp.c_str(), GetFileExInfoStandard, &fad)) {
                    if (err) err->win32 = GetLastError();
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

                // size(0 for directories)
                if (!out.isDirectory) {
                    LARGE_INTEGER li{};
                    li.HighPart = fad.nFileSizeHigh;
                    li.LowPart = fad.nFileSizeLow;
                    out.size = static_cast<uint64_t>(li.QuadPart);
                }
                else {
                    out.size = 0;
                }
                return true;
            }

            std::optional<uint64_t> FileSize(std::wstring_view path, Error* err) {
                FileStat st{};
                if (!Stat(path, st, err) || !st.exists || st.isDirectory) return std::nullopt;
                return st.size;
            }

            static bool ReadAllBytesImpl(HANDLE h, std::vector<std::byte>& out, uint64_t fileSize, Error* err) {
                out.clear();

                constexpr uint64_t MAX_FILE_SIZE = 64ULL * 1024 * 1024 * 1024; // 256 GB
                if (fileSize > SIZE_MAX || fileSize > MAX_FILE_SIZE ) { if (err) err->win32 = ERROR_FILE_TOO_LARGE; return false; }
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
                DWORD chunk = 0;
                size_t off = 0;
                while (toRead > 0) {
                    DWORD thisRead = 0;
                    DWORD ask = (toRead > 4 * 1024 * 1024) ? (4 * 1024 * 1024) : static_cast<DWORD>(toRead);
                    if (!ReadFile(h, ptr + off, ask, &thisRead, nullptr)) {
                        if (err) err->win32 = GetLastError();
                        return false;
                    }
                    if (thisRead == 0) break;
                    off += thisRead;
                    toRead -= thisRead;
                }
                out.resize(off);
                return true;
            }

            bool ReadAllBytes(std::wstring_view path, std::vector<std::byte>& out, Error* err) {
                out.clear();
                std::wstring longp = AddLongPathPrefix(path);
                HANDLE h = CreateFileW(longp.c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
                if (h == INVALID_HANDLE_VALUE) {
                    DWORD lastError = GetLastError();
                    if (err) err->win32 = lastError;
                    // Don't log for non-existent files in tests
                    if (lastError != ERROR_FILE_NOT_FOUND && lastError != ERROR_PATH_NOT_FOUND) {
                        SS_LOG_LAST_ERROR(L"FileUtils", L"ReadAllBytes: CreateFileW failed: %s", longp.c_str());
                    }
                    return false;
                }

                LARGE_INTEGER sz{};
                if (!GetFileSizeEx(h, &sz)) {
                    DWORD lastError = GetLastError();
                    if (err) err->win32 = lastError;
                    CloseHandle(h);
                    return false;
                }
                
                bool ok = ReadAllBytesImpl(h, out, static_cast<uint64_t>(sz.QuadPart), err);
                CloseHandle(h);
                return ok;
            }

            bool ReadAllTextUtf8(std::wstring_view path, std::string& out, Error* err) {
                std::vector<std::byte> bytes;
                if (!ReadAllBytes(path, bytes, err)) return false;
                out.assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
                return true;
            }

            static std::wstring MakeTempSibling(std::wstring_view dstPath) {
                std::wstring p(dstPath);
                auto pos = p.find_last_of(L"\\/");
                std::wstring dir = (pos == std::wstring::npos) ? L"" : p.substr(0, pos);
                std::wstring file = (pos == std::wstring::npos) ? p : p.substr(pos + 1);

				//Create unique file name using GUID
                GUID guid;
                CoCreateGuid(&guid);
                wchar_t guidStr[40];
                swprintf_s(guidStr, L"%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                    guid.Data1, guid.Data2, guid.Data3,
                    guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
                    guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);

                std::wstring tmp;
                tmp.reserve(p.size() + 64);
                if (!dir.empty()) { tmp.append(dir); tmp.push_back(L'\\'); }
                tmp.append(L".~");
                tmp.append(file);
                tmp.append(L"_");
                tmp.append(guidStr);
                tmp.append(L".tmp");
                return tmp;
            }


            bool WriteAllBytesAtomic(std::wstring_view path, const std::byte* data, size_t len, Error* err) {
                if (!data && len != 0) { if (err) err->win32 = ERROR_INVALID_PARAMETER; return false; }

                std::wstring dst = ToW(path);
                std::wstring tmp = MakeTempSibling(dst);

                // Create the directories
                if (!CreateDirectories(dst.substr(0, dst.find_last_of(L"\\/")), err)) {
					SS_LOG_LAST_ERROR(L"FileUtils", L"Creating directories failed. : %a", dst.c_str());
                    return false;
                }

                std::wstring longTmp = AddLongPathPrefix(tmp);
                HANDLE h = CreateFileW(longTmp.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                    nullptr, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
                if (h == INVALID_HANDLE_VALUE) {
                    if (err) err->win32 = GetLastError();
                    SS_LOG_LAST_ERROR(L"FileUtils", L"WriteAllBytesAtomic: CreateFileW failed: %s", longTmp.c_str());
                    return false;
                }

                const uint8_t* ptr = reinterpret_cast<const uint8_t*>(data);
                size_t toWrite = len;
                size_t off = 0;
                while (toWrite > 0) {
                    DWORD thisWrite = 0;
                    DWORD chunk = (toWrite > 4 * 1024 * 1024) ? (4 * 1024 * 1024) : static_cast<DWORD>(toWrite);
                    if (!WriteFile(h, ptr + off, chunk, &thisWrite, nullptr)) {
                        if (err) err->win32 = GetLastError();
                        CloseHandle(h);
                        RemoveFile(tmp);
                        return false;
                    }
                    off += thisWrite;
                    toWrite -= thisWrite;
                    if (thisWrite == 0) break;
                }
                FlushFileBuffers(h);
                CloseHandle(h);

                // Replace (atomic)
                bool repOk = ReplaceFileAtomic(tmp, dst, err);
                if (!repOk) {
                    RemoveFile(tmp);
                }
                return repOk;
            }


            bool WriteAllBytesAtomic(std::wstring_view path, const std::vector<std::byte>& data, Error* err) {
                return WriteAllBytesAtomic(path, data.data(), data.size(), err);
            }

            bool WriteAllTextUtf8Atomic(std::wstring_view path, std::string_view utf8, Error* err) {
                return WriteAllBytesAtomic(path, reinterpret_cast<const std::byte*>(utf8.data()), utf8.size(), err);
            }

            bool ReplaceFileAtomic(std::wstring_view srcPath, std::wstring_view dstPath, Error* err) {
                std::wstring longSrc = AddLongPathPrefix(srcPath);
                std::wstring longDst = AddLongPathPrefix(dstPath);
                if (!MoveFileExW(longSrc.c_str(), longDst.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                    if (err) err->win32 = GetLastError();
                    SS_LOG_LAST_ERROR(L"FileUtils", L"ReplaceFileAtomic: MoveFileExW failed: %s -> %s", longSrc.c_str(), longDst.c_str());
                    return false;
                }
                return true;
            }
            //Static
             bool CreateDirectories(std::wstring_view dir, Error* err) {
                if (dir.empty()) return true; 

                std::wstring d = ToW(dir);

                // Path traversal attack prevention
                if (d.find(L"..") != std::wstring::npos) {
					if (err) err->win32 = ERROR_INVALID_PARAMETER;
					SS_LOG_ERROR(L"FileUtils", L"CreateDirectories: Path contains .. : %s", d.c_str());
                    return false;
                }

                // More comprehensive invalid char check
                const wchar_t invalidChars[] = L"<>\"|?*";

                
                size_t colonPos = d.find(L':');
                while (colonPos != std::wstring::npos) {
                    
                    if (colonPos != 1) {
                        if (err) err->win32 = ERROR_INVALID_NAME;
                        SS_LOG_ERROR(L"FileUtils", L"CreateDirectories: Invalid colon position in path");
                        return false;
                    }
                   
                    colonPos = d.find(L':', colonPos + 1);
                }
                
                if (d.find_first_of(invalidChars) != std::wstring::npos) {
                    if (err) err->win32 = ERROR_INVALID_NAME;
                    return false;
                }

                std::wstring cur;
                // Reserve enough space for long path prefix
                cur.reserve(d.size() + LONG_PATH_PREFIX.size() + 8);

                for (size_t i = 0; i < d.size(); ++i) {
                    wchar_t c = d[i];
                    if (c == L'/') c = L'\\'; 
                    cur.push_back(c);

					// Skip first 3 characters (C:\)
                    if (c == L'\\' && cur.size() > 3) {
                        std::wstring longp = AddLongPathPrefix(cur);
                        if (!CreateDirectoryW(longp.c_str(), nullptr)) {
                            DWORD ec = GetLastError();
                            if (ec != ERROR_ALREADY_EXISTS) {
                                if (err) err->win32 = ec;
                                SS_LOG_LAST_ERROR(L"FileUtils", L"CreateDirectories failed for: %s", cur.c_str());
                                return false; 
                            }
                        }
                    }
                }

                // Create final directory
                std::wstring longp = AddLongPathPrefix(d);
                if (!CreateDirectoryW(longp.c_str(), nullptr)) {
                    DWORD ec = GetLastError();
                    if (ec != ERROR_ALREADY_EXISTS) {
                        if (err) err->win32 = ec;
                        SS_LOG_LAST_ERROR(L"FileUtils", L"CreateDirectories final failed: %s", d.c_str());
                        return false;
                    }
                }

				return true;
            }

            bool RemoveFile(std::wstring_view path, Error* err) {
                std::wstring longp = AddLongPathPrefix(path);
                if (!DeleteFileW(longp.c_str())) {
                    DWORD ec = GetLastError();
                    if (ec == ERROR_FILE_NOT_FOUND) return true;
                    if (err) err->win32 = ec;
                    SS_LOG_LAST_ERROR(L"FileUtils", L"RemoveFile: DeleteFileW failed: %s", longp.c_str());
                    return false;
                }
                return true;
            }

            //Getting file ID
            static bool GetFileIdFromHandle(HANDLE h, FileId& id) {
                BY_HANDLE_FILE_INFORMATION info{};
                if (!GetFileInformationByHandle(h, &info)) return false;
                id.volumeSerial = info.dwVolumeSerialNumber;
                id.fileIndex = (static_cast<uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
                return true;
            }

            static bool ShouldSkip(const WIN32_FIND_DATAW& fd, const WalkOptions& opts) {
                if (opts.skipHidden && (fd.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)) return true;
                if (opts.skipSystem && (fd.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)) return true;
                return false;
            }



            bool WalkDirectory(std::wstring_view root, const WalkOptions& opts, const WalkCallback& cb, Error* err) {
                constexpr size_t MAX_SYMLINK_DEPTH = 40; 
                if (root.empty()) { if (err) err->win32 = ERROR_INVALID_PARAMETER; return false; }

                std::wstring base = ToW(root);
                if (!IsDirectory(base,err)) { if (err) err->win32 = ERROR_DIRECTORY; return false; }

                
                std::unordered_set<FileId, FileIdHasher> visited;
                std::vector<std::pair<std::wstring, size_t>> stack; // path, depth
                stack.emplace_back(base, 0);

                while (!stack.empty()) {
					if (IsCancel(opts)) { if (err) err->win32 = ERROR_CANCELLED; return true; }//Cancellation is a success finish
                    auto [cur, depth] = stack.back();
                    stack.pop_back();

                    //Check depth BEFORE processing
                    if (depth > MAX_SYMLINK_DEPTH) {
                        if (err) err->win32 = ERROR_CANT_RESOLVE_FILENAME;
                        SS_LOG_ERROR(L"FileUtils", L"WalkDirectory: Maximum symlink depth exceeded: %s", cur.c_str());
                        return false;
                    }

                    // Check for symlink loops
                    {
                        std::wstring longp = AddLongPathPrefix(cur);
                        HANDLE dh = CreateFileW(longp.c_str(), FILE_READ_ATTRIBUTES,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS, nullptr);
                        if (dh != INVALID_HANDLE_VALUE) {
                            FileId fid{};
                            if (GetFileIdFromHandle(dh, fid)) {
                                if (!visited.insert(fid).second) {
                                    // Loop detected - skip this directory
                                    CloseHandle(dh);
                                    SS_LOG_WARN(L"FileUtils", L"Symlink loop detected at: %ls", cur.c_str());
                                    continue;
                                }
                            }
                            CloseHandle(dh);
                        }
                    }

                    std::wstring pattern = cur;
                    if (!pattern.empty() && pattern.back() != L'\\') pattern.push_back(L'\\');
                    pattern.append(L"*");

                    WIN32_FIND_DATAW fd{};
                    std::wstring longPattern = AddLongPathPrefix(pattern);
                    HANDLE hFind = FindFirstFileExW(longPattern.c_str(),
                        FindExInfoBasic,
                        &fd,
                        FindExSearchNameMatch,
                        nullptr,
                        FIND_FIRST_EX_LARGE_FETCH);
                    if (hFind == INVALID_HANDLE_VALUE) {
                        DWORD ec = GetLastError();
                        if (ec == ERROR_FILE_NOT_FOUND) continue;
                        if (err) err->win32 = ec;
                        SS_LOG_LAST_ERROR(L"FileUtils", L"WalkDirectory: FindFirstFileExW failed: %s", longPattern.c_str());
                        return false;
                    }

                    do {
						if (IsCancel(opts)) { FindClose(hFind); if (err) err->win32 = ERROR_CANCELLED; return true; }//Cancellation is a success finish
                        const std::wstring_view name = fd.cFileName;
                        if (name == L"." || name == L"..") continue;
                        if (ShouldSkip(fd, opts)) continue;

                        std::wstring child = cur;
                        if (!child.empty() && child.back() != L'\\') child.push_back(L'\\');
                        child.append(fd.cFileName);

                        const bool isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                        const bool isReparse = (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;

                        if (isDir) {
                            if (opts.includeDirs) {
                                if (!cb(child, fd)) { FindClose(hFind); return true; }
                            }
                            if (opts.recursive) {
                                if (isReparse && !opts.followReparsePoints) {
                                    continue;
                                }
                                if (depth + 1 <= opts.maxDepth) {
                                    stack.emplace_back(child, depth + 1);
                                }
                            }
                        }
                        else {
                            if (!cb(child, fd)) { FindClose(hFind); return true; }
                        }
                    } while (FindNextFileW(hFind, &fd));
                    FindClose(hFind);
                }

                return true;
            }

            bool ListAlternateStreams(std::wstring_view path,
                std::vector<AlternateStreamInfo>& out,
                Error* err) {
                out.clear();

                if (path.empty()) {
                    if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = "Path cannot be empty"; }
                    return false;
                }

                // Use FindFirstStreamW API (Windows Vista+) - reliable and simple
                std::wstring longp = AddLongPathPrefix(path);

                WIN32_FIND_STREAM_DATA findStreamData{};
                HANDLE hFind = FindFirstStreamW(longp.c_str(), FindStreamInfoStandard, &findStreamData, 0);

                if (hFind == INVALID_HANDLE_VALUE) {
                    DWORD le = GetLastError();
                    if (err) err->win32 = le;
                    if (le != ERROR_FILE_NOT_FOUND && le != ERROR_PATH_NOT_FOUND && le != ERROR_HANDLE_EOF) {
                        SS_LOG_LAST_ERROR(L"FileUtils", L"ListAlternateStreams: FindFirstStreamW failed: %s", longp.c_str());
                    }
                    return false;
                }

                // Process streams
                do {
                    std::wstring streamName = findStreamData.cStreamName;

                    // Filter out main stream (unnamed or "::$DATA")
                    bool isMainStream = false;
                    if (streamName.empty() || streamName == L"::$DATA") {
                        isMainStream = true;
                    }
                    else {
                        // Main stream variants: ":filename:$DATA" or ":filename::$DATA"
                        size_t colonCount = std::count(streamName.begin(), streamName.end(), L':');
                        if (colonCount <= 1) {
                            // Single colon or no alternate name = main stream
                            isMainStream = true;
                        }
                    }

                    if (!isMainStream) {
                        // Clean stream name: remove leading ':' and trailing ':$DATA'
                        if (!streamName.empty() && streamName[0] == L':') {
                            streamName = streamName.substr(1);
                        }

                        size_t dataPos = streamName.find(L":$DATA");
                        if (dataPos != std::wstring::npos) {
                            streamName = streamName.substr(0, dataPos);
                        }

                        // Security: reject embedded nulls
                        if (streamName.find(L'\0') != std::wstring::npos) {
                            if (err && err->win32 == 0) {
                                err->win32 = ERROR_INVALID_DATA;
                                err->message = "Stream name contains embedded NUL";
                            }
                            FindClose(hFind);
                            return false;
                        }

                        // Add to output
                        AlternateStreamInfo info{};
                        info.name = L":" + streamName; // Keep ':' prefix for consistency
                        info.size = static_cast<uint64_t>(findStreamData.StreamSize.QuadPart);
                        out.emplace_back(std::move(info));
                    }
                } while (FindNextStreamW(hFind, &findStreamData));

                DWORD lastErr = GetLastError();
                FindClose(hFind);

                // ERROR_HANDLE_EOF is normal end condition
                if (lastErr != ERROR_HANDLE_EOF && lastErr != ERROR_SUCCESS) {
                    if (err) err->win32 = lastErr;
                    return false;
                }

                return true;
            }


            bool ComputeFileSHA256(std::wstring_view path, std::array<uint8_t, 32>& outHash, Error* err) {

                outHash.fill(0);
                std::wstring longp = AddLongPathPrefix(path);
                HANDLE h = CreateFileW(longp.c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
                if (h == INVALID_HANDLE_VALUE) {
                    DWORD lastError = GetLastError();
                    if (err) err->win32 = lastError;
                    // Don't log for non-existent files
                    if (lastError != ERROR_FILE_NOT_FOUND && lastError != ERROR_PATH_NOT_FOUND) {
                        SS_LOG_LAST_ERROR(L"FileUtils", L"ComputeFileSHA256: CreateFileW failed: %s", longp.c_str());
                    }
                    return false;
                }

                BCRYPT_ALG_HANDLE alg = nullptr;
                BCRYPT_HASH_HANDLE hash = nullptr;
                NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
                if (st < 0) { 
                    CloseHandle(h); 
                    if (err) err->win32 = RtlNtStatusToDosError(st); 
                    return false; 
                }

                DWORD objLen = 0, cbRes = 0;
                st = BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen), &cbRes, 0);
                if (st < 0) { 
                    BCryptCloseAlgorithmProvider(alg, 0); 
                    CloseHandle(h); 
                    if (err) err->win32 = RtlNtStatusToDosError(st); 
                    return false; 
                }

                std::vector<uint8_t> obj(objLen);
                st = BCryptCreateHash(alg, &hash, obj.data(), objLen, nullptr, 0, 0);
                if (st < 0) { 
                    BCryptCloseAlgorithmProvider(alg, 0); 
                    CloseHandle(h); 
                    if (err) err->win32 = RtlNtStatusToDosError(st); 
                    return false; 
                }

                std::vector<uint8_t> buf(1 << 20); // 1MB
                DWORD rd = 0;
                while (ReadFile(h, buf.data(), static_cast<DWORD>(buf.size()), &rd, nullptr) && rd > 0) {
                    st = BCryptHashData(hash, buf.data(), rd, 0);
                    if (st < 0) { 
                        BCryptDestroyHash(hash); 
                        BCryptCloseAlgorithmProvider(alg, 0); 
                        CloseHandle(h); 
                        if (err) err->win32 = RtlNtStatusToDosError(st); 
                        return false; 
                    }
                }
                CloseHandle(h);

                st = BCryptFinishHash(hash, outHash.data(), static_cast<ULONG>(outHash.size()), 0);
                BCryptDestroyHash(hash);
                BCryptCloseAlgorithmProvider(alg, 0);
                if (st < 0) { 
                    if (err) err->win32 = RtlNtStatusToDosError(st); 
                    return false; 
                }
                return true;
            }


            bool SecureEraseFile(std::wstring_view path, SecureEraseMode mode, Error* err) {
                // Only files, not directories
                if (IsDirectory(path,err)) { 
                    if (err) err->win32 = ERROR_ACCESS_DENIED; 
                    return false; 
                }

                std::wstring longp = AddLongPathPrefix(path);
                
                // Single handle for both erase and delete - prevents race condition
                HANDLE h = CreateFileW(longp.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE,
					0, // Exclusive access
					nullptr, OPEN_EXISTING, 
					FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, // Delete on close
					nullptr);
                if (h == INVALID_HANDLE_VALUE) {
                    DWORD lastError = GetLastError();
                    if (err) err->win32 = lastError;
                    // Don't log for non-existent files
                    if (lastError != ERROR_FILE_NOT_FOUND && lastError != ERROR_PATH_NOT_FOUND) {
                        SS_LOG_LAST_ERROR(L"FileUtils", L"SecureEraseFile: CreateFileW failed: %s", longp.c_str());
                    }
                    return false;
                }

				// Verify it's not a directory using the handle
                BY_HANDLE_FILE_INFORMATION fileInfo;
                if (!GetFileInformationByHandle(h, &fileInfo)) {
                    DWORD ec = GetLastError();
                    CloseHandle(h);
                    if (err) err->win32 = ec;
                    return false;
                }
                if (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
					CloseHandle(h); 
					if (err) err->win32 = ERROR_ACCESS_DENIED;
                    return false;
                }
                
                LARGE_INTEGER sz{};
                if (!GetFileSizeEx(h, &sz)) {
                    if (err) err->win32 = GetLastError();
                    CloseHandle(h);
                    return false;
                }

                const int passCount = (mode == SecureEraseMode::TriplePass) ? 3 : 1;
                std::vector<uint8_t> buf(1 << 20); // 1MB buffer
                
                for (int pass = 0; pass < passCount; ++pass) {
                    // Create data pattern
                    if (pass == 0) {
                        std::fill(buf.begin(), buf.end(), 0x00);
                    }
                    else if (pass == 1) {
                        std::fill(buf.begin(), buf.end(), 0xFF);
                    }
                    else {
                        // Use cryptographically secure random for third pass
                        NTSTATUS st = BCryptGenRandom(nullptr, buf.data(), static_cast<ULONG>(buf.size()), 
                                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
                        if (st < 0) {
                            // Fallback to rand() if BCrypt fails
                            for (auto& b : buf) b = static_cast<uint8_t>(rand() & 0xFF);
                        }
                    }

                    LARGE_INTEGER pos{}; pos.QuadPart = 0;
                    if (!SetFilePointerEx(h, pos, nullptr, FILE_BEGIN)) { 
                        if (err) err->win32 = GetLastError(); 
                        CloseHandle(h); 
                        return false; 
                    }

                    uint64_t left = static_cast<uint64_t>(sz.QuadPart);
                    while (left > 0) {
                        DWORD chunk = static_cast<DWORD>(std::min<uint64_t>(buf.size(), left));
                        DWORD written = 0;
                        if (!WriteFile(h, buf.data(), chunk, &written, nullptr)) {
                            if (err) err->win32 = GetLastError();
                            CloseHandle(h);
                            return false;
                        }
                        left -= written;
                        if (written == 0) break;
                    }
                    FlushFileBuffers(h);
                }

                // Set delete disposition before closing (more reliable than FILE_FLAG_DELETE_ON_CLOSE alone)
                FILE_DISPOSITION_INFO_EX dx{};
                dx.Flags = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS;
                BOOL ok = SetFileInformationByHandle(h, FileDispositionInfoEx, &dx, sizeof(dx));
                if (!ok) {
                    // Fallback for older Windows versions
                    FILE_DISPOSITION_INFO d{};
                    d.DeleteFile = TRUE;
                    ok = SetFileInformationByHandle(h, FileDispositionInfo, &d, sizeof(d));
                }
                
                DWORD ec = ok ? ERROR_SUCCESS : GetLastError();
                CloseHandle(h); // This will delete the file due to FILE_FLAG_DELETE_ON_CLOSE
                
                if (!ok) { 
                    if (err) err->win32 = ec; 
                    return false; 
                }
                
                return true;
            }

            HANDLE OpenFileExclusive(std::wstring_view path, Error* err) {
                std::wstring longp = AddLongPathPrefix(path);
                HANDLE h = CreateFileW(longp.c_str(), GENERIC_READ,
                    0, // exclusive
                    nullptr, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, nullptr);
                if (h == INVALID_HANDLE_VALUE) {
                    DWORD lastError = GetLastError();
                    if (err) err->win32 = lastError;
                    // Don't log for non-existent files
                    if (lastError != ERROR_FILE_NOT_FOUND && lastError != ERROR_PATH_NOT_FOUND) {
                        SS_LOG_LAST_ERROR(L"FileUtils", L"OpenFileExclusive: CreateFileW failed: %s", longp.c_str());
                    }
                }
                return h;
            }

            bool GetTimes(std::wstring_view path, FILETIME& creation, FILETIME& lastAccess, FILETIME& lastWrite, Error* err) {
                std::wstring longp = AddLongPathPrefix(path);
                HANDLE h = CreateFileW(longp.c_str(), FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (h == INVALID_HANDLE_VALUE) {
                    if (err) err->win32 = GetLastError();
                    return false;
                }
                BOOL ok = GetFileTime(h, &creation, &lastAccess, &lastWrite);
                DWORD ec = ok ? ERROR_SUCCESS : GetLastError();
                CloseHandle(h);
                if (!ok) { if (err) err->win32 = ec; return false; }
                return true;
            }
            

            static bool RemoveDirectoryRecursiveImpl(const std::wstring& dir, Error* err) {
                WalkOptions opts{};
                opts.recursive = true;
                opts.includeDirs = true;
                opts.followReparsePoints = false;

                bool ok = WalkDirectory(dir, opts, [&](const std::wstring& path, const WIN32_FIND_DATAW& fd) -> bool {
                    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                        
                        return true;
                    }
                    else {
                        Error e{};
                        RemoveFile(path, &e);
                        return true;
                    }
                    }, err);
                if (!ok) return false;

            
                std::vector<std::wstring> dirs;
                WalkDirectory(dir, opts, [&](const std::wstring& path, const WIN32_FIND_DATAW& fd)->bool {
                    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                        dirs.emplace_back(path);
                    }
                    return true;
                    }, nullptr);
                std::sort(dirs.begin(), dirs.end(), [](const std::wstring& a, const std::wstring& b) {
                    return a.size() > b.size();
                    });
                for (auto& d : dirs) {
                    std::wstring longp = AddLongPathPrefix(d);
                    RemoveDirectoryW(longp.c_str());
                }
                std::wstring longp = AddLongPathPrefix(dir);
                if (!RemoveDirectoryW(longp.c_str())) {
                    DWORD ec = GetLastError();
                    if (ec != ERROR_DIR_NOT_EMPTY) {
                        if (err) err->win32 = ec;
                        return false;
                    }
                }
                return true;
            }

            bool RemoveDirectoryRecursive(std::wstring_view dir, Error* err) {
                if (!IsDirectory(dir,err)) return true;
                return RemoveDirectoryRecursiveImpl(ToW(dir), err);
            }





		}//namespace FileUtils

	}//namespace Utils
}//namespace ShadowStrike
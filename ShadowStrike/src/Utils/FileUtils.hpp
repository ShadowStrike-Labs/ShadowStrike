#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <cstdint>
#include <optional>
#include <functional>
#include <atomic>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#endif

#include "Logger.hpp"

namespace ShadowStrike {

	namespace Utils {

		namespace FileUtils {

			inline constexpr std::wstring_view LONG_PATH_PREFIX = L"\\\\?\\";
			inline constexpr std::wstring_view LONG_PATH_PREFIX_UNC = L"\\\\?\\UNC\\";

			//basic error structure
			struct Error {
				DWORD win32 = 0;
				std::string message;
			};

			//File statistics
			struct FileStat {
				bool exists = false;
				bool isDirectory = false;
				bool isReparsePoint = false;
				bool isHidden = false;
				bool isSystem = false;
				uint64_t size = 0;
				FILETIME creation{};
				FILETIME lastAccess{};
				FILETIME lastWrite{};
				DWORD attributes = 0;
			};


			//ADS(Alternate Data Stream) info
			struct AlternateStreamInfo {
				std::wstring name; // ":stream:$DATA" full name
				uint64_t size = 0;
			};
			
			// Directory navigation options

			struct WalkOptions {
				bool recursive = true;
				bool followReparsePoints = false; // Junction/symlink follow
				bool includeDirs = false;        
				bool skipHidden = false;
				bool skipSystem = false;
				size_t maxDepth = SIZE_MAX;
				const std::atomic<bool>* cancelFlag = nullptr; 
			};

			// To uniquely identify the file ID (loop detection)
			struct FileId {
				DWORD volumeSerial = 0;
				uint64_t fileIndex = 0; // high<<32 | low
				bool operator==(const FileId& o) const noexcept {
					return volumeSerial == o.volumeSerial && fileIndex == o.fileIndex;
				}
			};

			//Hash function(for unordered_set)
			struct FileIdHasher {
				size_t operator()(const FileId& id) const noexcept {
					return std::hash<uint64_t>{}((static_cast<uint64_t>(id.volumeSerial) << 32) ^ id.fileIndex);
				}
			};

			//Path helpers
			std::wstring AddLongPathPrefix(std::wstring_view path);
			std::wstring NormalizePath(std::wstring_view path, bool resolveFinal = false, Error* err = nullptr);

			//Exists check
			bool Exists(std::wstring_view path);
			bool IsDirectory(std::wstring_view path);
			bool Stat(std::wstring_view path, FileStat& out, Error* err = nullptr);


			//Reading/writing
			bool ReadAllBytes(std::wstring_view path, std::vector<std::byte>& out, Error* err = nullptr);
			bool ReadAllTextUtf8(std::wstring_view path, std::string& out, Error* err = nullptr); // UTF-8 döndürür
			bool WriteAllBytesAtomic(std::wstring_view path, const std::byte* data, size_t len, Error* err = nullptr);
			bool WriteAllBytesAtomic(std::wstring_view path, const std::vector<std::byte>& data, Error* err = nullptr);
			bool WriteAllTextUtf8Atomic(std::wstring_view path, std::string_view utf8, Error* err = nullptr);

			//Atomic rename/replace
			bool ReplaceFileAtomic(std::wstring_view srcPath, std::wstring_view dstPath, Error* err = nullptr);

			//Directory operations
			bool CreateDirectories(std::wstring_view dir, Error* err = nullptr);
			bool RemoveFile(std::wstring_view path, Error* err = nullptr);
			bool RemoveDirectoryRecursive(std::wstring_view dir, Error* err = nullptr);

			//Directory walking
			using WalkCallback = std::function<bool(const std::wstring& fullPath, const WIN32_FIND_DATAW& fd)>;
			bool WalkDirectory(std::wstring_view root, const WalkOptions& opts, const WalkCallback& cb, Error* err = nullptr);


			//ADS(Alternate Data Stream) List
			bool ListAlternateStreams(std::wstring_view path, std::vector<AlternateStreamInfo>& out, Error* err = nullptr);

			// SHA-256 (BCrypt) - Full file
			bool ComputeFileSHA256(std::wstring_view path, std::array<uint8_t, 32>& outHash, Error* err = nullptr);

			//Safe delete
			enum class SecureEraseMode : uint8_t { SinglePassZero = 1, TriplePass = 3 };
			bool SecureEraseFile(std::wstring_view path, SecureEraseMode mode = SecureEraseMode::SinglePassZero, Error* err = nullptr);

			HANDLE OpenFileExclusive(std::wstring_view path, Error* err = nullptr);
			
			//Time helpers.
			bool GetTimes(std::wstring_view path, FILETIME& creation, FILETIME& lastAccess, FILETIME& lastWrite, Error* err = nullptr);

		}//namespace FileUtils
	}//namespace Utils
}//namespace ShadowStrike
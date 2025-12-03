/**
 * @file MemoryUtils.cpp
 * @brief Implementation of memory management utilities.
 *
 * This file implements:
 * - Virtual memory allocation and protection
 * - Guard page allocations for buffer overflow detection
 * - Large page support
 * - Write-watch tracking
 * - Memory-mapped file I/O
 * - Aligned heap allocations
 *
 * @note Windows-specific implementation with stub fallbacks for other platforms.
 */

#include "MemoryUtils.hpp"

#include <algorithm>
#include <new>
#include <malloc.h>
#include <limits>

namespace ShadowStrike {
	namespace Utils {
		namespace MemoryUtils {

			// ============================================================================
			// Internal Constants
			// ============================================================================

			namespace {
				/// Maximum reasonable size for decommit operations (1TB)
				constexpr size_t kMaxDecommitSize = 1ULL << 40;
				
				/// Maximum reasonable alignment for heap allocations (1MB)
				constexpr size_t kMaxAlignment = 1ULL << 20;
				
				/// Maximum reasonable size for aligned heap allocations (4GB)
				constexpr size_t kMaxAlignedAllocSize = 1ULL << 32;
			}

			// ============================================================================
			// Helper Functions
			// ============================================================================

			/**
			 * @brief Align a value up to the specified alignment.
			 * @param v Value to align.
			 * @param a Alignment (must be power of 2).
			 * @return Aligned value, or SIZE_MAX on overflow.
			 */
			[[nodiscard]] static inline size_t AlignUp(size_t v, size_t a) noexcept {
				// Guard against invalid alignment
				if (a == 0) {
					return v;
				}
				
				// Check for overflow before aligning
				if (v > SIZE_MAX - (a - 1)) {
					// Overflow would occur - return max aligned value
					return SIZE_MAX & ~(a - 1);
				}
				
				return (v + (a - 1)) & ~(a - 1);
			}

			// ============================================================================
			// System Information
			// ============================================================================

			size_t PageSize() noexcept {
#ifdef _WIN32
				// Thread-safe initialization via static local
				static const size_t s_pageSize = [] {
					SYSTEM_INFO si{};
					GetNativeSystemInfo(&si);
					return static_cast<size_t>(si.dwPageSize);
				}();
				return s_pageSize;
#else
				return 4096;
#endif
			}

			size_t AllocationGranularity() noexcept {
#ifdef _WIN32
				static const size_t s_granularity = [] {
					SYSTEM_INFO si{};
					GetNativeSystemInfo(&si);
					return static_cast<size_t>(si.dwAllocationGranularity);
				}();
				return s_granularity;
#else
				return 64 * 1024;
#endif
			}

			size_t LargePageMinimum() noexcept {
#ifdef _WIN32
				const SIZE_T s = GetLargePageMinimum();
				return (s != 0) ? static_cast<size_t>(s) : 0;
#else
				return 0;
#endif
			}

			bool IsLargePagesSupported() noexcept {
				return LargePageMinimum() != 0;
			}


			// ============================================================================
			// Virtual Memory Operations
			// ============================================================================

			void* Alloc(size_t size, DWORD protect, DWORD flags, void* desiredBase) {
				if (size == 0) {
					return nullptr;
				}
#ifdef _WIN32
				void* p = ::VirtualAlloc(desiredBase, size, flags, protect);
				if (p == nullptr) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"VirtualAlloc failed (size=%llu, flags=0x%08X, protect=0x%08X)",
						static_cast<unsigned long long>(size), flags, protect);
				}
				return p;
#else
				(void)protect; (void)flags; (void)desiredBase;
				return nullptr;
#endif
			}

			bool Free(void* base, DWORD freeType, size_t size) noexcept {
#ifdef _WIN32
				if (base == nullptr) {
					return true;  // No-op for null pointer
				}

				// VirtualFree preconditions per WinAPI documentation
				if (freeType == MEM_RELEASE) {
					// For MEM_RELEASE: size must be 0
					if (!::VirtualFree(base, 0, MEM_RELEASE)) {
						SS_LOG_LAST_ERROR(L"MemoryUtils", L"VirtualFree(MEM_RELEASE) failed (base=%p)", base);
						return false;
					}
					return true;
				}
				else if (freeType == MEM_DECOMMIT) {
					// For MEM_DECOMMIT: validate size
					const size_t page = PageSize();
					
					if (size == 0) {
						SS_LOG_ERROR(L"MemoryUtils", L"VirtualFree(MEM_DECOMMIT) requires non-zero size (base=%p)", base);
						return false;
					}
					
					if ((size % page) != 0) {
						SS_LOG_ERROR(L"MemoryUtils", 
							L"VirtualFree(MEM_DECOMMIT) size must be page-aligned (size=%llu, page=%llu)",
							static_cast<unsigned long long>(size), static_cast<unsigned long long>(page));
						return false;
					}

					// Sanity check - prevent absurdly large sizes
					if (size > kMaxDecommitSize) {
						SS_LOG_ERROR(L"MemoryUtils", L"VirtualFree(MEM_DECOMMIT) size too large (size=%llu)",
							static_cast<unsigned long long>(size));
						return false;
					}

					if (!::VirtualFree(base, size, MEM_DECOMMIT)) {
						SS_LOG_LAST_ERROR(L"MemoryUtils", L"VirtualFree(MEM_DECOMMIT) failed (base=%p, size=%llu)",
							base, static_cast<unsigned long long>(size));
						return false;
					}
					return true;
				}
				else {
					SS_LOG_ERROR(L"MemoryUtils", L"VirtualFree called with unsupported freeType=0x%08X", freeType);
					return false;
				}
#else
				(void)base; (void)freeType; (void)size;
				return false;
#endif
			}


			bool Protect(void* base, size_t size, DWORD newProtect, DWORD* oldProtect) noexcept {
#ifdef _WIN32
				if (base == nullptr || size == 0) {
					return false;
				}
				
				DWORD oldProtLocal = 0;
				if (!::VirtualProtect(base, size, newProtect, &oldProtLocal)) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"VirtualProtect failed (base=%p, size=%llu, new=0x%08X)",
						base, static_cast<unsigned long long>(size), newProtect);
					return false;
				}
				
				if (oldProtect != nullptr) {
					*oldProtect = oldProtLocal;
				}
				return true;
#else
				(void)base; (void)size; (void)newProtect; (void)oldProtect;
				return false;
#endif
			}

			bool Lock(void* base, size_t size) noexcept {
#ifdef _WIN32
				if (base == nullptr || size == 0) {
					return false;
				}
				
				if (!::VirtualLock(base, size)) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"VirtualLock failed (base=%p, size=%llu)",
						base, static_cast<unsigned long long>(size));
					return false;
				}
				return true;
#else
				(void)base; (void)size;
				return false;
#endif
			}

			bool Unlock(void* base, size_t size) noexcept {
#ifdef _WIN32
				if (base == nullptr || size == 0) {
					return false;
				}
				
				if (!::VirtualUnlock(base, size)) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"VirtualUnlock failed (base=%p, size=%llu)",
						base, static_cast<unsigned long long>(size));
					return false;
				}
				return true;
#else
				(void)base; (void)size;
				return false;
#endif
			}

			bool QueryRegion(const void* addr, MEMORY_BASIC_INFORMATION& mbi) noexcept {
#ifdef _WIN32
				if (addr == nullptr) {
					return false;
				}
				
				const SIZE_T got = ::VirtualQuery(addr, &mbi, sizeof(mbi));
				if (got < sizeof(mbi)) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"VirtualQuery failed (addr=%p)", addr);
					return false;
				}
				return true;
#else
				(void)addr; (void)mbi;
				return false;
#endif
			}

			// ============================================================================
			// Guard Page Allocation
			// ============================================================================

			void GuardedAlloc::Release() noexcept {
#ifdef _WIN32
				if (base != nullptr) {
					if (!::VirtualFree(base, 0, MEM_RELEASE)) {
						SS_LOG_LAST_ERROR(L"MemoryUtils", L"GuardedAlloc::Release: VirtualFree failed (base=%p)", base);
					}
				}
#endif
				base = nullptr;
				data = nullptr;
				dataSize = 0;
				totalSize = 0;
				executable = false;
			}

			bool AllocateWithGuards(size_t dataSize, GuardedAlloc& out, bool executable) noexcept {
#ifdef _WIN32
				// Release any existing allocation
				out.Release();

				// Handle zero-size request
				if (dataSize == 0) {
					out.base = nullptr;
					out.data = nullptr;
					out.dataSize = 0;
					out.totalSize = 0;
					out.executable = executable;
					return true;
				}

				const size_t page = PageSize();
				const size_t dataSizeAligned = AlignUp(dataSize, page);
				
				// Check for overflow in total size calculation
				if (dataSizeAligned > SIZE_MAX - (page * 2)) {
					SS_LOG_ERROR(L"MemoryUtils", L"AllocateWithGuards: Size overflow (dataSize=%llu)",
						static_cast<unsigned long long>(dataSize));
					return false;
				}
				
				const size_t total = dataSizeAligned + (page * 2);

				// Reserve entire region as PAGE_NOACCESS
				void* base = ::VirtualAlloc(nullptr, total, MEM_RESERVE, PAGE_NOACCESS);
				if (base == nullptr) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"AllocateWithGuards: VirtualAlloc(MEM_RESERVE) failed (total=%llu)",
						static_cast<unsigned long long>(total));
					return false;
				}

				// Commit front guard page as PAGE_NOACCESS
				BYTE* guardFront = static_cast<BYTE*>(base);
				if (::VirtualAlloc(guardFront, page, MEM_COMMIT, PAGE_NOACCESS) == nullptr) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"AllocateWithGuards: Failed to commit front guard page");
					::VirtualFree(base, 0, MEM_RELEASE);
					return false;
				}

				// Commit data region with requested protection
				BYTE* dataPtr = guardFront + page;
				const DWORD prot = executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;

				if (::VirtualAlloc(dataPtr, dataSizeAligned, MEM_COMMIT, prot) == nullptr) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"AllocateWithGuards: VirtualAlloc(MEM_COMMIT) failed (dataSize=%llu)",
						static_cast<unsigned long long>(dataSizeAligned));
					::VirtualFree(base, 0, MEM_RELEASE);
					return false;
				}

				// Commit back guard page as PAGE_NOACCESS
				BYTE* guardBack = dataPtr + dataSizeAligned;
				if (::VirtualAlloc(guardBack, page, MEM_COMMIT, PAGE_NOACCESS) == nullptr) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"AllocateWithGuards: Failed to commit back guard page");
					::VirtualFree(base, 0, MEM_RELEASE);
					return false;
				}

				// Fill output structure
				out.base = base;
				out.data = dataPtr;
				out.dataSize = dataSize;
				out.totalSize = total;
				out.executable = executable;
				return true;
#else
				(void)dataSize; (void)out; (void)executable;
				return false;
#endif
			}


			// ============================================================================
			// Large Page Allocation
			// ============================================================================

			bool EnableLockMemoryPrivilege() noexcept {
#ifdef _WIN32
				if (!SystemUtils::EnablePrivilege(L"SeLockMemoryPrivilege", true)) {
					SS_LOG_WARN(L"MemoryUtils", L"EnablePrivilege(SeLockMemoryPrivilege) failed - large pages unavailable");
					return false;
				}
				return true;
#else
				return false;
#endif
			}

			void* AllocLargePages(size_t size, DWORD protect) {
#ifdef _WIN32
				if (size == 0) {
					return nullptr;
				}
				
				const size_t lp = LargePageMinimum();
				if (lp == 0) {
					SS_LOG_WARN(L"MemoryUtils", L"Large pages not supported on this system");
					return nullptr;
				}
				
				if (!EnableLockMemoryPrivilege()) {
					return nullptr;
				}
				
				const size_t aligned = AlignUp(size, lp);
				
				void* p = ::VirtualAlloc(nullptr, aligned, 
					MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES, protect);
					
				if (p == nullptr) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"VirtualAlloc(LARGE_PAGES) failed (size=%llu, aligned=%llu)",
						static_cast<unsigned long long>(size), static_cast<unsigned long long>(aligned));
				}
				return p;
#else
				(void)size; (void)protect;
				return nullptr;
#endif
			}

			bool FreeLargePages(void* base) noexcept {
				return Free(base, MEM_RELEASE, 0);
			}

			// ============================================================================
			// Write Watch Regions
			// ============================================================================

			void* AllocWriteWatch(size_t size, DWORD protect) {
#ifdef _WIN32
				if (size == 0) {
					return nullptr;
				}
				
				void* p = ::VirtualAlloc(nullptr, size, 
					MEM_COMMIT | MEM_RESERVE | MEM_WRITE_WATCH, protect);
					
				if (p == nullptr) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"VirtualAlloc(WRITE_WATCH) failed (size=%llu, protect=0x%08X)",
						static_cast<unsigned long long>(size), protect);
				}
				return p;
#else
				(void)size; (void)protect;
				return nullptr;
#endif
			}

			bool GetWriteWatchAddresses(void* base, size_t regionSize,
				std::vector<void*>& addresses,
				DWORD& granularity) noexcept {
#ifdef _WIN32
				addresses.clear();
				granularity = 0;
				
				if (base == nullptr || regionSize == 0) {
					SS_LOG_ERROR(L"MemoryUtils", L"GetWriteWatchAddresses: Invalid parameters");
					return false;
				}

				ULONG_PTR count = 0;
				DWORD gran = 0;

				// First call: get count of modified pages
				UINT res = ::GetWriteWatch(0, base, regionSize, nullptr, &count, &gran);

				// GetWriteWatch returns non-zero on failure
				if (res != 0) {
					const DWORD lastError = ::GetLastError();
					SS_LOG_ERROR(L"MemoryUtils",
						L"GetWriteWatch (count query) failed (res=%u, base=%p, size=%llu, error=%lu)",
						res, base, static_cast<unsigned long long>(regionSize), lastError);
					return false;
				}

				// No modified pages
				if (count == 0) {
					granularity = gran;
					return true;
				}

				// Allocate buffer and retrieve addresses
				try {
					addresses.resize(static_cast<size_t>(count));
				}
				catch (const std::bad_alloc&) {
					SS_LOG_ERROR(L"MemoryUtils", L"GetWriteWatchAddresses: Failed to allocate buffer for %llu addresses",
						static_cast<unsigned long long>(count));
					return false;
				}

				ULONG_PTR actualCount = count;
				gran = 0;

				// Second call: get actual addresses
				res = ::GetWriteWatch(0, base, regionSize, addresses.data(), &actualCount, &gran);

				if (res != 0) {
					const DWORD lastError = ::GetLastError();
					SS_LOG_ERROR(L"MemoryUtils",
						L"GetWriteWatch (address query) failed (res=%u, error=%lu)",
						res, lastError);
					addresses.clear();
					return false;
				}

				// Trim to actual count (may be less if pages were reset between calls)
				addresses.resize(static_cast<size_t>(actualCount));
				granularity = gran;
				return true;
#else
				(void)base; (void)regionSize; (void)addresses; (void)granularity;
				return false;
#endif
			}

			bool ResetWriteWatchRegion(void* base, size_t regionSize) noexcept {
#ifdef _WIN32
				if (base == nullptr || regionSize == 0) {
					return false;
				}
				
				const UINT res = ::ResetWriteWatch(base, regionSize);
				if (res != 0) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"ResetWriteWatch failed (res=%u, base=%p)", res, base);
					return false;
				}
				return true;
#else
				(void)base; (void)regionSize;
				return false;
#endif
			}

			// ============================================================================
			// Prefetch
			// ============================================================================

			bool PrefetchRegion(void* base, size_t size) noexcept {
#ifdef _WIN32
				if (base == nullptr || size == 0) {
					return false;
				}

				// PrefetchVirtualMemory is Windows 8+ - load dynamically
				using PFN_PrefetchVirtualMemory = BOOL(WINAPI*)(HANDLE, ULONG_PTR, PWIN32_MEMORY_RANGE_ENTRY, ULONG);
				
				static const PFN_PrefetchVirtualMemory s_pfnPrefetch = [] {
					HMODULE h = GetModuleHandleW(L"kernel32.dll");
					if (h == nullptr) {
						return static_cast<PFN_PrefetchVirtualMemory>(nullptr);
					}
					return reinterpret_cast<PFN_PrefetchVirtualMemory>(
						GetProcAddress(h, "PrefetchVirtualMemory"));
				}();

				if (s_pfnPrefetch == nullptr) {
					// Function not available (pre-Windows 8)
					return false;
				}

				WIN32_MEMORY_RANGE_ENTRY range{};
				range.VirtualAddress = base;
				range.NumberOfBytes = size;
				
				if (!s_pfnPrefetch(GetCurrentProcess(), 1, &range, 0)) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"PrefetchVirtualMemory failed (base=%p, size=%llu)",
						base, static_cast<unsigned long long>(size));
					return false;
				}
				return true;
#else
				(void)base; (void)size;
				return false;
#endif
			}

			// ============================================================================
			// Working Set Management
			// ============================================================================

			bool GetProcessWorkingSet(size_t& minBytes, size_t& maxBytes) noexcept {
#ifdef _WIN32
				SIZE_T minW = 0;
				SIZE_T maxW = 0;
				DWORD flags = 0;
				
				if (!::GetProcessWorkingSetSizeEx(GetCurrentProcess(), &minW, &maxW, &flags)) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"GetProcessWorkingSetSizeEx failed");
					return false;
				}
				
				minBytes = static_cast<size_t>(minW);
				maxBytes = static_cast<size_t>(maxW);
				return true;
#else
				(void)minBytes; (void)maxBytes;
				return false;
#endif
			}

			bool SetProcessWorkingSet(size_t minBytes, size_t maxBytes) noexcept {
#ifdef _WIN32
				// Validate that min <= max
				if (minBytes > maxBytes) {
					SS_LOG_ERROR(L"MemoryUtils", L"SetProcessWorkingSet: minBytes (%llu) > maxBytes (%llu)",
						static_cast<unsigned long long>(minBytes),
						static_cast<unsigned long long>(maxBytes));
					return false;
				}
				
				if (!::SetProcessWorkingSetSizeEx(GetCurrentProcess(),
					static_cast<SIZE_T>(minBytes),
					static_cast<SIZE_T>(maxBytes),
					0)) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"SetProcessWorkingSetSizeEx failed (min=%llu, max=%llu)",
						static_cast<unsigned long long>(minBytes),
						static_cast<unsigned long long>(maxBytes));
					return false;
				}
				return true;
#else
				(void)minBytes; (void)maxBytes;
				return false;
#endif
			}

			bool TrimProcessWorkingSet() noexcept {
#ifdef _WIN32
				// Passing (SIZE_T)-1 for both parameters trims the working set
				if (!::SetProcessWorkingSetSize(GetCurrentProcess(), 
					static_cast<SIZE_T>(-1), 
					static_cast<SIZE_T>(-1))) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"TrimProcessWorkingSet failed");
					return false;
				}
				return true;
#else
				return false;
#endif
			}

			// ============================================================================
			// Memory-Mapped File I/O - Helper Functions
			// ============================================================================

			/**
			 * @brief Open a file for memory mapping.
			 * @param path File path.
			 * @param rw True for read-write, false for read-only.
			 * @param hFile Output file handle.
			 * @param outSize Output file size.
			 * @return true on success.
			 */
			static bool OpenFileForMap(const std::wstring& path, bool rw, HANDLE& hFile, size_t& outSize) {
#ifdef _WIN32
				hFile = INVALID_HANDLE_VALUE;
				outSize = 0;

				if (path.empty()) {
					SS_LOG_ERROR(L"MemoryUtils", L"OpenFileForMap: Empty path");
					return false;
				}

				const DWORD access = rw ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_READ;
				const DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
				const DWORD disp = rw ? OPEN_ALWAYS : OPEN_EXISTING;
				const DWORD attrs = FILE_ATTRIBUTE_NORMAL | (rw ? 0 : FILE_FLAG_SEQUENTIAL_SCAN);

				HANDLE f = ::CreateFileW(path.c_str(), access, share, nullptr, disp, attrs, nullptr);
				if (f == INVALID_HANDLE_VALUE) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"CreateFileW failed: %ls", path.c_str());
					return false;
				}

				LARGE_INTEGER li{};
				if (!::GetFileSizeEx(f, &li)) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"GetFileSizeEx failed: %ls", path.c_str());
					::CloseHandle(f);
					return false;
				}

				// Check for files too large to map (> SIZE_MAX)
				if (li.QuadPart < 0 || static_cast<uint64_t>(li.QuadPart) > static_cast<uint64_t>(SIZE_MAX)) {
					SS_LOG_ERROR(L"MemoryUtils", L"File too large to map: %ls (size=%lld)", 
						path.c_str(), li.QuadPart);
					::CloseHandle(f);
					return false;
				}

				outSize = static_cast<size_t>(li.QuadPart);
				hFile = f;
				return true;
#else
				(void)path; (void)rw; (void)hFile; (void)outSize;
				return false;
#endif
			}

			// ============================================================================
			// Memory-Mapped File I/O - MappedView Class
			// ============================================================================

			bool MappedView::mapReadOnly(const std::wstring& path) {
#ifdef _WIN32
				close();
				
				size_t sz = 0;
				if (!OpenFileForMap(path, false, m_file, sz)) {
					return false;
				}

				m_rw = false;
				m_size = sz;

				// Handle empty files - valid but no mapping needed
				if (m_size == 0) {
					return true;
				}

				m_mapping = ::CreateFileMappingW(m_file, nullptr, PAGE_READONLY, 0, 0, nullptr);
				if (m_mapping == nullptr) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"CreateFileMappingW(PAGE_READONLY) failed: %ls", path.c_str());
					close();
					return false;
				}

				m_view = ::MapViewOfFile(m_mapping, FILE_MAP_READ, 0, 0, 0);
				if (m_view == nullptr) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"MapViewOfFile(FILE_MAP_READ) failed: %ls", path.c_str());
					close();
					return false;
				}
				return true;
#else
				(void)path;
				return false;
#endif
			}

			bool MappedView::mapReadWrite(const std::wstring& path) {
#ifdef _WIN32
				close();
				
				size_t sz = 0;
				if (!OpenFileForMap(path, true, m_file, sz)) {
					return false;
				}

				m_rw = true;
				m_size = sz;

				// Handle empty files - cannot create mapping for 0-byte files
				if (m_size == 0) {
					SS_LOG_WARN(L"MemoryUtils", L"mapReadWrite: Cannot map empty file: %ls", path.c_str());
					return true;
				}

				m_mapping = ::CreateFileMappingW(m_file, nullptr, PAGE_READWRITE, 0, 0, nullptr);
				if (m_mapping == nullptr) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"CreateFileMappingW(PAGE_READWRITE) failed: %ls", path.c_str());
					close();
					return false;
				}

				m_view = ::MapViewOfFile(m_mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
				if (m_view == nullptr) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"MapViewOfFile(RW) failed: %ls", path.c_str());
					close();
					return false;
				}
				return true;
#else
				(void)path;
				return false;
#endif
			}

			void MappedView::close() noexcept {
#ifdef _WIN32
				if (m_view != nullptr) {
					if (!::UnmapViewOfFile(m_view)) {
						SS_LOG_LAST_ERROR(L"MemoryUtils", L"UnmapViewOfFile failed");
					}
					m_view = nullptr;
				}
				
				if (m_mapping != nullptr) {
					::CloseHandle(m_mapping);
					m_mapping = nullptr;
				}
				
				if (m_file != INVALID_HANDLE_VALUE) {
					::CloseHandle(m_file);
					m_file = INVALID_HANDLE_VALUE;
				}
#endif
				m_size = 0;
				m_rw = false;
			}

			void MappedView::moveFrom(MappedView&& other) noexcept {
				m_file = other.m_file;
				m_mapping = other.m_mapping;
				m_view = other.m_view;
				m_size = other.m_size;
				m_rw = other.m_rw;

				// Reset source to default state
				other.m_file = INVALID_HANDLE_VALUE;
				other.m_mapping = nullptr;
				other.m_view = nullptr;
				other.m_size = 0;
				other.m_rw = false;
			}

			// ============================================================================
			// Aligned Heap Allocation
			// ============================================================================

			void* AlignedAlloc(size_t size, size_t alignment) noexcept {
				// Validate parameters
				if (size == 0 || alignment == 0) {
					return nullptr;
				}

				// Alignment must be a power of 2
				if ((alignment & (alignment - 1)) != 0) {
					SS_LOG_ERROR(L"MemoryUtils", L"AlignedAlloc: Alignment must be power of 2 (alignment=%llu)",
						static_cast<unsigned long long>(alignment));
					return nullptr;
				}

				// Sanity checks to prevent unreasonable allocations
				if (alignment > kMaxAlignment) {
					SS_LOG_ERROR(L"MemoryUtils", L"AlignedAlloc: Alignment too large (alignment=%llu, max=%llu)",
						static_cast<unsigned long long>(alignment),
						static_cast<unsigned long long>(kMaxAlignment));
					return nullptr;
				}

				if (size > kMaxAlignedAllocSize) {
					SS_LOG_ERROR(L"MemoryUtils", L"AlignedAlloc: Size too large (size=%llu, max=%llu)",
						static_cast<unsigned long long>(size),
						static_cast<unsigned long long>(kMaxAlignedAllocSize));
					return nullptr;
				}

				void* p = _aligned_malloc(size, alignment);
				if (p == nullptr) {
					SS_LOG_ERROR(L"MemoryUtils", L"_aligned_malloc failed (size=%llu, alignment=%llu)",
						static_cast<unsigned long long>(size),
						static_cast<unsigned long long>(alignment));
				}
				return p;
			}

			void AlignedFree(void* p) noexcept {
				if (p != nullptr) {
					_aligned_free(p);
				}
			}

		} // namespace MemoryUtils
	} // namespace Utils
} // namespace ShadowStrike
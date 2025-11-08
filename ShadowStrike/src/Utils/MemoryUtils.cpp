#include "MemoryUtils.hpp"

#include <algorithm>
#include <new>
#include <malloc.h>

namespace ShadowStrike {
	namespace Utils {
		namespace MemoryUtils {

			static inline size_t AlignUp(size_t v, size_t a) noexcept {
				// ? FIX: Check for overflow before addition
				if (a == 0) return v; // Avoid division by zero
				if (v > SIZE_MAX - (a - 1)) {
					// Overflow would occur - return max aligned value
					return SIZE_MAX & ~(a - 1);
				}
				return (v + (a - 1)) & ~(a - 1);
			}
      

			size_t PageSize() noexcept {
#ifdef _WIN32
				static size_t g = [] {
					SYSTEM_INFO si{};
					GetNativeSystemInfo(&si);
					return static_cast<size_t>(si.dwPageSize);
					}();
				return g;
#else
				return 4096;
#endif
			}

			size_t AllocationGranularity() noexcept {
#ifdef _WIN32
				static size_t g = [] {
					SYSTEM_INFO si{};
					GetNativeSystemInfo(&si);
					return static_cast<size_t>(si.dwAllocationGranularity);
					}();
				return g;
#else
				return 64 * 1024;
#endif
			}

			size_t LargePageMinimum() noexcept {
#ifdef _WIN32
				SIZE_T s = GetLargePageMinimum();
				return s ? static_cast<size_t>(s) : 0u;
#else
				return 0;
#endif
			}

			bool IsLargePagesSupported() noexcept {
				return LargePageMinimum() != 0;
			}


			void* Alloc(size_t size, DWORD protect, DWORD flags, void* desiredBase) {
				if (size == 0) return nullptr;
#ifdef _WIN32
				void* p = ::VirtualAlloc(desiredBase, size, flags, protect);
				if (!p) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"VirtualAlloc failed (size=%llu, flags=0x%08X, protect=0x%08X)",
						static_cast<unsigned long long>(size), flags, protect);
				}
				return p;
#else
				(void)protect; (void)flags; (void)desiredBase; return nullptr;
#endif
			}
			bool Free(void* base, DWORD freeType, size_t size) noexcept {
#ifdef _WIN32
    if (!base) return true;

    // VirtualFree preconditions per WinAPI
    if (freeType == MEM_RELEASE) {
        // size must be 0
        if (!::VirtualFree(base, 0, MEM_RELEASE)) {
            SS_LOG_LAST_ERROR(L"MemoryUtils", L"VirtualFree(MEM_RELEASE) failed (base=%p)", base);
            return false;
        }
        return true;
    } else if (freeType == MEM_DECOMMIT) {
        // ? FIX: Validate size doesn't exceed reasonable limits
        const size_t page = PageSize();
        if (size == 0 || (size % page) != 0) {
            SS_LOG_ERROR(L"MemoryUtils", L"VirtualFree(MEM_DECOMMIT) requires non-zero size aligned to page size (size=%llu, page=%llu)",
                static_cast<unsigned long long>(size), static_cast<unsigned long long>(page));
            return false;
        }
        
        // ? FIX: Sanity check - prevent absurdly large sizes
        constexpr size_t MAX_DECOMMIT_SIZE = 1ULL << 40; // 1TB limit
        if (size > MAX_DECOMMIT_SIZE) {
            SS_LOG_ERROR(L"MemoryUtils", L"VirtualFree(MEM_DECOMMIT) size too large (size=%llu)",
                static_cast<unsigned long long>(size));
            return false;
        }
        
        if (!::VirtualFree(base, size, MEM_DECOMMIT)) {
            SS_LOG_LAST_ERROR(L"MemoryUtils", L"VirtualFree(MEM_DECOMMIT) failed (base=%p, size=%llu)", base, static_cast<unsigned long long>(size));
            return false;
        }
        return true;
    } else {
        SS_LOG_ERROR(L"MemoryUtils", L"VirtualFree called with unsupported freeType=0x%08X", freeType);
        return false;
    }
#else
    (void)base; (void)freeType; (void)size; return false;
#endif
			}


			bool Protect(void* base, size_t size, DWORD newProtect, DWORD* oldProtect) noexcept {
#ifdef _WIN32
				if (!base || size == 0) return false;
				DWORD oldProtLocal = 0;
				if (!::VirtualProtect(base, size, newProtect, &oldProtLocal)) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"VirtualProtect failed (base=%p, size=%llu, new=0x%08X)",
						base, static_cast<unsigned long long>(size), newProtect);
					return false;
				}
				if (oldProtect) *oldProtect = oldProtLocal;
				return true;
#else
				(void)base; (void)size; (void)newProtect; (void)oldProtect; return false;
#endif
			}

			bool Lock(void* base, size_t size) noexcept {
#ifdef _WIN32
				if (!base || size == 0) return false;
				if (!::VirtualLock(base, size)) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"VirtualLock failed (base=%p, size=%llu)",
						base, static_cast<unsigned long long>(size));
					return false;
				}
				return true;
#else
				(void)base; (void)size; return false;
#endif
			}


			bool Unlock(void* base, size_t size) noexcept {
#ifdef _WIN32
				if (!base || size == 0) return false;
				if (!::VirtualUnlock(base, size)) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"VirtualUnlock failed (base=%p, size=%llu)",
						base, static_cast<unsigned long long>(size));
					return false;
				}
				return true;
#else
				(void)base; (void)size; return false;
#endif
			}

			bool QueryRegion(const void* addr, MEMORY_BASIC_INFORMATION& mbi) noexcept {
#ifdef _WIN32
				if (!addr) return false;
				SIZE_T got = ::VirtualQuery(addr, &mbi, sizeof(mbi));
				if (got < sizeof(mbi)) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"VirtualQuery failed (addr=%p)", addr);
					return false;
				}
				return true;
#else
				(void)addr; (void)mbi; return false;
#endif
			}

			void GuardedAlloc::Release() noexcept {
#ifdef _WIN32
				if (base) {
					if (!::VirtualFree(base, 0, MEM_RELEASE)) {
						SS_LOG_LAST_ERROR(L"MemoryUtils", L"GuardedAlloc Release: VirtualFree failed (base=%p)", base);
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
    out.Release();

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
    const size_t total = dataSizeAligned + page * 2;

    void* base = ::VirtualAlloc(nullptr, total, MEM_RESERVE, PAGE_NOACCESS);
    if (!base) {
        SS_LOG_LAST_ERROR(L"MemoryUtils", L"AllocateWithGuards: VirtualAlloc(MEM_RESERVE) failed (total=%llu)",
            static_cast<unsigned long long>(total));
        return false;
    }

    // ? FIX: Commit guard pages with PAGE_NOACCESS to trigger exceptions
    BYTE* guardFront = reinterpret_cast<BYTE*>(base);
    if (!::VirtualAlloc(guardFront, page, MEM_COMMIT, PAGE_NOACCESS)) {
        SS_LOG_LAST_ERROR(L"MemoryUtils", L"AllocateWithGuards: Failed to commit front guard page");
        ::VirtualFree(base, 0, MEM_RELEASE);
        return false;
    }

    BYTE* dataPtr = reinterpret_cast<BYTE*>(base) + page;
    DWORD prot = executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;

    if (!::VirtualAlloc(dataPtr, dataSizeAligned, MEM_COMMIT, prot)) {
        SS_LOG_LAST_ERROR(L"MemoryUtils", L"AllocateWithGuards: VirtualAlloc(MEM_COMMIT) failed (dataSize=%llu)",
            static_cast<unsigned long long>(dataSizeAligned));
        ::VirtualFree(base, 0, MEM_RELEASE);
        return false;
    }

    // ? FIX: Commit back guard page
    BYTE* guardBack = dataPtr + dataSizeAligned;
    if (!::VirtualAlloc(guardBack, page, MEM_COMMIT, PAGE_NOACCESS)) {
        SS_LOG_LAST_ERROR(L"MemoryUtils", L"AllocateWithGuards: Failed to commit back guard page");
        ::VirtualFree(base, 0, MEM_RELEASE);
        return false;
    }

    out.base = base;
    out.data = dataPtr;
    out.dataSize = dataSize;
    out.totalSize = total;
    out.executable = executable;
    return true;
#else
    (void)dataSize; (void)out; (void)executable; return false;
#endif
			}


			bool EnableLockMemoryPrivilege() noexcept {
#ifdef _WIN32
				if (!SystemUtils::EnablePrivilege(L"SeLockMemoryPrivilege", true)) {
					SS_LOG_WARN(L"MemoryUtils", L"EnablePrivilege(SeLockMemoryPrivilege) failed");
					return false;
				}
				return true;
#else
				return false;
#endif
			}

			void* AllocLargePages(size_t size, DWORD protect) {
#ifdef _WIN32
				size_t lp = LargePageMinimum();
				if (lp == 0) {
					SS_LOG_WARN(L"MemoryUtils", L"Large pages not supported on this system");
					return nullptr;
				}
				if (!EnableLockMemoryPrivilege()) {
					return nullptr;
				}
				size_t aligned = AlignUp(size, lp);
				void* p = ::VirtualAlloc(nullptr, aligned, MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES, protect);
				if (!p) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"VirtualAlloc(LARGE_PAGES) failed (size=%llu, aligned=%llu)",
						static_cast<unsigned long long>(size), static_cast<unsigned long long>(aligned));
				}
				return p;
#else
				(void)size; (void)protect; return nullptr;
#endif
			}

			bool FreeLargePages(void* base) noexcept {
				return Free(base, MEM_RELEASE, 0);
			}


			void* AllocWriteWatch(size_t size, DWORD protect) {
#ifdef _WIN32
				if (size == 0) return nullptr;
				void* p = ::VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE | MEM_WRITE_WATCH, protect);
				if (!p) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"VirtualAlloc(WRITE_WATCH) failed (size=%llu, protect=0x%08X)",
						static_cast<unsigned long long>(size), protect);
				}
				return p;
#else
				(void)size; (void)protect; return nullptr;
#endif
			}

			bool GetWriteWatchAddresses(void* base, size_t regionSize,
				std::vector<void*>& addresses,
				DWORD& granularity) noexcept {
#ifdef _WIN32
				addresses.clear();
				ULONG_PTR count = 0;
				DWORD res = ::GetWriteWatch(0, base, regionSize, nullptr, &count, &granularity);
				if (res != 0 && res != ERROR_INSUFFICIENT_BUFFER) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"GetWriteWatch size query failed (res=%lu)", res);
					return false;
				}
				if (count == 0) {
					return true;
				}
				addresses.resize(count, nullptr);
				
				// ? FIX: Update count variable for second call (it's in/out parameter)
				ULONG_PTR actualCount = count;
				res = ::GetWriteWatch(0, base, regionSize, reinterpret_cast<void**>(addresses.data()), &actualCount, &granularity);
				if (res != 0) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"GetWriteWatch addresses failed (res=%lu)", res);
					addresses.clear();
					return false;
				}
				
				// ? FIX: Always resize to actual count returned
				addresses.resize(actualCount);
				return true;
#else
				(void)base; (void)regionSize; (void)addresses; (void)granularity; return false;
#endif
			}



			bool ResetWriteWatchRegion(void* base, size_t regionSize) noexcept {
#ifdef _WIN32
				UINT res = ::ResetWriteWatch(base, regionSize);
				if (res != 0) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"ResetWriteWatch failed (res=%u)", res);
					return false;
				}
				return true;
#else
				(void)base; (void)regionSize; return false;
#endif
			}

			bool PrefetchRegion(void* base, size_t size) noexcept {
#ifdef _WIN32
				if (!base || size == 0) return false;

				// PrefetchVirtualMemory dynamic solution
				using PFN_PrefetchVirtualMemory = BOOL(WINAPI*)(HANDLE, ULONG_PTR, PWIN32_MEMORY_RANGE_ENTRY, ULONG);
				HMODULE h = GetModuleHandleW(L"kernel32.dll");
				if (!h) return false;
				auto pfn = reinterpret_cast<PFN_PrefetchVirtualMemory>(
					GetProcAddress(h, "PrefetchVirtualMemory"));
				if (!pfn) return false;

				WIN32_MEMORY_RANGE_ENTRY r{};
				r.VirtualAddress = base;
				r.NumberOfBytes = size;
				if (!pfn(GetCurrentProcess(), 1, &r, 0)) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"PrefetchVirtualMemory failed");
					return false;
				}
				return true;
#else
				(void)base; (void)size; return false;
#endif
			}


			bool GetProcessWorkingSet(size_t& minBytes, size_t& maxBytes) noexcept {
#ifdef _WIN32
				SIZE_T minW = 0, maxW = 0;
				DWORD flags = 0;
				if (!::GetProcessWorkingSetSizeEx(GetCurrentProcess(), &minW, &maxW, &flags)) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"GetProcessWorkingSetSizeEx failed");
					return false;
				}
				minBytes = static_cast<size_t>(minW);
				maxBytes = static_cast<size_t>(maxW);
				return true;
#else
				(void)minBytes; (void)maxBytes; return false;
#endif
			}

			bool SetProcessWorkingSet(size_t minBytes, size_t maxBytes) noexcept {
#ifdef _WIN32
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
				(void)minBytes; (void)maxBytes; return false;
#endif
			}

			bool TrimProcessWorkingSet() noexcept {
#ifdef _WIN32
				if (!::SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1)) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"TrimProcessWorkingSet failed");
					return false;
				}
				return true;
#else
				return false;
#endif
			}

			//Mapped View

			static bool OpenFileForMap(const std::wstring& path, bool rw, HANDLE& hFile, size_t& outSize) {
#ifdef _WIN32
				hFile = INVALID_HANDLE_VALUE;
				outSize = 0;

				DWORD access = rw ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_READ;
				DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
				DWORD disp = rw ? OPEN_ALWAYS : OPEN_EXISTING;
				DWORD attrs = FILE_ATTRIBUTE_NORMAL | (rw ? 0 : FILE_FLAG_SEQUENTIAL_SCAN);

				HANDLE f = ::CreateFileW(path.c_str(), access, share, nullptr, disp, attrs, nullptr);
				if (f == INVALID_HANDLE_VALUE) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"CreateFileW failed: %s", path.c_str());
					return false;
				}
				LARGE_INTEGER li{};
				if (!::GetFileSizeEx(f, &li)) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"GetFileSizeEx failed");
					::CloseHandle(f);
					return false;
				}
				outSize = static_cast<size_t>(li.QuadPart);
				hFile = f;
				return true;
#else
				(void)path; (void)rw; (void)hFile; (void)outSize; return false;
#endif
			}


			bool MappedView::mapReadOnly(const std::wstring& path) {
#ifdef _WIN32
				close();
				size_t sz = 0;
				if (!OpenFileForMap(path, false, m_file, sz)) return false;

				m_rw = false;
				m_size = sz;

				if (m_size == 0) {
					//File is empty, nothing to map
					return true;
				}

				m_mapping = ::CreateFileMappingW(m_file, nullptr, PAGE_READONLY, 0, 0, nullptr);
				if (!m_mapping) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"CreateFileMappingW(PAGE_READONLY) failed");
					close();
					return false;
				}
				m_view = ::MapViewOfFile(m_mapping, FILE_MAP_READ, 0, 0, 0);
				if (!m_view) {
					SS_LOG_LAST_ERROR(L"MemoryUtils", L"MapViewOfFile(FILE_MAP_READ) failed");
					close();
					return false;
				}
				return true;
#else
				(void)path; return false;
#endif
			}


			bool MappedView::mapReadWrite(const std::wstring& path) {
#ifdef _WIN32
    close();
    size_t sz = 0;
    if (!OpenFileForMap(path, true, m_file, sz)) return false;

    m_rw = true;
    m_size = sz;

    // ? FIX: Handle empty files - cannot create mapping for 0-byte files
    if (m_size == 0) {
        // File is empty - valid state but no mapping needed
        SS_LOG_WARN(L"MemoryUtils", L"mapReadWrite: Cannot map empty file: %ls", path.c_str());
        return true;
    }

    m_mapping = ::CreateFileMappingW(m_file, nullptr, PAGE_READWRITE, 0, 0, nullptr);
    if (!m_mapping) {
        SS_LOG_LAST_ERROR(L"MemoryUtils", L"CreateFileMappingW(PAGE_READWRITE) failed");
        close();
        return false;
    }
    m_view = ::MapViewOfFile(m_mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    if (!m_view) {
        SS_LOG_LAST_ERROR(L"MemoryUtils", L"MapViewOfFile(RW) failed");
        close();
        return false;
    }
    return true;
#else
    (void)path; return false;
#endif
			}

			void MappedView::close() noexcept {
#ifdef _WIN32
				if (m_view) {
					if (!::UnmapViewOfFile(m_view)) {
						SS_LOG_LAST_ERROR(L"MemoryUtils", L"UnmapViewOfFile failed");
					}
				}
				if (m_mapping) {
					::CloseHandle(m_mapping);
				}
				if (m_file != INVALID_HANDLE_VALUE) {
					::CloseHandle(m_file);
				}
#endif
				m_view = nullptr;
				m_mapping = nullptr;
				m_file = INVALID_HANDLE_VALUE;
				m_size = 0;
				m_rw = false;
			}

			void MappedView::moveFrom(MappedView&& other) noexcept {
				m_file = other.m_file; other.m_file = INVALID_HANDLE_VALUE;
				m_mapping = other.m_mapping; other.m_mapping = nullptr;
				m_view = other.m_view; other.m_view = nullptr;
				m_size = other.m_size; other.m_size = 0;
				m_rw = other.m_rw; other.m_rw = false;
			}

			//Aligned Heap

			void* AlignedAlloc(size_t size, size_t alignment) noexcept {
				if (size == 0 || alignment == 0) return nullptr;
				
				// ? FIX: Add sanity checks before allocation
				constexpr size_t MAX_ALIGNMENT = 1ULL << 20; // 1MB max alignment
				constexpr size_t MAX_ALLOC_SIZE = 1ULL << 32; // 4GB max allocation
				
				if (alignment > MAX_ALIGNMENT || size > MAX_ALLOC_SIZE) {
					SS_LOG_ERROR(L"MemoryUtils", L"AlignedAlloc: Invalid parameters (size=%llu, alignment=%llu)",
						static_cast<unsigned long long>(size),
						static_cast<unsigned long long>(alignment));
					return nullptr;
				}
				
				void* p = _aligned_malloc(size, alignment);
				if (!p) {
					SS_LOG_ERROR(L"MemoryUtils", L"_aligned_malloc failed (size=%llu, alignment=%llu)",
						static_cast<unsigned long long>(size),
						static_cast<unsigned long long>(alignment));
					// ? NOTE: Caller must check for nullptr - this is documented behavior
				}
				return p;
			}

			void AlignedFree(void* p) noexcept {
				if (!p) return;
				_aligned_free(p);
			}


		}// namespace MemoryUtils
	}// namespace Utils
}// namespace ShadowStrike
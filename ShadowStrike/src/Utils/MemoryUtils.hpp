#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <optional>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#endif

#include "Logger.hpp"
#include "SystemUtils.hpp"
#include "FileUtils.hpp"

namespace ShadowStrike {
    namespace Utils {
        namespace MemoryUtils {

			//Size informations
            size_t PageSize() noexcept;
            size_t AllocationGranularity() noexcept;
            size_t LargePageMinimum() noexcept; //Could return 0
            bool   IsLargePagesSupported() noexcept;

			//fundamental virtual memory operations
            void* Alloc(size_t size,
                DWORD protect = PAGE_READWRITE,
                DWORD flags = MEM_COMMIT | MEM_RESERVE,
                void* desiredBase = nullptr);
            bool   Free(void* base, DWORD freeType = MEM_RELEASE, size_t size = 0) noexcept;
            bool   Protect(void* base, size_t size, DWORD newProtect, DWORD* oldProtect = nullptr) noexcept;
            bool   Lock(void* base, size_t size) noexcept;
            bool   Unlock(void* base, size_t size) noexcept;


			//Memory location information
            bool   QueryRegion(const void* addr, MEMORY_BASIC_INFORMATION& mbi) noexcept;

            // Distribution of protection page (NoAccess head/bottom page)
            struct GuardedAlloc {
				void* base = nullptr;     // Start of the entire region (guard + data + guard)
                void* data = nullptr;     //data pointer
                size_t dataSize = 0;       // Commit size
                size_t totalSize = 0;      // Total rezervation (guard + data + guard)
                bool   executable = false;

                void   Release() noexcept; // release RAII
            };
            bool AllocateWithGuards(size_t dataSize,
                GuardedAlloc& out,
                bool executable = false) noexcept;

            //Big page allocation
            bool  EnableLockMemoryPrivilege() noexcept;
            void* AllocLargePages(size_t size,
                DWORD protect = PAGE_READWRITE); 
            bool  FreeLargePages(void* base) noexcept;

           //WriteWatch regions
            void* AllocWriteWatch(size_t size,
                DWORD protect = PAGE_READWRITE); // with MEM_WRITE_WATCH 
            bool  GetWriteWatchAddresses(void* base, size_t regionSize,
                std::vector<void*>& addresses,
                DWORD& granularity) noexcept;
            bool  ResetWriteWatchRegion(void* base, size_t regionSize) noexcept;

            // Prefetch (Win8+)
            bool  PrefetchRegion(void* base, size_t size) noexcept;

            //Working set
            bool  GetProcessWorkingSet(size_t& minBytes, size_t& maxBytes) noexcept;
            bool  SetProcessWorkingSet(size_t minBytes, size_t maxBytes) noexcept;
            bool  TrimProcessWorkingSet() noexcept;

            //RAII
            class MappedView {
            public:
                MappedView() = default;
                ~MappedView() { close(); }

                //No copy, movable
                MappedView(const MappedView&) = delete;
                MappedView& operator=(const MappedView&) = delete;
                MappedView(MappedView&& other) noexcept { moveFrom(std::move(other)); }
                MappedView& operator=(MappedView&& other) noexcept { if (this != &other) { close(); moveFrom(std::move(other)); } return *this; }

                bool mapReadOnly(const std::wstring& path);
                bool mapReadWrite(const std::wstring& path);
                void close() noexcept;

                [[nodiscard]] void* data() const noexcept { return m_view; }
                [[nodiscard]] size_t size() const noexcept { return m_size; }
                [[nodiscard]] bool  valid() const noexcept { 
                    // ? FIX: Correct operator precedence with explicit parentheses
                    return (m_view != nullptr) || (m_size == 0 && m_file != INVALID_HANDLE_VALUE); 
                }

            private:
                void moveFrom(MappedView&& other) noexcept;

                HANDLE m_file = INVALID_HANDLE_VALUE;
                HANDLE m_mapping = nullptr;
                void* m_view = nullptr;
                size_t m_size = 0;
                bool   m_rw = false;
            };

            //Secure Resetting

            inline void SecureZero(void* p, size_t n) noexcept {
#ifdef _WIN32
                if (p && n) RtlSecureZeroMemory(p, n);
#else
                volatile unsigned char* vp = reinterpret_cast<volatile unsigned char*>(p);
                for (size_t i = 0; i < n; ++i) vp[i] = 0;
#endif
            }

			//Heap Alloc/Free with alignment
            void* AlignedAlloc(size_t size, size_t alignment) noexcept;
            void   AlignedFree(void* p) noexcept;


		}// namespace MemoryUtils
	}// namespace Utils
}// namespace ShadowStrike
#pragma once
/**
 * @file MemoryUtils.hpp
 * @brief Memory management utilities for ShadowStrike Security Suite.
 *
 * Provides enterprise-grade memory operations including:
 * - Virtual memory allocation with guard pages
 * - Large page support for performance-critical allocations
 * - Write-watch regions for memory change detection
 * - Memory-mapped file I/O with RAII semantics
 * - Aligned heap allocations
 * - Secure memory wiping
 * - Working set management
 *
 * All functions are designed for security-critical applications with
 * proper error handling and logging.
 *
 * @note Windows-specific implementation. Non-Windows platforms have stub implementations.
 * @warning Memory operations require appropriate privileges for some features.
 */

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
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

#include "Logger.hpp"
#include "SystemUtils.hpp"
#include "FileUtils.hpp"

namespace ShadowStrike {
	namespace Utils {
		namespace MemoryUtils {

			// ============================================================================
			// System Information
			// ============================================================================

			/**
			 * @brief Get the system page size.
			 * @return Page size in bytes (typically 4096 on x64).
			 */
			[[nodiscard]] size_t PageSize() noexcept;

			/**
			 * @brief Get the system allocation granularity.
			 * @return Allocation granularity in bytes (typically 64KB on Windows).
			 */
			[[nodiscard]] size_t AllocationGranularity() noexcept;

			/**
			 * @brief Get the minimum large page size.
			 * @return Large page size in bytes, or 0 if not supported.
			 */
			[[nodiscard]] size_t LargePageMinimum() noexcept;

			/**
			 * @brief Check if large pages are supported.
			 * @return true if large pages are available.
			 */
			[[nodiscard]] bool IsLargePagesSupported() noexcept;

			// ============================================================================
			// Virtual Memory Operations
			// ============================================================================

			/**
			 * @brief Allocate virtual memory.
			 * @param size Size in bytes to allocate.
			 * @param protect Memory protection flags (default PAGE_READWRITE).
			 * @param flags Allocation flags (default MEM_COMMIT | MEM_RESERVE).
			 * @param desiredBase Optional base address hint.
			 * @return Pointer to allocated memory, or nullptr on failure.
			 */
			[[nodiscard]] void* Alloc(size_t size,
				DWORD protect = PAGE_READWRITE,
				DWORD flags = MEM_COMMIT | MEM_RESERVE,
				void* desiredBase = nullptr);

			/**
			 * @brief Free virtual memory.
			 * @param base Base address to free.
			 * @param freeType Free type (MEM_RELEASE or MEM_DECOMMIT).
			 * @param size Size for MEM_DECOMMIT (must be 0 for MEM_RELEASE).
			 * @return true on success.
			 */
			bool Free(void* base, DWORD freeType = MEM_RELEASE, size_t size = 0) noexcept;

			/**
			 * @brief Change memory protection.
			 * @param base Base address.
			 * @param size Region size.
			 * @param newProtect New protection flags.
			 * @param oldProtect Optional output for old protection.
			 * @return true on success.
			 */
			bool Protect(void* base, size_t size, DWORD newProtect, DWORD* oldProtect = nullptr) noexcept;

			/**
			 * @brief Lock memory pages in physical RAM.
			 * @param base Base address.
			 * @param size Region size.
			 * @return true on success.
			 */
			bool Lock(void* base, size_t size) noexcept;

			/**
			 * @brief Unlock previously locked memory pages.
			 * @param base Base address.
			 * @param size Region size.
			 * @return true on success.
			 */
			bool Unlock(void* base, size_t size) noexcept;

			// ============================================================================
			// Memory Query
			// ============================================================================

			/**
			 * @brief Query memory region information.
			 * @param addr Address to query.
			 * @param mbi Output structure for region info.
			 * @return true on success.
			 */
			[[nodiscard]] bool QueryRegion(const void* addr, MEMORY_BASIC_INFORMATION& mbi) noexcept;

			// ============================================================================
			// Guard Page Allocation
			// ============================================================================

			/**
			 * @brief Structure for guarded memory allocation.
			 * 
			 * Provides memory region with guard pages at front and back
			 * to detect buffer overflows/underflows.
			 */
			struct GuardedAlloc {
				void* base = nullptr;      ///< Start of entire region (guard + data + guard)
				void* data = nullptr;      ///< Pointer to usable data region
				size_t dataSize = 0;       ///< Requested data size
				size_t totalSize = 0;      ///< Total allocation (guards + data)
				bool executable = false;   ///< Whether data region is executable

				/**
				 * @brief Release the guarded allocation.
				 * @note Safe to call multiple times.
				 */
				void Release() noexcept;
			};

			/**
			 * @brief Allocate memory with guard pages.
			 * @param dataSize Size of data region.
			 * @param out Output structure.
			 * @param executable Whether to allow code execution.
			 * @return true on success.
			 */
			[[nodiscard]] bool AllocateWithGuards(size_t dataSize,
				GuardedAlloc& out,
				bool executable = false) noexcept;

			// ============================================================================
			// Large Page Allocation
			// ============================================================================

			/**
			 * @brief Enable SeLockMemoryPrivilege for large pages.
			 * @return true if privilege was enabled.
			 */
			bool EnableLockMemoryPrivilege() noexcept;

			/**
			 * @brief Allocate memory using large pages.
			 * @param size Size in bytes (will be rounded up to large page boundary).
			 * @param protect Memory protection flags.
			 * @return Pointer to allocated memory, or nullptr on failure.
			 * @note Requires SeLockMemoryPrivilege.
			 */
			[[nodiscard]] void* AllocLargePages(size_t size,
				DWORD protect = PAGE_READWRITE);

			/**
			 * @brief Free large page allocation.
			 * @param base Base address from AllocLargePages.
			 * @return true on success.
			 */
			bool FreeLargePages(void* base) noexcept;

			// ============================================================================
			// Write Watch Regions
			// ============================================================================

			/**
			 * @brief Allocate memory with write-watch tracking.
			 * @param size Region size.
			 * @param protect Memory protection flags.
			 * @return Pointer to allocated memory, or nullptr on failure.
			 */
			[[nodiscard]] void* AllocWriteWatch(size_t size,
				DWORD protect = PAGE_READWRITE);

			/**
			 * @brief Get addresses that have been written to.
			 * @param base Base address of write-watch region.
			 * @param regionSize Size of region.
			 * @param addresses Output vector of written addresses.
			 * @param granularity Output granularity of tracking.
			 * @return true on success.
			 */
			[[nodiscard]] bool GetWriteWatchAddresses(void* base, size_t regionSize,
				std::vector<void*>& addresses,
				DWORD& granularity) noexcept;

			/**
			 * @brief Reset write-watch tracking for a region.
			 * @param base Base address.
			 * @param regionSize Region size.
			 * @return true on success.
			 */
			bool ResetWriteWatchRegion(void* base, size_t regionSize) noexcept;

			// ============================================================================
			// Prefetch
			// ============================================================================

			/**
			 * @brief Prefetch memory region into cache (Windows 8+).
			 * @param base Base address.
			 * @param size Region size.
			 * @return true on success.
			 */
			bool PrefetchRegion(void* base, size_t size) noexcept;

			// ============================================================================
			// Working Set Management
			// ============================================================================

			/**
			 * @brief Get process working set limits.
			 * @param minBytes Output minimum working set.
			 * @param maxBytes Output maximum working set.
			 * @return true on success.
			 */
			[[nodiscard]] bool GetProcessWorkingSet(size_t& minBytes, size_t& maxBytes) noexcept;

			/**
			 * @brief Set process working set limits.
			 * @param minBytes Minimum working set.
			 * @param maxBytes Maximum working set.
			 * @return true on success.
			 */
			bool SetProcessWorkingSet(size_t minBytes, size_t maxBytes) noexcept;

			/**
			 * @brief Trim the process working set.
			 * @return true on success.
			 */
			bool TrimProcessWorkingSet() noexcept;

			// ============================================================================
			// Memory-Mapped File I/O
			// ============================================================================

			/**
			 * @brief RAII wrapper for memory-mapped file views.
			 *
			 * Provides safe, exception-safe memory mapping with automatic cleanup.
			 * Supports both read-only and read-write mappings.
			 *
			 * @note Move-only type (non-copyable).
			 */
			class MappedView {
			public:
				MappedView() = default;
				~MappedView() { close(); }

				// Non-copyable, movable
				MappedView(const MappedView&) = delete;
				MappedView& operator=(const MappedView&) = delete;
				MappedView(MappedView&& other) noexcept { moveFrom(std::move(other)); }
				MappedView& operator=(MappedView&& other) noexcept {
					if (this != &other) {
						close();
						moveFrom(std::move(other));
					}
					return *this;
				}

				/**
				 * @brief Map a file for read-only access.
				 * @param path File path.
				 * @return true on success.
				 */
				bool mapReadOnly(const std::wstring& path);

				/**
				 * @brief Map a file for read-write access.
				 * @param path File path.
				 * @return true on success.
				 */
				bool mapReadWrite(const std::wstring& path);

				/**
				 * @brief Close the mapping and release resources.
				 */
				void close() noexcept;

				/**
				 * @brief Get pointer to mapped data.
				 * @return Pointer to data, or nullptr if not mapped.
				 */
				[[nodiscard]] void* data() const noexcept { return m_view; }

				/**
				 * @brief Get size of mapped region.
				 * @return Size in bytes.
				 */
				[[nodiscard]] size_t size() const noexcept { return m_size; }

				/**
				 * @brief Check if mapping is valid.
				 * @return true if file is opened (may be empty file with no view).
				 * 
				 * @note A valid mapping can have m_view==nullptr if the file is empty (0 bytes).
				 *       In that case, m_file will be valid and m_size will be 0.
				 */
				[[nodiscard]] bool valid() const noexcept {
					// Valid states:
					// 1. Non-empty file: m_view != nullptr && m_file != INVALID_HANDLE_VALUE
					// 2. Empty file: m_view == nullptr && m_size == 0 && m_file != INVALID_HANDLE_VALUE
					// Invalid state: m_file == INVALID_HANDLE_VALUE (not opened)
					if (m_file == INVALID_HANDLE_VALUE) {
						return false;
					}
					// File is open - valid even if empty (no view)
					return (m_view != nullptr) || (m_size == 0);
				}

				/**
				 * @brief Check if mapping has data to read.
				 * @return true if view is mapped and non-empty.
				 */
				[[nodiscard]] bool hasData() const noexcept {
					return (m_view != nullptr) && (m_size > 0);
				}

				/**
				 * @brief Check if mapping is read-write.
				 * @return true if read-write mode.
				 */
				[[nodiscard]] bool isReadWrite() const noexcept { return m_rw; }

			private:
				void moveFrom(MappedView&& other) noexcept;

				HANDLE m_file = INVALID_HANDLE_VALUE;
				HANDLE m_mapping = nullptr;
				void* m_view = nullptr;
				size_t m_size = 0;
				bool m_rw = false;
			};

			// ============================================================================
			// Secure Memory Operations
			// ============================================================================

			/**
			 * @brief Securely zero memory (not optimized away by compiler).
			 * @param p Pointer to memory.
			 * @param n Size in bytes.
			 * 
			 * @note Uses RtlSecureZeroMemory on Windows to prevent compiler optimization.
			 */
			inline void SecureZero(void* p, size_t n) noexcept {
#ifdef _WIN32
				if (p != nullptr && n > 0) {
					RtlSecureZeroMemory(p, n);
				}
#else
				if (p != nullptr && n > 0) {
					volatile unsigned char* vp = reinterpret_cast<volatile unsigned char*>(p);
					for (size_t i = 0; i < n; ++i) {
						vp[i] = 0;
					}
				}
#endif
			}

			// ============================================================================
			// Aligned Heap Allocation
			// ============================================================================

			/**
			 * @brief Allocate aligned memory from heap.
			 * @param size Size in bytes.
			 * @param alignment Alignment requirement (must be power of 2).
			 * @return Pointer to aligned memory, or nullptr on failure.
			 * 
			 * @note Must be freed with AlignedFree().
			 */
			[[nodiscard]] void* AlignedAlloc(size_t size, size_t alignment) noexcept;

			/**
			 * @brief Free aligned memory.
			 * @param p Pointer from AlignedAlloc (safe to pass nullptr).
			 */
			void AlignedFree(void* p) noexcept;

		} // namespace MemoryUtils
	} // namespace Utils
} // namespace ShadowStrike
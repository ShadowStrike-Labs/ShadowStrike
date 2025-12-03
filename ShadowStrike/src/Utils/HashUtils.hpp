#pragma once
/**
 * @file HashUtils.hpp
 * @brief Cryptographic hashing utilities for ShadowStrike Security Suite.
 *
 * Provides secure hashing functionality including:
 * - Multiple algorithm support (SHA-1, SHA-256, SHA-384, SHA-512, MD5)
 * - HMAC authentication codes
 * - Streaming hash computation for large data
 * - File hashing with efficient buffered I/O
 * - Non-cryptographic fast hashes (FNV-1a)
 * - Hex encoding/decoding utilities
 *
 * Implementation uses Windows BCrypt API for FIPS-compliant operations.
 *
 * @note SHA-1 and MD5 are provided for compatibility only - use SHA-256+ for security.
 * @warning Thread-safe for independent Hasher/Hmac instances.
 */

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#  include <bcrypt.h>
#  include <winternl.h>
#  pragma comment(lib, "bcrypt.lib")
#  pragma comment(lib, "ntdll.lib")  // For RtlNtStatusToDosError
#endif

#include "Logger.hpp"

namespace ShadowStrike {
	namespace Utils {
		namespace HashUtils {

			// ============================================================================
			// Security Constants
			// ============================================================================

			/// Maximum input size for hex conversion to prevent DoS (20MB hex = 10MB binary)
			inline constexpr size_t MAX_HEX_INPUT_SIZE = 20 * 1024 * 1024;

			/// Maximum file size for single-pass hashing (4GB)
			inline constexpr uint64_t MAX_HASH_FILE_SIZE = 4ULL * 1024 * 1024 * 1024;

			/// Default buffer size for file hashing (1MB for optimal I/O)
			inline constexpr size_t FILE_HASH_BUFFER_SIZE = 1 << 20;

			// ============================================================================
			// Types and Enumerations
			// ============================================================================

			/**
			 * @brief Supported cryptographic hash algorithms.
			 *
			 * @note SHA-1 and MD5 are deprecated for security purposes.
			 *       Use SHA-256 or stronger for new implementations.
			 */
			enum class Algorithm : uint8_t {
				SHA1,       ///< SHA-1 (160-bit) - DEPRECATED, collision attacks exist
				SHA256,     ///< SHA-256 (256-bit) - Recommended minimum
				SHA384,     ///< SHA-384 (384-bit) - High security
				SHA512,     ///< SHA-512 (512-bit) - Maximum security
				MD5         ///< MD5 (128-bit) - INSECURE, compatibility only
			};

			/**
			 * @brief Error information structure for hash operations.
			 *
			 * Captures both Win32 and NTSTATUS error codes for comprehensive
			 * error reporting from BCrypt operations.
			 */
			struct Error {
				DWORD win32 = ERROR_SUCCESS;    ///< Win32 error code (0 = success)
				LONG ntstatus = 0;              ///< NTSTATUS code from BCrypt operations

				/// @brief Check if an error occurred
				[[nodiscard]] constexpr bool hasError() const noexcept {
					return win32 != ERROR_SUCCESS || ntstatus < 0;
				}

				/// @brief Clear error state
				constexpr void clear() noexcept {
					win32 = ERROR_SUCCESS;
					ntstatus = 0;
				}
			};

			// ============================================================================
			// Comparison Utilities
			// ============================================================================

			/**
			 * @brief Constant-time comparison of hash digests.
			 *
			 * Performs timing-safe comparison to prevent side-channel attacks.
			 * Both buffers must be the same length.
			 *
			 * @param a First digest buffer
			 * @param b Second digest buffer
			 * @param len Length of both buffers in bytes
			 * @return true if buffers are identical, false otherwise
			 */
			[[nodiscard]] bool Equal(const uint8_t* a, const uint8_t* b, size_t len) noexcept;

			// ============================================================================
			// Hex Encoding/Decoding
			// ============================================================================

			/**
			 * @brief Convert binary data to lowercase hexadecimal string.
			 * @param data Input binary data
			 * @param len Length of input data
			 * @return Lowercase hex string (empty on allocation failure)
			 */
			[[nodiscard]] std::string ToHexLower(const uint8_t* data, size_t len);

			/**
			 * @brief Convert binary data to uppercase hexadecimal string.
			 * @param data Input binary data
			 * @param len Length of input data
			 * @return Uppercase hex string (empty on allocation failure)
			 */
			[[nodiscard]] std::string ToHexUpper(const uint8_t* data, size_t len);

			/**
			 * @brief Convert vector to lowercase hex string.
			 * @param v Input byte vector
			 * @return Lowercase hex string
			 */
			[[nodiscard]] inline std::string ToHexLower(const std::vector<uint8_t>& v) {
				return ToHexLower(v.data(), v.size());
			}

			/**
			 * @brief Convert vector to uppercase hex string.
			 * @param v Input byte vector
			 * @return Uppercase hex string
			 */
			[[nodiscard]] inline std::string ToHexUpper(const std::vector<uint8_t>& v) {
				return ToHexUpper(v.data(), v.size());
			}

			/**
			 * @brief Decode hexadecimal string to binary data.
			 *
			 * Accepts both uppercase and lowercase hex characters.
			 * Input length must be even.
			 *
			 * @param hex Input hex string
			 * @param out Output byte vector (cleared on failure)
			 * @return true on success, false on invalid input or allocation failure
			 */
			[[nodiscard]] bool FromHex(std::string_view hex, std::vector<uint8_t>& out);

			// ============================================================================
			// Non-Cryptographic Hashes
			// ============================================================================

			/**
			 * @brief Compute FNV-1a 32-bit hash.
			 *
			 * Fast non-cryptographic hash suitable for hash tables.
			 * NOT suitable for security purposes.
			 *
			 * @param data Input data
			 * @param len Length of input data
			 * @return 32-bit hash value
			 */
			[[nodiscard]] uint32_t Fnv1a32(const void* data, size_t len) noexcept;

			/**
			 * @brief Compute FNV-1a 64-bit hash.
			 *
			 * Fast non-cryptographic hash suitable for hash tables.
			 * NOT suitable for security purposes.
			 *
			 * @param data Input data
			 * @param len Length of input data
			 * @return 64-bit hash value
			 */
			[[nodiscard]] uint64_t Fnv1a64(const void* data, size_t len) noexcept;

			// ============================================================================
			// Algorithm Information
			// ============================================================================

			/**
			 * @brief Get digest size for an algorithm.
			 * @param alg Hash algorithm
			 * @return Digest size in bytes
			 */
			[[nodiscard]] size_t DigestSize(Algorithm alg) noexcept;

			// ============================================================================
			// Streaming Hasher Class
			// ============================================================================

			/**
			 * @brief Streaming cryptographic hash computation.
			 *
			 * Allows incremental hashing of data in chunks, suitable for
			 * large files or streaming data. Uses Windows BCrypt API.
			 *
			 * Usage:
			 * @code
			 *   Hasher h(Algorithm::SHA256);
			 *   if (!h.Init()) return false;
			 *   if (!h.Update(data1, len1)) return false;
			 *   if (!h.Update(data2, len2)) return false;
			 *   std::vector<uint8_t> digest;
			 *   if (!h.Final(digest)) return false;
			 * @endcode
			 *
			 * @note Non-copyable, move-only. Each instance maintains its own state.
			 * @note Thread-safe for independent instances.
			 */
			class Hasher {
			public:
				/**
				 * @brief Construct hasher for specified algorithm.
				 * @param alg Hash algorithm to use (default: SHA256)
				 */
				explicit Hasher(Algorithm alg = Algorithm::SHA256) noexcept;

				/// @brief Destructor - securely clears internal state
				~Hasher();

				// Non-copyable
				Hasher(const Hasher&) = delete;
				Hasher& operator=(const Hasher&) = delete;

				// Move operations
				Hasher(Hasher&& other) noexcept;
				Hasher& operator=(Hasher&& other) noexcept;

				/**
				 * @brief Initialize hasher for new computation.
				 *
				 * Must be called before Update(). Can be called again to reset.
				 *
				 * @param err Optional error output
				 * @return true on success, false on failure
				 */
				[[nodiscard]] bool Init(Error* err = nullptr) noexcept;

				/**
				 * @brief Feed data into the hash computation.
				 *
				 * Can be called multiple times with different data chunks.
				 * Must call Init() first.
				 *
				 * @param data Input data buffer
				 * @param len Length of input data
				 * @param err Optional error output
				 * @return true on success, false on failure
				 */
				[[nodiscard]] bool Update(const void* data, size_t len, Error* err = nullptr) noexcept;

				/**
				 * @brief Finalize hash and retrieve digest.
				 *
				 * Completes the hash computation and resets internal state.
				 * The hasher can be reused by calling Init() again.
				 *
				 * @param out Output vector for hash digest
				 * @param err Optional error output
				 * @return true on success, false on failure
				 */
				[[nodiscard]] bool Final(std::vector<uint8_t>& out, Error* err = nullptr) noexcept;

				/**
				 * @brief Finalize hash and retrieve as hex string.
				 * @param outHex Output hex string
				 * @param upper If true, use uppercase hex characters
				 * @param err Optional error output
				 * @return true on success, false on failure
				 */
				[[nodiscard]] bool FinalHex(std::string& outHex, bool upper = false, Error* err = nullptr) noexcept;

				/// @brief Get digest size for current algorithm
				[[nodiscard]] size_t GetDigestSize() const noexcept { return m_hashLen; }

				/// @brief Get current algorithm
				[[nodiscard]] Algorithm GetAlgorithm() const noexcept { return m_alg; }

				/// @brief Check if hasher is initialized and ready for Update()
				[[nodiscard]] bool IsInitialized() const noexcept { return m_inited; }

			private:
#ifdef _WIN32
				void* m_objBuf = nullptr;           ///< BCrypt hash object buffer
				DWORD m_objLen = 0;                 ///< Size of object buffer
				BCRYPT_HASH_HANDLE m_hash = nullptr; ///< BCrypt hash handle
#endif
				Algorithm m_alg;                    ///< Selected algorithm
				size_t m_hashLen = 0;               ///< Digest size in bytes
				bool m_inited = false;              ///< Initialization state

				/// @brief Ensure algorithm provider is ready
				[[nodiscard]] bool ensureProviderReady(Error* err) noexcept;

				/// @brief Reset and securely clear internal state
				void resetState() noexcept;
			};


			// ============================================================================
			// HMAC Authentication Class
			// ============================================================================

			/**
			 * @brief HMAC (Hash-based Message Authentication Code) computation.
			 *
			 * Provides keyed hash authentication using Windows BCrypt API.
			 * Suitable for message authentication and integrity verification.
			 *
			 * Usage:
			 * @code
			 *   Hmac h(Algorithm::SHA256);
			 *   if (!h.Init(key, keyLen)) return false;
			 *   if (!h.Update(data, len)) return false;
			 *   std::vector<uint8_t> mac;
			 *   if (!h.Final(mac)) return false;
			 * @endcode
			 *
			 * @note Non-copyable. Key material is securely cleared after use.
			 * @note Thread-safe for independent instances.
			 */
			class Hmac {
			public:
				/**
				 * @brief Construct HMAC for specified algorithm.
				 * @param alg Hash algorithm for HMAC (default: SHA256)
				 */
				explicit Hmac(Algorithm alg = Algorithm::SHA256) noexcept;

				/// @brief Destructor - securely clears key and state
				~Hmac();

				// Non-copyable, non-movable (contains sensitive key material)
				Hmac(const Hmac&) = delete;
				Hmac& operator=(const Hmac&) = delete;
				Hmac(Hmac&&) = delete;
				Hmac& operator=(Hmac&&) = delete;

				/**
				 * @brief Initialize HMAC with secret key.
				 *
				 * Key material is copied and securely cleared after initialization.
				 *
				 * @param key Secret key buffer
				 * @param keyLen Length of key in bytes
				 * @param err Optional error output
				 * @return true on success, false on failure
				 */
				[[nodiscard]] bool Init(const void* key, size_t keyLen, Error* err = nullptr) noexcept;

				/**
				 * @brief Feed data into HMAC computation.
				 * @param data Input data buffer
				 * @param len Length of input data
				 * @param err Optional error output
				 * @return true on success, false on failure
				 */
				[[nodiscard]] bool Update(const void* data, size_t len, Error* err = nullptr) noexcept;

				/**
				 * @brief Finalize HMAC and retrieve authentication code.
				 * @param out Output vector for MAC
				 * @param err Optional error output
				 * @return true on success, false on failure
				 */
				[[nodiscard]] bool Final(std::vector<uint8_t>& out, Error* err = nullptr) noexcept;

				/**
				 * @brief Finalize HMAC and retrieve as hex string.
				 * @param outHex Output hex string
				 * @param upper If true, use uppercase hex
				 * @param err Optional error output
				 * @return true on success, false on failure
				 */
				[[nodiscard]] bool FinalHex(std::string& outHex, bool upper = false, Error* err = nullptr) noexcept;

				/// @brief Get MAC size for current algorithm
				[[nodiscard]] size_t GetDigestSize() const noexcept { return m_hashLen; }

				/// @brief Get current algorithm
				[[nodiscard]] Algorithm GetAlgorithm() const noexcept { return m_alg; }

				/// @brief Check if HMAC is initialized
				[[nodiscard]] bool IsInitialized() const noexcept { return m_inited; }

			private:
#ifdef _WIN32
				void* m_objBuf = nullptr;           ///< BCrypt hash object buffer
				DWORD m_objLen = 0;                 ///< Size of object buffer
				BCRYPT_HASH_HANDLE m_hash = nullptr; ///< BCrypt hash handle
#endif
				Algorithm m_alg;                    ///< Selected algorithm
				size_t m_hashLen = 0;               ///< MAC size in bytes
				bool m_inited = false;              ///< Initialization state

				/// @brief Ensure algorithm provider is ready
				[[nodiscard]] bool ensureProviderReady(Error* err) noexcept;

				/// @brief Reset and securely clear internal state
				void resetState() noexcept;
			};

			// ============================================================================
			// One-Shot Hash Functions
			// ============================================================================

			/**
			 * @brief Compute hash of data in one call.
			 * @param alg Hash algorithm
			 * @param data Input data buffer
			 * @param len Length of input data
			 * @param out Output digest vector
			 * @param err Optional error output
			 * @return true on success, false on failure
			 */
			[[nodiscard]] bool Compute(Algorithm alg, const void* data, size_t len,
			                           std::vector<uint8_t>& out, Error* err = nullptr) noexcept;

			/**
			 * @brief Compute hash of string data in one call.
			 * @param alg Hash algorithm
			 * @param data Input string data
			 * @param out Output digest vector
			 * @param err Optional error output
			 * @return true on success, false on failure
			 */
			[[nodiscard]] inline bool Compute(Algorithm alg, std::string_view data,
			                                  std::vector<uint8_t>& out, Error* err = nullptr) noexcept {
				return Compute(alg, data.data(), data.size(), out, err);
			}

			/**
			 * @brief Compute hash and return as hex string.
			 * @param alg Hash algorithm
			 * @param data Input data buffer
			 * @param len Length of input data
			 * @param outHex Output hex string
			 * @param upper If true, use uppercase hex
			 * @param err Optional error output
			 * @return true on success, false on failure
			 */
			[[nodiscard]] bool ComputeHex(Algorithm alg, const void* data, size_t len,
			                              std::string& outHex, bool upper = false, Error* err = nullptr) noexcept;

			// ============================================================================
			// One-Shot HMAC Functions
			// ============================================================================

			/**
			 * @brief Compute HMAC in one call.
			 * @param alg Hash algorithm
			 * @param key Secret key buffer
			 * @param keyLen Length of key
			 * @param data Input data buffer
			 * @param len Length of input data
			 * @param out Output MAC vector
			 * @param err Optional error output
			 * @return true on success, false on failure
			 */
			[[nodiscard]] bool ComputeHmac(Algorithm alg, const void* key, size_t keyLen,
			                               const void* data, size_t len,
			                               std::vector<uint8_t>& out, Error* err = nullptr) noexcept;

			/**
			 * @brief Compute HMAC and return as hex string.
			 * @param alg Hash algorithm
			 * @param key Secret key buffer
			 * @param keyLen Length of key
			 * @param data Input data buffer
			 * @param len Length of input data
			 * @param outHex Output hex string
			 * @param upper If true, use uppercase hex
			 * @param err Optional error output
			 * @return true on success, false on failure
			 */
			[[nodiscard]] bool ComputeHmacHex(Algorithm alg, const void* key, size_t keyLen,
			                                  const void* data, size_t len,
			                                  std::string& outHex, bool upper = false, Error* err = nullptr) noexcept;

			// ============================================================================
			// File Hashing
			// ============================================================================

			/**
			 * @brief Compute hash of file contents.
			 *
			 * Reads file in buffered chunks for memory efficiency.
			 * Uses FILE_FLAG_SEQUENTIAL_SCAN for optimal I/O.
			 *
			 * @param alg Hash algorithm
			 * @param path File path (supports long paths with \\?\ prefix)
			 * @param out Output digest vector
			 * @param err Optional error output
			 * @return true on success, false on failure
			 */
			[[nodiscard]] bool ComputeFile(Algorithm alg, std::wstring_view path,
			                               std::vector<uint8_t>& out, Error* err = nullptr) noexcept;

		}  // namespace HashUtils
	}  // namespace Utils
}  // namespace ShadowStrike
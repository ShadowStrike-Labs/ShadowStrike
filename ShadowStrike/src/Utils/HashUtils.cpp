/**
 * @file HashUtils.cpp
 * @brief Implementation of cryptographic hashing utilities.
 *
 * Uses Windows BCrypt API for FIPS-compliant hash operations.
 * Provider handles are cached per-algorithm for performance.
 */

#include "HashUtils.hpp"

#include <algorithm>
#include <memory>
#include <mutex>
#include <cstdio>

namespace ShadowStrike {
	namespace Utils {
		namespace HashUtils {

#ifdef _WIN32

			// ============================================================================
			// Algorithm Provider Management
			// ============================================================================

			/**
			 * @brief Cached algorithm provider state.
			 *
			 * BCrypt algorithm providers are expensive to create, so we cache them
			 * per-algorithm. Thread-safe initialization via std::call_once.
			 */
			struct AlgProv {
				BCRYPT_ALG_HANDLE hAlg = nullptr;      ///< Normal hash provider
				BCRYPT_ALG_HANDLE hAlgHmac = nullptr;  ///< HMAC provider
				DWORD hashLen = 0;                     ///< Digest size
				DWORD objLen = 0;                      ///< Hash object buffer size
				DWORD objLenHmac = 0;                  ///< HMAC object buffer size
				bool ready = false;                    ///< Initialization success flag
				NTSTATUS lastNt = 0;                   ///< Last NTSTATUS for error reporting
			};

			/**
			 * @brief Get BCrypt algorithm name string.
			 * @param a Algorithm enumeration
			 * @return BCrypt algorithm name constant
			 */
			[[nodiscard]] static const wchar_t* AlgName(Algorithm a) noexcept {
				switch (a) {
				case Algorithm::SHA1:   return BCRYPT_SHA1_ALGORITHM;
				case Algorithm::SHA256: return BCRYPT_SHA256_ALGORITHM;
				case Algorithm::SHA384: return BCRYPT_SHA384_ALGORITHM;
				case Algorithm::SHA512: return BCRYPT_SHA512_ALGORITHM;
				case Algorithm::MD5:    return BCRYPT_MD5_ALGORITHM;
				default:                return BCRYPT_SHA256_ALGORITHM;
				}
			}

			/**
			 * @brief Get cached provider for algorithm.
			 *
			 * Uses static storage for provider caching. Each algorithm
			 * has its own provider instance.
			 *
			 * @param a Algorithm to get provider for
			 * @return Reference to provider state
			 */
			[[nodiscard]] static AlgProv& GetProv(Algorithm a) noexcept {
				// Static providers - one per algorithm
				static AlgProv sha1, sha256, sha384, sha512, md5;
				switch (a) {
				case Algorithm::SHA1:   return sha1;
				case Algorithm::SHA256: return sha256;
				case Algorithm::SHA384: return sha384;
				case Algorithm::SHA512: return sha512;
				case Algorithm::MD5:    return md5;
				default:                return sha256;  // Safe default
				}
			}

			/**
			 * @brief Ensure algorithm provider is initialized.
			 *
			 * Thread-safe initialization using std::call_once.
			 * Opens both normal hash and HMAC providers.
			 *
			 * @param a Algorithm to initialize
			 * @param err Optional error output
			 * @return true if provider is ready, false on failure
			 */
			[[nodiscard]] static bool EnsureProv(Algorithm a, Error* err) noexcept {
				AlgProv& ap = GetProv(a);

				// Thread-safe one-time initialization per algorithm
				static std::once_flag onceFlags[5];
				const int idx = static_cast<int>(a);

				// Bounds check for safety
				if (idx < 0 || idx >= 5) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->ntstatus = STATUS_INVALID_PARAMETER;
					}
					return false;
				}

				std::call_once(onceFlags[idx], [&]() {
					const wchar_t* name = AlgName(a);

					// Open normal hash provider
					NTSTATUS st = BCryptOpenAlgorithmProvider(&ap.hAlg, name, nullptr, 0);
					ap.lastNt = st;
					if (!NT_SUCCESS(st)) {
						return;
					}

					// Query hash length
					DWORD cb = 0;
					st = BCryptGetProperty(ap.hAlg, BCRYPT_HASH_LENGTH,
					                       reinterpret_cast<PUCHAR>(&ap.hashLen),
					                       sizeof(ap.hashLen), &cb, 0);
					ap.lastNt = st;
					if (!NT_SUCCESS(st)) return;

					// Query object length for hash operations
					st = BCryptGetProperty(ap.hAlg, BCRYPT_OBJECT_LENGTH,
					                       reinterpret_cast<PUCHAR>(&ap.objLen),
					                       sizeof(ap.objLen), &cb, 0);
					ap.lastNt = st;
					if (!NT_SUCCESS(st)) return;

					// Open HMAC provider with HMAC flag
					st = BCryptOpenAlgorithmProvider(&ap.hAlgHmac, name, nullptr,
					                                 BCRYPT_ALG_HANDLE_HMAC_FLAG);
					ap.lastNt = st;
					if (!NT_SUCCESS(st)) return;

					// Query HMAC object length
					st = BCryptGetProperty(ap.hAlgHmac, BCRYPT_OBJECT_LENGTH,
					                       reinterpret_cast<PUCHAR>(&ap.objLenHmac),
					                       sizeof(ap.objLenHmac), &cb, 0);
					ap.lastNt = st;
					if (!NT_SUCCESS(st)) return;

					ap.ready = true;
				});

				if (!ap.ready) {
					if (err) {
						err->ntstatus = ap.lastNt;
						err->win32 = RtlNtStatusToDosError(static_cast<NTSTATUS>(ap.lastNt));
					}
					SS_LOG_ERROR(L"HashUtils", L"BCryptOpenAlgorithmProvider failed for %ls (nt=0x%08X)",
					             AlgName(a), static_cast<unsigned int>(ap.lastNt));
					return false;
				}
				return true;
			}

// NT_SUCCESS macro if not defined
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// NTSTATUS codes not available in standard SDK headers
#ifndef STATUS_INVALID_DEVICE_STATE
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xC0000184L)
#endif

// Maximum ULONG value for bounds checking
#ifndef MAXULONG
#define MAXULONG 0xFFFFFFFFUL
#endif

#endif  // _WIN32


			// ============================================================================
			// Algorithm Information
			// ============================================================================

			size_t DigestSize(Algorithm alg) noexcept {
				switch (alg) {
				case Algorithm::SHA1:   return 20;   // 160 bits
				case Algorithm::SHA256: return 32;   // 256 bits
				case Algorithm::SHA384: return 48;   // 384 bits
				case Algorithm::SHA512: return 64;   // 512 bits
				case Algorithm::MD5:    return 16;   // 128 bits
				default:                return 32;   // Default to SHA256
				}
			}

			// ============================================================================
			// Comparison Utilities
			// ============================================================================

			bool Equal(const uint8_t* a, const uint8_t* b, size_t len) noexcept {
				// Handle identical pointers (optimization)
				if (a == b) return true;

				// Null pointer safety
				if (!a || !b) return false;

				// Constant-time comparison to prevent timing attacks
				// Accumulator collects all XOR differences
				volatile uint8_t acc = 0;
				for (size_t i = 0; i < len; ++i) {
					acc |= (a[i] ^ b[i]);
				}

				// Force compiler to not optimize away the comparison
				return acc == 0;
			}

			// ============================================================================
			// Hex Encoding/Decoding
			// ============================================================================

			/// @brief Convert nibble to uppercase hex character
			[[nodiscard]] static inline char hexUpper(uint8_t v) noexcept {
				return "0123456789ABCDEF"[v & 0x0F];
			}

			/// @brief Convert nibble to lowercase hex character
			[[nodiscard]] static inline char hexLower(uint8_t v) noexcept {
				return "0123456789abcdef"[v & 0x0F];
			}

			std::string ToHexLower(const uint8_t* data, size_t len) {
				if (!data || len == 0) return std::string();

				// Check for overflow (len * 2 must fit in size_t)
				if (len > (SIZE_MAX / 2)) return std::string();

				std::string s;
				try {
					s.resize(len * 2);
				}
				catch (const std::bad_alloc&) {
					return std::string();
				}

				for (size_t i = 0; i < len; ++i) {
					const uint8_t c = data[i];
					s[(i << 1) + 0] = hexLower(c >> 4);
					s[(i << 1) + 1] = hexLower(c);
				}
				return s;
			}

			std::string ToHexUpper(const uint8_t* data, size_t len) {
				if (!data || len == 0) return std::string();

				// Check for overflow
				if (len > (SIZE_MAX / 2)) return std::string();

				std::string s;
				try {
					s.resize(len * 2);
				}
				catch (const std::bad_alloc&) {
					return std::string();
				}

				for (size_t i = 0; i < len; ++i) {
					const uint8_t c = data[i];
					s[(i << 1) + 0] = hexUpper(c >> 4);
					s[(i << 1) + 1] = hexUpper(c);
				}
				return s;
			}

			bool FromHex(std::string_view hex, std::vector<uint8_t>& out) {
				out.clear();

				// Empty input is valid (produces empty output)
				if (hex.empty()) return true;

				// Hex string must have even length
				if ((hex.size() & 1) != 0) return false;

				// Prevent DoS via extremely large hex input
				if (hex.size() > MAX_HEX_INPUT_SIZE) {
					return false;
				}

				// Lambda for hex character to value conversion
				auto hv = [](char c) -> int {
					if (c >= '0' && c <= '9') return c - '0';
					if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
					if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
					return -1;  // Invalid character
				};

				// Allocate output buffer with exception safety
				try {
					out.resize(hex.size() / 2);
				}
				catch (const std::bad_alloc&) {
					return false;
				}

				// Convert hex pairs to bytes
				for (size_t i = 0, j = 0; i < hex.size(); i += 2, ++j) {
					const int hi = hv(hex[i]);
					const int lo = hv(hex[i + 1]);

					if (hi < 0 || lo < 0) {
						out.clear();
						return false;
					}
					out[j] = static_cast<uint8_t>((hi << 4) | lo);
				}
				return true;
			}

			// ============================================================================
			// Non-Cryptographic Hashes (FNV-1a)
			// ============================================================================

			uint32_t Fnv1a32(const void* data, size_t len) noexcept {
				if (!data || len == 0) return 2166136261u;  // Return basis for empty input

				const uint8_t* p = static_cast<const uint8_t*>(data);
				uint32_t h = 2166136261u;  // FNV-1a 32-bit offset basis

				for (size_t i = 0; i < len; ++i) {
					h ^= p[i];
					h *= 16777619u;  // FNV-1a 32-bit prime
				}
				return h;
			}

			uint64_t Fnv1a64(const void* data, size_t len) noexcept {
				if (!data || len == 0) return 14695981039346656037ull;  // Return basis for empty

				const uint8_t* p = static_cast<const uint8_t*>(data);
				uint64_t h = 14695981039346656037ull;  // FNV-1a 64-bit offset basis

				for (size_t i = 0; i < len; ++i) {
					h ^= p[i];
					h *= 1099511628211ull;  // FNV-1a 64-bit prime
				}
				return h;
			}
			// ============================================================================
			// Hasher Class Implementation
			// ============================================================================

			Hasher::Hasher(Algorithm alg) noexcept
				: m_alg(alg)
				, m_hashLen(DigestSize(alg))
			{
			}

			Hasher::~Hasher() {
				resetState();
			}

			Hasher::Hasher(Hasher&& other) noexcept
				: m_objBuf(other.m_objBuf)
				, m_objLen(other.m_objLen)
#ifdef _WIN32
				, m_hash(other.m_hash)
#endif
				, m_alg(other.m_alg)
				, m_hashLen(other.m_hashLen)
				, m_inited(other.m_inited)
			{
				// Transfer ownership - nullify source to prevent double-free
				other.m_objBuf = nullptr;
				other.m_objLen = 0;
#ifdef _WIN32
				other.m_hash = nullptr;
#endif
				other.m_inited = false;
			}

			Hasher& Hasher::operator=(Hasher&& other) noexcept {
				if (this != &other) {
					// Clean up current state first
					resetState();

					// Transfer ownership
					m_objBuf = other.m_objBuf;
					m_objLen = other.m_objLen;
#ifdef _WIN32
					m_hash = other.m_hash;
#endif
					m_alg = other.m_alg;
					m_hashLen = other.m_hashLen;
					m_inited = other.m_inited;

					// Nullify source
					other.m_objBuf = nullptr;
					other.m_objLen = 0;
#ifdef _WIN32
					other.m_hash = nullptr;
#endif
					other.m_inited = false;
				}
				return *this;
			}

			void Hasher::resetState() noexcept {
#ifdef _WIN32
				// Destroy BCrypt hash handle
				if (m_hash) {
					BCryptDestroyHash(m_hash);
					m_hash = nullptr;
				}

				// Securely clear and free object buffer
				if (m_objBuf) {
					if (m_objLen > 0) {
						SecureZeroMemory(m_objBuf, m_objLen);
					}
					free(m_objBuf);
					m_objBuf = nullptr;
				}
				m_objLen = 0;
				m_inited = false;
#endif
			}

			bool Hasher::ensureProviderReady(Error* err) noexcept {
#ifdef _WIN32
				if (!EnsureProv(m_alg, err)) return false;

				// Update hash length from provider (authoritative source)
				AlgProv& ap = GetProv(m_alg);
				m_hashLen = ap.hashLen;
				return true;
#else
				if (err) err->win32 = ERROR_NOT_SUPPORTED;
				return false;
#endif
			}

			bool Hasher::Init(Error* err) noexcept {
				// Reset any existing state
				resetState();

#ifdef _WIN32
				if (!ensureProviderReady(err)) return false;

				AlgProv& ap = GetProv(m_alg);

				// Allocate hash object buffer
				m_objLen = ap.objLen;
				const size_t allocSize = (m_objLen > 0) ? m_objLen : 1;
				m_objBuf = malloc(allocSize);
				if (!m_objBuf) {
					if (err) {
						err->win32 = ERROR_OUTOFMEMORY;
						err->ntstatus = STATUS_NO_MEMORY;
					}
					SS_LOG_ERROR(L"HashUtils", L"Hasher::Init: malloc failed for %zu bytes", allocSize);
					return false;
				}

				// Create BCrypt hash object
				NTSTATUS st = BCryptCreateHash(ap.hAlg, &m_hash,
				                               static_cast<PUCHAR>(m_objBuf), m_objLen,
				                               nullptr, 0, 0);
				if (!NT_SUCCESS(st)) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
					}
					SS_LOG_ERROR(L"HashUtils", L"BCryptCreateHash failed (nt=0x%08X)", static_cast<unsigned int>(st));
					resetState();
					return false;
				}

				m_inited = true;
				return true;
#else
				if (err) err->win32 = ERROR_NOT_SUPPORTED;
				return false;
#endif
			}

			bool Hasher::Update(const void* data, size_t len, Error* err) noexcept {
#ifdef _WIN32
				// State validation
				if (!m_inited) {
					if (err) {
						err->win32 = ERROR_INVALID_STATE;
						err->ntstatus = STATUS_INVALID_DEVICE_STATE;
					}
					return false;
				}

				// Empty update is a no-op (valid)
				if (len == 0) return true;

				// Null data with non-zero length is invalid
				if (!data) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->ntstatus = STATUS_INVALID_PARAMETER;
					}
					return false;
				}

				// BCrypt uses ULONG for length - check for overflow on 64-bit
				if (len > static_cast<size_t>(MAXULONG)) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->ntstatus = STATUS_INVALID_PARAMETER;
					}
					SS_LOG_ERROR(L"HashUtils", L"Hasher::Update: length exceeds ULONG max");
					return false;
				}

				NTSTATUS st = BCryptHashData(m_hash,
				                             const_cast<PUCHAR>(static_cast<const UCHAR*>(data)),
				                             static_cast<ULONG>(len), 0);
				if (!NT_SUCCESS(st)) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
					}
					SS_LOG_ERROR(L"HashUtils", L"BCryptHashData failed (nt=0x%08X)", static_cast<unsigned int>(st));
					return false;
				}
				return true;
#else
				(void)data; (void)len;
				if (err) err->win32 = ERROR_NOT_SUPPORTED;
				return false;
#endif
			}

			bool Hasher::Final(std::vector<uint8_t>& out, Error* err) noexcept {
#ifdef _WIN32
				// State validation
				if (!m_inited) {
					if (err) {
						err->win32 = ERROR_INVALID_STATE;
						err->ntstatus = STATUS_INVALID_DEVICE_STATE;
					}
					return false;
				}

				// Allocate output buffer
				try {
					out.resize(m_hashLen);
				}
				catch (const std::bad_alloc&) {
					if (err) {
						err->win32 = ERROR_OUTOFMEMORY;
						err->ntstatus = STATUS_NO_MEMORY;
					}
					resetState();
					return false;
				}

				// Finalize hash
				NTSTATUS st = BCryptFinishHash(m_hash, out.data(),
				                               static_cast<ULONG>(out.size()), 0);
				if (!NT_SUCCESS(st)) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
					}
					SS_LOG_ERROR(L"HashUtils", L"BCryptFinishHash failed (nt=0x%08X)", static_cast<unsigned int>(st));
					out.clear();
					resetState();
					return false;
				}

				// Reset state after successful finalization
				resetState();
				return true;
#else
				out.clear();
				if (err) err->win32 = ERROR_NOT_SUPPORTED;
				return false;
#endif
			}

			bool Hasher::FinalHex(std::string& outHex, bool upper, Error* err) noexcept {
				std::vector<uint8_t> digest;
				if (!Final(digest, err)) {
					outHex.clear();
					return false;
				}
				outHex = upper ? ToHexUpper(digest) : ToHexLower(digest);
				return true;
			}

			// ============================================================================
			// HMAC Class Implementation
			// ============================================================================

			Hmac::Hmac(Algorithm alg) noexcept
				: m_alg(alg)
				, m_hashLen(DigestSize(alg))
			{
			}

			Hmac::~Hmac() {
				resetState();
			}

			void Hmac::resetState() noexcept {
#ifdef _WIN32
				// Destroy BCrypt hash handle
				if (m_hash) {
					BCryptDestroyHash(m_hash);
					m_hash = nullptr;
				}

				// Securely clear and free object buffer
				if (m_objBuf) {
					if (m_objLen > 0) {
						SecureZeroMemory(m_objBuf, m_objLen);
					}
					free(m_objBuf);
					m_objBuf = nullptr;
				}
				m_objLen = 0;
#endif
				m_inited = false;
			}

			bool Hmac::ensureProviderReady(Error* err) noexcept {
#ifdef _WIN32
				if (!EnsureProv(m_alg, err)) return false;

				AlgProv& ap = GetProv(m_alg);
				m_hashLen = ap.hashLen;
				return true;
#else
				if (err) err->win32 = ERROR_NOT_SUPPORTED;
				return false;
#endif
			}

			bool Hmac::Init(const void* key, size_t keyLen, Error* err) noexcept {
				resetState();

#ifdef _WIN32
				if (!ensureProviderReady(err)) return false;

				AlgProv& ap = GetProv(m_alg);

				// Allocate HMAC object buffer
				m_objLen = ap.objLenHmac;
				const size_t allocSize = (m_objLen > 0) ? m_objLen : 1;
				m_objBuf = malloc(allocSize);
				if (!m_objBuf) {
					if (err) {
						err->win32 = ERROR_OUTOFMEMORY;
						err->ntstatus = STATUS_NO_MEMORY;
					}
					SS_LOG_ERROR(L"HashUtils", L"Hmac::Init: malloc failed for %zu bytes", allocSize);
					return false;
				}

				// RAII wrapper for secure key buffer cleanup
				struct SecureKeyBuffer {
					std::unique_ptr<uint8_t[]> data;
					size_t size;

					explicit SecureKeyBuffer(size_t sz) : size(sz) {
						if (sz > 0) {
							data.reset(new (std::nothrow) uint8_t[sz]);
						}
					}

					~SecureKeyBuffer() {
						if (data && size > 0) {
							SecureZeroMemory(data.get(), size);
						}
					}

					uint8_t* get() noexcept { return data.get(); }
					explicit operator bool() const noexcept { return data != nullptr || size == 0; }

					// Non-copyable
					SecureKeyBuffer(const SecureKeyBuffer&) = delete;
					SecureKeyBuffer& operator=(const SecureKeyBuffer&) = delete;
				};

				// Copy key material for BCrypt (which may retain reference)
				SecureKeyBuffer keyCopy(keyLen);
				if (keyLen > 0) {
					if (!keyCopy) {
						if (err) {
							err->win32 = ERROR_OUTOFMEMORY;
							err->ntstatus = STATUS_NO_MEMORY;
						}
						SS_LOG_ERROR(L"HashUtils", L"Hmac::Init: key buffer allocation failed");
						resetState();
						return false;
					}

					if (!key) {
						if (err) {
							err->win32 = ERROR_INVALID_PARAMETER;
							err->ntstatus = STATUS_INVALID_PARAMETER;
						}
						resetState();
						return false;
					}

					memcpy(keyCopy.get(), key, keyLen);
				}

				// Create HMAC hash object with key
				NTSTATUS st = BCryptCreateHash(ap.hAlgHmac, &m_hash,
				                               static_cast<PUCHAR>(m_objBuf), m_objLen,
				                               keyLen ? keyCopy.get() : nullptr,
				                               static_cast<ULONG>(keyLen), 0);

				// Key is automatically zeroed by SecureKeyBuffer destructor

				if (!NT_SUCCESS(st)) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
					}
					SS_LOG_ERROR(L"HashUtils", L"BCryptCreateHash(HMAC) failed (nt=0x%08X)",
					             static_cast<unsigned int>(st));
					resetState();
					return false;
				}

				m_inited = true;
				return true;
#else
				(void)key; (void)keyLen;
				if (err) err->win32 = ERROR_NOT_SUPPORTED;
				return false;
#endif
			}

			bool Hmac::Update(const void* data, size_t len, Error* err) noexcept {
#ifdef _WIN32
				// State validation
				if (!m_inited) {
					if (err) {
						err->win32 = ERROR_INVALID_STATE;
						err->ntstatus = STATUS_INVALID_DEVICE_STATE;
					}
					return false;
				}

				// Empty update is valid
				if (len == 0) return true;

				// Null data with non-zero length is invalid
				if (!data) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->ntstatus = STATUS_INVALID_PARAMETER;
					}
					return false;
				}

				// Check for ULONG overflow
				if (len > static_cast<size_t>(MAXULONG)) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->ntstatus = STATUS_INVALID_PARAMETER;
					}
					return false;
				}

				NTSTATUS st = BCryptHashData(m_hash,
				                             const_cast<PUCHAR>(static_cast<const UCHAR*>(data)),
				                             static_cast<ULONG>(len), 0);
				if (!NT_SUCCESS(st)) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
					}
					SS_LOG_ERROR(L"HashUtils", L"BCryptHashData(HMAC) failed (nt=0x%08X)",
					             static_cast<unsigned int>(st));
					return false;
				}
				return true;
#else
				(void)data; (void)len;
				if (err) err->win32 = ERROR_NOT_SUPPORTED;
				return false;
#endif
			}

			bool Hmac::Final(std::vector<uint8_t>& out, Error* err) noexcept {
#ifdef _WIN32
				// State validation
				if (!m_inited) {
					if (err) {
						err->win32 = ERROR_INVALID_STATE;
						err->ntstatus = STATUS_INVALID_DEVICE_STATE;
					}
					return false;
				}

				// Allocate output buffer
				try {
					out.resize(m_hashLen);
				}
				catch (const std::bad_alloc&) {
					if (err) {
						err->win32 = ERROR_OUTOFMEMORY;
						err->ntstatus = STATUS_NO_MEMORY;
					}
					resetState();
					return false;
				}

				// Finalize HMAC
				NTSTATUS st = BCryptFinishHash(m_hash, out.data(),
				                               static_cast<ULONG>(out.size()), 0);
				if (!NT_SUCCESS(st)) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
					}
					SS_LOG_ERROR(L"HashUtils", L"BCryptFinishHash(HMAC) failed (nt=0x%08X)",
					             static_cast<unsigned int>(st));
					out.clear();
					resetState();
					return false;
				}

				resetState();
				return true;
#else
				out.clear();
				if (err) err->win32 = ERROR_NOT_SUPPORTED;
				return false;
#endif
			}

			bool Hmac::FinalHex(std::string& outHex, bool upper, Error* err) noexcept {
				std::vector<uint8_t> mac;
				if (!Final(mac, err)) {
					outHex.clear();
					return false;
				}
				outHex = upper ? ToHexUpper(mac) : ToHexLower(mac);
				return true;
			}

			// ============================================================================
			// One-Shot Hash Helper Functions
			// ============================================================================

			bool Compute(Algorithm alg, const void* data, size_t len,
			             std::vector<uint8_t>& out, Error* err) noexcept {
				out.clear();

				Hasher h(alg);
				if (!h.Init(err)) return false;

				// Handle data if present
				if (len > 0) {
					if (!data) {
						if (err) {
							err->win32 = ERROR_INVALID_PARAMETER;
							err->ntstatus = STATUS_INVALID_PARAMETER;
						}
						return false;
					}
					if (!h.Update(data, len, err)) return false;
				}

				return h.Final(out, err);
			}

			bool ComputeHex(Algorithm alg, const void* data, size_t len,
			                std::string& outHex, bool upper, Error* err) noexcept {
				std::vector<uint8_t> digest;
				if (!Compute(alg, data, len, digest, err)) {
					outHex.clear();
					return false;
				}
				outHex = upper ? ToHexUpper(digest) : ToHexLower(digest);
				return true;
			}

			// ============================================================================
			// One-Shot HMAC Helper Functions
			// ============================================================================

			bool ComputeHmac(Algorithm alg, const void* key, size_t keyLen,
			                 const void* data, size_t len,
			                 std::vector<uint8_t>& out, Error* err) noexcept {
				out.clear();

				Hmac h(alg);
				if (!h.Init(key, keyLen, err)) return false;

				if (len > 0) {
					if (!data) {
						if (err) {
							err->win32 = ERROR_INVALID_PARAMETER;
							err->ntstatus = STATUS_INVALID_PARAMETER;
						}
						return false;
					}
					if (!h.Update(data, len, err)) return false;
				}

				return h.Final(out, err);
			}

			bool ComputeHmacHex(Algorithm alg, const void* key, size_t keyLen,
			                    const void* data, size_t len,
			                    std::string& outHex, bool upper, Error* err) noexcept {
				std::vector<uint8_t> mac;
				if (!ComputeHmac(alg, key, keyLen, data, len, mac, err)) {
					outHex.clear();
					return false;
				}
				outHex = upper ? ToHexUpper(mac) : ToHexLower(mac);
				return true;
			}

			// ============================================================================
			// File Hashing
			// ============================================================================

			bool ComputeFile(Algorithm alg, std::wstring_view path,
			                 std::vector<uint8_t>& out, Error* err) noexcept {
				out.clear();

#ifdef _WIN32
				// Validate path
				if (path.empty()) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->ntstatus = STATUS_INVALID_PARAMETER;
					}
					return false;
				}

				// Convert to null-terminated string
				std::wstring pathStr;
				try {
					pathStr = std::wstring(path);
				}
				catch (const std::bad_alloc&) {
					if (err) {
						err->win32 = ERROR_OUTOFMEMORY;
						err->ntstatus = STATUS_NO_MEMORY;
					}
					return false;
				}

				// Open file with sequential scan hint for optimal I/O
				HANDLE h = CreateFileW(pathStr.c_str(), GENERIC_READ,
				                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				                       nullptr, OPEN_EXISTING,
				                       FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
				if (h == INVALID_HANDLE_VALUE) {
					if (err) err->win32 = GetLastError();
					SS_LOG_LAST_ERROR(L"HashUtils", L"ComputeFile: CreateFileW failed: %ls", pathStr.c_str());
					return false;
				}

				// RAII handle guard
				struct HandleGuard {
					HANDLE h;
					explicit HandleGuard(HANDLE hnd) noexcept : h(hnd) {}
					~HandleGuard() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
					HandleGuard(const HandleGuard&) = delete;
					HandleGuard& operator=(const HandleGuard&) = delete;
				} guard(h);

				// Initialize hasher
				Hasher hasher(alg);
				if (!hasher.Init(err)) {
					return false;
				}

				// Allocate read buffer (1MB for good sequential read performance)
				std::vector<uint8_t> buf;
				try {
					buf.resize(FILE_HASH_BUFFER_SIZE);
				}
				catch (const std::bad_alloc&) {
					if (err) {
						err->win32 = ERROR_OUTOFMEMORY;
						err->ntstatus = STATUS_NO_MEMORY;
					}
					return false;
				}

				// Read and hash file in chunks
				for (;;) {
					DWORD bytesRead = 0;
					BOOL ok = ReadFile(h, buf.data(), static_cast<DWORD>(buf.size()),
					                   &bytesRead, nullptr);
					if (!ok) {
						if (err) err->win32 = GetLastError();
						SS_LOG_LAST_ERROR(L"HashUtils", L"ComputeFile: ReadFile failed");
						return false;
					}

					// EOF reached
					if (bytesRead == 0) break;

					// Update hash with chunk
					if (!hasher.Update(buf.data(), bytesRead, err)) {
						return false;
					}
				}

				// Finalize hash
				return hasher.Final(out, err);
#else
				(void)alg; (void)path;
				if (err) err->win32 = ERROR_NOT_SUPPORTED;
				return false;
#endif
			}

		}  // namespace HashUtils
	}  // namespace Utils
}  // namespace ShadowStrike
// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
#include"pch.h"
#include"CryptoUtils.hpp"
#include"CryptoUtilsCommon.hpp"

namespace ShadowStrike {
	namespace Utils {
		namespace CryptoUtils {
			// =============================================================================
	  // SymmetricCipher Implementation
	  // =============================================================================

			SymmetricCipher::SymmetricCipher(SymmetricAlgorithm algorithm) noexcept
				: m_streamBuffer()
				, m_streamFinalized(false)
				, m_algorithm(algorithm)
				, m_paddingMode(PaddingMode::PKCS7)
#ifdef _WIN32
				, m_algHandle(nullptr)
				, m_keyHandle(nullptr)
				, m_keyObject()
#endif
				, m_key()
				, m_iv()
				, m_keySet(false)
				, m_ivSet(false)
			{
			}

			SymmetricCipher::~SymmetricCipher() {
				cleanup();
			}

			SymmetricCipher::SymmetricCipher(SymmetricCipher&& other) noexcept
				: m_streamBuffer(std::move(other.m_streamBuffer))
				, m_streamFinalized(other.m_streamFinalized)
				, m_algorithm(other.m_algorithm)
				, m_paddingMode(other.m_paddingMode)
#ifdef _WIN32
				, m_algHandle(other.m_algHandle)
				, m_keyHandle(other.m_keyHandle)
				, m_keyObject(std::move(other.m_keyObject))
#endif
				, m_key(std::move(other.m_key))
				, m_iv(std::move(other.m_iv))
				, m_keySet(other.m_keySet)
				, m_ivSet(other.m_ivSet)
			{
				// Clear source handles to prevent double-close
#ifdef _WIN32
				other.m_algHandle = nullptr;
				other.m_keyHandle = nullptr;
#endif
				other.m_keySet = false;
				other.m_ivSet = false;
				other.m_streamFinalized = false;
			}

			SymmetricCipher& SymmetricCipher::operator=(SymmetricCipher&& other) noexcept {
				if (this != &other) {
					// Clean up current resources first
					cleanup();

					// Move state from source
					m_streamBuffer = std::move(other.m_streamBuffer);
					m_streamFinalized = other.m_streamFinalized;
					m_algorithm = other.m_algorithm;
					m_paddingMode = other.m_paddingMode;

#ifdef _WIN32
					m_algHandle = other.m_algHandle;
					m_keyHandle = other.m_keyHandle;
					m_keyObject = std::move(other.m_keyObject);
					other.m_algHandle = nullptr;
					other.m_keyHandle = nullptr;
#endif

					m_key = std::move(other.m_key);
					m_iv = std::move(other.m_iv);
					m_keySet = other.m_keySet;
					m_ivSet = other.m_ivSet;

					// Clear source state
					other.m_keySet = false;
					other.m_ivSet = false;
					other.m_streamFinalized = false;
				}
				return *this;
			}

			void SymmetricCipher::cleanup() noexcept {
#ifdef _WIN32
				// Destroy key handle first (depends on algorithm handle)
				if (m_keyHandle != nullptr) {
					BCryptDestroyKey(m_keyHandle);
					m_keyHandle = nullptr;
				}

				// Close algorithm provider
				if (m_algHandle != nullptr) {
					BCryptCloseAlgorithmProvider(m_algHandle, 0);
					m_algHandle = nullptr;
				}

				// Secure wipe key object buffer
				if (!m_keyObject.empty()) {
					SecureZeroMemory(m_keyObject.data(), m_keyObject.size());
					m_keyObject.clear();
				}
#endif

				// Secure wipe key material
				if (!m_key.empty()) {
					SecureZeroMemory(m_key.data(), m_key.size());
					m_key.clear();
				}

				// Secure wipe IV
				if (!m_iv.empty()) {
					SecureZeroMemory(m_iv.data(), m_iv.size());
					m_iv.clear();
				}

				// Secure wipe stream buffer
				if (!m_streamBuffer.empty()) {
					SecureZeroMemory(m_streamBuffer.data(), m_streamBuffer.size());
					m_streamBuffer.clear();
				}

				// Reset state flags
				m_keySet = false;
				m_ivSet = false;
				m_streamFinalized = false;
			}

			bool SymmetricCipher::ensureProvider(Error* err) noexcept {
#ifdef _WIN32
				// Already initialized - return success
				if (m_algHandle != nullptr) {
					return true;
				}

				// Get algorithm name for this cipher
				const wchar_t* algName = AlgName(m_algorithm);
				if (algName == nullptr || algName[0] == L'\0') {
					if (err != nullptr) {
						err->SetWin32Error(ERROR_INVALID_PARAMETER,
							L"Invalid symmetric algorithm",
							L"ensureProvider");
					}

					wchar_t debugMsg[256];
					swprintf_s(debugMsg, _countof(debugMsg),
						L"ensureProvider: invalid algorithm enum: %d",
						static_cast<int>(m_algorithm));
					SafeLogError(debugMsg);

					return false;
				}

				// Open algorithm provider
				BCRYPT_ALG_HANDLE handle = nullptr;
				NTSTATUS st = BCryptOpenAlgorithmProvider(
					&handle,
					algName,
					nullptr,
					0
				);

				if (!BCRYPT_SUCCESS(st) || handle == nullptr) {
					if (err != nullptr) {
						err->SetNtStatus(st,
							L"BCryptOpenAlgorithmProvider failed",
							L"ensureProvider");
					}

					wchar_t debugMsg[512];
					swprintf_s(debugMsg, _countof(debugMsg),
						L"BCryptOpenAlgorithmProvider failed: Algorithm=%s, NTSTATUS=0x%08X",
						algName, static_cast<unsigned>(st));
					SafeLogError(debugMsg);

					// Ensure handle is null on failure
					m_algHandle = nullptr;
					return false;
				}

				m_algHandle = handle;

				// Set chaining mode if applicable
				const wchar_t* chainMode = ChainingMode(m_algorithm);
				if (chainMode != nullptr) {
					const size_t chainModeLen = wcslen(chainMode);

					// Validate string length to prevent overflow
					if (chainModeLen > 0 && chainModeLen < 256) {
						st = BCryptSetProperty(
							m_algHandle,
							BCRYPT_CHAINING_MODE,
							reinterpret_cast<PBYTE>(const_cast<wchar_t*>(chainMode)),
							static_cast<ULONG>((chainModeLen + 1) * sizeof(wchar_t)),
							0
						);

						if (!BCRYPT_SUCCESS(st)) {
							if (err != nullptr) {
								err->SetNtStatus(st,
									L"BCryptSetProperty for chaining mode failed",
									L"ensureProvider");
							}

							wchar_t debugMsg[256];
							swprintf_s(debugMsg, _countof(debugMsg),
								L"BCryptSetProperty failed for mode %s: 0x%08X",
								chainMode, static_cast<unsigned>(st));
							SafeLogError(debugMsg);

							// Cleanup on failure
							BCryptCloseAlgorithmProvider(m_algHandle, 0);
							m_algHandle = nullptr;
							return false;
						}
					}
				}

				// Log successful initialization
				wchar_t infoMsg[256];
				swprintf_s(infoMsg, _countof(infoMsg),
					L"Algorithm provider opened: %s (handle: %p)",
					algName, static_cast<void*>(m_algHandle));
				SafeLogInfo(infoMsg);

				return true;
#else
				if (err != nullptr) {
					err->SetWin32Error(ERROR_NOT_SUPPORTED,
						L"Platform not supported",
						L"ensureProvider");
				}
				return false;
#endif
			}

			bool SymmetricCipher::SetKey(const uint8_t* key, size_t keyLen, Error* err) noexcept {
				// Input validation
				if (key == nullptr || keyLen == 0) {
					if (err != nullptr) {
						err->SetWin32Error(ERROR_INVALID_PARAMETER,
							L"Invalid key pointer or length",
							L"SetKey");
					}
					return false;
				}

				// Validate key size matches algorithm requirements
				const size_t expectedSize = GetKeySize();
				if (expectedSize == 0) {
					if (err != nullptr) {
						err->SetWin32Error(ERROR_INVALID_PARAMETER,
							L"Unknown algorithm - cannot determine key size",
							L"SetKey");
					}
					return false;
				}

				if (keyLen != expectedSize) {
					if (err != nullptr) {
						err->SetWin32Error(ERROR_INVALID_PARAMETER,
							L"Invalid key size for algorithm",
							L"SetKey");
					}
					return false;
				}

				// Ensure provider is initialized
				if (!ensureProvider(err)) {
					return false;
				}

#ifdef _WIN32
				// Destroy existing key if any
				if (m_keyHandle != nullptr) {
					BCryptDestroyKey(m_keyHandle);
					m_keyHandle = nullptr;
				}

				// Securely store key copy
				try {
					m_key.assign(key, key + keyLen);
				}
				catch (const std::exception&) {
					if (err != nullptr) {
						err->SetWin32Error(ERROR_NOT_ENOUGH_MEMORY,
							L"Failed to allocate key storage",
							L"SetKey");
					}
					return false;
				}

				// Get required key object size
				DWORD objLen = 0;
				DWORD cbResult = 0;
				NTSTATUS st = BCryptGetProperty(
					m_algHandle,
					BCRYPT_OBJECT_LENGTH,
					reinterpret_cast<PUCHAR>(&objLen),
					sizeof(objLen),
					&cbResult,
					0
				);

				if (!BCRYPT_SUCCESS(st)) {
					if (err != nullptr) {
						err->SetNtStatus(st,
							L"BCryptGetProperty OBJECT_LENGTH failed",
							L"SetKey");
					}
					SecureZeroMemory(m_key.data(), m_key.size());
					m_key.clear();
					return false;
				}

				// Allocate key object buffer
				try {
					m_keyObject.resize(objLen);
				}
				catch (const std::exception&) {
					if (err != nullptr) {
						err->SetWin32Error(ERROR_NOT_ENOUGH_MEMORY,
							L"Failed to allocate key object buffer",
							L"SetKey");
					}
					SecureZeroMemory(m_key.data(), m_key.size());
					m_key.clear();
					return false;
				}

				// Generate symmetric key from key material
				st = BCryptGenerateSymmetricKey(
					m_algHandle,
					&m_keyHandle,
					m_keyObject.data(),
					static_cast<ULONG>(m_keyObject.size()),
					const_cast<uint8_t*>(m_key.data()),
					static_cast<ULONG>(m_key.size()),
					0
				);

				if (!BCRYPT_SUCCESS(st)) {
					if (err != nullptr) {
						err->SetNtStatus(st,
							L"BCryptGenerateSymmetricKey failed",
							L"SetKey");
					}

					wchar_t debugMsg[256];
					swprintf_s(debugMsg, _countof(debugMsg),
						L"BCryptGenerateSymmetricKey failed: 0x%08X",
						static_cast<unsigned>(st));
					SafeLogError(debugMsg);

					// Cleanup on failure
					SecureZeroMemory(m_key.data(), m_key.size());
					m_key.clear();
					SecureZeroMemory(m_keyObject.data(), m_keyObject.size());
					m_keyObject.clear();
					m_keyHandle = nullptr;
					return false;
				}

				m_keySet = true;
				return true;
#else
				if (err != nullptr) {
					err->SetWin32Error(ERROR_NOT_SUPPORTED,
						L"Platform not supported",
						L"SetKey");
				}
				return false;
#endif
			}

			bool SymmetricCipher::SetKey(const std::vector<uint8_t>& key, Error* err) noexcept {
				if (key.empty()) {
					if (err != nullptr) {
						err->SetWin32Error(ERROR_INVALID_PARAMETER,
							L"Empty key vector",
							L"SetKey");
					}
					return false;
				}
				return SetKey(key.data(), key.size(), err);
			}

			bool SymmetricCipher::GenerateKey(std::vector<uint8_t>& outKey, Error* err) noexcept {
				const size_t keySize = GetKeySize();
				if (keySize == 0) {
					if (err != nullptr) {
						err->SetWin32Error(ERROR_INVALID_PARAMETER,
							L"Unknown algorithm - cannot determine key size",
							L"GenerateKey");
					}
					return false;
				}

				// Generate random key
				SecureRandom rng;
				if (!rng.Generate(outKey, keySize, err)) {
					return false;
				}

				// Set the generated key
				if (!SetKey(outKey, err)) {
					SecureZeroMemory(outKey.data(), outKey.size());
					outKey.clear();
					return false;
				}

				return true;
			}

			bool SymmetricCipher::SetIV(const uint8_t* iv, size_t ivLen, Error* err) noexcept {
				const size_t expectedSize = GetIVSize();

				// Some algorithms don't need an IV
				if (expectedSize == 0) {
					m_iv.clear();
					m_ivSet = true;
					return true;
				}

				// Validate IV pointer
				if (iv == nullptr) {
					if (err != nullptr) {
						err->SetWin32Error(ERROR_INVALID_PARAMETER,
							L"IV pointer is null",
							L"SetIV");
					}
					return false;
				}

				// Validate IV size
				if (ivLen != expectedSize) {
					if (err != nullptr) {
						err->SetWin32Error(ERROR_INVALID_PARAMETER,
							L"Invalid IV size for algorithm",
							L"SetIV");
					}
					return false;
				}

				try {
					m_iv.assign(iv, iv + ivLen);
				}
				catch (const std::exception&) {
					if (err != nullptr) {
						err->SetWin32Error(ERROR_NOT_ENOUGH_MEMORY,
							L"Failed to allocate IV storage",
							L"SetIV");
					}
					return false;
				}

				m_ivSet = true;
				return true;
			}

			bool SymmetricCipher::SetIV(const std::vector<uint8_t>& iv, Error* err) noexcept {
				const size_t expectedSize = GetIVSize();

				// Some algorithms don't need an IV
				if (expectedSize == 0) {
					m_iv.clear();
					m_ivSet = true;
					return true;
				}

				if (iv.empty()) {
					if (err != nullptr) {
						err->SetWin32Error(ERROR_INVALID_PARAMETER,
							L"Empty IV vector",
							L"SetIV");
					}
					return false;
				}

				return SetIV(iv.data(), iv.size(), err);
			}

			bool SymmetricCipher::GenerateIV(std::vector<uint8_t>& outIV, Error* err) noexcept {
				const size_t ivSize = GetIVSize();

				// Some algorithms don't need an IV
				if (ivSize == 0) {
					outIV.clear();
					m_iv.clear();
					m_ivSet = true;
					return true;
				}

				// Generate random IV
				SecureRandom rng;
				if (!rng.Generate(outIV, ivSize, err)) {
					return false;
				}

				// Set the generated IV
				if (!SetIV(outIV, err)) {
					SecureZeroMemory(outIV.data(), outIV.size());
					outIV.clear();
					return false;
				}

				return true;
			}

			// =============================================================================
			// SymmetricCipher Property Accessors
			// =============================================================================

			size_t SymmetricCipher::GetKeySize() const noexcept {
				return KeySizeForAlg(m_algorithm);
			}

			size_t SymmetricCipher::GetIVSize() const noexcept {
				return IVSizeForAlg(m_algorithm);
			}

			size_t SymmetricCipher::GetBlockSize() const noexcept {
				// All supported algorithms use 16-byte (128-bit) blocks
				return AES_BLOCK_SIZE_BYTES;
			}

			size_t SymmetricCipher::GetTagSize() const noexcept {
				// AEAD modes use 16-byte (128-bit) authentication tags
				return IsAEAD() ? GCM_TAG_SIZE_BYTES : 0ULL;
			}

			bool SymmetricCipher::IsAEAD() const noexcept {
				return IsAEADAlg(m_algorithm);
			}

			// =============================================================================
			// SymmetricCipher Encrypt/Decrypt Implementation
			// =============================================================================

			bool SymmetricCipher::Encrypt(const uint8_t* plaintext, size_t plaintextLen,
				std::vector<uint8_t>& ciphertext, Error* err) noexcept
			{
				// Clear output buffer first
				ciphertext.clear();

				// ═══════════════════════════════════════════════════════════════════
				//  TIER-1 INPUT VALIDATION
				// ═══════════════════════════════════════════════════════════════════
				if (!m_keySet) {
					if (err != nullptr) {
						err->SetWin32Error(ERROR_INVALID_STATE,
							L"Key not set",
							L"Encrypt");
					}
					return false;
				}

				if (!m_ivSet && GetIVSize() > 0) {
					if (err != nullptr) {
						err->SetWin32Error(ERROR_INVALID_STATE,
							L"IV not set",
							L"Encrypt");
					}
					return false;
				}

				if (plaintext == nullptr && plaintextLen != 0) {
					if (err != nullptr) {
						err->SetWin32Error(ERROR_INVALID_PARAMETER,
							L"Invalid plaintext pointer",
							L"Encrypt");
					}
					return false;
				}

				if (IsAEAD()) {
					if (err != nullptr) {
						err->SetWin32Error(ERROR_INVALID_PARAMETER,
							L"Use EncryptAEAD for AEAD modes",
							L"Encrypt");
					}
					return false;
				}

				// Size limit validation
				if (plaintextLen > MAX_PLAINTEXT_SIZE) {
					if (err != nullptr) {
						err->SetWin32Error(ERROR_BUFFER_OVERFLOW,
							L"Plaintext exceeds maximum size limit",
							L"Encrypt");
					}
					return false;
				}

				// Handle empty plaintext
				if (plaintextLen == 0) {
					ciphertext.clear();
					return true;
				}

#ifdef _WIN32
				// ═══════════════════════════════════════════════════════════════════
				//  ALGORITHM CLASSIFICATION
				// ═══════════════════════════════════════════════════════════════════
				const bool isCBC = (m_algorithm == SymmetricAlgorithm::AES_128_CBC ||
					m_algorithm == SymmetricAlgorithm::AES_192_CBC ||
					m_algorithm == SymmetricAlgorithm::AES_256_CBC);

				const bool needsPadding = isCBC;
				const size_t blockSize = GetBlockSize();

				// Validate block size
				if (blockSize == 0) {
					if (err != nullptr) {
						err->SetWin32Error(ERROR_INVALID_PARAMETER,
							L"Invalid block size for algorithm",
							L"Encrypt");
					}
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  PADDING STRATEGY (Manual PKCS7 - Industry Standard)
				// ═══════════════════════════════════════════════════════════════════
				if (plaintextLen > static_cast<size_t>(ULONG_MAX)) {
					if (err != nullptr) {
						err->SetWin32Error(ERROR_BUFFER_OVERFLOW,
							L"Plaintext too large for Windows CNG API",
							L"Encrypt");
					}
					return false;
				}

				std::vector<uint8_t> plaintextWithPadding;
				const uint8_t* effectivePlaintext = plaintext;
				size_t effectiveLen = plaintextLen;

				if (needsPadding && m_paddingMode == PaddingMode::PKCS7) {
					// Apply PKCS7 padding manually
					try {
						plaintextWithPadding.assign(plaintext, plaintext + plaintextLen);
					}
					catch (const std::exception&) {
						if (err != nullptr) {
							err->SetWin32Error(ERROR_NOT_ENOUGH_MEMORY,
								L"Failed to allocate padding buffer",
								L"Encrypt");
						}
						return false;
					}

					if (!applyPadding(plaintextWithPadding, blockSize)) {
						if (err != nullptr) {
							err->SetWin32Error(ERROR_INVALID_DATA,
								L"PKCS7 padding failed",
								L"Encrypt");
						}
						SecureZeroMemory(plaintextWithPadding.data(), plaintextWithPadding.size());
						return false;
					}

					effectivePlaintext = plaintextWithPadding.data();
					effectiveLen = plaintextWithPadding.size();
				}
				else if (needsPadding && m_paddingMode == PaddingMode::None) {
					// No padding - must be block-aligned
					if (plaintextLen % blockSize != 0) {
						if (err != nullptr) {
							err->SetWin32Error(ERROR_INVALID_DATA,
								L"Plaintext must be block-aligned when padding is disabled",
								L"Encrypt");
						}
						return false;
					}
				}

				// ═══════════════════════════════════════════════════════════════════
				//  IV LOCAL COPY (Prevent IV reuse attacks)
				// ═══════════════════════════════════════════════════════════════════
				std::vector<uint8_t> ivLocal;
				try {
					ivLocal = m_iv;
				}
				catch (const std::exception&) {
					SecureZeroMemory(plaintextWithPadding.data(), plaintextWithPadding.size());
					if (err != nullptr) {
						err->SetWin32Error(ERROR_NOT_ENOUGH_MEMORY,
							L"Failed to allocate IV buffer",
							L"Encrypt");
					}
					return false;
				}

				PUCHAR ivPtr = ivLocal.empty() ? nullptr : ivLocal.data();
				ULONG ivLen = static_cast<ULONG>(ivLocal.size());

				// ═══════════════════════════════════════════════════════════════════
				//  BCRYPT ENCRYPTION (NO PADDING FLAG)
				// ═══════════════════════════════════════════════════════════════════
				constexpr DWORD flags = 0;  // We handle padding ourselves

				// Query encrypted size
				ULONG cbResult = 0;
				NTSTATUS st = BCryptEncrypt(
					m_keyHandle,
					const_cast<uint8_t*>(effectivePlaintext),
					static_cast<ULONG>(effectiveLen),
					nullptr,
					ivPtr,
					ivLen,
					nullptr,
					0,
					&cbResult,
					flags
				);

				if (!BCRYPT_SUCCESS(st)) {
					if (err != nullptr) {
						err->SetNtStatus(st,
							L"BCryptEncrypt size query failed",
							L"Encrypt");
					}
					SecureZeroMemory(plaintextWithPadding.data(), plaintextWithPadding.size());
					return false;
				}

				// Allocate output buffer
				try {
					ciphertext.resize(cbResult);
				}
				catch (const std::exception&) {
					SecureZeroMemory(plaintextWithPadding.data(), plaintextWithPadding.size());
					if (err != nullptr) {
						err->SetWin32Error(ERROR_NOT_ENOUGH_MEMORY,
							L"Failed to allocate ciphertext buffer",
							L"Encrypt");
					}
					return false;
				}

				// Perform encryption
				st = BCryptEncrypt(
					m_keyHandle,
					const_cast<uint8_t*>(effectivePlaintext),
					static_cast<ULONG>(effectiveLen),
					nullptr,
					ivPtr,
					ivLen,
					ciphertext.data(),
					static_cast<ULONG>(ciphertext.size()),
					&cbResult,
					flags
				);

				// Secure cleanup of padded plaintext
				SecureZeroMemory(plaintextWithPadding.data(), plaintextWithPadding.size());

				if (!BCRYPT_SUCCESS(st)) {
					if (err != nullptr) {
						err->SetNtStatus(st,
							L"BCryptEncrypt failed",
							L"Encrypt");
					}
					SecureZeroMemory(ciphertext.data(), ciphertext.size());
					ciphertext.clear();
					return false;
				}

				ciphertext.resize(cbResult);

				// ═══════════════════════════════════════════════════════════════════
				//  IV CHAINING (CBC mode - for continuous streaming)
				// ═══════════════════════════════════════════════════════════════════
				if (isCBC && ivPtr != nullptr && ivLen > 0) {
					if (ciphertext.size() >= ivLen) {
						// Use last ciphertext block as next IV for chaining
						std::memcpy(m_iv.data(),
							ciphertext.data() + ciphertext.size() - ivLen,
							ivLen);
					}
				}

				return true;
#else
				if (err != nullptr) {
					err->SetWin32Error(ERROR_NOT_SUPPORTED,
						L"Platform not supported",
						L"Encrypt");
				}
				return false;
#endif
			}

			bool SymmetricCipher::Decrypt(const uint8_t* ciphertext, size_t ciphertextLen,
				std::vector<uint8_t>& plaintext, Error* err) noexcept
			{
				// ═══════════════════════════════════════════════════════════════════
				//  TIER-1 INPUT VALIDATION
				// ═══════════════════════════════════════════════════════════════════
				if (!m_keySet) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Key not set"; }
					return false;
				}
				if (!m_ivSet && GetIVSize() > 0) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"IV not set"; }
					return false;
				}
				if (!ciphertext && ciphertextLen != 0) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid ciphertext pointer"; }
					return false;
				}
				if (IsAEAD()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Use DecryptAEAD for AEAD modes"; }
					return false;
				}

#ifdef _WIN32
				// ═══════════════════════════════════════════════════════════════════
				//  ALGORITHM CLASSIFICATION
				// ═══════════════════════════════════════════════════════════════════
				const bool isCBC = (m_algorithm == SymmetricAlgorithm::AES_128_CBC ||
					m_algorithm == SymmetricAlgorithm::AES_192_CBC ||
					m_algorithm == SymmetricAlgorithm::AES_256_CBC);

				const bool needsPadding = isCBC;
				const size_t blockSize = GetBlockSize();

				//  Block alignment validation
				if (needsPadding && (ciphertextLen % blockSize != 0)) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Ciphertext not block-aligned"; }
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  IV MUTATION PROTECTION
				// ═══════════════════════════════════════════════════════════════════
				std::vector<uint8_t> ivLocal = m_iv;
				PUCHAR ivPtr = ivLocal.empty() ? nullptr : ivLocal.data();
				ULONG ivLen = static_cast<ULONG>(ivLocal.size());

				// ═══════════════════════════════════════════════════════════════════
				//  BCRYPT DECRYPTION (NO PADDING FLAG)
				// ═══════════════════════════════════════════════════════════════════
				DWORD flags = 0; //  CRITICAL: We handle padding removal ourselves

				if (ciphertextLen > std::numeric_limits<ULONG>::max()) {
					if (err) {
						err->win32 = ERROR_BUFFER_OVERFLOW;
						err->message = L"Ciphertext too large for Windows CNG API";
					}
					return false;
				}
				// Query decrypted size
				ULONG cbResult = 0;
				NTSTATUS st = BCryptDecrypt(m_keyHandle,
					const_cast<uint8_t*>(ciphertext), static_cast<ULONG>(ciphertextLen),
					nullptr,
					ivPtr, ivLen,
					nullptr, 0, &cbResult, flags);

				if (st < 0) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"BCryptDecrypt size query failed";
					}
					return false;
				}

				// Allocate output buffer
				plaintext.resize(cbResult);

				// Perform decryption
				st = BCryptDecrypt(m_keyHandle,
					const_cast<uint8_t*>(ciphertext), static_cast<ULONG>(ciphertextLen),
					nullptr,
					ivPtr, ivLen,
					plaintext.data(), static_cast<ULONG>(plaintext.size()), &cbResult, flags);

				if (st < 0) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"BCryptDecrypt failed";
					}
					SecureZeroMemory(plaintext.data(), plaintext.size());
					return false;
				}

				plaintext.resize(cbResult);

				// ═══════════════════════════════════════════════════════════════════
				//  MANUAL PADDING REMOVAL (Constant-time validation)
				// ═══════════════════════════════════════════════════════════════════
				if (needsPadding && m_paddingMode == PaddingMode::PKCS7) {
					const size_t originalSize = plaintext.size();

					if (!removePadding(plaintext, blockSize)) {
						//  SECURITY: Zero memory before reporting error
						SecureZeroMemory(plaintext.data(), originalSize);
						plaintext.clear();

						if (err) {
							err->win32 = ERROR_INVALID_DATA;
							err->message = L"Decrypt Failed";
						}
						return false;
					}
				}

				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}


			bool SymmetricCipher::EncryptAEAD(const uint8_t* plaintext, size_t plaintextLen,
				const uint8_t* aad, size_t aadLen,
				std::vector<uint8_t>& ciphertext,
				std::vector<uint8_t>& tag, Error* err) noexcept
			{
				if (aadLen > 0 && !aad) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"AAD pointer invalid"; }
					return false;
				}
				if (!IsAEAD()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Not an AEAD algorithm"; }
					return false;
				}

				if (!m_keySet || !m_ivSet) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Key or IV not set"; }
					return false;
				}

				if (plaintextLen > std::numeric_limits<ULONG>::max()) {
					if (err) {
						err->win32 = ERROR_BUFFER_OVERFLOW;
						err->message = L"Plaintext too large for Windows CNG API";
					}
					return false;
				}

				if (aadLen > std::numeric_limits<ULONG>::max()) {
					if (err) {
						err->win32 = ERROR_BUFFER_OVERFLOW;
						err->message = L"AAD too large for Windows CNG API";
					}
					return false;
				}

#ifdef _WIN32
				// ═══════════════════════════════════════════════════════════════════
				//  IV MUTATION PROTECTION - Create local copy
				// ═══════════════════════════════════════════════════════════════════
				std::vector<uint8_t> ivLocal = m_iv;

				// ═══════════════════════════════════════════════════════════════════
				//  BCRYPT AUTHENTICATED CIPHER MODE INFO SETUP
				// ═══════════════════════════════════════════════════════════════════
				BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
				BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
				authInfo.pbNonce = ivLocal.data();
				authInfo.cbNonce = static_cast<ULONG>(ivLocal.size());
				authInfo.pbAuthData = const_cast<uint8_t*>(aad);
				authInfo.cbAuthData = static_cast<ULONG>(aadLen);

				// Allocate tag buffer
				const size_t tagSize = GetTagSize();
				tag.resize(tagSize);
				authInfo.pbTag = tag.data();
				authInfo.cbTag = static_cast<ULONG>(tagSize);
				authInfo.pbMacContext = nullptr;
				authInfo.cbMacContext = 0;
				authInfo.cbAAD = static_cast<ULONG>(aadLen);
				authInfo.cbData = static_cast<ULONG>(plaintextLen);
				authInfo.dwFlags = 0;

				// ═══════════════════════════════════════════════════════════════════
				//  BCRYPT AEAD ENCRYPTION
				// ═══════════════════════════════════════════════════════════════════
				ULONG cbResult = 0;

				NTSTATUS st = BCryptEncrypt(m_keyHandle,
					const_cast<uint8_t*>(plaintext), static_cast<ULONG>(plaintextLen),
					&authInfo,
					nullptr, 0,
					nullptr, 0, &cbResult, 0);
				if (st < 0) {
					// SECURITY: Clear tag on failure
					SecureZeroMemory(tag.data(), tag.size());
					tag.clear();
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptEncrypt AEAD size query failed"; }
					return false;
				}

				ciphertext.resize(cbResult);
				st = BCryptEncrypt(m_keyHandle,
					const_cast<uint8_t*>(plaintext), static_cast<ULONG>(plaintextLen),
					&authInfo,
					nullptr, 0,
					ciphertext.data(), static_cast<ULONG>(ciphertext.size()), &cbResult, 0);
				if (st < 0) {
					// SECURITY: Clear both ciphertext and tag on failure
					SecureZeroMemory(ciphertext.data(), ciphertext.size());
					SecureZeroMemory(tag.data(), tag.size());
					ciphertext.clear();
					tag.clear();
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptEncrypt AEAD failed"; }
					return false;
				}

				ciphertext.resize(cbResult);
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool SymmetricCipher::DecryptAEAD(const uint8_t* ciphertext, size_t ciphertextLen,
				const uint8_t* aad, size_t aadLen,
				const uint8_t* tag, size_t tagLen,
				std::vector<uint8_t>& plaintext, Error* err) noexcept
			{
				if (aadLen > 0 && !aad) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"AAD pointer invalid"; }
					return false;
				}
				if (!IsAEAD()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Not an AEAD algorithm"; }
					return false;
				}

				if (!m_keySet || !m_ivSet) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Key or IV not set"; }
					return false;
				}

				if (tagLen != GetTagSize()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid tag size"; }
					return false;
				}

				if (ciphertextLen > std::numeric_limits<ULONG>::max()) {
					if (err) {
						err->win32 = ERROR_BUFFER_OVERFLOW;
						err->message = L"Ciphertext is too large for Windows CNG API";
					}
					return false;
				}

				if (aadLen > std::numeric_limits<ULONG>::max()) {
					if (err) {
						err->win32 = ERROR_BUFFER_OVERFLOW;
						err->message = L"AAD too large for Windows CNG API";
					}
					return false;
				}

#ifdef _WIN32
				std::vector<uint8_t> ivLocal = m_iv;

				BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
				BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
				authInfo.pbNonce = ivLocal.data();
				authInfo.cbNonce = static_cast<ULONG>(m_iv.size());
				authInfo.pbAuthData = const_cast<uint8_t*>(aad);
				authInfo.cbAuthData = static_cast<ULONG>(aadLen);
				authInfo.pbTag = const_cast<uint8_t*>(tag);
				authInfo.cbTag = static_cast<ULONG>(tagLen);
				authInfo.pbMacContext = nullptr;
				authInfo.cbMacContext = 0;
				authInfo.cbAAD = static_cast<ULONG>(aadLen);
				authInfo.cbData = static_cast<ULONG>(ciphertextLen);
				authInfo.dwFlags = 0;

				ULONG cbResult = 0;
				NTSTATUS st = BCryptDecrypt(m_keyHandle,
					const_cast<uint8_t*>(ciphertext), static_cast<ULONG>(ciphertextLen),
					&authInfo,
					nullptr, 0,
					nullptr, 0, &cbResult, 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDecrypt AEAD size query failed"; }
					return false;
				}

				plaintext.resize(cbResult);
				st = BCryptDecrypt(m_keyHandle,
					const_cast<uint8_t*>(ciphertext), static_cast<ULONG>(ciphertextLen),
					&authInfo,
					nullptr, 0,
					plaintext.data(), static_cast<ULONG>(plaintext.size()), &cbResult, 0);
				if (st < 0) {
					SecureZeroMemory(plaintext.data(), plaintext.size());
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDecrypt AEAD failed or authentication failed"; }
					return false;
				}

				plaintext.resize(cbResult);
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool SymmetricCipher::EncryptInit(Error* err) noexcept {
				if (!m_keySet) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Key not set"; }
					return false;
				}
				if (!m_ivSet && GetIVSize() > 0) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"IV not set"; }
					return false;
				}

				//clear the internal buffer for streaming
				m_streamBuffer.clear();
				m_streamFinalized = false;

				return true;
			}

			bool SymmetricCipher::EncryptUpdate(const uint8_t* data, size_t len, std::vector<uint8_t>& out, Error* err) noexcept {
				if (!m_keySet) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Key not set"; }
					return false;
				}
				if (m_streamFinalized) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Stream already finalized"; }
					return false;
				}

				out.clear();
				if (len == 0) return true;

				// streaming is not supported for AEAD modes
				if (IsAEAD()) {
					if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"AEAD modes do not support streaming"; }
					return false;
				}

				//Add the new data to the internal buffer
				m_streamBuffer.insert(m_streamBuffer.end(), data, data + len);

				//encrypt the block-aligned data in the buffer
				const size_t blockSize = GetBlockSize();
				const size_t alignedSize = (m_streamBuffer.size() / blockSize) * blockSize;

				if (alignedSize == 0) {
					// there is not enough data to process a full block yet
					return true;
				}

#ifdef _WIN32
				// ═══════════════════════════════════════════════════════════════════
				//  EXTRACT BLOCK-ALIGNED DATA FOR ENCRYPTION
				// ═══════════════════════════════════════════════════════════════════
				std::vector<uint8_t> toEncrypt(m_streamBuffer.begin(), m_streamBuffer.begin() + alignedSize);

				// Validate sizes for ULONG conversion
				if (toEncrypt.size() > static_cast<size_t>(std::numeric_limits<ULONG>::max())) {
					SecureZeroMemory(toEncrypt.data(), toEncrypt.size());
					if (err) { err->win32 = ERROR_ARITHMETIC_OVERFLOW; err->message = L"Data too large for ULONG"; }
					return false;
				}

				ULONG cbResult = 0;
				NTSTATUS st = BCryptEncrypt(m_keyHandle,
					toEncrypt.data(), static_cast<ULONG>(toEncrypt.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					nullptr, 0, &cbResult, 0);
				if (st < 0) {
					// SECURITY: Clear temporary buffer on failure
					SecureZeroMemory(toEncrypt.data(), toEncrypt.size());
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptEncrypt size query failed"; }
					return false;
				}

				out.resize(cbResult);
				st = BCryptEncrypt(m_keyHandle,
					toEncrypt.data(), static_cast<ULONG>(toEncrypt.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					out.data(), static_cast<ULONG>(out.size()), &cbResult, 0);
				if (st < 0) {
					// SECURITY: Clear both buffers on failure
					SecureZeroMemory(toEncrypt.data(), toEncrypt.size());
					SecureZeroMemory(out.data(), out.size());
					out.clear();
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptEncrypt failed"; }
					return false;
				}

				out.resize(cbResult);

				// update IV for modes that require it (CBC, CFB, OFB)
				if (!out.empty() && m_iv.size() == blockSize) {
					std::memcpy(m_iv.data(), out.data() + out.size() - blockSize, blockSize);
				}

				// SECURITY: Securely clear temporary buffer after use
				SecureZeroMemory(toEncrypt.data(), toEncrypt.size());
				m_streamBuffer.erase(m_streamBuffer.begin(), m_streamBuffer.begin() + alignedSize);
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool SymmetricCipher::EncryptFinal(std::vector<uint8_t>& out, Error* err) noexcept {
				if (!m_keySet) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Key not set"; }
					return false;
				}
				if (m_streamFinalized) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Stream already finalized"; }
					return false;
				}

				out.clear();

				if (IsAEAD()) {
					if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"AEAD modes do not support streaming"; }
					return false;
				}

#ifdef _WIN32
				// Empty buffer handling (no logger spam)
				if (m_streamBuffer.empty()) {
					m_streamFinalized = true;
					return true;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  APPLY MANUAL PADDING (PKCS7)
				// ═══════════════════════════════════════════════════════════════════
				if (m_paddingMode == PaddingMode::PKCS7) {
					if (!applyPadding(m_streamBuffer, GetBlockSize())) {
						// SECURITY: Clear stream buffer on failure
						SecureZeroMemory(m_streamBuffer.data(), m_streamBuffer.size());
						m_streamBuffer.clear();
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Padding failed"; }
						return false;
					}
				}

				// Validate size for ULONG conversion
				if (m_streamBuffer.size() > static_cast<size_t>(std::numeric_limits<ULONG>::max())) {
					SecureZeroMemory(m_streamBuffer.data(), m_streamBuffer.size());
					m_streamBuffer.clear();
					if (err) { err->win32 = ERROR_ARITHMETIC_OVERFLOW; err->message = L"Data too large for ULONG"; }
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  ENCRYPT FINAL BLOCK (flags=0, BCrypt won't add padding)
				// ═══════════════════════════════════════════════════════════════════
				ULONG cbResult = 0;
				NTSTATUS st = BCryptEncrypt(
					m_keyHandle,
					m_streamBuffer.data(), static_cast<ULONG>(m_streamBuffer.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					nullptr, 0, &cbResult, 0);

				if (st < 0) {
					// SECURITY: Clear stream buffer on failure
					SecureZeroMemory(m_streamBuffer.data(), m_streamBuffer.size());
					m_streamBuffer.clear();
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"EncryptFinal failed"; }
					return false;
				}

				out.resize(cbResult);
				st = BCryptEncrypt(
					m_keyHandle,
					m_streamBuffer.data(), static_cast<ULONG>(m_streamBuffer.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					out.data(), static_cast<ULONG>(out.size()), &cbResult, 0);

				if (st < 0) {
					// SECURITY: Clear both buffers on failure
					SecureZeroMemory(out.data(), out.size());
					SecureZeroMemory(m_streamBuffer.data(), m_streamBuffer.size());
					out.clear();
					m_streamBuffer.clear();
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"EncryptFinal failed"; }
					return false;
				}

				out.resize(cbResult);

				// SECURITY: Securely clear stream buffer before clearing
				SecureZeroMemory(m_streamBuffer.data(), m_streamBuffer.size());
				m_streamBuffer.clear();
				m_streamFinalized = true;
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool SymmetricCipher::DecryptInit(Error* err) noexcept {
				if (!m_keySet) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Key not set"; }
					return false;
				}
				if (!m_ivSet && GetIVSize() > 0) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"IV not set"; }
					return false;
				}

				m_streamBuffer.clear();
				m_streamFinalized = false;

				return true;
			}

			bool SymmetricCipher::DecryptUpdate(const uint8_t* data, size_t len, std::vector<uint8_t>& out, Error* err) noexcept {
				if (!m_keySet) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"DecryptInit not called"; }
					return false;
				}
				if (m_streamFinalized) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Stream already finalized"; }
					return false;
				}

				out.clear();
				if (len == 0) return true;

				if (IsAEAD()) {
					if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"AEAD modes do not support streaming"; }
					return false;
				}

				//overflow guard
				if (len > SIZE_MAX - m_streamBuffer.size()) {
					if (err) { err->win32 = ERROR_ARITHMETIC_OVERFLOW; err->message = L"Buffer overflow risk"; }
					return false;
				}

				m_streamBuffer.insert(m_streamBuffer.end(), data, data + len);

				const size_t blockSize = GetBlockSize();

				//blocksize validation
				if (blockSize == 0) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid block size"; }
					return false;
				}
				//overflow guard for blocksize
				if (m_streamBuffer.size() / blockSize > SIZE_MAX / blockSize) {
					if (err) { err->win32 = ERROR_ARITHMETIC_OVERFLOW; err->message = L"Block size overflow"; }
					return false;
				}
				const size_t alignedSize = (m_streamBuffer.size() / blockSize) * blockSize;

				// hold the last block for padding
				const size_t keepSize = (m_paddingMode != PaddingMode::None && alignedSize > 0) ? blockSize : 0;
				const size_t processSize = (alignedSize > keepSize) ? (alignedSize - keepSize) : 0;

				if (processSize == 0) {
					return true;
				}

#ifdef _WIN32
				if (processSize > static_cast<size_t>(std::numeric_limits<ULONG>::max())) {
					if (err) { err->win32 = ERROR_ARITHMETIC_OVERFLOW; err->message = L"processSize too large for ULONG"; }
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  EXTRACT DATA FOR DECRYPTION
				// ═══════════════════════════════════════════════════════════════════
				std::vector<uint8_t> toDecrypt(m_streamBuffer.begin(), m_streamBuffer.begin() + processSize);

				// Validate sizes for ULONG conversion
				if (toDecrypt.size() > static_cast<size_t>(std::numeric_limits<ULONG>::max())) {
					SecureZeroMemory(toDecrypt.data(), toDecrypt.size());
					if (err) { err->win32 = ERROR_ARITHMETIC_OVERFLOW; err->message = L"toDecrypt size too large for ULONG"; }
					return false;
				}

				if (m_iv.size() > static_cast<size_t>(std::numeric_limits<ULONG>::max())) {
					SecureZeroMemory(toDecrypt.data(), toDecrypt.size());
					if (err) { err->win32 = ERROR_ARITHMETIC_OVERFLOW; err->message = L"IV size too large for ULONG"; }
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  BCRYPT DECRYPTION
				// ═══════════════════════════════════════════════════════════════════
				ULONG cbResult = 0;
				NTSTATUS st = BCryptDecrypt(m_keyHandle,
					toDecrypt.data(), static_cast<ULONG>(toDecrypt.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					nullptr, 0, &cbResult, 0);
				if (st < 0) {
					// SECURITY: Clear ciphertext copy on failure
					SecureZeroMemory(toDecrypt.data(), toDecrypt.size());
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDecrypt size query failed"; }
					return false;
				}

				out.resize(cbResult);
				st = BCryptDecrypt(m_keyHandle,
					toDecrypt.data(), static_cast<ULONG>(toDecrypt.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					out.data(), static_cast<ULONG>(out.size()), &cbResult, 0);
				if (st < 0) {
					// SECURITY: Clear both buffers on failure
					SecureZeroMemory(toDecrypt.data(), toDecrypt.size());
					SecureZeroMemory(out.data(), out.size());
					out.clear();
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDecrypt failed"; }
					return false;
				}

				out.resize(cbResult);

				// update IV (for CBC mode) - use ciphertext as next IV
				if (!toDecrypt.empty() && m_iv.size() == blockSize) {
					std::memcpy(m_iv.data(), toDecrypt.data() + toDecrypt.size() - blockSize, blockSize);
				}

				// SECURITY: Securely clear ciphertext copy
				SecureZeroMemory(toDecrypt.data(), toDecrypt.size());
				m_streamBuffer.erase(m_streamBuffer.begin(), m_streamBuffer.begin() + processSize);

				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool SymmetricCipher::DecryptFinal(std::vector<uint8_t>& out, Error* err) noexcept {
				if (!m_keySet) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"DecryptInit not called"; }
					return false;
				}
				if (m_streamFinalized) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Stream already finalized"; }
					return false;
				}

				out.clear();

				if (IsAEAD()) {
					if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"AEAD modes do not support streaming"; }
					return false;
				}

#ifdef _WIN32
				// Empty buffer handling
				if (m_streamBuffer.empty()) {
					m_streamFinalized = true;
					return true;
				}

				// Validate size for ULONG conversion
				if (m_streamBuffer.size() > static_cast<size_t>(std::numeric_limits<ULONG>::max())) {
					SecureZeroMemory(m_streamBuffer.data(), m_streamBuffer.size());
					m_streamBuffer.clear();
					if (err) { err->win32 = ERROR_ARITHMETIC_OVERFLOW; err->message = L"Data too large for ULONG"; }
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  DECRYPT FINAL BLOCK (flags=0, no BCrypt padding removal)
				// ═══════════════════════════════════════════════════════════════════
				ULONG cbResult = 0;
				NTSTATUS st = BCryptDecrypt(
					m_keyHandle,
					m_streamBuffer.data(), static_cast<ULONG>(m_streamBuffer.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					nullptr, 0, &cbResult, 0);

				if (st < 0) {
					// SECURITY: Clear stream buffer on failure
					SecureZeroMemory(m_streamBuffer.data(), m_streamBuffer.size());
					m_streamBuffer.clear();
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"DecryptFinal failed"; }
					return false;
				}

				out.resize(cbResult);
				st = BCryptDecrypt(
					m_keyHandle,
					m_streamBuffer.data(), static_cast<ULONG>(m_streamBuffer.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					out.data(), static_cast<ULONG>(out.size()), &cbResult, 0);

				if (st < 0) {
					// SECURITY: Clear both buffers on failure
					SecureZeroMemory(out.data(), out.size());
					SecureZeroMemory(m_streamBuffer.data(), m_streamBuffer.size());
					out.clear();
					m_streamBuffer.clear();
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"DecryptFinal failed"; }
					return false;
				}

				out.resize(cbResult);

				// ═══════════════════════════════════════════════════════════════════
				//  MANUAL PADDING REMOVAL (Constant-time validation)
				// ═══════════════════════════════════════════════════════════════════
				if (m_paddingMode == PaddingMode::PKCS7) {
					const size_t originalSize = out.size();
					if (!removePadding(out, GetBlockSize())) {
						// SECURITY: Clear sensitive data on padding failure
						SecureZeroMemory(out.data(), originalSize);
						SecureZeroMemory(m_streamBuffer.data(), m_streamBuffer.size());
						out.clear();
						m_streamBuffer.clear();
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid padding"; }
						return false;
					}
				}

				// SECURITY: Securely clear stream buffer
				SecureZeroMemory(m_streamBuffer.data(), m_streamBuffer.size());
				m_streamBuffer.clear();
				m_streamFinalized = true;
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool SymmetricCipher::applyPadding(std::vector<uint8_t>& data, size_t blockSize) noexcept {
				if (blockSize == 0 || blockSize > 255) return false;
				if (m_paddingMode != PaddingMode::PKCS7) return false;

				// PKCS7: Always add padding (even if block-aligned)
				const size_t remainder = data.size() % blockSize;
				const size_t padLen = (remainder == 0) ? blockSize : (blockSize - remainder);

				try {
					const uint8_t padByte = static_cast<uint8_t>(padLen);
					data.insert(data.end(), padLen, padByte);
					return true;
				}
				catch (const std::bad_alloc&) {
					return false;
				}
			}
			bool SymmetricCipher::removePadding(std::vector<uint8_t>& data, size_t blockSize) noexcept {
				if (blockSize == 0 || m_paddingMode != PaddingMode::PKCS7) return true;
				if (data.empty()) return false;
				if (data.size() % blockSize != 0) return false;

				const uint8_t padLen = data.back();

				// SECURITY: Validate padding length
				if (padLen == 0 || padLen > blockSize || padLen > data.size()) {
					return false;
				}

				// CONSTANT-TIME VALIDATION (Prevent padding oracle attacks)
				uint8_t diff = 0;
				for (size_t i = data.size() - padLen; i < data.size(); ++i) {
					diff |= (data[i] ^ padLen);
				}

				if (diff != 0) {
					return false; // Invalid padding
				}

				// Remove padding
				data.resize(data.size() - padLen);
				return true;
			}
		}
	}
}
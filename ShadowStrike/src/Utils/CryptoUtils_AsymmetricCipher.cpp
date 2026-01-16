// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
/**
 * @file CryptoUtils_AsymmetricCipher.cpp
 * @brief Enterprise-grade asymmetric cryptography implementation
 *
 * Implements AsymmetricCipher with RSA encryption/decryption, digital signatures,
 * ECC Diffie-Hellman key exchange, and key derivation functions using Windows CNG APIs.
 *
 * Features:
 * - RSA Encryption: 2048/3072/4096-bit with PKCS#1 v1.5 and OAEP padding (SHA1/256/384/512)
 * - RSA Signatures: PKCS#1 v1.5 and PSS padding with configurable hash algorithms
 * - ECC ECDH: P-256/P-384/P-521 for shared secret derivation
 * - Key Generation: Secure RSA/ECC key pair generation with proper finalization
 * - Key Import/Export: PEM and DER format support for public/private keys
 * - Key Derivation: PBKDF2, HKDF (RFC 5869) for key derivation from passwords
 *
 * Security Features:
 * - Secure key import: Private keys zeroed after BCrypt import
 * - Padding validation: RFC 8017 PSS salt length = hash length
 * - Blob integrity checks: BCRYPT_RSAKEY_BLOB header validation
 * - Thread-safe RAII: EcdhProviderHandle for resource management
 * - Constant-time operations: BCRYPT crypto primitives prevent timing attacks
 *
 * @copyright Copyright (c) 2025 ShadowStrike Security Suite
 */
#include"pch.h"
#include "CryptoUtils.hpp"
#include"CryptoUtilsCommon.hpp"
#include<sstream>

namespace ShadowStrike {
	namespace Utils {
		namespace CryptoUtils {

			// =============================================================================
			// AsymmetricCipher Implementation
			// =============================================================================
			AsymmetricCipher::AsymmetricCipher(AsymmetricAlgorithm algorithm) noexcept : m_algorithm(algorithm) {}

			AsymmetricCipher::~AsymmetricCipher() {
				cleanup();
			}

			void AsymmetricCipher::cleanup() noexcept {
#ifdef _WIN32
				// Proper cleanup order (keys before provider)
				if (m_publicKeyHandle) {
					BCryptDestroyKey(m_publicKeyHandle);
					m_publicKeyHandle = nullptr;
				}
				if (m_privateKeyHandle) {
					BCryptDestroyKey(m_privateKeyHandle);
					m_privateKeyHandle = nullptr;
				}

				// Close provider handle
				if (m_algHandle) {
					NTSTATUS st = BCryptCloseAlgorithmProvider(m_algHandle, 0);
					if (st < 0) {
						SS_LOG_WARN(L"CryptoUtils", L"BCryptCloseAlgorithmProvider failed: 0x%08X", st);
					}
					m_algHandle = nullptr;
				}
#endif
				m_publicKeyLoaded = false;
				m_privateKeyLoaded = false;
			}

			bool AsymmetricCipher::ensureProvider(Error* err) noexcept {
#ifdef _WIN32
				//if already opened
				if (m_algHandle) {
					return true;
				}

				//Get Algorithm Name
				const wchar_t* algName = RSAAlgName(m_algorithm);
				if (!algName || !*algName) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->ntstatus = 0;
						err->message = L"Invalid asymmetric algorithm";
						err->context.clear();
					}

					//prevents abort() if logger not initialized
					if (Logger::Instance().IsInitialized()) {
						SS_LOG_ERROR(L"CryptoUtils", L"ensureProvider: invalid algorithm enum: %d", static_cast<int>(m_algorithm));
					}
					else
					{
						wchar_t debugMsg[256];
						swprintf_s(debugMsg, L"[CryptoUtils] ensureProvider: invalid algorithm enum: %d\n",
							static_cast<int>(m_algorithm));
						OutputDebugStringW(debugMsg);
					}
					return false;
				}

				//Try to open
				BCRYPT_ALG_HANDLE h = nullptr;
				NTSTATUS st = BCryptOpenAlgorithmProvider(&h, algName, nullptr, 0);
				if (st < 0 || h == nullptr) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"BCryptOpenAlgorithmProvider failed for asymmetric";
						wchar_t tmp[256];
						swprintf_s(tmp, L"Algorithm=%s NTSTATUS=0x%08X Win32=%u", algName, static_cast<unsigned>(st), err->win32);
						err->context = tmp; //Copies std::wstring, no dangling
					}
					//prevents abort() if logger not initialized
					if (Logger::Instance().IsInitialized()) {
						SS_LOG_ERROR(L"CryptoUtils", L"BCryptOpenAlgorithmProvider failed: Algorithm=%s, NTSTATUS=0x%08X, Win32=%u\n", static_cast<int>(m_algorithm));
					}
					else
					{
						wchar_t debugMsg[512];
						swprintf_s(debugMsg,
							L"[CryptoUtils] BCryptOpenAlgorithmProvider failed: Algorithm=%s, NTSTATUS=0x%08X, Win32=%u\n",
							algName, static_cast<unsigned>(st), RtlNtStatusToDosError(st));
						OutputDebugStringW(debugMsg);
					}

					//Guarantee null handle on failure
					m_algHandle = nullptr;
					return false;
				}


				m_algHandle = h;


				if (Logger::Instance().IsInitialized()) {
					SS_LOG_INFO(L"CryptoUtils", L"Algorithm provider opened: %s (handle: %p)", algName, m_algHandle);
				}
				else {
					// Fallback to OutputDebugStringW if Logger not ready
					wchar_t debugMsg[256];
					swprintf_s(debugMsg, L"[CryptoUtils] Algorithm provider opened: %s (handle: %p)\n",
						algName, static_cast<void*>(m_algHandle));
					OutputDebugStringW(debugMsg);
				}

				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->ntstatus = 0; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool AsymmetricCipher::GenerateKeyPair(KeyPair& outKeyPair, Error* err) noexcept {
#ifdef _WIN32
				// Ensure provider is opened
				if (!ensureProvider(err)) {
					SS_LOG_ERROR(L"CryptoUtils", L"GenerateKeyPair: ensureProvider failed");
					return false;
				}

				if (!m_algHandle) {
					if (err) { err->win32 = ERROR_INVALID_HANDLE; err->ntstatus = 0; err->message = L"Algorithm provider handle is null"; }
					SS_LOG_ERROR(L"CryptoUtils", L"GenerateKeyPair: m_algHandle is null after ensureProvider");
					return false;
				}

				ULONG keySizeBits = RSAKeySizeForAlg(m_algorithm);
				SS_LOG_INFO(L"CryptoUtils", L"Generating key pair (alg=%d, bits=%u)", static_cast<int>(m_algorithm), keySizeBits);

				BCRYPT_KEY_HANDLE hKey = nullptr;
				NTSTATUS st = BCryptGenerateKeyPair(m_algHandle, &hKey, keySizeBits, 0);
				if (st < 0 || !hKey) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"BCryptGenerateKeyPair failed";
						wchar_t tmp[128];
						swprintf_s(tmp, L"KeySize=%u NTSTATUS=0x%08X", keySizeBits, static_cast<unsigned>(st));
						err->context = tmp;
					}
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptGenerateKeyPair failed: 0x%08X", st);
					return false;
				}

				st = BCryptFinalizeKeyPair(hKey, 0);
				if (st < 0) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"BCryptFinalizeKeyPair failed";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptFinalizeKeyPair failed: 0x%08X", st);
					BCryptDestroyKey(hKey);
					return false;
				}

				const bool isECC = (m_algorithm == AsymmetricAlgorithm::ECC_P256 ||
					m_algorithm == AsymmetricAlgorithm::ECC_P384 ||
					m_algorithm == AsymmetricAlgorithm::ECC_P521);

				const wchar_t* pubBlobType = isECC ? BCRYPT_ECCPUBLIC_BLOB : BCRYPT_RSAPUBLIC_BLOB;
				const wchar_t* privBlobType = isECC ? BCRYPT_ECCPRIVATE_BLOB : BCRYPT_RSAFULLPRIVATE_BLOB;

				// Export public key
				ULONG cbBlob = 0;
				st = BCryptExportKey(hKey, nullptr, pubBlobType, nullptr, 0, &cbBlob, 0);
				if (st < 0 || cbBlob == 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptExportKey (public size) failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptExportKey (public size) failed: 0x%08X", st);
					BCryptDestroyKey(hKey);
					return false;
				}
				outKeyPair.publicKey.algorithm = m_algorithm;
				outKeyPair.publicKey.keyBlob.resize(cbBlob);
				st = BCryptExportKey(hKey, nullptr, pubBlobType, outKeyPair.publicKey.keyBlob.data(), cbBlob, &cbBlob, 0);
				if (st < 0) {
					// SECURITY: Clear public key blob on failure
					outKeyPair.publicKey.keyBlob.clear();
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptExportKey (public) failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptExportKey (public) failed: 0x%08X", st);
					BCryptDestroyKey(hKey);
					return false;
				}

				// Export private key
				cbBlob = 0;
				st = BCryptExportKey(hKey, nullptr, privBlobType, nullptr, 0, &cbBlob, 0);
				if (st < 0 || cbBlob == 0) {
					// SECURITY: Clear public key blob since we're failing
					outKeyPair.publicKey.keyBlob.clear();
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptExportKey (private size) failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptExportKey (private size) failed: 0x%08X", st);
					BCryptDestroyKey(hKey);
					return false;
				}
				outKeyPair.privateKey.algorithm = m_algorithm;
				outKeyPair.privateKey.keyBlob.resize(cbBlob);
				st = BCryptExportKey(hKey, nullptr, privBlobType, outKeyPair.privateKey.keyBlob.data(), cbBlob, &cbBlob, 0);
				if (st < 0) {
					// SECURITY: Clear both key blobs on failure
					outKeyPair.publicKey.keyBlob.clear();
					if (!outKeyPair.privateKey.keyBlob.empty()) {
						SecureZeroMemory(outKeyPair.privateKey.keyBlob.data(), outKeyPair.privateKey.keyBlob.size());
						outKeyPair.privateKey.keyBlob.clear();
					}
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptExportKey (private) failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptExportKey (private) failed: 0x%08X", st);
					BCryptDestroyKey(hKey);
					return false;
				}

				BCryptDestroyKey(hKey);

				SS_LOG_INFO(L"CryptoUtils", L"Key pair generated (pub=%zu bytes, priv=%zu bytes)",
					outKeyPair.publicKey.keyBlob.size(), outKeyPair.privateKey.keyBlob.size());

				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->ntstatus = 0; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool AsymmetricCipher::LoadPublicKey(const PublicKey& key, Error* err) noexcept {
#ifdef _WIN32
				if (!ensureProvider(err)) return false;

				if (m_publicKeyHandle) {
					BCryptDestroyKey(m_publicKeyHandle);
					m_publicKeyHandle = nullptr;
				}

				// ECC vs RSA blob type selection
				const bool isECC = (key.algorithm == AsymmetricAlgorithm::ECC_P256 ||
					key.algorithm == AsymmetricAlgorithm::ECC_P384 ||
					key.algorithm == AsymmetricAlgorithm::ECC_P521);
				const wchar_t* blobType = isECC ? BCRYPT_ECCPUBLIC_BLOB : BCRYPT_RSAPUBLIC_BLOB;

				NTSTATUS st = BCryptImportKeyPair(m_algHandle, nullptr, blobType,
					&m_publicKeyHandle, const_cast<uint8_t*>(key.keyBlob.data()),
					static_cast<ULONG>(key.keyBlob.size()), 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptImportKeyPair public failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptImportKeyPair public failed: 0x%08X", st);
					return false;
				}

				m_publicKeyLoaded = true;
				SS_LOG_INFO(L"CryptoUtils", L"Public key loaded successfully");
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool AsymmetricCipher::LoadPrivateKey(const PrivateKey& key, Error* err) noexcept {
#ifdef _WIN32
				if (!ensureProvider(err)) return false;

				if (m_privateKeyHandle) {
					BCryptDestroyKey(m_privateKeyHandle);
					m_privateKeyHandle = nullptr;
				}

				// ECC vs RSA blob type selection
				const bool isECC = (key.algorithm == AsymmetricAlgorithm::ECC_P256 ||
					key.algorithm == AsymmetricAlgorithm::ECC_P384 ||
					key.algorithm == AsymmetricAlgorithm::ECC_P521);
				const wchar_t* blobType = isECC ? BCRYPT_ECCPRIVATE_BLOB : BCRYPT_RSAFULLPRIVATE_BLOB;

				NTSTATUS st = BCryptImportKeyPair(m_algHandle, nullptr, blobType,
					&m_privateKeyHandle, const_cast<uint8_t*>(key.keyBlob.data()),
					static_cast<ULONG>(key.keyBlob.size()), 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptImportKeyPair private failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptImportKeyPair private failed: 0x%08X", st);
					return false;
				}
				// NOTE: Private key blob is securely erased after import.
				// Do not rely on key.keyBlob later in the program.
				SecureZeroMemory(const_cast<uint8_t*>(key.keyBlob.data()), key.keyBlob.size());
				const_cast<std::vector<uint8_t>&>(key.keyBlob).clear();
				m_privateKeyLoaded = true;
				SS_LOG_INFO(L"CryptoUtils", L"Private key loaded successfully");
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool AsymmetricCipher::Encrypt(const uint8_t* plaintext, size_t plaintextLen,
				std::vector<uint8_t>& ciphertext,
				RSAPaddingScheme padding,
				Error* err) noexcept
			{
				// Basic state validation
				if (!m_publicKeyLoaded) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Public key not loaded"; }
					return false;
				}

#ifdef _WIN32
				if (!m_publicKeyHandle) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Public key handle is null"; }
					return false;
				}

				if (!(m_algorithm == AsymmetricAlgorithm::RSA_2048 ||
					m_algorithm == AsymmetricAlgorithm::RSA_3072 ||
					m_algorithm == AsymmetricAlgorithm::RSA_4096)) {
					if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Only RSA encryption is supported"; }
					return false;
				}

				if (!plaintext && plaintextLen != 0) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid plaintext pointer"; }
					return false;
				}

				// Padding setup
				ULONG flags = 0;
				BCRYPT_OAEP_PADDING_INFO oaep{};
				oaep.pbLabel = nullptr;
				oaep.cbLabel = 0;
				const void* pPadInfo = nullptr;

				auto setOaepAlg = [&](RSAPaddingScheme s) -> bool {
					switch (s) {
					case RSAPaddingScheme::OAEP_SHA1:   oaep.pszAlgId = BCRYPT_SHA1_ALGORITHM; break;
					case RSAPaddingScheme::OAEP_SHA256: oaep.pszAlgId = BCRYPT_SHA256_ALGORITHM; break;
					case RSAPaddingScheme::OAEP_SHA384: oaep.pszAlgId = BCRYPT_SHA384_ALGORITHM; break;
					case RSAPaddingScheme::OAEP_SHA512: oaep.pszAlgId = BCRYPT_SHA512_ALGORITHM; break;
					default: return false;
					}
					return true;
					};

				bool isOAEP = (padding == RSAPaddingScheme::OAEP_SHA1 ||
					padding == RSAPaddingScheme::OAEP_SHA256 ||
					padding == RSAPaddingScheme::OAEP_SHA384 ||
					padding == RSAPaddingScheme::OAEP_SHA512);

				if (padding == RSAPaddingScheme::PKCS1) {
					flags = BCRYPT_PAD_PKCS1;
					pPadInfo = nullptr;
				}
				else if (isOAEP) {
					if (!setOaepAlg(padding)) {
						if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid padding scheme"; }
						return false;
					}
					flags = BCRYPT_PAD_OAEP;
					pPadInfo = &oaep;
				}
				else {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid padding for encryption"; }
					return false;
				}

				// Max plaintext size validation using existing helper
				size_t maxPlain = GetMaxPlaintextSize(padding);
				if (plaintextLen > maxPlain) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Plaintext too large"; }
					return false;
				}

				// Query output size
				ULONG cbResult = 0;
				NTSTATUS st = BCryptEncrypt(m_publicKeyHandle,
					const_cast<uint8_t*>(plaintext), static_cast<ULONG>(plaintextLen),
					const_cast<void*>(pPadInfo),
					nullptr, 0,
					nullptr, 0, &cbResult, flags);

				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptEncrypt size query failed"; }
					return false;
				}

				ciphertext.resize(cbResult);
				st = BCryptEncrypt(m_publicKeyHandle,
					const_cast<uint8_t*>(plaintext), static_cast<ULONG>(plaintextLen),
					const_cast<void*>(pPadInfo),
					nullptr, 0,
					ciphertext.data(), static_cast<ULONG>(ciphertext.size()), &cbResult, flags);

				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptEncrypt failed"; }
					SecureZeroMemory(ciphertext.data(), ciphertext.size());
					return false;
				}

				ciphertext.resize(cbResult);
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}


			bool AsymmetricCipher::Decrypt(const uint8_t* ciphertext, size_t ciphertextLen,
				std::vector<uint8_t>& plaintext,
				RSAPaddingScheme padding,
				Error* err) noexcept
			{
				if (!m_privateKeyLoaded) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Private key not loaded"; }
					return false;
				}

#ifdef _WIN32
				if (!m_privateKeyHandle) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Private key handle is null"; }
					return false;
				}


				if (!(m_algorithm == AsymmetricAlgorithm::RSA_2048 ||
					m_algorithm == AsymmetricAlgorithm::RSA_3072 ||
					m_algorithm == AsymmetricAlgorithm::RSA_4096)) {
					if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Only RSA decryption is supported"; }
					return false;
				}

				if (!ciphertext && ciphertextLen != 0) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid ciphertext pointer"; }
					return false;
				}

				ULONG flags = 0;
				BCRYPT_OAEP_PADDING_INFO oaep{};
				oaep.pbLabel = nullptr;
				oaep.cbLabel = 0;
				const void* pPadInfo = nullptr;

				auto setOaepAlg = [&](RSAPaddingScheme s) -> bool {
					switch (s) {
					case RSAPaddingScheme::OAEP_SHA1:   oaep.pszAlgId = BCRYPT_SHA1_ALGORITHM; break;
					case RSAPaddingScheme::OAEP_SHA256: oaep.pszAlgId = BCRYPT_SHA256_ALGORITHM; break;
					case RSAPaddingScheme::OAEP_SHA384: oaep.pszAlgId = BCRYPT_SHA384_ALGORITHM; break;
					case RSAPaddingScheme::OAEP_SHA512: oaep.pszAlgId = BCRYPT_SHA512_ALGORITHM; break;
					default: return false;
					}
					return true;
					};

				bool isOAEP = (padding == RSAPaddingScheme::OAEP_SHA1 ||
					padding == RSAPaddingScheme::OAEP_SHA256 ||
					padding == RSAPaddingScheme::OAEP_SHA384 ||
					padding == RSAPaddingScheme::OAEP_SHA512);

				if (padding == RSAPaddingScheme::PKCS1) {
					flags = BCRYPT_PAD_PKCS1;
					pPadInfo = nullptr;
				}
				else if (isOAEP) {
					if (!setOaepAlg(padding)) {
						if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid padding scheme"; }
						return false;
					}
					flags = BCRYPT_PAD_OAEP;
					pPadInfo = &oaep;
				}
				else {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid padding for decryption"; }
					return false;
				}

				// Query output size
				ULONG cbResult = 0;
				NTSTATUS st = BCryptDecrypt(m_privateKeyHandle,
					const_cast<uint8_t*>(ciphertext), static_cast<ULONG>(ciphertextLen),
					const_cast<void*>(pPadInfo),
					nullptr, 0,
					nullptr, 0, &cbResult, flags);

				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDecrypt size query failed"; }
					return false;
				}

				plaintext.resize(cbResult);
				st = BCryptDecrypt(m_privateKeyHandle,
					const_cast<uint8_t*>(ciphertext), static_cast<ULONG>(ciphertextLen),
					const_cast<void*>(pPadInfo),
					nullptr, 0,
					plaintext.data(), static_cast<ULONG>(plaintext.size()), &cbResult, flags);

				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDecrypt failed"; }
					SecureZeroMemory(plaintext.data(), plaintext.size());
					return false;
				}

				plaintext.resize(cbResult);
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool AsymmetricCipher::Sign(const uint8_t* data, size_t dataLen,
				std::vector<uint8_t>& signature,
				HashUtils::Algorithm hashAlg,
				RSAPaddingScheme padding,
				Error* err) noexcept
			{
				if (!m_privateKeyLoaded) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Private key not loaded"; }
					return false;
				}

				std::vector<uint8_t> hash;
				if (!HashUtils::Compute(hashAlg, data, dataLen, hash, nullptr)) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Hash computation failed"; }
					return false;
				}

#ifdef _WIN32
				//Padding scheme selection
				ULONG flags = 0;
				void* pPaddingInfo = nullptr;

				BCRYPT_PKCS1_PADDING_INFO pkcs1Info{};
				BCRYPT_PSS_PADDING_INFO pssInfo{};

				// Map hash algorithm to BCrypt algorithm name
				auto getHashAlgName = [](HashUtils::Algorithm alg) -> LPCWSTR {
					switch (alg) {
					case HashUtils::Algorithm::SHA1:   return BCRYPT_SHA1_ALGORITHM;
					case HashUtils::Algorithm::SHA256: return BCRYPT_SHA256_ALGORITHM;
					case HashUtils::Algorithm::SHA384: return BCRYPT_SHA384_ALGORITHM;
					case HashUtils::Algorithm::SHA512: return BCRYPT_SHA512_ALGORITHM;
					default: return nullptr;
					}
					};

				LPCWSTR hashAlgName = getHashAlgName(hashAlg);
				if (!hashAlgName) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Unsupported hash algorithm for signing"; }
					return false;
				}

				// Use correct padding struct based on scheme
				if (padding == RSAPaddingScheme::PKCS1) {
					flags = BCRYPT_PAD_PKCS1;
					pkcs1Info.pszAlgId = hashAlgName;
					pPaddingInfo = &pkcs1Info;
				}
				else if (padding == RSAPaddingScheme::PSS_SHA256 ||
					padding == RSAPaddingScheme::PSS_SHA384 ||
					padding == RSAPaddingScheme::PSS_SHA512)
				{
					flags = BCRYPT_PAD_PSS;
					pssInfo.pszAlgId = hashAlgName;
					pssInfo.cbSalt = static_cast<ULONG>(hash.size()); // ✅ CRITICAL: Salt length = hash length (RFC 8017)
					pPaddingInfo = &pssInfo;
				}
				else {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Unsupported padding scheme for signing"; }
					return false;
				}

				// Query signature size
				ULONG cbResult = 0;
				NTSTATUS st = BCryptSignHash(m_privateKeyHandle,
					pPaddingInfo,
					hash.data(), static_cast<ULONG>(hash.size()),
					nullptr, 0, &cbResult, flags);

				if (st < 0) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"BCryptSignHash size query failed";
						wchar_t tmp[128];
						swprintf_s(tmp, L"NTSTATUS=0x%08X, Padding=%d", static_cast<unsigned>(st), static_cast<int>(padding));
						err->context = tmp;
					}
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptSignHash size query failed: 0x%08X (padding: %d)", st, static_cast<int>(padding));
					return false;
				}

				signature.resize(cbResult);

				// Perform signing
				st = BCryptSignHash(m_privateKeyHandle,
					pPaddingInfo,
					hash.data(), static_cast<ULONG>(hash.size()),
					signature.data(), static_cast<ULONG>(signature.size()), &cbResult, flags);

				if (st < 0) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"BCryptSignHash failed";
						wchar_t tmp[256];
						swprintf_s(tmp, L"NTSTATUS=0x%08X, HashLen=%zu, SigLen=%zu, Padding=%d",
							static_cast<unsigned>(st), hash.size(), signature.size(), static_cast<int>(padding));
						err->context = tmp;
					}
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptSignHash failed: 0x%08X (hash: %zu bytes, padding: %d)",
						st, hash.size(), static_cast<int>(padding));
					return false;
				}

				signature.resize(cbResult);

				SS_LOG_INFO(L"CryptoUtils", L"Signature generated successfully (%zu bytes, padding: %d)",
					signature.size(), static_cast<int>(padding));
				return true;

#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool AsymmetricCipher::Verify(const uint8_t* data, size_t dataLen,
				const uint8_t* signature, size_t signatureLen,
				HashUtils::Algorithm hashAlg,
				RSAPaddingScheme padding,
				Error* err) noexcept
			{
				if (!m_publicKeyLoaded) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Public key not loaded"; }
					return false;
				}

				std::vector<uint8_t> hash;
				if (!HashUtils::Compute(hashAlg, data, dataLen, hash, nullptr)) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Hash computation failed"; }
					return false;
				}

#ifdef _WIN32
				// Padding scheme selection
				ULONG flags = 0;
				void* pPaddingInfo = nullptr;

				BCRYPT_PKCS1_PADDING_INFO pkcs1Info{};
				BCRYPT_PSS_PADDING_INFO pssInfo{};

				// Map hash algorithm to BCrypt algorithm name
				auto getHashAlgName = [](HashUtils::Algorithm alg) -> LPCWSTR {
					switch (alg) {
					case HashUtils::Algorithm::SHA1:   return BCRYPT_SHA1_ALGORITHM;
					case HashUtils::Algorithm::SHA256: return BCRYPT_SHA256_ALGORITHM;
					case HashUtils::Algorithm::SHA384: return BCRYPT_SHA384_ALGORITHM;
					case HashUtils::Algorithm::SHA512: return BCRYPT_SHA512_ALGORITHM;
					default: return nullptr;
					}
					};

				LPCWSTR hashAlgName = getHashAlgName(hashAlg);
				if (!hashAlgName) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Unsupported hash algorithm for verification"; }
					return false;
				}

				// Use correct padding struct based on scheme
				if (padding == RSAPaddingScheme::PKCS1) {
					flags = BCRYPT_PAD_PKCS1;
					pkcs1Info.pszAlgId = hashAlgName;
					pPaddingInfo = &pkcs1Info;
				}
				else if (padding == RSAPaddingScheme::PSS_SHA256 ||
					padding == RSAPaddingScheme::PSS_SHA384 ||
					padding == RSAPaddingScheme::PSS_SHA512)
				{
					flags = BCRYPT_PAD_PSS;
					pssInfo.pszAlgId = hashAlgName;
					pssInfo.cbSalt = static_cast<ULONG>(hash.size()); // Salt length = hash length
					pPaddingInfo = &pssInfo;
				}
				else {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Unsupported padding scheme for verification"; }
					return false;
				}

				// Verify signature
				NTSTATUS st = BCryptVerifySignature(m_publicKeyHandle,
					pPaddingInfo,
					hash.data(), static_cast<ULONG>(hash.size()),
					const_cast<uint8_t*>(signature), static_cast<ULONG>(signatureLen),
					flags);

				if (st < 0) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"BCryptVerifySignature failed";
						wchar_t tmp[256];
						swprintf_s(tmp, L"NTSTATUS=0x%08X, HashLen=%zu, SigLen=%zu, Padding=%d",
							static_cast<unsigned>(st), hash.size(), signatureLen, static_cast<int>(padding));
						err->context = tmp;
					}
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptVerifySignature failed: 0x%08X (padding: %d)",
						st, static_cast<int>(padding));
					return false;
				}

				SS_LOG_INFO(L"CryptoUtils", L"Signature verified successfully (padding: %d)", static_cast<int>(padding));
				return true;

#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool AsymmetricCipher::DeriveSharedSecret(const PublicKey& peerPublicKey,
				std::vector<uint8_t>& sharedSecret,
				Error* err) noexcept
			{
				// Validate that we have a private key loaded
				if (!m_privateKeyLoaded) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Private key not loaded"; }
					return false;
				}

				// Validate algorithm compatibility
				if (m_algorithm != AsymmetricAlgorithm::ECC_P256 &&
					m_algorithm != AsymmetricAlgorithm::ECC_P384 &&
					m_algorithm != AsymmetricAlgorithm::ECC_P521) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"ECDH only supported for ECC algorithms"; }
					return false;
				}

				// Validate peer public key algorithm matches
				if (peerPublicKey.algorithm != m_algorithm) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Peer public key algorithm mismatch"; }
					return false;
				}

				if (peerPublicKey.keyBlob.empty()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Peer public key is empty"; }
					return false;
				}

#ifdef _WIN32
				// Get the correct algorithm name for ECC
				const wchar_t* algName = nullptr;
				switch (m_algorithm) {
				case AsymmetricAlgorithm::ECC_P256: algName = BCRYPT_ECDH_P256_ALGORITHM; break;
				case AsymmetricAlgorithm::ECC_P384: algName = BCRYPT_ECDH_P384_ALGORITHM; break;
				case AsymmetricAlgorithm::ECC_P521: algName = BCRYPT_ECDH_P521_ALGORITHM; break;
				default:
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Unsupported ECC algorithm"; }
					return false;
				}

				// RAII provider(no throw)
				struct EcdhProviderHandle {
					BCRYPT_ALG_HANDLE handle = nullptr;
					NTSTATUS status = 0;

					explicit EcdhProviderHandle(const wchar_t* name) {
						status = BCryptOpenAlgorithmProvider(&handle, name, nullptr, 0);
						if (status < 0) {
							handle = nullptr;
						}
					}
					~EcdhProviderHandle() {
						if (handle) {
							BCryptCloseAlgorithmProvider(handle, 0);
							handle = nullptr;
						}
					}
					EcdhProviderHandle(const EcdhProviderHandle&) = delete;
					EcdhProviderHandle& operator=(const EcdhProviderHandle&) = delete;
					EcdhProviderHandle(EcdhProviderHandle&& other) noexcept {
						handle = other.handle;
						status = other.status;
						other.handle = nullptr;
					}
					bool ok() const { return status >= 0 && handle != nullptr; }
				};

				EcdhProviderHandle provider(algName);
				if (!provider.ok()) {
					if (err) {
						err->ntstatus = provider.status;
						err->win32 = RtlNtStatusToDosError(provider.status);
						err->message = L"ECDH provider init failed";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"ECDH provider init failed: 0x%08X", provider.status);
					return false;
				}

				// Import peer's public key
				BCRYPT_KEY_HANDLE hPeerPublicKey = nullptr;
				NTSTATUS st = BCryptImportKeyPair(provider.handle, nullptr, BCRYPT_ECCPUBLIC_BLOB,
					&hPeerPublicKey,
					const_cast<uint8_t*>(peerPublicKey.keyBlob.data()),
					static_cast<ULONG>(peerPublicKey.keyBlob.size()), 0);

				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptImportKeyPair for peer public key failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptImportKeyPair for peer failed: 0x%08X", st);
					return false; // provider RAII ile kapanacak
				}

				// Derive shared secret using BCryptSecretAgreement
				BCRYPT_SECRET_HANDLE hSecret = nullptr;
				st = BCryptSecretAgreement(m_privateKeyHandle, hPeerPublicKey, &hSecret, 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptSecretAgreement failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptSecretAgreement failed: 0x%08X", st);
					BCryptDestroyKey(hPeerPublicKey);
					return false;
				}

				// Derive key material from the secret using RAW secret
				ULONG cbResult = 0;
				st = BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, nullptr, nullptr, 0, &cbResult, 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDeriveKey size query failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptDeriveKey size query failed: 0x%08X", st);
					BCryptDestroySecret(hSecret);
					BCryptDestroyKey(hPeerPublicKey);
					return false;
				}

				sharedSecret.resize(cbResult);

				st = BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, nullptr,
					sharedSecret.data(), static_cast<ULONG>(sharedSecret.size()), &cbResult, 0);

				// Cleanup secret + peer key
				BCryptDestroySecret(hSecret);
				BCryptDestroyKey(hPeerPublicKey);

				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDeriveKey failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptDeriveKey failed: 0x%08X", st);
					SecureZeroMemory(sharedSecret.data(), sharedSecret.size());
					sharedSecret.clear();
					return false;
				}

				sharedSecret.resize(cbResult);

				SS_LOG_INFO(L"CryptoUtils", L"ECDH shared secret derived successfully (%zu bytes)", sharedSecret.size());
				return true;

#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			size_t AsymmetricCipher::GetMaxPlaintextSize(RSAPaddingScheme padding) const noexcept {
#ifdef _WIN32

				ULONG keySizeBits = 0;

				if (m_publicKeyLoaded && m_publicKeyHandle) {
					ULONG cbBlob = 0;
					NTSTATUS st = BCryptExportKey(m_publicKeyHandle, nullptr, BCRYPT_RSAPUBLIC_BLOB,
						nullptr, 0, &cbBlob, 0);
					if (st >= 0 && cbBlob >= sizeof(BCRYPT_RSAKEY_BLOB)) {
						std::vector<uint8_t> blob(cbBlob);
						st = BCryptExportKey(m_publicKeyHandle, nullptr, BCRYPT_RSAPUBLIC_BLOB,
							blob.data(), cbBlob, &cbBlob, 0);
						if (st >= 0 && cbBlob >= sizeof(BCRYPT_RSAKEY_BLOB)) {
							//Parse the blob header securely
							const auto* hdr = reinterpret_cast<const BCRYPT_RSAKEY_BLOB*>(blob.data());
							//Magic and bit length sanity check
							if (hdr->Magic == BCRYPT_RSAPUBLIC_MAGIC && (hdr->BitLength % 8) == 0) {
								const size_t kBytes = static_cast<size_t>(hdr->BitLength / 8);
								const size_t headerSize = sizeof(BCRYPT_RSAKEY_BLOB);
								const size_t expectedMin = headerSize + hdr->cbPublicExp + hdr->cbModulus;
								//Blob size and modulus size consistency check
								if (cbBlob >= expectedMin && hdr->cbModulus == kBytes) {
									keySizeBits = hdr->BitLength;
								}
								else {
									SS_LOG_WARN(L"CryptoUtils",
										L"Inconsistent RSA public blob: cbBlob=%lu, expectedMin=%zu, cbModulus=%lu, kBytes=%zu",
										cbBlob, expectedMin, hdr->cbModulus, kBytes);
									keySizeBits = 0;
								}
							}
							else {
								SS_LOG_WARN(L"CryptoUtils",
									L"Invalid RSA public blob header: Magic=0x%08X, BitLength=%lu",
									hdr->Magic, hdr->BitLength);
								keySizeBits = 0;
							}
						}
					}
				}

				if (keySizeBits == 0) {
					//Algorithm based fallback
					keySizeBits = RSAKeySizeForAlg(m_algorithm);
				}
#else
				const ULONG keySizeBits = RSAKeySizeForAlg(m_algorithm);
#endif

				//for ECC, return a predefined cap
				const bool isECC = (m_algorithm == AsymmetricAlgorithm::ECC_P256 ||
					m_algorithm == AsymmetricAlgorithm::ECC_P384 ||
					m_algorithm == AsymmetricAlgorithm::ECC_P521);
				if (isECC) {
					// use a predefined ECC cap if exists, if not use the default 65536
					const size_t eccCap =
#ifdef HAS_ECC_CAP_MEMBER
						m_eccMaxPlaintextCap
#else
						static_cast<size_t>(65536)
#endif
						;
					return eccCap;
				}

				//bit-> byte conversion for RSA
				if (keySizeBits == 0 || (keySizeBits % 8) != 0) {
					SS_LOG_WARN(L"CryptoUtils", L"Invalid RSA key size bits: %lu", keySizeBits);
					return 0;
				}
				const size_t keySizeBytes = static_cast<size_t>(keySizeBits / 8);
				if (keySizeBytes == 0) return 0;

				// Sanity cap: block the unrealistic key sizes
				const size_t sanityCap = 1024 * 1024; // 1MB
				if (keySizeBytes > sanityCap) {
					SS_LOG_WARN(L"CryptoUtils", L"RSA key size bytes (%zu) exceeded sanity cap (%zu)", keySizeBytes, sanityCap);
					return 0;
				}

				//maximum plaintext size for the given padding
				switch (padding) {
				case RSAPaddingScheme::PKCS1:
					// PKCS#1 v1.5: max = k - 11
					if (keySizeBytes <= 11) return 0;
					return keySizeBytes - 11;

				case RSAPaddingScheme::OAEP_SHA1: {
					const size_t hLen = 20;
					// OAEP: max = k - 2*hLen - 2
					if (keySizeBytes <= (2 * hLen + 2)) return 0;
					return keySizeBytes - (2 * hLen) - 2;
				}
				case RSAPaddingScheme::OAEP_SHA256: {
					const size_t hLen = 32;
					if (keySizeBytes <= (2 * hLen + 2)) return 0;
					return keySizeBytes - (2 * hLen) - 2;
				}
				case RSAPaddingScheme::OAEP_SHA384: {
					const size_t hLen = 48;
					if (keySizeBytes <= (2 * hLen + 2)) return 0;
					return keySizeBytes - (2 * hLen) - 2;
				}
				case RSAPaddingScheme::OAEP_SHA512: {
					const size_t hLen = 64;
					if (keySizeBytes <= (2 * hLen + 2)) return 0;
					return keySizeBytes - (2 * hLen) - 2;
				}

				default:
					return 0;
				}
			}


			size_t AsymmetricCipher::GetSignatureSize() const noexcept {
				const ULONG keySize = RSAKeySizeForAlg(m_algorithm);
				return keySize / 8;
			}

			bool KeyDerivation::PBKDF2(const uint8_t* password, size_t passwordLen,
				const uint8_t* salt, size_t saltLen,
				uint32_t iterations,
				HashUtils::Algorithm hashAlg,
				uint8_t* outKey, size_t keyLen,
				Error* err) noexcept
			{
				if (!password || !salt || !outKey || keyLen == 0) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid parameters";
					}
					return false;
				}

				if (saltLen < 8) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->message = L"Salt length should be at least 8 bytes";
					}
					return false;
				}

#ifdef _WIN32
				// Map HashUtils::Algorithm to BCrypt algorithm
				const wchar_t* algName = BCRYPT_SHA256_ALGORITHM;
				switch (hashAlg) {
				case HashUtils::Algorithm::SHA1:   algName = BCRYPT_SHA1_ALGORITHM; break;
				case HashUtils::Algorithm::SHA256: algName = BCRYPT_SHA256_ALGORITHM; break;
				case HashUtils::Algorithm::SHA384: algName = BCRYPT_SHA384_ALGORITHM; break;
				case HashUtils::Algorithm::SHA512: algName = BCRYPT_SHA512_ALGORITHM; break;
				default: algName = BCRYPT_SHA256_ALGORITHM; break;
				}

				BCRYPT_ALG_HANDLE hAlg = nullptr;
				NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, algName, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptOpenAlgorithmProvider failed"; }
					return false;
				}

				st = BCryptDeriveKeyPBKDF2(hAlg,
					const_cast<uint8_t*>(password), static_cast<ULONG>(passwordLen),
					const_cast<uint8_t*>(salt), static_cast<ULONG>(saltLen),
					iterations,
					outKey, static_cast<ULONG>(keyLen),
					0);

				BCryptCloseAlgorithmProvider(hAlg, 0);

				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDeriveKeyPBKDF2 failed"; }
					return false;
				}

				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool KeyDerivation::HKDF(const uint8_t* inputKeyMaterial, size_t ikmLen,
				const uint8_t* salt, size_t saltLen,
				const uint8_t* info, size_t infoLen,
				HashUtils::Algorithm hashAlg,
				uint8_t* outKey, size_t keyLen,
				Error* err) noexcept
			{
				if (!inputKeyMaterial || !outKey || keyLen == 0) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid parameters"; }
					return false;
				}

				// HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
				std::vector<uint8_t> prk;
				size_t hashLen = 32; // Default SHA256
				switch (hashAlg) {
				case HashUtils::Algorithm::SHA256: hashLen = 32; break;
				case HashUtils::Algorithm::SHA384: hashLen = 48; break;
				case HashUtils::Algorithm::SHA512: hashLen = 64; break;
				default: hashLen = 32; break;
				}

				prk.resize(hashLen);

				// Use HMAC for extraction
				std::vector<uint8_t> hmacKey;
				if (salt && saltLen > 0) {
					hmacKey.assign(salt, salt + saltLen);
				}
				else {
					hmacKey.assign(hashLen, 0); // Zero-filled salt(RFC 5869 standard).
				}

				// Use ComputeHmac helper (one-shot) instead of non-existent HashUtils::Hmac(...) function
				if (!HashUtils::ComputeHmac(hashAlg, hmacKey.data(), hmacKey.size(),
					inputKeyMaterial, ikmLen, prk, nullptr)) {
					// SECURITY: Clear hmacKey on failure
					SecureZeroMemory(hmacKey.data(), hmacKey.size());
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"HKDF Extract failed"; }
					return false;
				}

				// SECURITY: Clear hmacKey after use (it may contain salt or zeros)
				SecureZeroMemory(hmacKey.data(), hmacKey.size());
				hmacKey.clear();

				if (keyLen > 255 * hashLen) {
					// SECURITY: Clear prk before returning
					SecureZeroMemory(prk.data(), prk.size());
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->message = L"HKDF keyLen too large";
					}
					return false;
				}


				// HKDF-Expand: OKM = T(1) | T(2) | T(3) | ...
				size_t n = (keyLen + hashLen - 1) / hashLen; // Ceiling division
				std::vector<uint8_t> t;
				std::vector<uint8_t> okm;

				for (size_t i = 1; i <= n; ++i) {
					std::vector<uint8_t> msg;
					msg.insert(msg.end(), t.begin(), t.end());
					if (info && infoLen > 0) {
						msg.insert(msg.end(), info, info + infoLen);
					}
					msg.push_back(static_cast<uint8_t>(i));

					t.resize(hashLen);
					//Use ComputeHmac here as well
					if (!HashUtils::ComputeHmac(hashAlg, prk.data(), prk.size(),
						msg.data(), msg.size(), t, nullptr)) {
						// SECURITY: Clear all intermediate key material on failure
						SecureZeroMemory(prk.data(), prk.size());
						SecureZeroMemory(t.data(), t.size());
						SecureZeroMemory(okm.data(), okm.size());
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"HKDF Expand failed"; }
						return false;
					}

					okm.insert(okm.end(), t.begin(), t.end());
				}

				std::memcpy(outKey, okm.data(), keyLen);

				// SECURITY: Clear all intermediate key material
				SecureZeroMemory(prk.data(), prk.size());
				SecureZeroMemory(t.data(), t.size());
				SecureZeroMemory(okm.data(), okm.size());

				return true;
			}

			bool KeyDerivation::DeriveKey(const uint8_t* password, size_t passwordLen,
				const KDFParams& params,
				std::vector<uint8_t>& outKey,
				Error* err) noexcept
			{
				if (!password || passwordLen == 0) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid password"; }
					return false;
				}

				outKey.resize(params.keyLength);

				// Generate salt if not provided
				std::vector<uint8_t> salt = params.salt;
				if (salt.empty()) {
					if (!GenerateSalt(salt, 32, err)) return false;
				}

				switch (params.algorithm) {
				case KDFAlgorithm::PBKDF2_SHA256:
					return PBKDF2(password, passwordLen, salt.data(), salt.size(),
						params.iterations, HashUtils::Algorithm::SHA256,
						outKey.data(), outKey.size(), err);

				case KDFAlgorithm::PBKDF2_SHA384:
					return PBKDF2(password, passwordLen, salt.data(), salt.size(),
						params.iterations, HashUtils::Algorithm::SHA384,
						outKey.data(), outKey.size(), err);

				case KDFAlgorithm::PBKDF2_SHA512:
					return PBKDF2(password, passwordLen, salt.data(), salt.size(),
						params.iterations, HashUtils::Algorithm::SHA512,
						outKey.data(), outKey.size(), err);

				case KDFAlgorithm::HKDF_SHA256:
					return HKDF(password, passwordLen, salt.data(), salt.size(),
						params.info.data(), params.info.size(),
						HashUtils::Algorithm::SHA256,
						outKey.data(), outKey.size(), err);

				case KDFAlgorithm::HKDF_SHA384:
					return HKDF(password, passwordLen, salt.data(), salt.size(),
						params.info.data(), params.info.size(),
						HashUtils::Algorithm::SHA384,
						outKey.data(), outKey.size(), err);

				case KDFAlgorithm::HKDF_SHA512:
					return HKDF(password, passwordLen, salt.data(), salt.size(),
						params.info.data(), params.info.size(),
						HashUtils::Algorithm::SHA512,
						outKey.data(), outKey.size(), err);

				case KDFAlgorithm::Scrypt:
				case KDFAlgorithm::Argon2id:
					if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Scrypt/Argon2 not implemented yet"; }
					return false;

				default:
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Unknown KDF algorithm"; }
					return false;
				}
			}

			bool KeyDerivation::DeriveKey(std::string_view password,
				const KDFParams& params,
				std::vector<uint8_t>& outKey,
				Error* err) noexcept
			{
				return DeriveKey(reinterpret_cast<const uint8_t*>(password.data()),
					password.size(), params, outKey, err);
			}

			bool KeyDerivation::GenerateSalt(std::vector<uint8_t>& salt, size_t size, Error* err) noexcept {
				SecureRandom rng;
				return rng.Generate(salt, size, err);
			}

			// =============================================================================
			// PublicKey Implementation
			// =============================================================================
			bool PublicKey::Export(std::vector<uint8_t>& out, Error* err) const noexcept {
				out = keyBlob;
				return true;
			}

			bool PublicKey::ExportPEM(std::string& out, Error* err) const noexcept {
				if (keyBlob.empty()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Key blob is empty"; }
					return false;
				}

				// Base64 encode the DER blob
				std::string base64 = Base64::Encode(keyBlob);
				if (base64.empty()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Base64 encoding failed"; }
					return false;
				}

				// PEM format: header + base64 (64 chars per line) + footer
				std::ostringstream oss;
				oss << "-----BEGIN PUBLIC KEY-----\n";

				// Split base64 into 64-character lines
				const size_t lineWidth = 64;
				for (size_t i = 0; i < base64.size(); i += lineWidth) {
					size_t chunkSize = std::min(lineWidth, base64.size() - i);
					oss << base64.substr(i, chunkSize) << "\n";
				}

				oss << "-----END PUBLIC KEY-----\n";

				out = oss.str();
				return true;
			}

			bool PublicKey::Import(const uint8_t* data, size_t len, PublicKey& out, Error* err) noexcept {
				if (!data || len == 0) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid input data"; }
					return false;
				}

				out.keyBlob.assign(data, data + len);
				return true;
			}

			bool PublicKey::ImportPEM(std::string_view pem, PublicKey& out, Error* err) noexcept {
				if (pem.empty()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"PEM string is empty"; }
					return false;
				}

				// Find PEM boundaries
				const std::string_view beginMarker = "-----BEGIN PUBLIC KEY-----";
				const std::string_view endMarker = "-----END PUBLIC KEY-----";

				size_t beginPos = pem.find(beginMarker);
				if (beginPos == std::string_view::npos) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"PEM begin marker not found"; }
					return false;
				}

				size_t endPos = pem.find(endMarker, beginPos);
				if (endPos == std::string_view::npos) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"PEM end marker not found"; }
					return false;
				}

				// Extract base64 content (skip header)
				beginPos += beginMarker.size();
				std::string_view base64Content = pem.substr(beginPos, endPos - beginPos);

				// Remove whitespace (newlines, spaces, tabs)
				std::string cleanBase64;
				cleanBase64.reserve(base64Content.size());
				for (char c : base64Content) {
					if (c != '\n' && c != '\r' && c != ' ' && c != '\t') {
						cleanBase64.push_back(c);
					}
				}

				if (cleanBase64.empty()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"PEM content is empty"; }
					return false;
				}

				// Base64 decode
				std::vector<uint8_t> decoded;
				if (!Base64::Decode(cleanBase64, decoded)) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Base64 decoding failed"; }
					return false;
				}

				if (decoded.empty()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Decoded data is empty"; }
					return false;
				}

				out.keyBlob = std::move(decoded);
				return true;
			}


		}
	}
}
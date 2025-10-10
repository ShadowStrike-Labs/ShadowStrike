
#include "CryptoUtils.hpp"
#include "Base64Utils.hpp"
#include "HashUtils.hpp"
#include "FileUtils.hpp"

#include <sstream> 
#include <cmath>
#include <limits>
#include <cstring>
#include <algorithm>
#include <fstream>
#include <vector>
#include <memory>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#  include <bcrypt.h>
#  include <ncrypt.h>
#  include <wincrypt.h>
#  include <wintrust.h>
#  include <softpub.h>
#  include <mscat.h>
#  pragma comment(lib, "bcrypt.lib")
#  pragma comment(lib, "ncrypt.lib")
#  pragma comment(lib, "crypt32.lib")
#  pragma comment(lib, "wintrust.lib")
#endif

namespace ShadowStrike {
	namespace Utils {
		namespace CryptoUtils {

			// =============================================================================
			// Helper Functions
			// =============================================================================

			static const wchar_t* AlgName(SymmetricAlgorithm alg) noexcept {
				switch (alg) {
				case SymmetricAlgorithm::AES_128_CBC:
				case SymmetricAlgorithm::AES_192_CBC:
				case SymmetricAlgorithm::AES_256_CBC: return BCRYPT_AES_ALGORITHM;
				case SymmetricAlgorithm::AES_128_GCM:
				case SymmetricAlgorithm::AES_192_GCM:
				case SymmetricAlgorithm::AES_256_GCM: return BCRYPT_AES_ALGORITHM;
				case SymmetricAlgorithm::AES_128_ECB:
				case SymmetricAlgorithm::AES_192_ECB:
				case SymmetricAlgorithm::AES_256_ECB: return BCRYPT_AES_ALGORITHM;
				case SymmetricAlgorithm::AES_128_CFB:
				case SymmetricAlgorithm::AES_192_CFB:
				case SymmetricAlgorithm::AES_256_CFB: return BCRYPT_AES_ALGORITHM;
				case SymmetricAlgorithm::ChaCha20_Poly1305: return L"ChaCha20-Poly1305";
				default: return BCRYPT_AES_ALGORITHM;
				}
			}

			static const wchar_t* ChainingMode(SymmetricAlgorithm alg) noexcept {
				switch (alg) {
				case SymmetricAlgorithm::AES_128_CBC:
				case SymmetricAlgorithm::AES_192_CBC:
				case SymmetricAlgorithm::AES_256_CBC: return BCRYPT_CHAIN_MODE_CBC;
				case SymmetricAlgorithm::AES_128_GCM:
				case SymmetricAlgorithm::AES_192_GCM:
				case SymmetricAlgorithm::AES_256_GCM: return BCRYPT_CHAIN_MODE_GCM;
				case SymmetricAlgorithm::AES_128_ECB:
				case SymmetricAlgorithm::AES_192_ECB:
				case SymmetricAlgorithm::AES_256_ECB: return BCRYPT_CHAIN_MODE_ECB;
				case SymmetricAlgorithm::AES_128_CFB:
				case SymmetricAlgorithm::AES_192_CFB:
				case SymmetricAlgorithm::AES_256_CFB: return BCRYPT_CHAIN_MODE_CFB;
				default: return BCRYPT_CHAIN_MODE_CBC;
				}
			}

			static size_t KeySizeForAlg(SymmetricAlgorithm alg) noexcept {
				switch (alg) {
				case SymmetricAlgorithm::AES_128_CBC:
				case SymmetricAlgorithm::AES_128_GCM:
				case SymmetricAlgorithm::AES_128_ECB:
				case SymmetricAlgorithm::AES_128_CFB: return 16;
				case SymmetricAlgorithm::AES_192_CBC:
				case SymmetricAlgorithm::AES_192_GCM:
				case SymmetricAlgorithm::AES_192_ECB:
				case SymmetricAlgorithm::AES_192_CFB: return 24;
				case SymmetricAlgorithm::AES_256_CBC:
				case SymmetricAlgorithm::AES_256_GCM:
				case SymmetricAlgorithm::AES_256_ECB:
				case SymmetricAlgorithm::AES_256_CFB:
				case SymmetricAlgorithm::ChaCha20_Poly1305: return 32;
				default: return 32;
				}
			}

			static size_t IVSizeForAlg(SymmetricAlgorithm alg) noexcept {
				switch (alg) {
				case SymmetricAlgorithm::AES_128_GCM:
				case SymmetricAlgorithm::AES_192_GCM:
				case SymmetricAlgorithm::AES_256_GCM: return 12;
				case SymmetricAlgorithm::ChaCha20_Poly1305: return 12;
				case SymmetricAlgorithm::AES_128_ECB:
				case SymmetricAlgorithm::AES_192_ECB:
				case SymmetricAlgorithm::AES_256_ECB: return 0;
				default: return 16;
				}
			}

			static bool IsAEADAlg(SymmetricAlgorithm alg) noexcept {
				return alg == SymmetricAlgorithm::AES_128_GCM ||
					alg == SymmetricAlgorithm::AES_192_GCM ||
					alg == SymmetricAlgorithm::AES_256_GCM ||
					alg == SymmetricAlgorithm::ChaCha20_Poly1305;
			}

			static const wchar_t* RSAAlgName(AsymmetricAlgorithm alg) noexcept {
				switch (alg) {
				case AsymmetricAlgorithm::RSA_1024:
				case AsymmetricAlgorithm::RSA_2048:
				case AsymmetricAlgorithm::RSA_3072:
				case AsymmetricAlgorithm::RSA_4096: return BCRYPT_RSA_ALGORITHM;
				case AsymmetricAlgorithm::ECC_P256:
				case AsymmetricAlgorithm::ECC_P384:
				case AsymmetricAlgorithm::ECC_P521: return BCRYPT_ECDH_P256_ALGORITHM;
				default: return BCRYPT_RSA_ALGORITHM;
				}
			}

			static ULONG RSAKeySizeForAlg(AsymmetricAlgorithm alg) noexcept {
				switch (alg) {
				case AsymmetricAlgorithm::RSA_1024: return 1024;
				case AsymmetricAlgorithm::RSA_2048: return 2048;
				case AsymmetricAlgorithm::RSA_3072: return 3072;
				case AsymmetricAlgorithm::RSA_4096: return 4096;
				case AsymmetricAlgorithm::ECC_P256: return 256;
				case AsymmetricAlgorithm::ECC_P384: return 384;
				case AsymmetricAlgorithm::ECC_P521: return 521;
				default: return 2048;
				}
			}

			// =============================================================================
			// Base64 helpers
			// =============================================================================
			namespace Base64 {
				std::string Encode(const uint8_t* data, size_t len) noexcept {
					std::string out;
					Utils::Base64EncodeOptions opt{};
					bool ok = Utils::Base64Encode(data, len, out, opt);
					if (!ok) out.clear();
					return out;
				}

				std::string Encode(const std::vector<uint8_t>& data) noexcept {
					return Encode(data.data(), data.size());
				}

				bool Decode(std::string_view base64, std::vector<uint8_t>& out) noexcept {
					Utils::Base64DecodeError derr = Utils::Base64DecodeError::None;
					Utils::Base64DecodeOptions opt{};
					return Utils::Base64Decode(base64, out, derr, opt);
				}
			}

			// =============================================================================
			// Secure compare (timing resistant)
			// =============================================================================
			bool SecureCompare(const uint8_t* a, const uint8_t* b, size_t len) noexcept {
				if (a == b) return true;
				if (!a || !b) return false;
				unsigned char acc = 0;
				for (size_t i = 0; i < len; ++i) {
					acc |= static_cast<unsigned char>(a[i] ^ b[i]);
				}
				return acc == 0;
			}

			bool SecureCompare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) noexcept {
				if (a.size() != b.size()) return false;
				return SecureCompare(a.data(), b.data(), a.size());
			}

			// =============================================================================
			// Secure memory wipe
			// =============================================================================
			void SecureZeroMemory(void* ptr, size_t size) noexcept {
#ifdef _WIN32
				if (ptr && size) {
					::RtlSecureZeroMemory(ptr, size);
				}
#else
				if (!ptr || !size) return;
				volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
				for (size_t i = 0; i < size; ++i) p[i] = 0;
#endif
			}

			// =============================================================================
			// Entropy helpers
			// =============================================================================
			double CalculateEntropy(const uint8_t* data, size_t len) noexcept {
				if (!data || len == 0) return 0.0;
				double freq[256] = { 0.0 };
				for (size_t i = 0; i < len; ++i) {
					freq[data[i]] += 1.0;
				}
				double invN = 1.0 / static_cast<double>(len);
				double H = 0.0;
				for (int i = 0; i < 256; ++i) {
					double p = freq[i] * invN;
					if (p > 0.0) {
						H -= p * std::log2(p);
					}
				}
				if (H < 0.0) H = 0.0;
				if (H > 8.0) H = 8.0;
				return H;
			}

			double CalculateEntropy(const std::vector<uint8_t>& data) noexcept {
				return CalculateEntropy(data.data(), data.size());
			}

			bool HasHighEntropy(const uint8_t* data, size_t len, double threshold) noexcept {
				return CalculateEntropy(data, len) >= threshold;
			}

			// =============================================================================
			// SecureRandom Implementation
			// =============================================================================
			SecureRandom::SecureRandom() noexcept {
#ifdef _WIN32
				NTSTATUS st = BCryptOpenAlgorithmProvider(&m_algHandle, BCRYPT_RNG_ALGORITHM, nullptr, 0);
				if (st >= 0 && m_algHandle) {
					m_initialized = true;
				}
#endif
			}

			SecureRandom::~SecureRandom() {
#ifdef _WIN32
				if (m_algHandle) {
					BCryptCloseAlgorithmProvider(m_algHandle, 0);
					m_algHandle = nullptr;
				}
#endif
				m_initialized = false;
			}

			bool SecureRandom::Generate(uint8_t* buffer, size_t size, Error* err) noexcept {
				if (!buffer || size == 0) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid buffer or size"; }
					return false;
				}
#ifdef _WIN32
				NTSTATUS st = 0;
				if (m_initialized && m_algHandle) {
					st = BCryptGenRandom(m_algHandle, buffer, static_cast<ULONG>(size), 0);
				}
				else {
					st = BCryptGenRandom(nullptr, buffer, static_cast<ULONG>(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
				}
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptGenRandom failed"; }
					return false;
				}
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool SecureRandom::Generate(std::vector<uint8_t>& out, size_t size, Error* err) noexcept {
				out.resize(size);
				if (size == 0) return true;
				return Generate(out.data(), size, err);
			}

			std::vector<uint8_t> SecureRandom::Generate(size_t size, Error* err) noexcept {
				std::vector<uint8_t> out;
				Generate(out, size, err);
				return out;
			}

			uint32_t SecureRandom::NextUInt32(Error* err) noexcept {
				uint32_t val = 0;
				if (!Generate(reinterpret_cast<uint8_t*>(&val), sizeof(val), err)) return 0;
				return val;
			}

			uint64_t SecureRandom::NextUInt64(Error* err) noexcept {
				uint64_t val = 0;
				if (!Generate(reinterpret_cast<uint8_t*>(&val), sizeof(val), err)) return 0;
				return val;
			}

			uint32_t SecureRandom::NextUInt32(uint32_t min, uint32_t max, Error* err) noexcept {
				if (min >= max) return min;
				const uint32_t range = max - min;
				const uint32_t limit = (UINT32_MAX / range) * range;
				uint32_t val = 0;
				do {
					val = NextUInt32(err);
				} while (val >= limit);
				return min + (val % range);
			}

			uint64_t SecureRandom::NextUInt64(uint64_t min, uint64_t max, Error* err) noexcept {
				if (min >= max) return min;
				const uint64_t range = max - min;
				const uint64_t limit = (UINT64_MAX / range) * range;
				uint64_t val = 0;
				do {
					val = NextUInt64(err);
				} while (val >= limit);
				return min + (val % range);
			}

			std::string SecureRandom::GenerateAlphanumeric(size_t length, Error* err) noexcept {
				static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
				static constexpr size_t alphaLen = sizeof(alphanum) - 1;
				std::string out;
				out.reserve(length);
				for (size_t i = 0; i < length; ++i) {
					uint32_t idx = NextUInt32(0, static_cast<uint32_t>(alphaLen), err);
					out.push_back(alphanum[idx]);
				}
				return out;
			}

			std::string SecureRandom::GenerateHex(size_t byteCount, Error* err) noexcept {
				std::vector<uint8_t> bytes;
				if (!Generate(bytes, byteCount, err)) return std::string();
				return HashUtils::ToHexLower(bytes.data(), bytes.size());
			}

			std::string SecureRandom::GenerateBase64(size_t byteCount, Error* err) noexcept {
				std::vector<uint8_t> bytes;
				if (!Generate(bytes, byteCount, err)) return std::string();
				return Base64::Encode(bytes);
			}

			// =============================================================================
			// SymmetricCipher Implementation
			// =============================================================================
			SymmetricCipher::SymmetricCipher(SymmetricAlgorithm algorithm) noexcept : m_algorithm(algorithm) {}

			SymmetricCipher::~SymmetricCipher() {
				cleanup();
			}

			SymmetricCipher::SymmetricCipher(SymmetricCipher&& other) noexcept
				: m_algorithm(other.m_algorithm), m_paddingMode(other.m_paddingMode),
#ifdef _WIN32
				m_algHandle(other.m_algHandle), m_keyHandle(other.m_keyHandle),
				m_keyObject(std::move(other.m_keyObject)),
#endif
				m_key(std::move(other.m_key)), m_iv(std::move(other.m_iv)),
				m_keySet(other.m_keySet), m_ivSet(other.m_ivSet)
			{
#ifdef _WIN32
				other.m_algHandle = nullptr;
				other.m_keyHandle = nullptr;
#endif
				other.m_keySet = false;
				other.m_ivSet = false;
			}

			SymmetricCipher& SymmetricCipher::operator=(SymmetricCipher&& other) noexcept {
				if (this != &other) {
					cleanup();
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
					other.m_keySet = false;
					other.m_ivSet = false;
				}
				return *this;
			}

			void SymmetricCipher::cleanup() noexcept {
#ifdef _WIN32
				if (m_keyHandle) {
					BCryptDestroyKey(m_keyHandle);
					m_keyHandle = nullptr;
				}
				if (m_algHandle) {
					BCryptCloseAlgorithmProvider(m_algHandle, 0);
					m_algHandle = nullptr;
				}
#endif
				SecureZeroMemory(m_key.data(), m_key.size());
				SecureZeroMemory(m_iv.data(), m_iv.size());
				m_key.clear();
				m_iv.clear();
				m_keyObject.clear();
				m_keySet = false;
				m_ivSet = false;
			}

			bool SymmetricCipher::ensureProvider(Error* err) noexcept {
#ifdef _WIN32
				if (m_algHandle) return true;

				const wchar_t* algName = AlgName(m_algorithm);
				NTSTATUS st = BCryptOpenAlgorithmProvider(&m_algHandle, algName, nullptr, 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptOpenAlgorithmProvider failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptOpenAlgorithmProvider failed: 0x%08X", st);
					return false;
				}

				const wchar_t* mode = ChainingMode(m_algorithm);
				st = BCryptSetProperty(m_algHandle, BCRYPT_CHAINING_MODE,
					reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(mode)),
					static_cast<ULONG>((wcslen(mode) + 1) * sizeof(wchar_t)), 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptSetProperty chaining mode failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptSetProperty chaining mode failed: 0x%08X", st);
					BCryptCloseAlgorithmProvider(m_algHandle, 0);
					m_algHandle = nullptr;
					return false;
				}

				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool SymmetricCipher::SetKey(const uint8_t* key, size_t keyLen, Error* err) noexcept {
				if (!key || keyLen == 0) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid key"; }
					return false;
				}

				const size_t expectedSize = GetKeySize();
				if (keyLen != expectedSize) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid key size"; }
					return false;
				}

				if (!ensureProvider(err)) return false;

#ifdef _WIN32
				if (m_keyHandle) {
					BCryptDestroyKey(m_keyHandle);
					m_keyHandle = nullptr;
				}

				m_key.assign(key, key + keyLen);

				DWORD objLen = 0, cbResult = 0;
				NTSTATUS st = BCryptGetProperty(m_algHandle, BCRYPT_OBJECT_LENGTH,
					reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen), &cbResult, 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptGetProperty OBJECT_LENGTH failed"; }
					return false;
				}

				m_keyObject.resize(objLen);

				st = BCryptGenerateSymmetricKey(m_algHandle, &m_keyHandle,
					m_keyObject.data(), static_cast<ULONG>(m_keyObject.size()),
					const_cast<uint8_t*>(m_key.data()), static_cast<ULONG>(m_key.size()), 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptGenerateSymmetricKey failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptGenerateSymmetricKey failed: 0x%08X", st);
					return false;
				}

				m_keySet = true;
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool SymmetricCipher::SetKey(const std::vector<uint8_t>& key, Error* err) noexcept {
				return SetKey(key.data(), key.size(), err);
			}

			bool SymmetricCipher::GenerateKey(std::vector<uint8_t>& outKey, Error* err) noexcept {
				const size_t keySize = GetKeySize();
				SecureRandom rng;
				if (!rng.Generate(outKey, keySize, err)) return false;
				return SetKey(outKey, err);
			}

			bool SymmetricCipher::SetIV(const uint8_t* iv, size_t ivLen, Error* err) noexcept {
				const size_t expectedSize = GetIVSize();
				if (expectedSize == 0) {
					m_ivSet = true;
					return true;
				}

				if (!iv || ivLen != expectedSize) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid IV size"; }
					return false;
				}

				m_iv.assign(iv, iv + ivLen);
				m_ivSet = true;
				return true;
			}

			bool SymmetricCipher::SetIV(const std::vector<uint8_t>& iv, Error* err) noexcept {
				return SetIV(iv.data(), iv.size(), err);
			}

			bool SymmetricCipher::GenerateIV(std::vector<uint8_t>& outIV, Error* err) noexcept {
				const size_t ivSize = GetIVSize();
				if (ivSize == 0) {
					outIV.clear();
					m_ivSet = true;
					return true;
				}

				SecureRandom rng;
				if (!rng.Generate(outIV, ivSize, err)) return false;
				return SetIV(outIV, err);
			}

			size_t SymmetricCipher::GetKeySize() const noexcept {
				return KeySizeForAlg(m_algorithm);
			}

			size_t SymmetricCipher::GetIVSize() const noexcept {
				return IVSizeForAlg(m_algorithm);
			}

			size_t SymmetricCipher::GetBlockSize() const noexcept {
				return 16;
			}

			size_t SymmetricCipher::GetTagSize() const noexcept {
				return IsAEAD() ? 16 : 0;
			}

			bool SymmetricCipher::IsAEAD() const noexcept {
				return IsAEADAlg(m_algorithm);
			}

			// BCrypt'in kendi padding sistemini kullan
			bool SymmetricCipher::Encrypt(const uint8_t* plaintext, size_t plaintextLen,
				std::vector<uint8_t>& ciphertext, Error* err) noexcept
			{
				if (!m_keySet) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Key not set"; }
					return false;
				}
				if (!m_ivSet && GetIVSize() > 0) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"IV not set"; }
					return false;
				}

				// Input validation
				if (!plaintext && plaintextLen != 0) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid input"; }
					return false;
				}

				// For AEAD modes, use separate function
				if (IsAEAD()) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->message = L"Use EncryptAEAD for AEAD modes";
					}
					return false;
				}
#ifdef _WIN32
				DWORD flags = 0;

				// BCrypt'in padding desteği varsa kullan
				if (m_paddingMode == PaddingMode::PKCS7) {
					flags = BCRYPT_BLOCK_PADDING; // BCrypt PKCS7 padding'i kendi yapar
				}

				ULONG cbResult = 0;
				NTSTATUS st = BCryptEncrypt(m_keyHandle,
					const_cast<uint8_t*>(plaintext), static_cast<ULONG>(plaintextLen),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					nullptr, 0, &cbResult, flags);

				if (st < 0) {
					if (err) {
						err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st);
						err->message = L"BCryptEncrypt size query failed";
					}
					return false;
				}

				ciphertext.resize(cbResult);
				st = BCryptEncrypt(m_keyHandle,
					const_cast<uint8_t*>(plaintext), static_cast<ULONG>(plaintextLen),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					ciphertext.data(), static_cast<ULONG>(ciphertext.size()), &cbResult, flags);

				if (st < 0) {
					if (err) {
						err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st);
						err->message = L"BCryptEncrypt failed";
					}
					return false;
				}

				ciphertext.resize(cbResult);
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool SymmetricCipher::Decrypt(const uint8_t* ciphertext, size_t ciphertextLen,
				std::vector<uint8_t>& plaintext, Error* err) noexcept
			{
				if (!m_keySet) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Key not set"; }
					return false;
				}
				if (!m_ivSet && GetIVSize() > 0) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"IV not set"; }
					return false;
				}

#ifdef _WIN32
				ULONG cbResult = 0;
				NTSTATUS st = BCryptDecrypt(m_keyHandle,
					const_cast<uint8_t*>(ciphertext), static_cast<ULONG>(ciphertextLen),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					nullptr, 0, &cbResult, 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDecrypt size query failed"; }
					return false;
				}

				plaintext.resize(cbResult);
				st = BCryptDecrypt(m_keyHandle,
					const_cast<uint8_t*>(ciphertext), static_cast<ULONG>(ciphertextLen),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					plaintext.data(), static_cast<ULONG>(plaintext.size()), &cbResult, 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDecrypt failed"; }
					return false;
				}

				plaintext.resize(cbResult);

				if (m_paddingMode != PaddingMode::None && !IsAEAD()) {
					if (!removePadding(plaintext, GetBlockSize())) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid padding"; }
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
				if (!IsAEAD()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Not an AEAD algorithm"; }
					return false;
				}

				if (!m_keySet || !m_ivSet) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Key or IV not set"; }
					return false;
				}

#ifdef _WIN32
				BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
				BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
				authInfo.pbNonce = m_iv.data();
				authInfo.cbNonce = static_cast<ULONG>(m_iv.size());
				authInfo.pbAuthData = const_cast<uint8_t*>(aad);
				authInfo.cbAuthData = static_cast<ULONG>(aadLen);

				tag.resize(GetTagSize());
				authInfo.pbTag = tag.data();
				authInfo.cbTag = static_cast<ULONG>(tag.size());
				authInfo.pbMacContext = nullptr;
				authInfo.cbMacContext = 0;
				authInfo.cbAAD = static_cast<ULONG>(aadLen);
				authInfo.cbData = 0;
				authInfo.dwFlags = 0;

				ULONG cbResult = 0;
				NTSTATUS st = BCryptEncrypt(m_keyHandle,
					const_cast<uint8_t*>(plaintext), static_cast<ULONG>(plaintextLen),
					&authInfo,
					nullptr, 0,
					nullptr, 0, &cbResult, 0);
				if (st < 0) {
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

#ifdef _WIN32
				BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
				BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
				authInfo.pbNonce = m_iv.data();
				authInfo.cbNonce = static_cast<ULONG>(m_iv.size());
				authInfo.pbAuthData = const_cast<uint8_t*>(aad);
				authInfo.cbAuthData = static_cast<ULONG>(aadLen);
				authInfo.pbTag = const_cast<uint8_t*>(tag);
				authInfo.cbTag = static_cast<ULONG>(tagLen);
				authInfo.pbMacContext = nullptr;
				authInfo.cbMacContext = 0;
				authInfo.cbAAD = static_cast<ULONG>(aadLen);
				authInfo.cbData = 0;
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
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"EncryptInit not called"; }
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

				// Gelen veriyi internal buffer'a ekle
				m_streamBuffer.insert(m_streamBuffer.end(), data, data + len);

				//encrypt the block-aligned data in the buffer
				const size_t blockSize = GetBlockSize();
				const size_t alignedSize = (m_streamBuffer.size() / blockSize) * blockSize;

				if (alignedSize == 0) {
					// there is not enough data to process a full block yet
					return true;
				}

#ifdef _WIN32
				std::vector<uint8_t> toEncrypt(m_streamBuffer.begin(), m_streamBuffer.begin() + alignedSize);

				ULONG cbResult = 0;
				NTSTATUS st = BCryptEncrypt(m_keyHandle,
					toEncrypt.data(), static_cast<ULONG>(toEncrypt.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					nullptr, 0, &cbResult, 0);
				if (st < 0) {
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
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptEncrypt failed"; }
					return false;
				}

				out.resize(cbResult);

				// update IV for modes that require it (CBC, CFB, OFB)
				if (!out.empty() && m_iv.size() == blockSize) {
					std::memcpy(m_iv.data(), out.data() + out.size() - blockSize, blockSize);
				}

				//Remove the processed data from the buffer
				m_streamBuffer.erase(m_streamBuffer.begin(), m_streamBuffer.begin() + alignedSize);

				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool SymmetricCipher::EncryptFinal(std::vector<uint8_t>& out, Error* err) noexcept {
				if (!m_keySet) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"EncryptInit not called"; }
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
				//Encrypt the remaining data with padding if needed
				if (m_paddingMode != PaddingMode::None) {
					if (!applyPadding(m_streamBuffer, GetBlockSize())) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Padding failed"; }
						return false;
					}
				}

				if (m_streamBuffer.empty()) {
					m_streamFinalized = true;
					return true;
				}

				ULONG cbResult = 0;
				NTSTATUS st = BCryptEncrypt(m_keyHandle,
					m_streamBuffer.data(), static_cast<ULONG>(m_streamBuffer.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					nullptr, 0, &cbResult, 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptEncrypt size query failed"; }
					return false;
				}

				out.resize(cbResult);
				st = BCryptEncrypt(m_keyHandle,
					m_streamBuffer.data(), static_cast<ULONG>(m_streamBuffer.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					out.data(), static_cast<ULONG>(out.size()), &cbResult, 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptEncrypt failed"; }
					return false;
				}

				out.resize(cbResult);
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

				m_streamBuffer.insert(m_streamBuffer.end(), data, data + len);

				const size_t blockSize = GetBlockSize();
				const size_t alignedSize = (m_streamBuffer.size() / blockSize) * blockSize;

				// hold the last block for padding
				const size_t keepSize = (m_paddingMode != PaddingMode::None && alignedSize > 0) ? blockSize : 0;
				const size_t processSize = (alignedSize > keepSize) ? (alignedSize - keepSize) : 0;

				if (processSize == 0) {
					return true;
				}

#ifdef _WIN32
				std::vector<uint8_t> toDecrypt(m_streamBuffer.begin(), m_streamBuffer.begin() + processSize);

				ULONG cbResult = 0;
				NTSTATUS st = BCryptDecrypt(m_keyHandle,
					toDecrypt.data(), static_cast<ULONG>(toDecrypt.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					nullptr, 0, &cbResult, 0);
				if (st < 0) {
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
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDecrypt failed"; }
					return false;
				}

				out.resize(cbResult);

				// update IV (for CBC mode)
				if (!toDecrypt.empty() && m_iv.size() == blockSize) {
					std::memcpy(m_iv.data(), toDecrypt.data() + toDecrypt.size() - blockSize, blockSize);
				}

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
				if (m_streamBuffer.empty()) {
					m_streamFinalized = true;
					return true;
				}

				ULONG cbResult = 0;
				NTSTATUS st = BCryptDecrypt(m_keyHandle,
					m_streamBuffer.data(), static_cast<ULONG>(m_streamBuffer.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					nullptr, 0, &cbResult, 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDecrypt size query failed"; }
					return false;
				}

				out.resize(cbResult);
				st = BCryptDecrypt(m_keyHandle,
					m_streamBuffer.data(), static_cast<ULONG>(m_streamBuffer.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					out.data(), static_cast<ULONG>(out.size()), &cbResult, 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDecrypt failed"; }
					return false;
				}

				out.resize(cbResult);

				//Remove padding if applied
				if (m_paddingMode != PaddingMode::None) {
					if (!removePadding(out, GetBlockSize())) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid padding"; }
						return false;
					}
				}

				m_streamBuffer.clear();
				m_streamFinalized = true;

				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool SymmetricCipher::applyPadding(std::vector<uint8_t>& data, size_t blockSize) noexcept {
				if (blockSize == 0 || m_paddingMode == PaddingMode::None) return true;

				//Validate block size
				if (blockSize > 256) {
					SS_LOG_ERROR(L"CryptoUtils", L"Invalid block size : %zu", blockSize);
					return false;
				}
				const size_t remainder = data.size() % blockSize;
				const size_t padLen = blockSize - remainder;

				if(padLen == 0 || padLen > blockSize) {
					SS_LOG_ERROR(L"CryptoUtils", L"Invalid padding length : %zu", padLen);
					return false;
				}

				//check for size overflow before resize
				if (data.size() > SIZE_MAX - padLen) {
					SS_LOG_ERROR(L"CryptoUtils", L"Data size overflow in padding");
					return false;
				}
				try {
					switch (m_paddingMode) {
					case PaddingMode::PKCS7: {
						const uint8_t padByte = static_cast<uint8_t>(padLen);
						data.insert(data.end(), padLen, padByte);
						break;
					}
					case PaddingMode::Zeros:
						data.insert(data.end(), padLen, 0x00);
						break;
					case PaddingMode::ANSIX923: {
						data.insert(data.end(), padLen - 1, 0x00);
						data.push_back(static_cast<uint8_t>(padLen));
						break;
					}
					case PaddingMode::ISO10126: {
						SecureRandom rng;
						std::vector<uint8_t> randBytes;
						if (!rng.Generate(randBytes, padLen - 1, nullptr)) return false;
						data.insert(data.end(), randBytes.begin(), randBytes.end());
						data.push_back(static_cast<uint8_t>(padLen));
						break;
					}
					default:
						return false;
					}
				}
				catch (const std::bad_alloc&) {
					SS_LOG_ERROR(L"CryptoUtils", L"Memory allocation failed during padding");
					return false;
				}

				return true;
			}

			bool SymmetricCipher::removePadding(std::vector<uint8_t>& data, size_t blockSize) noexcept {
				if (blockSize == 0 || m_paddingMode == PaddingMode::None) return true;
				if (data.empty() || data.size() % blockSize != 0) return false;

				switch (m_paddingMode) {
				case PaddingMode::PKCS7: {
					const uint8_t padLen = data.back();
					if (padLen == 0 || padLen > blockSize || padLen > data.size()) return false;
					for (size_t i = data.size() - padLen; i < data.size(); ++i) {
						if (data[i] != padLen) return false;
					}
					data.resize(data.size() - padLen);
					break;
				}
				case PaddingMode::Zeros: {
					while (!data.empty() && data.back() == 0x00) {
						data.pop_back();
					}
					break;
				}
				case PaddingMode::ANSIX923: {
					const uint8_t padLen = data.back();
					if (padLen == 0 || padLen > blockSize || padLen > data.size()) return false;
					for (size_t i = data.size() - padLen; i < data.size() - 1; ++i) {
						if (data[i] != 0x00) return false;
					}
					data.resize(data.size() - padLen);
					break;
				}
				case PaddingMode::ISO10126: {
					const uint8_t padLen = data.back();
					if (padLen == 0 || padLen > blockSize || padLen > data.size()) return false;
					data.resize(data.size() - padLen);
					break;
				}
				default:
					return false;
				}

				return true;
			}

			// =============================================================================
			// AsymmetricCipher Implementation (RSA/ECC stubs)
			// =============================================================================
			AsymmetricCipher::AsymmetricCipher(AsymmetricAlgorithm algorithm) noexcept : m_algorithm(algorithm) {}

			AsymmetricCipher::~AsymmetricCipher() {
				cleanup();
			}

			void AsymmetricCipher::cleanup() noexcept {
#ifdef _WIN32
				if (m_publicKeyHandle) {
					BCryptDestroyKey(m_publicKeyHandle);
					m_publicKeyHandle = nullptr;
				}
				if (m_privateKeyHandle) {
					BCryptDestroyKey(m_privateKeyHandle);
					m_privateKeyHandle = nullptr;
				}
				if (m_algHandle) {
					BCryptCloseAlgorithmProvider(m_algHandle, 0);
					m_algHandle = nullptr;
				}
#endif
				m_publicKeyLoaded = false;
				m_privateKeyLoaded = false;
			}

			bool AsymmetricCipher::ensureProvider(Error* err) noexcept {
#ifdef _WIN32
				if (m_algHandle) return true;

				const wchar_t* algName = RSAAlgName(m_algorithm);
				NTSTATUS st = BCryptOpenAlgorithmProvider(&m_algHandle, algName, nullptr, 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptOpenAlgorithmProvider failed for asymmetric"; }
					return false;
				}
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool AsymmetricCipher::GenerateKeyPair(KeyPair& outKeyPair, Error* err) noexcept {
#ifdef _WIN32
				if (!ensureProvider(err)) return false;

				BCRYPT_KEY_HANDLE hKey = nullptr;
				ULONG keySize = RSAKeySizeForAlg(m_algorithm);
				NTSTATUS st = BCryptGenerateKeyPair(m_algHandle, &hKey, keySize, 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptGenerateKeyPair failed"; }
					return false;
				}

				st = BCryptFinalizeKeyPair(hKey, 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptFinalizeKeyPair failed"; }
					BCryptDestroyKey(hKey);
					return false;
				}

				ULONG cbBlob = 0;
				st = BCryptExportKey(hKey, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &cbBlob, 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptExportKey public size query failed"; }
					BCryptDestroyKey(hKey);
					return false;
				}

				outKeyPair.publicKey.algorithm = m_algorithm;
				outKeyPair.publicKey.keyBlob.resize(cbBlob);
				st = BCryptExportKey(hKey, nullptr, BCRYPT_RSAPUBLIC_BLOB,
					outKeyPair.publicKey.keyBlob.data(), cbBlob, &cbBlob, 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptExportKey public failed"; }
					BCryptDestroyKey(hKey);
					return false;
				}

				cbBlob = 0;
				st = BCryptExportKey(hKey, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, nullptr, 0, &cbBlob, 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptExportKey private size query failed"; }
					BCryptDestroyKey(hKey);
					return false;
				}

				outKeyPair.privateKey.algorithm = m_algorithm;
				outKeyPair.privateKey.keyBlob.resize(cbBlob);
				st = BCryptExportKey(hKey, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB,
					outKeyPair.privateKey.keyBlob.data(), cbBlob, &cbBlob, 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptExportKey private failed"; }
					BCryptDestroyKey(hKey);
					return false;
				}

				BCryptDestroyKey(hKey);
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
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

				NTSTATUS st = BCryptImportKeyPair(m_algHandle, nullptr, BCRYPT_RSAPUBLIC_BLOB,
					&m_publicKeyHandle, const_cast<uint8_t*>(key.keyBlob.data()),
					static_cast<ULONG>(key.keyBlob.size()), 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptImportKeyPair public failed"; }
					return false;
				}

				m_publicKeyLoaded = true;
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

				NTSTATUS st = BCryptImportKeyPair(m_algHandle, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB,
					&m_privateKeyHandle, const_cast<uint8_t*>(key.keyBlob.data()),
					static_cast<ULONG>(key.keyBlob.size()), 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptImportKeyPair private failed"; }
					return false;
				}

				m_privateKeyLoaded = true;
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
				if (!m_publicKeyLoaded) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Public key not loaded"; }
					return false;
				}

#ifdef _WIN32
				BCRYPT_OAEP_PADDING_INFO paddingInfo{};
				paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
				paddingInfo.pbLabel = nullptr;
				paddingInfo.cbLabel = 0;

				ULONG cbResult = 0;
				NTSTATUS st = BCryptEncrypt(m_publicKeyHandle,
					const_cast<uint8_t*>(plaintext), static_cast<ULONG>(plaintextLen),
					&paddingInfo,
					nullptr, 0,
					nullptr, 0, &cbResult, BCRYPT_PAD_OAEP);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptEncrypt RSA size query failed"; }
					return false;
				}

				ciphertext.resize(cbResult);
				st = BCryptEncrypt(m_publicKeyHandle,
					const_cast<uint8_t*>(plaintext), static_cast<ULONG>(plaintextLen),
					&paddingInfo,
					nullptr, 0,
					ciphertext.data(), static_cast<ULONG>(ciphertext.size()), &cbResult, BCRYPT_PAD_OAEP);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptEncrypt RSA failed"; }
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
				BCRYPT_OAEP_PADDING_INFO paddingInfo{};
				paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
				paddingInfo.pbLabel = nullptr;
				paddingInfo.cbLabel = 0;

				ULONG cbResult = 0;
				NTSTATUS st = BCryptDecrypt(m_privateKeyHandle,
					const_cast<uint8_t*>(ciphertext), static_cast<ULONG>(ciphertextLen),
					&paddingInfo,
					nullptr, 0,
					nullptr, 0, &cbResult, BCRYPT_PAD_OAEP);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDecrypt RSA size query failed"; }
					return false;
				}

				plaintext.resize(cbResult);
				st = BCryptDecrypt(m_privateKeyHandle,
					const_cast<uint8_t*>(ciphertext), static_cast<ULONG>(ciphertextLen),
					&paddingInfo,
					nullptr, 0,
					plaintext.data(), static_cast<ULONG>(plaintext.size()), &cbResult, BCRYPT_PAD_OAEP);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDecrypt RSA failed"; }
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
				BCRYPT_PKCS1_PADDING_INFO paddingInfo{};
				paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

				ULONG cbResult = 0;
				NTSTATUS st = BCryptSignHash(m_privateKeyHandle,
					&paddingInfo,
					hash.data(), static_cast<ULONG>(hash.size()),
					nullptr, 0, &cbResult, BCRYPT_PAD_PKCS1);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptSignHash size query failed"; }
					return false;
				}

				signature.resize(cbResult);
				st = BCryptSignHash(m_privateKeyHandle,
					&paddingInfo,
					hash.data(), static_cast<ULONG>(hash.size()),
					signature.data(), static_cast<ULONG>(signature.size()), &cbResult, BCRYPT_PAD_PKCS1);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptSignHash failed"; }
					return false;
				}

				signature.resize(cbResult);
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
				BCRYPT_PKCS1_PADDING_INFO paddingInfo{};
				paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

				NTSTATUS st = BCryptVerifySignature(m_publicKeyHandle,
					&paddingInfo,
					hash.data(), static_cast<ULONG>(hash.size()),
					const_cast<uint8_t*>(signature), static_cast<ULONG>(signatureLen),
					BCRYPT_PAD_PKCS1);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptVerifySignature failed"; }
					return false;
				}

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
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"ECDH not implemented yet"; }
				return false;
			}

			size_t AsymmetricCipher::GetMaxPlaintextSize() const noexcept {
				const ULONG keySize = RSAKeySizeForAlg(m_algorithm);
				return (keySize / 8) - 66; // OAEP SHA-256 padding overhead
			}

			size_t AsymmetricCipher::GetSignatureSize() const noexcept {
				const ULONG keySize = RSAKeySizeForAlg(m_algorithm);
				return keySize / 8;
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


			// =============================================================================
			// PrivateKey Implementation
			// =============================================================================
			bool PrivateKey::Export(std::vector<uint8_t>& out, Error* err) const noexcept {
				out = keyBlob;
				return true;
			}

			bool PrivateKey::ExportPEM(std::string& out, bool encrypt, std::string_view password, Error* err) const noexcept {
				if (keyBlob.empty()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Key blob is empty"; }
					return false;
				}

				std::vector<uint8_t> dataToEncode = keyBlob;

				// If encryption requested, encrypt the DER blob first
				if (encrypt && !password.empty()) {
					// PKCS#8 encrypted private key format
					// Simple implementation: AES-256-CBC + PBKDF2

					KDFParams kdfParams{};
					kdfParams.algorithm = KDFAlgorithm::PBKDF2_SHA256;
					kdfParams.iterations = 10000;
					kdfParams.keyLength = 32;

					SecureRandom rng;
					std::vector<uint8_t> salt;
					if (!rng.Generate(salt, 16, err)) return false;
					kdfParams.salt = salt;

					std::vector<uint8_t> key;
					if (!KeyDerivation::DeriveKey(password, kdfParams, key, err)) return false;

					SymmetricCipher cipher(SymmetricAlgorithm::AES_256_CBC);
					if (!cipher.SetKey(key, err)) return false;

					std::vector<uint8_t> iv;
					if (!cipher.GenerateIV(iv, err)) return false;

					std::vector<uint8_t> encrypted;
					if (!cipher.Encrypt(keyBlob.data(), keyBlob.size(), encrypted, err)) return false;

					// Format: [SALT(16)] + [IV(16)] + [ENCRYPTED_DATA]
					dataToEncode.clear();
					dataToEncode.insert(dataToEncode.end(), salt.begin(), salt.end());
					dataToEncode.insert(dataToEncode.end(), iv.begin(), iv.end());
					dataToEncode.insert(dataToEncode.end(), encrypted.begin(), encrypted.end());
				}

				// Base64 encode
				std::string base64 = Base64::Encode(dataToEncode);
				if (base64.empty()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Base64 encoding failed"; }
					return false;
				}

				// PEM format
				std::ostringstream oss;
				if (encrypt && !password.empty()) {
					oss << "-----BEGIN ENCRYPTED PRIVATE KEY-----\n";
				}
				else {
					oss << "-----BEGIN PRIVATE KEY-----\n";
				}

				const size_t lineWidth = 64;
				for (size_t i = 0; i < base64.size(); i += lineWidth) {
					size_t chunkSize = std::min(lineWidth, base64.size() - i);
					oss << base64.substr(i, chunkSize) << "\n";
				}

				if (encrypt && !password.empty()) {
					oss << "-----END ENCRYPTED PRIVATE KEY-----\n";
				}
				else {
					oss << "-----END PRIVATE KEY-----\n";
				}

				out = oss.str();
				return true;
			}

			bool PrivateKey::Import(const uint8_t* data, size_t len, PrivateKey& out, Error* err) noexcept {
				if (!data || len == 0) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid input data"; }
					return false;
				}

				out.keyBlob.assign(data, data + len);
				return true;
			}
			// Helper for RSA PRIVATE KEY format
			static bool ImportPEM_RSAFormat(std::string_view pem, PrivateKey& out, std::string_view password, Error* err) noexcept {
				const std::string_view beginMarker = "-----BEGIN RSA PRIVATE KEY-----";
				const std::string_view endMarker = "-----END RSA PRIVATE KEY-----";

				size_t beginPos = pem.find(beginMarker);
				if (beginPos == std::string_view::npos) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"RSA PEM begin marker not found"; }
					return false;
				}

				size_t endPos = pem.find(endMarker, beginPos);
				if (endPos == std::string_view::npos) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"RSA PEM end marker not found"; }
					return false;
				}

				beginPos += beginMarker.size();
				std::string_view base64Content = pem.substr(beginPos, endPos - beginPos);

				std::string cleanBase64;
				cleanBase64.reserve(base64Content.size());
				for (char c : base64Content) {
					if (c != '\n' && c != '\r' && c != ' ' && c != '\t') {
						cleanBase64.push_back(c);
					}
				}

				std::vector<uint8_t> decoded;
				if (!Base64::Decode(cleanBase64, decoded)) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Base64 decoding failed"; }
					return false;
				}

				out.keyBlob = std::move(decoded);
				return true;
			}

			bool PrivateKey::ImportPEM(std::string_view pem, PrivateKey& out, std::string_view password, Error* err) noexcept {
				if (pem.empty()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"PEM string is empty"; }
					return false;
				}

				// Detect if encrypted
				bool isEncrypted = (pem.find("-----BEGIN ENCRYPTED PRIVATE KEY-----") != std::string_view::npos);

				const std::string_view beginMarker = isEncrypted ?
					"-----BEGIN ENCRYPTED PRIVATE KEY-----" :
					"-----BEGIN PRIVATE KEY-----";
				const std::string_view endMarker = isEncrypted ?
					"-----END ENCRYPTED PRIVATE KEY-----" :
					"-----END PRIVATE KEY-----";

				// Also support RSA PRIVATE KEY format
				if (pem.find(beginMarker) == std::string_view::npos) {
					if (pem.find("-----BEGIN RSA PRIVATE KEY-----") != std::string_view::npos) {
						// Fallback to RSA format
						return ImportPEM_RSAFormat(pem, out, password, err);
					}
				}

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

				beginPos += beginMarker.size();
				std::string_view base64Content = pem.substr(beginPos, endPos - beginPos);

				// Clean base64
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

				// If encrypted, decrypt
				if (isEncrypted) {
					if (password.empty()) {
						if (err) { err->win32 = ERROR_INVALID_PASSWORD; err->message = L"Password required for encrypted key"; }
						return false;
					}

					// Parse: [SALT(16)] + [IV(16)] + [ENCRYPTED_DATA]
					if (decoded.size() < 32) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Encrypted data too short"; }
						return false;
					}

					std::vector<uint8_t> salt(decoded.begin(), decoded.begin() + 16);
					std::vector<uint8_t> iv(decoded.begin() + 16, decoded.begin() + 32);
					const uint8_t* encryptedData = decoded.data() + 32;
					size_t encryptedSize = decoded.size() - 32;

					// Derive key
					KDFParams kdfParams{};
					kdfParams.algorithm = KDFAlgorithm::PBKDF2_SHA256;
					kdfParams.iterations = 10000;
					kdfParams.keyLength = 32;
					kdfParams.salt = salt;

					std::vector<uint8_t> key;
					if (!KeyDerivation::DeriveKey(password, kdfParams, key, err)) return false;

					// Decrypt
					SymmetricCipher cipher(SymmetricAlgorithm::AES_256_CBC);
					if (!cipher.SetKey(key, err)) return false;
					if (!cipher.SetIV(iv, err)) return false;

					std::vector<uint8_t> decrypted;
					if (!cipher.Decrypt(encryptedData, encryptedSize, decrypted, err)) return false;

					out.keyBlob = std::move(decrypted);
				}
				else {
					out.keyBlob = std::move(decoded);
				}

				return true;
			}

			

			void PrivateKey::SecureErase() noexcept {
				SecureZeroMemory(keyBlob.data(), keyBlob.size());
				keyBlob.clear();
			}

			// =============================================================================
			// KeyDerivation Implementation
			// =============================================================================
			bool KeyDerivation::PBKDF2(const uint8_t* password, size_t passwordLen,
				const uint8_t* salt, size_t saltLen,
				uint32_t iterations,
				HashUtils::Algorithm hashAlg,
				uint8_t* outKey, size_t keyLen,
				Error* err) noexcept
			{
#ifdef _WIN32
				BCRYPT_ALG_HANDLE hAlg = nullptr;
				const wchar_t* algName = BCRYPT_SHA256_ALGORITHM;
				switch (hashAlg) {
				case HashUtils::Algorithm::SHA1: algName = BCRYPT_SHA1_ALGORITHM; break;
				case HashUtils::Algorithm::SHA256: algName = BCRYPT_SHA256_ALGORITHM; break;
				case HashUtils::Algorithm::SHA384: algName = BCRYPT_SHA384_ALGORITHM; break;
				case HashUtils::Algorithm::SHA512: algName = BCRYPT_SHA512_ALGORITHM; break;
				default: algName = BCRYPT_SHA256_ALGORITHM; break;
				}

				NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, algName, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptOpenAlgorithmProvider failed for PBKDF2"; }
					return false;
				}

				st = BCryptDeriveKeyPBKDF2(hAlg,
					const_cast<uint8_t*>(password), static_cast<ULONG>(passwordLen),
					const_cast<uint8_t*>(salt), static_cast<ULONG>(saltLen),
					static_cast<ULONGLONG>(iterations),
					outKey, static_cast<ULONG>(keyLen), 0);

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
				// HKDF = Extract-then-Expand
				const size_t hashLen = HashUtils::DigestSize(hashAlg);
				std::vector<uint8_t> prk;

				// Extract: PRK = HMAC-Hash(salt, IKM)
				if (salt == nullptr || saltLen == 0) {
					std::vector<uint8_t> zeroSalt(hashLen, 0);
					if (!HashUtils::ComputeHmac(hashAlg, zeroSalt.data(), zeroSalt.size(), inputKeyMaterial, ikmLen, prk, nullptr)) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"HKDF Extract failed"; }
						return false;
					}
				}
				else {
					if (!HashUtils::ComputeHmac(hashAlg, salt, saltLen, inputKeyMaterial, ikmLen, prk, nullptr)) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"HKDF Extract failed"; }
						return false;
					}
				}

				// Expand: OKM = T(1) | T(2) | ... | T(N)
				std::vector<uint8_t> okm;
				std::vector<uint8_t> tPrev;
				const size_t n = (keyLen + hashLen - 1) / hashLen;

				for (size_t i = 1; i <= n; ++i) {
					std::vector<uint8_t> input;
					input.insert(input.end(), tPrev.begin(), tPrev.end());
					if (info && infoLen > 0) {
						input.insert(input.end(), info, info + infoLen);
					}
					input.push_back(static_cast<uint8_t>(i));

					std::vector<uint8_t> t;
					if (!HashUtils::ComputeHmac(hashAlg, prk.data(), prk.size(), input.data(), input.size(), t, nullptr)) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"HKDF Expand failed"; }
						return false;
					}

					okm.insert(okm.end(), t.begin(), t.end());
					tPrev = t;
				}

				std::memcpy(outKey, okm.data(), keyLen);
				return true;
			}

			bool KeyDerivation::DeriveKey(const uint8_t* password, size_t passwordLen,
				const KDFParams& params,
				std::vector<uint8_t>& outKey,
				Error* err) noexcept
			{
				outKey.resize(params.keyLength);

				std::vector<uint8_t> salt = params.salt;
				if (salt.empty()) {
					if (!GenerateSalt(salt, 32, err)) return false;
				}

				switch (params.algorithm) {
				case KDFAlgorithm::PBKDF2_SHA256:
					return PBKDF2(password, passwordLen, salt.data(), salt.size(), params.iterations, HashUtils::Algorithm::SHA256, outKey.data(), outKey.size(), err);
				case KDFAlgorithm::PBKDF2_SHA384:
					return PBKDF2(password, passwordLen, salt.data(), salt.size(), params.iterations, HashUtils::Algorithm::SHA384, outKey.data(), outKey.size(), err);
				case KDFAlgorithm::PBKDF2_SHA512:
					return PBKDF2(password, passwordLen, salt.data(), salt.size(), params.iterations, HashUtils::Algorithm::SHA512, outKey.data(), outKey.size(), err);
				case KDFAlgorithm::HKDF_SHA256:
					return HKDF(password, passwordLen, salt.data(), salt.size(), params.info.data(), params.info.size(), HashUtils::Algorithm::SHA256, outKey.data(), outKey.size(), err);
				case KDFAlgorithm::HKDF_SHA384:
					return HKDF(password, passwordLen, salt.data(), salt.size(), params.info.data(), params.info.size(), HashUtils::Algorithm::SHA384, outKey.data(), outKey.size(), err);
				case KDFAlgorithm::HKDF_SHA512:
					return HKDF(password, passwordLen, salt.data(), salt.size(), params.info.data(), params.info.size(), HashUtils::Algorithm::SHA512, outKey.data(), outKey.size(), err);
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
				return DeriveKey(reinterpret_cast<const uint8_t*>(password.data()), password.size(), params, outKey, err);
			}

			bool KeyDerivation::GenerateSalt(std::vector<uint8_t>& salt, size_t size, Error* err) noexcept {
				SecureRandom rng;
				return rng.Generate(salt, size, err);
			}

			// =============================================================================
			// Certificate Implementation
			// =============================================================================
			Certificate::~Certificate() {
				cleanup();
			}

			Certificate::Certificate(Certificate&& other) noexcept {
#ifdef _WIN32
				m_certContext = other.m_certContext;
				other.m_certContext = nullptr;
#endif
			}

			Certificate& Certificate::operator=(Certificate&& other) noexcept {
				if (this != &other) {
					cleanup();
#ifdef _WIN32
					m_certContext = other.m_certContext;
					other.m_certContext = nullptr;
#endif
				}
				return *this;
			}

			void Certificate::cleanup() noexcept {
#ifdef _WIN32
				if (m_certContext) {
					CertFreeCertificateContext(m_certContext);
					m_certContext = nullptr;
				}
#endif
			}

			bool Certificate::LoadFromFile(std::wstring_view path, Error* err) noexcept {
#ifdef _WIN32
				cleanup();

				std::vector<std::byte> data;
				FileUtils::Error fileErr{};
				if (!FileUtils::ReadAllBytes(path, data, &fileErr)) {
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to read certificate file"; }
					return false;
				}

				m_certContext = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
					reinterpret_cast<const BYTE*>(data.data()), static_cast<DWORD>(data.size()));

				if (!m_certContext) {
					if (err) { err->win32 = GetLastError(); err->message = L"CertCreateCertificateContext failed"; }
					return false;
				}

				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool Certificate::LoadFromMemory(const uint8_t* data, size_t len, Error* err) noexcept {
#ifdef _WIN32
				cleanup();

				m_certContext = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
					data, static_cast<DWORD>(len));

				if (!m_certContext) {
					if (err) { err->win32 = GetLastError(); err->message = L"CertCreateCertificateContext failed"; }
					return false;
				}

				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool Certificate::LoadFromStore(std::wstring_view storeName, std::wstring_view thumbprint, Error* err) noexcept {
#ifdef _WIN32
				cleanup();

				HCERTSTORE hStore = CertOpenSystemStoreW(0, storeName.data());
				if (!hStore) {
					if (err) { err->win32 = GetLastError(); err->message = L"CertOpenSystemStoreW failed"; }
					return false;
				}

				std::vector<uint8_t> thumbprintBytes;
				std::string thumbprintStr;
				thumbprintStr.reserve(thumbprint.size());
				for (wchar_t wc : thumbprint) {
					thumbprintStr.push_back(static_cast<char>(wc));
				}
				if (!HashUtils::FromHex(thumbprintStr, thumbprintBytes)) {
					CertCloseStore(hStore, 0);
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid thumbprint format"; }
					return false;
				}

				CRYPT_HASH_BLOB hashBlob{};
				hashBlob.cbData = static_cast<DWORD>(thumbprintBytes.size());
				hashBlob.pbData = thumbprintBytes.data();

				m_certContext = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
					0, CERT_FIND_HASH, &hashBlob, nullptr);

				CertCloseStore(hStore, 0);

				if (!m_certContext) {
					if (err) { err->win32 = GetLastError(); err->message = L"Certificate not found in store"; }
					return false;
				}

				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool Certificate::LoadFromPEM(std::string_view pem, Error* err) noexcept {
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"PEM loading not implemented yet"; }
				return false;
			}

			bool Certificate::Export(std::vector<uint8_t>& out, Error* err) const noexcept {
#ifdef _WIN32
				if (!m_certContext) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"No certificate loaded"; }
					return false;
				}

				out.assign(m_certContext->pbCertEncoded, m_certContext->pbCertEncoded + m_certContext->cbCertEncoded);
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool Certificate::ExportPEM(std::string& out, Error* err) const noexcept {
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"PEM export not implemented yet"; }
				return false;
			}

			bool Certificate::GetInfo(CertificateInfo& info, Error* err) const noexcept {
#ifdef _WIN32
				if (!m_certContext) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"No certificate loaded"; }
					return false;
				}

				// Subject
				DWORD subjectSize = CertGetNameStringW(m_certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
				if (subjectSize > 1) {
					std::wstring subject(subjectSize - 1, L'\0');
					CertGetNameStringW(m_certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, &subject[0], subjectSize);
					info.subject = subject;
				}

				// Issuer
				DWORD issuerSize = CertGetNameStringW(m_certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nullptr, nullptr, 0);
				if (issuerSize > 1) {
					std::wstring issuer(issuerSize - 1, L'\0');
					CertGetNameStringW(m_certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nullptr, &issuer[0], issuerSize);
					info.issuer = issuer;
				}

				// Validity
				info.notBefore = m_certContext->pCertInfo->NotBefore;
				info.notAfter = m_certContext->pCertInfo->NotAfter;

				FILETIME now;
				GetSystemTimeAsFileTime(&now);
				LONG cmp = CompareFileTime(&now, &info.notAfter);
				info.isExpired = (cmp > 0);

				// Serial number
				DWORD serialSize = m_certContext->pCertInfo->SerialNumber.cbData;
				if (serialSize > 0) {
					std::wstring serial;
					for (DWORD i = serialSize; i > 0; --i) {
						wchar_t buf[3];
						swprintf_s(buf, L"%02X", m_certContext->pCertInfo->SerialNumber.pbData[i - 1]);
						serial += buf;
					}
					info.serialNumber = serial;
				}

				// Thumbprint
				BYTE thumbprint[20] = {};
				DWORD thumbprintSize = sizeof(thumbprint);
				if (CertGetCertificateContextProperty(m_certContext, CERT_HASH_PROP_ID, thumbprint, &thumbprintSize)) {
					std::wstring thumb;
					for (DWORD i = 0; i < thumbprintSize; ++i) {
						wchar_t buf[3];
						swprintf_s(buf, L"%02X", thumbprint[i]);
						thumb += buf;
					}
					info.thumbprint = thumb;
				}

				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool Certificate::VerifySignature(const uint8_t* data, size_t dataLen,
				const uint8_t* signature, size_t signatureLen,
				Error* err) const noexcept
			{
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Signature verification not implemented yet"; }
				return false;
			}

			bool Certificate::VerifyChain(Error* err) const noexcept {
#ifdef _WIN32
				if (!m_certContext) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"No certificate loaded"; }
					return false;
				}

				CERT_CHAIN_PARA chainPara = {};
				chainPara.cbSize = sizeof(chainPara);

				PCCERT_CHAIN_CONTEXT pChainContext = nullptr;
				BOOL ok = CertGetCertificateChain(nullptr, m_certContext, nullptr, nullptr, &chainPara, 0, nullptr, &pChainContext);

				if (!ok || !pChainContext) {
					if (err) { err->win32 = GetLastError(); err->message = L"CertGetCertificateChain failed"; }
					return false;
				}

				bool valid = (pChainContext->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR);
				CertFreeCertificateChain(pChainContext);

				if (!valid && err) {
					err->win32 = ERROR_INVALID_DATA;
					err->message = L"Certificate chain verification failed";
				}

				return valid;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool Certificate::VerifyAgainstCA(const Certificate& caCert, Error* err) const noexcept {
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"CA verification not implemented yet"; }
				return false;
			}

			bool Certificate::ExtractPublicKey(PublicKey& outKey, Error* err) const noexcept {
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Public key extraction not implemented yet"; }
				return false;
			}

			// =============================================================================
			// SecureBuffer Implementation
			// =============================================================================
			template<typename T>
			SecureBuffer<T>::SecureBuffer(size_t size) : m_size(0) {
				if (size > 0) allocate(size);
			}

			template<typename T>
			SecureBuffer<T>::~SecureBuffer() {
				deallocate();
			}

			template<typename T>
			SecureBuffer<T>::SecureBuffer(SecureBuffer&& other) noexcept
				: m_data(other.m_data), m_size(other.m_size)
			{
				other.m_data = nullptr;
				other.m_size = 0;
			}

			template<typename T>
			SecureBuffer<T>& SecureBuffer<T>::operator=(SecureBuffer&& other) noexcept {
				if (this != &other) {
					deallocate();
					m_data = other.m_data;
					m_size = other.m_size;
					other.m_data = nullptr;
					other.m_size = 0;
				}
				return *this;
			}

			template<typename T>
			void SecureBuffer<T>::Resize(size_t newSize) {
				if (newSize == m_size) return;
				deallocate();
				if (newSize > 0) allocate(newSize);
			}

			template<typename T>
			void SecureBuffer<T>::Clear() {
				deallocate();
			}

			template<typename T>
			void SecureBuffer<T>::CopyFrom(const T* src, size_t count) {
				Resize(count);
				if (count > 0 && m_data && src) {
					std::memcpy(m_data, src, count * sizeof(T));
				}
			}

			template<typename T>
			void SecureBuffer<T>::CopyFrom(const std::vector<T>& src) {
				CopyFrom(src.data(), src.size());
			}

			template<typename T>
			void SecureBuffer<T>::allocate(size_t size) {
#ifdef _WIN32
				m_data = static_cast<T*>(VirtualAlloc(nullptr, size * sizeof(T), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
				if (m_data) {
					m_size = size;
					VirtualLock(m_data, m_size * sizeof(T));
				}
#else
				m_data = static_cast<T*>(std::malloc(size * sizeof(T)));
				if (m_data) m_size = size;
#endif
			}

			template<typename T>
			void SecureBuffer<T>::deallocate() {
				if (m_data) {
					SecureZeroMemory(m_data, m_size * sizeof(T));
#ifdef _WIN32
					VirtualUnlock(m_data, m_size * sizeof(T));
					VirtualFree(m_data, 0, MEM_RELEASE);
#else
					std::free(m_data);
#endif
					m_data = nullptr;
					m_size = 0;
				}
			}

			// Explicit instantiation
			template class SecureBuffer<uint8_t>;
			template class SecureBuffer<char>;
			template class SecureBuffer<wchar_t>;

			// =============================================================================
			// SecureString Implementation
			// =============================================================================
			SecureString::SecureString(std::string_view str) {
				Assign(str);
			}

			SecureString::SecureString(std::wstring_view str) {
				Assign(str);
			}

			SecureString::~SecureString() {
				Clear();
			}

			SecureString::SecureString(SecureString&& other) noexcept
				: m_buffer(std::move(other.m_buffer))
			{
			}

			SecureString& SecureString::operator=(SecureString&& other) noexcept {
				if (this != &other) {
					m_buffer = std::move(other.m_buffer);
				}
				return *this;
			}

			void SecureString::Assign(std::string_view str) {
				m_buffer.CopyFrom(str.data(), str.size() + 1);
			}

			void SecureString::Assign(std::wstring_view str) {
				// UTF-16 → UTF-8 conversion using Windows API
				if (str.empty()) {
					Clear();
					return;
				}

				int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, str.data(), static_cast<int>(str.size()),
					nullptr, 0, nullptr, nullptr);
				if (sizeNeeded <= 0) {
					Clear();
					return;
				}

				std::string narrow(sizeNeeded, '\0');
				WideCharToMultiByte(CP_UTF8, 0, str.data(), static_cast<int>(str.size()),
					&narrow[0], sizeNeeded, nullptr, nullptr);

				Assign(narrow);
			}

			void SecureString::Clear() {
				m_buffer.Clear();
			}

			std::string_view SecureString::ToStringView() const noexcept {
				if (m_buffer.Empty()) return std::string_view();
				return std::string_view(m_buffer.Data(), m_buffer.Size() > 0 ? m_buffer.Size() - 1 : 0);
			}

			// =============================================================================
			// High-Level File Encryption/Decryption
			// =============================================================================
			bool EncryptFile(std::wstring_view inputPath,
				std::wstring_view outputPath,
				const uint8_t* key, size_t keyLen,
				Error* err) noexcept
			{
				SymmetricCipher cipher(SymmetricAlgorithm::AES_256_GCM);
				if (!cipher.SetKey(key, keyLen, err)) return false;

				std::vector<uint8_t> iv;
				if (!cipher.GenerateIV(iv, err)) return false;

				std::vector<std::byte> plaintext;
				FileUtils::Error fileErr{};
				if (!FileUtils::ReadAllBytes(inputPath, plaintext, &fileErr)) {
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to read input file"; }
					return false;
				}

				std::vector<uint8_t> ciphertext, tag;
				if (!cipher.EncryptAEAD(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
					nullptr, 0, ciphertext, tag, err))
				{
					return false;
				}

				// Format: [IV_SIZE][IV][TAG_SIZE][TAG][CIPHERTEXT]
				std::vector<std::byte> output;
				const uint32_t ivSize = static_cast<uint32_t>(iv.size());
				const uint32_t tagSize = static_cast<uint32_t>(tag.size());

				output.insert(output.end(), reinterpret_cast<const std::byte*>(&ivSize), reinterpret_cast<const std::byte*>(&ivSize) + sizeof(ivSize));
				output.insert(output.end(), reinterpret_cast<const std::byte*>(iv.data()), reinterpret_cast<const std::byte*>(iv.data()) + iv.size());
				output.insert(output.end(), reinterpret_cast<const std::byte*>(&tagSize), reinterpret_cast<const std::byte*>(&tagSize) + sizeof(tagSize));
				output.insert(output.end(), reinterpret_cast<const std::byte*>(tag.data()), reinterpret_cast<const std::byte*>(tag.data()) + tag.size());
				output.insert(output.end(), reinterpret_cast<const std::byte*>(ciphertext.data()), reinterpret_cast<const std::byte*>(ciphertext.data()) + ciphertext.size());

				if (!FileUtils::WriteAllBytesAtomic(outputPath, output, &fileErr)) {
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to write output file"; }
					return false;
				}

				return true;
			}

			bool DecryptFile(std::wstring_view inputPath,
				std::wstring_view outputPath,
				const uint8_t* key, size_t keyLen,
				Error* err) noexcept
			{
				std::vector<std::byte> encrypted;
				FileUtils::Error fileErr{};
				if (!FileUtils::ReadAllBytes(inputPath, encrypted, &fileErr)) {
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to read encrypted file"; }
					return false;
				}
				if (encrypted.size() < sizeof(uint32_t) * 2 + 12 + 16) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid encrypted file format"; }
					return false;
				}
				size_t offset = 0;
				uint32_t ivSize = 0;
				std::memcpy(&ivSize, encrypted.data() + offset, sizeof(ivSize));
				offset += sizeof(ivSize);
				std::vector<uint8_t> iv(ivSize);
				std::memcpy(iv.data(), encrypted.data() + offset, ivSize);
				offset += ivSize;
				uint32_t tagSize = 0;
				std::memcpy(&tagSize, encrypted.data() + offset, sizeof(tagSize));
				offset += sizeof(tagSize);
				std::vector<uint8_t> tag(tagSize);
				std::memcpy(tag.data(), encrypted.data() + offset, tagSize);
				offset += tagSize;
				const size_t ciphertextSize = encrypted.size() - offset;
				const uint8_t* ciphertext = reinterpret_cast<const uint8_t*>(encrypted.data() + offset);
				SymmetricCipher cipher(SymmetricAlgorithm::AES_256_GCM);
				if (!cipher.SetKey(key, keyLen, err)) return false;
				if (!cipher.SetIV(iv, err)) return false;
				std::vector<uint8_t> plaintext;
				if (!cipher.DecryptAEAD(ciphertext, ciphertextSize, nullptr, 0, tag.data(), tag.size(), plaintext, err)) {
					return false;
				}

				//uint8_t --> std::byte
				std::vector<std::byte> output;
				output.reserve(plaintext.size());
				std::transform(plaintext.begin(), plaintext.end(), std::back_inserter(output),
					[](uint8_t b) { return static_cast<std::byte>(b); }
				);

				if (!FileUtils::WriteAllBytesAtomic(outputPath, output, &fileErr)) {
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to write output file"; }
					return false;
				}
				return true;
			}

			bool EncryptFileWithPassword(std::wstring_view inputPath,
				std::wstring_view outputPath,
				std::string_view password,
				Error* err) noexcept
			{
				KDFParams kdfParams{};
				kdfParams.algorithm = KDFAlgorithm::PBKDF2_SHA256;
				kdfParams.iterations = 100000;
				kdfParams.keyLength = 32;

				SecureRandom rng;
				std::vector<uint8_t> salt;
				if (!rng.Generate(salt, 32, err)) return false;
				kdfParams.salt = salt;

				std::vector<uint8_t> key;
				if (!KeyDerivation::DeriveKey(password, kdfParams, key, err)) return false;

				std::vector<std::byte> plaintext;
				FileUtils::Error fileErr{};
				if (!FileUtils::ReadAllBytes(inputPath, plaintext, &fileErr)) {
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to read input file"; }
					return false;
				}

				SymmetricCipher cipher(SymmetricAlgorithm::AES_256_GCM);
				if (!cipher.SetKey(key, err)) return false;

				std::vector<uint8_t> iv;
				if (!cipher.GenerateIV(iv, err)) return false;

				std::vector<uint8_t> ciphertext, tag;
				if (!cipher.EncryptAEAD(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
					nullptr, 0, ciphertext, tag, err))
				{
					return false;
				}

				// Format: [SALT_SIZE][SALT][IV_SIZE][IV][TAG_SIZE][TAG][CIPHERTEXT]
				std::vector<std::byte> output;
				const uint32_t saltSize = static_cast<uint32_t>(salt.size());
				const uint32_t ivSize = static_cast<uint32_t>(iv.size());
				const uint32_t tagSize = static_cast<uint32_t>(tag.size());

				output.insert(output.end(), reinterpret_cast<const std::byte*>(&saltSize), reinterpret_cast<const std::byte*>(&saltSize) + sizeof(saltSize));
				output.insert(output.end(), reinterpret_cast<const std::byte*>(salt.data()), reinterpret_cast<const std::byte*>(salt.data()) + salt.size());
				output.insert(output.end(), reinterpret_cast<const std::byte*>(&ivSize), reinterpret_cast<const std::byte*>(&ivSize) + sizeof(ivSize));
				output.insert(output.end(), reinterpret_cast<const std::byte*>(iv.data()), reinterpret_cast<const std::byte*>(iv.data()) + iv.size());
				output.insert(output.end(), reinterpret_cast<const std::byte*>(&tagSize), reinterpret_cast<const std::byte*>(&tagSize) + sizeof(tagSize));
				output.insert(output.end(), reinterpret_cast<const std::byte*>(tag.data()), reinterpret_cast<const std::byte*>(tag.data()) + tag.size());
				output.insert(output.end(), reinterpret_cast<const std::byte*>(ciphertext.data()), reinterpret_cast<const std::byte*>(ciphertext.data()) + ciphertext.size());

				if (!FileUtils::WriteAllBytesAtomic(outputPath, output, &fileErr)) {
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to write output file"; }
					return false;
				}

				return true;
			}

			bool DecryptFileWithPassword(std::wstring_view inputPath,
				std::wstring_view outputPath,
				std::string_view password,
				Error* err) noexcept
			{
				std::vector<std::byte> encrypted;
				FileUtils::Error fileErr{};
				if (!FileUtils::ReadAllBytes(inputPath, encrypted, &fileErr)) {
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to read encrypted file"; }
					return false;
				}

				if (encrypted.size() < sizeof(uint32_t) * 3 + 32 + 12 + 16) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid encrypted file format"; }
					return false;
				}

				size_t offset = 0;
				uint32_t saltSize = 0;
				std::memcpy(&saltSize, encrypted.data() + offset, sizeof(saltSize));
				offset += sizeof(saltSize);

				std::vector<uint8_t> salt(saltSize);
				std::memcpy(salt.data(), encrypted.data() + offset, saltSize);
				offset += saltSize;

				uint32_t ivSize = 0;
				std::memcpy(&ivSize, encrypted.data() + offset, sizeof(ivSize));
				offset += sizeof(ivSize);

				std::vector<uint8_t> iv(ivSize);
				std::memcpy(iv.data(), encrypted.data() + offset, ivSize);
				offset += ivSize;

				uint32_t tagSize = 0;
				std::memcpy(&tagSize, encrypted.data() + offset, sizeof(tagSize));
				offset += sizeof(tagSize);

				std::vector<uint8_t> tag(tagSize);
				std::memcpy(tag.data(), encrypted.data() + offset, tagSize);
				offset += tagSize;

				KDFParams kdfParams{};
				kdfParams.algorithm = KDFAlgorithm::PBKDF2_SHA256;
				kdfParams.iterations = 100000;
				kdfParams.keyLength = 32;
				kdfParams.salt = salt;

				std::vector<uint8_t> key;
				if (!KeyDerivation::DeriveKey(password, kdfParams, key, err)) return false;

				const size_t ciphertextSize = encrypted.size() - offset;
				const uint8_t* ciphertext = reinterpret_cast<const uint8_t*>(encrypted.data() + offset);

				SymmetricCipher cipher(SymmetricAlgorithm::AES_256_GCM);
				if (!cipher.SetKey(key, err)) return false;
				if (!cipher.SetIV(iv, err)) return false;

				std::vector<uint8_t> plaintext;
				if (!cipher.DecryptAEAD(ciphertext, ciphertextSize, nullptr, 0, tag.data(), tag.size(), plaintext, err)) {
					return false;
				}

				std::vector<std::byte> output;
				output.reserve(plaintext.size());
				std::transform(plaintext.begin(), plaintext.end(), std::back_inserter(output),
					[](uint8_t b) { return static_cast<std::byte>(b); }
				);
				if (!FileUtils::WriteAllBytesAtomic(outputPath, output, &fileErr)) {
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to write output file"; }
					return false;
				}

				return true;
			}

			bool EncryptString(std::string_view plaintext,
				const uint8_t* key, size_t keyLen,
				std::string& outBase64Ciphertext,
				Error* err) noexcept
			{
				SymmetricCipher cipher(SymmetricAlgorithm::AES_256_GCM);
				if (!cipher.SetKey(key, keyLen, err)) return false;

				std::vector<uint8_t> iv;
				if (!cipher.GenerateIV(iv, err)) return false;

				std::vector<uint8_t> ciphertext, tag;
				if (!cipher.EncryptAEAD(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
					nullptr, 0, ciphertext, tag, err))
				{
					return false;
				}

				std::vector<uint8_t> combined;
				const uint32_t ivSize = static_cast<uint32_t>(iv.size());
				const uint32_t tagSize = static_cast<uint32_t>(tag.size());

				combined.insert(combined.end(), reinterpret_cast<const uint8_t*>(&ivSize), reinterpret_cast<const uint8_t*>(&ivSize) + sizeof(ivSize));
				combined.insert(combined.end(), iv.begin(), iv.end());
				combined.insert(combined.end(), reinterpret_cast<const uint8_t*>(&tagSize), reinterpret_cast<const uint8_t*>(&tagSize) + sizeof(tagSize));
				combined.insert(combined.end(), tag.begin(), tag.end());
				combined.insert(combined.end(), ciphertext.begin(), ciphertext.end());

				outBase64Ciphertext = Base64::Encode(combined);
				return true;
			}

			bool DecryptString(std::string_view base64Ciphertext,
				const uint8_t* key, size_t keyLen,
				std::string& outPlaintext,
				Error* err) noexcept
			{
				std::vector<uint8_t> combined;
				if (!Base64::Decode(base64Ciphertext, combined)) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Base64 decode failed"; }
					return false;
				}

				if (combined.size() < sizeof(uint32_t) * 2 + 12 + 16) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid encrypted data format"; }
					return false;
				}

				size_t offset = 0;
				uint32_t ivSize = 0;
				std::memcpy(&ivSize, combined.data() + offset, sizeof(ivSize));
				offset += sizeof(ivSize);

				std::vector<uint8_t> iv(ivSize);
				std::memcpy(iv.data(), combined.data() + offset, ivSize);
				offset += ivSize;

				uint32_t tagSize = 0;
				std::memcpy(&tagSize, combined.data() + offset, sizeof(tagSize));
				offset += sizeof(tagSize);

				std::vector<uint8_t> tag(tagSize);
				std::memcpy(tag.data(), combined.data() + offset, tagSize);
				offset += tagSize;

				const size_t ciphertextSize = combined.size() - offset;
				const uint8_t* ciphertext = combined.data() + offset;

				SymmetricCipher cipher(SymmetricAlgorithm::AES_256_GCM);
				if (!cipher.SetKey(key, keyLen, err)) return false;
				if (!cipher.SetIV(iv, err)) return false;

				std::vector<uint8_t> plaintext;
				if (!cipher.DecryptAEAD(ciphertext, ciphertextSize, nullptr, 0, tag.data(), tag.size(), plaintext, err)) {
					return false;
				}

				outPlaintext.assign(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
				return true;
			}

			// =============================================================================
			// PE Signature Verification
			// =============================================================================
			bool VerifyPESignature(std::wstring_view filePath,
				SignatureInfo& info,
				Error* err) noexcept
			{
#ifdef _WIN32
				std::memset(&info, 0, sizeof(info));

				WINTRUST_FILE_INFO fileInfo = {};
				fileInfo.cbStruct = sizeof(fileInfo);
				fileInfo.pcwszFilePath = filePath.data();

				GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

				WINTRUST_DATA winTrustData = {};
				winTrustData.cbStruct = sizeof(winTrustData);
				winTrustData.dwUIChoice = WTD_UI_NONE;
				winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
				winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
				winTrustData.pFile = &fileInfo;
				winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
				winTrustData.dwProvFlags = WTD_SAFER_FLAG;

				LONG status = WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

				info.isSigned = (status == ERROR_SUCCESS || status == TRUST_E_NOSIGNATURE || status == TRUST_E_SUBJECT_NOT_TRUSTED);
				info.isVerified = (status == ERROR_SUCCESS);

				if (status == ERROR_SUCCESS) {
					// Get signer info
					CRYPT_PROVIDER_DATA* pProvData = WTHelperProvDataFromStateData(winTrustData.hWVTStateData);
					if (pProvData) {
						CRYPT_PROVIDER_SGNR* pSigner = WTHelperGetProvSignerFromChain(pProvData, 0, FALSE, 0);
						if (pSigner) {
							// Get the certificate context from CRYPT_PROVIDER_CERT
							CRYPT_PROVIDER_CERT* pCert = WTHelperGetProvCertFromChain(pSigner, 0);
							if (pCert && pCert->pCert) {
								PCCERT_CONTEXT pCertContext = pCert->pCert;

								// Extract subject name
								DWORD subjectSize = CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
								if (subjectSize > 1) {
									std::wstring subject(subjectSize - 1, L'\0');
									CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, &subject[0], subjectSize);
									info.signerName = subject;
								}

								// Extract issuer
								DWORD issuerSize = CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nullptr, nullptr, 0);
								if (issuerSize > 1) {
									std::wstring issuer(issuerSize - 1, L'\0');
									CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nullptr, &issuer[0], issuerSize);
									info.issuerName = issuer;
								}

								// Thumbprint
								BYTE thumbprint[20] = {};
								DWORD thumbprintSize = sizeof(thumbprint);
								if (CertGetCertificateContextProperty(pCertContext, CERT_HASH_PROP_ID, thumbprint, &thumbprintSize)) {
									std::wstring thumb;
									for (DWORD i = 0; i < thumbprintSize; ++i) {
										wchar_t buf[3];
										swprintf_s(buf, L"%02X", thumbprint[i]);
										thumb += buf;
									}
									info.thumbprint = thumb;
								}
							}
						}
					}
				}

				winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
				WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool VerifyCatalogSignature(std::wstring_view catalogPath,
				std::wstring_view fileHash,
				SignatureInfo& info,
				Error* err) noexcept
			{
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Catalog signature verification not implemented yet"; }
				return false;
			}

		} // namespace CryptoUtils
	} // namespace Utils
} // namespace ShadowStrike
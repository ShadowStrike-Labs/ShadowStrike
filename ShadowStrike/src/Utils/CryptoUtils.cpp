
#include "CryptoUtils.hpp"
#include "Base64Utils.hpp"
#include "HashUtils.hpp"
#include "FileUtils.hpp"
#include"Logger.hpp"

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
#ifndef CERT_KEY_CERT_SIGN_KEY_USAGE
#define CERT_KEY_CERT_SIGN_KEY_USAGE 0x04  // Bit 5 (keyCertSign)
#endif



#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0A00
#endif


#  include <Windows.h>


#  include <wincrypt.h>  
#  include <wintrust.h>  
#  include <softpub.h>    
#  include <bcrypt.h>  
#  include <ncrypt.h>    
#  include <mscat.h>    
#  include <ntstatus.h>   


#  pragma comment(lib, "crypt32.lib")
#  pragma comment(lib, "wintrust.lib")
#  pragma comment(lib, "bcrypt.lib")
#  pragma comment(lib, "ncrypt.lib")
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
				case SymmetricAlgorithm::AES_128_CFB:
				case SymmetricAlgorithm::AES_192_CFB:
				case SymmetricAlgorithm::AES_256_CFB: return BCRYPT_AES_ALGORITHM;
				case SymmetricAlgorithm::ChaCha20_Poly1305: return L"ChaCha20-Poly1305";
			 
				default: return nullptr;
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
				case SymmetricAlgorithm::AES_128_CFB:
				case SymmetricAlgorithm::AES_192_CFB:
				case SymmetricAlgorithm::AES_256_CFB: return BCRYPT_CHAIN_MODE_CFB;
				default: return nullptr;
				}
			}

			static size_t KeySizeForAlg(SymmetricAlgorithm alg) noexcept {
				switch (alg) {
				case SymmetricAlgorithm::AES_128_CBC:
				case SymmetricAlgorithm::AES_128_GCM:
				case SymmetricAlgorithm::AES_128_CFB: return 16;
				case SymmetricAlgorithm::AES_192_CBC:
				case SymmetricAlgorithm::AES_192_GCM:
				case SymmetricAlgorithm::AES_192_CFB: return 24;
				case SymmetricAlgorithm::AES_256_CBC:
				case SymmetricAlgorithm::AES_256_GCM:
				case SymmetricAlgorithm::AES_256_CFB:
				case SymmetricAlgorithm::ChaCha20_Poly1305: return 32;
				default: return 0;
				}
			}

			static size_t IVSizeForAlg(SymmetricAlgorithm alg) noexcept {
				switch (alg) {
				case SymmetricAlgorithm::AES_128_GCM:
				case SymmetricAlgorithm::AES_192_GCM:
				case SymmetricAlgorithm::AES_256_GCM: return 12;
				case SymmetricAlgorithm::ChaCha20_Poly1305: return 12;
				case SymmetricAlgorithm::AES_128_CBC:
				case SymmetricAlgorithm::AES_192_CBC:
				case SymmetricAlgorithm::AES_256_CBC:
				case SymmetricAlgorithm::AES_128_CFB:
				case SymmetricAlgorithm::AES_192_CFB:
				case SymmetricAlgorithm::AES_256_CFB: return 16;

					//Unknown Algorithm
				default: return 0;
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
				case AsymmetricAlgorithm::RSA_2048:
				case AsymmetricAlgorithm::RSA_3072:
				case AsymmetricAlgorithm::RSA_4096: return BCRYPT_RSA_ALGORITHM;

				case AsymmetricAlgorithm::ECC_P256:
					return BCRYPT_ECDH_P256_ALGORITHM;
				case AsymmetricAlgorithm::ECC_P384:
					return BCRYPT_ECDH_P384_ALGORITHM;
				case AsymmetricAlgorithm::ECC_P521:
					return BCRYPT_ECDH_P521_ALGORITHM;

				default:
					return nullptr;
				}
			}

			static ULONG RSAKeySizeForAlg(AsymmetricAlgorithm alg) noexcept {
				switch (alg) {
				case AsymmetricAlgorithm::RSA_2048: return 2048;
				case AsymmetricAlgorithm::RSA_3072: return 3072;
				case AsymmetricAlgorithm::RSA_4096: return 4096;
				case AsymmetricAlgorithm::ECC_P256: return 256;
				case AsymmetricAlgorithm::ECC_P384: return 384;
				case AsymmetricAlgorithm::ECC_P521: return 521;
				default: return 0;
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
				//use if there is already a handle
				if (m_algHandle) {
					return true;
				}

				//Get Algorithm name
				const wchar_t* algName = AlgName(m_algorithm);
				if (!algName || !*algName) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->ntstatus = 0;
						err->message = L"Invalid symmetric algorithm";
						err->context.clear();
					}
					
					
					// Logger may not be initialized yet (prevents abort)
					if (Logger::Instance().IsInitialized()) {
						SS_LOG_ERROR(L"CryptoUtils", L"ensureProvider: invalid algorithm enum: %d", 
							static_cast<int>(m_algorithm));
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

				//Try to open algorithm provider
				BCRYPT_ALG_HANDLE h = nullptr;
				NTSTATUS st = BCryptOpenAlgorithmProvider(&h, algName, nullptr, 0);
				if (st < 0 || h == nullptr) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"BCryptOpenAlgorithmProvider failed for asymmetric";
						wchar_t tmp[256];
						swprintf_s(tmp, L"Algorithm=%s NTSTATUS=0x%08X Win32=%u", algName, static_cast<unsigned>(st), err->win32);
						err->context = tmp; // copies std::wstring, no dangling
					}
					
				
					// Prevents abort() if Logger is not initialized
					if (Logger::Instance().IsInitialized()) {
						SS_LOG_ERROR(L"CryptoUtils", L"BCryptOpenAlgorithmProvider failed: Algorithm=%s, NTSTATUS=0x%08X, Win32=%u",
							algName, static_cast<unsigned>(st), RtlNtStatusToDosError(st));
					}
					else
					{
						wchar_t debugMsg[512];
						swprintf_s(debugMsg, 
							L"[CryptoUtils] BCryptOpenAlgorithmProvider failed: Algorithm=%s, NTSTATUS=0x%08X, Win32=%u\n",
							algName, static_cast<unsigned>(st), RtlNtStatusToDosError(st));
						OutputDebugStringW(debugMsg);
					}
					
					//Guarantee no dangling
					m_algHandle = nullptr;
					return false;
				}

				m_algHandle = h;



				const wchar_t* chainMode = ChainingMode(m_algorithm);
				if (chainMode) {
					st = BCryptSetProperty(
						m_algHandle,
						BCRYPT_CHAINING_MODE,
						(PBYTE)chainMode,
						(ULONG)((wcslen(chainMode) + 1) * sizeof(wchar_t)),
						0
					);

					if (st < 0) {
						if (err) {
							err->ntstatus = st;
							err->win32 = RtlNtStatusToDosError(st);
							err->message = L"BCryptSetProperty for chaining mode failed";
							wchar_t tmp[256];
							swprintf_s(tmp, L"Mode=%s NTSTATUS=0x%08X", chainMode, static_cast<unsigned>(st));
							err->context = tmp;
						}

						if (Logger::Instance().IsInitialized()) {
							SS_LOG_ERROR(L"CryptoUtils", L"BCryptSetProperty failed for mode %s: 0x%08X", chainMode, st);
						}

						
						BCryptCloseAlgorithmProvider(m_algHandle, 0);
						m_algHandle = nullptr;
						return false;
					}
				}

				// Prevents abort() if Logger is not initialized
				if (Logger::Instance().IsInitialized()) {
					SS_LOG_INFO(L"CryptoUtils", L"Algorithm provider opened: %s (handle: %p)", algName, m_algHandle);
				} else {
					//Fallback to OutputDebugStringW if Logger not ready
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
				if (ivSize == 0) { outIV.clear(); m_ivSet = true; return true; }

				outIV.resize(ivSize);
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
				return 16; // AES block size is always 16 bytes
			}

			size_t SymmetricCipher::GetTagSize() const noexcept {
				return IsAEAD() ? 16 : 0;
			}

			bool SymmetricCipher::IsAEAD() const noexcept {
				return IsAEADAlg(m_algorithm);
			}

			bool SymmetricCipher::Encrypt(const uint8_t* plaintext, size_t plaintextLen,
				std::vector<uint8_t>& ciphertext, Error* err) noexcept
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
				if (!plaintext && plaintextLen != 0) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid plaintext pointer"; }
					return false;
				}
				if (IsAEAD()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Use EncryptAEAD for AEAD modes"; }
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


				// ═══════════════════════════════════════════════════════════════════
				//  PADDING STRATEGY (Manual PKCS7 - Industry Standard)
				// ═══════════════════════════════════════════════════════════════════

				if (plaintextLen > std::numeric_limits<ULONG>::max()) {
					if (err) {
						err->win32 = ERROR_BUFFER_OVERFLOW;
						err->message = L"Ciphertext too large for Windows CNG API";
					}
					return false;
				}
				std::vector<uint8_t> plaintextWithPadding;
				const uint8_t* effectivePlaintext = plaintext;
				size_t effectiveLen = plaintextLen;

				if (needsPadding && m_paddingMode == PaddingMode::PKCS7) {
					// Apply PKCS7 padding MANUALLY
					plaintextWithPadding.assign(plaintext, plaintext + plaintextLen);

					if (!applyPadding(plaintextWithPadding, blockSize)) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"PKCS7 padding failed"; }
						return false;
					}

					effectivePlaintext = plaintextWithPadding.data();
					effectiveLen = plaintextWithPadding.size();
				}
				else if (needsPadding && m_paddingMode == PaddingMode::None) {
					//  No padding - MUST be block-aligned
					if (plaintextLen % blockSize != 0) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Plaintext must be block-aligned"; }
						return false;
					}
				}

				// ═══════════════════════════════════════════════════════════════════
				//  IV MUTATION PROTECTION (Prevent IV reuse attacks)
				// ═══════════════════════════════════════════════════════════════════
				std::vector<uint8_t> ivLocal = m_iv;
				PUCHAR ivPtr = ivLocal.empty() ? nullptr : ivLocal.data();
				ULONG ivLen = static_cast<ULONG>(ivLocal.size());

				// ═══════════════════════════════════════════════════════════════════
				//  BCRYPT ENCRYPTION (NO PADDING FLAG)
				// ═══════════════════════════════════════════════════════════════════
				DWORD flags = 0; // ✅ CRITICAL: We handle padding ourselves

				// Query encrypted size
				ULONG cbResult = 0;
				NTSTATUS st = BCryptEncrypt(m_keyHandle,
					const_cast<uint8_t*>(effectivePlaintext), static_cast<ULONG>(effectiveLen),
					nullptr,
					ivPtr, ivLen,
					nullptr, 0, &cbResult, flags);

				if (st < 0) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"BCryptEncrypt size query failed";
					}
					SecureZeroMemory(plaintextWithPadding.data(), plaintextWithPadding.size());
					return false;
				}

				// Allocate output buffer
				ciphertext.resize(cbResult);

				// Perform encryption
				st = BCryptEncrypt(m_keyHandle,
					const_cast<uint8_t*>(effectivePlaintext), static_cast<ULONG>(effectiveLen),
					nullptr,
					ivPtr, ivLen,
					ciphertext.data(), static_cast<ULONG>(ciphertext.size()), &cbResult, flags);

				//  SECURE CLEANUP
				SecureZeroMemory(plaintextWithPadding.data(), plaintextWithPadding.size());

				if (st < 0) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"BCryptEncrypt failed";
					}
					SecureZeroMemory(ciphertext.data(), ciphertext.size());
					return false;
				}

				ciphertext.resize(cbResult);

				// ═══════════════════════════════════════════════════════════════════
				//  IV CHAINING (CBC mode - prevent IV reuse)
				// ═══════════════════════════════════════════════════════════════════
				if (isCBC && ivPtr && ivLen > 0) {
					if (ciphertext.size() >= ivLen) {
						// Use last ciphertext block as next IV
						std::memcpy(m_iv.data(), ciphertext.data() + ciphertext.size() - ivLen, ivLen);
					}
				}

				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
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

				if(aadLen > std::numeric_limits<ULONG>::max()) {
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

				tag.resize(GetTagSize());
				authInfo.pbTag = tag.data();
				authInfo.cbTag = static_cast<ULONG>(tag.size());
				authInfo.pbMacContext = nullptr;
				authInfo.cbMacContext = 0;
				authInfo.cbAAD = static_cast<ULONG>(aadLen);
				authInfo.cbData = static_cast<ULONG>(plaintextLen);
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
					out.clear();
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptEncrypt failed"; }
					return false;
				}

				out.resize(cbResult);

				// update IV for modes that require it (CBC, CFB, OFB)
				if (!out.empty() && m_iv.size() == blockSize) {
					std::memcpy(m_iv.data(), out.data() + out.size() - blockSize, blockSize);
				}

				//Remove the processed data from the buffer
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

				// Apply manual padding ONLY if needed
				if (m_paddingMode == PaddingMode::PKCS7) {
					if (!applyPadding(m_streamBuffer, GetBlockSize())) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Padding failed"; }
						return false;
					}
				}

				//Encrypt final block (flags=0, BCrypt won't add padding)
				ULONG cbResult = 0;
				NTSTATUS st = BCryptEncrypt(
					m_keyHandle,
					m_streamBuffer.data(), static_cast<ULONG>(m_streamBuffer.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					nullptr, 0, &cbResult, 0); //flags=0 (no BCrypt padding)

				if (st < 0) {
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
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"EncryptFinal failed"; }
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

				std::vector<uint8_t> toDecrypt(m_streamBuffer.begin(), m_streamBuffer.begin() + processSize);

				//overflow guard
				if (toDecrypt.size() > static_cast<size_t>(std::numeric_limits<ULONG>::max())) {
					if (err) { err->win32 = ERROR_ARITHMETIC_OVERFLOW; err->message = L"toDecrypt size too large for ULONG"; }
					return false;
				}

				if (m_iv.size() > static_cast<size_t>(std::numeric_limits<ULONG>::max())) {
					if (err) { err->win32 = ERROR_ARITHMETIC_OVERFLOW; err->message = L"IV size too large for ULONG"; }
					return false;
				}
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
					SecureZeroMemory(out.data(), out.size());
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
				// Empty buffer handling
				if (m_streamBuffer.empty()) {
					m_streamFinalized = true;
					return true;
				}

				// Decrypt final block (flags=0, no BCrypt padding removal)
				ULONG cbResult = 0;
				NTSTATUS st = BCryptDecrypt(
					m_keyHandle,
					m_streamBuffer.data(), static_cast<ULONG>(m_streamBuffer.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					nullptr, 0, &cbResult, 0); // flags=0

				if (st < 0) {
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
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"DecryptFinal failed"; }
					return false;
				}

				out.resize(cbResult);

				// Manual padding removal (constant-time)
				if (m_paddingMode == PaddingMode::PKCS7) {
					const size_t originalSize = out.size();
					if (!removePadding(out, GetBlockSize())) {
						SecureZeroMemory(out.data(), originalSize);
						out.clear();
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid padding"; }
						return false;
					}
				}
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
					if(Logger::Instance().IsInitialized()) {
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
				} else {
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
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptExportKey (public) failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptExportKey (public) failed: 0x%08X", st);
					BCryptDestroyKey(hKey);
					return false;
				}

				// Export private key
				cbBlob = 0;
				st = BCryptExportKey(hKey, nullptr, privBlobType, nullptr, 0, &cbBlob, 0);
				if (st < 0 || cbBlob == 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptExportKey (private size) failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptExportKey (private size) failed: 0x%08X", st);
					BCryptDestroyKey(hKey);
					return false;
				}
				outKeyPair.privateKey.algorithm = m_algorithm;
				outKeyPair.privateKey.keyBlob.resize(cbBlob);
				st = BCryptExportKey(hKey, nullptr, privBlobType, outKeyPair.privateKey.keyBlob.data(), cbBlob, &cbBlob, 0);
				if (st < 0) {
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
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"HKDF Extract failed"; }
					return false;
				}
				if (keyLen > 255 * hashLen) {
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
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"HKDF Expand failed"; }
						return false;
					}

					okm.insert(okm.end(), t.begin(), t.end());
				}

				std::memcpy(outKey, okm.data(), keyLen);
				SecureZeroMemory(prk.data(), prk.size());
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


			// =============================================================================
			// PrivateKey Implementation
			// =============================================================================

			void PrivateKey::SecureErase() noexcept {
				if (!keyBlob.empty()) {
					SecureZeroMemory(keyBlob.data(), keyBlob.size());
					keyBlob.clear();
				}
			}
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
					// Increase PBKDF2 iterations from 10000 to 600000 (OWASP 2023 recommendation)

					KDFParams kdfParams{};
					kdfParams.algorithm = KDFAlgorithm::PBKDF2_SHA256;
					kdfParams.iterations = 600000; // Production-grade iteration count
					kdfParams.keyLength = 32;

					SecureRandom rng;
					std::vector<uint8_t> salt;
					if (!rng.Generate(salt, 32, err)) return false; // 32 bytes salt instead of 16
					kdfParams.salt = salt;

					std::vector<uint8_t> key;
					if (!KeyDerivation::DeriveKey(password, kdfParams, key, err)) return false;

					SymmetricCipher cipher(SymmetricAlgorithm::AES_256_CBC);
					if (!cipher.SetKey(key, err)) return false;

					std::vector<uint8_t> iv;
					if (!cipher.GenerateIV(iv, err)) return false;

					if(iv.size() != 16) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid IV size"; }
						return false;
					}
					std::vector<uint8_t> encrypted;
					if (!cipher.Encrypt(keyBlob.data(), keyBlob.size(), encrypted, err)) return false;

					// Format now includes iteration count for future-proofing
					// Format: [VERSION(4)] + [ITERATIONS(4)] + [SALT(32)] + [IV(16)] + [ENCRYPTED_DATA]
					dataToEncode.clear();
					const uint32_t version = 1;
					const uint32_t iterations = kdfParams.iterations;
					dataToEncode.insert(dataToEncode.end(), reinterpret_cast<const uint8_t*>(&version), reinterpret_cast<const uint8_t*>(&version) + sizeof(version));
					dataToEncode.insert(dataToEncode.end(), reinterpret_cast<const uint8_t*>(&iterations), reinterpret_cast<const uint8_t*>(&iterations) + sizeof(iterations));
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

			// Minimal ASN.1 sanity checks
			static bool ValidatePKCS1RSAPrivateKey(const std::vector<uint8_t>& der) noexcept {
				// Very light check: must start with SEQUENCE (0x30)
				if (der.size() < 2 || der[0] != 0x30) return false;
				// Optional deeper checks (heuristics): expect INTEGER tags 0x02 somewhere early
				// We keep it minimal to avoid full ASN.1 parsing.
				return true;
			}

			static bool ValidatePKCS8PrivateKeyInfo(const std::vector<uint8_t>& der) noexcept {
				// Very light check: must start with SEQUENCE (0x30)
				if (der.size() < 2 || der[0] != 0x30) return false;
				return true;
			}

			// Read little-endian uint32 safely (portable parsing)
			static uint32_t ReadLE32(const uint8_t* p) noexcept {
				return (static_cast<uint32_t>(p[0])) |
					(static_cast<uint32_t>(p[1]) << 8) |
					(static_cast<uint32_t>(p[2]) << 16) |
					(static_cast<uint32_t>(p[3]) << 24);
			}

			bool PrivateKey::ImportPEM(std::string_view pem,
				PrivateKey& out,
				std::string_view password,
				Error* err) noexcept
			{
				if (pem.empty()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"PEM string is empty"; }
					return false;
				}

				// Detect custom PKCS#8 encrypted vs unencrypted
				const bool isEncrypted = (pem.find("-----BEGIN ENCRYPTED PRIVATE KEY-----") != std::string_view::npos);

				const std::string_view beginMarker = isEncrypted ?
					"-----BEGIN ENCRYPTED PRIVATE KEY-----" :
					"-----BEGIN PRIVATE KEY-----";
				const std::string_view endMarker = isEncrypted ?
					"-----END ENCRYPTED PRIVATE KEY-----" :
					"-----END PRIVATE KEY-----";

				// Fallback to PKCS#1 RSA PRIVATE KEY helper if PKCS#8 markers not found
				if (pem.find(beginMarker) == std::string_view::npos) {
					if (pem.find("-----BEGIN RSA PRIVATE KEY-----") != std::string_view::npos) {
						// Import PKCS#1 (unencrypted) via helper
						if (!ImportPEM_RSAFormat(pem, out, /*password ignored*/ std::string_view{}, err)) return false;
						// Minimal ASN.1 sanity check
						if (!ValidatePKCS1RSAPrivateKey(out.keyBlob)) {
							if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid PKCS#1 RSA private key"; }
							// Zero sensitive data before returning
							SecureZeroMemory(out.keyBlob.data(), out.keyBlob.size());
							out.keyBlob.clear();
							return false;
						}
						return true;
					}
				}

				// Locate PEM block
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

				// Clean base64 (strip whitespace/newlines)
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

				if (isEncrypted) {
					if (password.empty()) {
						if (err) { err->win32 = ERROR_INVALID_PASSWORD; err->message = L"Password required for encrypted key"; }
						// Zero decoded buffer (contains sensitive header and ciphertext)
						SecureZeroMemory(decoded.data(), decoded.size());
						return false;
					}

					// Custom encrypted PKCS#8 header:
					// [VERSION(4)] + [ITERATIONS(4)] + [SALT(32)] + [IV(16)] + [ENCRYPTED_DATA]
					if (decoded.size() < (4 + 4 + 32 + 16)) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Encrypted data too short"; }
						SecureZeroMemory(decoded.data(), decoded.size());
						return false;
					}

					size_t offset = 0;
					const uint32_t version = ReadLE32(decoded.data() + offset); offset += 4;
					uint32_t iterations = ReadLE32(decoded.data() + offset); offset += 4;

					// Harden default if version mismatches (old blobs without iteration field should not reach here)
					if (version != 1) {
						// Fallback: enforce strong default
						iterations = 600000;
					}

					// Salt (fixed 32 bytes in v1 format)
					if (decoded.size() < offset + 32 + 16) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Encrypted data format mismatch"; }
						SecureZeroMemory(decoded.data(), decoded.size());
						return false;
					}
					std::vector<uint8_t> salt(decoded.begin() + offset, decoded.begin() + offset + 32);
					offset += 32;

					// IV (16 bytes for AES-CBC)
					std::vector<uint8_t> iv(decoded.begin() + offset, decoded.begin() + offset + 16);
					offset += 16;

					const uint8_t* encryptedData = decoded.data() + offset;
					const size_t encryptedSize = decoded.size() - offset;

					// Derive key (PBKDF2-SHA256) with hardened iteration count
					if (iterations < 1000) iterations = 600000; // enforce minimum (OWASP 2023)
					KDFParams kdfParams{};
					kdfParams.algorithm = KDFAlgorithm::PBKDF2_SHA256;
					kdfParams.iterations = iterations;
					kdfParams.keyLength = 32;
					kdfParams.salt = salt;

					std::vector<uint8_t> key;
					if (!KeyDerivation::DeriveKey(password, kdfParams, key, err)) {
						SecureZeroMemory(salt.data(), salt.size());
						SecureZeroMemory(iv.data(), iv.size());
						SecureZeroMemory(decoded.data(), decoded.size());
						return false;
					}

					// Decrypt AES-256-CBC
					SymmetricCipher cipher(SymmetricAlgorithm::AES_256_CBC);
					if (!cipher.SetKey(key, err)) {
						SecureZeroMemory(key.data(), key.size());
						SecureZeroMemory(salt.data(), salt.size());
						SecureZeroMemory(iv.data(), iv.size());
						SecureZeroMemory(decoded.data(), decoded.size());
						return false;
					}
					if (!cipher.SetIV(iv, err)) {
						SecureZeroMemory(key.data(), key.size());
						SecureZeroMemory(salt.data(), salt.size());
						SecureZeroMemory(iv.data(), iv.size());
						SecureZeroMemory(decoded.data(), decoded.size());
						return false;
					}

					std::vector<uint8_t> decrypted;
					const bool decOk = cipher.Decrypt(encryptedData, encryptedSize, decrypted, err);

					// Zero sensitive buffers regardless of success
					SecureZeroMemory(key.data(), key.size());
					SecureZeroMemory(salt.data(), salt.size());
					SecureZeroMemory(iv.data(), iv.size());
					SecureZeroMemory(decoded.data(), decoded.size());

					if (!decOk) return false;

					// ASN.1 minimal validation (reject obvious garbage)
					if (!ValidatePKCS1RSAPrivateKey(decrypted) && !ValidatePKCS8PrivateKeyInfo(decrypted)) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Decrypted data is not a valid private key"; }
						SecureZeroMemory(decrypted.data(), decrypted.size());
						return false;
					}

					out.keyBlob = std::move(decrypted);
					return true;
				}
				else {
					// Unencrypted PKCS#8: minimal ASN.1 sanity
					if (!ValidatePKCS8PrivateKeyInfo(decoded)) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid PKCS#8 PrivateKeyInfo"; }
						SecureZeroMemory(decoded.data(), decoded.size());
						return false;
					}
					out.keyBlob = std::move(decoded);
					return true;
				}
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
#ifdef _WIN32
				cleanup();

				if (pem.empty()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"PEM string is empty"; }
					return false;
				}

				// Find PEM boundaries
				const std::string_view beginMarker = "-----BEGIN CERTIFICATE-----";
				const std::string_view endMarker = "-----END CERTIFICATE-----";

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

				// Extract base64 content
				beginPos += beginMarker.size();
				std::string_view base64Content = pem.substr(beginPos, endPos - beginPos);

				// Remove whitespace
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

				// Create certificate context from decoded DER data
				m_certContext = CertCreateCertificateContext(
					X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
					decoded.data(),
					static_cast<DWORD>(decoded.size()));

				if (!m_certContext) {
					if (err) {
						err->win32 = GetLastError();
						err->message = L"Failed to create certificate context from PEM data";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"CertCreateCertificateContext failed: 0x%08X", GetLastError());
					return false;
				}

				SS_LOG_INFO(L"CryptoUtils", L"Certificate loaded successfully from PEM");
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
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
#ifdef _WIN32
				if (!m_certContext) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"No certificate loaded"; }
					return false;
				}

				// Get the DER-encoded certificate
				const BYTE* certData = m_certContext->pbCertEncoded;
				DWORD certSize = m_certContext->cbCertEncoded;

				if (!certData || certSize == 0) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Certificate data is empty"; }
					return false;
				}

				// Base64 encode the DER data
				std::string base64 = Base64::Encode(certData, certSize);
				if (base64.empty()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Base64 encoding failed"; }
					return false;
				}

				// PEM format
				std::ostringstream oss;
				oss << "-----BEGIN CERTIFICATE-----\n";

				const size_t lineWidth = 64;
				for (size_t i = 0; i < base64.size(); i += lineWidth) {
					size_t chunkSize = std::min(lineWidth, base64.size() - i);
					oss << base64.substr(i, chunkSize) << "\n";
				}

				oss << "-----END CERTIFICATE-----\n";

				out = oss.str();
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
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
#ifdef _WIN32
				// ═══════════════════════════════════════════════════════════════════
				//  TIER-1 INPUT VALIDATION
				// ═══════════════════════════════════════════════════════════════════
				if (!m_certContext) {
					if (err) {
						err->win32 = ERROR_INVALID_STATE;
						err->message = L"No certificate loaded";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"VerifySignature: Certificate context is null");
					return false;
				}

				if (!data || dataLen == 0) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->message = L"Invalid data buffer";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"VerifySignature: Data is null or empty");
					return false;
				}

				if (!signature || signatureLen == 0) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->message = L"Invalid signature buffer";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"VerifySignature: Signature is null or empty");
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  CERTIFICATE VALIDITY CHECKS
				// ═══════════════════════════════════════════════════════════════════
				FILETIME now;
				GetSystemTimeAsFileTime(&now);

				if (CompareFileTime(&now, &m_certContext->pCertInfo->NotBefore) < 0) {
					if (err) {
						err->win32 = CERT_E_EXPIRED;
						err->message = L"Certificate not yet valid";
					}
					SS_LOG_WARN(L"CryptoUtils", L"Certificate not yet valid");
					return false;
				}

				if (CompareFileTime(&now, &m_certContext->pCertInfo->NotAfter) > 0) {
					if (err) {
						err->win32 = CERT_E_EXPIRED;
						err->message = L"Certificate has expired";
					}
					SS_LOG_WARN(L"CryptoUtils", L"Certificate has expired");
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  ALGORITHM DETECTION FROM CERTIFICATE OID
				// ═══════════════════════════════════════════════════════════════════
				PCSTR sigOid = m_certContext->pCertInfo->SignatureAlgorithm.pszObjId;
				if (!sigOid) {
					if (err) {
						err->win32 = ERROR_INVALID_DATA;
						err->message = L"Certificate has no signature algorithm OID";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Certificate SignatureAlgorithm OID is null");
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  SIGNATURE SCHEME MAPPING (OID → Algorithm)
				// ═══════════════════════════════════════════════════════════════════
				enum class SigScheme {
					RSA_PKCS1v15,  // Legacy (SHA-1/256/384/512)
					RSA_PSS,       // Modern RSA (RFC 8017)
					ECDSA,         // Elliptic Curve (P-256/384/521)
					EdDSA,         // Ed25519/Ed448 (RFC 8032)
					Unknown
				};

				enum class HashAlg {
					SHA1, SHA256, SHA384, SHA512, Unknown
				};

				auto MapOidToScheme = [](PCSTR oid) -> std::pair<SigScheme, HashAlg> {
					if (!oid) return { SigScheme::Unknown, HashAlg::Unknown };

					// ✅ RSA PKCS#1 v1.5 (Legacy)
					if (strcmp(oid, "1.2.840.113549.1.1.5") == 0)  return { SigScheme::RSA_PKCS1v15, HashAlg::SHA1 };   // sha1WithRSAEncryption
					if (strcmp(oid, "1.2.840.113549.1.1.11") == 0) return { SigScheme::RSA_PKCS1v15, HashAlg::SHA256 }; // sha256WithRSAEncryption
					if (strcmp(oid, "1.2.840.113549.1.1.12") == 0) return { SigScheme::RSA_PKCS1v15, HashAlg::SHA384 }; // sha384WithRSAEncryption
					if (strcmp(oid, "1.2.840.113549.1.1.13") == 0) return { SigScheme::RSA_PKCS1v15, HashAlg::SHA512 }; // sha512WithRSAEncryption

					// ✅ RSA-PSS (Modern)
					if (strcmp(oid, "1.2.840.113549.1.1.10") == 0) return { SigScheme::RSA_PSS, HashAlg::SHA256 }; // RSASSA-PSS

					// ✅ ECDSA (Industry Standard)
					if (strcmp(oid, "1.2.840.10045.4.3.1") == 0) return { SigScheme::ECDSA, HashAlg::SHA1 };   // ecdsa-with-SHA1
					if (strcmp(oid, "1.2.840.10045.4.3.2") == 0) return { SigScheme::ECDSA, HashAlg::SHA256 }; // ecdsa-with-SHA256
					if (strcmp(oid, "1.2.840.10045.4.3.3") == 0) return { SigScheme::ECDSA, HashAlg::SHA384 }; // ecdsa-with-SHA384
					if (strcmp(oid, "1.2.840.10045.4.3.4") == 0) return { SigScheme::ECDSA, HashAlg::SHA512 }; // ecdsa-with-SHA512

					// ✅ EdDSA (Emerging Standard)
					if (strcmp(oid, "1.3.101.112") == 0) return { SigScheme::EdDSA, HashAlg::Unknown }; // Ed25519
					if (strcmp(oid, "1.3.101.113") == 0) return { SigScheme::EdDSA, HashAlg::Unknown }; // Ed448

					return { SigScheme::Unknown, HashAlg::Unknown };
					};

				auto [scheme, hashAlg] = MapOidToScheme(sigOid);

				if (scheme == SigScheme::Unknown) {
					if (err) {
						err->win32 = ERROR_NOT_SUPPORTED;
						err->message = L"Unsupported signature algorithm OID";
						wchar_t tmp[128];
						swprintf_s(tmp, L"OID: %S", sigOid);
						err->context = tmp;
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Unsupported signature OID: %S", sigOid);
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  EXTRACT PUBLIC KEY FROM CERTIFICATE
				// ═══════════════════════════════════════════════════════════════════
				PCERT_PUBLIC_KEY_INFO pPublicKeyInfo = &m_certContext->pCertInfo->SubjectPublicKeyInfo;
				if (!pPublicKeyInfo->PublicKey.pbData || pPublicKeyInfo->PublicKey.cbData == 0) {
					if (err) {
						err->win32 = ERROR_INVALID_DATA;
						err->message = L"Certificate has no public key";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Certificate public key is empty");
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  SIGNATURE LENGTH VALIDATION (DoS Protection)
				// ═══════════════════════════════════════════════════════════════════
				const DWORD pubKeyBits = pPublicKeyInfo->PublicKey.cbData * 8;

				size_t expectedMinSigLen = 0;
				size_t expectedMaxSigLen = 0;

				if (scheme == SigScheme::RSA_PKCS1v15 || scheme == SigScheme::RSA_PSS) {
					// RSA: signature length ≈ key size (in bytes)
					expectedMinSigLen = (pubKeyBits / 8) - 16; // tolerance
					expectedMaxSigLen = (pubKeyBits / 8) + 16;
				}
				else if (scheme == SigScheme::ECDSA) {
					// ECDSA: signature length ≈ 2 × curve size (r + s)
					expectedMinSigLen = (pubKeyBits / 8) * 2 - 16;
					expectedMaxSigLen = (pubKeyBits / 8) * 2 + 128; // ASN.1 encoding overhead
				}
				else if (scheme == SigScheme::EdDSA) {
					// EdDSA: fixed signature sizes
					expectedMinSigLen = 64;  // Ed25519
					expectedMaxSigLen = 114; // Ed448
				}

				if (signatureLen < expectedMinSigLen || signatureLen > expectedMaxSigLen) {
					if (err) {
						err->win32 = ERROR_INVALID_DATA;
						err->message = L"Signature length does not match key size";
						wchar_t tmp[256];
						swprintf_s(tmp, L"Expected: %zu-%zu bytes, Got: %zu bytes",
							expectedMinSigLen, expectedMaxSigLen, signatureLen);
						err->context = tmp;
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Invalid signature length: %zu (expected %zu-%zu)",
						signatureLen, expectedMinSigLen, expectedMaxSigLen);
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  HASH ALGORITHM MAPPING (HashAlg → BCrypt Algorithm)
				// ═══════════════════════════════════════════════════════════════════
				auto MapHashAlgToBCrypt = [](HashAlg alg) -> const wchar_t* {
					switch (alg) {
					case HashAlg::SHA1:   return BCRYPT_SHA1_ALGORITHM;
					case HashAlg::SHA256: return BCRYPT_SHA256_ALGORITHM;
					case HashAlg::SHA384: return BCRYPT_SHA384_ALGORITHM;
					case HashAlg::SHA512: return BCRYPT_SHA512_ALGORITHM;
					default: return nullptr;
					}
					};

				const wchar_t* bcryptHashAlg = MapHashAlgToBCrypt(hashAlg);
				if (!bcryptHashAlg && scheme != SigScheme::EdDSA) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->message = L"Unsupported hash algorithm";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Unsupported hash algorithm: %d", static_cast<int>(hashAlg));
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  COMPUTE MESSAGE HASH (SHA-256/384/512)
				// ═══════════════════════════════════════════════════════════════════
				std::vector<uint8_t> messageHash;

				if (scheme != SigScheme::EdDSA) { // EdDSA hashes internally
					BCRYPT_ALG_HANDLE hHashAlg = nullptr;
					NTSTATUS st = BCryptOpenAlgorithmProvider(&hHashAlg, bcryptHashAlg, nullptr, 0);
					if (st < 0) {
						if (err) {
							err->ntstatus = st;
							err->win32 = RtlNtStatusToDosError(st);
							err->message = L"Failed to open hash algorithm provider";
						}
						SS_LOG_ERROR(L"CryptoUtils", L"BCryptOpenAlgorithmProvider failed: 0x%08X", st);
						return false;
					}

					// RAII cleanup
					struct HashProviderCleanup {
						BCRYPT_ALG_HANDLE h;
						~HashProviderCleanup() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
					} hashProvCleanup{ hHashAlg };

					DWORD hashLen = 0, cbResult = 0;
					st = BCryptGetProperty(hHashAlg, BCRYPT_HASH_LENGTH,
						reinterpret_cast<PUCHAR>(&hashLen), sizeof(hashLen), &cbResult, 0);
					if (st < 0) {
						if (err) {
							err->ntstatus = st;
							err->win32 = RtlNtStatusToDosError(st);
							err->message = L"Failed to get hash length";
						}
						SS_LOG_ERROR(L"CryptoUtils", L"BCryptGetProperty HASH_LENGTH failed: 0x%08X", st);
						return false;
					}

					messageHash.resize(hashLen);

					st = BCryptHash(hHashAlg, nullptr, 0,
						const_cast<uint8_t*>(data), static_cast<ULONG>(dataLen),
						messageHash.data(), static_cast<ULONG>(messageHash.size()));
					if (st < 0) {
						if (err) {
							err->ntstatus = st;
							err->win32 = RtlNtStatusToDosError(st);
							err->message = L"Hash computation failed";
						}
						SS_LOG_ERROR(L"CryptoUtils", L"BCryptHash failed: 0x%08X", st);
						return false;
					}
				}

				// ═══════════════════════════════════════════════════════════════════
				//  IMPORT PUBLIC KEY INTO CNG (Modern BCrypt API)
				// ═══════════════════════════════════════════════════════════════════
				const wchar_t* keyAlgName = nullptr;
				const wchar_t* blobType = nullptr;

				if (scheme == SigScheme::RSA_PKCS1v15 || scheme == SigScheme::RSA_PSS) {
					keyAlgName = BCRYPT_RSA_ALGORITHM;
					blobType = BCRYPT_RSAPUBLIC_BLOB;
				}
				else if (scheme == SigScheme::ECDSA) {
					// Detect ECC curve from certificate
					PCSTR keyOid = pPublicKeyInfo->Algorithm.pszObjId;
					if (strcmp(keyOid, "1.2.840.10045.2.1") == 0) { // id-ecPublicKey
						// Curve is in Algorithm.Parameters
						keyAlgName = BCRYPT_ECDSA_P256_ALGORITHM; // Default (detect below if needed)
					}
					blobType = BCRYPT_ECCPUBLIC_BLOB;
				}
				else if (scheme == SigScheme::EdDSA) {
					keyAlgName = L"EdDSA"; // Not natively supported by BCrypt (requires custom impl)
					blobType = L"EdDSA";
				}

				if (!keyAlgName) {
					if (err) {
						err->win32 = ERROR_NOT_SUPPORTED;
						err->message = L"Unsupported key algorithm";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Unsupported key algorithm for scheme: %d", static_cast<int>(scheme));
					return false;
				}

				BCRYPT_ALG_HANDLE hKeyAlg = nullptr;
				NTSTATUS st = BCryptOpenAlgorithmProvider(&hKeyAlg, keyAlgName, nullptr, 0);
				if (st < 0) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"Failed to open key algorithm provider";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptOpenAlgorithmProvider (key) failed: 0x%08X", st);
					return false;
				}

				// RAII cleanup
				struct KeyProviderCleanup {
					BCRYPT_ALG_HANDLE h;
					~KeyProviderCleanup() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
				} keyProvCleanup{ hKeyAlg };

				// Import public key from certificate
				BCRYPT_KEY_HANDLE hPubKey = nullptr;
				st = BCryptImportKeyPair(hKeyAlg, nullptr, blobType, &hPubKey,
					pPublicKeyInfo->PublicKey.pbData, pPublicKeyInfo->PublicKey.cbData, 0);
				if (st < 0) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"Failed to import public key";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptImportKeyPair failed: 0x%08X", st);
					return false;
				}

				// RAII cleanup
				struct KeyCleanup {
					BCRYPT_KEY_HANDLE h;
					~KeyCleanup() { if (h) BCryptDestroyKey(h); }
				} keyCleanup{ hPubKey };

				// ═══════════════════════════════════════════════════════════════════
				//  SIGNATURE VERIFICATION (Modern CNG API)
				// ═══════════════════════════════════════════════════════════════════
				DWORD flags = 0;
				void* paddingInfo = nullptr;

				BCRYPT_PKCS1_PADDING_INFO pkcs1Info{};
				BCRYPT_PSS_PADDING_INFO pssInfo{};

				if (scheme == SigScheme::RSA_PKCS1v15) {
					pkcs1Info.pszAlgId = bcryptHashAlg;
					paddingInfo = &pkcs1Info;
					flags = BCRYPT_PAD_PKCS1;
				}
				else if (scheme == SigScheme::RSA_PSS) {
					pssInfo.pszAlgId = bcryptHashAlg;
					pssInfo.cbSalt = static_cast<ULONG>(messageHash.size()); // Standard salt length
					paddingInfo = &pssInfo;
					flags = BCRYPT_PAD_PSS;
				}

				st = BCryptVerifySignature(hPubKey, paddingInfo,
					messageHash.data(), static_cast<ULONG>(messageHash.size()),
					const_cast<uint8_t*>(signature), static_cast<ULONG>(signatureLen), flags);

				if (st == 0) {
					SS_LOG_INFO(L"CryptoUtils", L"Signature verified successfully (Scheme: %d, Hash: %d)",
						static_cast<int>(scheme), static_cast<int>(hashAlg));
					return true;
				}
				else if (st == STATUS_INVALID_SIGNATURE) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"Invalid signature - verification failed";
					}
					SS_LOG_WARN(L"CryptoUtils", L"Signature verification failed: Invalid signature");
					return false;
				}
				else {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"Signature verification failed";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptVerifySignature failed: 0x%08X", st);
					return false;
				}

#else
				if (err) {
					err->win32 = ERROR_NOT_SUPPORTED;
					err->message = L"Platform not supported";
				}
				return false;
#endif
			}


			bool Certificate::VerifyChain(Error* err,
				HCERTSTORE hAdditionalStore /*= nullptr*/,
				DWORD chainFlags /*= CERT_CHAIN_REVOCATION_CHECK_CHAIN*/,
				 FILETIME* verificationTime /*= nullptr*/,
				const char* requiredEkuOid /*= nullptr*/) const noexcept
			{
#ifdef _WIN32
				auto setErr = [&](DWORD code, const wchar_t* msg) {
					if (err) { err->win32 = code; err->message = msg; }
					};

				if (!m_certContext) {
					setErr(ERROR_INVALID_STATE, L"No certificate loaded");
					return false;
				}

				// Chain parameters
				CERT_CHAIN_PARA chainPara{};
				chainPara.cbSize = sizeof(chainPara);

				// Optionally require EKU (e.g., szOID_PKIX_KP_CODE_SIGNING)
				CERT_USAGE_MATCH usageMatch{};
				CERT_ENHKEY_USAGE enhUsage{};
				PCERT_ENHKEY_USAGE pEnhUsage = nullptr;

				if (requiredEkuOid && *requiredEkuOid) {
					LPCSTR oids[1] = { requiredEkuOid };
					enhUsage.cUsageIdentifier = 1;
					enhUsage.rgpszUsageIdentifier = const_cast<LPSTR*>(oids);

					usageMatch.dwType = USAGE_MATCH_TYPE_AND;
					usageMatch.Usage = enhUsage;

					chainPara.RequestedUsage = usageMatch;
					pEnhUsage = &enhUsage;
				}

				// Build chain
				PCCERT_CHAIN_CONTEXT pChainContext = nullptr;

				// Default flags: revocation check entire chain; if network unavailable, fall back to cache-only
				DWORD flags = chainFlags;
				if (flags == 0) {
					flags = CERT_CHAIN_REVOCATION_CHECK_CHAIN;
				}

				BOOL ok = CertGetCertificateChain(
					nullptr,                       // default chain engine
					m_certContext,                 // leaf certificate
					verificationTime,              // verification time (nullptr → current)
					hAdditionalStore,              // additional stores (intermediates)
					&chainPara,                    // parameters (EKU etc.)
					flags,                         // chain building flags
					nullptr,                       // reserved
					&pChainContext                 // out
				);

				if (!ok || !pChainContext) {
					setErr(GetLastError(), L"CertGetCertificateChain failed");
					return false;
				}

				// RAII cleanup
				struct ChainCleanup {
					PCCERT_CHAIN_CONTEXT c;
					~ChainCleanup() { if (c) CertFreeCertificateChain(c); }
				} _cleanup{ pChainContext };

				// Helper to enrich error details
				auto analyzeTrustStatus = [&](const CERT_TRUST_STATUS& ts, std::wstring& outMsg) -> DWORD {
					DWORD code = ERROR_INVALID_DATA;
					std::wstringstream ss;
					ss << L"Chain trust errors:";

					if (ts.dwErrorStatus == CERT_TRUST_NO_ERROR) {
						outMsg = L"Certificate chain is valid";
						return ERROR_SUCCESS;
					}

					if (ts.dwErrorStatus & CERT_TRUST_IS_REVOKED) { ss << L" REVOKED"; code = CRYPT_E_REVOKED; }
					if (ts.dwErrorStatus & CERT_TRUST_IS_UNTRUSTED_ROOT) { ss << L" UNTRUSTED_ROOT"; }
					if (ts.dwErrorStatus & CERT_TRUST_IS_PARTIAL_CHAIN) { ss << L" PARTIAL_CHAIN"; }
					if (ts.dwErrorStatus & CERT_TRUST_IS_NOT_TIME_VALID) { ss << L" NOT_TIME_VALID"; }
					if (ts.dwErrorStatus & CERT_TRUST_IS_NOT_TIME_NESTED) { ss << L" NOT_TIME_NESTED"; }
					if (ts.dwErrorStatus & CERT_TRUST_REVOCATION_STATUS_UNKNOWN) { ss << L" REVOCATION_UNKNOWN"; }
					if (ts.dwErrorStatus & CERT_TRUST_IS_CYCLIC) { ss << L" CYCLIC"; }
					if (ts.dwErrorStatus & CERT_TRUST_IS_EXPLICIT_DISTRUST) { ss << L" EXPLICIT_DISTRUST"; code = ERROR_ACCESS_DENIED; }
					if (ts.dwErrorStatus & CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT) { ss << L" NAME_CONSTRAINT_NOT_SUPPORTED"; }
					if (ts.dwErrorStatus & CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT) { ss << L" NAME_CONSTRAINT_NOT_DEFINED"; }
					if (ts.dwErrorStatus & CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT) { ss << L" NAME_CONSTRAINT_NOT_PERMITTED"; }
					if (ts.dwErrorStatus & CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT) { ss << L" NAME_CONSTRAINT_EXCLUDED"; }
					if (ts.dwErrorStatus & CERT_TRUST_IS_OFFLINE_REVOCATION) { ss << L" OFFLINE_REVOCATION"; }
					if (ts.dwErrorStatus & CERT_TRUST_NO_ISSUANCE_CHAIN_POLICY) { ss << L" NO_ISSUANCE_CHAIN_POLICY"; }

					// Info status (not fatal by itself, but good to log)
					if (ts.dwInfoStatus & CERT_TRUST_IS_SELF_SIGNED) { ss << L" (INFO: SELF_SIGNED)"; }
					if (ts.dwInfoStatus & CERT_TRUST_HAS_EXACT_MATCH_ISSUER) { ss << L" (INFO: EXACT_MATCH_ISSUER)"; }
					if (ts.dwInfoStatus & CERT_TRUST_HAS_KEY_MATCH_ISSUER) { ss << L" (INFO: KEY_MATCH_ISSUER)"; }
					if (ts.dwInfoStatus & CERT_TRUST_HAS_NAME_MATCH_ISSUER) { ss << L" (INFO: NAME_MATCH_ISSUER)"; }
					if (ts.dwInfoStatus & CERT_TRUST_IS_COMPLEX_CHAIN) { ss << L" (INFO: COMPLEX_CHAIN)"; }
					outMsg = ss.str();
					return code;
					};

				// Evaluate overall chain trust
				const CERT_TRUST_STATUS& trust = pChainContext->TrustStatus;

				if (trust.dwErrorStatus == CERT_TRUST_NO_ERROR) {
					// Optional: enforce EKU (even if chain says OK, ensure leaf has EKU we asked)
					if (requiredEkuOid && *requiredEkuOid) {
						// Walk simple chain[0] (leaf)
						if (pChainContext->cChain > 0 && pChainContext->rgpChain[0]->cElement > 0) {
							auto leaf = pChainContext->rgpChain[0]->rgpElement[0]->pCertContext;
							// Try to find required EKU in leaf
							PCERT_ENHKEY_USAGE pLeafUsage = nullptr;
							DWORD cbUsage = 0;
							if (CertGetEnhancedKeyUsage(leaf, 0, nullptr, &cbUsage) && cbUsage >= sizeof(CERT_ENHKEY_USAGE)) {
								pLeafUsage = (PCERT_ENHKEY_USAGE)LocalAlloc(LPTR, cbUsage);
								if (pLeafUsage && CertGetEnhancedKeyUsage(leaf, 0, pLeafUsage, &cbUsage)) {
									bool found = false;
									for (DWORD i = 0; i < pLeafUsage->cUsageIdentifier; ++i) {
										if (pLeafUsage->rgpszUsageIdentifier[i] &&
											std::strcmp(pLeafUsage->rgpszUsageIdentifier[i], requiredEkuOid) == 0) {
											found = true; break;
										}
									}
									LocalFree(pLeafUsage);
									if (!found) {
										setErr(ERROR_INVALID_DATA, L"Leaf certificate EKU does not include required usage");
										return false;
									}
								}
								else if (pLeafUsage) {
									LocalFree(pLeafUsage);
								}
							}
						}
					}
					return true;
				}

				// Chain not valid → analyze and return detailed error
				std::wstring msg;
				DWORD code = analyzeTrustStatus(trust, msg);
				setErr(code, msg.c_str());
				return false;

#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool Certificate::VerifyAgainstCA(const Certificate& caCert, Error* err) const noexcept {
#ifdef _WIN32
				// ═══════════════════════════════════════════════════════════════════
				//  TIER-1 STATE VALIDATION
				// ═══════════════════════════════════════════════════════════════════
				if (!m_certContext) {
					if (err) {
						err->win32 = ERROR_INVALID_STATE;
						err->message = L"No certificate loaded (leaf context is null)";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"VerifyAgainstCA: Leaf certificate context is null");
					return false;
				}

				if (!caCert.m_certContext) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->message = L"CA certificate is not loaded (CA context is null)";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"VerifyAgainstCA: CA certificate context is null");
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  STEP 1: CERTIFICATE VALIDITY TIME CHECKS
				// ═══════════════════════════════════════════════════════════════════
				FILETIME now;
				GetSystemTimeAsFileTime(&now);

				// Leaf certificate time validation
				if (CompareFileTime(&now, &m_certContext->pCertInfo->NotBefore) < 0) {
					if (err) {
						err->win32 = CERT_E_EXPIRED;
						err->message = L"Leaf certificate is not yet valid";
					}
					SS_LOG_WARN(L"CryptoUtils", L"Leaf certificate not yet valid");
					return false;
				}

				if (CompareFileTime(&now, &m_certContext->pCertInfo->NotAfter) > 0) {
					if (err) {
						err->win32 = CERT_E_EXPIRED;
						err->message = L"Leaf certificate has expired";
					}
					SS_LOG_WARN(L"CryptoUtils", L"Leaf certificate expired");
					return false;
				}

				// CA certificate time validation
				if (CompareFileTime(&now, &caCert.m_certContext->pCertInfo->NotBefore) < 0) {
					if (err) {
						err->win32 = CERT_E_EXPIRED;
						err->message = L"CA certificate is not yet valid";
					}
					SS_LOG_WARN(L"CryptoUtils", L"CA certificate not yet valid");
					return false;
				}

				if (CompareFileTime(&now, &caCert.m_certContext->pCertInfo->NotAfter) > 0) {
					if (err) {
						err->win32 = CERT_E_EXPIRED;
						err->message = L"CA certificate has expired";
					}
					SS_LOG_WARN(L"CryptoUtils", L"CA certificate expired");
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  STEP 2: CA CERTIFICATE VALIDATION (BasicConstraints)
				// ═══════════════════════════════════════════════════════════════════
				PCERT_EXTENSION pBasicConstraintsExt = CertFindExtension(
					szOID_BASIC_CONSTRAINTS2,
					caCert.m_certContext->pCertInfo->cExtension,
					caCert.m_certContext->pCertInfo->rgExtension
				);

				if (!pBasicConstraintsExt) {
					// Fallback to old OID (X.509v1/v2 compatibility)
					pBasicConstraintsExt = CertFindExtension(
						szOID_BASIC_CONSTRAINTS,
						caCert.m_certContext->pCertInfo->cExtension,
						caCert.m_certContext->pCertInfo->rgExtension
					);
				}

				if (!pBasicConstraintsExt) {
					if (err) {
						err->win32 = ERROR_INVALID_DATA;
						err->message = L"CA certificate lacks BasicConstraints extension";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"CA certificate missing BasicConstraints extension");
					return false;
				}

				CERT_BASIC_CONSTRAINTS2_INFO constraintsInfo{};
				DWORD cbConstraints = sizeof(constraintsInfo);

				if (!CryptDecodeObjectEx(
					X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
					szOID_BASIC_CONSTRAINTS2,
					pBasicConstraintsExt->Value.pbData,
					pBasicConstraintsExt->Value.cbData,
					0,
					nullptr,
					&constraintsInfo,
					&cbConstraints))
				{
					if (err) {
						err->win32 = GetLastError();
						err->message = L"Failed to decode CA BasicConstraints extension";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"CryptDecodeObjectEx failed for BasicConstraints: 0x%08X", GetLastError());
					return false;
				}

				// Verify CA flag is set
				if (!constraintsInfo.fCA) {
					if (err) {
						err->win32 = ERROR_INVALID_DATA;
						err->message = L"CA certificate is not marked as CA (fCA=FALSE)";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"CA certificate fCA flag is FALSE");
					return false;
				}

				// Verify pathLenConstraint (if present)
				if (constraintsInfo.fPathLenConstraint) {
					// For direct issuer, pathLen should allow at least 0
					if (constraintsInfo.dwPathLenConstraint < 0) {
						if (err) {
							err->win32 = ERROR_INVALID_DATA;
							err->message = L"CA certificate path length constraint violated";
						}
						SS_LOG_ERROR(L"CryptoUtils", L"CA pathLenConstraint too restrictive");
						return false;
					}
				}

				// ═══════════════════════════════════════════════════════════════════
				//  STEP 3: KEY USAGE VALIDATION (CA must have keyCertSign)
				// ═══════════════════════════════════════════════════════════════════
				PCERT_EXTENSION pKeyUsageExt = CertFindExtension(
					szOID_KEY_USAGE,
					caCert.m_certContext->pCertInfo->cExtension,
					caCert.m_certContext->pCertInfo->rgExtension
				);

				if (pKeyUsageExt) {
					CRYPT_BIT_BLOB keyUsage{};
					DWORD cbKeyUsage = sizeof(keyUsage);

					if (CryptDecodeObjectEx(
						X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
						X509_KEY_USAGE,
						pKeyUsageExt->Value.pbData,
						pKeyUsageExt->Value.cbData,
						CRYPT_DECODE_ALLOC_FLAG,
						nullptr,
						&keyUsage,
						&cbKeyUsage))
					{
						// RAII cleanup for decoded blob
						struct KeyUsageCleanup {
							CRYPT_BIT_BLOB* p;
							~KeyUsageCleanup() { if (p && p->pbData) LocalFree(p->pbData); }
						} cleanup{ &keyUsage };
			
						bool hasKeyCertSign = false;
						if (keyUsage.pbData && keyUsage.cbData > 0) {
							hasKeyCertSign = (keyUsage.pbData[0] & CERT_KEY_CERT_SIGN_KEY_USAGE) != 0;
						}

						if (!hasKeyCertSign) {
							if (err) {
								err->win32 = CERT_E_WRONG_USAGE;
								err->message = L"CA certificate lacks keyCertSign usage";
							}
							SS_LOG_ERROR(L"CryptoUtils", L"CA certificate missing keyCertSign flag");
							return false;
						}
					}
				}

				// ═══════════════════════════════════════════════════════════════════
				//  STEP 4: ISSUER-SUBJECT NAME MATCHING (Cryptographic Chain Validation)
				// ═══════════════════════════════════════════════════════════════════
				CERT_NAME_BLOB& leafIssuerName = m_certContext->pCertInfo->Issuer;
				CERT_NAME_BLOB& caSubjectName = caCert.m_certContext->pCertInfo->Subject;

				if (leafIssuerName.cbData == 0 || !leafIssuerName.pbData) {
					if (err) {
						err->win32 = ERROR_INVALID_DATA;
						err->message = L"Leaf certificate has no issuer name";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Leaf issuer name is empty");
					return false;
				}

				if (caSubjectName.cbData == 0 || !caSubjectName.pbData) {
					if (err) {
						err->win32 = ERROR_INVALID_DATA;
						err->message = L"CA certificate has no subject name";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"CA subject name is empty");
					return false;
				}

				// Exact byte-for-byte comparison (DER-encoded distinguished names)
				if (leafIssuerName.cbData != caSubjectName.cbData ||
					!SecureCompare(leafIssuerName.pbData, caSubjectName.pbData, leafIssuerName.cbData))
				{
					if (err) {
						err->win32 = CERT_E_ISSUERCHAINING;
						err->message = L"Issuer-Subject name mismatch (not issued by provided CA)";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Issuer-Subject DN mismatch");
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  STEP 5: AUTHORITY KEY IDENTIFIER VALIDATION (AKI-SKI Matching)
				// ═══════════════════════════════════════════════════════════════════
				PCERT_EXTENSION pAKIExt = CertFindExtension(
					szOID_AUTHORITY_KEY_IDENTIFIER2,
					m_certContext->pCertInfo->cExtension,
					m_certContext->pCertInfo->rgExtension
				);

				if (!pAKIExt) {
					// Fallback to old AKI OID
					pAKIExt = CertFindExtension(
						szOID_AUTHORITY_KEY_IDENTIFIER,
						m_certContext->pCertInfo->cExtension,
						m_certContext->pCertInfo->rgExtension
					);
				}

				PCERT_EXTENSION pSKIExt = CertFindExtension(
					szOID_SUBJECT_KEY_IDENTIFIER,
					caCert.m_certContext->pCertInfo->cExtension,
					caCert.m_certContext->pCertInfo->rgExtension
				);

				if (pAKIExt && pSKIExt) {
					// Decode AKI
					CERT_AUTHORITY_KEY_ID2_INFO* pAKI = nullptr;
					DWORD cbAKI = 0;

					if (CryptDecodeObjectEx(
						X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
						X509_AUTHORITY_KEY_ID2,
						pAKIExt->Value.pbData,
						pAKIExt->Value.cbData,
						CRYPT_DECODE_ALLOC_FLAG,
						nullptr,
						&pAKI,
						&cbAKI))
					{
						// RAII cleanup
						struct AKICleanup {
							CERT_AUTHORITY_KEY_ID2_INFO* p;
							~AKICleanup() { if (p) LocalFree(p); }
						} akiCleanup{ pAKI };

						// Decode SKI
						CRYPT_DATA_BLOB* pSKI = nullptr;
						DWORD cbSKI = 0;

						if (CryptDecodeObjectEx(
							X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
							szOID_SUBJECT_KEY_IDENTIFIER,
							pSKIExt->Value.pbData,
							pSKIExt->Value.cbData,
							CRYPT_DECODE_ALLOC_FLAG,
							nullptr,
							&pSKI,
							&cbSKI))
						{
							// RAII cleanup
							struct SKICleanup {
								CRYPT_DATA_BLOB* p;
								~SKICleanup() { if (p) LocalFree(p); }
							} skiCleanup{ pSKI };

							// Compare AKI KeyIdentifier with SKI
							if (pAKI->KeyId.cbData > 0 && pAKI->KeyId.pbData &&
								pSKI->cbData > 0 && pSKI->pbData)
							{
								if (pAKI->KeyId.cbData != pSKI->cbData ||
									!SecureCompare(pAKI->KeyId.pbData, pSKI->pbData, pAKI->KeyId.cbData))
								{
									if (err) {
										err->win32 = CERT_E_ISSUERCHAINING;
										err->message = L"AKI-SKI mismatch (key identifiers do not match)";
									}
									SS_LOG_ERROR(L"CryptoUtils", L"AKI-SKI key identifier mismatch");
									return false;
								}
							}
						}
					}
				}

				// ═══════════════════════════════════════════════════════════════════
				//  STEP 6: DIGITAL SIGNATURE VERIFICATION (Cryptographic Proof)
				// ═══════════════════════════════════════════════════════════════════
				// Extract the TBSCertificate (To-Be-Signed) data from leaf certificate
				DWORD tbsLen = 0;
				const BYTE* tbsData = nullptr;

				// DER-encoded certificate structure:
				// Certificate ::= SEQUENCE {
				//     tbsCertificate       TBSCertificate,
				//     signatureAlgorithm   AlgorithmIdentifier,
				//     signatureValue       BIT STRING
				// }

				// Method 1: Use CryptDecodeObjectEx to extract TBS (RECOMMENDED)
				CERT_SIGNED_CONTENT_INFO* pSignedInfo = nullptr;
				DWORD cbSignedInfo = 0;

				if (!CryptDecodeObjectEx(
					X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
					X509_CERT,
					m_certContext->pbCertEncoded,
					m_certContext->cbCertEncoded,
					CRYPT_DECODE_ALLOC_FLAG,
					nullptr,
					&pSignedInfo,
					&cbSignedInfo))
				{
					if (err) {
						err->win32 = GetLastError();
						err->message = L"Failed to decode certificate for TBS extraction";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"CryptDecodeObjectEx failed: 0x%08X", GetLastError());
					return false;
				}

				// RAII cleanup
				struct SignedInfoCleanup {
					CERT_SIGNED_CONTENT_INFO* p;
					~SignedInfoCleanup() { if (p) LocalFree(p); }
				} signedInfoCleanup{ pSignedInfo };

				tbsData = pSignedInfo->ToBeSigned.pbData;
				tbsLen = pSignedInfo->ToBeSigned.cbData;

				if (!tbsData || tbsLen == 0) {
					if (err) {
						err->win32 = ERROR_INVALID_DATA;
						err->message = L"TBSCertificate is empty";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"TBSCertificate extraction failed");
					return false;
				}

				// Extract the signature from leaf certificate
				const BYTE* signature = pSignedInfo->Signature.pbData;
				DWORD signatureLen = pSignedInfo->Signature.cbData;

				// BIT STRING format: first byte is unused bits count
				if (signatureLen < 1) {
					if (err) {
						err->win32 = ERROR_INVALID_DATA;
						err->message = L"Invalid signature format";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Signature is too short");
					return false;
				}

				// Skip the unused bits byte (usually 0x00)
				const BYTE unusedBits = signature[0];
				signature += 1;
				signatureLen -= 1;

				if (signatureLen == 0) {
					if (err) {
						err->win32 = ERROR_INVALID_DATA;
						err->message = L"Signature data is empty";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Signature is empty after BIT STRING parsing");
					return false;
				}

				// Get signature algorithm OID
				PCSTR sigAlgOid = m_certContext->pCertInfo->SignatureAlgorithm.pszObjId;
				if (!sigAlgOid) {
					if (err) {
						err->win32 = ERROR_INVALID_DATA;
						err->message = L"Certificate has no signature algorithm OID";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Signature algorithm OID is null");
					return false;
				}

				// Map OID to hash algorithm
				enum class HashAlg { SHA1, SHA256, SHA384, SHA512, Unknown };
				enum class SigScheme { RSA_PKCS1v15, RSA_PSS, ECDSA, Unknown };

				auto MapOidToAlgorithms = [](PCSTR oid) -> std::pair<SigScheme, HashAlg> {
					if (!oid) return { SigScheme::Unknown, HashAlg::Unknown };

					// RSA PKCS#1 v1.5
					if (strcmp(oid, "1.2.840.113549.1.1.5") == 0)  return { SigScheme::RSA_PKCS1v15, HashAlg::SHA1 };
					if (strcmp(oid, "1.2.840.113549.1.1.11") == 0) return { SigScheme::RSA_PKCS1v15, HashAlg::SHA256 };
					if (strcmp(oid, "1.2.840.113549.1.1.12") == 0) return { SigScheme::RSA_PKCS1v15, HashAlg::SHA384 };
					if (strcmp(oid, "1.2.840.113549.1.1.13") == 0) return { SigScheme::RSA_PKCS1v15, HashAlg::SHA512 };

					// RSA-PSS
					if (strcmp(oid, "1.2.840.113549.1.1.10") == 0) return { SigScheme::RSA_PSS, HashAlg::SHA256 };

					// ECDSA
					if (strcmp(oid, "1.2.840.10045.4.3.1") == 0) return { SigScheme::ECDSA, HashAlg::SHA1 };
					if (strcmp(oid, "1.2.840.10045.4.3.2") == 0) return { SigScheme::ECDSA, HashAlg::SHA256 };
					if (strcmp(oid, "1.2.840.10045.4.3.3") == 0) return { SigScheme::ECDSA, HashAlg::SHA384 };
					if (strcmp(oid, "1.2.840.10045.4.3.4") == 0) return { SigScheme::ECDSA, HashAlg::SHA512 };

					return { SigScheme::Unknown, HashAlg::Unknown };
					};

				auto [scheme, hashAlg] = MapOidToAlgorithms(sigAlgOid);

				if (scheme == SigScheme::Unknown || hashAlg == HashAlg::Unknown) {
					if (err) {
						err->win32 = ERROR_NOT_SUPPORTED;
						err->message = L"Unsupported signature algorithm";
						wchar_t tmp[128];
						swprintf_s(tmp, L"OID: %S", sigAlgOid);
						err->context = tmp;
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Unsupported signature OID: %S", sigAlgOid);
					return false;
				}

				// Map hash algorithm to BCrypt algorithm name
				auto MapHashAlgToBCrypt = [](HashAlg alg) -> const wchar_t* {
					switch (alg) {
					case HashAlg::SHA1:   return BCRYPT_SHA1_ALGORITHM;
					case HashAlg::SHA256: return BCRYPT_SHA256_ALGORITHM;
					case HashAlg::SHA384: return BCRYPT_SHA384_ALGORITHM;
					case HashAlg::SHA512: return BCRYPT_SHA512_ALGORITHM;
					default: return nullptr;
					}
					};

				const wchar_t* bcryptHashAlg = MapHashAlgToBCrypt(hashAlg);
				if (!bcryptHashAlg) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->message = L"Failed to map hash algorithm to BCrypt";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Hash algorithm mapping failed");
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  STEP 7: COMPUTE HASH OF TBSCertificate
				// ═══════════════════════════════════════════════════════════════════
				BCRYPT_ALG_HANDLE hHashAlg = nullptr;
				NTSTATUS st = BCryptOpenAlgorithmProvider(&hHashAlg, bcryptHashAlg, nullptr, 0);
				if (st < 0) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"Failed to open hash algorithm provider";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptOpenAlgorithmProvider failed: 0x%08X", st);
					return false;
				}

				// RAII cleanup
				struct HashProviderCleanup {
					BCRYPT_ALG_HANDLE h;
					~HashProviderCleanup() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
				} hashProvCleanup{ hHashAlg };

				DWORD hashLen = 0, cbResult = 0;
				st = BCryptGetProperty(hHashAlg, BCRYPT_HASH_LENGTH,
					reinterpret_cast<PUCHAR>(&hashLen), sizeof(hashLen), &cbResult, 0);
				if (st < 0) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"Failed to get hash length";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptGetProperty HASH_LENGTH failed: 0x%08X", st);
					return false;
				}

				std::vector<uint8_t> tbsHash(hashLen);
				st = BCryptHash(hHashAlg, nullptr, 0,
					const_cast<BYTE*>(tbsData), tbsLen,
					tbsHash.data(), static_cast<ULONG>(tbsHash.size()));
				if (st < 0) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"TBSCertificate hash computation failed";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptHash failed: 0x%08X", st);
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  STEP 8: IMPORT CA PUBLIC KEY
				// ═══════════════════════════════════════════════════════════════════
				const wchar_t* keyAlgName = nullptr;
				const wchar_t* blobType = nullptr;

				if (scheme == SigScheme::RSA_PKCS1v15 || scheme == SigScheme::RSA_PSS) {
					keyAlgName = BCRYPT_RSA_ALGORITHM;
					blobType = BCRYPT_RSAPUBLIC_BLOB;
				}
				else if (scheme == SigScheme::ECDSA) {
					keyAlgName = BCRYPT_ECDSA_P256_ALGORITHM; // Default (curve detection would be needed)
					blobType = BCRYPT_ECCPUBLIC_BLOB;
				}

				BCRYPT_ALG_HANDLE hKeyAlg = nullptr;
				st = BCryptOpenAlgorithmProvider(&hKeyAlg, keyAlgName, nullptr, 0);
				if (st < 0) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"Failed to open key algorithm provider";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptOpenAlgorithmProvider (key) failed: 0x%08X", st);
					return false;
				}

				// RAII cleanup
				struct KeyProviderCleanup {
					BCRYPT_ALG_HANDLE h;
					~KeyProviderCleanup() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
				} keyProvCleanup{ hKeyAlg };

				PCERT_PUBLIC_KEY_INFO pCAPublicKeyInfo = &caCert.m_certContext->pCertInfo->SubjectPublicKeyInfo;
				if (!pCAPublicKeyInfo->PublicKey.pbData || pCAPublicKeyInfo->PublicKey.cbData == 0) {
					if (err) {
						err->win32 = ERROR_INVALID_DATA;
						err->message = L"CA certificate has no public key";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"CA public key is empty");
					return false;
				}

				BCRYPT_KEY_HANDLE hPubKey = nullptr;
				st = BCryptImportKeyPair(hKeyAlg, nullptr, blobType, &hPubKey,
					pCAPublicKeyInfo->PublicKey.pbData, pCAPublicKeyInfo->PublicKey.cbData, 0);
				if (st < 0) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"Failed to import CA public key";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptImportKeyPair failed: 0x%08X", st);
					return false;
				}

				// RAII cleanup
				struct KeyCleanup {
					BCRYPT_KEY_HANDLE h;
					~KeyCleanup() { if (h) BCryptDestroyKey(h); }
				} keyCleanup{ hPubKey };

				// ═══════════════════════════════════════════════════════════════════
				//  STEP 9: VERIFY SIGNATURE
				// ═══════════════════════════════════════════════════════════════════
				DWORD flags = 0;
				void* paddingInfo = nullptr;

				BCRYPT_PKCS1_PADDING_INFO pkcs1Info{};
				BCRYPT_PSS_PADDING_INFO pssInfo{};

				if (scheme == SigScheme::RSA_PKCS1v15) {
					pkcs1Info.pszAlgId = bcryptHashAlg;
					paddingInfo = &pkcs1Info;
					flags = BCRYPT_PAD_PKCS1;
				}
				else if (scheme == SigScheme::RSA_PSS) {
					pssInfo.pszAlgId = bcryptHashAlg;
					pssInfo.cbSalt = static_cast<ULONG>(tbsHash.size());
					paddingInfo = &pssInfo;
					flags = BCRYPT_PAD_PSS;
				}

				st = BCryptVerifySignature(hPubKey, paddingInfo,
					tbsHash.data(), static_cast<ULONG>(tbsHash.size()),
					const_cast<BYTE*>(signature), signatureLen, flags);

				if (st == 0) {
					SS_LOG_INFO(L"CryptoUtils", L"Certificate verified successfully against CA");
					return true;
				}
				else if (st == STATUS_INVALID_SIGNATURE) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"Invalid signature - certificate not issued by CA";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Signature verification failed: Invalid signature");
					return false;
				}
				else {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"Signature verification failed";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptVerifySignature failed: 0x%08X", st);
					return false;
				}

#else
				if (err) {
					err->win32 = ERROR_NOT_SUPPORTED;
					err->message = L"Platform not supported";
				}
				return false;
#endif
			}


			bool Certificate::ExtractPublicKey(PublicKey& outKey, Error* err) const noexcept {
#ifdef _WIN32
				// ═══════════════════════════════════════════════════════════════════
				//  TIER-1 STATE VALIDATION
				// ═══════════════════════════════════════════════════════════════════
				if (!m_certContext) {
					if (err) {
						err->win32 = ERROR_INVALID_STATE;
						err->message = L"No certificate loaded (certificate context is null)";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"ExtractPublicKey: Certificate context is null");
					return false;
				}

				if (!m_certContext->pCertInfo) {
					if (err) {
						err->win32 = ERROR_INVALID_DATA;
						err->message = L"Certificate info structure is null";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"ExtractPublicKey: pCertInfo is null");
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  STEP 1: ALGORITHM OID DETECTION (RSA vs ECC)
				// ═══════════════════════════════════════════════════════════════════
				const CERT_PUBLIC_KEY_INFO& pubKeyInfo = m_certContext->pCertInfo->SubjectPublicKeyInfo;

				if (!pubKeyInfo.Algorithm.pszObjId || !*pubKeyInfo.Algorithm.pszObjId) {
					if (err) {
						err->win32 = ERROR_INVALID_DATA;
						err->message = L"Certificate has no public key algorithm OID";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"ExtractPublicKey: Algorithm OID is null or empty");
					return false;
				}

				PCSTR keyAlgOid = pubKeyInfo.Algorithm.pszObjId;

				// ═══════════════════════════════════════════════════════════════════
				//  STEP 2: OID → ALGORITHM MAPPING (Industry Standard OIDs)
				// ═══════════════════════════════════════════════════════════════════
				enum class KeyType { RSA, ECC, ED25519, UNKNOWN };

				auto MapOidToKeyType = [](PCSTR oid) -> KeyType {
					if (!oid) return KeyType::UNKNOWN;

					// ✅ RSA OID (RFC 8017)
					if (strcmp(oid, "1.2.840.113549.1.1.1") == 0) return KeyType::RSA; // rsaEncryption

					// ✅ ECC OID (SEC 2 / RFC 5480)
					if (strcmp(oid, "1.2.840.10045.2.1") == 0) return KeyType::ECC; // id-ecPublicKey

					// ✅ EdDSA (RFC 8410)
					if (strcmp(oid, "1.3.101.112") == 0) return KeyType::ED25519; // Ed25519

					return KeyType::UNKNOWN;
					};

				KeyType keyType = MapOidToKeyType(keyAlgOid);

				if (keyType == KeyType::UNKNOWN) {
					if (err) {
						err->win32 = ERROR_NOT_SUPPORTED;
						err->message = L"Unsupported public key algorithm";
						wchar_t tmp[128];
						swprintf_s(tmp, L"OID: %S", keyAlgOid);
						err->context = tmp;
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Unsupported key algorithm OID: %S", keyAlgOid);
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  STEP 3: PUBLIC KEY DATA VALIDATION (DoS Protection)
				// ═══════════════════════════════════════════════════════════════════
				if (!pubKeyInfo.PublicKey.pbData || pubKeyInfo.PublicKey.cbData == 0) {
					if (err) {
						err->win32 = ERROR_INVALID_DATA;
						err->message = L"Certificate contains no public key data";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Public key data is null or empty");
					return false;
				}

				// ✅ CRITICAL: Validate key size (prevent billion laughs attack)
				const DWORD maxKeySize = 16384; // 16KB (reasonable max for RSA-8192)
				if (pubKeyInfo.PublicKey.cbData > maxKeySize) {
					if (err) {
						err->win32 = ERROR_INVALID_DATA;
						err->message = L"Public key size exceeds maximum allowed size";
						wchar_t tmp[128];
						swprintf_s(tmp, L"Size: %lu bytes (max: %lu)", pubKeyInfo.PublicKey.cbData, maxKeySize);
						err->context = tmp;
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Public key too large: %lu bytes", pubKeyInfo.PublicKey.cbData);
					return false;
				}

				// ✅ BIT STRING format validation (ASN.1 tag 0x03)
				const BYTE* rawKeyData = pubKeyInfo.PublicKey.pbData;
				const DWORD rawKeySize = pubKeyInfo.PublicKey.cbData;

				// BIT STRING: first byte = unused bits count (must be 0-7)
				if (rawKeySize < 1) {
					if (err) {
						err->win32 = ERROR_INVALID_DATA;
						err->message = L"Invalid public key BIT STRING format (too short)";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Public key BIT STRING too short");
					return false;
				}

				const BYTE unusedBits = rawKeyData[0];
				if (unusedBits > 7) {
					if (err) {
						err->win32 = ERROR_INVALID_DATA;
						err->message = L"Invalid BIT STRING unused bits count";
						wchar_t tmp[64];
						swprintf_s(tmp, L"Unused bits: %u (expected 0-7)", unusedBits);
						err->context = tmp;
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Invalid unused bits: %u", unusedBits);
					return false;
				}

				// Extract key data (skip unused bits byte)
				const BYTE* keyData = rawKeyData + 1;
				const size_t keyDataLen = rawKeySize - 1;

				if (keyDataLen == 0) {
					if (err) {
						err->win32 = ERROR_INVALID_DATA;
						err->message = L"Public key data is empty after BIT STRING parsing";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Key data empty after BIT STRING header");
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  STEP 4: ALGORITHM-SPECIFIC PROCESSING
				// ═══════════════════════════════════════════════════════════════════
				AsymmetricAlgorithm detectedAlg = AsymmetricAlgorithm::RSA_2048; // Default

				if (keyType == KeyType::RSA) {
					// ✅ RSA: Detect key size from modulus (BCrypt blob parsing)
					// RSA public key blob format (BCrypt):
					// BCRYPT_RSAKEY_BLOB header + Exponent + Modulus

					if (keyDataLen < sizeof(BCRYPT_RSAKEY_BLOB) + 4) {
						if (err) {
							err->win32 = ERROR_INVALID_DATA;
							err->message = L"RSA public key blob too short";
						}
						SS_LOG_ERROR(L"CryptoUtils", L"RSA key blob too short: %zu bytes", keyDataLen);
						return false;
					}

					// Parse BCrypt RSA blob header
					const auto* rsaHeader = reinterpret_cast<const BCRYPT_RSAKEY_BLOB*>(keyData);

					// ✅ Validate magic number
					if (rsaHeader->Magic != BCRYPT_RSAPUBLIC_MAGIC &&
						rsaHeader->Magic != 0x31415352) { // "RSA1" in little-endian

						if (err) {
							err->win32 = ERROR_INVALID_DATA;
							err->message = L"Invalid RSA public key blob magic";
							wchar_t tmp[64];
							swprintf_s(tmp, L"Magic: 0x%08X", rsaHeader->Magic);
							err->context = tmp;
						}
						SS_LOG_ERROR(L"CryptoUtils", L"Invalid RSA magic: 0x%08X", rsaHeader->Magic);
						return false;
					}

					// ✅ Detect key size from BitLength field
					const ULONG keyBits = rsaHeader->BitLength;

					if (keyBits == 2048) {
						detectedAlg = AsymmetricAlgorithm::RSA_2048;
					}
					else if (keyBits == 3072) {
						detectedAlg = AsymmetricAlgorithm::RSA_3072;
					}
					else if (keyBits == 4096) {
						detectedAlg = AsymmetricAlgorithm::RSA_4096;
					}
					else {
						// Unsupported key size
						if (err) {
							err->win32 = ERROR_NOT_SUPPORTED;
							err->message = L"Unsupported RSA key size";
							wchar_t tmp[64];
							swprintf_s(tmp, L"Key size: %lu bits", keyBits);
							err->context = tmp;
						}
						SS_LOG_ERROR(L"CryptoUtils", L"Unsupported RSA key size: %lu bits", keyBits);
						return false;
					}

					SS_LOG_INFO(L"CryptoUtils", L"Detected RSA-%lu public key", keyBits);

				}
				else if (keyType == KeyType::ECC) {
					// ✅ ECC: Detect curve from Algorithm.Parameters (OID parsing)
					if (!pubKeyInfo.Algorithm.Parameters.pbData ||
						pubKeyInfo.Algorithm.Parameters.cbData < 3) {

						if (err) {
							err->win32 = ERROR_INVALID_DATA;
							err->message = L"ECC public key missing curve parameters";
						}
						SS_LOG_ERROR(L"CryptoUtils", L"ECC key missing curve OID");
						return false;
					}

					const BYTE* params = pubKeyInfo.Algorithm.Parameters.pbData;
					const size_t paramSize = pubKeyInfo.Algorithm.Parameters.cbData;

					// ✅ PARANOID: Validate paramSize to prevent integer overflow
					if (paramSize > 256) { // Reasonable max for OID encoding
						if (err) {
							err->win32 = ERROR_INVALID_DATA;
							err->message = L"ECC curve parameters too large";
						}
						SS_LOG_ERROR(L"CryptoUtils", L"ECC params too large: %zu bytes", paramSize);
						return false;
					}

					// ✅ ASN.1 OID format validation: TAG(0x06) + LENGTH + OID_DATA
					if (params[0] != 0x06) {
						if (err) {
							err->win32 = ERROR_INVALID_DATA;
							err->message = L"Invalid ASN.1 OID tag for ECC curve";
						}
						SS_LOG_ERROR(L"CryptoUtils", L"Invalid ASN.1 tag: 0x%02X", params[0]);
						return false;
					}

					const size_t oidLen = params[1];

					// ✅ CRITICAL: Bounds check to prevent buffer overread
					if (oidLen == 0 || oidLen + 2 > paramSize) {
						if (err) {
							err->win32 = ERROR_INVALID_DATA;
							err->message = L"Invalid OID length in ECC parameters";
						}
						SS_LOG_ERROR(L"CryptoUtils", L"Invalid OID length: %zu (max: %zu)", oidLen, paramSize - 2);
						return false;
					}

					const BYTE* oidData = params + 2;

					// ✅ ECC Curve OID Detection (NIST curves - FIPS 186-4)
					// P-256: 1.2.840.10045.3.1.7 → 06 08 2a 86 48 ce 3d 03 01 07
					// P-384: 1.3.132.0.34       → 06 05 2b 81 04 00 22
					// P-521: 1.3.132.0.35       → 06 05 2b 81 04 00 23

					if (oidLen == 8 && oidData[0] == 0x2a && oidData[1] == 0x86 &&
						oidData[2] == 0x48 && oidData[3] == 0xce && oidData[4] == 0x3d) {
						detectedAlg = AsymmetricAlgorithm::ECC_P256;
						SS_LOG_INFO(L"CryptoUtils", L"Detected ECC P-256 public key");
					}
					else if (oidLen == 5 && oidData[0] == 0x2b && oidData[1] == 0x81 &&
						oidData[2] == 0x04 && oidData[3] == 0x00) {

						if (oidData[4] == 0x22) {
							detectedAlg = AsymmetricAlgorithm::ECC_P384;
							SS_LOG_INFO(L"CryptoUtils", L"Detected ECC P-384 public key");
						}
						else if (oidData[4] == 0x23) {
							detectedAlg = AsymmetricAlgorithm::ECC_P521;
							SS_LOG_INFO(L"CryptoUtils", L"Detected ECC P-521 public key");
						}
						else {
							if (err) {
								err->win32 = ERROR_NOT_SUPPORTED;
								err->message = L"Unsupported ECC curve";
							}
							SS_LOG_ERROR(L"CryptoUtils", L"Unsupported ECC curve OID");
							return false;
						}
					}
					else {
						if (err) {
							err->win32 = ERROR_NOT_SUPPORTED;
							err->message = L"Unknown ECC curve OID";
						}
						SS_LOG_ERROR(L"CryptoUtils", L"Unknown ECC curve");
						return false;
					}

				}
				else if (keyType == KeyType::ED25519) {
					// ✅ EdDSA: Ed25519 (32-byte public key)
					if (keyDataLen != 32) {
						if (err) {
							err->win32 = ERROR_INVALID_DATA;
							err->message = L"Invalid Ed25519 key size (expected 32 bytes)";
						}
						SS_LOG_ERROR(L"CryptoUtils", L"Invalid Ed25519 key size: %zu", keyDataLen);
						return false;
					}

					// Note: Ed25519 not in AsymmetricAlgorithm enum yet(BCRYPT API does not support it) (future enhancement)
					if (err) {
						err->win32 = ERROR_NOT_SUPPORTED;
						err->message = L"Ed25519 not yet implemented in ShadowStrike";
					}
					SS_LOG_WARN(L"CryptoUtils", L"Ed25519 support not implemented");
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  STEP 5: COPY KEY BLOB TO OUTPUT (Exception-Safe)
				// ═══════════════════════════════════════════════════════════════════
				try {
					outKey.algorithm = detectedAlg;
					outKey.keyBlob.assign(keyData, keyData + keyDataLen);
				}
				catch (const std::bad_alloc&) {
					if (err) {
						err->win32 = ERROR_NOT_ENOUGH_MEMORY;
						err->message = L"Failed to allocate memory for public key blob";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Memory allocation failed for key blob (%zu bytes)", keyDataLen);
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  STEP 6: FINAL VALIDATION (Sanity Check)
				// ═══════════════════════════════════════════════════════════════════
				if (outKey.keyBlob.empty()) {
					if (err) {
						err->win32 = ERROR_INVALID_DATA;
						err->message = L"Public key blob is empty after extraction";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Key blob empty after copy");
					return false;
				}

				SS_LOG_INFO(L"CryptoUtils", L"Public key extracted successfully (%zu bytes, algorithm: %d, OID: %S)",
					outKey.keyBlob.size(), static_cast<int>(outKey.algorithm), keyAlgOid);

				return true;

#else
				if (err) {
					err->win32 = ERROR_NOT_SUPPORTED;
					err->message = L"Platform not supported (Windows only)";
				}
				return false;
#endif
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

				// Proper byte conversion
				const std::byte* ivSizeBytes = reinterpret_cast<const std::byte*>(&ivSize);
				const std::byte* tagSizeBytes = reinterpret_cast<const std::byte*>(&tagSize);

				output.insert(output.end(), ivSizeBytes, ivSizeBytes + sizeof(ivSize));
				for (auto b : iv) output.push_back(static_cast<std::byte>(b));
				output.insert(output.end(), tagSizeBytes, tagSizeBytes + sizeof(tagSize));
				for (auto b : tag) output.push_back(static_cast<std::byte>(b));
				for (auto b : ciphertext) output.push_back(static_cast<std::byte>(b));

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
				// Input validation
				if (!key || keyLen != 32) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid key (must be 32 bytes for AES-256)"; }
					return false;
				}

				std::vector<std::byte> encrypted;
				FileUtils::Error fileErr{};
				if (!FileUtils::ReadAllBytes(inputPath, encrypted, &fileErr)) {
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to read encrypted file"; }
					return false;
				}
				
				// size validation
				const size_t minSize = sizeof(uint32_t) * 2 + 12 + 16; // sizes + min salt + min iv + min tag
				if (encrypted.size() < minSize) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid encrypted file format"; }
					return false;
				}

				size_t offset = 0;
				uint32_t ivSize = 0;
				std::memcpy(&ivSize, encrypted.data() + offset, sizeof(ivSize));
				offset += sizeof(ivSize);

				// Sanity check IV size
				if (ivSize != 12 || offset + ivSize > encrypted.size()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid IV size"; }
					return false;
				}

				std::vector<uint8_t> iv(ivSize);
				std::memcpy(iv.data(), encrypted.data() + offset, ivSize);
				offset += ivSize;

				uint32_t tagSize = 0;
				std::memcpy(&tagSize, encrypted.data() + offset, sizeof(tagSize));
				offset += sizeof(tagSize);

				// Sanity check tag size
				if (tagSize != 16 || offset + tagSize > encrypted.size()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid tag size"; }
					return false;
				}

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
				if (password.empty()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Password is empty"; }
					return false;
				}

				// Derive encryption key using PBKDF2
				KDFParams kdfParams{};
				kdfParams.algorithm = KDFAlgorithm::PBKDF2_SHA256;
				kdfParams.iterations = 600000; // OWASP 2023 recommendation
				kdfParams.keyLength = 32; // AES-256

				SecureRandom rng;
				std::vector<uint8_t> salt;
				if (!rng.Generate(salt, 32, err)) return false;
				kdfParams.salt = salt;

				std::vector<uint8_t> key;
				if (!KeyDerivation::DeriveKey(password, kdfParams, key, err)) return false;

				// Read input file
				std::vector<std::byte> plaintext;
				FileUtils::Error fileErr{};
				if (!FileUtils::ReadAllBytes(inputPath, plaintext, &fileErr)) {
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to read input file"; }
					return false;
				}

				// Encrypt with AES-256-GCM
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

				// Format: [SALT_SIZE(4)][SALT][ITERATIONS(4)][IV_SIZE(4)][IV][TAG_SIZE(4)][TAG][CIPHERTEXT]
				std::vector<std::byte> output;
				const uint32_t saltSize = static_cast<uint32_t>(salt.size());
				const uint32_t iterations = kdfParams.iterations;
				const uint32_t ivSize = static_cast<uint32_t>(iv.size());
				const uint32_t tagSize = static_cast<uint32_t>(tag.size());

				const std::byte* saltSizeBytes = reinterpret_cast<const std::byte*>(&saltSize);
				const std::byte* iterationsBytes = reinterpret_cast<const std::byte*>(&iterations);
				const std::byte* ivSizeBytes = reinterpret_cast<const std::byte*>(&ivSize);
				const std::byte* tagSizeBytes = reinterpret_cast<const std::byte*>(&tagSize);

				output.insert(output.end(), saltSizeBytes, saltSizeBytes + sizeof(saltSize));
				for (auto b : salt) output.push_back(static_cast<std::byte>(b));
				output.insert(output.end(), iterationsBytes, iterationsBytes + sizeof(iterations));
				output.insert(output.end(), ivSizeBytes, ivSizeBytes + sizeof(ivSize));
				for (auto b : iv) output.push_back(static_cast<std::byte>(b));
				output.insert(output.end(), tagSizeBytes, tagSizeBytes + sizeof(tagSize));
				for (auto b : tag) output.push_back(static_cast<std::byte>(b));
				for (auto b : ciphertext) output.push_back(static_cast<std::byte>(b));

				if (!FileUtils::WriteAllBytesAtomic(outputPath, output, &fileErr)) {
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to write output file"; }
					return false;
				}

				SecureZeroMemory(key.data(), key.size());
				return true;
			}

			bool DecryptFileWithPassword(std::wstring_view inputPath,
				std::wstring_view outputPath,
				std::string_view password,
				Error* err) noexcept
			{
				if (password.empty()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Password is empty"; }
					return false;
				}

				// Read encrypted file
				std::vector<std::byte> encrypted;
				FileUtils::Error fileErr{};
				if (!FileUtils::ReadAllBytes(inputPath, encrypted, &fileErr)) {
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to read encrypted file"; }
					return false;
				}

				// Parse header: [SALT_SIZE(4)][SALT][ITERATIONS(4)][IV_SIZE(4)][IV][TAG_SIZE(4)][TAG][CIPHERTEXT]
				const size_t minSize = sizeof(uint32_t) * 4 + 32 + 12 + 16; // sizes + min salt + min iv + min tag
				if (encrypted.size() < minSize) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid encrypted file format"; }
					return false;
				}

				size_t offset = 0;

				// Read salt size and salt
				uint32_t saltSize = 0;
				std::memcpy(&saltSize, encrypted.data() + offset, sizeof(saltSize));
				offset += sizeof(saltSize);

				if (saltSize > 128 || offset + saltSize > encrypted.size()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid salt size"; }
					return false;
				}

				std::vector<uint8_t> salt(saltSize);
				std::memcpy(salt.data(), encrypted.data() + offset, saltSize);
				offset += saltSize;

				// Read iterations
				uint32_t iterations = 0;
				std::memcpy(&iterations, encrypted.data() + offset, sizeof(iterations));
				offset += sizeof(iterations);

				if (iterations < 10000 || iterations > 10000000) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid iteration count"; }
					return false;
				}

				// Read IV size and IV
				uint32_t ivSize = 0;
				std::memcpy(&ivSize, encrypted.data() + offset, sizeof(ivSize));
				offset += sizeof(ivSize);

				if (ivSize != 12 || offset + ivSize > encrypted.size()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid IV size"; }
					return false;
				}

				std::vector<uint8_t> iv(ivSize);
				std::memcpy(iv.data(), encrypted.data() + offset, ivSize);
				offset += ivSize;

				// Read tag size and tag
				uint32_t tagSize = 0;
				std::memcpy(&tagSize, encrypted.data() + offset, sizeof(tagSize));
				offset += sizeof(tagSize);

				if (tagSize != 16 || offset + tagSize > encrypted.size()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid tag size"; }
					return false;
				}

				std::vector<uint8_t> tag(tagSize);
				std::memcpy(tag.data(), encrypted.data() + offset, tagSize);
				offset += tagSize;

				const size_t ciphertextSize = encrypted.size() - offset;
				const uint8_t* ciphertext = reinterpret_cast<const uint8_t*>(encrypted.data() + offset);

				// Derive key
				KDFParams kdfParams{};
				kdfParams.algorithm = KDFAlgorithm::PBKDF2_SHA256;
				kdfParams.iterations = iterations;
				kdfParams.keyLength = 32;
				kdfParams.salt = salt;

				std::vector<uint8_t> key;
				if (!KeyDerivation::DeriveKey(password, kdfParams, key, err)) return false;

				// Decrypt
				SymmetricCipher cipher(SymmetricAlgorithm::AES_256_GCM);
				// DÜZELTME: keyLen tanımsızdı — vector overloadunu kullanıyoruz
				if (!cipher.SetKey(key, err)) return false;
				if (!cipher.SetIV(iv, err)) return false;

				std::vector<uint8_t> plaintext;
				if (!cipher.DecryptAEAD(ciphertext, ciphertextSize, nullptr, 0, tag.data(), tag.size(), plaintext, err)) {
					return false;
				}

				// Convert to std::byte
				std::vector<std::byte> output;
				output.reserve(plaintext.size());
				std::transform(plaintext.begin(), plaintext.end(), std::back_inserter(output),
					[](uint8_t b) { return static_cast<std::byte>(b); }
				);

				if (!FileUtils::WriteAllBytesAtomic(outputPath, output, &fileErr)) {
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to write output file"; }
					return false;
				}

				SecureZeroMemory(key.data(), key.size());
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
				// Input validation
				if (!key || keyLen != 32) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid key (must be 32 bytes)"; }
					return false;
				}

				if (base64Ciphertext.empty()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Empty ciphertext"; }
					return false;
				}

				std::vector<uint8_t> combined;
				if (!Base64::Decode(base64Ciphertext, combined)) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Base64 decode failed"; }
					return false;
				}

				const size_t minSize = sizeof(uint32_t) * 2 + 12 + 16;
				if (combined.size() < minSize) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid encrypted data format"; }
					return false;
				}

				size_t offset = 0;
				uint32_t ivSize = 0;
				std::memcpy(&ivSize, combined.data() + offset, sizeof(ivSize));
				offset += sizeof(ivSize);

				// Validate IV size
				if (ivSize != 12 || offset + ivSize > combined.size()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid IV size"; }
					return false;
				}

				std::vector<uint8_t> iv(ivSize);
				std::memcpy(iv.data(), combined.data() + offset, ivSize);
				offset += ivSize;

				uint32_t tagSize = 0;
				std::memcpy(&tagSize, combined.data() + offset, sizeof(tagSize));
				offset += sizeof(tagSize);

				// Validate tag size
				if (tagSize != 16 || offset + tagSize > combined.size()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid tag size"; }
					return false;
				}

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
            // PE Signature Verification (ENTERPRISE-GRADE)
            // =============================================================================

			bool VerifyPESignature(std::wstring_view filePath,
				SignatureInfo& info,
				Error* err) noexcept
			{
#ifdef _WIN32
				// ═══════════════════════════════════════════════════════════════════
				//  TIER-1 INPUT VALIDATION
				// ═══════════════════════════════════════════════════════════════════
				if (filePath.empty()) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->message = L"File path cannot be empty";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"VerifyPESignature: Empty file path");
					return false;
				}

				// Clear output structure
				std::memset(&info, 0, sizeof(info));

				// ═══════════════════════════════════════════════════════════════════
				//  STEP 1: FILE EXISTENCE AND ACCESS VALIDATION
				// ═══════════════════════════════════════════════════════════════════
				DWORD fileAttribs = GetFileAttributesW(filePath.data());
				if (fileAttribs == INVALID_FILE_ATTRIBUTES) {
					DWORD dwErr = GetLastError();
					if (err) {
						err->win32 = dwErr;
						err->message = L"File not found or access denied";
						err->context = std::wstring(filePath);
					}
					SS_LOG_ERROR(L"CryptoUtils", L"File not accessible: %s (0x%08X)",
						filePath.data(), dwErr);
					return false;
				}

				// Reject directories
				if (fileAttribs & FILE_ATTRIBUTE_DIRECTORY) {
					if (err) {
						err->win32 = ERROR_DIRECTORY;
						err->message = L"Path is a directory, not a file";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Path is directory: %s", filePath.data());
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  STEP 2: WINTRUST STRUCTURES INITIALIZATION
				// ═══════════════════════════════════════════════════════════════════
				WINTRUST_FILE_INFO fileInfo{};
				std::wstring path(filePath);
				fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
				fileInfo.pcwszFilePath = path.c_str();
				fileInfo.hFile = nullptr;
				fileInfo.pgKnownSubject = nullptr;

				GUID actionVerify = WINTRUST_ACTION_GENERIC_VERIFY_V2;

				WINTRUST_DATA winTrustData{};
				winTrustData.cbStruct = sizeof(WINTRUST_DATA);
				winTrustData.pPolicyCallbackData = nullptr;
				winTrustData.pSIPClientData = nullptr;
				winTrustData.dwUIChoice = WTD_UI_NONE;
				winTrustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN; // ✅ CRITICAL: Full chain revocation
				winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
				winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
				winTrustData.hWVTStateData = nullptr;
				winTrustData.pwszURLReference = nullptr;
				winTrustData.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN | WTD_CACHE_ONLY_URL_RETRIEVAL;
				winTrustData.dwUIContext = 0;
				winTrustData.pFile = &fileInfo;

				// ═══════════════════════════════════════════════════════════════════
				//  STEP 3: PRIMARY SIGNATURE VERIFICATION
				// ═══════════════════════════════════════════════════════════════════
				LONG verifyResult = WinVerifyTrust(
					static_cast<HWND>(INVALID_HANDLE_VALUE),
					&actionVerify,
					&winTrustData
				);

				// Update signature status flags
				info.isSigned = (verifyResult == ERROR_SUCCESS ||
					verifyResult == TRUST_E_NOSIGNATURE ||
					verifyResult == TRUST_E_SUBJECT_NOT_TRUSTED ||
					verifyResult == CERT_E_EXPIRED ||
					verifyResult == CERT_E_REVOKED ||
					verifyResult == CERT_E_UNTRUSTEDROOT);

				info.isVerified = (verifyResult == ERROR_SUCCESS);

				// ═══════════════════════════════════════════════════════════════════
				//  STEP 4: DETAILED ERROR ANALYSIS
				// ═══════════════════════════════════════════════════════════════════
				if (verifyResult != ERROR_SUCCESS) {
					if (err) {
						err->win32 = static_cast<DWORD>(verifyResult);

						switch (verifyResult) {
						case TRUST_E_NOSIGNATURE:
							err->message = L"File is not digitally signed";
							SS_LOG_INFO(L"CryptoUtils", L"Unsigned file: %s", filePath.data());
							break;

						case TRUST_E_SUBJECT_NOT_TRUSTED:
							err->message = L"Signature is not trusted (untrusted publisher)";
							SS_LOG_WARN(L"CryptoUtils", L"Untrusted signature: %s", filePath.data());
							break;

						case TRUST_E_PROVIDER_UNKNOWN:
							err->message = L"Unknown trust provider";
							break;

						case TRUST_E_BAD_DIGEST:
							err->message = L"Invalid signature digest (file may be tampered)";
							SS_LOG_ERROR(L"CryptoUtils", L"Bad digest (tampering detected): %s", filePath.data());
							break;

						case CERT_E_EXPIRED:
							err->message = L"Signing certificate has expired";
							SS_LOG_WARN(L"CryptoUtils", L"Expired certificate: %s", filePath.data());
							break;

						case CERT_E_REVOKED:
							err->message = L"Signing certificate has been revoked";
							SS_LOG_ERROR(L"CryptoUtils", L"Revoked certificate: %s", filePath.data());
							break;

						case CERT_E_UNTRUSTEDROOT:
							err->message = L"Certificate chain is not trusted (untrusted root CA)";
							break;

						case CERT_E_CHAINING:
							err->message = L"Certificate chain verification failed";
							break;

						case CRYPT_E_FILE_ERROR:
							err->message = L"File read error during verification";
							break;

						case CRYPT_E_SECURITY_SETTINGS:
							err->message = L"Security settings prevent verification";
							break;

						default:
							err->message = L"Signature verification failed (unknown error)";
							wchar_t tmp[64];
							swprintf_s(tmp, L"Error code: 0x%08X", verifyResult);
							err->context = tmp;
							break;
						}
					}
				}

				// ═══════════════════════════════════════════════════════════════════
				//  STEP 5: EXTRACT SIGNER INFORMATION (If signed)
				// ═══════════════════════════════════════════════════════════════════
				if (info.isSigned && winTrustData.hWVTStateData) {
					CRYPT_PROVIDER_DATA* pProvData = WTHelperProvDataFromStateData(winTrustData.hWVTStateData);
					if (pProvData) {
						CRYPT_PROVIDER_SGNR* pSigner = WTHelperGetProvSignerFromChain(pProvData, 0, FALSE, 0);
						if (pSigner) {
							// ═══════════════════════════════════════════════════════════
							//  STEP 5.1: EXTRACT SIGNING CERTIFICATE
							// ═══════════════════════════════════════════════════════════
							CRYPT_PROVIDER_CERT* pCert = WTHelperGetProvCertFromChain(pSigner, 0);
							if (pCert && pCert->pCert) {
								PCCERT_CONTEXT pCertContext = pCert->pCert;

								// Extract Subject Name (Signer)
								DWORD subjectSize = CertGetNameStringW(
									pCertContext,
									CERT_NAME_SIMPLE_DISPLAY_TYPE,
									0,
									nullptr,
									nullptr,
									0
								);

								if (subjectSize > 1) {
									std::wstring subject(subjectSize - 1, L'\0');
									CertGetNameStringW(
										pCertContext,
										CERT_NAME_SIMPLE_DISPLAY_TYPE,
										0,
										nullptr,
										&subject[0],
										subjectSize
									);
									info.signerName = subject;
								}

								// Extract Issuer Name (CA)
								DWORD issuerSize = CertGetNameStringW(
									pCertContext,
									CERT_NAME_SIMPLE_DISPLAY_TYPE,
									CERT_NAME_ISSUER_FLAG,
									nullptr,
									nullptr,
									0
								);

								if (issuerSize > 1) {
									std::wstring issuer(issuerSize - 1, L'\0');
									CertGetNameStringW(
										pCertContext,
										CERT_NAME_SIMPLE_DISPLAY_TYPE,
										CERT_NAME_ISSUER_FLAG,
										nullptr,
										&issuer[0],
										issuerSize
									);
									info.issuerName = issuer;
								}

								// Extract Email (if available)
								DWORD emailSize = CertGetNameStringW(
									pCertContext,
									CERT_NAME_EMAIL_TYPE,
									0,
									nullptr,
									nullptr,
									0
								);

								if (emailSize > 1) {
									std::wstring email(emailSize - 1, L'\0');
									CertGetNameStringW(
										pCertContext,
										CERT_NAME_EMAIL_TYPE,
										0,
										nullptr,
										&email[0],
										emailSize
									);
									info.signerEmail = email;
								}

								// Extract Certificate Thumbprint (SHA-256)
								BYTE thumbprint[32] = {}; // SHA-256 = 32 bytes
								DWORD thumbprintSize = sizeof(thumbprint);

								if (CertGetCertificateContextProperty(
									pCertContext,
									CERT_SHA256_HASH_PROP_ID, // USE SHA-256 (not SHA-1)
									thumbprint,
									&thumbprintSize))
								{
									std::wstring thumb;
									thumb.reserve(thumbprintSize * 2);
									for (DWORD i = 0; i < thumbprintSize; ++i) {
										wchar_t buf[3];
										swprintf_s(buf, L"%02X", thumbprint[i]);
										thumb += buf;
									}
									info.thumbprint = thumb;
								}
								else {
									// Fallback to SHA-1 if SHA-256 not available
									thumbprintSize = 20;
									if (CertGetCertificateContextProperty(
										pCertContext,
										CERT_HASH_PROP_ID,
										thumbprint,
										&thumbprintSize))
									{
										std::wstring thumb;
										thumb.reserve(thumbprintSize * 2);
										for (DWORD i = 0; i < thumbprintSize; ++i) {
											wchar_t buf[3];
											swprintf_s(buf, L"%02X", thumbprint[i]);
											thumb += buf;
										}
										info.thumbprint = thumb;
									}
								}

								// ═══════════════════════════════════════════════════════════════════
                                //  STEP 5.2: EXTRACT SIGNATURE TIMESTAMP (RFC 3161)
                                // ═══════════════════════════════════════════════════════════════════
								bool timestampFound = false;

								// Method 1: Counter-signature içinde timestamp ara
								if (pSigner->csCounterSigners > 0 && pSigner->pasCounterSigners) {
									for (DWORD cs = 0; cs < pSigner->csCounterSigners && !timestampFound; ++cs) {
										CRYPT_PROVIDER_SGNR* pCounterSigner = &pSigner->pasCounterSigners[cs];

										if (pCounterSigner->psSigner && pCounterSigner->psSigner->AuthAttrs.cAttr > 0) {
											// Authenticated attributes içinde szOID_RSA_signingTime ara
											for (DWORD i = 0; i < pCounterSigner->psSigner->AuthAttrs.cAttr; ++i) {
												const CRYPT_ATTRIBUTE& attr = pCounterSigner->psSigner->AuthAttrs.rgAttr[i];

												if (strcmp(attr.pszObjId, szOID_RSA_signingTime) == 0 && attr.cValue > 0) {
													// Decode signing time
													FILETIME ft{};
													DWORD cbData = sizeof(ft);

													if (CryptDecodeObjectEx(
														X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
														szOID_RSA_signingTime,
														attr.rgValue[0].pbData,
														attr.rgValue[0].cbData,
														0,
														nullptr,
														&ft,
														&cbData))
													{
														info.signTime = ft;
														timestampFound = true;

														// Logging (optional)
														SYSTEMTIME st{};
														if (FileTimeToSystemTime(&ft, &st)) {
															SS_LOG_INFO(L"CryptoUtils",
																L"Signature timestamp: %04d-%02d-%02d %02d:%02d:%02d UTC",
																st.wYear, st.wMonth, st.wDay,
																st.wHour, st.wMinute, st.wSecond);
														}
													}
													break;
												}
											}
										}
									}
								}

								// Method 2: Fallback - Find timestamp in main signer attributes
								if (!timestampFound && pSigner->psSigner && pSigner->psSigner->AuthAttrs.cAttr > 0) {
									for (DWORD i = 0; i < pSigner->psSigner->AuthAttrs.cAttr; ++i) {
										const CRYPT_ATTRIBUTE& attr = pSigner->psSigner->AuthAttrs.rgAttr[i];

										if (strcmp(attr.pszObjId, szOID_RSA_signingTime) == 0 && attr.cValue > 0) {
											FILETIME ft{};
											DWORD cbData = sizeof(ft);

											if (CryptDecodeObjectEx(
												X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
												szOID_RSA_signingTime,
												attr.rgValue[0].pbData,
												attr.rgValue[0].cbData,
												0,
												nullptr,
												&ft,
												&cbData))
											{
												info.signTime = ft;
												timestampFound = true;

												SS_LOG_INFO(L"CryptoUtils", L"Timestamp found in main signer attributes");
											}
											break;
										}
									}
								}

								if (!timestampFound) {
									SS_LOG_INFO(L"CryptoUtils", L"No timestamp found in signature");
								}
								// ═══════════════════════════════════════════════════════
								//  STEP 5.3: BUILD CERTIFICATE CHAIN
								// ═══════════════════════════════════════════════════════
								for (DWORD i = 0; i < pSigner->csCertChain; ++i) {
									CRYPT_PROVIDER_CERT* pChainCert = &pSigner->pasCertChain[i];
									if (pChainCert && pChainCert->pCert) {
										CertificateInfo chainInfo{};

										// Extract subject
										DWORD chainSubjectSize = CertGetNameStringW(
											pChainCert->pCert,
											CERT_NAME_SIMPLE_DISPLAY_TYPE,
											0,
											nullptr,
											nullptr,
											0
										);

										if (chainSubjectSize > 1) {
											std::wstring chainSubject(chainSubjectSize - 1, L'\0');
											CertGetNameStringW(
												pChainCert->pCert,
												CERT_NAME_SIMPLE_DISPLAY_TYPE,
												0,
												nullptr,
												&chainSubject[0],
												chainSubjectSize
											);
											chainInfo.subject = chainSubject;
										}

										// Extract issuer
										DWORD chainIssuerSize = CertGetNameStringW(
											pChainCert->pCert,
											CERT_NAME_SIMPLE_DISPLAY_TYPE,
											CERT_NAME_ISSUER_FLAG,
											nullptr,
											nullptr,
											0
										);

										if (chainIssuerSize > 1) {
											std::wstring chainIssuer(chainIssuerSize - 1, L'\0');
											CertGetNameStringW(
												pChainCert->pCert,
												CERT_NAME_SIMPLE_DISPLAY_TYPE,
												CERT_NAME_ISSUER_FLAG,
												nullptr,
												&chainIssuer[0],
												chainIssuerSize
											);
											chainInfo.issuer = chainIssuer;
										}

										// Check if CA certificate
										PCERT_EXTENSION pBasicConstraints = CertFindExtension(
											szOID_BASIC_CONSTRAINTS2,
											pChainCert->pCert->pCertInfo->cExtension,
											pChainCert->pCert->pCertInfo->rgExtension
										);

										if (pBasicConstraints) {
											CERT_BASIC_CONSTRAINTS2_INFO constraints{};
											DWORD cbConstraints = sizeof(constraints);

											if (CryptDecodeObjectEx(
												X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
												szOID_BASIC_CONSTRAINTS2,
												pBasicConstraints->Value.pbData,
												pBasicConstraints->Value.cbData,
												0,
												nullptr,
												&constraints,
												&cbConstraints))
											{
												chainInfo.isCA = (constraints.fCA == TRUE);
											}
										}

										// Check expiration
										FILETIME now;
										GetSystemTimeAsFileTime(&now);
										chainInfo.isExpired = (CompareFileTime(&now, &pChainCert->pCert->pCertInfo->NotAfter) > 0);

										info.certificateChain.push_back(chainInfo);
									}
								}
							}

							// ═══════════════════════════════════════════════════════════
							//  STEP 5.4: VALIDATE HASH ALGORITHM (Reject SHA-1)
							// ═══════════════════════════════════════════════════════════
							if (pSigner->psSigner && pSigner->psSigner->HashAlgorithm.pszObjId) {
								const char* hashOid = pSigner->psSigner->HashAlgorithm.pszObjId;

								// ✅ CRITICAL: Reject weak hash algorithms
								if (strcmp(hashOid, szOID_OIWSEC_sha1) == 0 ||
									strcmp(hashOid, szOID_RSA_MD5) == 0) {

									if (err && info.isVerified) {
										err->win32 = TRUST_E_BAD_DIGEST;
										err->message = L"Weak hash algorithm detected (SHA-1/MD5 not allowed)";
										err->context = L"Hash: ";
										err->context += (strcmp(hashOid, szOID_OIWSEC_sha1) == 0) ? L"SHA-1" : L"MD5";
									}

									SS_LOG_WARN(L"CryptoUtils",
										L"Weak hash algorithm in signature: %s (file: %s)",
										(strcmp(hashOid, szOID_OIWSEC_sha1) == 0) ? L"SHA-1" : L"MD5",
										filePath.data());

									// Mark as unverified due to weak crypto
									info.isVerified = false;
								}
							}
						}
					}
				}

				// ═══════════════════════════════════════════════════════════════════
				//  STEP 6: CLEANUP WINTRUST STATE
				// ═══════════════════════════════════════════════════════════════════
				winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
				WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &actionVerify, &winTrustData);

				// ═══════════════════════════════════════════════════════════════════
				//  STEP 7: FINAL LOGGING
				// ═══════════════════════════════════════════════════════════════════
				if (info.isVerified) {
					SS_LOG_INFO(L"CryptoUtils",
						L"Signature verified successfully - File: %s, Signer: %s, Issuer: %s",
						filePath.data(),
						info.signerName.c_str(),
						info.issuerName.c_str());
				}
				else if (info.isSigned) {
					SS_LOG_WARN(L"CryptoUtils",
						L"Signature verification failed - File: %s, Status: 0x%08X",
						filePath.data(),
						verifyResult);
				}
				else {
					SS_LOG_INFO(L"CryptoUtils", L"File not signed: %s", filePath.data());
				}

				return true;

#else
				if (err) {
					err->win32 = ERROR_NOT_SUPPORTED;
					err->message = L"Platform not supported (Windows only)";
				}
				return false;
#endif
			}
			
				bool VerifyCatalogSignature(std::wstring_view catalogPath,
					std::wstring_view fileHash,
					SignatureInfo & info,
					Error * err) noexcept
			{
#ifdef _WIN32
				// Windows Catalog API signature verification
				// Used for verifying driver/system file signatures against catalog files

				std::memset(&info, 0, sizeof(info));

				if (catalogPath.empty() || fileHash.empty()) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->message = L"Catalog path or file hash cannot be empty";
					}
					return false;
				}

				// Convert hex hash string to binary
				std::vector<uint8_t> hashBytes;
				std::string hashStr;
				hashStr.reserve(fileHash.size());
				for (wchar_t wc : fileHash) {
					hashStr.push_back(static_cast<char>(wc));
				}

				if (!HashUtils::FromHex(hashStr, hashBytes)) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->message = L"Invalid file hash format (expected hexadecimal string)";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Invalid hash format: %s", fileHash.data());
					return false;
				}

				// Validate hash size (must be SHA-1 or SHA-256)
				if (hashBytes.size() != 20 && hashBytes.size() != 32) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->message = L"Invalid hash size (expected 20 or 32 bytes)";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"Invalid hash size: %zu bytes", hashBytes.size());
					return false;
				}

				// Step 1: Acquire Catalog Admin Context
				HCATADMIN hCatAdmin = nullptr;
				if (!CryptCATAdminAcquireContext(&hCatAdmin, nullptr, 0)) {
					DWORD dwErr = GetLastError();
					if (err) {
						err->win32 = dwErr;
						err->message = L"Failed to acquire catalog admin context";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"CryptCATAdminAcquireContext failed: 0x%08X", dwErr);
					return false;
				}

				// RAII wrapper for catalog admin context
				struct CatAdminCleanup {
					HCATADMIN h;
					~CatAdminCleanup() { if (h) CryptCATAdminReleaseContext(h, 0); }
				} catAdminCleanup{ hCatAdmin };

				// Step 2: Open the catalog file
				HANDLE hCatalog = CryptCATOpen(const_cast<wchar_t*>(catalogPath.data()),
					CRYPTCAT_OPEN_EXISTING, 0, 0, 0);

				if (hCatalog == INVALID_HANDLE_VALUE) {
					DWORD dwErr = GetLastError();
					if (err) {
						err->win32 = dwErr;
						err->message = L"Failed to open catalog file";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"CryptCATOpen failed for: %s (0x%08X)",
						catalogPath.data(), dwErr);
					return false;
				}

				// RAII wrapper for catalog handle
				struct CatalogCleanup {
					HANDLE h;
					~CatalogCleanup() { if (h != INVALID_HANDLE_VALUE) CryptCATClose(h); }
				} catalogCleanup{ hCatalog };

				// Step 3: Get catalog info (for signature verification)
				CATALOG_INFO catInfo{};
				catInfo.cbStruct = sizeof(catInfo);

				if (!CryptCATCatalogInfoFromContext(hCatalog, &catInfo, 0)) {
					DWORD dwErr = GetLastError();
					if (err) {
						err->win32 = dwErr;
						err->message = L"Failed to get catalog information";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"CryptCATCatalogInfoFromContext failed: 0x%08X", dwErr);
					return false;
				}

				// Step 4: Verify catalog signature using WinVerifyTrust
				WINTRUST_CATALOG_INFO wtCatInfo{};
				wtCatInfo.cbStruct = sizeof(wtCatInfo);
				wtCatInfo.dwCatalogVersion = 0;
				wtCatInfo.pcwszCatalogFilePath = catalogPath.data();
				wtCatInfo.pcwszMemberTag = nullptr; // Will be set below after finding member
				wtCatInfo.pcwszMemberFilePath = nullptr;
				wtCatInfo.hMemberFile = nullptr;
				wtCatInfo.pbCalculatedFileHash = hashBytes.data();
				wtCatInfo.cbCalculatedFileHash = static_cast<DWORD>(hashBytes.size());
				wtCatInfo.pcCatalogContext = nullptr;
				wtCatInfo.hCatAdmin = hCatAdmin;

				// Step 5: Search for file hash in catalog
				CRYPTCATMEMBER* pMember = nullptr;
				BYTE hashTag[256] = {}; // Tag buffer for hash lookup
				DWORD hashTagSize = static_cast<DWORD>(hashBytes.size());
				std::memcpy(hashTag, hashBytes.data(), hashTagSize);

				// Enumerate catalog members to find matching hash
				pMember = CryptCATEnumerateMember(hCatalog, nullptr);
				bool hashFound = false;

				while (pMember != nullptr) {
					// Compare hash with member's reference tag
					if (pMember->pIndirectData &&
						pMember->pIndirectData->Digest.cbData == hashBytes.size()) {

						if (std::memcmp(
							pMember->pIndirectData->Digest.pbData,
							hashBytes.data(),
							hashBytes.size()) == 0) {

							hashFound = true;

							// Set member tag for WinVerifyTrust
							wtCatInfo.pcwszMemberTag = pMember->pwszReferenceTag;

							SS_LOG_INFO(L"CryptoUtils", L"Hash found in catalog: %s",
								pMember->pwszReferenceTag ? pMember->pwszReferenceTag : L"<no-tag>");
							break;
						}
					}

					pMember = CryptCATEnumerateMember(hCatalog, pMember);
				}

				if (!hashFound) {
					if (err) {
						err->win32 = ERROR_NOT_FOUND;
						err->message = L"File hash not found in catalog";
					}
					SS_LOG_INFO(L"CryptoUtils", L"Hash not found in catalog: %s", catalogPath.data());
					return false;
				}

				// Step 6: Verify catalog signature with WinVerifyTrust
				GUID policyGUID = DRIVER_ACTION_VERIFY; // Use driver policy for catalog verification

				WINTRUST_DATA winTrustData{};
				winTrustData.cbStruct = sizeof(winTrustData);
				winTrustData.pPolicyCallbackData = nullptr;
				winTrustData.pSIPClientData = nullptr;
				winTrustData.dwUIChoice = WTD_UI_NONE;
				winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
				winTrustData.dwUnionChoice = WTD_CHOICE_CATALOG;
				winTrustData.pCatalog = &wtCatInfo;
				winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
				winTrustData.hWVTStateData = nullptr;
				winTrustData.pwszURLReference = nullptr;
				winTrustData.dwProvFlags = WTD_SAFER_FLAG;
				winTrustData.dwUIContext = 0;

				LONG verifyResult = WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

				info.isSigned = (verifyResult == ERROR_SUCCESS ||
					verifyResult == TRUST_E_NOSIGNATURE ||
					verifyResult == TRUST_E_SUBJECT_NOT_TRUSTED);
				info.isVerified = (verifyResult == ERROR_SUCCESS);

				// Step 7: Extract signer information if signature is valid
				if (verifyResult == ERROR_SUCCESS) {
					CRYPT_PROVIDER_DATA* pProvData = WTHelperProvDataFromStateData(winTrustData.hWVTStateData);
					if (pProvData) {
						CRYPT_PROVIDER_SGNR* pSigner = WTHelperGetProvSignerFromChain(pProvData, 0, FALSE, 0);
						if (pSigner) {
							CRYPT_PROVIDER_CERT* pCert = WTHelperGetProvCertFromChain(pSigner, 0);
							if (pCert && pCert->pCert) {
								PCCERT_CONTEXT pCertContext = pCert->pCert;

								// Extract signer name
								DWORD subjectSize = CertGetNameStringW(pCertContext,
									CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
								if (subjectSize > 1) {
									std::wstring subject(subjectSize - 1, L'\0');
									CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE,
										0, nullptr, &subject[0], subjectSize);
									info.signerName = subject;
								}

								// Extract issuer name
								DWORD issuerSize = CertGetNameStringW(pCertContext,
									CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nullptr, nullptr, 0);
								if (issuerSize > 1) {
									std::wstring issuer(issuerSize - 1, L'\0');
									CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE,
										CERT_NAME_ISSUER_FLAG, nullptr, &issuer[0], issuerSize);
									info.issuerName = issuer;
								}

								// Extract thumbprint
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

					SS_LOG_INFO(L"CryptoUtils", L"Catalog signature verified successfully - Catalog: %s, Signer: %s",
						catalogPath.data(), info.signerName.c_str());
				}
				else {
					if (err) {
						err->win32 = static_cast<DWORD>(verifyResult);
						err->message = L"Catalog signature verification failed";

						switch (verifyResult) {
						case TRUST_E_NOSIGNATURE:
							err->context = L"Catalog is not signed";
							break;
						case TRUST_E_SUBJECT_NOT_TRUSTED:
							err->context = L"Catalog signature is not trusted";
							break;
						case TRUST_E_PROVIDER_UNKNOWN:
							err->context = L"Unknown trust provider";
							break;
						case TRUST_E_BAD_DIGEST:
							err->context = L"Invalid signature digest";
							break;
						case CRYPT_E_FILE_ERROR:
							err->context = L"Catalog file read error";
							break;
						default:
							err->context = L"Signature verification failed (unspecified)";
							break;
						}
					}
					SS_LOG_ERROR(L"CryptoUtils",
						L"Catalog signature verification failed: 0x%08X for %s",
						verifyResult, catalogPath.data());
				}

				// Cleanup WinVerifyTrust state
				winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
				WinVerifyTrust(nullptr, &policyGUID, &winTrustData);

				return info.isVerified;

#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}


			//Will be added later.

				bool CryptoUtils::CheckCodeSigningEKU(PCCERT_CONTEXT certContext,
					Error* err) noexcept
				{
					if(err)
					{
						err->win32 = ERROR_NOT_SUPPORTED;
						err->message = L"Not implemented yet.";
						return false;
					}
					return false;
				}

				bool CryptoUtils::ValidateTimestamp(const FILETIME& signTime, PCCERT_CONTEXT cert, Error* err) noexcept
				{
					if (err)
					{
						err->win32 = ERROR_NOT_SUPPORTED;
						err->message = L"Not implemented yet.";
						return false;
					}
					return false;
				}
					bool CheckRevocationOnline(PCCERT_CONTEXT cert, Error * err) noexcept {
					if (err)
					{
						err->win32 = ERROR_NOT_SUPPORTED;
						err->message = L"Not implemented yet.";
						return false;
					}
					return false;
				}

					//Plus multiple signature helpers will be added later.

		} // namespace CryptoUtils
	} // namespace Utils
} // namespace ShadowStrike
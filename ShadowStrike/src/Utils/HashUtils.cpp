
#include "HashUtils.hpp"

#include <algorithm>
#include <memory>
#include <cstdio>

namespace ShadowStrike {
	namespace Utils {
		namespace HashUtils {

#ifdef _WIN32

			struct AlgProv {
				BCRYPT_ALG_HANDLE hAlg = nullptr;      // normal hash
				BCRYPT_ALG_HANDLE hAlgHmac = nullptr;  //for HMAC
				DWORD hashLen = 0;
				DWORD objLen = 0;
				DWORD objLenHmac = 0;
				bool ready = false;
				LONG lastNt = 0;
			};

			static const wchar_t* AlgName(Algorithm a) noexcept {
				switch (a) {
				case Algorithm::SHA1:   return BCRYPT_SHA1_ALGORITHM;
				case Algorithm::SHA256: return BCRYPT_SHA256_ALGORITHM;
				case Algorithm::SHA384: return BCRYPT_SHA384_ALGORITHM;
				case Algorithm::SHA512: return BCRYPT_SHA512_ALGORITHM;
				case Algorithm::MD5:    return BCRYPT_MD5_ALGORITHM;
				default:                return BCRYPT_SHA256_ALGORITHM;
				}
			}

			static AlgProv& GetProv(Algorithm a) {
				static AlgProv sha1, sha256, sha384, sha512, md5;
				switch (a) {
				case Algorithm::SHA1:   return sha1;
				case Algorithm::SHA256: return sha256;
				case Algorithm::SHA384: return sha384;
				case Algorithm::SHA512: return sha512;
				case Algorithm::MD5:    return md5;
				}
				return sha256;
			}

			static bool EnsureProv(Algorithm a, Error* err) {
				AlgProv& ap = GetProv(a);
				static std::once_flag onceFlags[5];
				const int idx = static_cast<int>(a);
				std::call_once(onceFlags[idx], [&]() {
					const wchar_t* name = AlgName(a);

					NTSTATUS st = BCryptOpenAlgorithmProvider(&ap.hAlg, name, nullptr, 0);
					ap.lastNt = st;
					if (st < 0) {
						return;
					}

					DWORD cb = 0;
					st = BCryptGetProperty(ap.hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&ap.hashLen), sizeof(ap.hashLen), &cb, 0);
					ap.lastNt = st;
					if (st < 0) return;

					st = BCryptGetProperty(ap.hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&ap.objLen), sizeof(ap.objLen), &cb, 0);
					ap.lastNt = st;
					if (st < 0) return;

					// HMAC
					st = BCryptOpenAlgorithmProvider(&ap.hAlgHmac, name, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
					ap.lastNt = st;
					if (st < 0) return;

					st = BCryptGetProperty(ap.hAlgHmac, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&ap.objLenHmac), sizeof(ap.objLenHmac), &cb, 0);
					ap.lastNt = st;
					if (st < 0) return;

					ap.ready = true;
					});

				if (!ap.ready) {
					if (err) { err->ntstatus = ap.lastNt; err->win32 = RtlNtStatusToDosError(ap.lastNt); }
					SS_LOG_ERROR(L"HashUtils", L"BCryptOpenAlgorithmProvider failed for %ls (nt=0x%08X, win32=%lu)", AlgName(a), ap.lastNt, err ? err->win32 : 0);
					return false;
				}
				return true;
			}
#endif //_WIN32


			size_t DigestSize(Algorithm alg) noexcept {
				switch (alg) {
				case Algorithm::SHA1:   return 20;
				case Algorithm::SHA256: return 32;
				case Algorithm::SHA384: return 48;
				case Algorithm::SHA512: return 64;
				case Algorithm::MD5:    return 16;
				default:                return 32;
				}
			}


			bool Equal(const uint8_t* a, const uint8_t* b, size_t len) noexcept {
				if (a == b) return true;
				if (!a || !b) return false;
				uint8_t acc = 0;
				for (size_t i = 0; i < len; ++i) acc |= (a[i] ^ b[i]);
				return acc == 0;
			}

			static inline char hexUpper(uint8_t v) noexcept { return "0123456789ABCDEF"[v & 0xF]; }
			static inline char hexLower(uint8_t v) noexcept { return "0123456789abcdef"[v & 0xF]; }

			std::string ToHexLower(const uint8_t* data, size_t len) {
				std::string s; s.resize(len * 2);
				for (size_t i = 0; i < len; ++i) {
					const uint8_t c = data[i];
					s[(i << 1) + 0] = hexLower(c >> 4);
					s[(i << 1) + 1] = hexLower(c);
				}
				return s;
			}

			std::string ToHexUpper(const uint8_t* data, size_t len) {
				std::string s; s.resize(len * 2);
				for (size_t i = 0; i < len; ++i) {
					const uint8_t c = data[i];
					s[(i << 1) + 0] = hexUpper(c >> 4);
					s[(i << 1) + 1] = hexUpper(c);
				}
				return s;
			}

			bool FromHex(std::string_view hex, std::vector<uint8_t>& out) {
				out.clear();
				auto hv = [](char c) -> int {
					if (c >= '0' && c <= '9') return c - '0';
					if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
					if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
					return -1;
					};
				if ((hex.size() & 1) != 0) return false;
				out.resize(hex.size() / 2);
				for (size_t i = 0, j = 0; i < hex.size(); i += 2, ++j) {
					int hi = hv(hex[i]); int lo = hv(hex[i + 1]);
					if (hi < 0 || lo < 0) { out.clear(); return false; }
					out[j] = static_cast<uint8_t>((hi << 4) | lo);
				}
				return true;
			}


			uint32_t Fnv1a32(const void* data, size_t len) noexcept {
				const uint8_t* p = static_cast<const uint8_t*>(data);
				uint32_t h = 2166136261u;
				for (size_t i = 0; i < len; ++i) {
					h ^= p[i];
					h *= 16777619u;
				}
				return h;
			}

			uint64_t Fnv1a64(const void* data, size_t len) noexcept {
				const uint8_t* p = static_cast<const uint8_t*>(data);
				uint64_t h = 1469598103934665603ull;
				for (size_t i = 0; i < len; ++i) {
					h ^= p[i];
					h *= 1099511628211ull;
				}
				return h;
			}
			//Hasher


			Hasher::Hasher(Algorithm alg) noexcept : m_alg(alg), m_hashLen(DigestSize(alg)) {}

			Hasher::~Hasher(){
				resetState();
			}


			void Hasher::resetState() noexcept {
#ifdef _WIN32
				if (m_hash) {
					BCryptDestroyHash(m_hash);
					m_hash = nullptr;
				}
				if (m_objBuf) {
					SecureZeroMemory(m_objBuf, m_objLen);
					delete[] static_cast<uint8_t*>(m_objBuf);
					m_objBuf = nullptr;
				}
				m_objLen = 0;
				m_inited = false;
#endif
			
			}


			bool Hasher::ensureProviderReady(Error* err) noexcept {
#ifdef _WIN32
				if (!EnsureProv(m_alg, err)) return false;
				AlgProv& ap = GetProv(m_alg);
				m_hashLen = ap.hashLen;
				return true;
#else
				(void)err; return false;
#endif
			}

			bool Hasher::Init(Error* err) noexcept {
				resetState();
#ifdef _WIN32
				if (!ensureProviderReady(err)) return false;
				AlgProv& ap = GetProv(m_alg);

				m_objLen = ap.objLen;
				m_objBuf = malloc(m_objLen ? m_objLen : 1);
				if (!m_objBuf) {
					if (err) { err->win32 = ERROR_OUTOFMEMORY; err->ntstatus = STATUS_NO_MEMORY; }
					return false;
				}

				NTSTATUS st = BCryptCreateHash(ap.hAlg, &m_hash, static_cast<PUCHAR>(m_objBuf), m_objLen, nullptr, 0, 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); }
					SS_LOG_ERROR(L"HashUtils", L"BCryptCreateHash failed (nt=0x%08X, win32=%lu)", st, err ? err->win32 : 0);
					resetState();
					return false;
				}
				m_inited = true;
				return true;
#else
				(void)err; return false;
#endif
			}

			bool Hasher::Update(const void* data, size_t len, Error* err) noexcept {
#ifdef _WIN32
				if (!m_inited) { if (err) err->win32 = ERROR_INVALID_STATE; return false; }
				if (len == 0) return true;
				NTSTATUS st = BCryptHashData(m_hash, reinterpret_cast<const PUCHAR>(const_cast<void*>(data)), static_cast<ULONG>(len), 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); }
					SS_LOG_ERROR(L"HashUtils", L"BCryptHashData failed (nt=0x%08X, win32=%lu)", st, err ? err->win32 : 0);
					return false;
				}
				return true;
#else
				(void)data; (void)len; (void)err; return false;
#endif
			}


			bool Hasher::Final(std::vector<uint8_t>& out, Error* err) noexcept {
#ifdef _WIN32
				if (!m_inited) { if (err) err->win32 = ERROR_INVALID_STATE; return false; }
				out.resize(m_hashLen);
				NTSTATUS st = BCryptFinishHash(m_hash, out.data(), static_cast<ULONG>(out.size()), 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); }
					SS_LOG_ERROR(L"HashUtils", L"BCryptFinishHash failed (nt=0x%08X, win32=%lu)", st, err ? err->win32 : 0);
					resetState();
					return false;
				}
				resetState();
				return true;
#else
				(void)out; (void)err; return false;
#endif
			}

			bool Hasher::FinalHex(std::string& outHex, bool upper, Error* err) noexcept {
				std::vector<uint8_t> d;
				if (!Final(d, err)) return false;
				outHex = upper ? ToHexUpper(d) : ToHexLower(d);
				return true;
			}

			// Hmac

			Hmac::Hmac(Algorithm alg) noexcept : m_alg(alg), m_hashLen(DigestSize(alg)) {}

			Hmac::~Hmac() {
				resetState();
			}


			void Hmac::resetState() noexcept {
#ifdef _WIN32
				if (m_hash) {
					BCryptDestroyHash(m_hash);
					m_hash = nullptr;
				}
				if (m_objBuf) {
					SecureZeroMemory(m_objBuf, m_objLen);
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
				(void)err; return false;
#endif
			}

			bool Hmac::Init(const void* key, size_t keyLen, Error* err) noexcept {
				resetState();
#ifdef _WIN32
				if (!ensureProviderReady(err)) return false;
				AlgProv& ap = GetProv(m_alg);

				m_objLen = ap.objLenHmac;
				m_objBuf = malloc(m_objLen ? m_objLen : 1);
				if (!m_objBuf) {
					if (err) { err->win32 = ERROR_OUTOFMEMORY; err->ntstatus = STATUS_NO_MEMORY; }
					return false;
				}

				//Temporary copy for key(not on the stack, it could be big so use heap)
				std::unique_ptr<uint8_t[]> keyCopy;
				if (keyLen) {
					keyCopy.reset(new (std::nothrow) uint8_t[keyLen]);
					if (!keyCopy) {
						if (err) { err->win32 = ERROR_OUTOFMEMORY; err->ntstatus = STATUS_NO_MEMORY; }
						resetState();
						return false;
					}
					memcpy(keyCopy.get(), key, keyLen);
				}

				NTSTATUS st = BCryptCreateHash(ap.hAlgHmac, &m_hash, static_cast<PUCHAR>(m_objBuf), m_objLen,
					keyLen ? keyCopy.get() : nullptr, static_cast<ULONG>(keyLen), 0);

				if (keyCopy) SecureZeroMemory(keyCopy.get(), keyLen);

				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); }
					SS_LOG_ERROR(L"HashUtils", L"BCryptCreateHash(HMAC) failed (nt=0x%08X, win32=%lu)", st, err ? err->win32 : 0);
					resetState();
					return false;
				}
				m_inited = true;
				return true;
#else
				(void)key; (void)keyLen; (void)err; return false;
#endif
			}

			bool Hmac::Update(const void* data, size_t len, Error* err) noexcept {
#ifdef _WIN32
				if (!m_inited) { if (err) err->win32 = ERROR_INVALID_STATE; return false; }
				if (len == 0) return true;
				NTSTATUS st = BCryptHashData(m_hash, reinterpret_cast<const PUCHAR>(const_cast<void*>(data)), static_cast<ULONG>(len), 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); }
					SS_LOG_ERROR(L"HashUtils", L"BCryptHashData(HMAC) failed (nt=0x%08X, win32=%lu)", st, err ? err->win32 : 0);
					return false;
				}
				return true;
#else
				(void)data; (void)len; (void)err; return false;
#endif
			}

			bool Hmac::Final(std::vector<uint8_t>& out, Error* err) noexcept {
#ifdef _WIN32
				if (!m_inited) { if (err) err->win32 = ERROR_INVALID_STATE; return false; }
				out.resize(m_hashLen);
				NTSTATUS st = BCryptFinishHash(m_hash, out.data(), static_cast<ULONG>(out.size()), 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); }
					SS_LOG_ERROR(L"HashUtils", L"BCryptFinishHash(HMAC) failed (nt=0x%08X, win32=%lu)", st, err ? err->win32 : 0);
					resetState();
					return false;
				}
				resetState();
				return true;
#else
				(void)out; (void)err; return false;
#endif
			}


			bool Hmac::FinalHex(std::string& outHex, bool upper, Error* err) noexcept {
				std::vector<uint8_t> d;
				if (!Final(d, err)) return false;
				outHex = upper ? ToHexUpper(d) : ToHexLower(d);
				return true;
			}

			// Quick One-shot Helper Functions

			bool Compute(Algorithm alg, const void* data, size_t len, std::vector<uint8_t>& out, Error* err) noexcept {
				Hasher h(alg);
				if (!h.Init(err)) return false;
				if (len && !h.Update(data, len, err)) return false;
				return h.Final(out, err);
			}

			bool ComputeHex(Algorithm alg, const void* data, size_t len, std::string& outHex, bool upper, Error* err) noexcept {
				std::vector<uint8_t> d;
				if (!Compute(alg, data, len, d, err)) return false;
				outHex = upper ? ToHexUpper(d) : ToHexLower(d);
				return true;
			}

			bool ComputeHmac(Algorithm alg, const void* key, size_t keyLen, const void* data, size_t len, std::vector<uint8_t>& out, Error* err) noexcept {
				Hmac h(alg);
				if (!h.Init(key, keyLen, err)) return false;
				if (len && !h.Update(data, len, err)) return false;
				return h.Final(out, err);
			}

			bool ComputeHmacHex(Algorithm alg, const void* key, size_t keyLen, const void* data, size_t len, std::string& outHex, bool upper, Error* err) noexcept {
				std::vector<uint8_t> d;
				if (!ComputeHmac(alg, key, keyLen, data, len, d, err)) return false;
				outHex = upper ? ToHexUpper(d) : ToHexLower(d);
				return true;
			}



			bool ComputeFile(Algorithm alg, std::wstring_view path, std::vector<uint8_t>& out, Error* err) noexcept {
#ifdef _WIN32
				out.clear();

				HANDLE h = CreateFileW(std::wstring(path).c_str(), GENERIC_READ,
					FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
					nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
				if (h == INVALID_HANDLE_VALUE) {
					if (err) err->win32 = GetLastError();
					SS_LOG_LAST_ERROR(L"HashUtils", L"ComputeFile: CreateFileW failed: %ls", std::wstring(path).c_str());
					return false;
				}

				Hasher hasher(alg);
				if (!hasher.Init(err)) { CloseHandle(h); return false; }

				std::vector<uint8_t> buf(1 << 20); // 1MB
				DWORD rd = 0;
				BOOL ok = FALSE;
				for (;;) {
					ok = ReadFile(h, buf.data(), static_cast<DWORD>(buf.size()), &rd, nullptr);
					if (!ok) {
						if (err) err->win32 = GetLastError();
						SS_LOG_LAST_ERROR(L"HashUtils", L"ComputeFile: ReadFile failed");
						CloseHandle(h);
						return false;
					}
					if (rd == 0) break;
					if (!hasher.Update(buf.data(), rd, err)) { CloseHandle(h); return false; }
				}
				CloseHandle(h);
				return hasher.Final(out, err);
#else
				(void)alg; (void)path; (void)out; (void)err; return false;
#endif
			}

		}// namespace HashUtils
	}// namespace Utils
}// namespace ShadowStrike
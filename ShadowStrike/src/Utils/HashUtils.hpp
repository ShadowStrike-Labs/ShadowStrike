#pragma once

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
#  include <Windows.h>
#  include <bcrypt.h>
#  include <winternl.h>
#  pragma comment(lib, "bcrypt.lib")
#endif

#include "Logger.hpp"

namespace ShadowStrike {
	namespace Utils {
		namespace HashUtils {

			//Supported Algorithms
			enum class Algorithm : uint8_t {
				SHA1,
				SHA256,
				SHA384,
				SHA512,
				MD5 // Not safe only for compatibility
			};

			//Error codes
			struct Error {
				DWORD win32 = ERROR_SUCCESS; // 0 ise hata yok
				LONG ntstatus = 0;
			};

			//Comparison
			bool Equal(const uint8_t* a, const uint8_t* b, size_t len) noexcept;

			//Hex helpers
			std::string ToHexLower(const uint8_t* data, size_t len);
			std::string ToHexUpper(const uint8_t* data, size_t len);
			inline std::string ToHexLower(const std::vector<uint8_t>& v) { return ToHexLower(v.data(), v.size()); }
			inline std::string ToHexUpper(const std::vector<uint8_t>& v) { return ToHexUpper(v.data(), v.size()); }
			bool FromHex(std::string_view hex, std::vector<uint8_t>& out);


			//FNV-1a(Not Cryptographic) fast hash
			uint32_t Fnv1a32(const void* data, size_t len) noexcept;
			uint64_t Fnv1a64(const void* data, size_t len) noexcept;

			//Digest size(bytes)
			size_t DigestSize(Algorithm alg) noexcept;

			class Hasher {
			public:
				explicit Hasher(Algorithm alg) noexcept;
				~Hasher();

				//Start a new stream
				bool Init(Error* err = nullptr) noexcept;

				//Feed data
				bool Update(const void* data, size_t len, Error* err = nullptr) noexcept;

				//Finalize and get the hash
				bool Final(std::vector<uint8_t>& out, Error* err = nullptr) noexcept;

				//Return the hash as hex string
				bool FinalHex(std::string& outHex, bool upper = false, Error* err = nullptr) noexcept;

				
				size_t GetDigestSize() const noexcept { return m_hashLen; }

				Algorithm GetAlgorithm() const noexcept { return m_alg; }

			private:
#ifdef _WIN32
				void* m_objBuf = nullptr;
				DWORD m_objLen = 0;
				BCRYPT_HASH_HANDLE m_hash = nullptr;
#endif
				Algorithm m_alg;
				size_t m_hashLen = 0;
				bool m_inited = false;

				bool ensureProviderReady(Error* err) noexcept; // provider
				void resetState() noexcept;
			};


			
			class Hmac {
			public:
				explicit Hmac(Algorithm alg) noexcept;
				~Hmac();

				//Start with key
				bool Init(const void* key, size_t keyLen, Error* err = nullptr) noexcept;

				bool Update(const void* data, size_t len, Error* err = nullptr) noexcept;

				bool Final(std::vector<uint8_t>& out, Error* err = nullptr) noexcept;

				bool FinalHex(std::string& outHex, bool upper = false, Error* err = nullptr) noexcept;

				size_t GetDigestSize() const noexcept { return m_hashLen; }
				Algorithm GetAlgorithm() const noexcept { return m_alg; }

			private:
#ifdef _WIN32
				void* m_objBuf = nullptr;
				DWORD m_objLen = 0;
				BCRYPT_HASH_HANDLE m_hash = nullptr;
#endif
				Algorithm m_alg;
				size_t m_hashLen = 0;
				bool m_inited = false;

				bool ensureProviderReady(Error* err) noexcept;
				void resetState() noexcept;
			};

			//Quick helpers
			bool Compute(Algorithm alg, const void* data, size_t len, std::vector<uint8_t>& out, Error* err = nullptr) noexcept;
			inline bool Compute(Algorithm alg, std::string_view data, std::vector<uint8_t>& out, Error* err = nullptr) noexcept {
				return Compute(alg, data.data(), data.size(), out, err);
			}
			bool ComputeHex(Algorithm alg, const void* data, size_t len, std::string& outHex, bool upper = false, Error* err = nullptr) noexcept;

			//Quick HMAC helpers
			bool ComputeHmac(Algorithm alg, const void* key, size_t keyLen, const void* data, size_t len, std::vector<uint8_t>& out, Error* err = nullptr) noexcept;
			bool ComputeHmacHex(Algorithm alg, const void* key, size_t keyLen, const void* data, size_t len, std::string& outHex, bool upper = false, 
				Error* err = nullptr) noexcept;

			//File hash
			bool ComputeFile(Algorithm alg, std::wstring_view path, std::vector<uint8_t>& out, Error* err = nullptr) noexcept;


		}// namespace HashUtils
	}// namespace Utils
}// namespace ShadowStrike
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <optional>
#include <memory>
#include <functional>
#include <span>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#  include <bcrypt.h>
#  include <ncrypt.h>
#  include <wincrypt.h>
#  pragma comment(lib, "bcrypt.lib")
#  pragma comment(lib, "ncrypt.lib")
#  pragma comment(lib, "crypt32.lib")
#endif

#include "HashUtils.hpp"
#include "Logger.hpp"

namespace ShadowStrike {
	namespace Utils {
		namespace CryptoUtils {

			// ============================================================================
			// Error Handling
			// ============================================================================

			struct Error {
				DWORD win32 = ERROR_SUCCESS;
				LONG ntstatus = 0;
				std::wstring message;
				std::wstring context;

				bool HasError() const noexcept { return win32 != ERROR_SUCCESS || ntstatus != 0; }
				void Clear() noexcept { win32 = ERROR_SUCCESS; ntstatus = 0; message.clear(); context.clear(); }
			};

			// ============================================================================
			// Symmetric Encryption Algorithms
			// ============================================================================

			enum class SymmetricAlgorithm : uint8_t {
				AES_128_CBC,
				AES_192_CBC,
				AES_256_CBC,
				AES_128_GCM,
				AES_192_GCM,
				AES_256_GCM,
				AES_128_CFB,
				AES_192_CFB,
				AES_256_CFB,
				ChaCha20_Poly1305  // Modern AEAD cipher
			};

			enum class PaddingMode : uint8_t {
				None,
				PKCS7  // Industry standard, used by GravityZone/CrowdStrike
				// ANSIX923, ISO10126, and Zero Padding removed - insecure and non-standard
			};

			// ============================================================================
			// Asymmetric Encryption Algorithms
			// ============================================================================

			enum class AsymmetricAlgorithm : uint8_t {
				RSA_2048,
				RSA_3072,
				RSA_4096,
				ECC_P256,    // NIST P-256
				ECC_P384,    // NIST P-384
				ECC_P521     // NIST P-521
			};

			enum class RSAPaddingScheme : uint8_t {
				PKCS1,       // RSAES-PKCS1-v1_5
				OAEP_SHA1,   // RSAES-OAEP with SHA-1
				OAEP_SHA256, // RSAES-OAEP with SHA-256
				OAEP_SHA384,
				OAEP_SHA512,
				PSS_SHA256,  // For signatures
				PSS_SHA384,
				PSS_SHA512
			};

			// ============================================================================
			// Key Derivation
			// ============================================================================

			enum class KDFAlgorithm : uint8_t {
				PBKDF2_SHA256,
				PBKDF2_SHA384,
				PBKDF2_SHA512,
				HKDF_SHA256,
				HKDF_SHA384,
				HKDF_SHA512,
				Scrypt,
				Argon2id
			};

			struct KDFParams {
				KDFAlgorithm algorithm = KDFAlgorithm::PBKDF2_SHA256;
				uint32_t iterations = 100000;      // For PBKDF2
				uint32_t memoryCostKB = 65536;     // For Scrypt/Argon2 (64MB default)
				uint32_t parallelism = 4;          // For Argon2
				size_t keyLength = 32;             // Output key length in bytes
				std::vector<uint8_t> salt;         // Salt (auto-generated if empty)
				std::vector<uint8_t> info;         // For HKDF
			};

			// ============================================================================
			// Secure Random Number Generation
			// ============================================================================

			class SecureRandom {
			public:
				SecureRandom() noexcept;
				~SecureRandom();

				// No copy/move
				SecureRandom(const SecureRandom&) = delete;
				SecureRandom& operator=(const SecureRandom&) = delete;

				// Generate random bytes
				bool Generate(uint8_t* buffer, size_t size, Error* err = nullptr) noexcept;
				bool Generate(std::vector<uint8_t>& out, size_t size, Error* err = nullptr) noexcept;
				std::vector<uint8_t> Generate(size_t size, Error* err = nullptr) noexcept;

				// Generate random integers
				uint32_t NextUInt32(Error* err = nullptr) noexcept;
				uint64_t NextUInt64(Error* err = nullptr) noexcept;
				
				// Generate random in range [min, max)
				uint32_t NextUInt32(uint32_t min, uint32_t max, Error* err = nullptr) noexcept;
				uint64_t NextUInt64(uint64_t min, uint64_t max, Error* err = nullptr) noexcept;

				// Generate cryptographically secure random string
				std::string GenerateAlphanumeric(size_t length, Error* err = nullptr) noexcept;
				std::string GenerateHex(size_t byteCount, Error* err = nullptr) noexcept;
				std::string GenerateBase64(size_t byteCount, Error* err = nullptr) noexcept;

			private:
#ifdef _WIN32
				BCRYPT_ALG_HANDLE m_algHandle = nullptr;
#endif
				bool m_initialized = false;
			};

			// ============================================================================
			// Symmetric Encryption
			// ============================================================================

			class SymmetricCipher {
			public:
				explicit SymmetricCipher(SymmetricAlgorithm algorithm) noexcept;
				~SymmetricCipher();

				// No copy, allow move
				SymmetricCipher(const SymmetricCipher&) = delete;
				SymmetricCipher& operator=(const SymmetricCipher&) = delete;
				SymmetricCipher(SymmetricCipher&&) noexcept;
				SymmetricCipher& operator=(SymmetricCipher&&) noexcept;

				// Key management
				bool SetKey(const uint8_t* key, size_t keyLen, Error* err = nullptr) noexcept;
				bool SetKey(const std::vector<uint8_t>& key, Error* err = nullptr) noexcept;
				bool GenerateKey(std::vector<uint8_t>& outKey, Error* err = nullptr) noexcept;

				// IV/Nonce management
				bool SetIV(const uint8_t* iv, size_t ivLen, Error* err = nullptr) noexcept;
				bool SetIV(const std::vector<uint8_t>& iv, Error* err = nullptr) noexcept;
				bool GenerateIV(std::vector<uint8_t>& outIV, Error* err = nullptr) noexcept;

				// Padding mode (for CBC, ECB, CFB)
				void SetPaddingMode(PaddingMode mode) noexcept { m_paddingMode = mode; }

				// Encryption/Decryption (one-shot)
				bool Encrypt(const uint8_t* plaintext, size_t plaintextLen,
					std::vector<uint8_t>& ciphertext, Error* err = nullptr) noexcept;
				
				bool Decrypt(const uint8_t* ciphertext, size_t ciphertextLen,
					std::vector<uint8_t>& plaintext, Error* err = nullptr) noexcept;

				// AEAD (GCM, ChaCha20-Poly1305) - with authentication
				bool EncryptAEAD(const uint8_t* plaintext, size_t plaintextLen,
					const uint8_t* aad, size_t aadLen,
					std::vector<uint8_t>& ciphertext,
					std::vector<uint8_t>& tag, Error* err = nullptr) noexcept;

				bool DecryptAEAD(const uint8_t* ciphertext, size_t ciphertextLen,
					const uint8_t* aad, size_t aadLen,
					const uint8_t* tag, size_t tagLen,
					std::vector<uint8_t>& plaintext, Error* err = nullptr) noexcept;

				// Streaming encryption/decryption
				bool EncryptInit(Error* err = nullptr) noexcept;
				bool EncryptUpdate(const uint8_t* data, size_t len, std::vector<uint8_t>& out, Error* err = nullptr) noexcept;
				bool EncryptFinal(std::vector<uint8_t>& out, Error* err = nullptr) noexcept;

				bool DecryptInit(Error* err = nullptr) noexcept;
				bool DecryptUpdate(const uint8_t* data, size_t len, std::vector<uint8_t>& out, Error* err = nullptr) noexcept;
				bool DecryptFinal(std::vector<uint8_t>& out, Error* err = nullptr) noexcept;

				// Properties
				size_t GetKeySize() const noexcept;
				size_t GetIVSize() const noexcept;
				size_t GetBlockSize() const noexcept;
				size_t GetTagSize() const noexcept; // For AEAD
				bool IsAEAD() const noexcept;
				SymmetricAlgorithm GetAlgorithm() const noexcept { return m_algorithm; }

			private:
			
				std::vector<uint8_t> m_streamBuffer;  // internal buffer for streaming
				bool m_streamFinalized = false;       // Stream finalize situation
				SymmetricAlgorithm m_algorithm;
				PaddingMode m_paddingMode = PaddingMode::PKCS7;
				
#ifdef _WIN32
				BCRYPT_ALG_HANDLE m_algHandle = nullptr;
				BCRYPT_KEY_HANDLE m_keyHandle = nullptr;
				std::vector<uint8_t> m_keyObject;
#endif
				std::vector<uint8_t> m_key;
				std::vector<uint8_t> m_iv;
				bool m_keySet = false;
				bool m_ivSet = false;

				bool ensureProvider(Error* err) noexcept;
				void cleanup() noexcept;
				bool applyPadding(std::vector<uint8_t>& data, size_t blockSize) noexcept;
				bool removePadding(std::vector<uint8_t>& data, size_t blockSize) noexcept;
			};

			// ============================================================================
			// Asymmetric Encryption (RSA/ECC)
			// ============================================================================

			struct PublicKey {
				AsymmetricAlgorithm algorithm;
				std::vector<uint8_t> keyBlob;
				
				bool Export(std::vector<uint8_t>& out, Error* err = nullptr) const noexcept;
				bool ExportPEM(std::string& out, Error* err = nullptr) const noexcept;
				static bool Import(const uint8_t* data, size_t len, PublicKey& out, Error* err = nullptr) noexcept;
				static bool ImportPEM(std::string_view pem, PublicKey& out, Error* err = nullptr) noexcept;
			};

			struct PrivateKey {
				AsymmetricAlgorithm algorithm;
				std::vector<uint8_t> keyBlob;
				
				bool Export(std::vector<uint8_t>& out, Error* err = nullptr) const noexcept;
				bool ExportPEM(std::string& out, bool encrypt = false, std::string_view password = "", Error* err = nullptr) const noexcept;
				static bool Import(const uint8_t* data, size_t len, PrivateKey& out, Error* err = nullptr) noexcept;
				static bool ImportPEM(std::string_view pem, PrivateKey& out, std::string_view password = "", Error* err = nullptr) noexcept;
				
				// Secure cleanup
				void SecureErase() noexcept;
				~PrivateKey() { SecureErase(); }
			};

			struct KeyPair {
				PublicKey publicKey;
				PrivateKey privateKey;
			};

			class AsymmetricCipher {
			public:
				explicit AsymmetricCipher(AsymmetricAlgorithm algorithm) noexcept;
				~AsymmetricCipher();

				// No copy/move
				AsymmetricCipher(const AsymmetricCipher&) = delete;
				AsymmetricCipher& operator=(const AsymmetricCipher&) = delete;

				// Key generation
				bool GenerateKeyPair(KeyPair& outKeyPair, Error* err = nullptr) noexcept;

				// Load keys
				bool LoadPublicKey(const PublicKey& key, Error* err = nullptr) noexcept;
				bool LoadPrivateKey(const PrivateKey& key, Error* err = nullptr) noexcept;

				// RSA Encryption/Decryption
				bool Encrypt(const uint8_t* plaintext, size_t plaintextLen,
					std::vector<uint8_t>& ciphertext,
					RSAPaddingScheme padding = RSAPaddingScheme::OAEP_SHA256,
					Error* err = nullptr) noexcept;

				bool Decrypt(const uint8_t* ciphertext, size_t ciphertextLen,
					std::vector<uint8_t>& plaintext,
					RSAPaddingScheme padding = RSAPaddingScheme::OAEP_SHA256,
					Error* err = nullptr) noexcept;

				// Digital Signatures
				bool Sign(const uint8_t* data, size_t dataLen,
					std::vector<uint8_t>& signature,
					HashUtils::Algorithm hashAlg = HashUtils::Algorithm::SHA256,
					RSAPaddingScheme padding = RSAPaddingScheme::PSS_SHA256,
					Error* err = nullptr) noexcept;

				bool Verify(const uint8_t* data, size_t dataLen,
					const uint8_t* signature, size_t signatureLen,
					HashUtils::Algorithm hashAlg = HashUtils::Algorithm::SHA256,
					RSAPaddingScheme padding = RSAPaddingScheme::PSS_SHA256,
					Error* err = nullptr) noexcept;

				// ECDH Key Agreement (for ECC)
				bool DeriveSharedSecret(const PublicKey& peerPublicKey,
				std::vector<uint8_t>& sharedSecret,
				Error* err = nullptr) noexcept;

				// Properties
				size_t GetMaxPlaintextSize(RSAPaddingScheme padding) const noexcept;
				size_t GetSignatureSize() const noexcept;
				AsymmetricAlgorithm GetAlgorithm() const noexcept { return m_algorithm; }

			private:
				AsymmetricAlgorithm m_algorithm;
				
#ifdef _WIN32
				BCRYPT_ALG_HANDLE m_algHandle = nullptr;
				BCRYPT_KEY_HANDLE m_publicKeyHandle = nullptr;
				BCRYPT_KEY_HANDLE m_privateKeyHandle = nullptr;
#endif
				bool m_publicKeyLoaded = false;
				bool m_privateKeyLoaded = false;

				bool ensureProvider(Error* err) noexcept;
				void cleanup() noexcept;
			};

			// ============================================================================
			// Key Derivation Functions
			// ============================================================================

			class KeyDerivation {
			public:
				// PBKDF2
				static bool PBKDF2(const uint8_t* password, size_t passwordLen,
					const uint8_t* salt, size_t saltLen,
					uint32_t iterations,
					HashUtils::Algorithm hashAlg,
					uint8_t* outKey, size_t keyLen,
					Error* err = nullptr) noexcept;

				// HKDF (Extract and Expand)
				static bool HKDF(const uint8_t* inputKeyMaterial, size_t ikmLen,
					const uint8_t* salt, size_t saltLen,
					const uint8_t* info, size_t infoLen,
					HashUtils::Algorithm hashAlg,
					uint8_t* outKey, size_t keyLen,
					Error* err = nullptr) noexcept;

				// Generic KDF with parameters
				static bool DeriveKey(const uint8_t* password, size_t passwordLen,
					const KDFParams& params,
					std::vector<uint8_t>& outKey,
					Error* err = nullptr) noexcept;

				// Convenience for string passwords
				static bool DeriveKey(std::string_view password,
					const KDFParams& params,
					std::vector<uint8_t>& outKey,
					Error* err = nullptr) noexcept;

				// Generate random salt
				static bool GenerateSalt(std::vector<uint8_t>& salt, size_t size = 32, Error* err = nullptr) noexcept;
			};

			// ============================================================================
			// Certificate Management
			// ============================================================================

			struct CertificateInfo {
				std::wstring subject;
				std::wstring issuer;
				std::wstring serialNumber;
				std::wstring thumbprint;
				FILETIME notBefore{};
				FILETIME notAfter{};
				std::vector<std::wstring> subjectAltNames;
				bool isCA = false;
				bool isExpired = false;
				bool isRevoked = false;
			};

			class Certificate {
			public:
				Certificate() noexcept = default;
				~Certificate();

				// No copy, allow move
				Certificate(const Certificate&) = delete;
				Certificate& operator=(const Certificate&) = delete;
				Certificate(Certificate&&) noexcept;
				Certificate& operator=(Certificate&&) noexcept;

				// Load certificate
				bool LoadFromFile(std::wstring_view path, Error* err = nullptr) noexcept;
				bool LoadFromMemory(const uint8_t* data, size_t len, Error* err = nullptr) noexcept;
				bool LoadFromStore(std::wstring_view storeName, std::wstring_view thumbprint, Error* err = nullptr) noexcept;
				bool LoadFromPEM(std::string_view pem, Error* err = nullptr) noexcept;

				// Export certificate
				bool Export(std::vector<uint8_t>& out, Error* err = nullptr) const noexcept;
				bool ExportPEM(std::string& out, Error* err = nullptr) const noexcept;

				// Certificate info
				bool GetInfo(CertificateInfo& info, Error* err = nullptr) const noexcept;

				// Verification
				bool VerifySignature(const uint8_t* data, size_t dataLen,
					const uint8_t* signature, size_t signatureLen,
					Error* err = nullptr) const noexcept;

				bool VerifyChain(Error* err,
					HCERTSTORE hAdditionalStore /*= nullptr*/,
					DWORD chainFlags /*= CERT_CHAIN_REVOCATION_CHECK_CHAIN*/,
					 FILETIME* verificationTime /*= nullptr*/,
					const char* requiredEkuOid /*= nullptr*/) const noexcept;
				bool VerifyAgainstCA(const Certificate& caCert, Error* err = nullptr) const noexcept;

				// Extract public key
				bool ExtractPublicKey(PublicKey& outKey, Error* err = nullptr) const noexcept;

				// Properties
				bool IsValid() const noexcept { return m_certContext != nullptr; }

			private:
#ifdef _WIN32
				PCCERT_CONTEXT m_certContext = nullptr;
#endif
				void cleanup() noexcept;
			};

			// ============================================================================
			// Secure Memory Management
			// ============================================================================

			template<typename T>
			class SecureBuffer {
			public:
				explicit SecureBuffer(size_t size = 0);
				~SecureBuffer();

				// No copy, allow move
				SecureBuffer(const SecureBuffer&) = delete;
				SecureBuffer& operator=(const SecureBuffer&) = delete;
				SecureBuffer(SecureBuffer&& other) noexcept;
				SecureBuffer& operator=(SecureBuffer&& other) noexcept;

				void Resize(size_t newSize);
				void Clear();
				
				T* Data() noexcept { return m_data; }
				const T* Data() const noexcept { return m_data; }
				size_t Size() const noexcept { return m_size; }
				bool Empty() const noexcept { return m_size == 0; }

				T& operator[](size_t index) noexcept { return m_data[index]; }
				const T& operator[](size_t index) const noexcept { return m_data[index]; }

				// Secure copy
				void CopyFrom(const T* src, size_t count);
				void CopyFrom(const std::vector<T>& src);

			private:
				T* m_data = nullptr;
				size_t m_size = 0;

				void allocate(size_t size);
				void deallocate();
			};

			using SecureByteBuffer = SecureBuffer<uint8_t>;

			// Secure string for passwords
			class SecureString {
			public:
				SecureString() = default;
				explicit SecureString(std::string_view str);
				explicit SecureString(std::wstring_view str);
				~SecureString();

				// No copy, allow move
				SecureString(const SecureString&) = delete;
				SecureString& operator=(const SecureString&) = delete;
				SecureString(SecureString&& other) noexcept;
				SecureString& operator=(SecureString&& other) noexcept;

				void Assign(std::string_view str);
				void Assign(std::wstring_view str);
				void Clear();

				const char* Data() const noexcept { return m_buffer.Data(); }
				size_t Size() const noexcept { return m_buffer.Size(); }
				bool Empty() const noexcept { return m_buffer.Empty(); }

				std::string_view ToStringView() const noexcept;

			private:
				SecureBuffer<char> m_buffer;
			};

			// ============================================================================
			// High-Level Encryption/Decryption Functions
			// ============================================================================

			// File encryption with AES-256-GCM
			bool EncryptFile(std::wstring_view inputPath,
				std::wstring_view outputPath,
				const uint8_t* key, size_t keyLen,
				Error* err = nullptr) noexcept;

			bool DecryptFile(std::wstring_view inputPath,
				std::wstring_view outputPath,
				const uint8_t* key, size_t keyLen,
				Error* err = nullptr) noexcept;

			// Password-based file encryption (PBKDF2 + AES-256-GCM)
			bool EncryptFileWithPassword(std::wstring_view inputPath,
				std::wstring_view outputPath,
				std::string_view password,
				Error* err = nullptr) noexcept;

			bool DecryptFileWithPassword(std::wstring_view inputPath,
				std::wstring_view outputPath,
				std::string_view password,
				Error* err = nullptr) noexcept;

			// String encryption (returns Base64)
			bool EncryptString(std::string_view plaintext,
				const uint8_t* key, size_t keyLen,
				std::string& outBase64Ciphertext,
				Error* err = nullptr) noexcept;

			bool DecryptString(std::string_view base64Ciphertext,
				const uint8_t* key, size_t keyLen,
				std::string& outPlaintext,
				Error* err = nullptr) noexcept;

			// ============================================================================
			// Digital Signature Verification (for malware detection)
			// ============================================================================

			struct SignatureInfo {
				bool isSigned = false;
				bool isVerified = false;
				std::wstring signerName;
				std::wstring signerEmail;
				std::wstring issuerName;
				std::wstring thumbprint;
				FILETIME signTime{};
				std::vector<CertificateInfo> certificateChain;
			};

			// Verify PE file signature (for whitelisting trusted software)
			bool VerifyPESignature(std::wstring_view filePath,
				SignatureInfo& info,
				Error* err = nullptr) noexcept;

			// Verify catalog signature
			bool VerifyCatalogSignature(std::wstring_view catalogPath,
				std::wstring_view fileHash,
				SignatureInfo& info,
				Error* err = nullptr) noexcept;

			//EKU checking helper
			bool CheckCodeSigningEKU(PCCERT_CONTEXT cert, Error* err) noexcept;

			//Validate signature timestamp
			bool ValidateTimestamp(const FILETIME& signTime, PCCERT_CONTEXT cert, Error* err) noexcept;

			//Online revocation check via OCSP/CRL
			bool CheckRevocationOnline(PCCERT_CONTEXT cert, Error* err) noexcept;

		    //Multiple signature Support(will be added in future)

			// ============================================================================
			// Base64 Encoding/Decoding
			// ============================================================================

			namespace Base64 {
				std::string Encode(const uint8_t* data, size_t len) noexcept;
				std::string Encode(const std::vector<uint8_t>& data) noexcept;
				bool Decode(std::string_view base64, std::vector<uint8_t>& out) noexcept;
			}

			// ============================================================================
			// Secure Comparison (timing-attack resistant)
			// ============================================================================

			bool SecureCompare(const uint8_t* a, const uint8_t* b, size_t len) noexcept;
			bool SecureCompare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) noexcept;

			// ============================================================================
			// Secure Memory Wipe
			// ============================================================================

			void SecureZeroMemory(void* ptr, size_t size) noexcept;

			// ============================================================================
			// Entropy Testing (for malware detection)
			// ============================================================================

			// Calculate Shannon entropy of data (0.0 to 8.0 for bytes)
			double CalculateEntropy(const uint8_t* data, size_t len) noexcept;
			double CalculateEntropy(const std::vector<uint8_t>& data) noexcept;

			// Check if data appears to be encrypted/compressed (high entropy)
			bool HasHighEntropy(const uint8_t* data, size_t len, double threshold = 7.0) noexcept;

		} // namespace CryptoUtils
	} // namespace Utils
} // namespace ShadowStrike

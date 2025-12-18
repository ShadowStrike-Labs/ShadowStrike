/**
 * @file CryptoUtils_private_key.cpp
 * @brief Enterprise-grade cryptographic utilities implementation
 *
 * Implements Private Key implementation using Windows CNG APIs.
 *
 * @copyright Copyright (c) 2025 ShadowStrike Security Suite
 */

#include"CryptoUtils.hpp"
#include"CryptoUtilsCommon.hpp"
#include<sstream>

namespace ShadowStrike {
	namespace Utils {
		namespace CryptoUtils {

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
					if (!KeyDerivation::DeriveKey(password, kdfParams, key, err)) {
						SecureZeroMemory(salt.data(), salt.size());
						return false;
					}

					SymmetricCipher cipher(SymmetricAlgorithm::AES_256_CBC);
					if (!cipher.SetKey(key, err)) {
						SecureZeroMemory(key.data(), key.size());
						SecureZeroMemory(salt.data(), salt.size());
						return false;
					}

					// SECURITY: Clear key immediately after setting
					SecureZeroMemory(key.data(), key.size());
					key.clear();

					std::vector<uint8_t> iv;
					if (!cipher.GenerateIV(iv, err)) {
						SecureZeroMemory(salt.data(), salt.size());
						return false;
					}

					if (iv.size() != 16) {
						SecureZeroMemory(salt.data(), salt.size());
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid IV size"; }
						return false;
					}
					std::vector<uint8_t> encrypted;
					if (!cipher.Encrypt(keyBlob.data(), keyBlob.size(), encrypted, err)) {
						SecureZeroMemory(salt.data(), salt.size());
						return false;
					}

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

					// SECURITY: Clear sensitive intermediate data
					SecureZeroMemory(salt.data(), salt.size());
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
		}//namespace CryptoUtils
	}// namespace Utils
}// namespace ShadowStrike
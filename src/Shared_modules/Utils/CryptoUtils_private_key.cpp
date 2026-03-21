/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * @file CryptoUtils_private_key.cpp
 * @brief Enterprise-grade cryptographic utilities implementation
 *
 * Implements Private Key implementation using Windows CNG APIs.
 *
 * @copyright Copyright (c) 2025 ShadowStrike Security Suite
 */

#include"pch.h"
#include"CryptoUtils.hpp"
#include"CryptoUtilsCommon.hpp"

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
				if (keyBlob.empty()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Key blob is empty"; }
					return false;
				}
				try {
					out = keyBlob;
				}
				catch (const std::exception&) {
					if (err) { err->win32 = ERROR_NOT_ENOUGH_MEMORY; err->message = L"Failed to copy key blob"; }
					return false;
				}
				// SECURITY WARNING: Caller MUST call SecureZeroMemory(out.data(), out.size())
				// when finished with the exported key material.
				return true;
			}

			bool PrivateKey::ExportPEM(std::string& out, bool encrypt, std::string_view password, Error* err) const noexcept {
				if (keyBlob.empty()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Key blob is empty"; }
					return false;
				}

				// PK7: Reject encrypt=true with empty password (silent fallthrough to unencrypted is a security hazard)
				if (encrypt && password.empty()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Password required when encryption is requested"; }
					return false;
				}

				// Declare sensitive locals before try so catch can wipe on exception
				std::vector<uint8_t> dataToEncode;
				std::string base64;

				try {
					if (encrypt) {
						// PKCS#8 encrypted private key format (OWASP 2023 recommendations)
						KDFParams kdfParams{};
						kdfParams.algorithm = KDFAlgorithm::PBKDF2_SHA256;
						kdfParams.iterations = 600000;
						kdfParams.keyLength = 32;

						SecureRandom rng;
						std::vector<uint8_t> salt;
						if (!rng.Generate(salt, 32, err)) return false;
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

						// Format: [VERSION(4)] + [ITERATIONS(4)] + [SALT(32)] + [IV(16)] + [ENCRYPTED_DATA]
						const uint32_t version = 1;
						const uint32_t iters = kdfParams.iterations;
						dataToEncode.reserve(4 + 4 + 32 + 16 + encrypted.size());
						dataToEncode.insert(dataToEncode.end(), reinterpret_cast<const uint8_t*>(&version), reinterpret_cast<const uint8_t*>(&version) + sizeof(version));
						dataToEncode.insert(dataToEncode.end(), reinterpret_cast<const uint8_t*>(&iters), reinterpret_cast<const uint8_t*>(&iters) + sizeof(iters));
						dataToEncode.insert(dataToEncode.end(), salt.begin(), salt.end());
						dataToEncode.insert(dataToEncode.end(), iv.begin(), iv.end());
						dataToEncode.insert(dataToEncode.end(), encrypted.begin(), encrypted.end());

						SecureZeroMemory(salt.data(), salt.size());
						SecureZeroMemory(encrypted.data(), encrypted.size());
					}
					else {
						dataToEncode.assign(keyBlob.begin(), keyBlob.end());
					}

					// Base64 encode
					base64 = Base64::Encode(dataToEncode);

					// PK5/PK9: Securely erase plaintext/intermediate data
					SecureZeroMemory(dataToEncode.data(), dataToEncode.capacity());
					dataToEncode.clear();

					if (base64.empty()) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Base64 encoding failed"; }
						return false;
					}

					// PK6: Build PEM with std::string (no ostringstream — cannot securely wipe its buffer)
					const char* beginMarker = encrypt ? "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" : "-----BEGIN PRIVATE KEY-----\n";
					const char* endMarker = encrypt ? "-----END ENCRYPTED PRIVATE KEY-----\n" : "-----END PRIVATE KEY-----\n";

					std::string pem;
					pem.reserve(std::strlen(beginMarker) + base64.size() + (base64.size() / 64) + std::strlen(endMarker) + 16);
					pem.append(beginMarker);

					constexpr size_t lineWidth = 64;
					for (size_t i = 0; i < base64.size(); i += lineWidth) {
						size_t chunkSize = std::min(lineWidth, base64.size() - i);
						pem.append(base64, i, chunkSize);
						pem.push_back('\n');
					}

					pem.append(endMarker);

					// PK6: Securely wipe base64-encoded key material
					SecureZeroMemory(base64.data(), base64.capacity());
					base64.clear();

					out = std::move(pem);
					return true;
				}
				catch (const std::exception&) {
					// Wipe sensitive locals that survived stack unwinding (declared before try)
					if (!dataToEncode.empty()) SecureZeroMemory(dataToEncode.data(), dataToEncode.capacity());
					if (!base64.empty()) SecureZeroMemory(base64.data(), base64.capacity());
					if (err) { err->win32 = ERROR_NOT_ENOUGH_MEMORY; err->message = L"Allocation failure in ExportPEM"; }
					return false;
				}
			}

			bool PrivateKey::Import(const uint8_t* data, size_t len, PrivateKey& out, Error* err) noexcept {
				if (!data || len == 0) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid input data"; }
					return false;
				}

				try {
					out.keyBlob.assign(data, data + len);
				}
				catch (const std::exception&) {
					if (err) { err->win32 = ERROR_NOT_ENOUGH_MEMORY; err->message = L"Failed to copy key data"; }
					return false;
				}
				return true;
			}
			// Helper for RSA PRIVATE KEY format
			static bool ImportPEM_RSAFormat(std::string_view pem, PrivateKey& out, std::string_view password, Error* err) noexcept {
				// Declare sensitive local before try so catch can wipe on exception
				std::string cleanBase64;

				try {
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

					cleanBase64.reserve(base64Content.size());
					for (char c : base64Content) {
						if (c != '\n' && c != '\r' && c != ' ' && c != '\t') {
							cleanBase64.push_back(c);
						}
					}

					std::vector<uint8_t> decoded;
					if (!Base64::Decode(cleanBase64, decoded)) {
						SecureZeroMemory(cleanBase64.data(), cleanBase64.capacity());
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Base64 decoding failed"; }
						return false;
					}

					SecureZeroMemory(cleanBase64.data(), cleanBase64.capacity());
					cleanBase64.clear();

					out.keyBlob = std::move(decoded);
					return true;
				}
				catch (const std::exception&) {
					if (!cleanBase64.empty()) SecureZeroMemory(cleanBase64.data(), cleanBase64.capacity());
					if (err) { err->win32 = ERROR_NOT_ENOUGH_MEMORY; err->message = L"Allocation failure in ImportPEM_RSAFormat"; }
					return false;
				}
			}

			// PK12: Enhanced ASN.1 sanity checks (validate SEQUENCE tag + length field)
			static bool ValidatePKCS1RSAPrivateKey(const std::vector<uint8_t>& der) noexcept {
				// PKCS#1: SEQUENCE { INTEGER(version), INTEGER(modulus), ... }
				if (der.size() < 4 || der[0] != 0x30) return false;

				// Validate length encoding
				size_t lengthBytes = 0;
				size_t contentLength = 0;
				if (der[1] <= 0x7F) {
					// Short form: length in single byte
					contentLength = der[1];
					lengthBytes = 1;
				}
				else {
					// Long form: der[1] & 0x7F = number of length bytes
					size_t numLenBytes = der[1] & 0x7F;
					if (numLenBytes == 0 || numLenBytes > 4 || (2 + numLenBytes) > der.size()) return false;
					for (size_t i = 0; i < numLenBytes; ++i) {
						contentLength = (contentLength << 8) | der[2 + i];
					}
					lengthBytes = 1 + numLenBytes;
				}

				// Total must be at least tag(1) + lengthField + contentLength
				if (der.size() < 1 + lengthBytes + contentLength) return false;

				// RSA private key must contain version INTEGER (tag 0x02) as first element
				size_t contentStart = 1 + lengthBytes;
				if (contentStart >= der.size() || der[contentStart] != 0x02) return false;

				return true;
			}

			static bool ValidatePKCS8PrivateKeyInfo(const std::vector<uint8_t>& der) noexcept {
				// PKCS#8: SEQUENCE { INTEGER(version), SEQUENCE(algorithm), OCTET STRING(key) }
				if (der.size() < 4 || der[0] != 0x30) return false;

				// Validate length encoding
				size_t lengthBytes = 0;
				size_t contentLength = 0;
				if (der[1] <= 0x7F) {
					contentLength = der[1];
					lengthBytes = 1;
				}
				else {
					size_t numLenBytes = der[1] & 0x7F;
					if (numLenBytes == 0 || numLenBytes > 4 || (2 + numLenBytes) > der.size()) return false;
					for (size_t i = 0; i < numLenBytes; ++i) {
						contentLength = (contentLength << 8) | der[2 + i];
					}
					lengthBytes = 1 + numLenBytes;
				}

				if (der.size() < 1 + lengthBytes + contentLength) return false;

				// PKCS#8 must contain version INTEGER (tag 0x02) as first element
				size_t contentStart = 1 + lengthBytes;
				if (contentStart >= der.size() || der[contentStart] != 0x02) return false;

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

				// PK10: Cap PEM input size to prevent DoS (no legitimate private key PEM exceeds 1 MiB)
				constexpr size_t kMaxPemSize = 1024 * 1024;
				if (pem.size() > kMaxPemSize) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"PEM input exceeds maximum allowed size"; }
					return false;
				}

				// Sensitive locals declared before try so catch can wipe on exception
				std::string cleanBase64;
				std::vector<uint8_t> decoded;
				std::vector<uint8_t> salt;
				std::vector<uint8_t> iv;
				std::vector<uint8_t> key;
				std::vector<uint8_t> decrypted;

				try {
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
							if (!ImportPEM_RSAFormat(pem, out, std::string_view{}, err)) return false;
							if (!ValidatePKCS1RSAPrivateKey(out.keyBlob)) {
								if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid PKCS#1 RSA private key"; }
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
					if (!Base64::Decode(cleanBase64, decoded)) {
						SecureZeroMemory(cleanBase64.data(), cleanBase64.capacity());
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Base64 decoding failed"; }
						return false;
					}

					// Wipe base64 material
					SecureZeroMemory(cleanBase64.data(), cleanBase64.capacity());
					cleanBase64.clear();

					if (decoded.empty()) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Decoded data is empty"; }
						return false;
					}

					if (isEncrypted) {
						if (password.empty()) {
							if (err) { err->win32 = ERROR_INVALID_PASSWORD; err->message = L"Password required for encrypted key"; }
							SecureZeroMemory(decoded.data(), decoded.size());
							return false;
						}

						// Custom encrypted PKCS#8 header:
						// [VERSION(4)] + [ITERATIONS(4)] + [SALT(32)] + [IV(16)] + [ENCRYPTED_DATA]
						constexpr size_t kMinHeaderSize = 4 + 4 + 32 + 16;
						if (decoded.size() < kMinHeaderSize) {
							if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Encrypted data too short"; }
							SecureZeroMemory(decoded.data(), decoded.size());
							return false;
						}

						size_t offset = 0;
						const uint32_t version = ReadLE32(decoded.data() + offset); offset += 4;
						uint32_t iterations = ReadLE32(decoded.data() + offset); offset += 4;

						// PK8: Reject unknown format versions instead of silent fallback
						if (version != 1) {
							if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Unsupported encrypted key format version"; }
							SecureZeroMemory(decoded.data(), decoded.size());
							return false;
						}

						if (decoded.size() < offset + 32 + 16) {
							if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Encrypted data format mismatch"; }
							SecureZeroMemory(decoded.data(), decoded.size());
							return false;
						}

						salt.assign(decoded.begin() + offset, decoded.begin() + offset + 32);
						offset += 32;
						iv.assign(decoded.begin() + offset, decoded.begin() + offset + 16);
						offset += 16;

						const uint8_t* encryptedData = decoded.data() + offset;
						const size_t encryptedSize = decoded.size() - offset;

						// PK10: Cap encrypted data size (no legitimate key exceeds 64 KiB encrypted)
						constexpr size_t kMaxEncryptedKeySize = 64 * 1024;
						if (encryptedSize > kMaxEncryptedKeySize || encryptedSize == 0) {
							if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Encrypted key data size out of range"; }
							SecureZeroMemory(salt.data(), salt.size());
							SecureZeroMemory(iv.data(), iv.size());
							SecureZeroMemory(decoded.data(), decoded.size());
							return false;
						}

						// Enforce minimum iterations (OWASP 2023)
						if (iterations < 1000) iterations = 600000;

						KDFParams kdfParams{};
						kdfParams.algorithm = KDFAlgorithm::PBKDF2_SHA256;
						kdfParams.iterations = iterations;
						kdfParams.keyLength = 32;
						kdfParams.salt = salt;

						if (!KeyDerivation::DeriveKey(password, kdfParams, key, err)) {
							SecureZeroMemory(salt.data(), salt.size());
							SecureZeroMemory(iv.data(), iv.size());
							SecureZeroMemory(decoded.data(), decoded.size());
							return false;
						}

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

						const bool decOk = cipher.Decrypt(encryptedData, encryptedSize, decrypted, err);

						// Zero sensitive buffers regardless of success
						SecureZeroMemory(key.data(), key.size());
						SecureZeroMemory(salt.data(), salt.size());
						SecureZeroMemory(iv.data(), iv.size());
						SecureZeroMemory(decoded.data(), decoded.size());

						if (!decOk) {
							// PK11: Wipe decrypted buffer on failure (may contain partial plaintext)
							if (!decrypted.empty()) {
								SecureZeroMemory(decrypted.data(), decrypted.size());
							}
							return false;
						}

						// ASN.1 validation
						if (!ValidatePKCS1RSAPrivateKey(decrypted) && !ValidatePKCS8PrivateKeyInfo(decrypted)) {
							if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Decrypted data is not a valid private key"; }
							SecureZeroMemory(decrypted.data(), decrypted.size());
							return false;
						}

						out.keyBlob = std::move(decrypted);
						return true;
					}
					else {
						// Unencrypted PKCS#8
						if (!ValidatePKCS8PrivateKeyInfo(decoded)) {
							if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid PKCS#8 PrivateKeyInfo"; }
							SecureZeroMemory(decoded.data(), decoded.size());
							return false;
						}
						out.keyBlob = std::move(decoded);
						return true;
					}
				}
				catch (const std::exception&) {
					// Wipe all sensitive locals that survived stack unwinding
					if (!cleanBase64.empty()) SecureZeroMemory(cleanBase64.data(), cleanBase64.capacity());
					if (!decoded.empty()) SecureZeroMemory(decoded.data(), decoded.capacity());
					if (!salt.empty()) SecureZeroMemory(salt.data(), salt.capacity());
					if (!iv.empty()) SecureZeroMemory(iv.data(), iv.capacity());
					if (!key.empty()) SecureZeroMemory(key.data(), key.capacity());
					if (!decrypted.empty()) SecureZeroMemory(decrypted.data(), decrypted.capacity());
					if (err) { err->win32 = ERROR_NOT_ENOUGH_MEMORY; err->message = L"Allocation failure in ImportPEM"; }
					return false;
				}
			}
		}//namespace CryptoUtils
	}// namespace Utils
}// namespace ShadowStrike
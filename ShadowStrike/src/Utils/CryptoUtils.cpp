// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
/**
 * @file CryptoUtils.cpp
 * @brief Enterprise-grade cryptographic utilities implementation
 *
 * Implements symmetric/asymmetric encryption, secure random generation,
 * key derivation, and secure memory handling using Windows CNG APIs.
 *
 * @copyright Copyright (c) 2025 ShadowStrike Security Suite
 */

#include"pch.h"
#include "CryptoUtils.hpp"
#include "Base64Utils.hpp"
#include "HashUtils.hpp"
#include "FileUtils.hpp"
#include "Logger.hpp"
#include"CryptoUtilsCommon.hpp"

// ============================================================================
// Standard Library Headers
// ============================================================================
#include <sstream>
#include <cmath>
#include <limits>
#include <cstring>
#include <algorithm>
#include <fstream>
#include <vector>
#include <memory>
#include <type_traits>

// ============================================================================
// Windows Platform Headers
// ============================================================================
#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif

#  ifndef CERT_KEY_CERT_SIGN_KEY_USAGE
#    define CERT_KEY_CERT_SIGN_KEY_USAGE 0x04  // Bit 5 (keyCertSign)
#  endif

#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0A00
#  endif

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
					// SECURITY: Clear plaintext before returning on error
					SecureZeroMemory(plaintext.data(), plaintext.size());
					return false;
				}

				// SECURITY: Clear plaintext immediately after encryption
				SecureZeroMemory(plaintext.data(), plaintext.size());
				plaintext.clear();

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

				// SECURITY: Clear plaintext after conversion
				SecureZeroMemory(plaintext.data(), plaintext.size());
				plaintext.clear();

				if (!FileUtils::WriteAllBytesAtomic(outputPath, output, &fileErr)) {
					// SECURITY: Clear output buffer on write failure
					SecureZeroMemory(output.data(), output.size());
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to write output file"; }
					return false;
				}

				// SECURITY: Clear output buffer after successful write
				SecureZeroMemory(output.data(), output.size());
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
					// SECURITY: Clear key on failure
					SecureZeroMemory(key.data(), key.size());
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to read input file"; }
					return false;
				}

				// Encrypt with AES-256-GCM
				SymmetricCipher cipher(SymmetricAlgorithm::AES_256_GCM);
				if (!cipher.SetKey(key, err)) {
					SecureZeroMemory(key.data(), key.size());
					SecureZeroMemory(plaintext.data(), plaintext.size());
					return false;
				}

				// SECURITY: Clear key immediately after setting in cipher
				SecureZeroMemory(key.data(), key.size());
				key.clear();

				std::vector<uint8_t> iv;
				if (!cipher.GenerateIV(iv, err)) {
					SecureZeroMemory(plaintext.data(), plaintext.size());
					return false;
				}

				std::vector<uint8_t> ciphertext, tag;
				if (!cipher.EncryptAEAD(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
					nullptr, 0, ciphertext, tag, err))
				{
					// SECURITY: Clear plaintext on encryption failure
					SecureZeroMemory(plaintext.data(), plaintext.size());
					return false;
				}

				// SECURITY: Clear plaintext immediately after encryption
				SecureZeroMemory(plaintext.data(), plaintext.size());
				plaintext.clear();

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

				// SECURITY: Clear salt after use (key already cleared earlier)
				SecureZeroMemory(salt.data(), salt.size());
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
				if (!cipher.SetKey(key, err)) {
					SecureZeroMemory(key.data(), key.size());
					return false;
				}

				// SECURITY: Clear key immediately after setting in cipher
				SecureZeroMemory(key.data(), key.size());
				key.clear();

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

				// SECURITY: Clear plaintext after conversion
				SecureZeroMemory(plaintext.data(), plaintext.size());
				plaintext.clear();

				if (!FileUtils::WriteAllBytesAtomic(outputPath, output, &fileErr)) {
					// SECURITY: Clear output on write failure
					SecureZeroMemory(output.data(), output.size());
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to write output file"; }
					return false;
				}

				// SECURITY: Clear output buffer after successful write
				SecureZeroMemory(output.data(), output.size());
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

				// SECURITY: Clear plaintext vector after assignment
				SecureZeroMemory(plaintext.data(), plaintext.size());
				return true;
			}

			}//namespace CryptoUtils
			}//namespace Utils
			}//namespace ShadowStrike
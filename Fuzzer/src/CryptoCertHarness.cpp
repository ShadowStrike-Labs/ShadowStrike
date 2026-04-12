// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
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
 * @file CryptoCertHarness.cpp
 * @brief Implementation of the crypto and certificate utility fuzz harness.
 */

#include "ShadowStrike/Fuzzer/Harnesses/CryptoCertHarness.hpp"
#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"

#include "Utils/CertUtils.hpp"
#include "Utils/CryptoUtils.hpp"
#include "Utils/HashUtils.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <malloc.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <exception>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <vector>

namespace ShadowStrike::Fuzzer {
namespace {

namespace Cert = ShadowStrike::Utils::CertUtils;
namespace Crypto = ShadowStrike::Utils::CryptoUtils;
namespace Hash = ShadowStrike::Utils::HashUtils;

constexpr std::array<Hash::Algorithm, 6> kHashAlgorithms{
    Hash::Algorithm::SHA1,
    Hash::Algorithm::SHA256,
    Hash::Algorithm::SHA384,
    Hash::Algorithm::SHA512,
    Hash::Algorithm::MD5,
    Hash::Algorithm::SHA3_256,
};

std::string ExceptionCodeToStringInternal(DWORD code) {
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:         return "EXCEPTION_ACCESS_VIOLATION";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
    case EXCEPTION_BREAKPOINT:               return "EXCEPTION_BREAKPOINT";
    case EXCEPTION_DATATYPE_MISALIGNMENT:    return "EXCEPTION_DATATYPE_MISALIGNMENT";
    case EXCEPTION_FLT_DENORMAL_OPERAND:     return "EXCEPTION_FLT_DENORMAL_OPERAND";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:       return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
    case EXCEPTION_FLT_INEXACT_RESULT:       return "EXCEPTION_FLT_INEXACT_RESULT";
    case EXCEPTION_FLT_INVALID_OPERATION:    return "EXCEPTION_FLT_INVALID_OPERATION";
    case EXCEPTION_FLT_OVERFLOW:             return "EXCEPTION_FLT_OVERFLOW";
    case EXCEPTION_FLT_STACK_CHECK:          return "EXCEPTION_FLT_STACK_CHECK";
    case EXCEPTION_FLT_UNDERFLOW:            return "EXCEPTION_FLT_UNDERFLOW";
    case EXCEPTION_GUARD_PAGE:               return "EXCEPTION_GUARD_PAGE";
    case EXCEPTION_ILLEGAL_INSTRUCTION:      return "EXCEPTION_ILLEGAL_INSTRUCTION";
    case EXCEPTION_IN_PAGE_ERROR:            return "EXCEPTION_IN_PAGE_ERROR";
    case EXCEPTION_INT_DIVIDE_BY_ZERO:       return "EXCEPTION_INT_DIVIDE_BY_ZERO";
    case EXCEPTION_INT_OVERFLOW:             return "EXCEPTION_INT_OVERFLOW";
    case EXCEPTION_INVALID_DISPOSITION:      return "EXCEPTION_INVALID_DISPOSITION";
    case EXCEPTION_INVALID_HANDLE:           return "EXCEPTION_INVALID_HANDLE";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
    case EXCEPTION_PRIV_INSTRUCTION:         return "EXCEPTION_PRIV_INSTRUCTION";
    case EXCEPTION_SINGLE_STEP:              return "EXCEPTION_SINGLE_STEP";
    case EXCEPTION_STACK_OVERFLOW:           return "EXCEPTION_STACK_OVERFLOW";
    case STATUS_HEAP_CORRUPTION:             return "STATUS_HEAP_CORRUPTION";
    default: {
        char buffer[32]{};
        std::snprintf(buffer, sizeof(buffer), "EXCEPTION_0x%08lX", code);
        return buffer;
    }
    }
}

void SetFirstError(HarnessResult& result, std::string message) {
    if (result.errorMessage.empty()) {
        result.errorMessage = std::move(message);
    }
}

void RecordValidation(HarnessResult& result, std::string message) {
    ++result.validationIssueCount;
    SetFirstError(result, std::move(message));
}

std::string NarrowWide(std::wstring_view value) {
    if (value.empty()) {
        return {};
    }

    const int required = WideCharToMultiByte(
        CP_UTF8,
        0,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (required <= 0) {
        return {};
    }

    std::string result(static_cast<size_t>(required), '\0');
    const int written = WideCharToMultiByte(
        CP_UTF8,
        0,
        value.data(),
        static_cast<int>(value.size()),
        result.data(),
        required,
        nullptr,
        nullptr);
    if (written <= 0) {
        return {};
    }

    return result;
}

std::string BuildErrorMessage(std::string_view operation, const Cert::Error& error) {
    std::ostringstream stream;
    stream << operation;

    const std::string context = NarrowWide(error.context);
    if (!context.empty()) {
        stream << " [" << context << ']';
    }

    const std::string message = NarrowWide(error.message);
    if (!message.empty()) {
        stream << ": " << message;
    }

    stream << " (win32=" << error.win32 << ", ntstatus=" << error.ntstatus << ')';
    return stream.str();
}

std::string BuildErrorMessage(std::string_view operation, const Crypto::Error& error) {
    std::ostringstream stream;
    stream << operation;

    const std::string context = NarrowWide(error.context);
    if (!context.empty()) {
        stream << " [" << context << ']';
    }

    const std::string message = NarrowWide(error.message);
    if (!message.empty()) {
        stream << ": " << message;
    }

    stream << " (win32=" << error.win32 << ", ntstatus=" << error.ntstatus << ')';
    return stream.str();
}

std::string BuildErrorMessage(std::string_view operation, const Hash::Error& error) {
    std::ostringstream stream;
    stream << operation << " (win32=" << error.win32 << ", ntstatus=" << error.ntstatus << ')';
    return stream.str();
}

[[nodiscard]] bool ContainsPemMarkers(std::string_view text) noexcept {
    return text.find("-----BEGIN CERTIFICATE-----") != std::string_view::npos &&
           text.find("-----END CERTIFICATE-----") != std::string_view::npos;
}

[[nodiscard]] bool EqualsCaseInsensitiveHex(std::string_view lhs, std::string_view rhs) noexcept {
    if (lhs.size() != rhs.size()) {
        return false;
    }

    for (size_t index = 0; index < lhs.size(); ++index) {
        const unsigned char left = static_cast<unsigned char>(lhs[index]);
        const unsigned char right = static_cast<unsigned char>(rhs[index]);
        if (std::tolower(left) != std::tolower(right)) {
            return false;
        }
    }

    return true;
}

[[nodiscard]] bool IsSyntacticallyValidHex(std::string_view hex) noexcept {
    if (hex.empty() || (hex.size() % 2) != 0 || hex.size() > Hash::MAX_HEX_INPUT_SIZE) {
        return false;
    }

    return std::all_of(hex.begin(), hex.end(), [](char ch) {
        const unsigned char value = static_cast<unsigned char>(ch);
        return std::isxdigit(value) != 0;
    });
}

std::vector<uint8_t> BuildNormalizedMaterial(
    std::span<const uint8_t> preferred,
    std::span<const uint8_t> fallback,
    size_t minimumSize)
{
    const std::span<const uint8_t> source = !preferred.empty() ? preferred : fallback;
    if (source.empty()) {
        return {};
    }

    const size_t targetSize = std::max(minimumSize, source.size());
    std::vector<uint8_t> material;
    material.reserve(targetSize);

    while (material.size() < targetSize) {
        const size_t copyLength = std::min(source.size(), targetSize - material.size());
        material.insert(material.end(), source.begin(), source.begin() + static_cast<std::ptrdiff_t>(copyLength));
    }

    return material;
}

[[nodiscard]] const uint8_t* DataOrNull(std::span<const uint8_t> bytes) noexcept {
    return bytes.empty() ? nullptr : bytes.data();
}

void ExerciseLoadedCertificate(
    Cert::Certificate& certificate,
    std::span<const uint8_t> originalInput,
    bool originalInputWasPem,
    HarnessResult& result)
{
    Cert::Error certError{};
    Cert::CertificateInfo info{};
    if (!certificate.GetInfo(info, &certError)) {
        RecordValidation(result, BuildErrorMessage("Certificate::GetInfo", certError));
    } else {
        if (!info.thumbprint.empty() && info.thumbprint.size() != 64) {
            RecordValidation(result, "CertificateInfo thumbprint length mismatch");
        }
        if (info.isExpired) {
            ++result.anomalyCount;
        }
        if (info.isSelfSigned) {
            ++result.anomalyCount;
        }
        if (info.isCA) {
            ++result.anomalyCount;
        }
    }

    std::wstring sha256Thumbprint;
    certError.Clear();
    if (!certificate.GetThumbprint(sha256Thumbprint, true, &certError)) {
        RecordValidation(result, BuildErrorMessage("Certificate::GetThumbprint(SHA-256)", certError));
    } else if (sha256Thumbprint.size() != 64) {
        RecordValidation(result, "Certificate SHA-256 thumbprint length mismatch");
    } else if (!info.thumbprint.empty() && info.thumbprint != sha256Thumbprint) {
        RecordValidation(result, "CertificateInfo thumbprint does not match GetThumbprint(SHA-256)");
    }

    std::wstring sha1Thumbprint;
    certError.Clear();
    if (!certificate.GetThumbprint(sha1Thumbprint, false, &certError)) {
        RecordValidation(result, BuildErrorMessage("Certificate::GetThumbprint(SHA-1)", certError));
    } else if (sha1Thumbprint.size() != 40) {
        RecordValidation(result, "Certificate SHA-1 thumbprint length mismatch");
    }

    std::vector<uint8_t> exportedDer;
    certError.Clear();
    if (!certificate.Export(exportedDer, &certError)) {
        RecordValidation(result, BuildErrorMessage("Certificate::Export", certError));
    } else {
        if (exportedDer.empty()) {
            RecordValidation(result, "Certificate::Export returned an empty DER buffer");
        }

        if (!originalInputWasPem) {
            if (exportedDer.size() != originalInput.size() ||
                !std::equal(exportedDer.begin(), exportedDer.end(), originalInput.begin(), originalInput.end())) {
                RecordValidation(result, "Certificate DER export does not match original DER input");
            }
        }

        Cert::Certificate derRoundTrip;
        Cert::Error roundTripError{};
        if (!derRoundTrip.LoadFromMemory(exportedDer.data(), exportedDer.size(), &roundTripError)) {
            RecordValidation(result, BuildErrorMessage("Certificate::LoadFromMemory(round-trip)", roundTripError));
        } else {
            std::vector<uint8_t> roundTripDer;
            roundTripError.Clear();
            if (!derRoundTrip.Export(roundTripDer, &roundTripError)) {
                RecordValidation(result, BuildErrorMessage("Certificate::Export(round-trip)", roundTripError));
            } else if (roundTripDer != exportedDer) {
                RecordValidation(result, "Round-tripped DER export mismatch");
            }
        }
    }

    std::string exportedPem;
    certError.Clear();
    if (!certificate.ExportPEM(exportedPem, &certError)) {
        RecordValidation(result, BuildErrorMessage("Certificate::ExportPEM", certError));
    } else {
        if (!ContainsPemMarkers(exportedPem)) {
            RecordValidation(result, "Certificate::ExportPEM output is missing PEM markers");
        }

        Cert::Certificate pemRoundTrip;
        Cert::Error roundTripError{};
        if (!pemRoundTrip.LoadFromPEM(exportedPem, &roundTripError)) {
            RecordValidation(result, BuildErrorMessage("Certificate::LoadFromPEM(round-trip)", roundTripError));
        } else if (!exportedDer.empty()) {
            std::vector<uint8_t> pemDer;
            roundTripError.Clear();
            if (!pemRoundTrip.Export(pemDer, &roundTripError)) {
                RecordValidation(result, BuildErrorMessage("Certificate::Export(PEM round-trip)", roundTripError));
            } else if (pemDer != exportedDer) {
                RecordValidation(result, "PEM round-trip DER mismatch");
            }
        }
    }

    Cert::Error verifyError{};
    if (!certificate.VerifyChain(
            &verifyError,
            nullptr,
            CERT_CHAIN_CACHE_END_CERT | CERT_CHAIN_DISABLE_AIA,
            nullptr,
            nullptr)) {
        ++result.anomalyCount;
    }
}

void ExerciseHashes(std::span<const uint8_t> input, std::string_view inputText, HarnessResult& result) {
    std::vector<uint8_t> inputHexDecoded;
    if (Hash::FromHex(inputText, inputHexDecoded)) {
        const std::string normalized = Hash::ToHexLower(inputHexDecoded);
        if (!normalized.empty() && !EqualsCaseInsensitiveHex(normalized, inputText)) {
            RecordValidation(result, "HashUtils::FromHex round-trip mismatch for raw input");
        }
    } else if (IsSyntacticallyValidHex(inputText)) {
        RecordValidation(result, "HashUtils::FromHex rejected syntactically valid hex input");
    }

    for (const Hash::Algorithm algorithm : kHashAlgorithms) {
        const size_t expectedDigestSize = Hash::DigestSize(algorithm);
        std::vector<uint8_t> digest;
        Hash::Error hashError{};

        if (!Hash::Compute(algorithm, DataOrNull(input), input.size(), digest, &hashError)) {
            if (algorithm != Hash::Algorithm::SHA3_256) {
                RecordValidation(result, BuildErrorMessage("HashUtils::Compute", hashError));
            }
            continue;
        }

        if (digest.size() != expectedDigestSize) {
            RecordValidation(result, "HashUtils::Compute returned an unexpected digest length");
        }

        std::string hexLower;
        hashError.clear();
        if (!Hash::ComputeHex(algorithm, DataOrNull(input), input.size(), hexLower, false, &hashError)) {
            RecordValidation(result, BuildErrorMessage("HashUtils::ComputeHex(lower)", hashError));
            continue;
        }

        if (hexLower.size() != expectedDigestSize * 2) {
            RecordValidation(result, "HashUtils::ComputeHex(lower) returned an unexpected hex length");
        }

        std::vector<uint8_t> decodedHex;
        if (!Hash::FromHex(hexLower, decodedHex)) {
            RecordValidation(result, "HashUtils::FromHex failed on ComputeHex(lower) output");
        } else if (decodedHex != digest) {
            RecordValidation(result, "HashUtils::FromHex output does not match original digest");
        }

        std::string hexUpper;
        hashError.clear();
        if (!Hash::ComputeHex(algorithm, DataOrNull(input), input.size(), hexUpper, true, &hashError)) {
            RecordValidation(result, BuildErrorMessage("HashUtils::ComputeHex(upper)", hashError));
        } else if (hexUpper.size() != expectedDigestSize * 2) {
            RecordValidation(result, "HashUtils::ComputeHex(upper) returned an unexpected hex length");
        }
    }
}

void ExerciseKeyDerivation(std::span<const uint8_t> input, HarnessResult& result) {
    if (input.empty()) {
        return;
    }

    const size_t midpoint = input.size() / 2;
    const std::span<const uint8_t> passwordPart = input.first(midpoint);
    const std::span<const uint8_t> saltPart = input.subspan(midpoint);

    const std::vector<uint8_t> password = BuildNormalizedMaterial(passwordPart, input, 1);
    const std::vector<uint8_t> salt = BuildNormalizedMaterial(saltPart, input, 8);
    if (password.empty() || salt.empty()) {
        return;
    }

    std::array<uint8_t, 32> pbkdf2First{};
    std::array<uint8_t, 32> pbkdf2Second{};
    Crypto::Error cryptoError{};
    if (!Crypto::KeyDerivation::PBKDF2(
            password.data(),
            password.size(),
            salt.data(),
            salt.size(),
            1,
            Hash::Algorithm::SHA256,
            pbkdf2First.data(),
            pbkdf2First.size(),
            &cryptoError)) {
        RecordValidation(result, BuildErrorMessage("KeyDerivation::PBKDF2", cryptoError));
    } else {
        cryptoError.Clear();
        if (!Crypto::KeyDerivation::PBKDF2(
                password.data(),
                password.size(),
                salt.data(),
                salt.size(),
                1,
                Hash::Algorithm::SHA256,
                pbkdf2Second.data(),
                pbkdf2Second.size(),
                &cryptoError)) {
            RecordValidation(result, BuildErrorMessage("KeyDerivation::PBKDF2(repeat)", cryptoError));
        } else if (pbkdf2First != pbkdf2Second) {
            RecordValidation(result, "PBKDF2 returned inconsistent output for identical inputs");
        }
    }

    std::array<uint8_t, 42> hkdfFirst{};
    std::array<uint8_t, 42> hkdfSecond{};
    const uint8_t* infoData = password.empty() ? nullptr : password.data();
    const size_t infoSize = password.size();

    cryptoError.Clear();
    if (!Crypto::KeyDerivation::HKDF(
            input.data(),
            input.size(),
            salt.data(),
            salt.size(),
            infoData,
            infoSize,
            Hash::Algorithm::SHA256,
            hkdfFirst.data(),
            hkdfFirst.size(),
            &cryptoError)) {
        RecordValidation(result, BuildErrorMessage("KeyDerivation::HKDF", cryptoError));
    } else {
        cryptoError.Clear();
        if (!Crypto::KeyDerivation::HKDF(
                input.data(),
                input.size(),
                salt.data(),
                salt.size(),
                infoData,
                infoSize,
                Hash::Algorithm::SHA256,
                hkdfSecond.data(),
                hkdfSecond.size(),
                &cryptoError)) {
            RecordValidation(result, BuildErrorMessage("KeyDerivation::HKDF(repeat)", cryptoError));
        } else if (hkdfFirst != hkdfSecond) {
            RecordValidation(result, "HKDF returned inconsistent output for identical inputs");
        }
    }
}

void ExerciseStringCrypto(std::span<const uint8_t> input, std::string_view inputText, HarnessResult& result) {
    if (input.size() < 32) {
        return;
    }

    const uint8_t* key = input.data();
    const std::string plaintext(
        reinterpret_cast<const char*>(input.data() + 32),
        input.size() - 32);

    std::string encoded;
    Crypto::Error cryptoError{};
    if (!Crypto::EncryptString(std::string_view(plaintext.data(), plaintext.size()), key, 32, encoded, &cryptoError)) {
        RecordValidation(result, BuildErrorMessage("CryptoUtils::EncryptString", cryptoError));
    } else {
        std::string decoded;
        cryptoError.Clear();
        if (!Crypto::DecryptString(encoded, key, 32, decoded, &cryptoError)) {
            RecordValidation(result, BuildErrorMessage("CryptoUtils::DecryptString(round-trip)", cryptoError));
        } else if (decoded != plaintext) {
            RecordValidation(result, "CryptoUtils::DecryptString round-trip mismatch");
        }
    }

    std::string fuzzDecoded;
    cryptoError.Clear();
    (void)Crypto::DecryptString(inputText, key, 32, fuzzDecoded, &cryptoError);
}

void ExerciseSymmetricRoundTrip(std::span<const uint8_t> input, HarnessResult& result) {
    if (input.size() < 48) {
        return;
    }

    const std::span<const uint8_t> key = input.first(32);
    const std::span<const uint8_t> iv = input.subspan(32, 16);
    const std::span<const uint8_t> plaintext = input.subspan(48);

    Crypto::Error cryptoError{};
    Crypto::SymmetricCipher encryptor(Crypto::SymmetricAlgorithm::AES_256_CBC);
    if (!encryptor.SetKey(key.data(), key.size(), &cryptoError)) {
        RecordValidation(result, BuildErrorMessage("SymmetricCipher::SetKey(encrypt)", cryptoError));
        return;
    }

    cryptoError.Clear();
    if (!encryptor.SetIV(iv.data(), iv.size(), &cryptoError)) {
        RecordValidation(result, BuildErrorMessage("SymmetricCipher::SetIV(encrypt)", cryptoError));
        return;
    }

    std::vector<uint8_t> ciphertext;
    cryptoError.Clear();
    if (!encryptor.Encrypt(DataOrNull(plaintext), plaintext.size(), ciphertext, &cryptoError)) {
        RecordValidation(result, BuildErrorMessage("SymmetricCipher::Encrypt", cryptoError));
        return;
    }

    const size_t blockSize = encryptor.GetBlockSize();
    if (blockSize == 0 || (ciphertext.size() % blockSize) != 0) {
        RecordValidation(result, "SymmetricCipher::Encrypt produced a non-block-aligned ciphertext");
    }

    Crypto::SymmetricCipher decryptor(Crypto::SymmetricAlgorithm::AES_256_CBC);
    cryptoError.Clear();
    if (!decryptor.SetKey(key.data(), key.size(), &cryptoError)) {
        RecordValidation(result, BuildErrorMessage("SymmetricCipher::SetKey(decrypt)", cryptoError));
        return;
    }

    cryptoError.Clear();
    if (!decryptor.SetIV(iv.data(), iv.size(), &cryptoError)) {
        RecordValidation(result, BuildErrorMessage("SymmetricCipher::SetIV(decrypt)", cryptoError));
        return;
    }

    std::vector<uint8_t> decrypted;
    cryptoError.Clear();
    if (!decryptor.Decrypt(ciphertext.empty() ? nullptr : ciphertext.data(), ciphertext.size(), decrypted, &cryptoError)) {
        RecordValidation(result, BuildErrorMessage("SymmetricCipher::Decrypt", cryptoError));
        return;
    }

    if (decrypted.size() != plaintext.size() ||
        !std::equal(decrypted.begin(), decrypted.end(), plaintext.begin(), plaintext.end())) {
        RecordValidation(result, "SymmetricCipher round-trip plaintext mismatch");
    }
}

}  // namespace

std::string CryptoCertHarness::ExceptionCodeToString(unsigned long code) {
    return ExceptionCodeToStringInternal(static_cast<DWORD>(code));
}

bool CryptoCertHarness::ExerciseImpl(
    const uint8_t* data,
    size_t size,
    HarnessResult& result)
{
    const auto startTime = std::chrono::high_resolution_clock::now();

    const std::span<const uint8_t> input(data, size);
    const char* textData = size == 0 ? "" : reinterpret_cast<const char*>(data);
    const std::string_view inputText(textData, size);

    Cert::Certificate certFromMemory;
    Cert::Error certError{};
    if (certFromMemory.LoadFromMemory(data, size, &certError)) {
        result.parsedOk = true;
        ExerciseLoadedCertificate(certFromMemory, input, ContainsPemMarkers(inputText), result);
    }

    Cert::Certificate certFromPem;
    certError.Clear();
    if (certFromPem.LoadFromPEM(inputText, &certError)) {
        result.parsedOk = true;
        ExerciseLoadedCertificate(certFromPem, input, true, result);
    }

    ExerciseHashes(input, inputText, result);
    ExerciseKeyDerivation(input, result);
    ExerciseStringCrypto(input, inputText, result);
    ExerciseSymmetricRoundTrip(input, result);

    const auto endTime = std::chrono::high_resolution_clock::now();
    result.parseTimeNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime).count());
    return true;
}

unsigned long CryptoCertHarness::SEHCallExercise(
    const uint8_t* data,
    size_t size,
    HarnessResult* pResult) noexcept
{
    DWORD exCode = 0;
    __try {
        (void)ExerciseImpl(data, size, *pResult);
    }
    __except (exCode = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
        if (exCode == EXCEPTION_STACK_OVERFLOW) {
            if (_resetstkoflw() == 0) {
                TerminateProcess(GetCurrentProcess(), exCode);
            }
        }
        if (exCode == STATUS_HEAP_CORRUPTION) {
            TerminateProcess(GetCurrentProcess(), exCode);
        }
    }
    return exCode;
}

HarnessResult CryptoCertHarness::Run(std::span<const uint8_t> input) {
    HarnessResult result{};

    try {
        const DWORD exceptionCode = SEHCallExercise(
            input.empty() ? nullptr : input.data(),
            input.size(),
            &result);
        if (exceptionCode != 0) {
            result.crashed = true;
            result.crashSignal = ExceptionCodeToString(exceptionCode);
        }
    } catch (const std::exception& ex) {
        result.crashed = true;
        result.crashSignal = "CPP_EXCEPTION";
        result.errorMessage = ex.what();
    } catch (...) {
        result.crashed = true;
        result.crashSignal = "CPP_UNKNOWN_EXCEPTION";
    }

    return result;
}

HarnessFunction CryptoCertHarness::GetHarnessFunction() {
    return [](std::span<const uint8_t> input) -> HarnessResult {
        return Run(input);
    };
}

std::string_view CryptoCertHarness::GetName() noexcept {
    return "crypto-cert";
}

std::string_view CryptoCertHarness::GetDescription() noexcept {
    return "Crypto and certificate utility fuzz harness for ShadowStrike NGAV";
}

int RunCryptoCertFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config)
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[CryptoCertFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const auto corpusDir = workspaceDir / "corpora" / "crypto";
    const auto crashDir = workspaceDir / "crashes" / "crypto";

    std::error_code ec;
    std::filesystem::create_directories(corpusDir, ec);
    if (ec) {
        std::cerr << "[CryptoCertFuzzer] Failed to create corpus directory: "
                  << corpusDir << '\n';
        return 1;
    }

    ec.clear();
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        std::cerr << "[CryptoCertFuzzer] Failed to create crash directory: "
                  << crashDir << '\n';
        return 1;
    }

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(CryptoCertHarness::GetName());

    std::cout << "[CryptoCertFuzzer] Starting crypto/certificate fuzzing...\n";
    std::cout << "[CryptoCertFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[CryptoCertFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(corpusDir, crashDir, CryptoCertHarness::GetHarnessFunction(), loopConfig);
    const bool success = loop.Run();
    const auto& stats = loop.GetStatistics();

    std::cout << "\n[CryptoCertFuzzer] Final Results:\n";
    std::cout << "  Total iterations: " << stats.totalIterations << '\n';
    std::cout << "  Unique crashes:   " << stats.uniqueCrashes << '\n';
    std::cout << "  Total crashes:    " << stats.crashesFound << '\n';
    std::cout << "  Final corpus:     " << stats.corpusSize << '\n';
    std::cout << "  Parse success:    " << stats.parseSuccesses << '\n';
    std::cout << "  Parse failure:    " << stats.parseFailures << '\n';
    std::cout << "  Duration:         " << (stats.durationMs / 1000) << "s\n";
    std::cout << "  Speed:            " << std::fixed << std::setprecision(1)
              << stats.iterationsPerSecond << " iter/s\n";

    return success ? 0 : 1;
}

}  // namespace ShadowStrike::Fuzzer

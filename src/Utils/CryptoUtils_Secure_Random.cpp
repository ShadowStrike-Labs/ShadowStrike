
// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
#include"pch.h"
#include"CryptoUtils.hpp"
#include "CryptoUtilsCommon.hpp"
#include<ntstatus.h>
namespace ShadowStrike {
	namespace Utils {
		namespace CryptoUtils {

            // =============================================================================
            // SecureRandom Implementation
            // =============================================================================

            SecureRandom::SecureRandom() noexcept {
#ifdef _WIN32
                // Open algorithm provider for random number generation
                BCRYPT_ALG_HANDLE handle = nullptr;
                const NTSTATUS st = BCryptOpenAlgorithmProvider(
                    &handle,
                    BCRYPT_RNG_ALGORITHM,
                    nullptr,
                    0
                );

                if (BCRYPT_SUCCESS(st) && handle != nullptr) {
                    m_algHandle = handle;
                    m_initialized = true;
                }
                else {
                    // Initialization failed - will fall back to system RNG
                    m_algHandle = nullptr;
                    m_initialized = false;
                }
#else
                m_initialized = false;
#endif
            }

            SecureRandom::~SecureRandom() {
#ifdef _WIN32
                if (m_algHandle != nullptr) {
                    BCryptCloseAlgorithmProvider(m_algHandle, 0);
                    m_algHandle = nullptr;
                }
#endif
                m_initialized = false;
            }

            bool SecureRandom::Generate(uint8_t* buffer, size_t size, Error* err) noexcept {
                // Input validation
                if (buffer == nullptr || size == 0) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_INVALID_PARAMETER,
                            L"Invalid buffer or size for random generation");
                    }
                    return false;
                }

                // Size validation - prevent overflow when casting to ULONG
                if (size > static_cast<size_t>(ULONG_MAX)) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_BUFFER_OVERFLOW,
                            L"Random generation size exceeds ULONG_MAX");
                    }
                    return false;
                }

#ifdef _WIN32
                NTSTATUS st = STATUS_UNSUCCESSFUL;

                if (m_initialized && m_algHandle != nullptr) {
                    // Use our dedicated RNG handle
                    st = BCryptGenRandom(
                        m_algHandle,
                        buffer,
                        static_cast<ULONG>(size),
                        0
                    );
                }
                else {
                    // Fallback to system preferred RNG (always available)
                    st = BCryptGenRandom(
                        nullptr,
                        buffer,
                        static_cast<ULONG>(size),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG
                    );
                }

                if (!BCRYPT_SUCCESS(st)) {
                    // Secure wipe the buffer on failure
                    SecureZeroMemory(buffer, size);

                    if (err != nullptr) {
                        err->SetNtStatus(st, L"BCryptGenRandom failed");
                    }
                    return false;
                }

                return true;
#else
                // Non-Windows platforms not supported
                SecureZeroMemory(buffer, size);
                if (err != nullptr) {
                    err->SetWin32Error(ERROR_NOT_SUPPORTED, L"Platform not supported");
                }
                return false;
#endif
            }

            bool SecureRandom::Generate(std::vector<uint8_t>& out, size_t size, Error* err) noexcept {
                // Handle zero-size request
                if (size == 0) {
                    out.clear();
                    return true;
                }

                try {
                    out.resize(size);
                }
                catch (const std::exception&) {
                    out.clear();
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_NOT_ENOUGH_MEMORY,
                            L"Failed to allocate random buffer");
                    }
                    return false;
                }

                if (!Generate(out.data(), size, err)) {
                    SecureZeroMemory(out.data(), out.size());
                    out.clear();
                    return false;
                }

                return true;
            }

            std::vector<uint8_t> SecureRandom::Generate(size_t size, Error* err) noexcept {
                std::vector<uint8_t> out;
                if (!Generate(out, size, err)) {
                    return std::vector<uint8_t>();
                }
                return out;
            }

            uint32_t SecureRandom::NextUInt32(Error* err) noexcept {
                uint32_t val = 0;
                if (!Generate(reinterpret_cast<uint8_t*>(&val), sizeof(val), err)) {
                    return 0;
                }
                return val;
            }

            uint64_t SecureRandom::NextUInt64(Error* err) noexcept {
                uint64_t val = 0;
                if (!Generate(reinterpret_cast<uint8_t*>(&val), sizeof(val), err)) {
                    return 0;
                }
                return val;
            }

            uint32_t SecureRandom::NextUInt32(uint32_t min, uint32_t max, Error* err) noexcept {
                // Validate range
                if (min >= max) {
                    return min;
                }

                const uint32_t range = max - min;

                // Prevent division by zero (shouldn't happen given min < max check)
                if (range == 0) {
                    return min;
                }

                // Calculate rejection threshold to avoid modulo bias
                // We reject values >= limit to ensure uniform distribution
                const uint32_t limit = (UINT32_MAX / range) * range;

                uint32_t val = 0;
                uint32_t iterations = 0;

                do {
                    val = NextUInt32(err);
                    ++iterations;

                    // Safety limit to prevent infinite loop on RNG failure
                    if (iterations > MAX_REJECTION_ITERATIONS) {
                        if (err != nullptr) {
                            err->SetWin32Error(ERROR_TIMEOUT,
                                L"Random range generation exceeded iteration limit");
                        }
                        return min;
                    }
                } while (val >= limit);

                return min + (val % range);
            }

            uint64_t SecureRandom::NextUInt64(uint64_t min, uint64_t max, Error* err) noexcept {
                // Validate range
                if (min >= max) {
                    return min;
                }

                const uint64_t range = max - min;

                if (range == 0) {
                    return min;
                }

                // Calculate rejection threshold
                const uint64_t limit = (UINT64_MAX / range) * range;

                uint64_t val = 0;
                uint32_t iterations = 0;

                do {
                    val = NextUInt64(err);
                    ++iterations;

                    if (iterations > MAX_REJECTION_ITERATIONS) {
                        if (err != nullptr) {
                            err->SetWin32Error(ERROR_TIMEOUT,
                                L"Random range generation exceeded iteration limit");
                        }
                        return min;
                    }
                } while (val >= limit);

                return min + (val % range);
            }

            std::string SecureRandom::GenerateAlphanumeric(size_t length, Error* err) noexcept {
                // Character set for alphanumeric strings
                static constexpr char alphanum[] =
                    "0123456789"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz";
                static constexpr size_t alphaLen = sizeof(alphanum) - 1;  // Exclude null terminator

                if (length == 0) {
                    return std::string();
                }

                try {
                    std::string out;
                    out.reserve(length);

                    for (size_t i = 0; i < length; ++i) {
                        const uint32_t idx = NextUInt32(0, static_cast<uint32_t>(alphaLen), err);
                        out.push_back(alphanum[idx]);
                    }

                    return out;
                }
                catch (const std::exception&) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_NOT_ENOUGH_MEMORY,
                            L"Failed to allocate alphanumeric string");
                    }
                    return std::string();
                }
            }

            std::string SecureRandom::GenerateHex(size_t byteCount, Error* err) noexcept {
                if (byteCount == 0) {
                    return std::string();
                }

                std::vector<uint8_t> bytes;
                if (!Generate(bytes, byteCount, err)) {
                    return std::string();
                }

                try {
                    return HashUtils::ToHexLower(bytes.data(), bytes.size());
                }
                catch (const std::exception&) {
                    SecureZeroMemory(bytes.data(), bytes.size());
                    return std::string();
                }
            }

            std::string SecureRandom::GenerateBase64(size_t byteCount, Error* err) noexcept {
                if (byteCount == 0) {
                    return std::string();
                }

                std::vector<uint8_t> bytes;
                if (!Generate(bytes, byteCount, err)) {
                    return std::string();
                }

                std::string result = Base64::Encode(bytes);

                // Securely wipe the raw bytes
                SecureZeroMemory(bytes.data(), bytes.size());

                return result;
            }
		}
	}
}
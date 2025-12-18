#pragma once
#include"CryptoUtils.hpp"
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <cstdint>

// Forward declarations of enums
enum class SymmetricAlgorithm;
enum class AsymmetricAlgorithm;

namespace ShadowStrike {
    namespace Utils {
        namespace CryptoUtils {

       // =============================================================================
      // Internal Constants
      // =============================================================================

      /// Maximum iterations for rejection sampling to prevent infinite loops
           inline static constexpr uint32_t MAX_REJECTION_ITERATIONS = 1000UL;

            /// Log category for crypto operations
            inline static constexpr const wchar_t* LOG_CATEGORY = L"CryptoUtils";

            // Algorithm mapping helpers
            const wchar_t* AlgName(SymmetricAlgorithm alg) noexcept;
            const wchar_t* ChainingMode(SymmetricAlgorithm alg) noexcept;
            size_t KeySizeForAlg(SymmetricAlgorithm alg) noexcept;
            size_t IVSizeForAlg(SymmetricAlgorithm alg) noexcept;
            bool IsAEADAlg(SymmetricAlgorithm alg) noexcept;

            const wchar_t* RSAAlgName(AsymmetricAlgorithm alg) noexcept;
            unsigned long RSAKeySizeForAlg(AsymmetricAlgorithm alg) noexcept;
            bool IsRSAAlgorithm(AsymmetricAlgorithm alg) noexcept;
            bool IsECCAlgorithm(AsymmetricAlgorithm alg) noexcept;

            // Logging helpers
            void SafeLogError(const wchar_t* msg) noexcept;
            void SafeLogInfo(const wchar_t* msg) noexcept;

            // Base64 helpers
            namespace Base64 {
                std::string Encode(const uint8_t* data, size_t len) noexcept;
                std::string Encode(const std::vector<uint8_t>& data) noexcept;
                bool Decode(std::string_view base64, std::vector<uint8_t>& out) noexcept;
            }

            // Secure comparison
            bool SecureCompare(const uint8_t* a, const uint8_t* b, size_t len) noexcept;
            bool SecureCompare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) noexcept;

            // Secure memory wipe
            void SecureZeroMemory(void* ptr, size_t size) noexcept;
		}// namespace CryptoUtils
	}// namespace Utils
}// namespace ShadowStrike

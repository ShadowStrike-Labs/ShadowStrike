
#include"CryptoUtilsCommon.hpp"
#include"Base64Utils.hpp"
#include"Logger.hpp"

namespace ShadowStrike  {
    namespace Utils {
        namespace CryptoUtils {

            // =============================================================================
            // Helper Functions - Algorithm Mapping
            // =============================================================================

            /**
             * @brief Get CNG algorithm identifier for symmetric algorithm
             * @param alg Symmetric algorithm enum
             * @return CNG algorithm name or nullptr if invalid
             */
            const wchar_t* AlgName(SymmetricAlgorithm alg) noexcept {
                switch (alg) {
                case SymmetricAlgorithm::AES_128_CBC:
                case SymmetricAlgorithm::AES_192_CBC:
                case SymmetricAlgorithm::AES_256_CBC:
                case SymmetricAlgorithm::AES_128_GCM:
                case SymmetricAlgorithm::AES_192_GCM:
                case SymmetricAlgorithm::AES_256_GCM:
                case SymmetricAlgorithm::AES_128_CFB:
                case SymmetricAlgorithm::AES_192_CFB:
                case SymmetricAlgorithm::AES_256_CFB:
                    return BCRYPT_AES_ALGORITHM;
                case SymmetricAlgorithm::ChaCha20_Poly1305:
                    return L"ChaCha20-Poly1305";
                default:
                    return nullptr;
                }
            }

            /**
             * @brief Get CNG chaining mode for symmetric algorithm
             * @param alg Symmetric algorithm enum
             * @return CNG chaining mode or nullptr if not applicable
             */
            const wchar_t* ChainingMode(SymmetricAlgorithm alg) noexcept {
                switch (alg) {
                case SymmetricAlgorithm::AES_128_CBC:
                case SymmetricAlgorithm::AES_192_CBC:
                case SymmetricAlgorithm::AES_256_CBC:
                    return BCRYPT_CHAIN_MODE_CBC;
                case SymmetricAlgorithm::AES_128_GCM:
                case SymmetricAlgorithm::AES_192_GCM:
                case SymmetricAlgorithm::AES_256_GCM:
                    return BCRYPT_CHAIN_MODE_GCM;
                case SymmetricAlgorithm::AES_128_CFB:
                case SymmetricAlgorithm::AES_192_CFB:
                case SymmetricAlgorithm::AES_256_CFB:
                    return BCRYPT_CHAIN_MODE_CFB;
                default:
                    return nullptr;
                }
            }

            /**
             * @brief Get key size in bytes for symmetric algorithm
             * @param alg Symmetric algorithm enum
             * @return Key size in bytes, 0 if invalid
             */
            size_t KeySizeForAlg(SymmetricAlgorithm alg) noexcept {
                switch (alg) {
                case SymmetricAlgorithm::AES_128_CBC:
                case SymmetricAlgorithm::AES_128_GCM:
                case SymmetricAlgorithm::AES_128_CFB:
                    return 16ULL;  // 128 bits
                case SymmetricAlgorithm::AES_192_CBC:
                case SymmetricAlgorithm::AES_192_GCM:
                case SymmetricAlgorithm::AES_192_CFB:
                    return 24ULL;  // 192 bits
                case SymmetricAlgorithm::AES_256_CBC:
                case SymmetricAlgorithm::AES_256_GCM:
                case SymmetricAlgorithm::AES_256_CFB:
                case SymmetricAlgorithm::ChaCha20_Poly1305:
                    return 32ULL;  // 256 bits
                default:
                    return 0ULL;
                }
            }

            /**
             * @brief Get IV/nonce size in bytes for symmetric algorithm
             * @param alg Symmetric algorithm enum
             * @return IV size in bytes, 0 if invalid
             */
            size_t IVSizeForAlg(SymmetricAlgorithm alg) noexcept {
                switch (alg) {
                case SymmetricAlgorithm::AES_128_GCM:
                case SymmetricAlgorithm::AES_192_GCM:
                case SymmetricAlgorithm::AES_256_GCM:
                case SymmetricAlgorithm::ChaCha20_Poly1305:
                    return GCM_NONCE_SIZE_BYTES;  // 12 bytes (96-bit nonce)
                case SymmetricAlgorithm::AES_128_CBC:
                case SymmetricAlgorithm::AES_192_CBC:
                case SymmetricAlgorithm::AES_256_CBC:
                case SymmetricAlgorithm::AES_128_CFB:
                case SymmetricAlgorithm::AES_192_CFB:
                case SymmetricAlgorithm::AES_256_CFB:
                    return AES_BLOCK_SIZE_BYTES;  // 16 bytes
                default:
                    return 0ULL;
                }
            }

            /**
             * @brief Check if algorithm is an AEAD mode
             * @param alg Symmetric algorithm enum
             * @return true if AEAD (provides authenticated encryption)
             */
            bool IsAEADAlg(SymmetricAlgorithm alg) noexcept {
                switch (alg) {
                case SymmetricAlgorithm::AES_128_GCM:
                case SymmetricAlgorithm::AES_192_GCM:
                case SymmetricAlgorithm::AES_256_GCM:
                case SymmetricAlgorithm::ChaCha20_Poly1305:
                    return true;
                default:
                    return false;
                }
            }

            /**
             * @brief Get CNG algorithm identifier for asymmetric algorithm
             * @param alg Asymmetric algorithm enum
             * @return CNG algorithm name or nullptr if invalid
             */
            const wchar_t* RSAAlgName(AsymmetricAlgorithm alg) noexcept {
                switch (alg) {
                case AsymmetricAlgorithm::RSA_2048:
                case AsymmetricAlgorithm::RSA_3072:
                case AsymmetricAlgorithm::RSA_4096:
                    return BCRYPT_RSA_ALGORITHM;
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

            /**
             * @brief Get key size in bits for asymmetric algorithm
             * @param alg Asymmetric algorithm enum
             * @return Key size in bits, 0 if invalid
             */
            ULONG RSAKeySizeForAlg(AsymmetricAlgorithm alg) noexcept {
                switch (alg) {
                case AsymmetricAlgorithm::RSA_2048: return 2048UL;
                case AsymmetricAlgorithm::RSA_3072: return 3072UL;
                case AsymmetricAlgorithm::RSA_4096: return 4096UL;
                case AsymmetricAlgorithm::ECC_P256: return 256UL;
                case AsymmetricAlgorithm::ECC_P384: return 384UL;
                case AsymmetricAlgorithm::ECC_P521: return 521UL;
                default: return 0UL;
                }
            }

            /**
             * @brief Check if algorithm is RSA-based
             * @param alg Asymmetric algorithm enum
             * @return true if RSA algorithm
             */
            [[maybe_unused]] static bool IsRSAAlgorithm(AsymmetricAlgorithm alg) noexcept {
                switch (alg) {
                case AsymmetricAlgorithm::RSA_2048:
                case AsymmetricAlgorithm::RSA_3072:
                case AsymmetricAlgorithm::RSA_4096:
                    return true;
                default:
                    return false;
                }
            }

            /**
             * @brief Check if algorithm is ECC-based
             * @param alg Asymmetric algorithm enum
             * @return true if ECC algorithm
             */
            [[maybe_unused]] static bool IsECCAlgorithm(AsymmetricAlgorithm alg) noexcept {
                switch (alg) {
                case AsymmetricAlgorithm::ECC_P256:
                case AsymmetricAlgorithm::ECC_P384:
                case AsymmetricAlgorithm::ECC_P521:
                    return true;
                default:
                    return false;
                }
            }

            /**
             * @brief Safe logging helper - logs to debug output if Logger not initialized
             * @param msg Message to log
             */
            void SafeLogError(const wchar_t* msg) noexcept {
                if (msg == nullptr) return;

                try {
                    if (Logger::Instance().IsInitialized()) {
                        SS_LOG_ERROR(LOG_CATEGORY, L"%s", msg);
                    }
                    else {
                        OutputDebugStringW(L"[CryptoUtils] ");
                        OutputDebugStringW(msg);
                        OutputDebugStringW(L"\n");
                    }
                }
                catch (...) {
                    // Logging should never throw - silently ignore
                }
            }

            /**
             * @brief Safe logging helper for info messages
             * @param msg Message to log
             */
            void SafeLogInfo(const wchar_t* msg) noexcept {
                if (msg == nullptr) return;

                try {
                    if (Logger::Instance().IsInitialized()) {
                        SS_LOG_INFO(LOG_CATEGORY, L"%s", msg);
                    }
                    else {
                        OutputDebugStringW(L"[CryptoUtils] ");
                        OutputDebugStringW(msg);
                        OutputDebugStringW(L"\n");
                    }
                }
                catch (...) {
                    // Logging should never throw - silently ignore
                }
            }

            // =============================================================================
            // Base64 Helpers
            // =============================================================================

            namespace Base64 {

                std::string Encode(const uint8_t* data, size_t len) noexcept {
                    // Handle edge cases
                    if (data == nullptr && len != 0) {
                        return std::string();
                    }
                    if (len == 0) {
                        return std::string();
                    }

                    try {
                        std::string out;
                        Utils::Base64EncodeOptions opt{};
                        const bool ok = Utils::Base64Encode(data, len, out, opt);
                        if (!ok) {
                            out.clear();
                        }
                        return out;
                    }
                    catch (const std::exception&) {
                        return std::string();
                    }
                }

                std::string Encode(const std::vector<uint8_t>& data) noexcept {
                    if (data.empty()) {
                        return std::string();
                    }
                    return Encode(data.data(), data.size());
                }

                bool Decode(std::string_view base64, std::vector<uint8_t>& out) noexcept {
                    out.clear();

                    if (base64.empty()) {
                        return true;  // Empty input is valid
                    }

                    try {
                        Utils::Base64DecodeError derr = Utils::Base64DecodeError::None;
                        Utils::Base64DecodeOptions opt{};
                        return Utils::Base64Decode(base64, out, derr, opt);
                    }
                    catch (const std::exception&) {
                        out.clear();
                        return false;
                    }
                }

            } // namespace Base64

            // =============================================================================
            // Secure Comparison (Constant-Time)
            // =============================================================================

            bool SecureCompare(const uint8_t* a, const uint8_t* b, size_t len) noexcept {
                // Handle pointer equality (same buffer)
                if (a == b) {
                    return true;
                }

                // Null pointer check (both must be valid unless len is 0)
                if (len == 0) {
                    return true;
                }
                if (a == nullptr || b == nullptr) {
                    return false;
                }

                // Constant-time comparison to prevent timing attacks
                // Uses volatile to prevent compiler optimization
                volatile unsigned char accumulator = 0;

                for (size_t i = 0; i < len; ++i) {
                    accumulator |= static_cast<unsigned char>(a[i] ^ b[i]);
                }

                // Return true only if no differences found
                return accumulator == 0;
            }

            bool SecureCompare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) noexcept {
                // Size comparison must be done in constant time to prevent length oracle
                // However, if sizes differ, result is always false
                if (a.size() != b.size()) {
                    return false;
                }

                if (a.empty()) {
                    return true;  // Both empty
                }

                return SecureCompare(a.data(), b.data(), a.size());
            }

            // =============================================================================
            // Secure Memory Wipe
            // =============================================================================

            void SecureZeroMemory(void* ptr, size_t size) noexcept {
                if (ptr == nullptr || size == 0) {
                    return;
                }

#ifdef _WIN32
                // Windows: Use RtlSecureZeroMemory which is guaranteed not to be optimized away
                ::RtlSecureZeroMemory(ptr, size);
#else
                // Non-Windows: Use volatile pointer to prevent optimization
                volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
                while (size > 0) {
                    *p++ = 0;
                    --size;
                }
                // Memory barrier to ensure writes complete
                std::atomic_thread_fence(std::memory_order_seq_cst);
#endif
            }

		}// namespace CryptoUtils
	}// namespace ShadowStrike
}// namespace Utils
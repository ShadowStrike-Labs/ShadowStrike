/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include "../Common/Types.hpp"
#include "../Common/Config.hpp"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace Phantom {

// Forward declarations
class VirtualMemory;

// ============================================================================
// Cryptographic Algorithm Classification
// ============================================================================

enum class CryptoAlgorithm : uint8_t {
    Unknown,
    AES,
    AES_Inv,
    RC4,
    XOR_Single,
    XOR_Multi,
    RSA,
    DES,
    TripleDES,
    ChaCha20,
    Salsa20,
    Blowfish,
    Twofish,
    Serpent,
    CRC32,
    MD5,
    SHA1,
    SHA256,
    SHA512,
    ECC,
    Base64,
    Base32,
    HexEncoding,
    APIHashing,
    StackString,
    JunkCode,
    RansomwarePattern,
    CustomSymmetric,
    CustomHash,
    CustomStream,
};

// ============================================================================
// Crypto Finding Record
// ============================================================================

struct CryptoFinding {
    CryptoAlgorithm         algorithm     = CryptoAlgorithm::Unknown;
    GuestAddress            address       = 0;   // Where the crypto artefact was found
    GuestSize               size          = 0;   // Artefact size in bytes
    float                   confidence    = 0.0f; // 0.0 – 1.0
    std::string             description;
    std::vector<uint8_t>    keyMaterial;          // Extracted key (max 256 bytes)
    bool                    isEncryption  = false;
};

// ============================================================================
// Aggregate Statistics
// ============================================================================

struct CryptoStats {
    uint32_t totalFindings           = 0;
    uint32_t encryptionCount         = 0;
    uint32_t decryptionCount         = 0;
    bool     hasRansomwareIndicator  = false; // AES + RSA + file enumeration
    bool     hasC2Encryption         = false; // Symmetric + network activity
    bool     hasObfuscationIndicator = false; // API hashing + stack strings + junk code
    bool     hasEncodingIndicator    = false; // Base64/Base32/Hex encoding detected
    bool     hasECCKeyExchange       = false; // Elliptic curve constants detected
    uint32_t perFileKeyGenCount      = 0;     // CryptGenRandom calls tracked
    std::vector<CryptoAlgorithm> algorithmsFound;
};

// ============================================================================
// Crypto Detector
// ============================================================================
// Detects cryptographic operations during emulation — critical for ransomware
// detection, encrypted C2 identification, and payload decryption analysis.
//
// Thread-safe: designed for single-threaded analysis pass.

class CryptoDetector {
public:
    explicit CryptoDetector(const EmulationConfig& config) noexcept;
    ~CryptoDetector() noexcept;

    CryptoDetector(const CryptoDetector&) = delete;
    CryptoDetector& operator=(const CryptoDetector&) = delete;
    CryptoDetector(CryptoDetector&&) noexcept;
    CryptoDetector& operator=(CryptoDetector&&) noexcept;

    // Scan a memory region for crypto artefacts
    void ScanRegion(const uint8_t* data, size_t size, GuestAddress base) noexcept;

    // Scan entire guest memory
    void ScanAll(const VirtualMemory& memory) noexcept;

    // Track XOR operations during emulation
    void OnXOROperation(GuestAddress rip, uint8_t key,
                        GuestAddress dataAddr, uint32_t size) noexcept;

    // Track WinCrypt / BCrypt API calls
    void OnCryptoAPICall(const char* funcName, const uint64_t* args) noexcept;

    // --- Results ---

    [[nodiscard]] const std::vector<CryptoFinding>& GetFindings() const noexcept;
    [[nodiscard]] CryptoStats GetStats() const noexcept;
    [[nodiscard]] std::vector<const CryptoFinding*> GetByAlgorithm(CryptoAlgorithm algo) const noexcept;

    void Reset() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace Phantom

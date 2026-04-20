/*
 * ShadowStrike - Enterprise NGAV Platform
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */

/**
 * @file IPCFrameFuzz.cpp
 * @brief Fuzz smoke driver for the PhantomHome UI IPC frame + payload decoders.
 *
 * The PipeServer runs as LocalSystem and receives CBOR-encoded envelopes from
 * interactive clients; the first line of defence against a compromised or
 * malicious client is the frame decoder (`DecodeEnvelopeCbor`) and every
 * `FromJson` payload parser reachable from `IPCRouter::Dispatch`. Any input
 * that drives any of those paths into a crash, UB, or unbounded allocation is
 * a service-wide DoS at minimum.
 *
 * This driver ships two complementary harnesses in one TU:
 *
 *   1. A `LLVMFuzzerTestOneInput` entry point with the exact libFuzzer ABI,
 *      so the file can be linked against libFuzzer, afl++, or any other
 *      sanitizer-aware engine without modification.
 *
 *   2. A self-contained `wmain()` that drives the harness against:
 *        - a hand-crafted hostile corpus designed to exercise every known
 *          rejection path (bad CBOR, oversize frame, missing field, wrong
 *          type, integer out-of-range, oversize string, deep nesting),
 *        - a deterministic PRNG-driven mutator that flips bits on a valid
 *          baseline envelope a configurable number of rounds.
 *
 *      The standalone run is usable today as a compile-verifiable smoke test
 *      and will be wired into CI once a dedicated test vcxproj lands.
 *
 * The driver NEVER rethrows - any std::exception is caught, counted, and
 * logged so one bad frame cannot abort the run.
 *
 * Build (standalone):
 *   cl /EHa /std:c++20 /Zc:__cplusplus /DUNICODE /D_UNICODE /DNOMINMAX /DWIN32_LEAN_AND_MEAN
 *      /I include /I include\YARA /I src
 *      tests\integration\ui_ipc_fuzz\IPCFrameFuzz.cpp
 *      /link /out:ipc_frame_fuzz.exe
 *
 * Build (libFuzzer):
 *   clang-cl /fsanitize=fuzzer,address /std:c++20 ... IPCFrameFuzz.cpp
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "../../../src/Products/Community/PhantomHome/UI/IPC/Messages.hpp"

namespace SSIPC = ShadowStrike::PhantomHome::IPC;

namespace {

// --- Statistics -----------------------------------------------------------

struct FuzzStats {
    std::uint64_t inputs{0};
    std::uint64_t decoder_accepts{0};
    std::uint64_t decoder_rejects{0};
    std::uint64_t payload_accepts{0};
    std::uint64_t payload_rejects{0};
    std::uint64_t exceptions{0};
};

FuzzStats g_stats{};

// Try every FromJson payload parser on a decoded envelope's payload. If any
// FromJson throws, the exception is counted and swallowed.
void ExercisePayloadParsers(const SSIPC::FrameEnvelope& env) {
    try {
        if (SSIPC::Hello::FromJson(env.payload))        ++g_stats.payload_accepts; else ++g_stats.payload_rejects;
        if (SSIPC::HelloOk::FromJson(env.payload))      ++g_stats.payload_accepts; else ++g_stats.payload_rejects;
        if (SSIPC::ErrorPayload::FromJson(env.payload)) ++g_stats.payload_accepts; else ++g_stats.payload_rejects;
    } catch (const std::exception&) {
        ++g_stats.exceptions;
    } catch (...) {
        ++g_stats.exceptions;
    }
}

// Core harness: feed bytes to DecodeEnvelopeCbor, then run every payload
// parser on the decoded json. Never throws.
void FuzzOne(std::span<const std::uint8_t> input) noexcept {
    ++g_stats.inputs;

    try {
        auto env = SSIPC::DecodeEnvelopeCbor(input);
        if (!env) {
            ++g_stats.decoder_rejects;
            return;
        }
        ++g_stats.decoder_accepts;

        // Basic decoder-contract sanity check on accepted envelopes.
        if (env->version == 0) {
            std::fprintf(stderr, "[ipc-fuzz] contract: version=0 accepted\n");
        }

        ExercisePayloadParsers(*env);
    } catch (const std::exception& e) {
        ++g_stats.exceptions;
        std::fprintf(stderr, "[ipc-fuzz] std::exception: %s\n", e.what());
    } catch (...) {
        ++g_stats.exceptions;
        std::fprintf(stderr, "[ipc-fuzz] unknown exception\n");
    }
}

// --- Hand-crafted hostile corpus -----------------------------------------
//
// Each entry exercises a specific decoder or parser rejection path. Contract:
// the harness MUST NOT crash on any of them. Whether the frame is accepted
// or rejected is not asserted here (memory safety, not schema correctness).

std::vector<std::vector<std::uint8_t>> HostileCorpus() {
    std::vector<std::vector<std::uint8_t>> out;

    // 1) Empty frame.
    out.push_back({});
    // 2) Single zero byte - not a valid CBOR envelope map.
    out.push_back({0x00});
    // 3) CBOR with unterminated indefinite-length map.
    out.push_back({0xBF, 0x63, 'f', 'o', 'o'});
    // 4) CBOR with a string claiming 2^32 bytes.
    out.push_back({0x7A, 0xFF, 0xFF, 0xFF, 0xFF});
    // 5) CBOR with a 64-bit length header claiming a huge value.
    out.push_back({0x7B, 0x80, 0, 0, 0, 0, 0, 0, 0});
    // 6) CBOR with nested map depth well past anything the schema needs.
    {
        std::vector<std::uint8_t> deep;
        for (int i = 0; i < 512; ++i) deep.push_back(0xA1); // map(1)
        for (int i = 0; i < 512; ++i) deep.push_back(0x60); // empty text
        out.push_back(std::move(deep));
    }
    // 7) CBOR bignum tag (tag 2 + oversize bytestring).
    out.push_back({0xC2, 0x5A, 0x00, 0x10, 0x00, 0x00});
    // 8) CBOR float value where the schema wants a uint.
    out.push_back({0xA1, 0x61, 'v', 0xFA, 0x40, 0x49, 0x0F, 0xDB});
    // 9) Valid CBOR map with garbage keys only.
    out.push_back({0xA2, 0x63, 'x', 'y', 'z', 0x01, 0x63, 'w', 'w', 'w', 0x02});
    // 10) All 0xFF bytes - hits CBOR break marker + invalid major types.
    out.push_back(std::vector<std::uint8_t>(128, 0xFF));
    // 11) Oversize by construction (cap + 1) - decoder must reject.
    out.push_back(std::vector<std::uint8_t>(
        static_cast<std::size_t>(SSIPC::kMaxFrameBytes) + 1, 0x00));

    return out;
}

// --- Baseline envelope + bit-flip mutator --------------------------------

std::vector<std::uint8_t> BaselineHello() {
    SSIPC::FrameEnvelope env;
    env.version        = SSIPC::kProtocolVersion;
    env.type           = SSIPC::MessageType::Hello;
    env.correlation_id = 42;
    SSIPC::Hello h;
    h.client_version = SSIPC::kProtocolVersion;
    h.client_build   = "fuzz-smoke";
    h.session_id     = 1;
    env.payload      = h.ToJson();
    return SSIPC::EncodeEnvelopeCbor(env);
}

void BitflipCampaign(std::uint64_t rounds, std::uint32_t seed) {
    auto baseline = BaselineHello();
    if (baseline.empty()) return;

    std::mt19937 rng(seed);
    std::uniform_int_distribution<std::size_t> pos(0, baseline.size() - 1);
    std::uniform_int_distribution<int>         nbits(1, 8);

    for (std::uint64_t i = 0; i < rounds; ++i) {
        auto mutated = baseline;
        const int flips = nbits(rng);
        for (int k = 0; k < flips; ++k) {
            const auto p = pos(rng);
            mutated[p] = static_cast<std::uint8_t>(
                mutated[p] ^ (1u << (rng() & 7u)));
        }
        FuzzOne(std::span<const std::uint8_t>(mutated));
    }
}

}  // namespace

// --- libFuzzer ABI --------------------------------------------------------
//
// Exposed as extern "C" so any libFuzzer-style driver can link against this
// TU directly. Safe against nullptr / zero-size via the span constructor.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (!data && size != 0) return 0;
    FuzzOne(std::span<const std::uint8_t>(data, size));
    return 0;
}

// --- Standalone driver ---------------------------------------------------

int wmain(int argc, wchar_t** argv) {
    std::uint64_t rounds = 4096;
    std::uint32_t seed   = 0xC0FFEEu;
    if (argc >= 2) rounds = std::wcstoull(argv[1], nullptr, 10);
    if (argc >= 3) seed   = static_cast<std::uint32_t>(std::wcstoul(argv[2], nullptr, 10));

    std::puts("[ipc-fuzz] hand-crafted hostile corpus");
    for (const auto& frame : HostileCorpus()) {
        FuzzOne(std::span<const std::uint8_t>(frame));
    }

    std::printf("[ipc-fuzz] bit-flip campaign: rounds=%llu seed=0x%08X\n",
                static_cast<unsigned long long>(rounds),
                static_cast<unsigned>(seed));
    BitflipCampaign(rounds, seed);

    std::printf("[ipc-fuzz] summary: inputs=%llu decoder_ok=%llu decoder_rej=%llu "
                "payload_ok=%llu payload_rej=%llu exceptions=%llu\n",
                static_cast<unsigned long long>(g_stats.inputs),
                static_cast<unsigned long long>(g_stats.decoder_accepts),
                static_cast<unsigned long long>(g_stats.decoder_rejects),
                static_cast<unsigned long long>(g_stats.payload_accepts),
                static_cast<unsigned long long>(g_stats.payload_rejects),
                static_cast<unsigned long long>(g_stats.exceptions));

    return 0;
}

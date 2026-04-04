/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * DnsAPI.cpp — Ws2_32 DNS and address-conversion implementations
 *
 * DNS resolution is one of the most critical IOCs in malware analysis.
 * Every hostname queried by the sample is captured as a potential C2
 * domain. We return a fake resolution (10.0.0.1) to allow the malware
 * to proceed with its connection sequence so we can observe the full
 * network behavior chain.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "DnsAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <string>

namespace Phantom::WinAPI::Ws2_32 {

// ============================================================================
// Internal constants
// ============================================================================

static constexpr uint16_t kAF_INET          = 2;
static constexpr uint32_t kMaxHostnameLen   = 256;
static constexpr uint32_t kMaxAddrStringLen = 64;

// Fake IP returned for all DNS resolutions: 10.0.0.1
static constexpr uint8_t  kFakeIP[4]        = { 10, 0, 0, 1 };
static constexpr uint32_t kFakeIPNet        = 0x0100000A; // 10.0.0.1 in network byte order

// Guest memory region for static hostent / inet_ntoa buffers.
// We allocate a small scratch area in guest memory to hold returned structures
// that the guest may reference. Address chosen in high userspace.
static GuestAddress s_scratchBase   = 0;
static constexpr GuestSize kScratchSize = 4096;
static GuestAddress s_scratchOffset = 0;

// ============================================================================
// Helpers
// ============================================================================

static GuestAddress AllocScratch(VirtualMemory& mem, uint32_t size) noexcept {
    if (s_scratchBase == 0) {
        auto result = mem.Allocate(0x7FFE0000, kScratchSize, MemProt::RW);
        if (!result.has_value()) {
            result = mem.Allocate(0, kScratchSize, MemProt::RW);
        }
        if (!result.has_value()) return 0;
        s_scratchBase = result.value();
        s_scratchOffset = 0;
    }

    if (s_scratchOffset + size > kScratchSize) {
        // Wrap — reuse from beginning (static-lifetime buffers are overwritten)
        s_scratchOffset = 0;
    }

    GuestAddress addr = s_scratchBase + s_scratchOffset;
    s_scratchOffset += AlignUp(size, 8);
    return addr;
}

// ============================================================================
// gethostbyname — name(0)
// ============================================================================
// CRITICAL IOC: Every DNS lookup reveals a potential C2 domain.
// We build a fake hostent in guest memory and return a pointer to it.
//
// struct hostent {
//   char*  h_name;        // +0 (ptr)
//   char** h_aliases;     // +ptr_size
//   short  h_addrtype;    // +2*ptr_size
//   short  h_length;      // +2*ptr_size+2
//   char** h_addr_list;   // +2*ptr_size+4 (padded to ptr align)
// };

bool HandleGethostbyname(APIContext& ctx) {
    const auto namePtr = ctx.GetArgPtr(0);
    if (namePtr == 0) {
        ctx.SetReturn(0);
        return true;
    }

    const std::string hostname = ctx.ReadAnsiString(namePtr, kMaxHostnameLen);
    if (hostname.empty()) {
        ctx.SetReturn(0);
        return true;
    }

    auto& mem = ctx.Memory();
    const bool is64 = ctx.Is64Bit();
    const uint32_t ptrSize = is64 ? 8 : 4;

    // Layout in scratch memory:
    // [hostname string] [null alias list] [addr 10.0.0.1] [addr_list ptr, null]
    // [hostent struct]
    const uint32_t hostnameAlloc = static_cast<uint32_t>(hostname.size()) + 1;
    const uint32_t addrSize      = 4; // IPv4
    const uint32_t addrListSize  = ptrSize * 2; // one addr ptr + null terminator
    const uint32_t aliasListSize = ptrSize;     // null terminator only
    const uint32_t hostentSize   = ptrSize * 3 + 4; // h_name, h_aliases, h_addr_list + addrtype/length
    const uint32_t totalSize     = AlignUp(hostnameAlloc, 8)
                                 + AlignUp(aliasListSize, 8)
                                 + AlignUp(addrSize, 8)
                                 + AlignUp(addrListSize, 8)
                                 + AlignUp(hostentSize, 8);

    GuestAddress base = AllocScratch(mem, totalSize);
    if (base == 0) {
        ctx.SetReturn(0);
        return true;
    }

    GuestAddress cur = base;

    // Write hostname string
    const GuestAddress hNameAddr = cur;
    mem.Write(cur, hostname.c_str(), hostnameAlloc);
    cur += AlignUp(hostnameAlloc, 8);

    // Write empty alias list (just a null pointer)
    const GuestAddress aliasAddr = cur;
    const uint64_t zero = 0;
    mem.Write(cur, &zero, ptrSize);
    cur += AlignUp(aliasListSize, 8);

    // Write the fake IP address bytes
    const GuestAddress ipAddr = cur;
    mem.Write(cur, kFakeIP, addrSize);
    cur += AlignUp(addrSize, 8);

    // Write addr_list: pointer to ipAddr, then null
    const GuestAddress addrListAddr = cur;
    if (is64) {
        mem.WriteU64(cur, ipAddr);
        mem.WriteU64(cur + ptrSize, 0);
    } else {
        mem.WriteU32(cur, static_cast<uint32_t>(ipAddr));
        mem.WriteU32(cur + ptrSize, 0);
    }
    cur += AlignUp(addrListSize, 8);

    // Write hostent struct
    const GuestAddress hostentAddr = cur;
    if (is64) {
        mem.WriteU64(hostentAddr, hNameAddr);                     // h_name
        mem.WriteU64(hostentAddr + 8, aliasAddr);                 // h_aliases
        mem.WriteU16(hostentAddr + 16, kAF_INET);                // h_addrtype
        mem.WriteU16(hostentAddr + 18, 4);                        // h_length
        // Pad to 8-byte alignment for h_addr_list
        mem.WriteU64(hostentAddr + 24, addrListAddr);             // h_addr_list
    } else {
        mem.WriteU32(hostentAddr, static_cast<uint32_t>(hNameAddr));
        mem.WriteU32(hostentAddr + 4, static_cast<uint32_t>(aliasAddr));
        mem.WriteU16(hostentAddr + 8, kAF_INET);
        mem.WriteU16(hostentAddr + 10, 4);
        mem.WriteU32(hostentAddr + 12, static_cast<uint32_t>(addrListAddr));
    }

    ctx.SetReturn(hostentAddr);
    return true;
}

// ============================================================================
// gethostname — name(0), namelen(1)
// ============================================================================

bool HandleGethostname(APIContext& ctx) {
    const auto namePtr = ctx.GetArgPtr(0);
    const auto nameLen = ctx.GetArg32(1);

    if (namePtr == 0 || nameLen == 0) {
        ctx.SetReturn32(static_cast<uint32_t>(-1));
        return true;
    }

    // Convert wide computerName from config to narrow
    const auto& wname = ctx.Config().computerName;
    std::string narrow;
    narrow.reserve(wname.size());
    for (wchar_t wc : wname) {
        narrow.push_back(static_cast<char>(wc & 0x7F));
    }

    const uint32_t copyLen = std::min(static_cast<uint32_t>(narrow.size() + 1), nameLen);
    ctx.WriteAnsiString(namePtr, std::string_view(narrow.data(), narrow.size()), copyLen);

    ctx.SetReturn32(0);
    return true;
}

// ============================================================================
// getaddrinfo — pNodeName(0), pServiceName(1), pHints(2), ppResult(3)
// ============================================================================
// Similar to gethostbyname but returns an addrinfo linked list.
//
// struct addrinfo {
//   int    ai_flags;      // +0
//   int    ai_family;     // +4
//   int    ai_socktype;   // +8
//   int    ai_protocol;   // +12
//   size_t ai_addrlen;    // +16 (4 or 8 depending on arch)
//   char*  ai_canonname;  // +16+ptr_size (or +20 on x86)
//   struct sockaddr* ai_addr;
//   struct addrinfo* ai_next;
// };

bool HandleGetaddrinfo(APIContext& ctx) {
    const auto pNodeName    = ctx.GetArgPtr(0);
    const auto pServiceName = ctx.GetArgPtr(1);
    // pHints(2) — ignored for emulation purposes
    const auto ppResult     = ctx.GetArgPtr(3);

    if (ppResult == 0) {
        ctx.SetReturn32(static_cast<uint32_t>(-1));
        return true;
    }

    std::string hostname;
    if (pNodeName != 0) {
        hostname = ctx.ReadAnsiString(pNodeName, kMaxHostnameLen);
    }

    (void)pServiceName;

    auto& mem = ctx.Memory();
    const bool is64 = ctx.Is64Bit();
    const uint32_t ptrSize = is64 ? 8 : 4;

    // Layout: [sockaddr_in(16)] [addrinfo struct]
    // addrinfo x64: 4+4+4+4 + 8(addrlen) + 8(canonname) + 8(addr) + 8(next) = 48
    // addrinfo x86: 4+4+4+4 + 4(addrlen) + 4(canonname) + 4(addr) + 4(next) = 32
    const uint32_t addrinfoSize = is64 ? 48 : 32;
    const uint32_t totalSize = AlignUp(16, 8) + AlignUp(addrinfoSize, 8);

    GuestAddress base = AllocScratch(mem, totalSize);
    if (base == 0) {
        if (is64) mem.WriteU64(ppResult, 0);
        else      mem.WriteU32(ppResult, 0);
        ctx.SetReturn32(static_cast<uint32_t>(-1));
        return true;
    }

    GuestAddress cur = base;

    // Write sockaddr_in
    const GuestAddress saAddr = cur;
    std::array<uint8_t, 16> sa{};
    sa[0] = kAF_INET & 0xFF;
    sa[1] = (kAF_INET >> 8) & 0xFF;
    sa[2] = 0; sa[3] = 80; // port 80 in network byte order (0x0050)
    sa[4] = kFakeIP[0]; sa[5] = kFakeIP[1]; sa[6] = kFakeIP[2]; sa[7] = kFakeIP[3];
    mem.Write(cur, sa.data(), 16);
    cur += AlignUp(16, 8);

    // Write addrinfo struct
    const GuestAddress aiAddr = cur;
    if (is64) {
        mem.WriteU32(aiAddr + 0, 0);              // ai_flags
        mem.WriteU32(aiAddr + 4, kAF_INET);       // ai_family
        mem.WriteU32(aiAddr + 8, 1);              // ai_socktype (SOCK_STREAM)
        mem.WriteU32(aiAddr + 12, 6);             // ai_protocol (IPPROTO_TCP)
        mem.WriteU64(aiAddr + 16, 16);            // ai_addrlen
        mem.WriteU64(aiAddr + 24, 0);             // ai_canonname (null)
        mem.WriteU64(aiAddr + 32, saAddr);        // ai_addr
        mem.WriteU64(aiAddr + 40, 0);             // ai_next (null — single entry)
    } else {
        mem.WriteU32(aiAddr + 0, 0);
        mem.WriteU32(aiAddr + 4, kAF_INET);
        mem.WriteU32(aiAddr + 8, 1);
        mem.WriteU32(aiAddr + 12, 6);
        mem.WriteU32(aiAddr + 16, 16);                            // ai_addrlen
        mem.WriteU32(aiAddr + 20, 0);                             // ai_canonname
        mem.WriteU32(aiAddr + 24, static_cast<uint32_t>(saAddr)); // ai_addr
        mem.WriteU32(aiAddr + 28, 0);                             // ai_next
    }

    // Write result pointer
    if (is64) mem.WriteU64(ppResult, aiAddr);
    else      mem.WriteU32(ppResult, static_cast<uint32_t>(aiAddr));

    ctx.SetReturn32(0);
    return true;
}

// ============================================================================
// freeaddrinfo — pAddrInfo(0)
// ============================================================================

bool HandleFreeaddrinfo(APIContext& ctx) {
    // No-op: scratch memory is reused, not individually freed
    (void)ctx;
    ctx.SetReturn32(0);
    return true;
}

// ============================================================================
// inet_ntoa — in_addr(0) — 4-byte value, NOT a pointer
// ============================================================================

bool HandleInet_ntoa(APIContext& ctx) {
    const auto inAddr = ctx.GetArg32(0);

    const uint8_t a = static_cast<uint8_t>(inAddr & 0xFF);
    const uint8_t b = static_cast<uint8_t>((inAddr >> 8) & 0xFF);
    const uint8_t c = static_cast<uint8_t>((inAddr >> 16) & 0xFF);
    const uint8_t d = static_cast<uint8_t>((inAddr >> 24) & 0xFF);

    std::string ipStr = std::to_string(a) + "." + std::to_string(b) + "."
                      + std::to_string(c) + "." + std::to_string(d);

    auto& mem = ctx.Memory();
    const uint32_t strLen = static_cast<uint32_t>(ipStr.size()) + 1;
    GuestAddress buf = AllocScratch(mem, strLen);
    if (buf == 0) {
        ctx.SetReturn(0);
        return true;
    }

    mem.Write(buf, ipStr.c_str(), strLen);
    ctx.SetReturn(buf);
    return true;
}

// ============================================================================
// inet_addr — cp(0) — parse "x.x.x.x" string, return in_addr
// ============================================================================

bool HandleInet_addr(APIContext& ctx) {
    const auto cpPtr = ctx.GetArgPtr(0);
    if (cpPtr == 0) {
        ctx.SetReturn32(0xFFFFFFFF); // INADDR_NONE
        return true;
    }

    const std::string ipStr = ctx.ReadAnsiString(cpPtr, kMaxAddrStringLen);
    if (ipStr.empty()) {
        ctx.SetReturn32(0xFFFFFFFF);
        return true;
    }

    // Parse dotted-quad manually (no strtok, no platform APIs)
    uint32_t parts[4] = {};
    uint32_t partIdx = 0;
    uint32_t current = 0;
    bool hasDigit = false;

    for (char ch : ipStr) {
        if (ch >= '0' && ch <= '9') {
            current = current * 10 + static_cast<uint32_t>(ch - '0');
            if (current > 255) {
                ctx.SetReturn32(0xFFFFFFFF);
                return true;
            }
            hasDigit = true;
        } else if (ch == '.') {
            if (!hasDigit || partIdx >= 3) {
                ctx.SetReturn32(0xFFFFFFFF);
                return true;
            }
            parts[partIdx++] = current;
            current = 0;
            hasDigit = false;
        } else {
            break; // Stop at first non-IP character
        }
    }

    if (!hasDigit || partIdx != 3) {
        ctx.SetReturn32(0xFFFFFFFF);
        return true;
    }
    parts[3] = current;

    // Network byte order: a.b.c.d → bytes [a][b][c][d] → little-endian uint32
    const uint32_t result = parts[0] | (parts[1] << 8) | (parts[2] << 16) | (parts[3] << 24);
    ctx.SetReturn32(result);
    return true;
}

// ============================================================================
// htons — hostshort(0)
// ============================================================================

bool HandleHtons(APIContext& ctx) {
    const auto val = static_cast<uint16_t>(ctx.GetArg32(0));
    const uint16_t result = static_cast<uint16_t>((val >> 8) | (val << 8));
    ctx.SetReturn32(result);
    return true;
}

// ============================================================================
// htonl — hostlong(0)
// ============================================================================

bool HandleHtonl(APIContext& ctx) {
    const auto val = ctx.GetArg32(0);
    const uint32_t result = ((val & 0xFF000000u) >> 24)
                          | ((val & 0x00FF0000u) >> 8)
                          | ((val & 0x0000FF00u) << 8)
                          | ((val & 0x000000FFu) << 24);
    ctx.SetReturn32(result);
    return true;
}

// ============================================================================
// ntohs — netshort(0)
// ============================================================================

bool HandleNtohs(APIContext& ctx) {
    // ntohs is identical to htons on little-endian
    return HandleHtons(ctx);
}

// ============================================================================
// ntohl — netlong(0)
// ============================================================================

bool HandleNtohl(APIContext& ctx) {
    // ntohl is identical to htonl on little-endian
    return HandleHtonl(ctx);
}

// ============================================================================
// Registration
// ============================================================================

void RegisterDnsAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "ws2_32.dll", "gethostbyname",
          HandleGethostbyname, 1, true },
        { "ws2_32.dll", "gethostname",
          HandleGethostname, 2, false },
        { "ws2_32.dll", "getaddrinfo",
          HandleGetaddrinfo, 4, true },
        { "ws2_32.dll", "freeaddrinfo",
          HandleFreeaddrinfo, 1, false },
        { "ws2_32.dll", "inet_ntoa",
          HandleInet_ntoa, 1, false },
        { "ws2_32.dll", "inet_addr",
          HandleInet_addr, 1, false },
        { "ws2_32.dll", "htons",
          HandleHtons, 1, false },
        { "ws2_32.dll", "htonl",
          HandleHtonl, 1, false },
        { "ws2_32.dll", "ntohs",
          HandleNtohs, 1, false },
        { "ws2_32.dll", "ntohl",
          HandleNtohl, 1, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Ws2_32

// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * ShadowStrike Phantom - PhantomEmulator API dispatcher tests
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 */

/**
 * @file APIDispatcher_Tests.cpp
 * @brief Pins which Windows API handler sets the emulator can reach, and that each survives hostile input.
 *
 * APIDispatcher::RegisterAll used to call empty bodies for kernel32, advapi32, ws2_32, wininet, winhttp,
 * user32, shell32 and urlmon, so 37 of the 47 handler sets the emulator ships were never registered and
 * an emulated sample's calls into those DLLs reached no handler (task 351).
 *
 * Wiring them puts every handler on the path of guest-controlled input, and the emulator runs inside the
 * service. So the last case dispatches every registered API with hostile arguments - null, small integers,
 * all-ones, pointers into mapped and unmapped guest memory - and requires each call to return to its
 * caller without taking the host process down.
 */

#include <gtest/gtest.h>

#include "../../../PhantomEmulator/WinAPI/APIDispatcher.hpp"
#include "../../../PhantomEmulator/Core/CPU/CPU.hpp"
#include "../../../PhantomEmulator/Core/Memory/VirtualMemory.hpp"
#include "../../../PhantomEmulator/Common/Config.hpp"
#include "../../../PhantomEmulator/Common/Types.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <random>
#include <tuple>
#include <string>
#include <utility>
#include <vector>

using namespace Phantom;

namespace {

constexpr GuestAddress kStackBase   = 0x00700000ULL;
constexpr GuestSize    kStackSize   = 0x00100000ULL;
constexpr GuestAddress kDataBase    = 0x00900000ULL;
constexpr GuestSize    kDataSize    = 0x00010000ULL;
constexpr GuestAddress kReturnTo    = 0x00401000ULL;
constexpr GuestAddress kUnmapped    = 0x0000DEAD0000ULL;

class APIDispatcherTest : public ::testing::Test {
protected:
    EmulationConfig config;
    VirtualMemory   memory{ 256ULL * 1024 * 1024 };
    CPU             cpu;
    APIDispatcher   dispatcher{ memory, config };

    void SetUp() override {
        ASSERT_TRUE(memory.Allocate(kStackBase, kStackSize, MemProt::RW).has_value());
        ASSERT_TRUE(memory.Allocate(kDataBase, kDataSize, MemProt::RW).has_value());
        dispatcher.RegisterAll();
    }

    // A handler may legitimately free or re-protect the guest memory a hostile pointer
    // named (VirtualFree, VirtualProtect, UnmapViewOfFile). Put the fixture's regions back.
    void RestoreRegion(GuestAddress base, GuestSize size) {
        if (memory.Protect(base, size, MemProt::RW)) {
            return;
        }
        (void)memory.Free(base, size);
        ASSERT_TRUE(memory.Allocate(base, size, MemProt::RW).has_value())
            << "cannot restore the region at 0x" << std::hex << base;
    }

    // A fresh 64-bit call frame: return address on top of the stack, home space and
    // stack arguments above it.
    void PrepareCall(const std::array<uint64_t, 4>& registerArgs, const std::array<uint64_t, 8>& stackArgs) {
        RestoreRegion(kStackBase, kStackSize);
        cpu.Reset64();
        auto& state = cpu.State();
        const GuestAddress rsp = kStackBase + kStackSize / 2;
        ASSERT_EQ(memory.WriteValue<uint64_t>(rsp, kReturnTo), ErrorCode::Success);
        for (size_t i = 0; i < stackArgs.size(); ++i) {
            ASSERT_EQ(memory.WriteValue<uint64_t>(rsp + 0x28 + 8 * i, stackArgs[i]), ErrorCode::Success);
        }
        state.SetReg64(GPR::RSP, rsp);
        state.SetReg64(GPR::RCX, registerArgs[0]);
        state.SetReg64(GPR::RDX, registerArgs[1]);
        state.SetReg64(GPR::R8, registerArgs[2]);
        state.SetReg64(GPR::R9, registerArgs[3]);
        state.SetRIP(0);
    }

    bool Call(std::string_view dll, std::string_view function) {
        const auto hook = dispatcher.GetHookAddress(dll, function);
        EXPECT_TRUE(hook.has_value()) << std::string(dll) << "!" << std::string(function);
        return hook.has_value() && dispatcher.Dispatch(cpu.State(), memory, *hook);
    }
};

}  // namespace

// One function from every handler set, so a set that stops being registered fails by name.
TEST_F(APIDispatcherTest, EveryHandlerSetIsReachableAfterRegisterAll) {
    const std::vector<std::pair<const char*, const char*>> oneFromEachSet = {
        {"ntdll.dll", "NtAllocateVirtualMemory"},
        {"ntdll.dll", "NtCreateFile"},
        {"ntdll.dll", "NtOpenProcess"},
        {"ntdll.dll", "NtCreateThreadEx"},
        {"ntdll.dll", "NtOpenKey"},
        {"ntdll.dll", "NtQuerySystemInformation"},
        {"ntdll.dll", "NtOpenProcessToken"},
        {"ntdll.dll", "NtWaitForSingleObject"},
        {"ntdll.dll", "LdrLoadDll"},
        {"ntdll.dll", "EtwEventRegister"},
        {"ntdll.dll", "RtlAllocateHeap"},
        {"kernel32.dll", "SetLastError"},
        {"kernel32.dll", "VirtualAlloc"},
        {"kernel32.dll", "CreateFileA"},
        {"kernel32.dll", "SetFileTime"},
        {"kernel32.dll", "CreateFileMappingA"},
        {"kernel32.dll", "CreateProcessA"},
        {"kernel32.dll", "CreateThread"},
        {"kernel32.dll", "QueueUserAPC"},
        {"kernel32.dll", "LoadLibraryA"},
        {"kernel32.dll", "WaitForSingleObject"},
        {"kernel32.dll", "GetTickCount"},
        {"kernel32.dll", "GetComputerNameA"},
        {"kernel32.dll", "lstrlenA"},
        {"kernel32.dll", "OutputDebugStringA"},
        {"advapi32.dll", "RegOpenKeyExA"},
        {"advapi32.dll", "OpenSCManagerA"},
        {"advapi32.dll", "OpenProcessToken"},
        {"advapi32.dll", "CryptAcquireContextA"},
        {"advapi32.dll", "CredReadA"},
        {"ws2_32.dll", "WSAStartup"},
        {"ws2_32.dll", "gethostbyname"},
        {"ws2_32.dll", "WSAGetLastError"},
        {"wininet.dll", "InternetOpenA"},
        {"wininet.dll", "HttpSendRequestExA"},
        {"winhttp.dll", "WinHttpOpen"},
        {"user32.dll", "MessageBoxA"},
        {"user32.dll", "GetAsyncKeyState"},
        {"shell32.dll", "ShellExecuteA"},
        {"urlmon.dll", "URLDownloadToFileA"},
        {"ole32.dll", "CoInitialize"},
        {"oleaut32.dll", "SysAllocString"},
        {"bcrypt.dll", "BCryptOpenAlgorithmProvider"},
        {"amsi.dll", "AmsiInitialize"},
        {"vssapi.dll", "CreateVssBackupComponentsInternal"},
        {"ntoskrnl.exe", "ExAllocatePoolWithTag"}
    };
    for (const auto& [dll, function] : oneFromEachSet) {
        EXPECT_TRUE(dispatcher.IsRegistered(dll, function)) << dll << "!" << function;
    }
}

// The anti-debug answer every evasive sample asks for first, through the real dispatch path.
TEST_F(APIDispatcherTest, AnAntiDebugCheckIsAnsweredAndReturnsToItsCaller) {
    PrepareCall({}, {});
    cpu.State().SetReg64(GPR::RAX, 0x1234);
    ASSERT_TRUE(Call("kernel32.dll", "IsDebuggerPresent"));
    EXPECT_EQ(cpu.State().RAX(), 0u) << "the emulator must never report a debugger";
    EXPECT_EQ(cpu.State().GetRIP(), kReturnTo);
    ASSERT_FALSE(dispatcher.GetCallLog().empty());
    EXPECT_EQ(std::string(dispatcher.GetCallLog().back().funcName), "IsDebuggerPresent");
}

// A real handler with a real effect: VirtualAlloc maps guest memory and returns its address.
TEST_F(APIDispatcherTest, VirtualAllocMapsGuestMemoryThroughTheDispatcher) {
    constexpr uint64_t kCommitReserve = 0x3000;  // MEM_COMMIT | MEM_RESERVE
    constexpr uint64_t kReadWrite     = 0x04;    // PAGE_READWRITE
    PrepareCall({0, 0x2000, kCommitReserve, kReadWrite}, {});
    ASSERT_TRUE(Call("kernel32.dll", "VirtualAlloc"));
    const GuestAddress allocated = cpu.State().RAX();
    ASSERT_NE(allocated, 0u);
    EXPECT_EQ(memory.WriteValue<uint64_t>(allocated + 0x1FF8, 0x1122334455667788ULL), ErrorCode::Success)
        << "the returned range is not mapped for writing";
    EXPECT_EQ(cpu.State().GetRIP(), kReturnTo);
}

// Every registered handler, with hostile arguments, must hand control back without taking the host
// process down. Seeded, so a failure reproduces.
TEST_F(APIDispatcherTest, EveryRegisteredHandlerSurvivesHostileArguments) {
    auto apis = dispatcher.GetRegisteredAPIs();
    ASSERT_GT(apis.size(), 450u) << "RegisterAll registered far fewer APIs than the handler modules define";
    std::sort(apis.begin(), apis.end(), [](const auto& a, const auto& b) {
        return std::tie(a.dllName, a.funcName) < std::tie(b.dllName, b.funcName);
    });

    std::mt19937_64 random(0x5348414430574BULL);
    const std::array<uint64_t, 8> pool = {
        0, 1, 0x10, 0xFFFFFFFFULL, ~0ULL, kUnmapped, kDataBase + 0x100, kStackBase + 0x1000 };
    std::vector<uint8_t> noise(kDataSize);

    std::vector<std::string> lostControl;
    for (const auto& api : apis) {
        for (int round = 0; round < 24; ++round) {
            RestoreRegion(kDataBase, kDataSize);
            for (auto& byte : noise) byte = static_cast<uint8_t>(random());
            // Leave terminated strings in the data region so string readers find an end.
            for (size_t i = 0x100; i < noise.size(); i += 0x40) { noise[i] = 0; noise[i + 1] = 0; }
            ASSERT_EQ(memory.Write(kDataBase, noise.data(), static_cast<uint32_t>(noise.size())), ErrorCode::Success);

            std::array<uint64_t, 4> registers{};
            std::array<uint64_t, 8> stack{};
            for (auto& value : registers) value = pool[random() % pool.size()];
            for (auto& value : stack) value = pool[random() % pool.size()];
            PrepareCall(registers, stack);

            const bool keepRunning = Call(api.dllName, api.funcName);
            if (keepRunning && cpu.State().GetRIP() != kReturnTo) {
                lostControl.push_back(api.dllName + "!" + api.funcName);
                break;
            }
        }
    }
    EXPECT_TRUE(lostControl.empty()) << "handlers that did not return to their caller: " << [&] {
        std::string joined;
        for (const auto& name : lostControl) joined += name + " ";
        return joined;
    }();
}

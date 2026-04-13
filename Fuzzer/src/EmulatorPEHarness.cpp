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
 * @file EmulatorPEHarness.cpp
 * @brief Implementation of the PhantomEmulator PE loader fuzz harness.
 */

#include "ShadowStrike/Fuzzer/Harnesses/EmulatorPEHarness.hpp"
#include "ShadowStrike/Fuzzer/Core/FuzzLoop.hpp"

#include "PhantomEmulator/Common/Config.hpp"
#include "PhantomEmulator/Common/Errors.hpp"
#include "PhantomEmulator/Common/Types.hpp"
#include "PhantomEmulator/Core/CPU/CPU.hpp"
#include "PhantomEmulator/Core/Loader/ExportResolver.hpp"
#include "PhantomEmulator/Core/Loader/ImportResolver.hpp"
#include "PhantomEmulator/Core/Loader/PELoader.hpp"
#include "PhantomEmulator/Core/Loader/PEParser.hpp"
#include "PhantomEmulator/Core/Memory/MemoryTracker.hpp"
#include "PhantomEmulator/Core/Memory/VirtualMemory.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <malloc.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Fuzzer {
namespace {

using Phantom::CPU;
using Phantom::CPUMode;
using Phantom::CPUState;
using Phantom::EmulationConfig;
using Phantom::EmulationTarget;
using Phantom::ErrorCode;
using Phantom::ExecutionResult;
using Phantom::ExportResolver;
using Phantom::GPR;
using Phantom::GuestAddress;
using Phantom::GuestSize;
using Phantom::ImportResolver;
using Phantom::LoadedImage;
using Phantom::MemoryTracker;
using Phantom::PELoader;
using Phantom::PEParser;
using Phantom::StopReason;
using Phantom::VirtualMemory;

constexpr GuestAddress kApiHookBase = 0x70000000ULL;
constexpr GuestAddress kKnownNoArgApiHook = kApiHookBase;
constexpr GuestAddress kAutoApiHookBase = kApiHookBase + 0x100ULL;
constexpr GuestSize kApiHookSize = 0x20000ULL;
constexpr uint64_t kMaxInstructions = 25'000ULL;
constexpr uint64_t kMaxAPICalls = 128ULL;
constexpr GuestSize kMaxGuestMemoryBudget = 64ULL * 1024ULL * 1024ULL;
constexpr uint16_t kImageFileDll = 0x2000;

constexpr size_t kPE32DataDirectoryOffset = 0xB8;
constexpr size_t kPE64DataDirectoryOffset = 0xC8;
constexpr size_t kCOFFCharacteristicsOffset = 0x56;
constexpr size_t kSectionRawOffset = 0x200;
constexpr size_t kPE32ImportDescriptorOffset = 0x320;
constexpr size_t kPE32ILTOffset = 0x340;
constexpr size_t kPE32IATOffset = 0x350;
constexpr size_t kPE32DllNameOffset = 0x360;
constexpr size_t kPE32HintNameOffset = 0x370;
constexpr size_t kPE32RelocOffset = 0x380;
constexpr size_t kPE32TLSOffset = 0x390;
constexpr size_t kPE32TLSDataOffset = 0x3C0;
constexpr size_t kPE32TLSIndexOffset = 0x3C8;
constexpr size_t kPE32TLSCallbacksOffset = 0x3D0;

constexpr size_t kPE64ImportDescriptorOffset = 0x320;
constexpr size_t kPE64ILTOffset = 0x340;
constexpr size_t kPE64IATOffset = 0x350;
constexpr size_t kPE64DllNameOffset = 0x360;
constexpr size_t kPE64HintNameOffset = 0x370;
constexpr size_t kPE64RelocOffset = 0x380;
constexpr size_t kPE64TLSOffset = 0x390;
constexpr size_t kPE64TLSDataOffset = 0x3C0;
constexpr size_t kPE64TLSIndexOffset = 0x3C8;
constexpr size_t kPE64TLSCallbacksOffset = 0x3D0;

constexpr uint32_t kImportDirRva = 0x1120;
constexpr uint32_t kImportDirSize = 40;
constexpr uint32_t kILT32Rva = 0x1140;
constexpr uint32_t kIAT32Rva = 0x1150;
constexpr uint32_t kImportDllNameRva = 0x1160;
constexpr uint32_t kHintNameRva = 0x1170;
constexpr uint32_t kRelocDirRva = 0x1180;
constexpr uint32_t kRelocDirSize = 12;
constexpr uint32_t kTLSDirRva = 0x1190;
constexpr uint32_t kTLSDirSize32 = 24;
constexpr uint32_t kTLSDirSize64 = 40;
constexpr uint32_t kTLSRawDataRva = 0x11C0;
constexpr uint32_t kTLSIndexRva = 0x11C8;
constexpr uint32_t kTLSCallbacksRva = 0x11D0;

struct CandidateSpec {
    std::string name;
    std::vector<uint8_t> bytes;
    EmulationTarget target = EmulationTarget::PE64;
    bool forceRelocation = false;
    bool exerciseLoadDll = false;
};

std::string ExceptionCodeToStringInternal(DWORD code) noexcept {
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

[[nodiscard]] bool IsTarget64Bit(EmulationTarget target) noexcept {
    return target == EmulationTarget::PE64 || target == EmulationTarget::DLL64;
}

[[nodiscard]] bool IsValidStopReason(StopReason reason) noexcept {
    switch (reason) {
    case StopReason::None:
    case StopReason::InstructionLimit:
    case StopReason::TimeLimit:
    case StopReason::MemoryLimit:
    case StopReason::InvalidInstruction:
    case StopReason::AccessViolation:
    case StopReason::DivideByZero:
    case StopReason::StackOverflow:
    case StopReason::Breakpoint:
    case StopReason::Syscall:
    case StopReason::APICallTrap:
    case StopReason::ExitProcess:
    case StopReason::UnpackComplete:
    case StopReason::Crashed:
    case StopReason::UserAborted:
        return true;
    }

    return false;
}

void RecordValidationIssue(HarnessResult& result, std::string_view message) {
    ++result.validationIssueCount;
    if (result.errorMessage.empty()) {
        result.errorMessage.assign(message.data(), message.size());
    }
}

void RecordAnomaly(HarnessResult& result, std::string_view message) {
    ++result.anomalyCount;
    if (result.errorMessage.empty()) {
        result.errorMessage.assign(message.data(), message.size());
    }
}

template <typename T>
void WriteLE(std::vector<uint8_t>& bytes, size_t offset, T value) {
    if (offset + sizeof(T) > bytes.size()) {
        return;
    }

    for (size_t index = 0; index < sizeof(T); ++index) {
        bytes[offset + index] = static_cast<uint8_t>((static_cast<uint64_t>(value) >> (index * 8)) & 0xFFU);
    }
}

std::vector<uint8_t> GenerateMinimalPE32Seed() noexcept {
    std::vector<uint8_t> pe;
    pe.reserve(1024);

    pe.resize(64, 0);
    pe[0] = 'M';
    pe[1] = 'Z';
    pe[0x3C] = 0x40;

    pe.push_back('P');
    pe.push_back('E');
    pe.push_back(0);
    pe.push_back(0);

    pe.push_back(0x4C); pe.push_back(0x01);
    pe.push_back(0x01); pe.push_back(0x00);
    for (int index = 0; index < 12; ++index) pe.push_back(0x00);
    pe.push_back(0xE0); pe.push_back(0x00);
    pe.push_back(0x02); pe.push_back(0x01);

    pe.push_back(0x0B); pe.push_back(0x01);
    pe.push_back(0x0E); pe.push_back(0x00);
    for (int index = 0; index < 12; ++index) pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x20); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x40); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x02); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x06); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x06); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x30); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x02); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x03); pe.push_back(0x00);
    pe.push_back(0x40); pe.push_back(0x81);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    for (int index = 0; index < 128; ++index) pe.push_back(0x00);

    pe.push_back('.'); pe.push_back('t'); pe.push_back('e'); pe.push_back('x');
    pe.push_back('t'); pe.push_back(0); pe.push_back(0); pe.push_back(0);
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x02); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x02); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x20); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x60);

    while (pe.size() < 512) {
        pe.push_back(0x00);
    }

    pe.push_back(0xC3);

    while (pe.size() < 1024) {
        pe.push_back(0x00);
    }

    return pe;
}

std::vector<uint8_t> GenerateMinimalPE64Seed() noexcept {
    std::vector<uint8_t> pe;
    pe.reserve(1024);

    pe.resize(64, 0);
    pe[0] = 'M';
    pe[1] = 'Z';
    pe[0x3C] = 0x40;

    pe.push_back('P');
    pe.push_back('E');
    pe.push_back(0);
    pe.push_back(0);

    pe.push_back(0x64); pe.push_back(0x86);
    pe.push_back(0x01); pe.push_back(0x00);
    for (int index = 0; index < 12; ++index) pe.push_back(0x00);
    pe.push_back(0xF0); pe.push_back(0x00);
    pe.push_back(0x22); pe.push_back(0x00);

    pe.push_back(0x0B); pe.push_back(0x02);
    pe.push_back(0x0E); pe.push_back(0x00);
    for (int index = 0; index < 12; ++index) pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x40);
    pe.push_back(0x01); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x02); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x06); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x06); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x30); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x02); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x03); pe.push_back(0x00);
    pe.push_back(0x60); pe.push_back(0x81);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    for (int index = 0; index < 128; ++index) pe.push_back(0x00);

    pe.push_back('.'); pe.push_back('t'); pe.push_back('e'); pe.push_back('x');
    pe.push_back('t'); pe.push_back(0); pe.push_back(0); pe.push_back(0);
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x10); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x02); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x02); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x00); pe.push_back(0x00);
    pe.push_back(0x20); pe.push_back(0x00); pe.push_back(0x00); pe.push_back(0x60);

    while (pe.size() < 512) {
        pe.push_back(0x00);
    }

    pe.push_back(0xC3);

    while (pe.size() < 1024) {
        pe.push_back(0x00);
    }

    return pe;
}

void SetDLLCharacteristics(std::vector<uint8_t>& bytes, bool isDll) {
    if (bytes.size() <= kCOFFCharacteristicsOffset + sizeof(uint16_t)) {
        return;
    }

    uint16_t characteristics = static_cast<uint16_t>(bytes[kCOFFCharacteristicsOffset])
        | (static_cast<uint16_t>(bytes[kCOFFCharacteristicsOffset + 1]) << 8);
    if (isDll) {
        characteristics = static_cast<uint16_t>(characteristics | kImageFileDll);
    } else {
        characteristics = static_cast<uint16_t>(characteristics & ~kImageFileDll);
    }
    WriteLE<uint16_t>(bytes, kCOFFCharacteristicsOffset, characteristics);
}

void PatchStructuredPE32(std::vector<uint8_t>& bytes, bool isDll) {
    SetDLLCharacteristics(bytes, isDll);

    if (!isDll) {
        bytes[kSectionRawOffset + 0] = 0xFF;
        bytes[kSectionRawOffset + 1] = 0x15;
        bytes[kSectionRawOffset + 2] = 0x50;
        bytes[kSectionRawOffset + 3] = 0x11;
        bytes[kSectionRawOffset + 4] = 0x40;
        bytes[kSectionRawOffset + 5] = 0x00;
        bytes[kSectionRawOffset + 6] = 0xC3;
    }

    WriteLE<uint32_t>(bytes, kPE32DataDirectoryOffset + 8, kImportDirRva);
    WriteLE<uint32_t>(bytes, kPE32DataDirectoryOffset + 12, kImportDirSize);
    WriteLE<uint32_t>(bytes, kPE32DataDirectoryOffset + 40, kRelocDirRva);
    WriteLE<uint32_t>(bytes, kPE32DataDirectoryOffset + 44, kRelocDirSize);
    WriteLE<uint32_t>(bytes, kPE32DataDirectoryOffset + 72, kTLSDirRva);
    WriteLE<uint32_t>(bytes, kPE32DataDirectoryOffset + 76, kTLSDirSize32);

    WriteLE<uint32_t>(bytes, kSectionRawOffset + 0x50, 0x00401234U);

    WriteLE<uint32_t>(bytes, kPE32ImportDescriptorOffset + 0x00, kILT32Rva);
    WriteLE<uint32_t>(bytes, kPE32ImportDescriptorOffset + 0x0C, kImportDllNameRva);
    WriteLE<uint32_t>(bytes, kPE32ImportDescriptorOffset + 0x10, kIAT32Rva);

    WriteLE<uint32_t>(bytes, kPE32ILTOffset + 0x00, kHintNameRva);
    WriteLE<uint32_t>(bytes, kPE32ILTOffset + 0x04, 0U);
    WriteLE<uint32_t>(bytes, kPE32IATOffset + 0x00, kHintNameRva);
    WriteLE<uint32_t>(bytes, kPE32IATOffset + 0x04, 0U);

    static constexpr std::string_view kDllName = "kernel32.dll";
    for (size_t index = 0; index < kDllName.size(); ++index) {
        bytes[kPE32DllNameOffset + index] = static_cast<uint8_t>(kDllName[index]);
    }
    bytes[kPE32DllNameOffset + kDllName.size()] = 0;

    WriteLE<uint16_t>(bytes, kPE32HintNameOffset, 0U);
    static constexpr std::string_view kImportName = "GetTickCount";
    for (size_t index = 0; index < kImportName.size(); ++index) {
        bytes[kPE32HintNameOffset + 2 + index] = static_cast<uint8_t>(kImportName[index]);
    }
    bytes[kPE32HintNameOffset + 2 + kImportName.size()] = 0;

    WriteLE<uint32_t>(bytes, kPE32RelocOffset + 0x00, 0x1000U);
    WriteLE<uint32_t>(bytes, kPE32RelocOffset + 0x04, 12U);
    WriteLE<uint16_t>(bytes, kPE32RelocOffset + 0x08, static_cast<uint16_t>((3U << 12) | 0x50U));
    WriteLE<uint16_t>(bytes, kPE32RelocOffset + 0x0A, 0U);

    const uint32_t imageBase = 0x00400000U;
    WriteLE<uint32_t>(bytes, kPE32TLSOffset + 0x00, imageBase + kTLSRawDataRva);
    WriteLE<uint32_t>(bytes, kPE32TLSOffset + 0x04, imageBase + kTLSRawDataRva + 4U);
    WriteLE<uint32_t>(bytes, kPE32TLSOffset + 0x08, imageBase + kTLSIndexRva);
    WriteLE<uint32_t>(bytes, kPE32TLSOffset + 0x0C, imageBase + kTLSCallbacksRva);
    WriteLE<uint32_t>(bytes, kPE32TLSOffset + 0x10, 0U);
    WriteLE<uint32_t>(bytes, kPE32TLSOffset + 0x14, 0U);

    WriteLE<uint32_t>(bytes, kPE32TLSDataOffset + 0x00, 0x11223344U);
    WriteLE<uint32_t>(bytes, kPE32TLSIndexOffset + 0x00, 0U);
    WriteLE<uint32_t>(bytes, kPE32TLSCallbacksOffset + 0x00, 0x00401000U);
    WriteLE<uint32_t>(bytes, kPE32TLSCallbacksOffset + 0x04, 0U);
}

void PatchStructuredPE64(std::vector<uint8_t>& bytes, bool isDll) {
    SetDLLCharacteristics(bytes, isDll);

    bytes[kSectionRawOffset + 0] = 0xFF;
    bytes[kSectionRawOffset + 1] = 0x15;
    bytes[kSectionRawOffset + 2] = 0x4A;
    bytes[kSectionRawOffset + 3] = 0x01;
    bytes[kSectionRawOffset + 4] = 0x00;
    bytes[kSectionRawOffset + 5] = 0x00;
    bytes[kSectionRawOffset + 6] = 0xC3;

    WriteLE<uint32_t>(bytes, kPE64DataDirectoryOffset + 8, kImportDirRva);
    WriteLE<uint32_t>(bytes, kPE64DataDirectoryOffset + 12, kImportDirSize);
    WriteLE<uint32_t>(bytes, kPE64DataDirectoryOffset + 40, kRelocDirRva);
    WriteLE<uint32_t>(bytes, kPE64DataDirectoryOffset + 44, kRelocDirSize);
    WriteLE<uint32_t>(bytes, kPE64DataDirectoryOffset + 72, kTLSDirRva);
    WriteLE<uint32_t>(bytes, kPE64DataDirectoryOffset + 76, kTLSDirSize64);

    WriteLE<uint64_t>(bytes, kSectionRawOffset + 0x50, 0x0000000140123456ULL);

    WriteLE<uint32_t>(bytes, kPE64ImportDescriptorOffset + 0x00, kILT32Rva);
    WriteLE<uint32_t>(bytes, kPE64ImportDescriptorOffset + 0x0C, kImportDllNameRva);
    WriteLE<uint32_t>(bytes, kPE64ImportDescriptorOffset + 0x10, kIAT32Rva);

    WriteLE<uint64_t>(bytes, kPE64ILTOffset + 0x00, static_cast<uint64_t>(kHintNameRva));
    WriteLE<uint64_t>(bytes, kPE64ILTOffset + 0x08, 0ULL);
    WriteLE<uint64_t>(bytes, kPE64IATOffset + 0x00, static_cast<uint64_t>(kHintNameRva));
    WriteLE<uint64_t>(bytes, kPE64IATOffset + 0x08, 0ULL);

    static constexpr std::string_view kDllName = "kernel32.dll";
    for (size_t index = 0; index < kDllName.size(); ++index) {
        bytes[kPE64DllNameOffset + index] = static_cast<uint8_t>(kDllName[index]);
    }
    bytes[kPE64DllNameOffset + kDllName.size()] = 0;

    WriteLE<uint16_t>(bytes, kPE64HintNameOffset, 0U);
    static constexpr std::string_view kImportName = "GetTickCount";
    for (size_t index = 0; index < kImportName.size(); ++index) {
        bytes[kPE64HintNameOffset + 2 + index] = static_cast<uint8_t>(kImportName[index]);
    }
    bytes[kPE64HintNameOffset + 2 + kImportName.size()] = 0;

    WriteLE<uint32_t>(bytes, kPE64RelocOffset + 0x00, 0x1000U);
    WriteLE<uint32_t>(bytes, kPE64RelocOffset + 0x04, 12U);
    WriteLE<uint16_t>(bytes, kPE64RelocOffset + 0x08, static_cast<uint16_t>((10U << 12) | 0x50U));
    WriteLE<uint16_t>(bytes, kPE64RelocOffset + 0x0A, 0U);

    const uint64_t imageBase = 0x0000000140000000ULL;
    WriteLE<uint64_t>(bytes, kPE64TLSOffset + 0x00, imageBase + kTLSRawDataRva);
    WriteLE<uint64_t>(bytes, kPE64TLSOffset + 0x08, imageBase + kTLSRawDataRva + 8ULL);
    WriteLE<uint64_t>(bytes, kPE64TLSOffset + 0x10, imageBase + kTLSIndexRva);
    WriteLE<uint64_t>(bytes, kPE64TLSOffset + 0x18, imageBase + kTLSCallbacksRva);
    WriteLE<uint32_t>(bytes, kPE64TLSOffset + 0x20, 0U);
    WriteLE<uint32_t>(bytes, kPE64TLSOffset + 0x24, 0U);

    WriteLE<uint64_t>(bytes, kPE64TLSDataOffset + 0x00, 0x1122334455667788ULL);
    WriteLE<uint64_t>(bytes, kPE64TLSIndexOffset + 0x00, 0ULL);
    WriteLE<uint64_t>(bytes, kPE64TLSCallbacksOffset + 0x00, 0x0000000140001000ULL);
    WriteLE<uint64_t>(bytes, kPE64TLSCallbacksOffset + 0x08, 0ULL);
}

void BlendInputIntoStructuredSeed(std::vector<uint8_t>& bytes, std::span<const uint8_t> input) {
    if (input.empty()) {
        return;
    }

    constexpr std::array<std::pair<size_t, size_t>, 4> kMutableRanges{{
        { kSectionRawOffset + 0x01, 0x1F },
        { kSectionRawOffset + 0x50, 0x10 },
        { kSectionRawOffset + 0x1C0, 0x10 },
        { kSectionRawOffset + 0x1E0, 0x10 },
    }};

    size_t inputIndex = 0;
    for (const auto& [offset, length] : kMutableRanges) {
        for (size_t index = 0; index < length && inputIndex < input.size(); ++index, ++inputIndex) {
            bytes[offset + index] ^= static_cast<uint8_t>(input[inputIndex] + static_cast<uint8_t>(inputIndex));
        }
    }
}

std::vector<CandidateSpec> BuildCandidateSet(std::span<const uint8_t> input) {
    std::vector<CandidateSpec> candidates;
    candidates.reserve(4);

    auto pe32 = GenerateMinimalPE32Seed();
    PatchStructuredPE32(pe32, false);
    BlendInputIntoStructuredSeed(pe32, input);
    CandidateSpec pe32Candidate{};
    pe32Candidate.name = "seed-pe32";
    pe32Candidate.bytes = std::move(pe32);
    pe32Candidate.target = EmulationTarget::PE32;
    pe32Candidate.forceRelocation = false;
    candidates.push_back(std::move(pe32Candidate));

    auto pe64 = GenerateMinimalPE64Seed();
    PatchStructuredPE64(pe64, false);
    BlendInputIntoStructuredSeed(pe64, input);
    CandidateSpec pe64Candidate{};
    pe64Candidate.name = "seed-pe64";
    pe64Candidate.bytes = std::move(pe64);
    pe64Candidate.target = EmulationTarget::PE64;
    pe64Candidate.forceRelocation = true;
    candidates.push_back(std::move(pe64Candidate));

    auto dll32 = GenerateMinimalPE32Seed();
    PatchStructuredPE32(dll32, true);
    BlendInputIntoStructuredSeed(dll32, input);
    CandidateSpec dll32Candidate{};
    dll32Candidate.name = "seed-dll32";
    dll32Candidate.bytes = std::move(dll32);
    dll32Candidate.target = EmulationTarget::DLL32;
    dll32Candidate.forceRelocation = true;
    dll32Candidate.exerciseLoadDll = true;
    candidates.push_back(std::move(dll32Candidate));

    auto dll64 = GenerateMinimalPE64Seed();
    PatchStructuredPE64(dll64, true);
    BlendInputIntoStructuredSeed(dll64, input);
    CandidateSpec dll64Candidate{};
    dll64Candidate.name = "seed-dll64";
    dll64Candidate.bytes = std::move(dll64);
    dll64Candidate.target = EmulationTarget::DLL64;
    dll64Candidate.forceRelocation = true;
    dll64Candidate.exerciseLoadDll = true;
    candidates.push_back(std::move(dll64Candidate));

    return candidates;
}

[[nodiscard]] EmulationConfig BuildPEConfig(EmulationTarget target) noexcept {
    EmulationConfig config{};
    config.target = target;
    config.cpuMode = IsTarget64Bit(target) ? CPUMode::Long64 : CPUMode::Protected32;
    config.maxInstructions = kMaxInstructions;
    config.maxAPIcalls = kMaxAPICalls;
    config.maxWallTime = std::chrono::milliseconds{ 750 };
    config.maxGuestMemory = kMaxGuestMemoryBudget;
    config.maxThreads = 1;
    config.maxUnpackLayers = 0;
    config.maxStackDepth = 256;
    config.stackSize = 64ULL * 1024ULL;
    config.heapSize = 256ULL * 1024ULL;
    config.enableDEP = true;
    config.trackMemoryAccess = false;
    config.enableFileSystem = false;
    config.enableADSTracking = false;
    config.enableRegistry = false;
    config.enableNetwork = false;
    config.enableCOM = false;
    config.enableETW = false;
    config.enableAMSI = false;
    config.enableVSS = false;
    config.enableWMI = false;
    config.enableDotNetAnalysis = false;
    config.blockExternalCalls = false;
    config.enableTimingAcceleration = false;
    config.enableAntiDebugBypass = false;
    config.enableAntiVMBypass = false;
    config.enableAntiSandboxBypass = false;
    config.enableUnpacking = false;
    config.captureUnpackLayers = false;
    config.minOEPInstructions = 0;
    config.enableBehaviorMonitor = false;
    config.enableAPISequenceAnalysis = false;
    config.enableMemoryForensics = false;
    config.enableMITREMapping = false;
    config.enableIOCExtraction = false;
    config.enableTaintAnalysis = false;
    config.enableMLClassifier = false;
    config.yaraScansPerSession = 0;
    config.enableJIT = false;
    config.enableHardwareAccel = false;
    config.enableSIMDScanning = false;
    config.enableCryptoAcceleration = false;
    config.enableMemoryScanAccel = false;
    config.enableJITOptimizer = false;
    config.enableCET = false;
    config.cetEnforceShadowStack = false;
    config.cetEnforceIBT = false;
    config.enableKernelEmulation = false;
    config.enableDKOMDetection = false;
    config.enableSSDTIntegrity = false;
    config.enableIDTIntegrity = false;
    config.enableMSRMonitoring = false;
    config.enableRingTransitionCheck = false;
    config.enableDriverLoading = false;
    config.enableKernelAPITracking = false;
    config.maxKernelDrivers = 0;
    config.enableMultiProcess = false;
    config.maxChildProcesses = 0;
    config.maxInjectedPayloadCapture = 0;
    config.enableWoW64 = false;
    config.detectHeavensGate = false;
    config.enableFsRedirection = false;
    config.enableRegistryRedirection = false;
    config.enableInstructionTrace = false;
    config.enableAPITrace = false;
    config.enableMemoryTrace = false;
    return config;
}

bool StopOnSyscall(CPUState&, VirtualMemory&) noexcept {
    return false;
}

bool StopOnInterrupt(CPUState&, VirtualMemory&, uint8_t) noexcept {
    return false;
}

bool ContinuePastAPICall(CPUState& state, VirtualMemory& memory, GuestAddress apiAddr) noexcept {
    if (state.mode == CPUMode::Long64) {
        const GuestAddress rsp = state.GetReg64(GPR::RSP);
        uint64_t returnAddress = 0;
        if (memory.ReadU64(rsp, returnAddress) != ErrorCode::Success || returnAddress == 0) {
            return false;
        }

        state.SetReg64(GPR::RAX, 0);
        state.SetReg64(GPR::RSP, rsp + sizeof(uint64_t));
        state.SetRIP(returnAddress);
        return true;
    }

    if (apiAddr != kKnownNoArgApiHook) {
        return false;
    }

    const uint32_t esp = state.GetReg32(GPR::RSP);
    uint32_t returnAddress = 0;
    if (memory.ReadU32(esp, returnAddress) != ErrorCode::Success || returnAddress == 0) {
        return false;
    }

    state.SetReg32(GPR::RAX, 0);
    state.SetReg32(GPR::RSP, esp + sizeof(uint32_t));
    state.SetRIP(returnAddress);
    return true;
}

void ValidateLoadedImage(
    const PELoader::LoadResult& loadResult,
    bool expectRuntimeEnvironment,
    HarnessResult& result) {
    const LoadedImage& image = loadResult.image;
    if (image.imageBase == 0) {
        RecordValidationIssue(result, "PELoader returned a loaded image without an image base.");
    }

    if (image.sectionsLoaded > image.parsedPE.sections.size()) {
        RecordValidationIssue(result, "PELoader reported more loaded sections than the parsed PE contains.");
    }

    if (image.parsedPE.entryPointRVA != 0) {
        const GuestAddress expectedEntryPoint = image.imageBase + image.parsedPE.entryPointRVA;
        if (image.entryPoint != expectedEntryPoint) {
            RecordValidationIssue(result, "PELoader entry point disagreed with the parsed PE entry RVA.");
        }
    }

    if (image.parsedPE.imports.empty()) {
        if (image.imports.totalResolved != 0 || image.imports.totalFailed != 0) {
            RecordValidationIssue(result, "PELoader reported import resolution results for a PE without parsed imports.");
        }
    } else {
        size_t totalParsedImports = 0;
        for (const auto& dll : image.parsedPE.imports) {
            totalParsedImports += dll.entries.size();
        }

        const size_t totalResolved = static_cast<size_t>(image.imports.totalResolved);
        const size_t totalFailed = static_cast<size_t>(image.imports.totalFailed);
        if (totalResolved + totalFailed > totalParsedImports) {
            RecordValidationIssue(result, "ImportResolver reported more imports than PEParser parsed from the candidate.");
        }
    }

    if (expectRuntimeEnvironment && image.parsedPE.hasTLS && !image.tlsInfo.present) {
        RecordValidationIssue(result, "PELoader parsed a TLS directory but TLSHandler did not mark the image as TLS-present.");
    }

    if (expectRuntimeEnvironment) {
        if (image.stackBase == 0 || image.stackTop == 0) {
            RecordValidationIssue(result, "Full PELoader path did not initialize a stack.");
        }
        if (image.heapBase == 0) {
            RecordValidationIssue(result, "Full PELoader path did not initialize a heap.");
        }
        if (image.pebAddress == 0 || image.tebAddress == 0) {
            RecordValidationIssue(result, "Full PELoader path did not initialize the PEB/TEB.");
        }
    }
}

void ValidateExecutionResult(
    const ExecutionResult& execResult,
    const EmulationConfig& config,
    HarnessResult& result) {
    if (!IsValidStopReason(execResult.reason)) {
        RecordValidationIssue(result, "CPU::Execute returned an unknown stop reason.");
    }

    if (execResult.instructionsExecuted > config.maxInstructions) {
        RecordValidationIssue(result, "CPU::Execute exceeded the configured instruction budget.");
    }

    if (execResult.apiCallCount > config.maxAPIcalls) {
        RecordValidationIssue(result, "CPU::Execute exceeded the configured API-call budget.");
    }

    if (execResult.reason == StopReason::InstructionLimit && execResult.instructionsExecuted + 1 < config.maxInstructions) {
        RecordValidationIssue(result, "CPU::Execute hit the instruction limit too early.");
    }

    if (execResult.reason != StopReason::None && execResult.instructionsExecuted > 0 && execResult.lastRIP == 0) {
        RecordValidationIssue(result, "CPU::Execute reported progress without a last RIP.");
    }

    if (execResult.reason == StopReason::Crashed || execResult.reason == StopReason::None) {
        RecordAnomaly(result, "CPU::Execute terminated in an unexpected state.");
    }
}

std::optional<PELoader::LoadResult> ExecuteFullLoadPath(
    const CandidateSpec& candidate,
    HarnessResult& result) {
    const auto parseResult = PEParser::Parse(candidate.bytes);
    if (!parseResult.Ok()) {
        return std::nullopt;
    }

    result.parsedOk = true;

    EmulationConfig config = BuildPEConfig(candidate.target);
    VirtualMemory memory(config.maxGuestMemory);

    if (candidate.forceRelocation && parseResult.pe.imageBase != 0 && parseResult.pe.sizeOfImage != 0) {
        const GuestAddress preferredBase = static_cast<GuestAddress>(parseResult.pe.imageBase);
        const GuestSize reserveSize = Phantom::AlignUp(static_cast<GuestSize>(parseResult.pe.sizeOfImage), Phantom::kPageSize);
        (void)memory.Allocate(preferredBase, reserveSize, Phantom::MemProt::RW);
    }

    ExportResolver exports;
    ImportResolver imports(exports);
    imports.SetAPIHookRange(kAutoApiHookBase, kApiHookSize - (kAutoApiHookBase - kApiHookBase));
    imports.RegisterAPIHook("kernel32.dll", "GetTickCount", kKnownNoArgApiHook);

    PELoader loader(memory, exports, imports);
    auto loadResult = loader.Load(candidate.bytes, config);
    if (!loadResult.Ok()) {
        return loadResult;
    }

    ValidateLoadedImage(loadResult, true, result);

    MemoryTracker tracker;
    tracker.Reset();

    CPU cpu;
    cpu.SetSyscallCallback(StopOnSyscall);
    cpu.SetInterruptCallback(StopOnInterrupt);
    cpu.SetAPICallCallback(ContinuePastAPICall);
    cpu.SetAPIHookRange(kApiHookBase, kApiHookSize);

    loader.PrepareCPUState(cpu, loadResult.image, config);

    const ExecutionResult execResult = cpu.Execute(memory, &tracker, config);
    ValidateExecutionResult(execResult, config, result);
    return loadResult;
}

void ExerciseDependencyLoadPath(const CandidateSpec& candidate, HarnessResult& result) {
    VirtualMemory memory(kMaxGuestMemoryBudget);
    ExportResolver exports;
    ImportResolver imports(exports);
    imports.SetAPIHookRange(kAutoApiHookBase, kApiHookSize - (kAutoApiHookBase - kApiHookBase));
    imports.RegisterAPIHook("kernel32.dll", "GetTickCount", kKnownNoArgApiHook);

    PELoader loader(memory, exports, imports);
    const auto dllLoad = loader.LoadDLL(candidate.bytes, "fuzzpayload.dll");
    if (!dllLoad.Ok()) {
        return;
    }

    ValidateLoadedImage(dllLoad, false, result);

    if (!exports.HasModule("fuzzpayload.dll")) {
        RecordValidationIssue(result, "PELoader::LoadDLL succeeded without registering the loaded module exports.");
    }
}

bool ExerciseCandidate(const CandidateSpec& candidate, HarnessResult& result) {
    const auto loadResult = ExecuteFullLoadPath(candidate, result);
    if (!loadResult.has_value()) {
        return false;
    }

    if (candidate.exerciseLoadDll) {
        ExerciseDependencyLoadPath(candidate, result);
    }

    return loadResult->Ok();
}

bool ExerciseDirectInput(std::span<const uint8_t> input, HarnessResult& result) {
    if (input.empty()) {
        return false;
    }

    const auto parseResult = PEParser::Parse(input);
    if (!parseResult.Ok()) {
        return false;
    }

    CandidateSpec direct{};
    direct.name = "raw-input";
    direct.bytes.assign(input.begin(), input.end());
    direct.target = parseResult.pe.isDLL
        ? (parseResult.pe.is64Bit ? EmulationTarget::DLL64 : EmulationTarget::DLL32)
        : (parseResult.pe.is64Bit ? EmulationTarget::PE64 : EmulationTarget::PE32);
    direct.forceRelocation = parseResult.pe.hasRelocations;
    direct.exerciseLoadDll = parseResult.pe.isDLL;
    return ExerciseCandidate(direct, result);
}

bool WriteSeedFile(const std::filesystem::path& path, const std::vector<uint8_t>& bytes) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        return false;
    }

    stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return stream.good();
}

void EnsureSeedCorpus(const std::filesystem::path& corpusDir) {
    std::error_code ec;
    const bool corpusExists = std::filesystem::exists(corpusDir, ec);
    bool hasEntries = false;
    if (corpusExists) {
        std::filesystem::directory_iterator it(corpusDir, ec);
        hasEntries = !ec && it != std::filesystem::directory_iterator{};
    }
    if (hasEntries) {
        return;
    }

    auto pe32 = GenerateMinimalPE32Seed();
    PatchStructuredPE32(pe32, false);
    auto pe64 = GenerateMinimalPE64Seed();
    PatchStructuredPE64(pe64, false);
    auto dll32 = GenerateMinimalPE32Seed();
    PatchStructuredPE32(dll32, true);
    auto dll64 = GenerateMinimalPE64Seed();
    PatchStructuredPE64(dll64, true);

    (void)WriteSeedFile(corpusDir / "seed-pe32.bin", pe32);
    (void)WriteSeedFile(corpusDir / "seed-pe64.bin", pe64);
    (void)WriteSeedFile(corpusDir / "seed-dll32.bin", dll32);
    (void)WriteSeedFile(corpusDir / "seed-dll64.bin", dll64);
}

}  // namespace

std::string EmulatorPEHarness::ExceptionCodeToString(unsigned long code) noexcept {
    return ExceptionCodeToStringInternal(static_cast<DWORD>(code));
}

bool EmulatorPEHarness::ExercisePEImpl(
    const uint8_t* data,
    size_t size,
    HarnessResult& result)
{
    const auto startTime = std::chrono::high_resolution_clock::now();
    const std::span<const uint8_t> input =
        (data != nullptr && size != 0)
            ? std::span<const uint8_t>(data, size)
            : std::span<const uint8_t>{};

    bool reachedDeepPath = false;
    reachedDeepPath |= ExerciseDirectInput(input, result);

    for (const auto& candidate : BuildCandidateSet(input)) {
        reachedDeepPath |= ExerciseCandidate(candidate, result);
    }

    const auto endTime = std::chrono::high_resolution_clock::now();
    result.parseTimeNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(endTime - startTime).count());
    result.parsedOk = result.parsedOk || reachedDeepPath;
    return result.parsedOk;
}

unsigned long EmulatorPEHarness::SEHCallPE(
    const uint8_t* data,
    size_t size,
    HarnessResult* pResult) noexcept
{
    DWORD exceptionCode = 0;
    __try {
        ExercisePEImpl(data, size, *pResult);
    }
    __except (exceptionCode = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
        if (exceptionCode == EXCEPTION_STACK_OVERFLOW) {
            if (_resetstkoflw() == 0) {
                TerminateProcess(GetCurrentProcess(), exceptionCode);
            }
        }

        if (exceptionCode == STATUS_HEAP_CORRUPTION) {
            TerminateProcess(GetCurrentProcess(), exceptionCode);
        }
    }

    return exceptionCode;
}

HarnessResult EmulatorPEHarness::Run(std::span<const uint8_t> input) noexcept {
    HarnessResult result{};

    try {
        const DWORD exceptionCode = SEHCallPE(
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

HarnessFunction EmulatorPEHarness::GetHarnessFunction() noexcept {
    return [](std::span<const uint8_t> input) -> HarnessResult {
        return Run(input);
    };
}

std::string_view EmulatorPEHarness::GetName() noexcept {
    return "emu-pe";
}

std::string_view EmulatorPEHarness::GetDescription() noexcept {
    return "PhantomEmulator PE parser/loader/CPU fuzz harness for PE32, PE64, and DLL entry paths";
}

int RunEmulatorPEFuzzer(
    const std::filesystem::path& workspaceDir,
    const FuzzLoopConfig& config) noexcept
{
    if (!InstallCtrlCHandler()) {
        std::cerr << "[EmuPEFuzzer] Warning: Failed to install Ctrl+C handler\n";
    }

    const auto corpusDir = workspaceDir / "corpora" / "emulator" / "pe";
    const auto crashDir = workspaceDir / "crashes" / "emulator" / "pe";

    std::error_code ec;
    std::filesystem::create_directories(corpusDir, ec);
    if (ec) {
        std::cerr << "[EmuPEFuzzer] Failed to create corpus directory: " << corpusDir << '\n';
        return 1;
    }

    ec.clear();
    std::filesystem::create_directories(crashDir, ec);
    if (ec) {
        std::cerr << "[EmuPEFuzzer] Failed to create crash directory: " << crashDir << '\n';
        return 1;
    }

    EnsureSeedCorpus(corpusDir);

    FuzzLoopConfig loopConfig = config;
    loopConfig.targetName = std::string(EmulatorPEHarness::GetName());

    std::cout << "[EmuPEFuzzer] Starting emulator PE fuzzing...\n";
    std::cout << "[EmuPEFuzzer] Corpus: " << corpusDir << '\n';
    std::cout << "[EmuPEFuzzer] Crashes: " << crashDir << '\n';

    FuzzLoop loop(corpusDir, crashDir, EmulatorPEHarness::GetHarnessFunction(), loopConfig);
    const bool success = loop.Run();
    const auto& stats = loop.GetStatistics();

    std::cout << "\n[EmuPEFuzzer] Final Results:\n";
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

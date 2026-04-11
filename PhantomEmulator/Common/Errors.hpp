/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 * Copyright (C) 2025-2026 ShadowStrike Labs
 *
 * AGPL-3.0 License
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <stdexcept>

namespace Phantom {

// ============================================================================
// Error Categories
// ============================================================================

enum class ErrorCode : uint32_t {
    Success = 0,

    // Decoder errors (1xx)
    InvalidOpcode         = 100,
    InvalidPrefix         = 101,
    InvalidModRM          = 102,
    InstructionTooLong    = 103,
    UnsupportedOpcode     = 104,
    InvalidREXPrefix      = 105,
    TruncatedInstruction  = 106,

    // Executor errors (2xx)
    DivideByZero          = 200,
    DivideOverflow        = 201,
    InvalidOperandSize    = 202,
    UnimplementedOpcode   = 203,
    StackOverflow         = 204,
    StackUnderflow        = 205,
    InvalidSystemCall     = 206,
    PrivilegedInstruction = 207,
    ControlProtectionFault = 208,  // CET: shadow stack / IBT violation

    // Memory errors (3xx)
    AccessViolationRead   = 300,
    AccessViolationWrite  = 301,
    AccessViolationExec   = 302,
    GuardPageViolation    = 303,
    OutOfMemory           = 304,
    InvalidAddress        = 305,
    AddressOverflow       = 306,
    UnalignedAccess       = 307,
    PageNotPresent        = 308,
    MemoryLimitExceeded   = 309,
    DoubleFree            = 310,
    UseAfterFree          = 311,

    // Loader errors (4xx)
    InvalidPESignature    = 400,
    InvalidPEHeader       = 401,
    UnsupportedMachine    = 402,
    SectionOverflow       = 403,
    ImportResolutionFail  = 404,
    RelocApplyFail        = 405,
    TLSCallbackFail       = 406,
    MalformedPE           = 407,
    PETooLarge            = 408,
    InvalidEntryPoint     = 409,

    // API emulation errors (5xx)
    UnknownAPI            = 500,
    APIParameterInvalid   = 501,
    APINotImplemented     = 502,
    HandleTableFull       = 503,
    InvalidHandle         = 504,
    FileNotFound          = 505,
    AccessDenied          = 506,
    BufferOverflow        = 507,

    // Thread errors (6xx)
    ThreadLimitExceeded   = 600,
    ThreadCreateFailed    = 601,
    DeadlockDetected      = 602,
    InvalidThreadId       = 603,

    // Session errors (7xx)
    SessionNotInitialized = 700,
    SessionAlreadyRunning = 701,
    TimeLimitExceeded     = 702,
    InstructionLimit      = 703,
    UserAborted           = 704,
    InternalError         = 705,

    // Analysis errors (8xx)
    PatternBufferFull     = 800,
    AnalysisTimeout       = 801,
    IOCExtractionFail     = 802,
};

// ============================================================================
// Error Category for std::error_code integration
// ============================================================================

class EmulatorErrorCategory : public std::error_category {
public:
    [[nodiscard]] const char* name() const noexcept override {
        return "PhantomEmulator";
    }

    [[nodiscard]] std::string message(int code) const override {
        switch (static_cast<ErrorCode>(code)) {
            case ErrorCode::Success:              return "Success";
            case ErrorCode::InvalidOpcode:        return "Invalid opcode";
            case ErrorCode::InvalidPrefix:        return "Invalid instruction prefix";
            case ErrorCode::InvalidModRM:         return "Invalid ModR/M byte";
            case ErrorCode::InstructionTooLong:   return "Instruction exceeds 15-byte limit";
            case ErrorCode::UnsupportedOpcode:    return "Unsupported opcode";
            case ErrorCode::TruncatedInstruction: return "Truncated instruction stream";
            case ErrorCode::DivideByZero:         return "Division by zero";
            case ErrorCode::DivideOverflow:       return "Division overflow";
            case ErrorCode::StackOverflow:        return "Stack overflow";
            case ErrorCode::AccessViolationRead:  return "Read access violation";
            case ErrorCode::AccessViolationWrite: return "Write access violation";
            case ErrorCode::AccessViolationExec:  return "Execute access violation";
            case ErrorCode::OutOfMemory:          return "Out of guest memory";
            case ErrorCode::InvalidPESignature:   return "Invalid PE signature";
            case ErrorCode::MalformedPE:          return "Malformed PE structure";
            case ErrorCode::UnknownAPI:           return "Unknown API call";
            case ErrorCode::InternalError:        return "Internal emulator error";
            default:                              return "Unknown error (" + std::to_string(code) + ")";
        }
    }
};

[[nodiscard]] inline const EmulatorErrorCategory& GetEmulatorErrorCategory() noexcept {
    static const EmulatorErrorCategory instance;
    return instance;
}

[[nodiscard]] inline std::error_code MakeError(ErrorCode code) noexcept {
    return { static_cast<int>(code), GetEmulatorErrorCategory() };
}

// ============================================================================
// Exception Types (used only at session boundaries — not in hot paths)
// ============================================================================

class EmulationException : public std::runtime_error {
public:
    explicit EmulationException(ErrorCode code, std::string_view detail = {})
        : std::runtime_error(BuildMessage(code, detail))
        , m_code(code) {}

    [[nodiscard]] ErrorCode Code() const noexcept { return m_code; }

private:
    ErrorCode m_code;

    static std::string BuildMessage(ErrorCode code, std::string_view detail) {
        auto msg = GetEmulatorErrorCategory().message(static_cast<int>(code));
        if (!detail.empty()) {
            msg += ": ";
            msg.append(detail.data(), detail.size());
        }
        return msg;
    }
};

class DecoderException : public EmulationException {
public:
    using EmulationException::EmulationException;
};

class MemoryException : public EmulationException {
    GuestAddress m_faultAddress = 0;
public:
    MemoryException(ErrorCode code, GuestAddress faultAddr, std::string_view detail = {})
        : EmulationException(code, detail)
        , m_faultAddress(faultAddr) {}

    [[nodiscard]] GuestAddress FaultAddress() const noexcept { return m_faultAddress; }
};

} // namespace Phantom

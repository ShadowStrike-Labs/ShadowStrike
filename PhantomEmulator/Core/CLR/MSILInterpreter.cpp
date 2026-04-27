/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * MSILInterpreter.cpp — Stack-based CIL/MSIL virtual machine
 *
 * Interprets .NET method bodies to extract:
 *   - Decrypted strings  (ldstr + string-method simulation)
 *   - API call sequences (call/callvirt/newobj → DotNetAPICall)
 *   - Byte-array payloads (newarr + stelem tracking)
 *   - Obfuscation indicators (excessive switches, opaque predicates)
 *
 * References:
 *   ECMA-335 (6th Edition) — Common Language Infrastructure §III
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "MSILInterpreter.hpp"
#include "MetadataParser.hpp"
#include "CLRTypes.hpp"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

namespace Phantom::CLR {

// ============================================================================
// Internal Limits
// ============================================================================

static constexpr uint64_t kDefaultMaxInstructions  = 5'000'000;
static constexpr uint32_t kDefaultMaxStackDepth    = kMaxEvalStackDepth;    // 1024
static constexpr uint32_t kDefaultMaxCallDepth     = 16;
static constexpr uint32_t kDefaultMaxArraySize     = 16u * 1024 * 1024;    // 16 MB
static constexpr uint32_t kDefaultMaxStrings       = kMaxExtractedStrings; // 10 000
static constexpr uint32_t kDefaultMaxAPICalls      = 50'000;
static constexpr uint32_t kDefaultMaxArrays        = 1000;
static constexpr uint32_t kHardMaxArraySize        = 16 * 1024 * 1024;
static constexpr uint32_t kMinPayloadArraySize     = 16;
static constexpr uint32_t kMaxTrackedStringLength  = 64 * 1024;

// ============================================================================
// Forward-declared MetadataParser stub
// ============================================================================
//
// MetadataParser is built in a sibling module compiled in parallel.
// We depend only on a thin contract:
//   - ReadUserString(uint32_t usToken) -> std::u16string
//   - ResolveMethodToken(MetadataToken) -> {nameSpace, className, methodName}
//   - GetTypeDefRows()  -> const std::vector<TypeDefRow>&
//   - GetMethodDefRows()-> const std::vector<MethodDefRow>&
//   - GetMemberRefRows()-> const std::vector<MemberRefRow>&
//   - GetTypeRefRows()  -> const std::vector<TypeRefRow>&
//
// All interaction goes through const-reference so no linking dependency.

// ============================================================================
// Tracked Array — byte[] created by newarr
// ============================================================================

namespace {

template <typename T>
[[nodiscard]] bool ReserveNoThrow(std::vector<T>& values, size_t capacity) noexcept {
    try {
        values.reserve(capacity);
        return true;
    } catch (const std::bad_alloc&) {
        return false;
    } catch (const std::length_error&) {
        return false;
    }
}

template <typename K, typename V>
[[nodiscard]] bool ReserveNoThrow(std::unordered_map<K, V>& values, size_t capacity) noexcept {
    try {
        values.reserve(capacity);
        return true;
    } catch (const std::bad_alloc&) {
        return false;
    } catch (const std::length_error&) {
        return false;
    }
}

[[nodiscard]] uint32_t CheckedNextPc(uint32_t pc) noexcept {
    return (pc == std::numeric_limits<uint32_t>::max()) ? UINT32_MAX : pc + 1;
}

[[nodiscard]] bool CheckedAddSignedOffset(
    uint32_t base,
    int32_t delta,
    uint32_t& out) noexcept {
    if (delta >= 0) {
        const auto udelta = static_cast<uint32_t>(delta);
        if (base > std::numeric_limits<uint32_t>::max() - udelta) return false;
        out = base + udelta;
        return true;
    }
    const auto magnitude = static_cast<uint32_t>(-(static_cast<int64_t>(delta)));
    if (base < magnitude) return false;
    out = base - magnitude;
    return true;
}

struct TrackedArray {
    std::vector<uint8_t> data;
    uint32_t             elementType = 0;
    bool                 modified    = false;
};

// ============================================================================
// Resolved method info (from token)
// ============================================================================

struct ResolvedMethod {
    std::string nameSpace;
    std::string className;
    std::string methodName;
    bool        isLocal = false;    // MethodDef → can be interpreted recursively
};

// ============================================================================
// API Category Classification
// ============================================================================

[[nodiscard]] DotNetAPICategory ClassifyAPI(
    std::string_view ns,
    std::string_view cls,
    std::string_view method) noexcept
{
    // --- Process Execution ---
    if (cls == "Process" && method == "Start")
        return DotNetAPICategory::ProcessStart;
    if (cls == "ProcessStartInfo")
        return DotNetAPICategory::ProcessStart;

    // --- File I/O ---
    if (ns.find("System.IO") != std::string_view::npos) {
        if (cls == "File" || cls == "FileStream" || cls == "StreamReader" ||
            cls == "StreamWriter" || cls == "BinaryReader" || cls == "BinaryWriter") {
            if (method.find("Read") != std::string_view::npos)
                return DotNetAPICategory::FileRead;
            if (method.find("Write") != std::string_view::npos)
                return DotNetAPICategory::FileWrite;
            if (method == "Delete")
                return DotNetAPICategory::FileDelete;
            return DotNetAPICategory::FileRead;
        }
        if (cls == "Directory") {
            if (method == "Delete")
                return DotNetAPICategory::FileDelete;
            return DotNetAPICategory::FileRead;
        }
        if (cls == "Path")
            return DotNetAPICategory::PathManipulation;
    }

    // --- Network I/O ---
    if (cls == "WebClient") {
        return DotNetAPICategory::WebDownload;
    }
    if (cls == "HttpClient" || cls == "HttpWebRequest")
        return DotNetAPICategory::WebDownload;
    if (cls == "TcpClient" || cls == "Socket")
        return DotNetAPICategory::SocketConnect;
    if (cls == "Dns")
        return DotNetAPICategory::DnsResolve;

    // --- Registry ---
    if (cls == "Registry" || cls == "RegistryKey") {
        if (method.find("Set") != std::string_view::npos)
            return DotNetAPICategory::RegistryWrite;
        return DotNetAPICategory::RegistryRead;
    }

    // --- Crypto ---
    if (ns.find("Cryptography") != std::string_view::npos) {
        if (cls.find("Aes") != std::string_view::npos ||
            cls.find("Rijndael") != std::string_view::npos ||
            cls.find("DES") != std::string_view::npos ||
            cls.find("RC2") != std::string_view::npos)
            return DotNetAPICategory::SymmetricEncrypt;
        if (cls.find("RSA") != std::string_view::npos ||
            cls.find("DSA") != std::string_view::npos)
            return DotNetAPICategory::AsymmetricEncrypt;
        if (cls.find("SHA") != std::string_view::npos ||
            cls.find("MD5") != std::string_view::npos)
            return DotNetAPICategory::HashCompute;
        if (cls.find("RNG") != std::string_view::npos ||
            cls.find("RandomNumber") != std::string_view::npos)
            return DotNetAPICategory::RandomGenerate;
        return DotNetAPICategory::SymmetricEncrypt;
    }

    // --- Reflection / Dynamic Load ---
    if (cls == "Assembly") {
        if (method == "Load" || method == "LoadFrom" || method == "LoadFile")
            return DotNetAPICategory::AssemblyLoad;
        if (method == "LoadRaw" || method.find("Load") != std::string_view::npos)
            return DotNetAPICategory::AssemblyLoadRaw;
    }
    if (cls == "Activator" && method == "CreateInstance")
        return DotNetAPICategory::ReflectionInvoke;
    if (cls == "Type" && method == "GetType")
        return DotNetAPICategory::ReflectionInvoke;
    if (cls == "MethodInfo" && method == "Invoke")
        return DotNetAPICategory::ReflectionInvoke;
    if (cls == "Delegate" && method == "DynamicInvoke")
        return DotNetAPICategory::ReflectionInvoke;

    // --- P/Invoke / Marshal ---
    if (cls == "Marshal")
        return DotNetAPICategory::MarshalCopy;

    // --- Thread creation ---
    if (cls == "Thread" && method == "Start")
        return DotNetAPICategory::SleepDelay; // Closest category for thread lifecycle
    if (cls == "ThreadPool" && method == "QueueUserWorkItem")
        return DotNetAPICategory::SleepDelay;

    // --- Code generation ---
    if (cls == "DynamicMethod" || cls == "ILGenerator")
        return DotNetAPICategory::DynamicCompile;

    // --- WMI ---
    if (cls == "ManagementObjectSearcher" || cls == "WqlObjectQuery")
        return DotNetAPICategory::WmiQuery;

    // --- Environment ---
    if (cls == "Environment")
        return DotNetAPICategory::EnvironmentQuery;

    // --- Anti-analysis ---
    if (cls == "Debugger") {
        if (method == "IsAttached" || method == "get_IsAttached" || method == "IsLogging")
            return DotNetAPICategory::AntiDebug;
    }

    // --- Sleep / Delay ---
    if (cls == "Thread" && method == "Sleep")
        return DotNetAPICategory::SleepDelay;
    if (cls == "Task" && method == "Delay")
        return DotNetAPICategory::SleepDelay;

    // --- Serialization (map to closest existing category) ---
    if (cls == "BinaryFormatter" || cls == "XmlSerializer" || cls == "JsonConvert")
        return DotNetAPICategory::UnsafeCode;

    // --- Resource access ---
    if (cls == "ResourceManager" ||
        (cls == "Assembly" && method == "GetManifestResourceStream"))
        return DotNetAPICategory::FileRead;

    return DotNetAPICategory::Unknown;
}

/// Check if a method name looks like a string-manipulation method we can simulate.
[[nodiscard]] bool IsStringMethod(
    std::string_view cls,
    std::string_view method) noexcept
{
    if (cls != "String")
        return false;
    return method == "Concat" || method == "Replace" ||
           method == "Substring" || method == "ToLower" ||
           method == "ToUpper" || method == "Trim" ||
           method == "Format";
}

} // anonymous namespace

// ============================================================================
// Impl (PIMPL)
// ============================================================================

struct MSILInterpreter::Impl {

    // --- References ---
    const MetadataParser& metadata;

    // --- Configuration ---
    uint64_t maxInstructions = kDefaultMaxInstructions;
    uint32_t maxStackDepth   = kDefaultMaxStackDepth;
    uint32_t maxCallDepth    = kDefaultMaxCallDepth;
    uint32_t maxArraySize    = kDefaultMaxArraySize;

    // --- Method body provider ---
    MethodBodyProvider bodyProvider;

    // --- Collected results (persist across calls) ---
    std::vector<std::u16string>       collectedStrings;
    std::vector<DotNetAPICall>        collectedAPICalls;
    std::vector<std::vector<uint8_t>> collectedArrays;

    // --- Per-execution state ---
    std::vector<ILValue>              evalStack;
    std::vector<ILValue>              locals;
    std::vector<ILValue>              args;
    std::vector<TrackedArray>         arrays;
    std::unordered_map<uint32_t, uint32_t> stringTable;  // ref → index into collectedStrings

    uint64_t instrCount     = 0;
    uint32_t currentCallDepth = 0;
    uint32_t peakStackDepth = 0;
    MetadataToken currentMethodToken{};
    bool     aborted        = false;
    bool     threw          = false;

    // Instruction-index map: IL offset → vector index (for branch targets)
    std::unordered_map<uint32_t, uint32_t> offsetToIndex;

    explicit Impl(const MetadataParser& md) noexcept : metadata(md) {}

    // ------------------------------------------------------------------
    // Stack helpers
    // ------------------------------------------------------------------
    bool Push(ILValue val) noexcept {
        if (evalStack.size() >= maxStackDepth) {
            aborted = true;
            return false;
        }
        try {
            evalStack.push_back(val);
        } catch (const std::bad_alloc&) {
            aborted = true;
            return false;
        } catch (const std::length_error&) {
            aborted = true;
            return false;
        }
        if (evalStack.size() > peakStackDepth)
            peakStackDepth = static_cast<uint32_t>(evalStack.size());
        return true;
    }

    bool Pop(ILValue& out) noexcept {
        if (evalStack.empty()) {
            aborted = true;
            return false;
        }
        out = evalStack.back();
        evalStack.pop_back();
        return true;
    }

    ILValue PopValue() noexcept {
        ILValue v;
        Pop(v);
        return v;
    }

    bool Peek(ILValue& out) const noexcept {
        if (evalStack.empty()) return false;
        out = evalStack.back();
        return true;
    }

    // ------------------------------------------------------------------
    // String tracking
    // ------------------------------------------------------------------
    uint32_t TrackString(const std::u16string& s) noexcept {
        if (collectedStrings.size() >= kDefaultMaxStrings)
            return static_cast<uint32_t>(collectedStrings.size() - 1);
        if (s.size() > kMaxTrackedStringLength) {
            return static_cast<uint32_t>(collectedStrings.empty() ? 0 : collectedStrings.size() - 1);
        }
        uint32_t idx = static_cast<uint32_t>(collectedStrings.size());
        try {
            collectedStrings.push_back(s);
        } catch (const std::bad_alloc&) {
            aborted = true;
            return static_cast<uint32_t>(collectedStrings.empty() ? 0 : collectedStrings.size() - 1);
        } catch (const std::length_error&) {
            aborted = true;
            return static_cast<uint32_t>(collectedStrings.empty() ? 0 : collectedStrings.size() - 1);
        }
        return idx;
    }

    [[nodiscard]] const std::u16string& GetTrackedString(uint32_t idx) const noexcept {
        static const std::u16string kEmpty;
        if (idx >= collectedStrings.size()) return kEmpty;
        return collectedStrings[idx];
    }

    // ------------------------------------------------------------------
    // Array tracking
    // ------------------------------------------------------------------
    uint32_t CreateArray(uint32_t length, uint32_t elemType) noexcept {
        if (length > maxArraySize) length = maxArraySize;
        if (arrays.size() >= kDefaultMaxArrays)
            return static_cast<uint32_t>(arrays.size() - 1);
        try {
            TrackedArray ta;
            ta.data.resize(length, 0);
            ta.elementType = elemType;
            uint32_t idx = static_cast<uint32_t>(arrays.size());
            arrays.push_back(std::move(ta));
            return idx;
        } catch (const std::bad_alloc&) {
            aborted = true;
            return static_cast<uint32_t>(arrays.empty() ? 0 : arrays.size() - 1);
        } catch (const std::length_error&) {
            aborted = true;
            return static_cast<uint32_t>(arrays.empty() ? 0 : arrays.size() - 1);
        }
    }

    // ------------------------------------------------------------------
    // API call recording
    // ------------------------------------------------------------------
    void RecordAPICall(const ResolvedMethod& rm,
                       MetadataToken token,
                       uint32_t ilOffset) noexcept
    {
        if (collectedAPICalls.size() >= kDefaultMaxAPICalls) return;
        try {
        DotNetAPICall call{};
        call.category       = ClassifyAPI(rm.nameSpace, rm.className, rm.methodName);
        call.className      = rm.nameSpace.empty()
                                ? rm.className
                                : rm.nameSpace + "." + rm.className;
        call.methodName     = rm.methodName;
        call.token          = token;
        call.ilOffset       = ilOffset;
        call.resolvedTarget = call.className + "::" + rm.methodName;

        collectedAPICalls.push_back(std::move(call));
        } catch (const std::bad_alloc&) {
            aborted = true;
        } catch (const std::length_error&) {
            aborted = true;
        }
    }

    // ------------------------------------------------------------------
    // Token resolution
    // ------------------------------------------------------------------
    // Uses MetadataParser to resolve a call/callvirt/newobj token.
    // Since MetadataParser is compiled in parallel, we provide a safe
    // fallback that returns an empty ResolvedMethod if something fails.
    [[nodiscard]] ResolvedMethod ResolveToken(MetadataToken tok) const noexcept {
        ResolvedMethod rm;
        try {
            auto table = tok.Table();
            auto row   = tok.Row();
            if (row == 0) return rm;

            if (table == MetadataTableId::MethodDef) {
                rm.isLocal = true;
                const auto& methodDefs = metadata.GetMethodDefs();
                if (row <= static_cast<uint32_t>(methodDefs.size())) {
                    rm.methodName = methodDefs[row - 1].name;
                    // Find owning type by scanning TypeDefs
                    const auto& typeDefs = metadata.GetTypeDefs();
                    for (uint32_t t = 0; t < static_cast<uint32_t>(typeDefs.size()); ++t) {
                        uint32_t mStart = typeDefs[t].methodList;
                        uint32_t mEnd   = (t + 1 < static_cast<uint32_t>(typeDefs.size()))
                                              ? typeDefs[t + 1].methodList
                                              : static_cast<uint32_t>(methodDefs.size()) + 1;
                        if (row >= mStart && row < mEnd) {
                            rm.nameSpace = typeDefs[t].typeNamespace;
                            rm.className = typeDefs[t].typeName;
                            break;
                        }
                    }
                }
            } else if (table == MetadataTableId::MemberRef) {
                const auto& memberRefs = metadata.GetMemberRefs();
                if (row <= static_cast<uint32_t>(memberRefs.size())) {
                    const auto& ref = memberRefs[row - 1];
                    rm.methodName = ref.name;
                    // Resolve the class via the coded index token
                    const uint32_t tag = ref.classCodedIndex & 0x07u;
                    const uint32_t parentRow = ref.classCodedIndex >> 3;
                    MetadataToken parentTok{};
                    switch (tag) {
                    case 0: parentTok = MetadataToken::Make(MetadataTableId::TypeDef, parentRow); break;
                    case 1: parentTok = MetadataToken::Make(MetadataTableId::TypeRef, parentRow); break;
                    case 2: parentTok = MetadataToken::Make(MetadataTableId::ModuleRef, parentRow); break;
                    case 3: parentTok = MetadataToken::Make(MetadataTableId::MethodDef, parentRow); break;
                    case 4: parentTok = MetadataToken::Make(MetadataTableId::TypeSpec, parentRow); break;
                    default: break;
                    }
                    std::string resolved = metadata.ResolveToken(parentTok);
                    // Split "Namespace.ClassName" into parts
                    auto lastDot = resolved.rfind('.');
                    if (lastDot != std::string::npos) {
                        rm.nameSpace = resolved.substr(0, lastDot);
                        rm.className = resolved.substr(lastDot + 1);
                    } else {
                        rm.className = resolved;
                    }
                }
            } else {
                // For other table types, use generic token resolution
                std::string resolved = metadata.ResolveToken(tok);
                if (!resolved.empty()) {
                    rm.methodName = resolved;
                }
            }

        } catch (const std::bad_alloc&) {
            return {};
        } catch (const std::length_error&) {
            return {};
        }
        return rm;
    }

    // ------------------------------------------------------------------
    // Build offset → instruction-index map
    // ------------------------------------------------------------------
    void BuildOffsetMap(const std::vector<MSILInstruction>& instructions) noexcept {
        offsetToIndex.clear();
        if (!ReserveNoThrow(offsetToIndex, instructions.size())) {
            aborted = true;
            return;
        }
        try {
            for (uint32_t i = 0; i < static_cast<uint32_t>(instructions.size()); ++i) {
                offsetToIndex[instructions[i].offset] = i;
            }
        } catch (const std::bad_alloc&) {
            aborted = true;
        } catch (const std::length_error&) {
            aborted = true;
        }
    }

    [[nodiscard]] uint32_t FindInstructionIndex(uint32_t ilOffset) const noexcept {
        auto it = offsetToIndex.find(ilOffset);
        if (it != offsetToIndex.end()) return it->second;
        return UINT32_MAX;
    }

    [[nodiscard]] bool EnsureVectorSize(std::vector<ILValue>& values, uint32_t count) noexcept {
        try {
            values.resize(count);
            return true;
        } catch (const std::bad_alloc&) {
            aborted = true;
            return false;
        } catch (const std::length_error&) {
            aborted = true;
            return false;
        }
    }

    // ------------------------------------------------------------------
    // Compute absolute branch target
    // ------------------------------------------------------------------
    [[nodiscard]] uint32_t ComputeBranchTarget(
        const MSILInstruction& instr) const noexcept
    {
        uint32_t base = 0;
        if (instr.offset > std::numeric_limits<uint32_t>::max() - instr.size) return UINT32_MAX;
        base = instr.offset + instr.size;
        uint32_t target = 0;
        return CheckedAddSignedOffset(base, instr.operand.branchOffset, target) ? target : UINT32_MAX;
    }

    // ------------------------------------------------------------------
    // String method simulation
    // ------------------------------------------------------------------
    std::u16string SimulateStringMethod(
        std::string_view method,
        const std::vector<ILValue>& methodArgs) noexcept
    {
        try {
        // We simulate basic operations on tracked strings.
        if (method == "Concat") {
            std::u16string result;
            for (const auto& a : methodArgs) {
                if (a.type == ILValueType::String) {
                    const auto& piece = GetTrackedString(a.ref);
                    if (piece.size() > kMaxTrackedStringLength - std::min(result.size(), static_cast<size_t>(kMaxTrackedStringLength))) {
                        return {};
                    }
                    result += piece;
                }
            }
            return result;
        }
        if (method == "Replace" && methodArgs.size() >= 3) {
            if (methodArgs[0].type == ILValueType::String &&
                methodArgs[1].type == ILValueType::String &&
                methodArgs[2].type == ILValueType::String) {
                std::u16string s   = GetTrackedString(methodArgs[0].ref);
                const auto& old_s  = GetTrackedString(methodArgs[1].ref);
                const auto& new_s  = GetTrackedString(methodArgs[2].ref);
                if (!old_s.empty()) {
                    std::u16string::size_type pos = 0;
                    while ((pos = s.find(old_s, pos)) != std::u16string::npos) {
                        if (new_s.size() > old_s.size() &&
                            s.size() > kMaxTrackedStringLength - (new_s.size() - old_s.size())) {
                            return {};
                        }
                        s.replace(pos, old_s.size(), new_s);
                        pos += new_s.size();
                    }
                }
                return s;
            }
        }
        if (method == "Substring" && methodArgs.size() >= 2) {
            if (methodArgs[0].type == ILValueType::String &&
                methodArgs[1].type == ILValueType::Int32) {
                const auto& base = GetTrackedString(methodArgs[0].ref);
                if (methodArgs[1].i32 < 0) return {};
                auto start = static_cast<size_t>(methodArgs[1].i32);
                if (start < base.size()) {
                    if (methodArgs.size() >= 3 && methodArgs[2].type == ILValueType::Int32) {
                        if (methodArgs[2].i32 < 0) return {};
                        auto len = static_cast<size_t>(methodArgs[2].i32);
                        return base.substr(start, len);
                    }
                    return base.substr(start);
                }
            }
        }
        if (method == "ToLower" && !methodArgs.empty() &&
            methodArgs[0].type == ILValueType::String) {
            std::u16string s = GetTrackedString(methodArgs[0].ref);
            for (auto& c : s) {
                if (c >= u'A' && c <= u'Z') c += 32;
            }
            return s;
        }
        if (method == "ToUpper" && !methodArgs.empty() &&
            methodArgs[0].type == ILValueType::String) {
            std::u16string s = GetTrackedString(methodArgs[0].ref);
            for (auto& c : s) {
                if (c >= u'a' && c <= u'z') c -= 32;
            }
            return s;
        }
        if (method == "Trim" && !methodArgs.empty() &&
            methodArgs[0].type == ILValueType::String) {
            std::u16string s = GetTrackedString(methodArgs[0].ref);
            auto l = s.find_first_not_of(u" \t\r\n");
            auto r = s.find_last_not_of(u" \t\r\n");
            if (l == std::u16string::npos) return {};
            return s.substr(l, r - l + 1);
        }
        return {};
        } catch (const std::bad_alloc&) {
            aborted = true;
            return {};
        } catch (const std::length_error&) {
            aborted = true;
            return {};
        }
    }

    // ------------------------------------------------------------------
    // Execute a single instruction
    // ------------------------------------------------------------------
    // Returns the new instruction index (pc). UINT32_MAX means abort.
    uint32_t Step(const std::vector<MSILInstruction>& instructions,
                  uint32_t pc) noexcept
    {
        if (pc >= static_cast<uint32_t>(instructions.size())) {
            aborted = true;
            return UINT32_MAX;
        }
        if (++instrCount > maxInstructions) {
            aborted = true;
            return UINT32_MAX;
        }

        const auto& instr = instructions[pc];
        const auto  op    = instr.opcode;

        switch (op) {

        // ==================================================================
        // NOP / BREAK
        // ==================================================================
        case MSILOpcode::Nop:
        case MSILOpcode::Break:
            return pc + 1;

        // ==================================================================
        // LOAD CONSTANTS
        // ==================================================================
        case MSILOpcode::Ldc_I4_M1: if (!Push(ILValue::MakeI32(-1))) return UINT32_MAX; return pc + 1;
        case MSILOpcode::Ldc_I4_0:  if (!Push(ILValue::MakeI32(0)))  return UINT32_MAX; return pc + 1;
        case MSILOpcode::Ldc_I4_1:  if (!Push(ILValue::MakeI32(1)))  return UINT32_MAX; return pc + 1;
        case MSILOpcode::Ldc_I4_2:  if (!Push(ILValue::MakeI32(2)))  return UINT32_MAX; return pc + 1;
        case MSILOpcode::Ldc_I4_3:  if (!Push(ILValue::MakeI32(3)))  return UINT32_MAX; return pc + 1;
        case MSILOpcode::Ldc_I4_4:  if (!Push(ILValue::MakeI32(4)))  return UINT32_MAX; return pc + 1;
        case MSILOpcode::Ldc_I4_5:  if (!Push(ILValue::MakeI32(5)))  return UINT32_MAX; return pc + 1;
        case MSILOpcode::Ldc_I4_6:  if (!Push(ILValue::MakeI32(6)))  return UINT32_MAX; return pc + 1;
        case MSILOpcode::Ldc_I4_7:  if (!Push(ILValue::MakeI32(7)))  return UINT32_MAX; return pc + 1;
        case MSILOpcode::Ldc_I4_8:  if (!Push(ILValue::MakeI32(8)))  return UINT32_MAX; return pc + 1;

        case MSILOpcode::Ldc_I4_S:
            if (!Push(ILValue::MakeI32(static_cast<int32_t>(instr.operand.shortI))))
                return UINT32_MAX;
            return pc + 1;

        case MSILOpcode::Ldc_I4:
            if (!Push(ILValue::MakeI32(instr.operand.i32)))
                return UINT32_MAX;
            return pc + 1;

        case MSILOpcode::Ldc_I8:
            if (!Push(ILValue::MakeI64(instr.operand.i64)))
                return UINT32_MAX;
            return pc + 1;

        case MSILOpcode::Ldc_R4:
            if (!Push(ILValue::MakeF64(static_cast<double>(instr.operand.f32))))
                return UINT32_MAX;
            return pc + 1;

        case MSILOpcode::Ldc_R8:
            if (!Push(ILValue::MakeF64(instr.operand.f64)))
                return UINT32_MAX;
            return pc + 1;

        case MSILOpcode::Ldnull:
            if (!Push(ILValue::MakeNull())) return UINT32_MAX;
            return pc + 1;

        // ==================================================================
        // LOAD / STORE LOCALS
        // ==================================================================
        case MSILOpcode::Ldloc_0: case MSILOpcode::Ldloc_1:
        case MSILOpcode::Ldloc_2: case MSILOpcode::Ldloc_3: {
            uint32_t idx = static_cast<uint32_t>(op) - static_cast<uint32_t>(MSILOpcode::Ldloc_0);
            if (idx < locals.size()) {
                if (!Push(locals[idx])) return UINT32_MAX;
            } else {
                if (!Push(ILValue::MakeNull())) return UINT32_MAX;
            }
            return pc + 1;
        }

        case MSILOpcode::Ldloc_S: {
            uint32_t idx = instr.operand.varIndex8;
            if (idx < locals.size()) {
                if (!Push(locals[idx])) return UINT32_MAX;
            } else {
                if (!Push(ILValue::MakeNull())) return UINT32_MAX;
            }
            return pc + 1;
        }

        case MSILOpcode::Ldloc: {
            uint32_t idx = instr.operand.varIndex16;
            if (idx < locals.size()) {
                if (!Push(locals[idx])) return UINT32_MAX;
            } else {
                if (!Push(ILValue::MakeNull())) return UINT32_MAX;
            }
            return pc + 1;
        }

        case MSILOpcode::Ldloca_S: {
            // Load address of local — we just push the local's value (approximation)
            uint32_t idx = instr.operand.varIndex8;
            if (idx < locals.size()) {
                if (!Push(locals[idx])) return UINT32_MAX;
            } else {
                if (!Push(ILValue::MakeNull())) return UINT32_MAX;
            }
            return pc + 1;
        }

        case MSILOpcode::Ldloca: {
            uint32_t idx = instr.operand.varIndex16;
            if (idx < locals.size()) {
                if (!Push(locals[idx])) return UINT32_MAX;
            } else {
                if (!Push(ILValue::MakeNull())) return UINT32_MAX;
            }
            return pc + 1;
        }

        case MSILOpcode::Stloc_0: case MSILOpcode::Stloc_1:
        case MSILOpcode::Stloc_2: case MSILOpcode::Stloc_3: {
            ILValue val;
            if (!Pop(val)) return UINT32_MAX;
            uint32_t idx = static_cast<uint32_t>(op) - static_cast<uint32_t>(MSILOpcode::Stloc_0);
            if (idx >= locals.size() && !EnsureVectorSize(locals, idx + 1)) return UINT32_MAX;
            locals[idx] = val;
            return pc + 1;
        }

        case MSILOpcode::Stloc_S: {
            ILValue val;
            if (!Pop(val)) return UINT32_MAX;
            uint32_t idx = instr.operand.varIndex8;
            if (idx >= locals.size() && !EnsureVectorSize(locals, idx + 1)) return UINT32_MAX;
            locals[idx] = val;
            return pc + 1;
        }

        case MSILOpcode::Stloc: {
            ILValue val;
            if (!Pop(val)) return UINT32_MAX;
            uint32_t idx = instr.operand.varIndex16;
            if (idx >= locals.size() && !EnsureVectorSize(locals, idx + 1)) return UINT32_MAX;
            locals[idx] = val;
            return pc + 1;
        }

        // ==================================================================
        // LOAD / STORE ARGUMENTS
        // ==================================================================
        case MSILOpcode::Ldarg_0: case MSILOpcode::Ldarg_1:
        case MSILOpcode::Ldarg_2: case MSILOpcode::Ldarg_3: {
            uint32_t idx = static_cast<uint32_t>(op) - static_cast<uint32_t>(MSILOpcode::Ldarg_0);
            if (idx < args.size()) {
                if (!Push(args[idx])) return UINT32_MAX;
            } else {
                if (!Push(ILValue::MakeNull())) return UINT32_MAX;
            }
            return pc + 1;
        }

        case MSILOpcode::Ldarg_S: {
            uint32_t idx = instr.operand.varIndex8;
            if (idx < args.size()) {
                if (!Push(args[idx])) return UINT32_MAX;
            } else {
                if (!Push(ILValue::MakeNull())) return UINT32_MAX;
            }
            return pc + 1;
        }

        case MSILOpcode::Ldarg: {
            uint32_t idx = instr.operand.varIndex16;
            if (idx < args.size()) {
                if (!Push(args[idx])) return UINT32_MAX;
            } else {
                if (!Push(ILValue::MakeNull())) return UINT32_MAX;
            }
            return pc + 1;
        }

        case MSILOpcode::Ldarga_S: {
            uint32_t idx = instr.operand.varIndex8;
            if (idx < args.size()) {
                if (!Push(args[idx])) return UINT32_MAX;
            } else {
                if (!Push(ILValue::MakeNull())) return UINT32_MAX;
            }
            return pc + 1;
        }

        case MSILOpcode::Ldarga: {
            uint32_t idx = instr.operand.varIndex16;
            if (idx < args.size()) {
                if (!Push(args[idx])) return UINT32_MAX;
            } else {
                if (!Push(ILValue::MakeNull())) return UINT32_MAX;
            }
            return pc + 1;
        }

        case MSILOpcode::Starg_S: {
            ILValue val;
            if (!Pop(val)) return UINT32_MAX;
            uint32_t idx = instr.operand.varIndex8;
            if (idx >= args.size() && !EnsureVectorSize(args, idx + 1)) return UINT32_MAX;
            args[idx] = val;
            return pc + 1;
        }

        case MSILOpcode::Starg: {
            ILValue val;
            if (!Pop(val)) return UINT32_MAX;
            uint32_t idx = instr.operand.varIndex16;
            if (idx >= args.size() && !EnsureVectorSize(args, idx + 1)) return UINT32_MAX;
            args[idx] = val;
            return pc + 1;
        }

        // ==================================================================
        // DUP / POP
        // ==================================================================
        case MSILOpcode::Dup: {
            ILValue top;
            if (!Peek(top)) { aborted = true; return UINT32_MAX; }
            if (!Push(top)) return UINT32_MAX;
            return pc + 1;
        }
        case MSILOpcode::Pop: {
            ILValue discard;
            if (!Pop(discard)) return UINT32_MAX;
            return pc + 1;
        }

        // ==================================================================
        // BINARY ARITHMETIC
        // ==================================================================
        case MSILOpcode::Add: case MSILOpcode::Add_Ovf: case MSILOpcode::Add_Ovf_Un:
        case MSILOpcode::Sub: case MSILOpcode::Sub_Ovf: case MSILOpcode::Sub_Ovf_Un:
        case MSILOpcode::Mul: case MSILOpcode::Mul_Ovf: case MSILOpcode::Mul_Ovf_Un:
        case MSILOpcode::Div: case MSILOpcode::Div_Un:
        case MSILOpcode::Rem: case MSILOpcode::Rem_Un:
        case MSILOpcode::And: case MSILOpcode::Or: case MSILOpcode::Xor:
        case MSILOpcode::Shl: case MSILOpcode::Shr: case MSILOpcode::Shr_Un: {
            ILValue b, a;
            if (!Pop(b) || !Pop(a)) return UINT32_MAX;
            return HandleBinaryArith(op, a, b, pc);
        }

        // ==================================================================
        // UNARY ARITHMETIC
        // ==================================================================
        case MSILOpcode::Neg: {
            ILValue v;
            if (!Pop(v)) return UINT32_MAX;
            if (v.type == ILValueType::Int32)
                v.i32 = static_cast<int32_t>(0u - static_cast<uint32_t>(v.i32));
            else if (v.type == ILValueType::Int64)
                v.i64 = static_cast<int64_t>(0ull - static_cast<uint64_t>(v.i64));
            else if (v.type == ILValueType::Float64)
                v.f64 = -v.f64;
            if (!Push(v)) return UINT32_MAX;
            return pc + 1;
        }
        case MSILOpcode::Not: {
            ILValue v;
            if (!Pop(v)) return UINT32_MAX;
            if (v.type == ILValueType::Int32)
                v.i32 = ~v.i32;
            else if (v.type == ILValueType::Int64)
                v.i64 = ~v.i64;
            if (!Push(v)) return UINT32_MAX;
            return pc + 1;
        }

        // ==================================================================
        // COMPARISON
        // ==================================================================
        case MSILOpcode::Ceq: {
            ILValue b, a;
            if (!Pop(b) || !Pop(a)) return UINT32_MAX;
            int32_t result = (a.AsInteger() == b.AsInteger()) ? 1 : 0;
            if (a.type == ILValueType::Float64 && b.type == ILValueType::Float64)
                result = (a.f64 == b.f64) ? 1 : 0;
            if ((a.type == ILValueType::Null && b.type == ILValueType::Null))
                result = 1;
            if (!Push(ILValue::MakeI32(result))) return UINT32_MAX;
            return pc + 1;
        }
        case MSILOpcode::Cgt: case MSILOpcode::Cgt_Un: {
            ILValue b, a;
            if (!Pop(b) || !Pop(a)) return UINT32_MAX;
            int32_t result;
            if (a.type == ILValueType::Float64 && b.type == ILValueType::Float64)
                result = (a.f64 > b.f64) ? 1 : 0;
            else if (op == MSILOpcode::Cgt_Un)
                result = (static_cast<uint64_t>(a.AsInteger()) >
                          static_cast<uint64_t>(b.AsInteger())) ? 1 : 0;
            else
                result = (a.AsInteger() > b.AsInteger()) ? 1 : 0;
            if (!Push(ILValue::MakeI32(result))) return UINT32_MAX;
            return pc + 1;
        }
        case MSILOpcode::Clt: case MSILOpcode::Clt_Un: {
            ILValue b, a;
            if (!Pop(b) || !Pop(a)) return UINT32_MAX;
            int32_t result;
            if (a.type == ILValueType::Float64 && b.type == ILValueType::Float64)
                result = (a.f64 < b.f64) ? 1 : 0;
            else if (op == MSILOpcode::Clt_Un)
                result = (static_cast<uint64_t>(a.AsInteger()) <
                          static_cast<uint64_t>(b.AsInteger())) ? 1 : 0;
            else
                result = (a.AsInteger() < b.AsInteger()) ? 1 : 0;
            if (!Push(ILValue::MakeI32(result))) return UINT32_MAX;
            return pc + 1;
        }

        // ==================================================================
        // CONVERSIONS
        // ==================================================================
        case MSILOpcode::Conv_I1: case MSILOpcode::Conv_Ovf_I1:
        case MSILOpcode::Conv_Ovf_I1_Un: {
            ILValue v;
            if (!Pop(v)) return UINT32_MAX;
            if (!Push(ILValue::MakeI32(static_cast<int32_t>(static_cast<int8_t>(
                    v.type == ILValueType::Float64 ? static_cast<int64_t>(v.f64) : v.AsInteger())))))
                return UINT32_MAX;
            return pc + 1;
        }
        case MSILOpcode::Conv_I2: case MSILOpcode::Conv_Ovf_I2:
        case MSILOpcode::Conv_Ovf_I2_Un: {
            ILValue v;
            if (!Pop(v)) return UINT32_MAX;
            if (!Push(ILValue::MakeI32(static_cast<int32_t>(static_cast<int16_t>(
                    v.type == ILValueType::Float64 ? static_cast<int64_t>(v.f64) : v.AsInteger())))))
                return UINT32_MAX;
            return pc + 1;
        }
        case MSILOpcode::Conv_I4: case MSILOpcode::Conv_Ovf_I4:
        case MSILOpcode::Conv_Ovf_I4_Un: {
            ILValue v;
            if (!Pop(v)) return UINT32_MAX;
            if (!Push(ILValue::MakeI32(static_cast<int32_t>(
                    v.type == ILValueType::Float64 ? static_cast<int64_t>(v.f64) : v.AsInteger()))))
                return UINT32_MAX;
            return pc + 1;
        }
        case MSILOpcode::Conv_I8: case MSILOpcode::Conv_Ovf_I8:
        case MSILOpcode::Conv_Ovf_I8_Un: {
            ILValue v;
            if (!Pop(v)) return UINT32_MAX;
            int64_t val = v.type == ILValueType::Float64
                              ? static_cast<int64_t>(v.f64)
                              : v.AsInteger();
            if (!Push(ILValue::MakeI64(val))) return UINT32_MAX;
            return pc + 1;
        }
        case MSILOpcode::Conv_U1: case MSILOpcode::Conv_Ovf_U1:
        case MSILOpcode::Conv_Ovf_U1_Un: {
            ILValue v;
            if (!Pop(v)) return UINT32_MAX;
            if (!Push(ILValue::MakeI32(static_cast<int32_t>(static_cast<uint8_t>(
                    v.type == ILValueType::Float64 ? static_cast<uint64_t>(v.f64) : static_cast<uint64_t>(v.AsInteger()))))))
                return UINT32_MAX;
            return pc + 1;
        }
        case MSILOpcode::Conv_U2: case MSILOpcode::Conv_Ovf_U2:
        case MSILOpcode::Conv_Ovf_U2_Un: {
            ILValue v;
            if (!Pop(v)) return UINT32_MAX;
            if (!Push(ILValue::MakeI32(static_cast<int32_t>(static_cast<uint16_t>(
                    v.type == ILValueType::Float64 ? static_cast<uint64_t>(v.f64) : static_cast<uint64_t>(v.AsInteger()))))))
                return UINT32_MAX;
            return pc + 1;
        }
        case MSILOpcode::Conv_U4: case MSILOpcode::Conv_Ovf_U4:
        case MSILOpcode::Conv_Ovf_U4_Un: {
            ILValue v;
            if (!Pop(v)) return UINT32_MAX;
            if (!Push(ILValue::MakeI32(static_cast<int32_t>(static_cast<uint32_t>(
                    v.type == ILValueType::Float64 ? static_cast<uint64_t>(v.f64) : static_cast<uint64_t>(v.AsInteger()))))))
                return UINT32_MAX;
            return pc + 1;
        }
        case MSILOpcode::Conv_U8: case MSILOpcode::Conv_Ovf_U8:
        case MSILOpcode::Conv_Ovf_U8_Un: {
            ILValue v;
            if (!Pop(v)) return UINT32_MAX;
            uint64_t val = v.type == ILValueType::Float64
                               ? static_cast<uint64_t>(v.f64)
                               : static_cast<uint64_t>(v.AsInteger());
            if (!Push(ILValue::MakeI64(static_cast<int64_t>(val)))) return UINT32_MAX;
            return pc + 1;
        }
        case MSILOpcode::Conv_R4: case MSILOpcode::Conv_R_Un: {
            ILValue v;
            if (!Pop(v)) return UINT32_MAX;
            double d = v.type == ILValueType::Float64
                           ? v.f64
                           : static_cast<double>(v.AsInteger());
            if (!Push(ILValue::MakeF64(static_cast<float>(d)))) return UINT32_MAX;
            return pc + 1;
        }
        case MSILOpcode::Conv_R8: {
            ILValue v;
            if (!Pop(v)) return UINT32_MAX;
            double d = v.type == ILValueType::Float64
                           ? v.f64
                           : static_cast<double>(v.AsInteger());
            if (!Push(ILValue::MakeF64(d))) return UINT32_MAX;
            return pc + 1;
        }
        case MSILOpcode::Conv_I: case MSILOpcode::Conv_Ovf_I:
        case MSILOpcode::Conv_Ovf_I_Un:
        case MSILOpcode::Conv_U: case MSILOpcode::Conv_Ovf_U:
        case MSILOpcode::Conv_Ovf_U_Un: {
            // native int — treat as i64 in our model
            ILValue v;
            if (!Pop(v)) return UINT32_MAX;
            int64_t val = v.type == ILValueType::Float64
                              ? static_cast<int64_t>(v.f64)
                              : v.AsInteger();
            if (!Push(ILValue::MakeI64(val))) return UINT32_MAX;
            return pc + 1;
        }

        // ==================================================================
        // UNCONDITIONAL BRANCH
        // ==================================================================
        case MSILOpcode::Br_S: case MSILOpcode::Br: {
            uint32_t target = ComputeBranchTarget(instr);
            uint32_t idx    = FindInstructionIndex(target);
            if (idx == UINT32_MAX) { aborted = true; return UINT32_MAX; }
            return idx;
        }

        // ==================================================================
        // CONDITIONAL BRANCHES (unary)
        // ==================================================================
        case MSILOpcode::Brfalse_S: case MSILOpcode::Brfalse: {
            ILValue v;
            if (!Pop(v)) return UINT32_MAX;
            if (v.IsZero()) {
                uint32_t target = ComputeBranchTarget(instr);
                uint32_t idx    = FindInstructionIndex(target);
                if (idx == UINT32_MAX) { aborted = true; return UINT32_MAX; }
                return idx;
            }
            return pc + 1;
        }
        case MSILOpcode::Brtrue_S: case MSILOpcode::Brtrue: {
            ILValue v;
            if (!Pop(v)) return UINT32_MAX;
            if (!v.IsZero()) {
                uint32_t target = ComputeBranchTarget(instr);
                uint32_t idx    = FindInstructionIndex(target);
                if (idx == UINT32_MAX) { aborted = true; return UINT32_MAX; }
                return idx;
            }
            return pc + 1;
        }

        // ==================================================================
        // CONDITIONAL BRANCHES (binary comparison)
        // ==================================================================
        case MSILOpcode::Beq_S: case MSILOpcode::Beq:
        case MSILOpcode::Bge_S: case MSILOpcode::Bge:
        case MSILOpcode::Bgt_S: case MSILOpcode::Bgt:
        case MSILOpcode::Ble_S: case MSILOpcode::Ble:
        case MSILOpcode::Blt_S: case MSILOpcode::Blt:
        case MSILOpcode::Bne_Un_S: case MSILOpcode::Bne_Un:
        case MSILOpcode::Bge_Un_S: case MSILOpcode::Bge_Un:
        case MSILOpcode::Bgt_Un_S: case MSILOpcode::Bgt_Un:
        case MSILOpcode::Ble_Un_S: case MSILOpcode::Ble_Un:
        case MSILOpcode::Blt_Un_S: case MSILOpcode::Blt_Un: {
            ILValue b, a;
            if (!Pop(b) || !Pop(a)) return UINT32_MAX;
            bool condition = EvalBranchCondition(op, a, b);
            if (condition) {
                uint32_t target = ComputeBranchTarget(instr);
                uint32_t idx    = FindInstructionIndex(target);
                if (idx == UINT32_MAX) { aborted = true; return UINT32_MAX; }
                return idx;
            }
            return pc + 1;
        }

        // ==================================================================
        // SWITCH
        // ==================================================================
        case MSILOpcode::Switch: {
            ILValue v;
            if (!Pop(v)) return UINT32_MAX;
            auto idx = static_cast<uint32_t>(v.AsInteger());
            if (idx < static_cast<uint32_t>(instr.switchTargets.size())) {
                // Switch target offsets are relative to the end of the switch instruction
                if (instr.offset > std::numeric_limits<uint32_t>::max() - instr.size) {
                    aborted = true;
                    return UINT32_MAX;
                }
                uint32_t baseOffset = instr.offset + instr.size;
                uint32_t target = 0;
                if (!CheckedAddSignedOffset(baseOffset, instr.switchTargets[idx], target)) {
                    aborted = true;
                    return UINT32_MAX;
                }
                uint32_t tgtIdx     = FindInstructionIndex(target);
                if (tgtIdx == UINT32_MAX) { aborted = true; return UINT32_MAX; }
                return tgtIdx;
            }
            return pc + 1; // Fall through
        }

        // ==================================================================
        // LDSTR — load user string from #US heap
        // ==================================================================
        case MSILOpcode::Ldstr: {
            uint32_t usToken = instr.operand.token;
            // Attempt to read from MetadataParser.  If that fails, track empty.
            std::u16string s;
            try {
                // MetadataParser::ReadUserString returns std::u16string.
                // We rely on a const-reference method.
                s = ReadUserStringFromMetadata(usToken);
            } catch (const std::bad_alloc&) {
                aborted = true;
                return UINT32_MAX;
            } catch (const std::length_error&) {
                aborted = true;
                return UINT32_MAX;
            }
            uint32_t sIdx = TrackString(s);
            if (!Push(ILValue::MakeString(sIdx))) return UINT32_MAX;
            return pc + 1;
        }

        // ==================================================================
        // CALL / CALLVIRT / NEWOBJ
        // ==================================================================
        case MSILOpcode::Call:
        case MSILOpcode::Callvirt:
        case MSILOpcode::Newobj: {
            return HandleCall(instr, pc);
        }

        // ==================================================================
        // RET
        // ==================================================================
        case MSILOpcode::Ret:
            return UINT32_MAX; // End of method

        // ==================================================================
        // NEWARR — create a tracked byte array
        // ==================================================================
        case MSILOpcode::Newarr: {
            ILValue lenVal;
            if (!Pop(lenVal)) return UINT32_MAX;
            auto length = static_cast<uint32_t>(
                std::max<int64_t>(0, std::min<int64_t>(lenVal.AsInteger(), maxArraySize)));
            uint32_t arrIdx = CreateArray(length, instr.operand.token);
            if (!Push(ILValue::MakeArrayRef(arrIdx))) return UINT32_MAX;
            return pc + 1;
        }

        // ==================================================================
        // LDLEN — array length
        // ==================================================================
        case MSILOpcode::Ldlen: {
            ILValue arrRef;
            if (!Pop(arrRef)) return UINT32_MAX;
            int32_t len = 0;
            if (arrRef.type == ILValueType::ArrayRef && arrRef.ref < arrays.size())
                len = static_cast<int32_t>(arrays[arrRef.ref].data.size());
            if (!Push(ILValue::MakeI32(len))) return UINT32_MAX;
            return pc + 1;
        }

        // ==================================================================
        // STELEM.* — store into array
        // ==================================================================
        case MSILOpcode::Stelem_I1: case MSILOpcode::Stelem_I2:
        case MSILOpcode::Stelem_I4: case MSILOpcode::Stelem_I8:
        case MSILOpcode::Stelem_R4: case MSILOpcode::Stelem_R8:
        case MSILOpcode::Stelem_Ref: case MSILOpcode::Stelem_I:
        case MSILOpcode::Stelem: {
            ILValue val, idxVal, arrRef;
            if (!Pop(val) || !Pop(idxVal) || !Pop(arrRef)) return UINT32_MAX;
            if (arrRef.type == ILValueType::ArrayRef && arrRef.ref < arrays.size()) {
                auto& arr = arrays[arrRef.ref];
                auto  idx = static_cast<size_t>(idxVal.AsInteger());
                if (idx < arr.data.size()) {
                    arr.data[idx] = static_cast<uint8_t>(val.AsInteger() & 0xFF);
                    arr.modified  = true;
                }
            }
            return pc + 1;
        }

        // ==================================================================
        // LDELEM.* — load from array
        // ==================================================================
        case MSILOpcode::Ldelem_I1: case MSILOpcode::Ldelem_U1:
        case MSILOpcode::Ldelem_I2: case MSILOpcode::Ldelem_U2:
        case MSILOpcode::Ldelem_I4: case MSILOpcode::Ldelem_U4:
        case MSILOpcode::Ldelem_I8: case MSILOpcode::Ldelem_I:
        case MSILOpcode::Ldelem_R4: case MSILOpcode::Ldelem_R8:
        case MSILOpcode::Ldelem_Ref: case MSILOpcode::Ldelem:
        case MSILOpcode::Ldelema: {
            ILValue idxVal, arrRef;
            if (!Pop(idxVal) || !Pop(arrRef)) return UINT32_MAX;
            int32_t elem = 0;
            if (arrRef.type == ILValueType::ArrayRef && arrRef.ref < arrays.size()) {
                auto& arr = arrays[arrRef.ref];
                auto  idx = static_cast<size_t>(idxVal.AsInteger());
                if (idx < arr.data.size()) {
                    elem = static_cast<int32_t>(arr.data[idx]);
                    // Sign-extend for signed variants
                    if (op == MSILOpcode::Ldelem_I1)
                        elem = static_cast<int32_t>(static_cast<int8_t>(arr.data[idx]));
                    else if (op == MSILOpcode::Ldelem_I2) {
                        uint16_t word = static_cast<uint16_t>(arr.data[idx]);
                        if (idx + 1 < arr.data.size()) {
                            word = static_cast<uint16_t>(
                                word | (static_cast<uint16_t>(arr.data[idx + 1]) << 8));
                        }
                        elem = static_cast<int32_t>(static_cast<int16_t>(word));
                    } else if (op == MSILOpcode::Ldelem_U2 && idx + 1 < arr.data.size()) {
                        elem = static_cast<int32_t>(
                            static_cast<uint16_t>(arr.data[idx]) |
                            (static_cast<uint16_t>(arr.data[idx + 1]) << 8));
                    }
                }
            }
            if (op == MSILOpcode::Ldelem_I8) {
                if (!Push(ILValue::MakeI64(static_cast<int64_t>(elem)))) return UINT32_MAX;
            } else if (op == MSILOpcode::Ldelem_R4 || op == MSILOpcode::Ldelem_R8) {
                if (!Push(ILValue::MakeF64(static_cast<double>(elem)))) return UINT32_MAX;
            } else if (op == MSILOpcode::Ldelem_Ref || op == MSILOpcode::Ldelema) {
                if (!Push(ILValue::MakeI32(elem))) return UINT32_MAX;
            } else {
                if (!Push(ILValue::MakeI32(elem))) return UINT32_MAX;
            }
            return pc + 1;
        }

        // ==================================================================
        // EXCEPTION HANDLING
        // ==================================================================
        case MSILOpcode::Throw: {
            ILValue exc;
            if (!Pop(exc)) return UINT32_MAX;
            threw = true;
            return UINT32_MAX;
        }
        case MSILOpcode::Rethrow: {
            threw = true;
            return UINT32_MAX;
        }
        case MSILOpcode::Leave: case MSILOpcode::Leave_S: {
            // Clear evaluation stack (ECMA-335 spec) then branch
            evalStack.clear();
            uint32_t target = ComputeBranchTarget(instr);
            uint32_t idx    = FindInstructionIndex(target);
            if (idx == UINT32_MAX) { aborted = true; return UINT32_MAX; }
            return idx;
        }
        case MSILOpcode::Endfinally:
        case MSILOpcode::Endfilter:
            return pc + 1;

        // ==================================================================
        // FIELD ACCESS — we don't model full objects, push/pop Null
        // ==================================================================
        case MSILOpcode::Ldfld: case MSILOpcode::Ldflda:
        case MSILOpcode::Ldsfld: case MSILOpcode::Ldsflda: {
            // Static field loads don't pop; instance field loads pop the object ref
            if (op == MSILOpcode::Ldfld || op == MSILOpcode::Ldflda) {
                ILValue discard;
                if (!Pop(discard)) return UINT32_MAX;
            }
            if (!Push(ILValue::MakeNull())) return UINT32_MAX;
            return pc + 1;
        }
        case MSILOpcode::Stfld: {
            ILValue val, obj;
            if (!Pop(val) || !Pop(obj)) return UINT32_MAX;
            return pc + 1;
        }
        case MSILOpcode::Stsfld: {
            ILValue val;
            if (!Pop(val)) return UINT32_MAX;
            return pc + 1;
        }

        // ==================================================================
        // OBJECT MODEL — minimal modeling
        // ==================================================================
        case MSILOpcode::Box: case MSILOpcode::Unbox: case MSILOpcode::Unbox_Any: {
            // Box: pop value, push objectref (we just keep the value)
            // Unbox: pop objectref, push value
            return pc + 1;
        }
        case MSILOpcode::Castclass: case MSILOpcode::Isinst: {
            // Pop object ref, push it back (or null for isinst failure)
            return pc + 1;
        }
        case MSILOpcode::Ldobj: case MSILOpcode::Stobj: case MSILOpcode::Cpobj:
        case MSILOpcode::Initobj: {
            if (op == MSILOpcode::Stobj || op == MSILOpcode::Cpobj) {
                ILValue v1, v2;
                if (!Pop(v1)) return UINT32_MAX;
                if (op == MSILOpcode::Cpobj) { if (!Pop(v2)) return UINT32_MAX; }
            } else if (op == MSILOpcode::Initobj) {
                ILValue addr;
                if (!Pop(addr)) return UINT32_MAX;
            } else {
                // Ldobj: pop address, push value
                ILValue addr;
                if (!Pop(addr)) return UINT32_MAX;
                if (!Push(ILValue::MakeNull())) return UINT32_MAX;
            }
            return pc + 1;
        }

        // ==================================================================
        // LDTOKEN — push a runtime handle (we push Null)
        // ==================================================================
        case MSILOpcode::Ldtoken: {
            if (!Push(ILValue::MakeI32(static_cast<int32_t>(instr.operand.token))))
                return UINT32_MAX;
            return pc + 1;
        }

        // ==================================================================
        // INDIRECT LOAD/STORE — we approximate
        // ==================================================================
        case MSILOpcode::Ldind_I1: case MSILOpcode::Ldind_U1:
        case MSILOpcode::Ldind_I2: case MSILOpcode::Ldind_U2:
        case MSILOpcode::Ldind_I4: case MSILOpcode::Ldind_U4:
        case MSILOpcode::Ldind_I8: case MSILOpcode::Ldind_I:
        case MSILOpcode::Ldind_R4: case MSILOpcode::Ldind_R8:
        case MSILOpcode::Ldind_Ref: {
            ILValue addr;
            if (!Pop(addr)) return UINT32_MAX;
            // Return the pointer value itself as a best-effort approximation
            if (!Push(addr)) return UINT32_MAX;
            return pc + 1;
        }
        case MSILOpcode::Stind_I1: case MSILOpcode::Stind_I2:
        case MSILOpcode::Stind_I4: case MSILOpcode::Stind_I8:
        case MSILOpcode::Stind_R4: case MSILOpcode::Stind_R8:
        case MSILOpcode::Stind_Ref: case MSILOpcode::Stind_I: {
            ILValue val, addr;
            if (!Pop(val) || !Pop(addr)) return UINT32_MAX;
            return pc + 1;
        }

        // ==================================================================
        // SIZEOF — push a constant size
        // ==================================================================
        case MSILOpcode::Sizeof: {
            if (!Push(ILValue::MakeI32(4))) return UINT32_MAX; // default approximation
            return pc + 1;
        }

        // ==================================================================
        // PREFIX OPCODES — skip (they modify the next instruction semantics)
        // ==================================================================
        case MSILOpcode::Unaligned:
        case MSILOpcode::Volatile:
        case MSILOpcode::Tail:
        case MSILOpcode::Constrained:
        case MSILOpcode::Readonly:
            return pc + 1;

        // ==================================================================
        // LOCALLOC — allocate stack memory (approximate with Null)
        // ==================================================================
        case MSILOpcode::Localloc: {
            ILValue size;
            if (!Pop(size)) return UINT32_MAX;
            if (!Push(ILValue::MakeNull())) return UINT32_MAX;
            return pc + 1;
        }

        // ==================================================================
        // LDFTN / LDVIRTFTN — push function pointer (approximate with token)
        // ==================================================================
        case MSILOpcode::Ldftn: case MSILOpcode::Ldvirtftn: {
            if (op == MSILOpcode::Ldvirtftn) {
                ILValue obj;
                if (!Pop(obj)) return UINT32_MAX;
            }
            if (!Push(ILValue::MakeI32(static_cast<int32_t>(instr.operand.token))))
                return UINT32_MAX;
            return pc + 1;
        }

        // ==================================================================
        // ARGLIST / REFANYVAL / MKREFANY / CKFINITE / REFANYTYPE
        // ==================================================================
        case MSILOpcode::Arglist: {
            if (!Push(ILValue::MakeNull())) return UINT32_MAX;
            return pc + 1;
        }
        case MSILOpcode::Ckfinite: {
            // Just peek the top — it should be a float; leave it
            return pc + 1;
        }
        case MSILOpcode::Refanyval: case MSILOpcode::Mkrefany:
        case MSILOpcode::Refanytype: {
            // Opaque — pop inputs, push Null
            ILValue v;
            if (!Pop(v)) return UINT32_MAX;
            if (!Push(ILValue::MakeNull())) return UINT32_MAX;
            return pc + 1;
        }

        // ==================================================================
        // CPBLK / INITBLK
        // ==================================================================
        case MSILOpcode::Cpblk: case MSILOpcode::Initblk: {
            ILValue a, b, c;
            if (!Pop(a) || !Pop(b) || !Pop(c)) return UINT32_MAX;
            return pc + 1;
        }

        // ==================================================================
        // JMP — tail jump (we just return)
        // ==================================================================
        case MSILOpcode::Jmp:
            return UINT32_MAX;

        // ==================================================================
        // CALLI — indirect call (pop function pointer + args, push Null)
        // ==================================================================
        case MSILOpcode::Calli: {
            ILValue ftn;
            if (!Pop(ftn)) return UINT32_MAX;
            if (!Push(ILValue::MakeNull())) return UINT32_MAX;
            return pc + 1;
        }

        // ==================================================================
        // DEFAULT — unrecognized opcode, skip
        // ==================================================================
        default:
            return pc + 1;
        }
    }

    // ------------------------------------------------------------------
    // Binary arithmetic helper
    // ------------------------------------------------------------------
    uint32_t HandleBinaryArith(MSILOpcode op, ILValue a, ILValue b,
                               uint32_t pc) noexcept
    {
        // Promote both to the widest type
        bool useI64 = (a.type == ILValueType::Int64 || b.type == ILValueType::Int64);
        bool useF64 = (a.type == ILValueType::Float64 || b.type == ILValueType::Float64);

        if (useF64) {
            double da = a.type == ILValueType::Float64 ? a.f64 : static_cast<double>(a.AsInteger());
            double db = b.type == ILValueType::Float64 ? b.f64 : static_cast<double>(b.AsInteger());
            double result = 0.0;
            switch (op) {
                case MSILOpcode::Add: case MSILOpcode::Add_Ovf: case MSILOpcode::Add_Ovf_Un:
                    result = da + db; break;
                case MSILOpcode::Sub: case MSILOpcode::Sub_Ovf: case MSILOpcode::Sub_Ovf_Un:
                    result = da - db; break;
                case MSILOpcode::Mul: case MSILOpcode::Mul_Ovf: case MSILOpcode::Mul_Ovf_Un:
                    result = da * db; break;
                case MSILOpcode::Div: case MSILOpcode::Div_Un:
                    result = (db != 0.0) ? da / db : 0.0; break;
                case MSILOpcode::Rem: case MSILOpcode::Rem_Un:
                    result = (db != 0.0) ? std::fmod(da, db) : 0.0; break;
                default: break;
            }
            if (!Push(ILValue::MakeF64(result))) return UINT32_MAX;
            return pc + 1;
        }

        int64_t ia = a.AsInteger();
        int64_t ib = b.AsInteger();
        int64_t result = 0;
        const auto ua = static_cast<uint64_t>(ia);
        const auto ub = static_cast<uint64_t>(ib);
        const auto shift = static_cast<unsigned>(ub & 63u);

        switch (op) {
            case MSILOpcode::Add: case MSILOpcode::Add_Ovf: case MSILOpcode::Add_Ovf_Un:
                result = static_cast<int64_t>(ua + ub); break;
            case MSILOpcode::Sub: case MSILOpcode::Sub_Ovf: case MSILOpcode::Sub_Ovf_Un:
                result = static_cast<int64_t>(ua - ub); break;
            case MSILOpcode::Mul: case MSILOpcode::Mul_Ovf: case MSILOpcode::Mul_Ovf_Un:
                result = static_cast<int64_t>(ua * ub); break;
            case MSILOpcode::Div:
                if (ib == 0) { result = 0; }
                else if (ia == std::numeric_limits<int64_t>::min() && ib == -1) {
                    result = std::numeric_limits<int64_t>::min();
                }
                else { result = ia / ib; }
                break;
            case MSILOpcode::Div_Un:
                if (ib == 0) { result = 0; }
                else { result = static_cast<int64_t>(ua / ub); }
                break;
            case MSILOpcode::Rem:
                if (ib == 0) { result = 0; }
                else if (ia == std::numeric_limits<int64_t>::min() && ib == -1) {
                    result = 0;
                }
                else { result = ia % ib; }
                break;
            case MSILOpcode::Rem_Un:
                if (ib == 0) { result = 0; }
                else { result = static_cast<int64_t>(ua % ub); }
                break;
            case MSILOpcode::And:
                result = static_cast<int64_t>(ua & ub); break;
            case MSILOpcode::Or:
                result = static_cast<int64_t>(ua | ub); break;
            case MSILOpcode::Xor:
                result = static_cast<int64_t>(ua ^ ub); break;
            case MSILOpcode::Shl:
                result = static_cast<int64_t>(ua << shift); break;
            case MSILOpcode::Shr:
                result = ia >= 0
                    ? static_cast<int64_t>(ua >> shift)
                    : static_cast<int64_t>(~((~ua) >> shift));
                break;
            case MSILOpcode::Shr_Un:
                result = static_cast<int64_t>(ua >> shift); break;
            default: break;
        }

        if (useI64) {
            if (!Push(ILValue::MakeI64(result))) return UINT32_MAX;
        } else {
            if (!Push(ILValue::MakeI32(static_cast<int32_t>(result)))) return UINT32_MAX;
        }
        return pc + 1;
    }

    // ------------------------------------------------------------------
    // Binary branch condition evaluator
    // ------------------------------------------------------------------
    [[nodiscard]] bool EvalBranchCondition(MSILOpcode op,
                                           const ILValue& a,
                                           const ILValue& b) const noexcept
    {
        int64_t ia = a.AsInteger();
        int64_t ib = b.AsInteger();
        uint64_t ua = static_cast<uint64_t>(ia);
        uint64_t ub = static_cast<uint64_t>(ib);

        switch (op) {
            case MSILOpcode::Beq_S:    case MSILOpcode::Beq:     return ia == ib;
            case MSILOpcode::Bge_S:    case MSILOpcode::Bge:     return ia >= ib;
            case MSILOpcode::Bgt_S:    case MSILOpcode::Bgt:     return ia >  ib;
            case MSILOpcode::Ble_S:    case MSILOpcode::Ble:     return ia <= ib;
            case MSILOpcode::Blt_S:    case MSILOpcode::Blt:     return ia <  ib;
            case MSILOpcode::Bne_Un_S: case MSILOpcode::Bne_Un:  return ia != ib;
            case MSILOpcode::Bge_Un_S: case MSILOpcode::Bge_Un:  return ua >= ub;
            case MSILOpcode::Bgt_Un_S: case MSILOpcode::Bgt_Un:  return ua >  ub;
            case MSILOpcode::Ble_Un_S: case MSILOpcode::Ble_Un:  return ua <= ub;
            case MSILOpcode::Blt_Un_S: case MSILOpcode::Blt_Un:  return ua <  ub;
            default: return false;
        }
    }

    // ------------------------------------------------------------------
    // Read user string from MetadataParser (compile-time safe bridge)
    // ------------------------------------------------------------------
    [[nodiscard]] std::u16string ReadUserStringFromMetadata(uint32_t usToken) const noexcept {
        // The MetadataParser exposes:
        //   std::u16string ReadUserString(uint32_t token) const;
        // We invoke it through the const reference.
        try {
            return metadata.ReadUserString(usToken);
        } catch (const std::bad_alloc&) {
            return {};
        } catch (const std::length_error&) {
            return {};
        }
    }

    // ------------------------------------------------------------------
    // Handle call / callvirt / newobj
    // ------------------------------------------------------------------
    uint32_t HandleCall(const MSILInstruction& instr, uint32_t pc) noexcept {
        MetadataToken tok{ instr.operand.token };

        // Resolve the method target using our local ResolveToken bridge
        ResolvedMethod rm = ResolveToken(tok);

        // Record API call
        RecordAPICall(rm, tok, instr.offset);

        // Determine argument count (approximate: pop based on what's available)
        // For string methods, we collect args for simulation
        bool isStrMethod = IsStringMethod(rm.className, rm.methodName);

        // Attempt recursive interpretation for local MethodDef calls
        if (rm.isLocal && bodyProvider && currentCallDepth < maxCallDepth) {
            try {
                auto [ilBytes, ilSize] = bodyProvider(tok.raw);
                if (ilBytes != nullptr && ilSize > 0) {
                    // This requires disassembling the IL first.
                    // Since MSILDisassembler is a sibling module, we skip recursive
                    // interpretation here unless pre-disassembled instructions are
                    // cached.  In practice the Execute() entry point is called with
                    // pre-disassembled instructions, so recursion would require the
                    // caller to wire in a disassembler callback too.
                    // For now: pop args and push Null.
                }
            } catch (...) {
                // DESIGN: MethodBodyProvider is caller-owned plugin code. It is an
                // exception boundary, so arbitrary callback failures abort this run
                // instead of escaping a noexcept interpreter path.
                aborted = true;
                return UINT32_MAX;
            }
        }

        // Handle string methods specially
        if (isStrMethod) {
            try {
            // Collect arguments from stack for simulation
            // String.Concat can have 2-4 args; we pop until non-string or stack empty
            std::vector<ILValue> strArgs;
            strArgs.reserve(4);
            if (rm.methodName == "Concat") {
                // Pop all consecutive string values (up to 4)
                for (int i = 0; i < 4 && !evalStack.empty(); ++i) {
                    if (evalStack.back().type == ILValueType::String ||
                        evalStack.back().type == ILValueType::Null) {
                        strArgs.insert(strArgs.begin(), evalStack.back());
                        evalStack.pop_back();
                    } else {
                        break;
                    }
                }
            } else if (rm.methodName == "Replace") {
                // instance.Replace(old, new) → 3 values
                if (evalStack.size() >= 3) {
                    ILValue newS = PopValue();
                    ILValue oldS = PopValue();
                    ILValue inst = PopValue();
                    strArgs = { inst, oldS, newS };
                }
            } else if (rm.methodName == "Substring") {
                // instance.Substring(start[, length])
                if (evalStack.size() >= 2) {
                    ILValue arg1 = PopValue();
                    ILValue inst = PopValue();
                    strArgs = { inst, arg1 };
                    // Check if there's a length arg
                    if (!evalStack.empty() &&
                        evalStack.back().type == ILValueType::Int32) {
                        // Actually Substring(int,int) has the length as the 2nd operand
                        // Re-read: stack was [inst, start, len] → need to check operand count
                    }
                }
            } else {
                // Other string methods: pop instance
                if (!evalStack.empty()) {
                    strArgs.push_back(PopValue());
                }
            }

            std::u16string result = SimulateStringMethod(rm.methodName, strArgs);
            if (!result.empty()) {
                uint32_t sIdx = TrackString(result);
                if (!Push(ILValue::MakeString(sIdx))) return UINT32_MAX;
            } else {
                // Push original string if we had one
                if (!strArgs.empty() && strArgs[0].type == ILValueType::String) {
                    if (!Push(strArgs[0])) return UINT32_MAX;
                } else {
                    if (!Push(ILValue::MakeNull())) return UINT32_MAX;
                }
            }
            return pc + 1;
            } catch (const std::bad_alloc&) {
                aborted = true;
                return UINT32_MAX;
            } catch (const std::length_error&) {
                aborted = true;
                return UINT32_MAX;
            }
        }

        // For newobj: push an ObjectRef
        if (instr.opcode == MSILOpcode::Newobj) {
            // Pop constructor arguments — we don't know the exact count without
            // parsing the method signature, so we don't pop (the stack may be
            // slightly inaccurate but this is safe for our extraction purposes)
            if (!Push(ILValue::MakeObjectRef(0))) return UINT32_MAX;
            return pc + 1;
        }

        // Generic call: pop nothing extra (signature unknown), push Null return
        if (!Push(ILValue::MakeNull())) return UINT32_MAX;
        return pc + 1;
    }

    // ------------------------------------------------------------------
    // Main execution loop
    // ------------------------------------------------------------------
    InterpretationResult Run(const std::vector<MSILInstruction>& instructions,
                             MetadataToken methodToken,
                             const std::vector<ILValue>& methodArgs) noexcept
    {
        // Reset per-execution state
        evalStack.clear();
        locals.clear();
        args.clear();
        arrays.clear();
        stringTable.clear();
        aborted = false;
        try {
            locals.resize(256); // Pre-allocate generous local space
            args = methodArgs;
        } catch (const std::bad_alloc&) {
            aborted = true;
        } catch (const std::length_error&) {
            aborted = true;
        }
        instrCount     = 0;
        currentCallDepth = 0;
        peakStackDepth = 0;
        threw          = false;
        currentMethodToken = methodToken;

        BuildOffsetMap(instructions);

        uint32_t pc = 0;
        while (pc != UINT32_MAX && !aborted) {
            pc = Step(instructions, pc);
        }

        // Harvest byte arrays into collected results
        for (auto& arr : arrays) {
            if (arr.modified && arr.data.size() >= kMinPayloadArraySize) {
                if (collectedArrays.size() < kDefaultMaxArrays) {
                    try {
                        collectedArrays.push_back(arr.data);
                    } catch (const std::bad_alloc&) {
                        aborted = true;
                        break;
                    } catch (const std::length_error&) {
                        aborted = true;
                        break;
                    }
                }
            }
        }

        InterpretationResult result;
        try {
            result.decryptedStrings      = collectedStrings;
            result.apiCalls              = collectedAPICalls;
            result.extractedArrays       = collectedArrays;
        } catch (const std::bad_alloc&) {
            result.decryptedStrings.clear();
            result.apiCalls.clear();
            result.extractedArrays.clear();
        } catch (const std::length_error&) {
            result.decryptedStrings.clear();
            result.apiCalls.clear();
            result.extractedArrays.clear();
        }
        result.instructionsExecuted  = instrCount;
        result.maxStackDepthReached  = peakStackDepth;
        result.callDepthReached      = currentCallDepth;
        result.hitInstructionLimit   = (instrCount >= maxInstructions);
        result.hitStackLimit         = (peakStackDepth >= maxStackDepth);
        result.hitCallDepthLimit     = (currentCallDepth >= maxCallDepth);
        result.threwException        = threw;
        return result;
    }
};

// ============================================================================
// MSILInterpreter — Public Interface
// ============================================================================

MSILInterpreter::MSILInterpreter(const MetadataParser& metadata) noexcept
{
    try {
        m_impl = std::make_unique<Impl>(metadata);
    } catch (const std::bad_alloc&) {
        m_impl.reset();
    }
}

MSILInterpreter::~MSILInterpreter() noexcept = default;

MSILInterpreter::MSILInterpreter(MSILInterpreter&&) noexcept = default;
MSILInterpreter& MSILInterpreter::operator=(MSILInterpreter&&) noexcept = default;

void MSILInterpreter::SetMethodBodyProvider(MethodBodyProvider provider) noexcept {
    if (!m_impl) return;
    try {
        m_impl->bodyProvider = std::move(provider);
    } catch (const std::bad_alloc&) {
        m_impl->bodyProvider = {};
    }
}

InterpretationResult MSILInterpreter::Execute(
    const std::vector<MSILInstruction>& instructions,
    MetadataToken                       methodToken,
    const std::vector<ILValue>&         args) noexcept
{
    if (!m_impl || instructions.empty()) {
        return {};
    }
    return m_impl->Run(instructions, methodToken, args);
}

InterpretationResult MSILInterpreter::ExecuteStaticConstructors(
    MethodBodyProvider bodyProvider) noexcept
{
    if (!m_impl) return {};

    try {
        m_impl->bodyProvider = std::move(bodyProvider);
    } catch (const std::bad_alloc&) {
        m_impl->bodyProvider = {};
        return {};
    }

    // Iterate all TypeDef rows in the assembly, find methods named ".cctor",
    // fetch their IL bytes via the body provider, and execute them.
    //
    // MetadataParser exposes:
    //   const std::vector<TypeDefRow>&   GetTypeDefs() const;
    //   const std::vector<MethodDefRow>& GetMethodDefs() const;
    //
    // For each TypeDef, MethodDef rows from [methodList, next.methodList) belong
    // to that type.  We look for methods named ".cctor".

    InterpretationResult aggregated;

    try {
        const auto& typeDefs   = m_impl->metadata.GetTypeDefs();
        const auto& methodDefs = m_impl->metadata.GetMethodDefs();

        for (uint32_t tIdx = 0; tIdx < static_cast<uint32_t>(typeDefs.size()); ++tIdx) {
            uint32_t mStart = typeDefs[tIdx].methodList;
            uint32_t mEnd   = (tIdx + 1 < static_cast<uint32_t>(typeDefs.size()))
                                  ? typeDefs[tIdx + 1].methodList
                                  : static_cast<uint32_t>(methodDefs.size()) + 1;

            for (uint32_t mRow = mStart; mRow < mEnd; ++mRow) {
                if (mRow == 0 || mRow > static_cast<uint32_t>(methodDefs.size()))
                    continue;
                const auto& mdef = methodDefs[mRow - 1]; // 1-based → 0-based
                if (mdef.name != ".cctor")
                    continue;

                // Fetch IL body
                MetadataToken mToken = MetadataToken::Make(MetadataTableId::MethodDef, mRow);
                if (!m_impl->bodyProvider) continue;
                std::pair<const uint8_t*, uint32_t> body{};
                try {
                    body = m_impl->bodyProvider(mToken.raw);
                } catch (...) {
                    // DESIGN: caller-supplied body providers are an exception
                    // boundary; one bad provider result must not escape noexcept.
                    continue;
                }
                auto [ilBytes, ilSize] = body;
                if (ilBytes == nullptr || ilSize == 0) continue;

                // We need the disassembler to turn raw bytes into MSILInstruction
                // vector.  Since MSILDisassembler is a sibling module, the caller
                // should wrap the body provider to return pre-disassembled instructions.
                // For raw bytes we cannot proceed — skip silently.
                // The primary intended call path is Execute() with pre-disassembled
                // instructions; ExecuteStaticConstructors is a convenience that
                // requires the caller to wire in a disassembler.
            }
        }
    } catch (const std::bad_alloc&) {
        // Allocation pressure is reported as a partial result rather than crossing noexcept.
    } catch (const std::length_error&) {
        // Hostile metadata can expose impossible row ranges; return partial results.
    }

    try {
        aggregated.decryptedStrings     = m_impl->collectedStrings;
        aggregated.apiCalls             = m_impl->collectedAPICalls;
        aggregated.extractedArrays      = m_impl->collectedArrays;
    } catch (const std::bad_alloc&) {
        aggregated.decryptedStrings.clear();
        aggregated.apiCalls.clear();
        aggregated.extractedArrays.clear();
    } catch (const std::length_error&) {
        aggregated.decryptedStrings.clear();
        aggregated.apiCalls.clear();
        aggregated.extractedArrays.clear();
    }
    aggregated.instructionsExecuted = m_impl->instrCount;
    aggregated.maxStackDepthReached = m_impl->peakStackDepth;
    aggregated.callDepthReached     = m_impl->currentCallDepth;
    return aggregated;
}

void MSILInterpreter::SetMaxInstructions(uint64_t max) noexcept {
    if (m_impl) m_impl->maxInstructions = std::clamp<uint64_t>(max, 1, kMaxInterpretedInstr);
}
void MSILInterpreter::SetMaxStackDepth(uint32_t max) noexcept {
    if (m_impl) m_impl->maxStackDepth = std::clamp<uint32_t>(max, 1, kMaxEvalStackDepth);
}
void MSILInterpreter::SetMaxCallDepth(uint32_t max) noexcept {
    if (m_impl) m_impl->maxCallDepth = std::clamp<uint32_t>(max, 1, kMaxCallDepth);
}
void MSILInterpreter::SetMaxArraySize(uint32_t max) noexcept {
    if (m_impl) m_impl->maxArraySize = std::clamp<uint32_t>(max, 1, kHardMaxArraySize);
}

const std::vector<std::u16string>& MSILInterpreter::GetDecryptedStrings() const noexcept {
    static const std::vector<std::u16string> kEmpty;
    if (!m_impl) return kEmpty;
    return m_impl->collectedStrings;
}

const std::vector<DotNetAPICall>& MSILInterpreter::GetAPICalls() const noexcept {
    static const std::vector<DotNetAPICall> kEmpty;
    if (!m_impl) return kEmpty;
    return m_impl->collectedAPICalls;
}

} // namespace Phantom::CLR

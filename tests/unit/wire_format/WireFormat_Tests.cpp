/**
 * ============================================================================
 * ShadowStrike - KERNEL/USER WIRE FORMAT CONTRACT
 * ============================================================================
 *
 * @file WireFormat_Tests.cpp
 * @brief Pins the layout of every structure that crosses the kernel boundary.
 *
 * @par Why this file exists
 * The frame the driver sends is
 *
 *     [FILTER_MESSAGE_HEADER (fltmgr, cleartext)][application header][payload]
 *
 * and five user-mode subsystems parse it: the IPC manager, the filter
 * connection, the file-system filter, the network traffic filter and the file
 * lock manager. Every one of them locates the payload by arithmetic on
 * `sizeof(...)`. Nothing verified that the sizes they compute are the sizes the
 * driver wrote, and three separate defects had already been traced to exactly
 * that gap:
 *
 *   - The transport prefix name resolved to a DIFFERENT TYPE depending on
 *     include order. MessageProtocol.h aliased our own 40-byte
 *     SHADOWSTRIKE_MESSAGE_HEADER to FILTER_MESSAGE_HEADER - the name of a
 *     16-byte OS structure - for any translation unit that had not yet reached
 *     <fltUser.h>. A unit that resolved it the wrong way located the payload 24
 *     bytes past where the kernel put it and read whatever was there as a
 *     struct. Two of the five consumers had an explicit include and a comment
 *     about the hazard; the rest relied on their include graph. The only
 *     compile-time check on the type was `sizeof(SS_MESSAGE_HEADER) <= 64`,
 *     which 16 and 40 both satisfy.
 *
 *   - The application header is declared TWICE: SHADOWSTRIKE_MESSAGE_HEADER in
 *     the shared header both sides include, and FilterMessageHeader in
 *     FileSystemFilter.hpp. The magic constant is declared THREE times. They
 *     agree today only because each enum used inside the duplicate happens to
 *     carry an explicit underlying type; deleting one `: uint16_t` silently
 *     displaces every field after it by two bytes, in one consumer only.
 *
 *   - The same class of defect has bitten this boundary twice already for real:
 *     a length derived from TotalSize was 32 bytes short of what the driver
 *     wrote for HMAC-bearing frames (1,048 files answered fail-open), and a
 *     compression transform was applied with no inverse on the receiving side.
 *
 * @par What these tests are for
 * Numbers, not shapes. Each assertion names an absolute offset taken from the
 * driver's own definition, so the test fails if EITHER side moves. The runtime
 * cases go further than comparing sizes: they write a byte pattern through one
 * declaration and read every field back through the other, which is the
 * property the product actually depends on and the only one that catches two
 * fields swapping while the total size stays the same.
 *
 * @copyright ShadowStrike Labs. Licensed under AGPL-3.0.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <type_traits>

// Deliberately included in this order, and deliberately NOT ordered around
// <fltUser.h>: the point of the fix these tests guard is that include order no
// longer changes what any of these names mean.
#include "PhantomCore/Communication/FilterPortGate.hpp"
#include "PhantomCore/Communication/Communication.hpp"
#include "PhantomCore/RealTime/FileSystemFilter.hpp"

// IPCManager.hpp is deliberately NOT included here, and that is a finding rather
// than a preference: it declares ShadowStrike::Communication::FileScanCallback
// and ::ProcessNotifyCallback with DIFFERENT types from the ones Communication.hpp
// declares under the same fully-qualified names, so a translation unit that
// includes both fails to compile (C2371). The per-message-type statistics
// assertions therefore live in IpcStatistics_Tests.cpp, which includes
// IPCManager.hpp and not Communication.hpp.

#include "../../../PhantomSensor/Shared/MessageProtocol.h"

namespace {

using ShadowStrike::RealTime::FilterMessageHeader;
using ShadowStrike::RealTime::FileScanRequest;

// ============================================================================
// TRANSPORT PREFIX - the filter manager's own header
// ============================================================================
//
// 16 bytes on x64: ULONG ReplyLength at 0, then 4 bytes of padding, then
// ULONGLONG MessageId at 8. It is NOT 12, which is what it would be under
// pack(1) and what two comments in this repo used to claim, and it is NOT 40,
// which is what the removed alias made it.
//
static_assert(sizeof(FILTER_MESSAGE_HEADER) == 16,
              "Transport prefix must be the OS structure. If this fails, this translation unit "
              "resolved FILTER_MESSAGE_HEADER to something else and every payload offset "
              "computed from it is displaced.");

// ============================================================================
// APPLICATION HEADER - the driver's definition is the authority
// ============================================================================

static_assert(sizeof(SHADOWSTRIKE_MESSAGE_HEADER) == 40, "");

// The duplicate declaration must be byte-identical, not merely the same size.
static_assert(sizeof(FilterMessageHeader) == sizeof(SHADOWSTRIKE_MESSAGE_HEADER),
              "FileSystemFilter's FilterMessageHeader is a second declaration of the frame "
              "header the driver writes. A size disagreement means one consumer parses every "
              "kernel frame at the wrong offsets.");

static_assert(offsetof(FilterMessageHeader, magic) ==
              offsetof(SHADOWSTRIKE_MESSAGE_HEADER, Magic), "");
static_assert(offsetof(FilterMessageHeader, version) ==
              offsetof(SHADOWSTRIKE_MESSAGE_HEADER, Version), "");
static_assert(offsetof(FilterMessageHeader, messageType) ==
              offsetof(SHADOWSTRIKE_MESSAGE_HEADER, MessageType), "");
static_assert(offsetof(FilterMessageHeader, messageId) ==
              offsetof(SHADOWSTRIKE_MESSAGE_HEADER, MessageId), "");
static_assert(offsetof(FilterMessageHeader, totalSize) ==
              offsetof(SHADOWSTRIKE_MESSAGE_HEADER, TotalSize), "");
static_assert(offsetof(FilterMessageHeader, dataSize) ==
              offsetof(SHADOWSTRIKE_MESSAGE_HEADER, DataSize), "");
static_assert(offsetof(FilterMessageHeader, timestamp) ==
              offsetof(SHADOWSTRIKE_MESSAGE_HEADER, Timestamp), "");
static_assert(offsetof(FilterMessageHeader, flags) ==
              offsetof(SHADOWSTRIKE_MESSAGE_HEADER, Flags), "");
static_assert(offsetof(FilterMessageHeader, reserved) ==
              offsetof(SHADOWSTRIKE_MESSAGE_HEADER, Reserved), "");

// The enum widths are the reason the duplicate agrees. Asserted so that dropping
// an explicit underlying type is a build failure and not a silent two-byte
// displacement of every field after it.
static_assert(sizeof(ShadowStrike::RealTime::FilterMessageType) == 2,
              "FilterMessageType must stay 2 bytes wide; it sits mid-structure in a packed "
              "frame header, so widening it displaces every field after it.");

// ============================================================================
// SCAN REQUEST PAYLOAD
// ============================================================================
//
// processId at offset 12 is called out specifically: a field log once reported
// this process's own PID where a frame's magic belonged, which is what a
// displaced read of this payload looks like from the outside.
//
static_assert(sizeof(FileScanRequest) == sizeof(FILE_SCAN_REQUEST),
              "FileScanRequest duplicates the driver's FILE_SCAN_REQUEST. A size disagreement "
              "means the scan request is parsed at the wrong offsets.");
static_assert(offsetof(FileScanRequest, messageId) ==
              offsetof(FILE_SCAN_REQUEST, MessageId), "");
static_assert(offsetof(FileScanRequest, processId) ==
              offsetof(FILE_SCAN_REQUEST, ProcessId), "");
static_assert(offsetof(FileScanRequest, threadId) ==
              offsetof(FILE_SCAN_REQUEST, ThreadId), "");
static_assert(offsetof(FileScanRequest, fileSize) ==
              offsetof(FILE_SCAN_REQUEST, FileSize), "");
static_assert(offsetof(FileScanRequest, fileId) ==
              offsetof(FILE_SCAN_REQUEST, FileId), "");
static_assert(offsetof(FileScanRequest, pathLength) ==
              offsetof(FILE_SCAN_REQUEST, PathLength), "");
static_assert(offsetof(FileScanRequest, processNameLength) ==
              offsetof(FILE_SCAN_REQUEST, ProcessNameLength), "");

}  // namespace

// ============================================================================
// ABSOLUTE OFFSETS - taken from the driver, which is the authority
// ============================================================================

TEST(WireFormatContractTest, ApplicationHeaderFieldOffsetsAreFixed) {
    // Stated as literals on purpose. Comparing the two declarations to each
    // other proves they agree; it does not prove they agree with the driver.
    // These are the numbers the driver writes.
    EXPECT_EQ(0u,  offsetof(SHADOWSTRIKE_MESSAGE_HEADER, Magic));
    EXPECT_EQ(4u,  offsetof(SHADOWSTRIKE_MESSAGE_HEADER, Version));
    EXPECT_EQ(6u,  offsetof(SHADOWSTRIKE_MESSAGE_HEADER, MessageType));
    EXPECT_EQ(8u,  offsetof(SHADOWSTRIKE_MESSAGE_HEADER, MessageId));
    EXPECT_EQ(16u, offsetof(SHADOWSTRIKE_MESSAGE_HEADER, TotalSize));
    EXPECT_EQ(20u, offsetof(SHADOWSTRIKE_MESSAGE_HEADER, DataSize));
    EXPECT_EQ(24u, offsetof(SHADOWSTRIKE_MESSAGE_HEADER, Timestamp));
    EXPECT_EQ(32u, offsetof(SHADOWSTRIKE_MESSAGE_HEADER, Flags));
    EXPECT_EQ(36u, offsetof(SHADOWSTRIKE_MESSAGE_HEADER, Reserved));
    EXPECT_EQ(40u, sizeof(SHADOWSTRIKE_MESSAGE_HEADER));
}

TEST(WireFormatContractTest, PayloadBeginsAtFiftySixBytesIntoTheFrame) {
    // The single number every consumer depends on. 16 + 40. It was computed as
    // 40 + 40 by any translation unit that resolved the transport prefix to the
    // removed alias, and documented as 12 + 40 in two places.
    constexpr size_t kPayloadOffset =
        sizeof(FILTER_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
    EXPECT_EQ(56u, kPayloadOffset);

    // Guard both wrong answers explicitly, so a regression names itself.
    EXPECT_NE(52u, kPayloadOffset) << "transport prefix read as 12 bytes";
    EXPECT_NE(80u, kPayloadOffset) << "transport prefix read as our 40-byte application header";
}

// ============================================================================
// THE DISCRIMINATOR - the two declarations must be interchangeable on real bytes
// ============================================================================

TEST(WireFormatContractTest, BothHeaderDeclarationsReadIdenticalBytesIdentically) {
    // Distinct values per field, so a swap of two same-width neighbours is
    // caught. Matching sizes and offsets cannot catch that; reading the values
    // back can.
    SHADOWSTRIKE_MESSAGE_HEADER driverView{};
    driverView.Magic       = SHADOWSTRIKE_MESSAGE_MAGIC;
    driverView.Version     = SHADOWSTRIKE_PROTOCOL_VERSION;
    driverView.MessageType = 0x1234;
    driverView.MessageId   = 0x0102030405060708ull;
    driverView.TotalSize   = 0x11223344u;
    driverView.DataSize    = 0x55667788u;
    driverView.Timestamp   = 0x1122334455667788ull;
    driverView.Flags       = SHADOWSTRIKE_MSG_FLAG_ENCRYPTED;
    driverView.Reserved    = 0x99aabbccu;

    FilterMessageHeader consumerView{};
    std::memcpy(&consumerView, &driverView, sizeof(driverView));

    EXPECT_EQ(driverView.Magic,     consumerView.magic);
    EXPECT_EQ(driverView.Version,   consumerView.version);
    EXPECT_EQ(driverView.MessageType,
              static_cast<uint16_t>(consumerView.messageType));
    EXPECT_EQ(driverView.MessageId, consumerView.messageId);
    EXPECT_EQ(driverView.TotalSize, consumerView.totalSize);
    EXPECT_EQ(driverView.DataSize,  consumerView.dataSize);
    EXPECT_EQ(driverView.Timestamp, consumerView.timestamp);
    EXPECT_EQ(driverView.Flags,     consumerView.flags);
    EXPECT_EQ(driverView.Reserved,  consumerView.reserved);
}

TEST(WireFormatContractTest, BothScanRequestDeclarationsAgreeOnProcessIdentity) {
    // processId specifically: the field a displaced read of this payload
    // surfaced as a bogus frame magic in the field.
    FILE_SCAN_REQUEST driverView{};
    driverView.MessageId       = 0xAABBCCDDEEFF0011ull;
    driverView.ProcessId       = 11428u;
    driverView.ThreadId        = 3704u;
    driverView.ParentProcessId = 992u;
    driverView.SessionId       = 1u;
    driverView.FileSize        = 0x0123456789ABCDEFull;
    driverView.PathLength      = 260u;

    FileScanRequest consumerView{};
    std::memcpy(&consumerView, &driverView, sizeof(driverView));

    EXPECT_EQ(driverView.MessageId,       consumerView.messageId);
    EXPECT_EQ(driverView.ProcessId,       consumerView.processId);
    EXPECT_EQ(driverView.ThreadId,        consumerView.threadId);
    EXPECT_EQ(driverView.ParentProcessId, consumerView.parentProcessId);
    EXPECT_EQ(driverView.SessionId,       consumerView.sessionId);
    EXPECT_EQ(driverView.FileSize,        consumerView.fileSize);
    EXPECT_EQ(driverView.PathLength,      consumerView.pathLength);
}

// ============================================================================
// THE MAGIC AND VERSION CONSTANTS - declared three times
// ============================================================================

TEST(WireFormatContractTest, AllThreeMagicDeclarationsAgree) {
    // MessageProtocol.h (shared with the driver), Communication.hpp and
    // FileSystemFilter.hpp each declare these independently. A frame is
    // recognised or rejected on this value, so a drift makes one consumer reject
    // every frame the others accept - and rejection on this path means the file
    // was not scanned.
    EXPECT_EQ(SHADOWSTRIKE_MESSAGE_MAGIC,
              ShadowStrike::Communication::MESSAGE_MAGIC);
    EXPECT_EQ(SHADOWSTRIKE_MESSAGE_MAGIC,
              ShadowStrike::RealTime::FilterConstants::MESSAGE_MAGIC);

    EXPECT_EQ(SHADOWSTRIKE_PROTOCOL_VERSION,
              ShadowStrike::Communication::PROTOCOL_VERSION);
    EXPECT_EQ(SHADOWSTRIKE_PROTOCOL_VERSION,
              ShadowStrike::RealTime::FilterConstants::PROTOCOL_VERSION);
}

TEST(WireFormatContractTest, PayloadTransformMaskNamesEveryByteChangingFlag) {
    // A receiver must reverse every transform named here or refuse the frame.
    // The mask exists because a compression transform was applied with no
    // inverse and the receiver parsed transformed bytes as a structure.
    EXPECT_EQ(static_cast<uint32_t>(SHADOWSTRIKE_MSG_FLAG_COMPRESSED |
                                    SHADOWSTRIKE_MSG_FLAG_ENCRYPTED),
              static_cast<uint32_t>(SHADOWSTRIKE_MSG_FLAG_PAYLOAD_TRANSFORMS));

    // Delivery hints must NOT be in the mask: a receiver may ignore them and
    // still parse the payload correctly, so including them would refuse frames
    // that are perfectly readable.
    EXPECT_EQ(0u, SHADOWSTRIKE_MSG_FLAG_PAYLOAD_TRANSFORMS &
                  SHADOWSTRIKE_MSG_FLAG_PRIORITY_HIGH);
    EXPECT_EQ(0u, SHADOWSTRIKE_MSG_FLAG_PAYLOAD_TRANSFORMS &
                  SHADOWSTRIKE_MSG_FLAG_NO_ACK);
}

// ============================================================================
// FILE OPERATION EVENT - the payload that shipped with no header in front of it
// ============================================================================

TEST(WireFormatContractTest, FileOperationEventFieldOffsetsAreFixed) {
    // Absolute offsets, because this payload is what a displaced read exposed in
    // the field. The driver used to send this structure with NO frame header, so
    // the service read its first field where Magic belongs; that field was a
    // kernel HANDLE process id, and the process performing the operation was the
    // scanner itself, so the reported magic was our own pid.
    EXPECT_EQ(0u,  offsetof(SHADOWSTRIKE_FILE_OPERATION_EVENT, ProcessId));
    EXPECT_EQ(4u,  offsetof(SHADOWSTRIKE_FILE_OPERATION_EVENT, InfoClass));
    EXPECT_EQ(8u,  offsetof(SHADOWSTRIKE_FILE_OPERATION_EVENT, BlockReason));
    EXPECT_EQ(12u, offsetof(SHADOWSTRIKE_FILE_OPERATION_EVENT, SuspicionScore));
    EXPECT_EQ(16u, offsetof(SHADOWSTRIKE_FILE_OPERATION_EVENT, WasBlocked));
    EXPECT_EQ(20u, offsetof(SHADOWSTRIKE_FILE_OPERATION_EVENT, Timestamp));
    EXPECT_EQ(28u, offsetof(SHADOWSTRIKE_FILE_OPERATION_EVENT, FileNameBytes));
    EXPECT_EQ(30u, sizeof(SHADOWSTRIKE_FILE_OPERATION_EVENT));

    // No trailing array member, deliberately. A WCHAR Name[1] would make sizeof()
    // carry one phantom character and every size calculation downstream would
    // inherit it.
    EXPECT_EQ(30u, sizeof(SHADOWSTRIKE_FILE_OPERATION_EVENT))
        << "a trailing array member would show up here";
}

TEST(WireFormatContractTest, FileOperationEventIsFramedNotBare) {
    // The defect was structural: a payload sent where a frame belongs. This pins
    // the arithmetic that distinguishes the two, so the framed size can never
    // silently collapse back to the payload size.
    constexpr size_t kBarePayload = sizeof(SHADOWSTRIKE_FILE_OPERATION_EVENT);
    constexpr size_t kFramedMinimum =
        sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + kBarePayload;

    EXPECT_EQ(70u, kFramedMinimum);
    EXPECT_NE(kBarePayload, kFramedMinimum)
        << "a framed event must be larger than its payload by exactly one header";
    EXPECT_EQ(sizeof(SHADOWSTRIKE_MESSAGE_HEADER), kFramedMinimum - kBarePayload);
}

// ============================================================================
// THE BEHAVIOURAL ALERT MUST SATISFY A CONSUMER THAT ALREADY EXISTED
// ============================================================================
//
// BehaviorBlocker::OnKernelBehavioralAlert reads a uint32 process id at offset 0
// and a uint32 parent process id at offset 4, and refuses anything shorter than
// those eight bytes. That consumer was written first and had never been reached:
// the only producer of FilterMessageType_BehavioralAlert in the driver sent a bare
// SHADOWSTRIKE_MESSAGE_HEADER with DataSize == 0, and RealTimeProtection gates the
// call on `if (data && size > 0)`. So the contract existed and was unsatisfiable,
// which is the shape these tests exist to catch.
//
TEST(WireFormatContractTest, BehavioralAlertFieldOffsetsAreFixed) {
    EXPECT_EQ(56u, sizeof(SHADOWSTRIKE_BEHAVIORAL_ALERT));

    EXPECT_EQ(0u,  offsetof(SHADOWSTRIKE_BEHAVIORAL_ALERT, ProcessId));
    EXPECT_EQ(4u,  offsetof(SHADOWSTRIKE_BEHAVIORAL_ALERT, ParentProcessId));
    EXPECT_EQ(8u,  offsetof(SHADOWSTRIKE_BEHAVIORAL_ALERT, ThreadId));
    EXPECT_EQ(12u, offsetof(SHADOWSTRIKE_BEHAVIORAL_ALERT, SequenceNumber));
    EXPECT_EQ(16u, offsetof(SHADOWSTRIKE_BEHAVIORAL_ALERT, Timestamp));
    EXPECT_EQ(24u, offsetof(SHADOWSTRIKE_BEHAVIORAL_ALERT, Keywords));
    EXPECT_EQ(32u, offsetof(SHADOWSTRIKE_BEHAVIORAL_ALERT, CorrelationId));
    EXPECT_EQ(40u, offsetof(SHADOWSTRIKE_BEHAVIORAL_ALERT, EventId));
    EXPECT_EQ(42u, offsetof(SHADOWSTRIKE_BEHAVIORAL_ALERT, Task));
    EXPECT_EQ(44u, offsetof(SHADOWSTRIKE_BEHAVIORAL_ALERT, Level));
    EXPECT_EQ(45u, offsetof(SHADOWSTRIKE_BEHAVIORAL_ALERT, Opcode));
    EXPECT_EQ(46u, offsetof(SHADOWSTRIKE_BEHAVIORAL_ALERT, Priority));
    EXPECT_EQ(47u, offsetof(SHADOWSTRIKE_BEHAVIORAL_ALERT, Source));
    EXPECT_EQ(48u, offsetof(SHADOWSTRIKE_BEHAVIORAL_ALERT, UserDataBytes));
    EXPECT_EQ(52u, offsetof(SHADOWSTRIKE_BEHAVIORAL_ALERT, Reserved0));

    // Every field fixed-width. An enum here would let the layout move silently
    // between the kernel producer and this consumer.
    static_assert(std::is_same_v<decltype(SHADOWSTRIKE_BEHAVIORAL_ALERT::Priority), uint8_t>,
                  "Priority is narrowed from a kernel enum on purpose");
    static_assert(std::is_same_v<decltype(SHADOWSTRIKE_BEHAVIORAL_ALERT::Source), uint8_t>,
                  "Source is narrowed from a kernel enum on purpose");
}

// THE DISCRIMINATOR. This reads the payload byte-for-byte the way
// BehaviorBlocker::OnKernelBehavioralAlert does - two memcpy's from offsets 0 and
// 4 - rather than by naming the fields. A test that read alert.ProcessId would
// pass even if the consumer and the producer disagreed about where the process id
// lives, which is the only failure that matters here.
TEST(WireFormatContractTest, BehavioralAlertIsReadableTheWayTheConsumerReadsIt) {
    SHADOWSTRIKE_BEHAVIORAL_ALERT alert{};
    alert.ProcessId       = 0xA1B2C3D4u;
    alert.ParentProcessId = 0x11223344u;
    alert.ThreadId        = 0x55667788u;

    const auto* raw = reinterpret_cast<const uint8_t*>(&alert);

    // Exactly the consumer's arithmetic.
    constexpr size_t kMinPayload = sizeof(uint32_t) * 2;
    ASSERT_GE(sizeof(alert), kMinPayload)
        << "the payload must satisfy the consumer's documented minimum";

    uint32_t pid = 0;
    uint32_t parentPid = 0;
    std::memcpy(&pid, raw, sizeof(uint32_t));
    std::memcpy(&parentPid, raw + sizeof(uint32_t), sizeof(uint32_t));

    EXPECT_EQ(0xA1B2C3D4u, pid);
    EXPECT_EQ(0x11223344u, parentPid);

    // And the next field must NOT be where the consumer looks for either of those,
    // which is what catches a field inserted at the front.
    EXPECT_NE(alert.ThreadId, pid);
    EXPECT_NE(alert.ThreadId, parentPid);
}

// A header-only frame is what the producer used to emit. It cannot satisfy the
// consumer and it cannot be encrypted, so it must remain distinguishable from a
// real one by size alone - that is the property the kernel's three refusal checks
// rely on.
TEST(WireFormatContractTest, BehavioralAlertHeaderOnlyFrameIsDistinguishable) {
    constexpr size_t kHeaderOnly = sizeof(SHADOWSTRIKE_MESSAGE_HEADER);
    constexpr size_t kFramed =
        sizeof(SHADOWSTRIKE_MESSAGE_HEADER) + sizeof(SHADOWSTRIKE_BEHAVIORAL_ALERT);

    EXPECT_EQ(40u, kHeaderOnly);
    EXPECT_EQ(96u, kFramed);
    EXPECT_GT(kFramed, kHeaderOnly)
        << "the kernel refuses any frame whose size is <= one header, because such "
           "a frame has no payload to encrypt and so cannot be authenticated";

    // The payload the consumer needs cannot fit in a frame that carries none.
    EXPECT_LT(kHeaderOnly, kHeaderOnly + (sizeof(uint32_t) * 2));
}

// ============================================================================
// THE TWO VERDICT REPLIES ARE NOT INTERCHANGEABLE
// ============================================================================
//
// The kernel allocates a DIFFERENT reply buffer per path and user mode must reply
// with the matching one. This is the trap that kept process blocking from ever
// working: the dispatcher owned one reply builder, typed for the file-scan reply,
// so the obvious way to answer a process notification was to send that struct --
// and it is 10 bytes too long for the buffer ProcessNotify.c allocates.
//
// What makes it worth a permanent test is that the failure is INVISIBLE in every
// way a developer would normally notice. It is not a compile error, because both
// are plain structs. It is not a wrong verdict, because both place Verdict at the
// same offset, so the byte would have been right. It is an oversized reply that
// Filter Manager refuses, after which the kernel simply waits out its budget and
// fails open, leaving one Debug-level line behind.
TEST(WireFormatContractTest, ProcessAndScanVerdictRepliesAreDifferentSizes) {
    // Sizes the two drivers' paths actually allocate.
    EXPECT_EQ(16u, sizeof(SHADOWSTRIKE_PROCESS_VERDICT_REPLY));
    EXPECT_EQ(26u, sizeof(SHADOWSTRIKE_SCAN_VERDICT_REPLY));

    // The property that matters: they are NOT the same size, so one cannot stand
    // in for the other. If a future edit makes them equal, the distinction this
    // test exists to protect has gone and the branch in DispatchMessage becomes
    // untestable by size.
    EXPECT_NE(sizeof(SHADOWSTRIKE_PROCESS_VERDICT_REPLY),
              sizeof(SHADOWSTRIKE_SCAN_VERDICT_REPLY));

    // And the scan reply is the LARGER one, which is the direction that fails:
    // sending it into the process path's buffer overruns what the driver allocated.
    EXPECT_GT(sizeof(SHADOWSTRIKE_SCAN_VERDICT_REPLY),
              sizeof(SHADOWSTRIKE_PROCESS_VERDICT_REPLY))
        << "the scan reply must remain the larger of the two, otherwise the "
           "overflow direction this test documents has silently reversed";
}

// The coincidence that made the wrong struct look correct, pinned deliberately.
// Both replies carry Verdict at offset 8. That is why swapping them produces a
// correct verdict byte and an undeliverable reply -- the hardest kind of defect to
// find, because every value you inspect is right.
TEST(WireFormatContractTest, BothVerdictRepliesCarryVerdictAtOffsetEight) {
    EXPECT_EQ(0u, offsetof(SHADOWSTRIKE_PROCESS_VERDICT_REPLY, MessageId));
    EXPECT_EQ(8u, offsetof(SHADOWSTRIKE_PROCESS_VERDICT_REPLY, Verdict));
    EXPECT_EQ(9u, offsetof(SHADOWSTRIKE_PROCESS_VERDICT_REPLY, ThreatScore));
    EXPECT_EQ(12u, offsetof(SHADOWSTRIKE_PROCESS_VERDICT_REPLY, Flags));

    EXPECT_EQ(offsetof(SHADOWSTRIKE_SCAN_VERDICT_REPLY, Verdict),
              offsetof(SHADOWSTRIKE_PROCESS_VERDICT_REPLY, Verdict))
        << "both replies place Verdict at the same offset; this is a coincidence "
           "the code must not rely on, and it is recorded here so the next reader "
           "understands why the size is the only thing that distinguishes them";

    // The driver reads the verdict only when the delivered length reaches the
    // field, so the minimum useful process reply is offset + one byte.
    constexpr size_t kMinUsable =
        offsetof(SHADOWSTRIKE_PROCESS_VERDICT_REPLY, Verdict) + sizeof(UINT8);
    EXPECT_EQ(9u, kMinUsable);
    EXPECT_LE(kMinUsable, sizeof(SHADOWSTRIKE_PROCESS_VERDICT_REPLY));
}

// A blocking verdict must be the one value the driver acts on. Verdict_Malicious
// is the only value ProcessNotify.c turns into STATUS_ACCESS_DENIED, so every
// other verdict user mode can produce must be non-blocking by construction.
TEST(WireFormatContractTest, OnlyMaliciousBlocksAProcessCreation) {
    EXPECT_EQ(2, static_cast<int>(Verdict_Malicious));

    // Everything the dispatcher can send on a refusal path must NOT equal it,
    // otherwise a malformed payload or a handler exception would block a process.
    EXPECT_NE(static_cast<int>(Verdict_Malicious), static_cast<int>(Verdict_Unknown));
    EXPECT_NE(static_cast<int>(Verdict_Malicious), static_cast<int>(Verdict_Error));
    EXPECT_NE(static_cast<int>(Verdict_Malicious), static_cast<int>(Verdict_Clean));
    EXPECT_NE(static_cast<int>(Verdict_Malicious), static_cast<int>(Verdict_Suspicious));
    EXPECT_NE(static_cast<int>(Verdict_Malicious), static_cast<int>(Verdict_Timeout));

    // Verdict is a single byte on the wire, so every value must survive narrowing.
    EXPECT_EQ(static_cast<int>(Verdict_Malicious),
              static_cast<int>(static_cast<UINT8>(Verdict_Malicious)));
    EXPECT_EQ(static_cast<int>(Verdict_Timeout),
              static_cast<int>(static_cast<UINT8>(Verdict_Timeout)));
}

// ============================================================================
// PER-TYPE STATISTICS MUST COVER EVERY TYPE ON THE WIRE
// ============================================================================
//
// These assertions live in IpcStatistics_Tests.cpp. They need IPCManager.hpp,
// which cannot be included in this translation unit alongside Communication.hpp
// (see the note at the top of this file).

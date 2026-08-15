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

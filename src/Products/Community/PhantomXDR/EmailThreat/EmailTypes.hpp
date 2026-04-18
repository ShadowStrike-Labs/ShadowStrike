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
#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::EmailThreat {

enum class PhishingIndicator : uint32_t {
    None                        = 0,
    SuspiciousSender            = 1u << 0,
    SpoofedDomain               = 1u << 1,
    UrgentLanguage              = 1u << 2,
    SuspiciousLink              = 1u << 3,
    MismatchedURL               = 1u << 4,
    HomoglyphDomain             = 1u << 5,
    RecentlyRegisteredDomain    = 1u << 6,
    SuspiciousAttachment        = 1u << 7,
    MacroAttachment             = 1u << 8,
    PasswordProtectedAttachment = 1u << 9,
    ExecutableAttachment        = 1u << 10,
    DoubleExtension             = 1u << 11,
    HeaderAnomaly               = 1u << 12,
    SPFFailure                  = 1u << 13,
    DKIMFailure                 = 1u << 14,
    DMARCFailure                = 1u << 15
};

[[nodiscard]] inline constexpr PhishingIndicator operator|(const PhishingIndicator lhs,
                                                            const PhishingIndicator rhs) noexcept {
    return static_cast<PhishingIndicator>(
        static_cast<uint32_t>(lhs) | static_cast<uint32_t>(rhs));
}

[[nodiscard]] inline constexpr PhishingIndicator operator&(const PhishingIndicator lhs,
                                                            const PhishingIndicator rhs) noexcept {
    return static_cast<PhishingIndicator>(
        static_cast<uint32_t>(lhs) & static_cast<uint32_t>(rhs));
}

inline constexpr PhishingIndicator& operator|=(PhishingIndicator& lhs,
                                               const PhishingIndicator rhs) noexcept {
    lhs = lhs | rhs;
    return lhs;
}

[[nodiscard]] inline constexpr bool HasIndicator(const PhishingIndicator mask,
                                                 const PhishingIndicator flag) noexcept {
    return (static_cast<uint32_t>(mask) & static_cast<uint32_t>(flag)) != 0;
}

enum class EmailVerdict : uint8_t {
    Clean = 0,
    Suspicious,
    Phishing,
    Malicious,
    Spear_Phishing
};

struct EmailHeader {
    std::string from;
    std::string to;
    std::string cc;
    std::string subject;
    std::string date;
    std::string messageId;
    std::string inReplyTo;
    std::vector<std::string> receivedChain;
    std::string returnPath;
    std::string spfResult;
    std::string dkimResult;
    std::string dmarcResult;
};

struct EmailAttachment {
    std::string filename;
    std::string contentType;
    uint64_t size = 0;
    std::string sha256;
    bool isExecutable = false;
    bool hasMacro = false;
    bool isPasswordProtected = false;
    bool isDoubleExtension = false;
};

struct EndpointExecutionMatch {
    int64_t timestamp = 0;
    uint32_t processId = 0;
    std::string processName;
    std::string processPath;
    std::string commandLine;
    std::string userName;
    std::string sourceTable;
    std::string sourceEvent;
};

struct CorrelationTimelineEvent {
    int64_t timestamp = 0;
    std::string phase;
    std::string description;
    std::string artifact;
};

struct EmailAnalysisResult {
    std::string filePath;
    std::string fileSha256;
    EmailHeader header;
    EmailVerdict verdict = EmailVerdict::Clean;
    PhishingIndicator indicators = PhishingIndicator::None;
    double confidence = 0.0;
    std::vector<EmailAttachment> attachmentsAnalyzed;
    std::vector<std::string> linksExtracted;
    std::vector<std::string> suspiciousLinks;
    std::vector<std::string> headerAnomalies;
    std::string mitreTechnique;
    std::string summary;
    std::chrono::system_clock::time_point analyzedAt{};
};

struct PhishingCorrelation {
    std::string emailMessageId;
    std::vector<std::string> attachmentHashes;
    std::vector<EndpointExecutionMatch> endpointExecutionsMatched;
    std::vector<CorrelationTimelineEvent> timeline;
    EmailVerdict verdict = EmailVerdict::Clean;
    double confidence = 0.0;
    std::vector<std::string> matchedUrls;
    std::vector<std::string> relatedSenders;
    bool escalated = false;
};

struct EmailAnalyzerStatistics {
    uint64_t totalScans = 0;
    uint64_t suspiciousScans = 0;
    uint64_t phishingScans = 0;
    uint64_t maliciousScans = 0;
    uint64_t totalAttachments = 0;
    uint64_t totalLinks = 0;
    uint64_t emlFilesParsed = 0;
    uint64_t msgFilesParsed = 0;
    uint64_t persistedResults = 0;
    uint64_t databaseFailures = 0;
};

struct PhishingCorrelationStatistics {
    uint64_t totalCorrelations = 0;
    uint64_t escalatedCorrelations = 0;
    uint64_t attachmentExecutionMatches = 0;
    uint64_t urlVisitMatches = 0;
    uint64_t senderMatches = 0;
    uint64_t timelineEventsPersisted = 0;
    uint64_t databaseFailures = 0;
};

} // namespace ShadowStrike::Products::PhantomXDR::EmailThreat

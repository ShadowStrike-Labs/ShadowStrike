/*
 * ShadowStrike - Enterprise NGAV/EDR/XDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

#pragma once

/// @file XDRTypes.hpp
/// @brief Shared types for the entire XDR Correlation subsystem.

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace ShadowStrike::Products::PhantomXDR::XDRCorrelation {

using TimePoint = std::chrono::system_clock::time_point;

// ============================================================================
// DOMAIN & SEVERITY
// ============================================================================

enum class XDREventDomain : uint8_t {
    Unknown   = 0,
    Endpoint  = 1,
    Network   = 2,
    Identity  = 3,
    Email     = 4,
    Cloud     = 5,
};

enum class IncidentSeverity : uint8_t {
    Info     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
};

// ============================================================================
// XDR EVENT (unified cross-domain event)
// ============================================================================

struct XDREvent {
    uint64_t        eventId{0};
    XDREventDomain  domain{XDREventDomain::Unknown};
    TimePoint       timestamp{};
    uint8_t         severity{0};

    std::string     userName;
    std::string     hostName;
    std::string     ipAddress;
    std::string     fileHash;
    std::string     sessionId;
    uint32_t        processId{0};

    std::string     mitreAttackId;
    std::string     mitreTactic;
    std::string     sourceModule;

    std::map<std::string, std::string> metadata;
};

// ============================================================================
// CORRELATION RULE PRIMITIVES
// ============================================================================

enum class ConditionOp : uint8_t {
    Equals      = 0,
    NotEquals   = 1,
    Contains    = 2,
    StartsWith  = 3,
    EndsWith    = 4,
    Regex       = 5,
    GreaterThan = 6,
    LessThan    = 7,
    InSet       = 8,
};

enum class EntityLink : uint8_t {
    SameUser     = 0,
    SameHost     = 1,
    SameIP       = 2,
    SameProcess  = 3,
    SameFileHash = 4,
    SameSession  = 5,
};

enum class CorrelationVerdict : uint8_t {
    Benign        = 0,
    Informational = 1,
    Suspicious    = 2,
    Malicious     = 3,
    Critical      = 4,
};

enum class RuleStatus : uint8_t {
    Inactive = 0,
    Active   = 1,
    Testing  = 2,
};

struct RuleCondition {
    XDREventDomain  domain{XDREventDomain::Unknown};
    std::string     fieldName;
    ConditionOp     op{ConditionOp::Equals};
    std::string     value;
    uint8_t         minSeverity{0};
};

struct CorrelationRule {
    std::string                 ruleId;
    std::string                 name;
    std::string                 description;
    RuleStatus                  status{RuleStatus::Active};
    uint8_t                     confidence{50};
    CorrelationVerdict          verdict{CorrelationVerdict::Suspicious};
    uint32_t                    timeWindowSec{900};
    std::vector<EntityLink>     entityLinks;
    std::string                 mitreAttackId;
    std::string                 mitreTactic;
    std::vector<RuleCondition>  conditions;
    TimePoint                   createdAt{};
    TimePoint                   updatedAt{};
};

// ============================================================================
// CORRELATION MATCH
// ============================================================================

struct CorrelationMatch {
    std::string               matchId;
    std::string               ruleId;
    std::string               ruleName;
    CorrelationVerdict        verdict{CorrelationVerdict::Suspicious};
    uint8_t                   confidence{0};
    TimePoint                 firstEventTime{};
    TimePoint                 lastEventTime{};
    std::vector<uint64_t>     matchedEventIds;
    std::string               linkedEntity;
    EntityLink                linkDimension{EntityLink::SameUser};
};

// ============================================================================
// STORYLINE TYPES
// ============================================================================

enum class StorylinePhase : uint8_t {
    Unknown              = 0,
    Reconnaissance       = 1,
    ResourceDevelopment  = 2,
    InitialAccess        = 3,
    Execution            = 4,
    Persistence          = 5,
    PrivilegeEscalation  = 6,
    DefenseEvasion       = 7,
    CredentialAccess     = 8,
    Discovery            = 9,
    LateralMovement      = 10,
    Collection           = 11,
    CommandAndControl    = 12,
    Exfiltration         = 13,
    Impact               = 14,
};

struct StorylineNode {
    uint64_t                 eventId{0};
    XDREventDomain           domain{XDREventDomain::Unknown};
    StorylinePhase           phase{StorylinePhase::Unknown};
    TimePoint                timestamp{};
    std::string              mitreAttackId;
    std::string              description;
    std::vector<uint64_t>    parentEventIds;
};

struct Storyline {
    std::string                 storylineId;
    std::string                 title;
    IncidentSeverity            severity{IncidentSeverity::Info};
    TimePoint                   startTime{};
    TimePoint                   endTime{};
    std::string                 narrative;
    std::vector<std::string>    mitreTactics;
    std::vector<std::string>    mitreTechniques;
    std::vector<std::string>    affectedUsers;
    std::vector<std::string>    affectedHosts;
    uint8_t                     killChainCoverage{0};
    std::vector<StorylineNode>  nodes;
};

// ============================================================================
// INCIDENT SCORE
// ============================================================================

struct IncidentScore {
    std::string       storylineId;
    double            rawScore{0.0};
    double            normalizedScore{0.0};
    IncidentSeverity  severity{IncidentSeverity::Info};

    double            tacticScore{0.0};
    double            techniqueScore{0.0};
    double            crossDomainScore{0.0};
    double            temporalScore{0.0};
    double            killChainScore{0.0};

    uint32_t          uniqueTactics{0};
    uint32_t          uniqueTechniques{0};
    uint32_t          domainsInvolved{0};
    bool              temporalOrderCorrect{false};

    std::string       explanation;
};

// ============================================================================
// CORRELATION STATISTICS
// ============================================================================

struct CorrelationStatistics {
    uint64_t  totalEventsIngested{0};
    uint64_t  totalRulesEvaluated{0};
    uint64_t  totalMatchesProduced{0};
    size_t    activeWindowEvents{0};
    uint32_t  activeRuleCount{0};
    uint32_t  activeStorylineCount{0};
};

} // namespace ShadowStrike::Products::PhantomXDR::XDRCorrelation

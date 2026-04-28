/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * AnalysisTypes.hpp — Convenience header: re-exports all shared analysis types
 *
 * Aggregates the canonical type definitions from each analysis module so that
 * downstream consumers (ThreatScorer, MITREMapper, IOCExtractor) can include
 * a single header to access BehaviorAlert, SequenceMatch, MemoryFindingDetail,
 * CryptoFinding, PackerType, etc. without depending on every individual module
 * header.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

// Canonical type definitions — each type is defined exactly once in the
// module that owns it.  This header merely re-exports them.

#include "BehaviorMonitor.hpp"        // AlertSeverity, BehaviorCategory, BehaviorAlert
#include "CryptoDetector.hpp"         // CryptoAlgorithm, CryptoFinding, CryptoStats
#include "MemoryForensics.hpp"        // MemoryFinding, MemoryFindingDetail
#include "UnpackingEngine.hpp"        // PackerType
#include "APISequenceAnalyzer.hpp"    // SequenceMatch

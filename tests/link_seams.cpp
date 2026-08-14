/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file link_seams.cpp
 * @brief The choices phantom-tests makes at the link seams PhantomCoreLib
 *        deliberately leaves open.
 *
 * PhantomCoreLib is not a closed library. It contains objects that reference
 * symbols it does not define, and expects the LINKING BINARY to supply them.
 * WiringStub.cpp states that contract in its own header comment: "The
 * service-side PhantomCoreLib expects EnsureAllModulesWired() to be provided by
 * the linking binary."
 *
 * There are three linking binaries today and each answers differently:
 *
 *   ShadowStrikePhantomService  WiringAnchor.cpp  - force-references every
 *                                                   PhantomHome module TU
 *   ShadowStrikePhantomUI       WiringStub.cpp    - no-op; the UI process does
 *                                                   not host the module registry
 *   phantom-tests               THIS FILE         - no-op, for the same reason
 *
 * WHY THE TEST BINARY TAKES THE STUB AND NOT THE ANCHOR. WiringAnchor.cpp exists
 * to stop /OPT:REF and /LTCG discarding roughly forty PhantomHome wiring
 * translation units, and it does that by taking the address of a
 * PhantomHome_KeepAlive_* extern for each one. Those live in the PhantomHome
 * product, not in PhantomCoreLib, so linking the anchor here would introduce
 * about forty fresh unresolved externals in exchange for anchoring TUs this
 * binary does not contain. The stub is not a weaker choice, it is the correct
 * one: a no-op is what "this process does not host the module registry" means.
 *
 * WHAT IS DELIBERATELY *NOT* STUBBED HERE, AND WHY IT MATTERS MORE THAN WHAT IS.
 * The same link failure also named HomeReportsStore::Instance/Query/GetRecent,
 * referenced by HomeIpcDispatcher.obj and RecommendationsEngine.obj inside the
 * library. Those are NOT stubbed. HomeReportsStore has exactly one
 * implementation and the library genuinely depends on it, so the real
 * HomeReportsStore.cpp is compiled into this project instead - the same file the
 * service compiles. Stubbing it would have been faster and would have made every
 * test that reaches a report query pass against a store that returns nothing,
 * which is indistinguishable from a store that works and holds no reports. This
 * codebase has produced that exact failure often enough (an empty Bloom filter
 * answering "not present" to every lookup; a fixture that never initialised the
 * store so every scan assertion was vacuous) that a stub is only acceptable
 * where the absence of behaviour IS the correct behaviour. Here it is, for the
 * wiring anchor, and it is not, for the report store.
 *
 * RECORDED, NOT FIXED HERE: that PhantomCoreLib carries objects whose
 * definitions only the service supplies is a real structural issue - any new
 * consumer of the library hits it the moment it touches one of those objects,
 * and the error names a mangled symbol rather than the missing file. Moving
 * HomeReportsStore.cpp into the library would close it, but that changes the
 * link topology of the shipping service and the UI, so it belongs in its own
 * change with both of those re-verified, not in a change that enables test
 * suites.
 */

namespace ShadowStrike::Products::Home {

void EnsureAllModulesWired() noexcept {
    // No-op: phantom-tests does not host the PhantomHome module registry.
    // Suites that need a module exercise it directly.
}

}  // namespace ShadowStrike::Products::Home

// ============================================================================
//  CortexSwitch.hpp - the single switch that turns on-device AI/ML on or off
// ----------------------------------------------------------------------------
//  Change ONE line to enable or disable every PhantomCortex inference path
//  across the product. Everything else derives from it.
//
//  WHY THIS EXISTS, AND WHY IT SHIPS AT 0
//
//  PhantomCortex is complete on the C++ side - PhantomCortex.cpp, the ONNX
//  bridge in ModelInference.cpp, ModelCache.cpp, the 74 KB feature extractor
//  and CortexConfig.cpp are all real, working code. What is missing is the
//  trained models. There is no .onnx anywhere in the tree that belongs to this
//  product, and the installer staging directory ships none, so on a deployed
//  machine ModelCache reports a load failure and every inference call takes an
//  early exit.
//
//  That early exit is safe. MakeErrorVerdict in PhantomCortex.cpp returns
//  ThreatVerdict::Benign with confidence 0.0, and no failure path in the AI or
//  Engine code yields Malicious. So the models being absent has never produced
//  a false positive - it produces silence.
//
//  Turning it off therefore removes ZERO detection coverage. It cannot, because
//  there is no coverage to remove: an engine that always answers Benign with
//  zero confidence contributes nothing to a verdict. What it does remove is the
//  cost of walking up to the point where the model turns out to be missing -
//  feature extraction and the call itself - on the scan path.
//
//  This is the one case where disabling something is not weakening detection.
//  When models exist and are packaged, flip this to 1 and every call site comes
//  back on with no other edit. That is the whole point of routing it through a
//  single constant instead of scattering per-site decisions.
//
//  Do not use this switch to silence a misbehaving model. If a model is wrong,
//  fix or retrain it - a detector that is disabled to hide a defect is a
//  regression wearing a configuration flag.
// ============================================================================

#pragma once

// ----------------------------------------------------------------------------
// THE SWITCH. 0 = AI/ML off everywhere. 1 = on.
// ----------------------------------------------------------------------------
#ifndef SHADOWSTRIKE_ENABLE_CORTEX
#define SHADOWSTRIKE_ENABLE_CORTEX 0
#endif

namespace ShadowStrike::AI {

    /// Compile-time state of the on-device AI/ML subsystem.
    ///
    /// Used as the default initialiser for every ML feature flag so that the
    /// switch above is the only place the decision is made. Call sites keep
    /// their runtime flags, so a build with Cortex enabled can still turn it off
    /// per scan profile or per configuration.
    inline constexpr bool kCortexEnabled = (SHADOWSTRIKE_ENABLE_CORTEX != 0);

} // namespace ShadowStrike::AI

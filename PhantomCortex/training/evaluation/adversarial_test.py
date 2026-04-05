"""
Adversarial Evasion Tester for PhantomCortex Models
=====================================================

Tests model robustness against adversarial perturbation attacks commonly
used by threat actors to evade ML-based detection:

    - Append attack: append benign bytes to malware samples
    - Section injection: add legitimate-looking PE sections
    - Import table manipulation: add decoy imports
    - Header manipulation: modify timestamps, checksums
    - Packer wrapping: pack known malware and re-test
    - Feature-space gradient attack: perturb features directly

Measures:
    - Evasion rate (fraction of detected malware that evades after attack)
    - Perturbation magnitude needed to achieve evasion
    - Per-attack-type breakdowns
"""

from __future__ import annotations

import enum
import logging
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Union

import numpy as np
import onnxruntime as ort
from numpy.typing import NDArray
from pathlib import Path

logger = logging.getLogger("PhantomCortex.Evaluation.Adversarial")


# ---------------------------------------------------------------------------
# Attack types
# ---------------------------------------------------------------------------


class AttackType(enum.Enum):
    """Adversarial attack categories."""

    APPEND_BYTES = "append_bytes"
    SECTION_INJECTION = "section_injection"
    IMPORT_MANIPULATION = "import_manipulation"
    HEADER_MANIPULATION = "header_manipulation"
    PACKER_WRAPPING = "packer_wrapping"
    FEATURE_SPACE = "feature_space"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AttackResult:
    """Result of a single adversarial attack on one sample."""

    sample_index: int
    attack_type: str
    original_score: float
    perturbed_score: float
    evaded: bool
    perturbation_magnitude: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_index": self.sample_index,
            "attack_type": self.attack_type,
            "original_score": round(self.original_score, 6),
            "perturbed_score": round(self.perturbed_score, 6),
            "evaded": self.evaded,
            "perturbation_magnitude": round(self.perturbation_magnitude, 6),
        }


@dataclass(frozen=True)
class AttackSummary:
    """Summary metrics for one attack type."""

    attack_type: str
    samples_tested: int
    originally_detected: int
    evaded_count: int
    evasion_rate: float
    mean_perturbation: float
    median_perturbation: float
    min_perturbation_to_evade: Optional[float]

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_type": self.attack_type,
            "samples_tested": self.samples_tested,
            "originally_detected": self.originally_detected,
            "evaded_count": self.evaded_count,
            "evasion_rate": round(self.evasion_rate, 6),
            "mean_perturbation": round(self.mean_perturbation, 6),
            "median_perturbation": round(self.median_perturbation, 6),
            "min_perturbation_to_evade": (
                round(self.min_perturbation_to_evade, 6)
                if self.min_perturbation_to_evade is not None
                else None
            ),
        }


@dataclass(frozen=True)
class AdversarialReport:
    """Complete adversarial testing report."""

    total_samples: int
    attacks_executed: int
    overall_evasion_rate: float
    overall_resistance_score: float
    per_attack_summary: list[AttackSummary]
    detailed_results: list[AttackResult] = field(repr=False)
    test_time_sec: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_samples": self.total_samples,
            "attacks_executed": self.attacks_executed,
            "overall_evasion_rate": round(self.overall_evasion_rate, 6),
            "overall_resistance_score": round(self.overall_resistance_score, 6),
            "per_attack_summary": [s.to_dict() for s in self.per_attack_summary],
            "test_time_sec": round(self.test_time_sec, 3),
        }


# ---------------------------------------------------------------------------
# Feature-space perturbation strategies
# ---------------------------------------------------------------------------


class _FeatureSpacePerturbations:
    """Feature-vector-level adversarial perturbation generators.

    Operates directly on extracted feature vectors to test model
    robustness without requiring raw PE file manipulation.
    """

    @staticmethod
    def append_bytes_perturbation(
        features: NDArray[np.float32],
        *,
        magnitude: float = 0.05,
        rng: np.random.Generator,
    ) -> NDArray[np.float32]:
        """Simulate append attack: add small noise to file-size features.

        Appending benign bytes mainly affects file size, entropy of
        the overlay section, and byte histogram features.
        """
        perturbed = features.copy()
        n_features = features.shape[-1]

        # Affect ~5% of features (simulating byte histogram changes)
        n_perturb = max(1, int(n_features * 0.05))
        indices = rng.choice(n_features, size=n_perturb, replace=False)

        noise = rng.normal(0, magnitude, size=n_perturb).astype(np.float32)
        if perturbed.ndim == 1:
            perturbed[indices] += noise
        else:
            perturbed[:, indices] += noise
        return perturbed

    @staticmethod
    def section_injection_perturbation(
        features: NDArray[np.float32],
        *,
        magnitude: float = 0.1,
        rng: np.random.Generator,
    ) -> NDArray[np.float32]:
        """Simulate section injection: perturb section-related features.

        Adding a .text-like section changes PE structure features:
        section count, sizes, entropy distribution.
        """
        perturbed = features.copy()
        n_features = features.shape[-1]

        # Affect ~10% of features (structural PE features)
        n_perturb = max(1, int(n_features * 0.10))
        indices = rng.choice(n_features, size=n_perturb, replace=False)

        noise = rng.normal(0, magnitude, size=n_perturb).astype(np.float32)
        if perturbed.ndim == 1:
            perturbed[indices] += noise
        else:
            perturbed[:, indices] += noise
        return perturbed

    @staticmethod
    def import_manipulation_perturbation(
        features: NDArray[np.float32],
        *,
        magnitude: float = 0.08,
        rng: np.random.Generator,
    ) -> NDArray[np.float32]:
        """Simulate import table manipulation: add decoy imports.

        Adding benign imports (e.g., from kernel32, user32) changes the
        import-related feature dimensions.
        """
        perturbed = features.copy()
        n_features = features.shape[-1]

        n_perturb = max(1, int(n_features * 0.07))
        indices = rng.choice(n_features, size=n_perturb, replace=False)

        # Shift toward benign distribution (positive offset)
        shift = rng.uniform(0, magnitude, size=n_perturb).astype(np.float32)
        if perturbed.ndim == 1:
            perturbed[indices] += shift
        else:
            perturbed[:, indices] += shift
        return perturbed

    @staticmethod
    def header_manipulation_perturbation(
        features: NDArray[np.float32],
        *,
        magnitude: float = 0.03,
        rng: np.random.Generator,
    ) -> NDArray[np.float32]:
        """Simulate header manipulation: modify timestamps, checksums.

        Header changes are minor and affect only a few features.
        """
        perturbed = features.copy()
        n_features = features.shape[-1]

        n_perturb = max(1, int(n_features * 0.02))
        indices = rng.choice(n_features, size=n_perturb, replace=False)

        noise = rng.normal(0, magnitude, size=n_perturb).astype(np.float32)
        if perturbed.ndim == 1:
            perturbed[indices] += noise
        else:
            perturbed[:, indices] += noise
        return perturbed

    @staticmethod
    def packer_wrapping_perturbation(
        features: NDArray[np.float32],
        *,
        magnitude: float = 0.3,
        rng: np.random.Generator,
    ) -> NDArray[np.float32]:
        """Simulate packer wrapping: significant feature transformation.

        Packing malware dramatically changes byte histogram, entropy,
        section layout, and import table features.
        """
        perturbed = features.copy()
        n_features = features.shape[-1]

        # Affect ~40% of features (packing changes everything)
        n_perturb = max(1, int(n_features * 0.40))
        indices = rng.choice(n_features, size=n_perturb, replace=False)

        noise = rng.normal(0, magnitude, size=n_perturb).astype(np.float32)
        if perturbed.ndim == 1:
            perturbed[indices] += noise
        else:
            perturbed[:, indices] += noise
        return perturbed

    @staticmethod
    def gradient_approximation_attack(
        features: NDArray[np.float32],
        score_fn: Callable[[NDArray[np.float32]], NDArray[np.float64]],
        *,
        epsilon: float = 0.01,
        steps: int = 20,
        step_size: float = 0.005,
    ) -> NDArray[np.float32]:
        """Zeroth-order gradient approximation attack (FGSM-like).

        Estimates the gradient of the model score with respect to input
        features using finite differences, then steps in the direction
        that decreases the malware score.

        Args:
            features: Input feature vector(s).
            score_fn: Callable returning malware probability scores.
            epsilon: Finite difference step for gradient estimation.
            steps: Number of attack iterations.
            step_size: Perturbation step size per iteration.

        Returns:
            Perturbed feature vector(s).
        """
        perturbed = features.copy()
        n_features = features.shape[-1]

        for _ in range(steps):
            current_score = score_fn(perturbed)
            if perturbed.ndim == 1 and current_score.ndim == 0:
                if float(current_score) < 0.5:
                    break  # already evading

            grad = np.zeros_like(perturbed)
            for f_idx in range(n_features):
                perturbed_plus = perturbed.copy()
                if perturbed_plus.ndim == 1:
                    perturbed_plus[f_idx] += epsilon
                else:
                    perturbed_plus[:, f_idx] += epsilon

                score_plus = score_fn(perturbed_plus)
                # Gradient: direction to increase score
                g = (score_plus - current_score) / epsilon
                if perturbed.ndim == 1:
                    grad[f_idx] = float(g)
                else:
                    grad[:, f_idx] = g

            # Step in direction that decreases score (negative gradient)
            perturbed = perturbed - step_size * np.sign(grad).astype(np.float32)

        return perturbed


# ---------------------------------------------------------------------------
# AdversarialTester
# ---------------------------------------------------------------------------


class AdversarialTester:
    """Test model robustness against adversarial evasion attacks.

    Operates in feature space: takes pre-extracted feature vectors,
    applies various perturbation strategies, and measures whether the
    model's detection is evaded.

    For raw PE-level attacks, integrate with a PE feature extractor.
    """

    def __init__(
        self,
        *,
        threshold: float = 0.5,
        seed: int = 42,
    ) -> None:
        """Initialize adversarial tester.

        Args:
            threshold: Decision threshold for malicious classification.
            seed: Random seed for reproducible perturbations.
        """
        self._threshold = threshold
        self._rng = np.random.default_rng(seed)
        self._perturbations = _FeatureSpacePerturbations()

    # ------------------------------------------------------------------
    # Full test suite
    # ------------------------------------------------------------------

    def run_all_attacks(
        self,
        model_path: Union[str, Path],
        malware_features: NDArray[np.float32],
        *,
        attack_types: Optional[list[AttackType]] = None,
        magnitudes: Optional[dict[AttackType, list[float]]] = None,
    ) -> AdversarialReport:
        """Execute all attack types against the model on malware samples.

        Args:
            model_path: Path to the ONNX model.
            malware_features: Feature matrix of known-malware samples.
            attack_types: Subset of attacks to run (None = all).
            magnitudes: Per-attack magnitude sweep values.

        Returns:
            AdversarialReport with per-attack breakdowns.
        """
        if attack_types is None:
            attack_types = [
                AttackType.APPEND_BYTES,
                AttackType.SECTION_INJECTION,
                AttackType.IMPORT_MANIPULATION,
                AttackType.HEADER_MANIPULATION,
                AttackType.PACKER_WRAPPING,
            ]

        default_magnitudes: dict[AttackType, list[float]] = {
            AttackType.APPEND_BYTES: [0.01, 0.05, 0.1, 0.2],
            AttackType.SECTION_INJECTION: [0.05, 0.1, 0.2, 0.3],
            AttackType.IMPORT_MANIPULATION: [0.02, 0.05, 0.08, 0.15],
            AttackType.HEADER_MANIPULATION: [0.01, 0.03, 0.05, 0.1],
            AttackType.PACKER_WRAPPING: [0.1, 0.2, 0.3, 0.5],
        }
        if magnitudes is not None:
            default_magnitudes.update(magnitudes)

        sess_opts = ort.SessionOptions()
        sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        session = ort.InferenceSession(str(model_path), sess_opts)
        input_name = session.get_inputs()[0].name

        start_time = time.monotonic()

        # Get original scores
        if malware_features.ndim == 1:
            malware_features = malware_features.reshape(1, -1)

        original_outputs = session.run(None, {input_name: malware_features})[0]
        original_scores = original_outputs.flatten().astype(np.float64)
        originally_detected = original_scores >= self._threshold

        all_results: list[AttackResult] = []
        all_summaries: list[AttackSummary] = []
        total_evaded = 0
        total_detected = int(originally_detected.sum())

        for attack_type in attack_types:
            mags = default_magnitudes.get(attack_type, [0.1])
            attack_results = self._run_single_attack(
                session,
                input_name,
                malware_features,
                original_scores,
                originally_detected,
                attack_type,
                mags,
            )
            all_results.extend(attack_results)

            summary = self._summarize_attack(attack_results, attack_type)
            all_summaries.append(summary)
            total_evaded += summary.evaded_count

        elapsed = time.monotonic() - start_time

        overall_evasion = total_evaded / max(total_detected * len(attack_types), 1)
        resistance = 1.0 - overall_evasion

        report = AdversarialReport(
            total_samples=len(malware_features),
            attacks_executed=len(all_results),
            overall_evasion_rate=overall_evasion,
            overall_resistance_score=resistance,
            per_attack_summary=all_summaries,
            detailed_results=all_results,
            test_time_sec=elapsed,
        )

        logger.info(
            "Adversarial testing complete: %d attacks, evasion_rate=%.4f, "
            "resistance=%.4f (%.2fs)",
            len(all_results),
            overall_evasion,
            resistance,
            elapsed,
        )

        return report

    # ------------------------------------------------------------------
    # Gradient-based attack
    # ------------------------------------------------------------------

    def run_gradient_attack(
        self,
        model_path: Union[str, Path],
        malware_features: NDArray[np.float32],
        *,
        steps: int = 20,
        step_size: float = 0.005,
        epsilon: float = 0.01,
    ) -> AdversarialReport:
        """Run zeroth-order gradient approximation attack.

        More expensive but more targeted than heuristic perturbations.

        Args:
            model_path: Path to the ONNX model.
            malware_features: Feature matrix of malware samples.
            steps: Gradient attack iterations per sample.
            step_size: Step size per iteration.
            epsilon: Finite difference epsilon.

        Returns:
            AdversarialReport for gradient attack.
        """
        sess_opts = ort.SessionOptions()
        sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        session = ort.InferenceSession(str(model_path), sess_opts)
        input_name = session.get_inputs()[0].name

        start_time = time.monotonic()

        if malware_features.ndim == 1:
            malware_features = malware_features.reshape(1, -1)

        original_outputs = session.run(None, {input_name: malware_features})[0]
        original_scores = original_outputs.flatten().astype(np.float64)
        originally_detected = original_scores >= self._threshold

        def score_fn(x: NDArray[np.float32]) -> NDArray[np.float64]:
            if x.ndim == 1:
                x = x.reshape(1, -1)
            return session.run(None, {input_name: x})[0].flatten().astype(np.float64)

        results: list[AttackResult] = []

        for i in range(len(malware_features)):
            if not originally_detected[i]:
                continue

            sample = malware_features[i]
            perturbed = _FeatureSpacePerturbations.gradient_approximation_attack(
                sample, score_fn, epsilon=epsilon, steps=steps, step_size=step_size
            )

            pert_score = float(score_fn(perturbed)[0])
            magnitude = float(np.linalg.norm(perturbed - sample))
            evaded = pert_score < self._threshold

            results.append(
                AttackResult(
                    sample_index=i,
                    attack_type=AttackType.FEATURE_SPACE.value,
                    original_score=float(original_scores[i]),
                    perturbed_score=pert_score,
                    evaded=evaded,
                    perturbation_magnitude=magnitude,
                )
            )

        elapsed = time.monotonic() - start_time

        summary = self._summarize_attack(results, AttackType.FEATURE_SPACE)
        total_detected = int(originally_detected.sum())
        evasion_rate = summary.evaded_count / max(total_detected, 1)

        return AdversarialReport(
            total_samples=len(malware_features),
            attacks_executed=len(results),
            overall_evasion_rate=evasion_rate,
            overall_resistance_score=1.0 - evasion_rate,
            per_attack_summary=[summary],
            detailed_results=results,
            test_time_sec=elapsed,
        )

    # ------------------------------------------------------------------
    # Internal: run one attack type
    # ------------------------------------------------------------------

    def _run_single_attack(
        self,
        session: ort.InferenceSession,
        input_name: str,
        features: NDArray[np.float32],
        original_scores: NDArray[np.float64],
        originally_detected: NDArray[np.bool_],
        attack_type: AttackType,
        magnitudes: list[float],
    ) -> list[AttackResult]:
        """Run a single attack type at multiple magnitudes."""
        perturb_fn = {
            AttackType.APPEND_BYTES: self._perturbations.append_bytes_perturbation,
            AttackType.SECTION_INJECTION: self._perturbations.section_injection_perturbation,
            AttackType.IMPORT_MANIPULATION: self._perturbations.import_manipulation_perturbation,
            AttackType.HEADER_MANIPULATION: self._perturbations.header_manipulation_perturbation,
            AttackType.PACKER_WRAPPING: self._perturbations.packer_wrapping_perturbation,
        }[attack_type]

        results: list[AttackResult] = []

        for i in range(len(features)):
            if not originally_detected[i]:
                continue

            best_evade = False
            best_pert_score = float(original_scores[i])
            best_magnitude = 0.0

            for mag in magnitudes:
                perturbed = perturb_fn(
                    features[i], magnitude=mag, rng=self._rng
                )

                pert_out = session.run(
                    None, {input_name: perturbed.reshape(1, -1)}
                )[0]
                pert_score = float(pert_out.flatten()[0])
                pert_magnitude = float(np.linalg.norm(perturbed - features[i]))

                if pert_score < best_pert_score:
                    best_pert_score = pert_score
                    best_magnitude = pert_magnitude

                if pert_score < self._threshold:
                    best_evade = True
                    best_pert_score = pert_score
                    best_magnitude = pert_magnitude
                    break  # Evasion achieved, no need for larger magnitudes

            results.append(
                AttackResult(
                    sample_index=i,
                    attack_type=attack_type.value,
                    original_score=float(original_scores[i]),
                    perturbed_score=best_pert_score,
                    evaded=best_evade,
                    perturbation_magnitude=best_magnitude,
                )
            )

        return results

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    @staticmethod
    def _summarize_attack(
        results: list[AttackResult], attack_type: AttackType
    ) -> AttackSummary:
        """Summarize results for a single attack type."""
        if not results:
            return AttackSummary(
                attack_type=attack_type.value,
                samples_tested=0,
                originally_detected=0,
                evaded_count=0,
                evasion_rate=0.0,
                mean_perturbation=0.0,
                median_perturbation=0.0,
                min_perturbation_to_evade=None,
            )

        evaded = [r for r in results if r.evaded]
        magnitudes = [r.perturbation_magnitude for r in results]
        evade_magnitudes = [r.perturbation_magnitude for r in evaded]

        return AttackSummary(
            attack_type=attack_type.value,
            samples_tested=len(results),
            originally_detected=len(results),
            evaded_count=len(evaded),
            evasion_rate=len(evaded) / max(len(results), 1),
            mean_perturbation=float(np.mean(magnitudes)),
            median_perturbation=float(np.median(magnitudes)),
            min_perturbation_to_evade=(
                float(min(evade_magnitudes)) if evade_magnitudes else None
            ),
        )

"""
PhantomCortex Evaluation Bridge
================================

Pipeline-callable evaluation module that runs comprehensive model quality
assessment across all Cortex models. Called by the pipeline orchestrator
at the EVALUATE step.

Public API::

    report = evaluate_all(
        model_dir=Path("training/data/models/staging"),
        data_dir=Path("training/data/datasets"),
        models=["behavioral", "memory", "network", "emulation"],
    )

For each model the module:
    1. Loads the ONNX model from ``model_dir``.
    2. Generates or loads test data appropriate to the model type.
    3. Runs ONNX Runtime inference.
    4. Computes standard classification metrics (accuracy, F1, AUC-ROC).
    5. Runs adversarial robustness testing.
    6. Runs false positive testing on synthetic goodware features.
    7. Assembles a quality-gate pass/fail verdict.

Author: ShadowStrike-Labs contact@ShadowStrike.dev
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Optional

import numpy as np
import onnxruntime as ort
from numpy.typing import NDArray
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    roc_auc_score,
)

from PhantomCortex.training.evaluation.metrics import (
    FullMetricsReport,
    MetricsCalculator,
)
from PhantomCortex.training.evaluation.adversarial_test import (
    AdversarialReport,
    AdversarialTester,
)
from PhantomCortex.training.evaluation.false_positive_test import (
    FalsePositiveTester,
    FPReport,
)

logger = logging.getLogger("PhantomCortex.Evaluation.Bridge")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ONNX_FILES: dict[str, str] = {
    "static": "cortex_static.onnx",
    "behavioral": "cortex_behavioral.onnx",
    "memory": "cortex_memory.onnx",
    "network": "cortex_network.onnx",
    "emulation": "cortex_emulation.onnx",
}

# Quality gates aligned with pipeline.py QualityGates defaults
_QUALITY_GATES: dict[str, float] = {
    "min_auc_roc": 0.995,
    "max_fpr_at_001": 0.001,
    "min_detection_rate": 0.995,
    "min_evasion_resistance": 0.90,
}

# Per-model test data generation configuration
_TEST_SAMPLES = 2000
_ADVERSARIAL_SAMPLES = 500
_GOODWARE_SAMPLES = 1000
_DECISION_THRESHOLD = 0.5
_SEED = 42


# ---------------------------------------------------------------------------
# ONNX inference helper
# ---------------------------------------------------------------------------

def _create_session(model_path: str) -> ort.InferenceSession:
    """Create an optimised ONNXRuntime inference session."""
    opts = ort.SessionOptions()
    opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    opts.intra_op_num_threads = os.cpu_count() or 1
    return ort.InferenceSession(model_path, opts)


def _run_inference(
    session: ort.InferenceSession,
    data: NDArray[np.float32],
) -> NDArray[np.float64]:
    """Run inference and return flattened output scores."""
    input_name = session.get_inputs()[0].name
    outputs = session.run(None, {input_name: data})[0]
    return outputs.flatten().astype(np.float64)


# ---------------------------------------------------------------------------
# Test data generators for each model domain
# ---------------------------------------------------------------------------

def _generate_static_test_data(
    data_dir: Path,
    n_samples: int,
) -> tuple[NDArray[np.float32], NDArray[np.int32]]:
    """Load or synthesize static PE feature test data.

    If EMBER data is available in data_dir, loads a subset. Otherwise
    generates random feature vectors with realistic distribution for
    evaluation infrastructure testing.
    """
    feature_dim = 2568  # EMBER 2024 (was 2381 for EMBER 2018)

    ember_test_x = data_dir / "ember" / "X_test.npy"
    ember_test_y = data_dir / "ember" / "y_test.npy"

    if ember_test_x.exists() and ember_test_y.exists():
        logger.info("Loading EMBER test data from %s", data_dir / "ember")
        X = np.load(str(ember_test_x)).astype(np.float32)
        y = np.load(str(ember_test_y)).astype(np.int32)
        if len(X) > n_samples:
            rng = np.random.default_rng(_SEED)
            idx = rng.choice(len(X), size=n_samples, replace=False)
            X, y = X[idx], y[idx]
        return X, y

    logger.info("Generating synthetic static test data (n=%d, features=%d)", n_samples, feature_dim)
    rng = np.random.default_rng(_SEED)
    X = rng.standard_normal((n_samples, feature_dim)).astype(np.float32)
    y = rng.integers(0, 2, size=n_samples).astype(np.int32)
    return X, y


def _generate_behavioral_test_data(
    n_samples: int,
) -> tuple[NDArray[np.float32], NDArray[np.int32]]:
    """Generate synthetic behavioral API-call sequence test data."""
    from PhantomCortex.training.data.behavioral_generator import (
        BehavioralDataGenerator,
        GeneratorConfig,
    )
    from PhantomCortex.training.models.behavioral_cnn import BehaviorCategory

    num_classes = len(BehaviorCategory)
    samples_per_class = max(1, n_samples // num_classes)

    cfg = GeneratorConfig(
        samples_per_class=samples_per_class,
        sequence_length=512,
        batch_size=256,
        seed=_SEED,
    )
    generator = BehavioralDataGenerator(cfg)
    _, _, test_loader, _ = generator.generate_dataloaders()

    X_list: list[NDArray[np.float32]] = []
    y_list: list[NDArray[np.int32]] = []
    for batch_x, batch_y in test_loader:
        X_list.append(batch_x.numpy().astype(np.float32))
        y_list.append(batch_y.numpy().astype(np.int32))

    X = np.concatenate(X_list, axis=0)
    y = np.concatenate(y_list, axis=0)
    return X, y


def _generate_memory_test_data(
    n_samples: int,
) -> tuple[NDArray[np.float32], NDArray[np.int32]]:
    """Generate or load memory forensics test data.

    Attempts to load real CIC-MalMem-2022 data first (4-class model).
    Falls back to synthetic generation if real data is unavailable.
    """
    try:
        from PhantomCortex.training.data.memory_external_loader import (
            NUM_CLASSES,
            FEATURE_DIM,
            load_memory_external_dataset,
        )
        real_data = load_memory_external_dataset()
        if real_data is not None:
            X_all, y_all = real_data[0], real_data[1]
            if len(X_all) > n_samples:
                rng = np.random.default_rng(_SEED)
                idx = rng.choice(len(X_all), size=n_samples, replace=False)
                X_all, y_all = X_all[idx], y_all[idx]
            return X_all.astype(np.float32), y_all.astype(np.int32)
    except Exception:
        pass

    from PhantomCortex.training.data.memory_generator import (
        FEATURE_DIM,
        NUM_CLASSES,
        generate_memory_dataset,
    )

    samples_per_class = max(1, n_samples // NUM_CLASSES)
    split = generate_memory_dataset(
        samples_per_class=samples_per_class,
        seed=_SEED,
        batch_size=256,
    )
    X = split.X_test.numpy().astype(np.float32)
    y = split.y_test.numpy().astype(np.int32)
    return X, y


def _generate_network_test_data(
    n_samples: int,
) -> tuple[NDArray[np.float32], NDArray[np.int32]]:
    """Generate synthetic network flow test data."""
    from PhantomCortex.training.data.network_generator import (
        NUM_CLASSES,
        generate_network_dataset,
    )

    samples_per_class = max(1, n_samples // NUM_CLASSES)
    split = generate_network_dataset(
        samples_per_class=samples_per_class,
        seed=_SEED,
        batch_size=256,
    )
    X = split.X_test.numpy().astype(np.float32)
    y = split.y_test.numpy().astype(np.int32)
    return X, y


def _generate_emulation_test_data(
    n_samples: int,
) -> tuple[NDArray[np.float32], NDArray[np.int32]]:
    """Generate synthetic emulation trace test data."""
    from PhantomCortex.training.data.emulation_generator import (
        generate_emulation_dataset,
    )
    from PhantomCortex.training.data.dataset_utils import split_data

    X, y = generate_emulation_dataset(
        n_samples=n_samples,
        seed=_SEED,
    )
    (_, _), (_, _), (X_te, y_te) = split_data(X, y, seed=_SEED)
    return X_te.astype(np.float32), y_te.astype(np.int32)


# ---------------------------------------------------------------------------
# Test data dispatcher
# ---------------------------------------------------------------------------

_DATA_GENERATORS: dict[str, Any] = {
    "static": lambda data_dir, n: _generate_static_test_data(data_dir, n),
    "behavioral": lambda data_dir, n: _generate_behavioral_test_data(n),
    "memory": lambda data_dir, n: _generate_memory_test_data(n),
    "network": lambda data_dir, n: _generate_network_test_data(n),
    "emulation": lambda data_dir, n: _generate_emulation_test_data(n),
}


# ---------------------------------------------------------------------------
# Multiclass -> binary score conversion for adversarial / FP testing
# ---------------------------------------------------------------------------

def _multiclass_to_malware_score(
    scores: NDArray[np.float64],
    model_name: str,
) -> NDArray[np.float64]:
    """Convert multiclass model outputs to a single malware probability.

    For binary models (static), scores are already P(malware).
    For multiclass models, the malware score is 1 - P(benign), where
    the benign class is assumed to be at index 0 in the softmax output.
    If the output is already 1-D (single score per sample), return as-is.
    """
    if scores.ndim == 1:
        return scores

    if model_name == "static":
        # LightGBM outputs [P(benign), P(malware)] or single P(malware)
        if scores.shape[-1] == 2:
            return scores[:, 1]
        return scores.flatten()

    # For multiclass: malware score = 1 - P(benign_class_0)
    if scores.shape[-1] >= 2:
        return 1.0 - scores[:, 0]

    return scores.flatten()


# ---------------------------------------------------------------------------
# Per-model evaluation
# ---------------------------------------------------------------------------

def _evaluate_single_model(
    model_name: str,
    model_path: Path,
    data_dir: Path,
    calc: MetricsCalculator,
) -> dict[str, Any]:
    """Run full evaluation suite on a single model.

    Returns a result dict with keys: accuracy, macro_f1, auc_roc,
    fpr_at_001, detection_rate, evasion_resistance, fp_rate, pass_quality_gates.
    """
    t_total = time.monotonic()
    result: dict[str, Any] = {"model": model_name, "onnx_path": str(model_path)}

    # 1. Load ONNX model
    logger.info("Loading ONNX model: %s", model_path)
    session = _create_session(str(model_path))
    input_name = session.get_inputs()[0].name

    # 2. Generate test data
    logger.info("Generating test data for %s", model_name)
    gen_fn = _DATA_GENERATORS.get(model_name)
    if gen_fn is None:
        raise ValueError(f"No test data generator for model: {model_name}")

    t_data = time.monotonic()
    X_test, y_test = gen_fn(data_dir, _TEST_SAMPLES)
    data_time = time.monotonic() - t_data
    logger.info(
        "Test data: %d samples, shape=%s, generated in %.1fs",
        len(X_test), X_test.shape, data_time,
    )

    # 3. Run inference
    logger.info("Running inference on test set")
    t_infer = time.monotonic()
    raw_output = session.run(None, {input_name: X_test})[0]
    infer_time = time.monotonic() - t_infer
    result["inference_time_sec"] = round(infer_time, 3)

    # Convert raw output to score array
    raw_scores = raw_output.astype(np.float64)

    # Determine if this is binary or multiclass
    is_binary = (model_name == "static")
    num_output_classes = raw_scores.shape[-1] if raw_scores.ndim > 1 else 1

    # 4. Compute classification metrics
    logger.info("Computing classification metrics for %s", model_name)
    if is_binary or num_output_classes <= 2:
        # Binary classification path
        if raw_scores.ndim > 1 and raw_scores.shape[-1] == 2:
            y_scores = raw_scores[:, 1]
        else:
            y_scores = raw_scores.flatten()

        y_true_binary = (y_test > 0).astype(np.int32)
        report: FullMetricsReport = calc.evaluate(y_true_binary, y_scores)

        result["accuracy"] = report.accuracy
        result["precision"] = report.precision
        result["recall"] = report.recall
        result["macro_f1"] = report.f1
        result["auc_roc"] = report.auc_roc
        result["auc_pr"] = report.auc_pr

        # Extract FPR at 0.1% operating point
        fpr_at_001 = 1.0
        detection_rate_at_001 = 0.0
        for op in report.operating_points:
            if abs(op.target_fpr - 0.001) < 1e-6:
                fpr_at_001 = op.actual_fpr
                detection_rate_at_001 = op.detection_rate
                break
        result["fpr_at_001"] = fpr_at_001
        result["detection_rate"] = detection_rate_at_001

    else:
        # Multiclass classification path
        y_pred = np.argmax(raw_scores, axis=1)
        accuracy = float(accuracy_score(y_test, y_pred))
        macro_f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))

        # AUC-ROC: one-vs-rest for multiclass
        try:
            if raw_scores.ndim > 1:
                # Apply softmax if raw logits
                from scipy.special import softmax
                probs = softmax(raw_scores, axis=1)
                auc = float(roc_auc_score(y_test, probs, multi_class="ovr", average="macro"))
            else:
                auc = 0.0
        except (ValueError, TypeError):
            auc = 0.0
            logger.warning("AUC-ROC computation failed for %s (multiclass)", model_name)

        result["accuracy"] = accuracy
        result["macro_f1"] = macro_f1
        result["auc_roc"] = auc

        # For multiclass: FPR approximation (benign misclassified / total benign)
        benign_mask = y_test == 0
        if benign_mask.any():
            fpr = float((y_pred[benign_mask] != 0).mean())
        else:
            fpr = 0.0
        result["fpr_at_001"] = fpr

        # Detection rate: fraction of non-benign correctly classified
        mal_mask = y_test > 0
        if mal_mask.any():
            result["detection_rate"] = float((y_pred[mal_mask] == y_test[mal_mask]).mean())
        else:
            result["detection_rate"] = 0.0

    # 5. Adversarial robustness testing
    logger.info("Running adversarial evasion tests for %s", model_name)
    adv_result = _run_adversarial_test(
        session=session,
        input_name=input_name,
        X_test=X_test,
        y_test=y_test,
        model_name=model_name,
        model_path=model_path,
    )
    result["evasion_resistance"] = adv_result.get("resistance_score", 0.0)
    result["adversarial_summary"] = adv_result

    # 6. False positive testing on synthetic goodware
    logger.info("Running false positive test for %s", model_name)
    fp_result = _run_false_positive_test(
        session=session,
        input_name=input_name,
        X_test=X_test,
        model_name=model_name,
        model_path=model_path,
    )
    result["fp_rate"] = fp_result.get("fpr", 0.0)
    result["fp_summary"] = fp_result

    # 7. Quality gate evaluation
    result["pass_quality_gates"] = _check_quality_gates(result)

    total_time = time.monotonic() - t_total
    result["evaluation_time_sec"] = round(total_time, 2)

    logger.info(
        "Evaluation complete for %s: accuracy=%.4f, macro_f1=%.4f, "
        "auc_roc=%.4f, evasion_resistance=%.4f, fpr=%.6f, "
        "quality_gates=%s (%.1fs)",
        model_name,
        result.get("accuracy", 0.0),
        result.get("macro_f1", 0.0),
        result.get("auc_roc", 0.0),
        result.get("evasion_resistance", 0.0),
        result.get("fp_rate", 0.0),
        "PASS" if result["pass_quality_gates"] else "FAIL",
        total_time,
    )

    return result


# ---------------------------------------------------------------------------
# Adversarial testing helper
# ---------------------------------------------------------------------------

def _run_adversarial_test(
    session: ort.InferenceSession,
    input_name: str,
    X_test: NDArray[np.float32],
    y_test: NDArray[np.int32],
    model_name: str,
    model_path: Path,
) -> dict[str, Any]:
    """Run adversarial attack suite and return summary dict.

    Selects a subset of malware-class samples and runs the adversarial
    tester's feature-space perturbation attacks against the ONNX model.
    """
    try:
        tester = AdversarialTester(threshold=_DECISION_THRESHOLD, seed=_SEED)

        # Select malware samples for adversarial testing
        if model_name == "static":
            mal_mask = y_test == 1
        else:
            mal_mask = y_test > 0

        mal_features = X_test[mal_mask]
        if len(mal_features) == 0:
            logger.warning("No malware samples for adversarial testing (%s)", model_name)
            return {"resistance_score": 1.0, "samples_tested": 0}

        # Cap the number of adversarial samples to bound compute time
        if len(mal_features) > _ADVERSARIAL_SAMPLES:
            rng = np.random.default_rng(_SEED)
            idx = rng.choice(len(mal_features), size=_ADVERSARIAL_SAMPLES, replace=False)
            mal_features = mal_features[idx]

        adv_report: AdversarialReport = tester.run_all_attacks(
            model_path=str(model_path),
            malware_features=mal_features,
        )

        return {
            "resistance_score": adv_report.overall_resistance_score,
            "evasion_rate": adv_report.overall_evasion_rate,
            "samples_tested": adv_report.total_samples,
            "attacks_executed": adv_report.attacks_executed,
            "test_time_sec": round(adv_report.test_time_sec, 2),
        }

    except Exception as exc:
        logger.error(
            "Adversarial testing failed for %s: %s", model_name, exc, exc_info=True
        )
        return {"resistance_score": 0.0, "error": str(exc), "samples_tested": 0}


# ---------------------------------------------------------------------------
# False positive testing helper
# ---------------------------------------------------------------------------

def _run_false_positive_test(
    session: ort.InferenceSession,
    input_name: str,
    X_test: NDArray[np.float32],
    model_name: str,
    model_path: Path,
) -> dict[str, Any]:
    """Run false positive testing with synthetic goodware features.

    Generates random feature vectors drawn from a distribution that
    approximates benign software characteristics (low-magnitude,
    mostly-zero features) and measures how many the model incorrectly
    flags as malicious.
    """
    try:
        tester = FalsePositiveTester(
            threshold=_DECISION_THRESHOLD,
            target_fpr=0.0001,
        )

        # Generate synthetic goodware features
        feature_dim = X_test.shape[-1]
        rng = np.random.default_rng(_SEED + 99)

        # Benign features: sparse, low-magnitude, mimicking legitimate software
        goodware_features = np.zeros((_GOODWARE_SAMPLES, feature_dim), dtype=np.float32)
        n_active = max(1, feature_dim // 5)
        for i in range(_GOODWARE_SAMPLES):
            active_idx = rng.choice(feature_dim, size=n_active, replace=False)
            goodware_features[i, active_idx] = rng.standard_normal(n_active).astype(np.float32) * 0.1

        categories = ["synthetic_goodware"] * _GOODWARE_SAMPLES

        fp_report: FPReport = tester.test_model_precomputed(
            model_path=str(model_path),
            features=goodware_features,
            categories=categories,
        )

        return {
            "fpr": fp_report.fpr,
            "false_positives": fp_report.false_positives,
            "files_scanned": fp_report.files_scanned,
            "meets_target": fp_report.meets_target,
            "target_fpr": fp_report.target_fpr,
            "scan_time_sec": round(fp_report.scan_time_sec, 3),
        }

    except Exception as exc:
        logger.error(
            "False positive testing failed for %s: %s", model_name, exc, exc_info=True
        )
        return {"fpr": 1.0, "error": str(exc), "files_scanned": 0}


# ---------------------------------------------------------------------------
# Quality gate checker
# ---------------------------------------------------------------------------

def _check_quality_gates(result: dict[str, Any]) -> bool:
    """Evaluate per-model metrics against enterprise quality thresholds.

    Uses model-specific gate thresholds: Static/Network have stricter AUC/FPR
    targets as primary classifiers; Behavioral/Memory/Emulation use macro-F1
    and accuracy gates appropriate to their multiclass task.

    Returns True if all gates pass. Logs individual failures.
    """
    model_name = result.get("model", "unknown")
    passed = True

    # Model-specific gate profiles
    _MODEL_GATES: dict[str, dict[str, float]] = {
        "static": {"min_auc_roc": 0.995, "max_fpr_at_001": 0.002, "min_detection_rate": 0.97},
        "behavioral": {"min_auc_roc": 0.0, "min_macro_f1": 0.85, "min_accuracy": 0.88},
        "memory": {"min_auc_roc": 0.0, "min_macro_f1": 0.65, "min_accuracy": 0.70},
        "network": {"min_auc_roc": 0.85, "max_fpr_at_001": 0.01, "min_detection_rate": 0.90},
        "emulation": {"min_auc_roc": 0.0, "min_macro_f1": 0.85, "min_accuracy": 0.93},
    }

    gates = _MODEL_GATES.get(model_name, _QUALITY_GATES)

    min_auc = gates.get("min_auc_roc", 0.0)
    if min_auc > 0:
        auc = result.get("auc_roc", 0.0)
        if auc < min_auc:
            logger.warning(
                "Quality gate FAIL [%s]: AUC-ROC %.4f < %.4f",
                model_name, auc, min_auc,
            )
            passed = False

    max_fpr = gates.get("max_fpr_at_001")
    if max_fpr is not None:
        fpr = result.get("fpr_at_001", 1.0)
        if fpr > max_fpr:
            logger.warning(
                "Quality gate FAIL [%s]: FPR@0.1%% %.6f > %.6f",
                model_name, fpr, max_fpr,
            )
            passed = False

    min_dr = gates.get("min_detection_rate")
    if min_dr is not None:
        dr = result.get("detection_rate", 0.0)
        if dr < min_dr:
            logger.warning(
                "Quality gate FAIL [%s]: detection_rate %.4f < %.4f",
                model_name, dr, min_dr,
            )
            passed = False

    min_f1 = gates.get("min_macro_f1")
    if min_f1 is not None:
        f1 = result.get("macro_f1", 0.0)
        if f1 < min_f1:
            logger.warning(
                "Quality gate FAIL [%s]: macro_f1 %.4f < %.4f",
                model_name, f1, min_f1,
            )
            passed = False

    min_acc = gates.get("min_accuracy")
    if min_acc is not None:
        acc = result.get("accuracy", 0.0)
        if acc < min_acc:
            logger.warning(
                "Quality gate FAIL [%s]: accuracy %.4f < %.4f",
                model_name, acc, min_acc,
            )
            passed = False

    resistance = result.get("evasion_resistance", 0.0)
    min_resistance = gates.get("min_evasion_resistance", _QUALITY_GATES.get("min_evasion_resistance", 0.0))
    if min_resistance > 0 and resistance < min_resistance:
        logger.warning(
            "Quality gate FAIL [%s]: evasion_resistance %.4f < %.4f",
            model_name, resistance, min_resistance,
        )
        passed = False

    if passed:
        logger.info("Quality gates PASS for %s", model_name)

    return passed


# ---------------------------------------------------------------------------
# Ensemble scoring
# ---------------------------------------------------------------------------

def _compute_ensemble_score(model_results: dict[str, dict[str, Any]]) -> float:
    """Compute a weighted ensemble quality score across all evaluated models.

    Each model receives a reliability weight reflecting its importance in the
    overall detection pipeline. Static and Behavioral are primary classifiers
    with highest weight; Network and Emulation are secondary signals; Memory
    provides complementary in-memory detection.

    Returns a value in [0, 1] where 1.0 is perfect.
    """
    if not model_results:
        return 0.0

    _MODEL_WEIGHTS: dict[str, float] = {
        "static": 0.30,
        "behavioral": 0.25,
        "network": 0.20,
        "emulation": 0.15,
        "memory": 0.10,
    }

    weighted_sum = 0.0
    total_weight = 0.0

    for model_name, result in model_results.items():
        weight = _MODEL_WEIGHTS.get(model_name, 0.1)

        if result.get("status") == "failed":
            total_weight += weight
            continue

        auc = result.get("auc_roc", 0.0)
        resistance = result.get("evasion_resistance", 0.0)
        fpr = result.get("fp_rate", 0.0)

        fpr_penalty = min(fpr * 10.0, 0.1)
        model_score = 0.7 * auc + 0.2 * resistance + 0.1 * (1.0 - fpr_penalty)
        model_score = max(0.0, min(1.0, model_score))

        weighted_sum += weight * model_score
        total_weight += weight

    return round(weighted_sum / total_weight, 6) if total_weight > 0 else 0.0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def evaluate_all(
    model_dir: Path,
    data_dir: Path,
    models: list[str],
) -> dict[str, Any]:
    """Evaluate all requested models and return a comprehensive report.

    This is the entry point called by ``pipeline.py`` at the EVALUATE step.

    Args:
        model_dir: Directory containing trained ONNX model files
            (``cortex_{name}.onnx``).
        data_dir: Root directory containing evaluation datasets. Per-model
            test data is generated if not available on disk.
        models: List of model identifiers to evaluate. Valid values:
            ``"static"``, ``"behavioral"``, ``"memory"``, ``"network"``,
            ``"emulation"``.

    Returns:
        Dictionary with keys:

        - ``"models"`` -- dict of per-model evaluation result dicts.
        - ``"ensemble_score"`` -- weighted ensemble quality metric.
        - ``"all_gates_passed"`` -- True if every model passes quality gates.
        - ``"total_evaluation_time_sec"`` -- wall-clock total.
        - ``"quality_gates"`` -- the threshold values applied.
    """
    pipeline_start = time.monotonic()
    calc = MetricsCalculator(
        threshold=_DECISION_THRESHOLD,
        target_fprs=[0.01, 0.001, 0.0001],
    )

    model_results: dict[str, dict[str, Any]] = {}
    all_passed = True

    for model_name in models:
        onnx_filename = _ONNX_FILES.get(model_name)
        if onnx_filename is None:
            logger.error("Unknown model identifier: %s", model_name)
            model_results[model_name] = {
                "model": model_name,
                "status": "failed",
                "error": f"Unknown model: {model_name}",
            }
            all_passed = False
            continue

        model_path = model_dir / onnx_filename
        if not model_path.exists():
            logger.error("ONNX model not found: %s", model_path)
            model_results[model_name] = {
                "model": model_name,
                "status": "failed",
                "error": f"ONNX file not found: {model_path}",
            }
            all_passed = False
            continue

        try:
            result = _evaluate_single_model(model_name, model_path, data_dir, calc)
            model_results[model_name] = result

            if not result.get("pass_quality_gates", False):
                all_passed = False

        except Exception as exc:
            logger.error(
                "Evaluation failed for %s: %s", model_name, exc, exc_info=True
            )
            model_results[model_name] = {
                "model": model_name,
                "status": "failed",
                "error": str(exc),
            }
            all_passed = False

    total_time = time.monotonic() - pipeline_start
    ensemble = _compute_ensemble_score(model_results)

    report: dict[str, Any] = {
        "models": model_results,
        "ensemble_score": ensemble,
        "all_gates_passed": all_passed,
        "total_evaluation_time_sec": round(total_time, 2),
        "quality_gates": _QUALITY_GATES,
    }

    # Persist report to disk
    report_path = model_dir / "evaluation_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, indent=2, default=str), encoding="utf-8"
    )

    logger.info(
        "Evaluation complete: %d models, ensemble=%.4f, gates=%s (%.1fs). Report: %s",
        len(models),
        ensemble,
        "ALL PASS" if all_passed else "FAILURES DETECTED",
        total_time,
        report_path,
    )

    return report

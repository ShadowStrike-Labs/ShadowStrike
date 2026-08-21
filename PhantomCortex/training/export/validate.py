"""
Deployment Validation Suite for PhantomCortex Models
=====================================================

Comprehensive pre-deployment checks ensuring every model meets ShadowStrike's
enterprise requirements before reaching production endpoints:

    - ONNX graph validity and load test
    - Input/output shape conformance
    - Accuracy on known-good and known-bad test sets
    - Model size constraints
    - Inference latency constraints (<5ms per sample)
    - Edge case robustness
    - Regression testing against previous model versions
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

import numpy as np
import onnx
import onnxruntime as ort
from numpy.typing import NDArray

logger = logging.getLogger("PhantomCortex.Export.Validate")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CheckResult:
    """Result of a single validation check."""

    name: str
    passed: bool
    message: str
    value: Optional[float] = None
    threshold: Optional[float] = None


@dataclass(frozen=True)
class ValidationReport:
    """Aggregate report of all validation checks."""

    model_path: str
    all_passed: bool
    checks: list[CheckResult]
    total_checks: int
    passed_checks: int
    failed_checks: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_path": self.model_path,
            "all_passed": self.all_passed,
            "total_checks": self.total_checks,
            "passed_checks": self.passed_checks,
            "failed_checks": self.failed_checks,
            "checks": [
                {
                    "name": c.name,
                    "passed": c.passed,
                    "message": c.message,
                    "value": c.value,
                    "threshold": c.threshold,
                }
                for c in self.checks
            ],
        }


@dataclass(frozen=True)
class RegressionReport:
    """Regression test comparing new model vs previous version."""

    new_model_path: str
    old_model_path: str
    samples_tested: int
    new_accuracy: float
    old_accuracy: float
    accuracy_delta: float
    new_mean_latency_ms: float
    old_mean_latency_ms: float
    latency_delta_ms: float
    regression_detected: bool
    details: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "new_model_path": self.new_model_path,
            "old_model_path": self.old_model_path,
            "samples_tested": self.samples_tested,
            "new_accuracy": round(self.new_accuracy, 6),
            "old_accuracy": round(self.old_accuracy, 6),
            "accuracy_delta": round(self.accuracy_delta, 6),
            "new_mean_latency_ms": round(self.new_mean_latency_ms, 4),
            "old_mean_latency_ms": round(self.old_mean_latency_ms, 4),
            "latency_delta_ms": round(self.latency_delta_ms, 4),
            "regression_detected": self.regression_detected,
            "details": self.details,
        }


@dataclass(frozen=True)
class LatencyReport:
    """Latency benchmark for deployment readiness."""

    model_path: str
    iterations: int
    mean_ms: float
    median_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    under_threshold: bool
    threshold_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_path": self.model_path,
            "iterations": self.iterations,
            "mean_ms": round(self.mean_ms, 4),
            "median_ms": round(self.median_ms, 4),
            "p95_ms": round(self.p95_ms, 4),
            "p99_ms": round(self.p99_ms, 4),
            "max_ms": round(self.max_ms, 4),
            "under_threshold": self.under_threshold,
            "threshold_ms": self.threshold_ms,
        }


# ---------------------------------------------------------------------------
# Validation configuration
# ---------------------------------------------------------------------------


@dataclass
class ValidationConfig:
    """Configuration for model validation checks."""

    expected_input_names: Optional[list[str]] = None
    expected_output_names: Optional[list[str]] = None
    expected_input_shapes: Optional[list[list[Optional[int]]]] = None
    expected_output_shapes: Optional[list[list[Optional[int]]]] = None
    max_model_size_mb: float = 20.0
    max_inference_ms: float = 5.0
    min_accuracy: Optional[float] = None
    min_detection_rate: Optional[float] = None
    max_fpr: Optional[float] = None
    test_inputs: Optional[NDArray[np.float32]] = None
    test_labels: Optional[NDArray[np.int32]] = None
    edge_case_inputs: Optional[list[NDArray[np.float32]]] = None
    latency_iterations: int = 1000
    latency_warmup: int = 50


# ---------------------------------------------------------------------------
# Helper: shape conformance
# ---------------------------------------------------------------------------


def _shapes_match(
    actual: list[Optional[int]], expected: list[Optional[int]]
) -> bool:
    """Check if two shapes match, treating None as wildcard."""
    if len(actual) != len(expected):
        return False
    for a, e in zip(actual, expected):
        if e is not None and a is not None and a != e:
            return False
    return True


def _extract_shape(type_proto: onnx.TypeProto) -> list[Optional[int]]:
    """Extract shape from ONNX type proto."""
    shape: list[Optional[int]] = []
    if type_proto.HasField("tensor_type"):
        st = type_proto.tensor_type
        if st.HasField("shape"):
            for dim in st.shape.dim:
                if dim.HasField("dim_value"):
                    shape.append(dim.dim_value)
                else:
                    shape.append(None)
    return shape


# ---------------------------------------------------------------------------
# Comprehensive model validation
# ---------------------------------------------------------------------------


def validate_model(
    onnx_path: Union[str, Path],
    config: ValidationConfig,
) -> ValidationReport:
    """Run all validation checks on an ONNX model before deployment.

    Checks:
        1. File existence and loadability
        2. ONNX graph validity
        3. Input/output name conformance
        4. Input/output shape conformance
        5. Model size constraint
        6. Inference latency constraint
        7. Test set accuracy (if test data provided)
        8. Edge case robustness (if edge cases provided)

    Args:
        onnx_path: Path to the ONNX model.
        config: Validation configuration with thresholds and test data.

    Returns:
        ValidationReport with all check results.
    """
    path = Path(onnx_path)
    checks: list[CheckResult] = []

    # --- Check 1: File existence ---
    if not path.exists():
        checks.append(
            CheckResult("file_exists", False, f"Model file not found: {path}")
        )
        return _build_report(str(path), checks)

    # --- Check 2: ONNX loadability and graph validity ---
    try:
        model = onnx.load(str(path))
        onnx.checker.check_model(model)
        checks.append(CheckResult("onnx_valid", True, "ONNX graph is valid"))
    except Exception as exc:
        checks.append(
            CheckResult("onnx_valid", False, f"ONNX validation failed: {exc}")
        )
        return _build_report(str(path), checks)

    # --- Check 3: Input/output names ---
    actual_input_names = [inp.name for inp in model.graph.input]
    actual_output_names = [out.name for out in model.graph.output]

    if config.expected_input_names is not None:
        match = actual_input_names == config.expected_input_names
        checks.append(
            CheckResult(
                "input_names",
                match,
                f"Expected {config.expected_input_names}, got {actual_input_names}",
            )
        )

    if config.expected_output_names is not None:
        match = actual_output_names == config.expected_output_names
        checks.append(
            CheckResult(
                "output_names",
                match,
                f"Expected {config.expected_output_names}, got {actual_output_names}",
            )
        )

    # --- Check 4: Input/output shapes ---
    if config.expected_input_shapes is not None:
        for i, expected in enumerate(config.expected_input_shapes):
            if i < len(model.graph.input):
                actual = _extract_shape(model.graph.input[i].type)
                match = _shapes_match(actual, expected)
                checks.append(
                    CheckResult(
                        f"input_shape_{i}",
                        match,
                        f"Expected {expected}, got {actual}",
                    )
                )

    if config.expected_output_shapes is not None:
        for i, expected in enumerate(config.expected_output_shapes):
            if i < len(model.graph.output):
                actual = _extract_shape(model.graph.output[i].type)
                match = _shapes_match(actual, expected)
                checks.append(
                    CheckResult(
                        f"output_shape_{i}",
                        match,
                        f"Expected {expected}, got {actual}",
                    )
                )

    # --- Check 5: Model size ---
    size_mb = path.stat().st_size / (1024 * 1024)
    size_ok = size_mb <= config.max_model_size_mb
    checks.append(
        CheckResult(
            "model_size",
            size_ok,
            f"Size: {size_mb:.2f} MB (limit: {config.max_model_size_mb} MB)",
            value=size_mb,
            threshold=config.max_model_size_mb,
        )
    )

    # --- Check 6: Inference latency ---
    try:
        sess_opts = ort.SessionOptions()
        sess_opts.graph_optimization_level = (
            ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        )
        session = ort.InferenceSession(str(path), sess_opts)
        input_name = session.get_inputs()[0].name
        input_shape = []
        for dim in session.get_inputs()[0].shape:
            input_shape.append(dim if isinstance(dim, int) else 1)

        dummy = np.random.randn(*input_shape).astype(np.float32)

        # Warmup
        for _ in range(config.latency_warmup):
            session.run(None, {input_name: dummy})

        # Timed
        latencies: list[float] = []
        for _ in range(config.latency_iterations):
            start = time.perf_counter()
            session.run(None, {input_name: dummy})
            latencies.append((time.perf_counter() - start) * 1000.0)

        arr = np.array(latencies)
        p99 = float(np.percentile(arr, 99))
        mean_lat = float(arr.mean())
        lat_ok = p99 <= config.max_inference_ms

        checks.append(
            CheckResult(
                "inference_latency",
                lat_ok,
                f"P99: {p99:.3f}ms, mean: {mean_lat:.3f}ms "
                f"(limit: {config.max_inference_ms}ms)",
                value=p99,
                threshold=config.max_inference_ms,
            )
        )
    except Exception as exc:
        checks.append(
            CheckResult(
                "inference_latency", False, f"Latency test failed: {exc}"
            )
        )

    # --- Check 7: Test set accuracy ---
    if config.test_inputs is not None and config.test_labels is not None:
        try:
            outputs = session.run(None, {input_name: config.test_inputs})[0]

            if outputs.ndim == 1:
                preds = (outputs >= 0.5).astype(np.int32)
            else:
                preds = outputs.argmax(axis=1).astype(np.int32)

            accuracy = float((preds == config.test_labels).mean())

            if config.min_accuracy is not None:
                acc_ok = accuracy >= config.min_accuracy
                checks.append(
                    CheckResult(
                        "test_accuracy",
                        acc_ok,
                        f"Accuracy: {accuracy:.6f} (min: {config.min_accuracy})",
                        value=accuracy,
                        threshold=config.min_accuracy,
                    )
                )

            # FPR check (binary classification)
            if config.max_fpr is not None:
                benign_mask = config.test_labels == 0
                if benign_mask.sum() > 0:
                    fpr = float((preds[benign_mask] == 1).mean())
                    fpr_ok = fpr <= config.max_fpr
                    checks.append(
                        CheckResult(
                            "false_positive_rate",
                            fpr_ok,
                            f"FPR: {fpr:.6f} (max: {config.max_fpr})",
                            value=fpr,
                            threshold=config.max_fpr,
                        )
                    )

            # Detection rate check
            if config.min_detection_rate is not None:
                mal_mask = config.test_labels == 1
                if mal_mask.sum() > 0:
                    dr = float((preds[mal_mask] == 1).mean())
                    dr_ok = dr >= config.min_detection_rate
                    checks.append(
                        CheckResult(
                            "detection_rate",
                            dr_ok,
                            f"DR: {dr:.6f} (min: {config.min_detection_rate})",
                            value=dr,
                            threshold=config.min_detection_rate,
                        )
                    )
        except Exception as exc:
            checks.append(
                CheckResult("test_accuracy", False, f"Test evaluation failed: {exc}")
            )

    # --- Check 8: Edge case robustness ---
    if config.edge_case_inputs is not None:
        for idx, edge_input in enumerate(config.edge_case_inputs):
            try:
                session.run(None, {input_name: edge_input})
                checks.append(
                    CheckResult(
                        f"edge_case_{idx}",
                        True,
                        f"Edge case {idx}: inference succeeded",
                    )
                )
            except Exception as exc:
                checks.append(
                    CheckResult(
                        f"edge_case_{idx}",
                        False,
                        f"Edge case {idx} crashed: {exc}",
                    )
                )

    return _build_report(str(path), checks)


def _build_report(model_path: str, checks: list[CheckResult]) -> ValidationReport:
    """Construct a ValidationReport from check results."""
    passed = sum(1 for c in checks if c.passed)
    failed = sum(1 for c in checks if not c.passed)
    all_ok = failed == 0

    report = ValidationReport(
        model_path=model_path,
        all_passed=all_ok,
        checks=checks,
        total_checks=len(checks),
        passed_checks=passed,
        failed_checks=failed,
    )

    status = "PASS" if all_ok else "FAIL"
    logger.info(
        "Validation %s: %d/%d checks passed for %s",
        status,
        passed,
        len(checks),
        model_path,
    )
    for c in checks:
        level = logging.INFO if c.passed else logging.WARNING
        logger.log(level, "  [%s] %s: %s", "OK" if c.passed else "FAIL", c.name, c.message)

    return report


# ---------------------------------------------------------------------------
# Regression testing
# ---------------------------------------------------------------------------


def regression_test(
    new_path: Union[str, Path],
    old_path: Union[str, Path],
    test_data: NDArray[np.float32],
    *,
    test_labels: Optional[NDArray[np.int32]] = None,
    accuracy_tolerance: float = 0.001,
    latency_tolerance_ms: float = 1.0,
    iterations: int = 500,
) -> RegressionReport:
    """Compare a new model against a previous version for regressions.

    A regression is detected if:
        - New model accuracy drops by more than ``accuracy_tolerance``
        - New model p99 latency increases by more than ``latency_tolerance_ms``

    Args:
        new_path: Path to the new ONNX model.
        old_path: Path to the previous ONNX model.
        test_data: Test input array.
        test_labels: Ground truth labels (for accuracy comparison).
        accuracy_tolerance: Maximum acceptable accuracy drop.
        latency_tolerance_ms: Maximum acceptable latency increase.
        iterations: Latency benchmark iterations.

    Returns:
        RegressionReport indicating whether a regression was detected.
    """
    details: list[str] = []
    regression = False

    new_session = ort.InferenceSession(str(new_path))
    old_session = ort.InferenceSession(str(old_path))

    new_input = new_session.get_inputs()[0].name
    old_input = old_session.get_inputs()[0].name

    new_out = new_session.run(None, {new_input: test_data})[0]
    old_out = old_session.run(None, {old_input: test_data})[0]

    # Accuracy comparison
    new_acc = 0.0
    old_acc = 0.0
    if test_labels is not None:
        if new_out.ndim == 1:
            new_preds = (new_out >= 0.5).astype(np.int32)
            old_preds = (old_out >= 0.5).astype(np.int32)
        else:
            new_preds = new_out.argmax(axis=1).astype(np.int32)
            old_preds = old_out.argmax(axis=1).astype(np.int32)

        new_acc = float((new_preds == test_labels).mean())
        old_acc = float((old_preds == test_labels).mean())

        if new_acc < old_acc - accuracy_tolerance:
            regression = True
            details.append(
                f"Accuracy regression: {new_acc:.6f} < {old_acc:.6f} "
                f"(tolerance: {accuracy_tolerance})"
            )
        else:
            details.append(
                f"Accuracy OK: new={new_acc:.6f}, old={old_acc:.6f}"
            )

    acc_delta = new_acc - old_acc

    # Latency comparison
    def _bench(session: ort.InferenceSession, name: str) -> float:
        inp_name = session.get_inputs()[0].name
        single = test_data[:1]
        for _ in range(50):
            session.run(None, {inp_name: single})
        lats = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            session.run(None, {inp_name: single})
            lats.append((time.perf_counter() - t0) * 1000.0)
        return float(np.mean(lats))

    new_lat = _bench(new_session, "new")
    old_lat = _bench(old_session, "old")
    lat_delta = new_lat - old_lat

    if lat_delta > latency_tolerance_ms:
        regression = True
        details.append(
            f"Latency regression: {new_lat:.3f}ms > {old_lat:.3f}ms + "
            f"{latency_tolerance_ms}ms tolerance"
        )
    else:
        details.append(
            f"Latency OK: new={new_lat:.3f}ms, old={old_lat:.3f}ms"
        )

    report = RegressionReport(
        new_model_path=str(new_path),
        old_model_path=str(old_path),
        samples_tested=test_data.shape[0],
        new_accuracy=new_acc,
        old_accuracy=old_acc,
        accuracy_delta=acc_delta,
        new_mean_latency_ms=new_lat,
        old_mean_latency_ms=old_lat,
        latency_delta_ms=lat_delta,
        regression_detected=regression,
        details=details,
    )

    status = "REGRESSION DETECTED" if regression else "NO REGRESSION"
    logger.info("Regression test: %s", status)
    for d in details:
        logger.info("  %s", d)

    return report


# ---------------------------------------------------------------------------
# Latency benchmark
# ---------------------------------------------------------------------------


def benchmark_latency(
    onnx_path: Union[str, Path],
    input_shape: tuple[int, ...],
    *,
    iterations: int = 10000,
    warmup: int = 100,
    threshold_ms: float = 5.0,
) -> LatencyReport:
    """Benchmark inference latency for deployment readiness.

    Generates random input of the specified shape and measures per-sample
    latency over many iterations.

    Args:
        onnx_path: Path to .onnx model file.
        input_shape: Shape of a single input (e.g., (1, 2381)).
        iterations: Number of timed iterations.
        warmup: Warmup iterations (not timed).
        threshold_ms: Maximum acceptable P99 latency.

    Returns:
        LatencyReport with percentile breakdown.
    """
    session = ort.InferenceSession(str(onnx_path))
    input_name = session.get_inputs()[0].name
    dummy = np.random.randn(*input_shape).astype(np.float32)

    for _ in range(warmup):
        session.run(None, {input_name: dummy})

    latencies: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        session.run(None, {input_name: dummy})
        latencies.append((time.perf_counter() - start) * 1000.0)

    arr = np.array(latencies)
    p99 = float(np.percentile(arr, 99))

    report = LatencyReport(
        model_path=str(onnx_path),
        iterations=iterations,
        mean_ms=float(arr.mean()),
        median_ms=float(np.median(arr)),
        p95_ms=float(np.percentile(arr, 95)),
        p99_ms=p99,
        max_ms=float(arr.max()),
        under_threshold=p99 <= threshold_ms,
        threshold_ms=threshold_ms,
    )

    logger.info(
        "Latency benchmark [%s]: mean=%.3fms p95=%.3fms p99=%.3fms — %s",
        onnx_path,
        report.mean_ms,
        report.p95_ms,
        report.p99_ms,
        "PASS" if report.under_threshold else "FAIL",
    )

    return report

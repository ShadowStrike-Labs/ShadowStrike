"""
INT8 Quantization Pipeline for PhantomCortex Models
====================================================

Reduces ONNX models from FP32 to INT8 for deployment on resource-constrained
endpoints while preserving detection accuracy above enterprise thresholds.

Supports:
    - Dynamic quantization (no calibration data needed)
    - Static quantization (accuracy-aware with calibration set)
    - Before/after accuracy comparison
    - Before/after size and latency benchmarks
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union

import numpy as np
import onnx
import onnxruntime as ort
from numpy.typing import NDArray
from onnxruntime.quantization import (
    CalibrationDataReader,
    QuantFormat,
    QuantType,
    quantize_dynamic as ort_quantize_dynamic,
    quantize_static as ort_quantize_static,
)

logger = logging.getLogger("PhantomCortex.Export.Quantize")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QuantizeReport:
    """Report generated after quantizing a model."""

    original_size_mb: float
    quantized_size_mb: float
    size_reduction_pct: float
    quantization_method: str
    weight_type: str
    success: bool
    error_message: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_size_mb": round(self.original_size_mb, 4),
            "quantized_size_mb": round(self.quantized_size_mb, 4),
            "size_reduction_pct": round(self.size_reduction_pct, 2),
            "quantization_method": self.quantization_method,
            "weight_type": self.weight_type,
            "success": self.success,
            "error_message": self.error_message,
        }


@dataclass(frozen=True)
class ComparisonReport:
    """Accuracy comparison between FP32 and INT8 models."""

    fp32_mean_output: float
    int8_mean_output: float
    max_absolute_error: float
    mean_absolute_error: float
    correlation: float
    samples_tested: int
    accuracy_preserved: bool
    tolerance: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "fp32_mean_output": round(self.fp32_mean_output, 6),
            "int8_mean_output": round(self.int8_mean_output, 6),
            "max_absolute_error": round(self.max_absolute_error, 6),
            "mean_absolute_error": round(self.mean_absolute_error, 6),
            "correlation": round(self.correlation, 6),
            "samples_tested": self.samples_tested,
            "accuracy_preserved": self.accuracy_preserved,
            "tolerance": self.tolerance,
        }


@dataclass(frozen=True)
class BenchmarkReport:
    """Inference performance benchmark results."""

    model_path: str
    iterations: int
    mean_latency_ms: float
    median_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    min_latency_ms: float
    max_latency_ms: float
    throughput_samples_per_sec: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_path": self.model_path,
            "iterations": self.iterations,
            "mean_latency_ms": round(self.mean_latency_ms, 4),
            "median_latency_ms": round(self.median_latency_ms, 4),
            "p95_latency_ms": round(self.p95_latency_ms, 4),
            "p99_latency_ms": round(self.p99_latency_ms, 4),
            "min_latency_ms": round(self.min_latency_ms, 4),
            "max_latency_ms": round(self.max_latency_ms, 4),
            "throughput_samples_per_sec": round(self.throughput_samples_per_sec, 2),
        }


# ---------------------------------------------------------------------------
# Calibration data reader for static quantization
# ---------------------------------------------------------------------------


class _ArrayCalibrationReader(CalibrationDataReader):
    """CalibrationDataReader backed by a numpy array."""

    def __init__(
        self, data: NDArray[np.float32], input_name: str, batch_size: int = 32
    ) -> None:
        self._data = data
        self._input_name = input_name
        self._batch_size = batch_size
        self._index = 0
        self._total = data.shape[0]

    def get_next(self) -> Optional[dict[str, NDArray[np.float32]]]:
        if self._index >= self._total:
            return None
        end = min(self._index + self._batch_size, self._total)
        batch = self._data[self._index : end]
        self._index = end
        return {self._input_name: batch}

    def rewind(self) -> None:
        self._index = 0


# ---------------------------------------------------------------------------
# Helper: create inference session
# ---------------------------------------------------------------------------


def _create_session(model_path: str) -> ort.InferenceSession:
    """Create an optimized ONNXRuntime inference session."""
    opts = ort.SessionOptions()
    opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    opts.intra_op_num_threads = os.cpu_count() or 1
    return ort.InferenceSession(model_path, opts)


# ---------------------------------------------------------------------------
# Dynamic quantization
# ---------------------------------------------------------------------------


def quantize_dynamic(
    input_path: Union[str, Path],
    output_path: Union[str, Path],
    *,
    weight_type: QuantType = QuantType.QInt8,
) -> QuantizeReport:
    """Apply dynamic INT8 quantization to an ONNX model.

    Dynamic quantization quantizes model weights offline and quantizes
    activations dynamically at inference time. No calibration data needed.

    Args:
        input_path: Path to the FP32 ONNX model.
        output_path: Path for the quantized ONNX model.
        weight_type: Quantization type for weights.

    Returns:
        QuantizeReport with size statistics.
    """
    inp = Path(input_path)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    if not inp.exists():
        return QuantizeReport(
            original_size_mb=0.0,
            quantized_size_mb=0.0,
            size_reduction_pct=0.0,
            quantization_method="dynamic",
            weight_type=str(weight_type),
            success=False,
            error_message=f"Input model not found: {inp}",
        )

    original_size = inp.stat().st_size

    logger.info("Dynamic quantization: %s → %s", inp, out)

    try:
        ort_quantize_dynamic(
            model_input=str(inp),
            model_output=str(out),
            weight_type=weight_type,
        )
    except Exception as exc:
        logger.error("Dynamic quantization failed: %s", exc)
        return QuantizeReport(
            original_size_mb=original_size / (1024 * 1024),
            quantized_size_mb=0.0,
            size_reduction_pct=0.0,
            quantization_method="dynamic",
            weight_type=str(weight_type),
            success=False,
            error_message=str(exc),
        )

    quantized_size = out.stat().st_size
    orig_mb = original_size / (1024 * 1024)
    quant_mb = quantized_size / (1024 * 1024)
    reduction = (1.0 - quantized_size / max(original_size, 1)) * 100.0

    logger.info(
        "Quantization complete: %.2f MB → %.2f MB (%.1f%% reduction)",
        orig_mb,
        quant_mb,
        reduction,
    )

    return QuantizeReport(
        original_size_mb=orig_mb,
        quantized_size_mb=quant_mb,
        size_reduction_pct=reduction,
        quantization_method="dynamic",
        weight_type=str(weight_type),
        success=True,
    )


# ---------------------------------------------------------------------------
# Static quantization (accuracy-aware)
# ---------------------------------------------------------------------------


def quantize_static(
    input_path: Union[str, Path],
    output_path: Union[str, Path],
    calibration_data: NDArray[np.float32],
    *,
    weight_type: QuantType = QuantType.QInt8,
    activation_type: QuantType = QuantType.QUInt8,
    calibration_batch_size: int = 32,
) -> QuantizeReport:
    """Apply static INT8 quantization using calibration data.

    Static quantization quantizes both weights and activations offline
    using representative calibration data to determine activation ranges.

    Args:
        input_path: Path to the FP32 ONNX model.
        output_path: Path for the quantized ONNX model.
        calibration_data: Representative input data for range calibration.
        weight_type: Quantization type for weights.
        activation_type: Quantization type for activations.
        calibration_batch_size: Batch size for calibration passes.

    Returns:
        QuantizeReport with size statistics.
    """
    inp = Path(input_path)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    if not inp.exists():
        return QuantizeReport(
            original_size_mb=0.0,
            quantized_size_mb=0.0,
            size_reduction_pct=0.0,
            quantization_method="static",
            weight_type=str(weight_type),
            success=False,
            error_message=f"Input model not found: {inp}",
        )

    original_size = inp.stat().st_size

    # Need preprocessed model for static quantization
    from onnxruntime.quantization import preprocess as ort_preprocess

    preprocessed_path = str(out.with_suffix(".preprocessed.onnx"))

    logger.info(
        "Static quantization: %s → %s (calibration samples: %d)",
        inp,
        out,
        calibration_data.shape[0],
    )

    try:
        ort_preprocess.quant_pre_process(
            input_model_path=str(inp),
            output_model_path=preprocessed_path,
        )

        # Determine input name from the model
        session = _create_session(preprocessed_path)
        input_name = session.get_inputs()[0].name
        del session

        reader = _ArrayCalibrationReader(
            calibration_data, input_name, calibration_batch_size
        )

        ort_quantize_static(
            model_input=preprocessed_path,
            model_output=str(out),
            calibration_data_reader=reader,
            quant_format=QuantFormat.QDQ,
            weight_type=weight_type,
            activation_type=activation_type,
        )

        # Clean up preprocessed model
        Path(preprocessed_path).unlink(missing_ok=True)

    except Exception as exc:
        logger.error("Static quantization failed: %s", exc)
        Path(preprocessed_path).unlink(missing_ok=True)
        return QuantizeReport(
            original_size_mb=original_size / (1024 * 1024),
            quantized_size_mb=0.0,
            size_reduction_pct=0.0,
            quantization_method="static",
            weight_type=str(weight_type),
            success=False,
            error_message=str(exc),
        )

    quantized_size = out.stat().st_size
    orig_mb = original_size / (1024 * 1024)
    quant_mb = quantized_size / (1024 * 1024)
    reduction = (1.0 - quantized_size / max(original_size, 1)) * 100.0

    logger.info(
        "Static quantization complete: %.2f MB → %.2f MB (%.1f%% reduction)",
        orig_mb,
        quant_mb,
        reduction,
    )

    return QuantizeReport(
        original_size_mb=orig_mb,
        quantized_size_mb=quant_mb,
        size_reduction_pct=reduction,
        quantization_method="static",
        weight_type=str(weight_type),
        success=True,
    )


# ---------------------------------------------------------------------------
# Accuracy comparison
# ---------------------------------------------------------------------------


def compare_accuracy(
    fp32_path: Union[str, Path],
    int8_path: Union[str, Path],
    test_data: NDArray[np.float32],
    *,
    tolerance: float = 0.05,
) -> ComparisonReport:
    """Compare outputs between FP32 and INT8 models on the same inputs.

    Args:
        fp32_path: Path to the FP32 ONNX model.
        int8_path: Path to the quantized INT8 ONNX model.
        test_data: Test input array.
        tolerance: Max acceptable mean absolute error.

    Returns:
        ComparisonReport with error statistics and pass/fail.
    """
    fp32_session = _create_session(str(fp32_path))
    int8_session = _create_session(str(int8_path))

    fp32_input_name = fp32_session.get_inputs()[0].name
    int8_input_name = int8_session.get_inputs()[0].name

    fp32_outputs = fp32_session.run(None, {fp32_input_name: test_data})[0]
    int8_outputs = int8_session.run(None, {int8_input_name: test_data})[0]

    fp32_flat = fp32_outputs.flatten().astype(np.float64)
    int8_flat = int8_outputs.flatten().astype(np.float64)

    min_len = min(len(fp32_flat), len(int8_flat))
    fp32_flat = fp32_flat[:min_len]
    int8_flat = int8_flat[:min_len]

    abs_diff = np.abs(fp32_flat - int8_flat)
    max_err = float(abs_diff.max())
    mean_err = float(abs_diff.mean())

    # Pearson correlation
    if np.std(fp32_flat) > 0 and np.std(int8_flat) > 0:
        correlation = float(np.corrcoef(fp32_flat, int8_flat)[0, 1])
    else:
        correlation = 1.0 if mean_err < tolerance else 0.0

    preserved = mean_err <= tolerance

    logger.info(
        "Accuracy comparison: max_err=%.6f, mean_err=%.6f, corr=%.6f — %s",
        max_err,
        mean_err,
        correlation,
        "PASS" if preserved else "FAIL",
    )

    return ComparisonReport(
        fp32_mean_output=float(fp32_flat.mean()),
        int8_mean_output=float(int8_flat.mean()),
        max_absolute_error=max_err,
        mean_absolute_error=mean_err,
        correlation=correlation,
        samples_tested=test_data.shape[0],
        accuracy_preserved=preserved,
        tolerance=tolerance,
    )


# ---------------------------------------------------------------------------
# Inference benchmark
# ---------------------------------------------------------------------------


def benchmark_inference(
    model_path: Union[str, Path],
    test_input: NDArray[np.float32],
    *,
    iterations: int = 1000,
    warmup: int = 50,
) -> BenchmarkReport:
    """Benchmark ONNX model inference latency.

    Performs warmup iterations followed by timed iterations to measure
    latency percentiles and throughput.

    Args:
        model_path: Path to .onnx file.
        test_input: Single input sample (will be used for all iterations).
        iterations: Number of timed inference iterations.
        warmup: Number of warmup iterations (not measured).

    Returns:
        BenchmarkReport with latency percentiles and throughput.
    """
    session = _create_session(str(model_path))
    input_name = session.get_inputs()[0].name

    # Warmup
    for _ in range(warmup):
        session.run(None, {input_name: test_input})

    # Timed iterations
    latencies: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        session.run(None, {input_name: test_input})
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        latencies.append(elapsed_ms)

    arr = np.array(latencies)
    mean_lat = float(arr.mean())
    throughput = 1000.0 / mean_lat if mean_lat > 0 else 0.0

    report = BenchmarkReport(
        model_path=str(model_path),
        iterations=iterations,
        mean_latency_ms=mean_lat,
        median_latency_ms=float(np.median(arr)),
        p95_latency_ms=float(np.percentile(arr, 95)),
        p99_latency_ms=float(np.percentile(arr, 99)),
        min_latency_ms=float(arr.min()),
        max_latency_ms=float(arr.max()),
        throughput_samples_per_sec=throughput,
    )

    logger.info(
        "Benchmark [%s]: mean=%.3fms, p95=%.3fms, p99=%.3fms, throughput=%.0f/s",
        model_path,
        report.mean_latency_ms,
        report.p95_latency_ms,
        report.p99_latency_ms,
        report.throughput_samples_per_sec,
    )

    return report

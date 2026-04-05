"""
ONNX Export Pipeline for PhantomCortex Models
==============================================

Exports LightGBM and PyTorch models to ONNX format for deployment in the
ShadowStrike C++ inference engine. Validates exported models produce
identical outputs to their source models within floating-point tolerance.

Supported:
    - LightGBM → onnxmltools → .onnx
    - PyTorch  → torch.onnx.export → .onnx
    - All models use ONNX opset 17
    - Dynamic batch dimension for all models
    - Named inputs/outputs for C++ integration
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union

import lightgbm as lgb
import numpy as np
import onnx
import onnxruntime as ort
import torch
import torch.nn as nn
from numpy.typing import NDArray

logger = logging.getLogger("PhantomCortex.Export.ONNX")

DEFAULT_OPSET: int = 17
ONNX_TOLERANCE: float = 1e-5


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModelMetadata:
    """ONNX model metadata extracted from the graph."""

    opset_version: int
    model_size_bytes: int
    model_size_mb: float
    input_names: list[str]
    input_shapes: list[list[Optional[int]]]
    output_names: list[str]
    output_shapes: list[list[Optional[int]]]
    model_hash: str
    ir_version: int
    producer: str
    num_nodes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "opset_version": self.opset_version,
            "model_size_mb": round(self.model_size_mb, 4),
            "input_names": self.input_names,
            "input_shapes": self.input_shapes,
            "output_names": self.output_names,
            "output_shapes": self.output_shapes,
            "model_hash": self.model_hash,
            "ir_version": self.ir_version,
            "producer": self.producer,
            "num_nodes": self.num_nodes,
        }


@dataclass(frozen=True)
class ValidationResult:
    """Result of validating an exported ONNX model against the source."""

    passed: bool
    max_absolute_error: float
    mean_absolute_error: float
    tolerance: float
    inference_time_ms: float
    error_message: Optional[str] = None


# ---------------------------------------------------------------------------
# Helper: extract ONNX shape info
# ---------------------------------------------------------------------------


def _extract_shape(
    tensor_type: onnx.TensorProto,
) -> list[Optional[int]]:
    """Extract shape from ONNX tensor, using None for dynamic dims."""
    shape: list[Optional[int]] = []
    if tensor_type.HasField("tensor_type"):
        st = tensor_type.tensor_type
        if st.HasField("shape"):
            for dim in st.shape.dim:
                if dim.HasField("dim_value"):
                    shape.append(dim.dim_value)
                else:
                    shape.append(None)
    return shape


# ---------------------------------------------------------------------------
# LightGBM → ONNX
# ---------------------------------------------------------------------------


def export_lgbm_to_onnx(
    model: lgb.Booster,
    output_path: Union[str, Path],
    *,
    feature_count: int = 2381,
    opset: int = DEFAULT_OPSET,
    input_name: str = "pe_features",
    output_name: str = "malware_probability",
    num_iteration: Optional[int] = None,
) -> Path:
    """Export a trained LightGBM booster to ONNX via onnxmltools.

    The exported model accepts float32 input of shape (batch, feature_count)
    and produces float32 probability output of shape (batch, 2).

    Args:
        model: Trained LightGBM Booster.
        output_path: Destination .onnx file.
        feature_count: Number of input features.
        opset: Target ONNX opset version.
        input_name: Named input for C++ integration.
        output_name: Named output for C++ integration.
        num_iteration: Number of boosting iterations to export (None = all).

    Returns:
        Path to the saved ONNX file.

    Raises:
        RuntimeError: If onnxmltools conversion fails.
    """
    import onnxmltools
    from onnxmltools.convert.lightgbm.operator_converters.LightGbm import (
        convert_lightgbm,
    )
    from onnxconverter_common.data_types import FloatTensorType

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    initial_types = [(input_name, FloatTensorType([None, feature_count]))]

    logger.info(
        "Converting LightGBM model to ONNX (features=%d, opset=%d)",
        feature_count,
        opset,
    )

    onnx_model = onnxmltools.convert_lightgbm(
        model,
        initial_types=initial_types,
        target_opset=opset,
    )

    # Rename outputs
    for output in onnx_model.graph.output:
        output.name = output_name

    onnx.checker.check_model(onnx_model)
    onnx.save(onnx_model, str(out))

    size_mb = out.stat().st_size / (1024 * 1024)
    logger.info("LightGBM ONNX exported to %s (%.2f MB)", out, size_mb)
    return out


# ---------------------------------------------------------------------------
# PyTorch → ONNX
# ---------------------------------------------------------------------------


def export_pytorch_to_onnx(
    model: nn.Module,
    output_path: Union[str, Path],
    input_shape: tuple[int, ...],
    *,
    input_names: Optional[list[str]] = None,
    output_names: Optional[list[str]] = None,
    opset: int = DEFAULT_OPSET,
    dynamic_batch: bool = True,
) -> Path:
    """Export a PyTorch model to ONNX with proper named I/O and dynamic batch.

    Args:
        model: Trained PyTorch nn.Module (will be set to eval mode).
        output_path: Destination .onnx file.
        input_shape: Shape of a single-batch input (e.g., (1, 512, 4)).
        input_names: Named inputs for C++ integration.
        output_names: Named outputs for C++ integration.
        opset: Target ONNX opset version.
        dynamic_batch: Make batch dimension dynamic.

    Returns:
        Path to the saved ONNX file.
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    model.eval()
    model = model.to("cpu")

    if input_names is None:
        input_names = ["input"]
    if output_names is None:
        output_names = ["output"]

    dummy = torch.randn(*input_shape)

    dynamic_axes: Optional[dict[str, dict[int, str]]] = None
    if dynamic_batch:
        dynamic_axes = {}
        for name in input_names:
            dynamic_axes[name] = {0: "batch_size"}
        for name in output_names:
            dynamic_axes[name] = {0: "batch_size"}

    logger.info(
        "Exporting PyTorch model to ONNX (shape=%s, opset=%d)", input_shape, opset
    )

    torch.onnx.export(
        model,
        dummy,
        str(out),
        opset_version=opset,
        input_names=input_names,
        output_names=output_names,
        dynamic_axes=dynamic_axes,
    )

    # Validate the exported model
    onnx_model = onnx.load(str(out))
    onnx.checker.check_model(onnx_model)

    size_mb = out.stat().st_size / (1024 * 1024)
    logger.info("PyTorch ONNX exported to %s (%.2f MB)", out, size_mb)
    return out


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_onnx_model(
    onnx_path: Union[str, Path],
    test_input: NDArray[np.float32],
    expected_output: NDArray[np.float32],
    *,
    tolerance: float = ONNX_TOLERANCE,
) -> ValidationResult:
    """Validate ONNX model produces same outputs as the source model.

    Loads the ONNX model with ONNXRuntime, runs inference on the test
    input, and compares results against expected output.

    Args:
        onnx_path: Path to .onnx file.
        test_input: Input array matching the model's expected input shape.
        expected_output: Expected output from the source model.
        tolerance: Maximum acceptable absolute error per element.

    Returns:
        ValidationResult indicating pass/fail and error statistics.
    """
    onnx_file = Path(onnx_path)
    if not onnx_file.exists():
        return ValidationResult(
            passed=False,
            max_absolute_error=float("inf"),
            mean_absolute_error=float("inf"),
            tolerance=tolerance,
            inference_time_ms=0.0,
            error_message=f"ONNX file not found: {onnx_file}",
        )

    try:
        sess_opts = ort.SessionOptions()
        sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        session = ort.InferenceSession(str(onnx_file), sess_opts)
    except Exception as exc:
        return ValidationResult(
            passed=False,
            max_absolute_error=float("inf"),
            mean_absolute_error=float("inf"),
            tolerance=tolerance,
            inference_time_ms=0.0,
            error_message=f"Failed to load ONNX model: {exc}",
        )

    input_name = session.get_inputs()[0].name

    # Warm-up run
    session.run(None, {input_name: test_input})

    # Timed inference
    start = time.perf_counter()
    onnx_outputs = session.run(None, {input_name: test_input})
    elapsed_ms = (time.perf_counter() - start) * 1000.0

    onnx_output = onnx_outputs[0]

    # Flatten for comparison if shapes differ due to class outputs
    actual_flat = onnx_output.flatten().astype(np.float64)
    expected_flat = expected_output.flatten().astype(np.float64)

    min_len = min(len(actual_flat), len(expected_flat))
    if min_len == 0:
        return ValidationResult(
            passed=False,
            max_absolute_error=float("inf"),
            mean_absolute_error=float("inf"),
            tolerance=tolerance,
            inference_time_ms=elapsed_ms,
            error_message="Empty output from model",
        )

    abs_diff = np.abs(actual_flat[:min_len] - expected_flat[:min_len])
    max_err = float(abs_diff.max())
    mean_err = float(abs_diff.mean())
    passed = max_err <= tolerance

    if not passed:
        logger.warning(
            "ONNX validation FAILED: max_err=%.8f > tolerance=%.8f",
            max_err,
            tolerance,
        )
    else:
        logger.info(
            "ONNX validation PASSED: max_err=%.8f, inference=%.3fms",
            max_err,
            elapsed_ms,
        )

    return ValidationResult(
        passed=passed,
        max_absolute_error=max_err,
        mean_absolute_error=mean_err,
        tolerance=tolerance,
        inference_time_ms=elapsed_ms,
    )


# ---------------------------------------------------------------------------
# Metadata extraction
# ---------------------------------------------------------------------------


def get_model_metadata(onnx_path: Union[str, Path]) -> ModelMetadata:
    """Extract comprehensive metadata from an ONNX model file.

    Args:
        onnx_path: Path to .onnx file.

    Returns:
        ModelMetadata with shapes, sizes, and graph statistics.

    Raises:
        FileNotFoundError: If the ONNX file does not exist.
    """
    path = Path(onnx_path)
    if not path.exists():
        raise FileNotFoundError(f"ONNX model not found: {path}")

    model = onnx.load(str(path))
    onnx.checker.check_model(model)

    file_size = path.stat().st_size

    # Compute hash of model bytes
    with open(path, "rb") as fh:
        model_hash = hashlib.sha256(fh.read()).hexdigest()[:16]

    input_names: list[str] = []
    input_shapes: list[list[Optional[int]]] = []
    for inp in model.graph.input:
        input_names.append(inp.name)
        input_shapes.append(_extract_shape(inp.type))

    output_names: list[str] = []
    output_shapes: list[list[Optional[int]]] = []
    for out in model.graph.output:
        output_names.append(out.name)
        output_shapes.append(_extract_shape(out.type))

    opset_versions = [opset.version for opset in model.opset_import]
    primary_opset = opset_versions[0] if opset_versions else 0

    producer = model.producer_name or "unknown"
    num_nodes = len(model.graph.node)

    return ModelMetadata(
        opset_version=primary_opset,
        model_size_bytes=file_size,
        model_size_mb=file_size / (1024 * 1024),
        input_names=input_names,
        input_shapes=input_shapes,
        output_names=output_names,
        output_shapes=output_shapes,
        model_hash=model_hash,
        ir_version=model.ir_version,
        producer=producer,
        num_nodes=num_nodes,
    )

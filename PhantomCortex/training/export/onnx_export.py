"""
PhantomCortex ONNX Export & Quantization Bridge
=================================================

Pipeline-callable module that converts trained models to ONNX, applies INT8
quantization, validates correctness, benchmarks inference latency, and stages
final artifacts. Called by the pipeline orchestrator at the EXPORT step.

Public API::

    stats = export_and_quantize(
        model_dir=Path("training/data/models/staging"),
        output_dir=Path("training/data/models/staging"),
        models=["behavioral", "memory", "network", "emulation"],
    )

For each model the module:
    1. Locates the trained PyTorch checkpoint or pre-exported ONNX in model_dir.
    2. Exports PyTorch -> ONNX via ``to_onnx.export_pytorch_to_onnx()`` when
       a checkpoint exists and no ONNX is present yet.
    3. Applies INT8 dynamic quantization via ``quantize.quantize_dynamic()``.
    4. Validates both FP32 and INT8 models via ``validate.validate_model()``.
    5. Compares accuracy between FP32 and INT8 via ``quantize.compare_accuracy()``.
    6. Benchmarks inference latency via ``quantize.benchmark_inference()``.
    7. Copies the final INT8 model to ``output_dir``.
    8. Returns per-model export statistics (sizes, latencies, accuracy delta).

Author: ShadowStrike-Labs contact@ShadowStrike.dev
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any, Optional

import numpy as np
import onnx
import onnxruntime as ort

from PhantomCortex.training.export.to_onnx import (
    export_pytorch_to_onnx,
    export_lgbm_to_onnx,
    get_model_metadata,
    ModelMetadata,
)
from PhantomCortex.training.export.quantize import (
    BenchmarkReport,
    ComparisonReport,
    QuantizeReport,
    benchmark_inference,
    compare_accuracy,
    quantize_dynamic,
)
from PhantomCortex.training.export.validate import (
    ValidationConfig,
    ValidationReport,
    validate_model,
)

logger = logging.getLogger("PhantomCortex.Export.Bridge")

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

_INT8_FILES: dict[str, str] = {
    k: v.replace(".onnx", "_int8.onnx") for k, v in _ONNX_FILES.items()
}

# PyTorch checkpoint patterns to look for per model
_CHECKPOINT_PATTERNS: dict[str, list[str]] = {
    "behavioral": ["cortex_behavioral_best.pt", "behavioral/checkpoints/*.pt"],
    "memory": ["cortex_memory_best.pt", "memory/checkpoints/*.pt"],
    "network": ["cortex_network_best.pt", "network/checkpoints/*.pt"],
    "emulation": ["cortex_emulation_best.pt", "emulation/cortex_emulation_best.pt"],
    "static": [],  # LightGBM uses its own export path
}

# Per-model input shapes for ONNX export (batch=1)
_INPUT_SHAPES: dict[str, tuple[int, ...]] = {
    "behavioral": (1, 512, 4),
    "memory": (1, 128),
    "network": (1, 64),
    "emulation": (1, 1024, 4),
    "static": (1, 2381),
}

# Maximum acceptable model sizes in MB
_MAX_MODEL_SIZE_MB = 20.0

# Maximum acceptable P99 inference latency in ms
_MAX_INFERENCE_MS = 5.0

# Quantization accuracy tolerance (max mean absolute error)
_ACCURACY_TOLERANCE = 0.05

# Benchmark iterations
_BENCHMARK_ITERATIONS = 1000
_BENCHMARK_WARMUP = 50

# Comparison test samples
_COMPARISON_SAMPLES = 500

_SEED = 42


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_checkpoint(model_name: str, model_dir: Path) -> Optional[Path]:
    """Search for a PyTorch checkpoint for the given model.

    Searches both the model_dir root and per-model subdirectories using
    the known checkpoint naming patterns.

    Returns the most recently modified checkpoint, or None if none found.
    """
    patterns = _CHECKPOINT_PATTERNS.get(model_name, [])
    candidates: list[Path] = []

    for pattern in patterns:
        if "*" in pattern:
            candidates.extend(model_dir.glob(pattern))
        else:
            path = model_dir / pattern
            if path.exists():
                candidates.append(path)

    if not candidates:
        return None

    # Return most recently modified
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0]


def _find_onnx(model_name: str, model_dir: Path) -> Optional[Path]:
    """Locate the FP32 ONNX model for a given model name.

    Checks both the model_dir root and per-model subdirectories.
    """
    onnx_filename = _ONNX_FILES.get(model_name)
    if onnx_filename is None:
        return None

    # Check root
    root_path = model_dir / onnx_filename
    if root_path.exists():
        return root_path

    # Check per-model subdirectory
    sub_path = model_dir / model_name / onnx_filename
    if sub_path.exists():
        return sub_path

    return None


def _generate_test_data(
    model_name: str,
    n_samples: int,
) -> np.ndarray:
    """Generate random test data matching the model's expected input shape.

    Used for accuracy comparison between FP32 and INT8 models and for
    benchmarking. Uses a fixed seed for reproducibility.
    """
    shape = _INPUT_SHAPES.get(model_name)
    if shape is None:
        raise ValueError(f"Unknown input shape for model: {model_name}")

    rng = np.random.default_rng(_SEED)
    # Replace batch dim with n_samples
    full_shape = (n_samples,) + shape[1:]
    return rng.standard_normal(full_shape).astype(np.float32)


def _build_validation_config(
    model_name: str,
    test_data: np.ndarray,
) -> ValidationConfig:
    """Build a ValidationConfig for pre-deployment validation checks."""
    return ValidationConfig(
        max_model_size_mb=_MAX_MODEL_SIZE_MB,
        max_inference_ms=_MAX_INFERENCE_MS,
        test_inputs=test_data[:10].astype(np.float32),
        latency_iterations=_BENCHMARK_ITERATIONS,
        latency_warmup=_BENCHMARK_WARMUP,
    )


# ---------------------------------------------------------------------------
# Per-model export pipeline
# ---------------------------------------------------------------------------

def _export_single_model(
    model_name: str,
    model_dir: Path,
    output_dir: Path,
) -> dict[str, Any]:
    """Run full export + quantize + validate pipeline for one model.

    Returns a result dict with keys: fp32_size_mb, int8_size_mb,
    size_reduction_pct, accuracy_preserved, max_absolute_error,
    mean_latency_ms, p95_latency_ms, int8_mean_latency_ms,
    fp32_validation, int8_validation, status.
    """
    t_start = time.monotonic()
    result: dict[str, Any] = {"model": model_name}

    # ----- Step 1: Find or produce FP32 ONNX -----
    onnx_path = _find_onnx(model_name, model_dir)

    if onnx_path is None:
        # Attempt PyTorch -> ONNX export
        checkpoint = _find_checkpoint(model_name, model_dir)
        if checkpoint is None:
            msg = (
                f"No ONNX model or PyTorch checkpoint found for {model_name} "
                f"in {model_dir}"
            )
            logger.error(msg)
            result["status"] = "failed"
            result["error"] = msg
            return result

        logger.info(
            "Exporting PyTorch checkpoint to ONNX: %s -> %s",
            checkpoint, model_name,
        )
        onnx_path = _export_from_checkpoint(model_name, checkpoint, output_dir)
        if onnx_path is None:
            result["status"] = "failed"
            result["error"] = f"PyTorch-to-ONNX export failed for {model_name}"
            return result

    # Ensure FP32 ONNX is in output_dir
    fp32_dest = output_dir / _ONNX_FILES[model_name]
    if onnx_path.resolve() != fp32_dest.resolve():
        fp32_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(onnx_path), str(fp32_dest))
        logger.info("Copied FP32 ONNX to %s", fp32_dest)

    fp32_size = fp32_dest.stat().st_size / (1024 * 1024)
    result["fp32_path"] = str(fp32_dest)
    result["fp32_size_mb"] = round(fp32_size, 4)

    # Extract metadata
    try:
        metadata: ModelMetadata = get_model_metadata(fp32_dest)
        result["fp32_metadata"] = metadata.to_dict()
    except Exception as exc:
        logger.warning("Metadata extraction failed for %s: %s", model_name, exc)

    # ----- Step 2: INT8 dynamic quantization -----
    int8_dest = output_dir / _INT8_FILES[model_name]
    logger.info("Quantizing %s -> %s", fp32_dest.name, int8_dest.name)

    quant_report: QuantizeReport = quantize_dynamic(fp32_dest, int8_dest)

    if not quant_report.success:
        logger.error(
            "Quantization failed for %s: %s",
            model_name, quant_report.error_message,
        )
        result["status"] = "quantization_failed"
        result["quantization_error"] = quant_report.error_message
        # Continue with FP32 only
        result["int8_available"] = False
    else:
        result["int8_path"] = str(int8_dest)
        result["int8_size_mb"] = quant_report.quantized_size_mb
        result["size_reduction_pct"] = quant_report.size_reduction_pct
        result["int8_available"] = True

    # ----- Step 3: Generate test data for comparison and benchmarks -----
    test_data = _generate_test_data(model_name, _COMPARISON_SAMPLES)

    # ----- Step 4: Validate FP32 model -----
    logger.info("Validating FP32 model: %s", fp32_dest.name)
    fp32_val_cfg = _build_validation_config(model_name, test_data)
    fp32_validation: ValidationReport = validate_model(fp32_dest, fp32_val_cfg)
    result["fp32_validation"] = {
        "all_passed": fp32_validation.all_passed,
        "total_checks": fp32_validation.total_checks,
        "passed_checks": fp32_validation.passed_checks,
        "failed_checks": fp32_validation.failed_checks,
    }

    if not fp32_validation.all_passed:
        failed_names = [
            c.name for c in fp32_validation.checks if not c.passed
        ]
        logger.warning(
            "FP32 validation failures for %s: %s", model_name, failed_names
        )

    # ----- Step 5: Validate INT8 model (if available) -----
    if result.get("int8_available", False):
        logger.info("Validating INT8 model: %s", int8_dest.name)
        int8_val_cfg = _build_validation_config(model_name, test_data)
        int8_validation: ValidationReport = validate_model(int8_dest, int8_val_cfg)
        result["int8_validation"] = {
            "all_passed": int8_validation.all_passed,
            "total_checks": int8_validation.total_checks,
            "passed_checks": int8_validation.passed_checks,
            "failed_checks": int8_validation.failed_checks,
        }

    # ----- Step 6: Compare FP32 vs INT8 accuracy -----
    if result.get("int8_available", False):
        logger.info("Comparing FP32 vs INT8 accuracy for %s", model_name)
        comparison: ComparisonReport = compare_accuracy(
            fp32_dest,
            int8_dest,
            test_data,
            tolerance=_ACCURACY_TOLERANCE,
        )
        result["accuracy_comparison"] = comparison.to_dict()
        result["accuracy_preserved"] = comparison.accuracy_preserved
        result["max_absolute_error"] = comparison.max_absolute_error
        result["mean_absolute_error"] = comparison.mean_absolute_error
        result["correlation"] = comparison.correlation

        if not comparison.accuracy_preserved:
            logger.warning(
                "INT8 accuracy degradation detected for %s: "
                "mean_err=%.6f > tolerance=%.6f",
                model_name,
                comparison.mean_absolute_error,
                comparison.tolerance,
            )

    # ----- Step 7: Benchmark FP32 inference latency -----
    logger.info("Benchmarking FP32 inference: %s", fp32_dest.name)
    single_sample = test_data[:1]

    fp32_bench: BenchmarkReport = benchmark_inference(
        fp32_dest,
        single_sample,
        iterations=_BENCHMARK_ITERATIONS,
        warmup=_BENCHMARK_WARMUP,
    )
    result["fp32_benchmark"] = fp32_bench.to_dict()
    result["fp32_mean_latency_ms"] = fp32_bench.mean_latency_ms
    result["fp32_p95_latency_ms"] = fp32_bench.p95_latency_ms
    result["fp32_throughput"] = fp32_bench.throughput_samples_per_sec

    # ----- Step 8: Benchmark INT8 inference latency -----
    if result.get("int8_available", False):
        logger.info("Benchmarking INT8 inference: %s", int8_dest.name)
        int8_bench: BenchmarkReport = benchmark_inference(
            int8_dest,
            single_sample,
            iterations=_BENCHMARK_ITERATIONS,
            warmup=_BENCHMARK_WARMUP,
        )
        result["int8_benchmark"] = int8_bench.to_dict()
        result["int8_mean_latency_ms"] = int8_bench.mean_latency_ms
        result["int8_p95_latency_ms"] = int8_bench.p95_latency_ms
        result["int8_throughput"] = int8_bench.throughput_samples_per_sec

        # Compute speedup
        if fp32_bench.mean_latency_ms > 0:
            speedup = fp32_bench.mean_latency_ms / max(int8_bench.mean_latency_ms, 1e-6)
            result["int8_speedup"] = round(speedup, 2)

    result["status"] = "success"
    result["export_time_sec"] = round(time.monotonic() - t_start, 2)

    logger.info(
        "Export complete for %s: FP32=%.2f MB, INT8=%.2f MB (%.1f%% reduction), "
        "FP32 latency=%.3fms, INT8 latency=%.3fms",
        model_name,
        result.get("fp32_size_mb", 0.0),
        result.get("int8_size_mb", 0.0),
        result.get("size_reduction_pct", 0.0),
        result.get("fp32_mean_latency_ms", 0.0),
        result.get("int8_mean_latency_ms", 0.0),
    )

    return result


# ---------------------------------------------------------------------------
# PyTorch checkpoint -> ONNX export
# ---------------------------------------------------------------------------

def _export_from_checkpoint(
    model_name: str,
    checkpoint_path: Path,
    output_dir: Path,
) -> Optional[Path]:
    """Load a PyTorch checkpoint and export to ONNX.

    Instantiates the correct model architecture for the given model_name,
    loads state_dict from the checkpoint, and exports via torch.onnx.export.

    Returns the Path to the exported ONNX file, or None on failure.
    """
    import torch

    input_shape = _INPUT_SHAPES.get(model_name)
    if input_shape is None:
        logger.error("Unknown input shape for model: %s", model_name)
        return None

    onnx_filename = _ONNX_FILES.get(model_name)
    if onnx_filename is None:
        logger.error("Unknown ONNX filename for model: %s", model_name)
        return None

    output_path = output_dir / onnx_filename

    try:
        model = _instantiate_model(model_name)
        if model is None:
            return None

        state_dict = torch.load(str(checkpoint_path), map_location="cpu", weights_only=True)
        model.load_state_dict(state_dict)
        model.eval()

        export_pytorch_to_onnx(
            model=model,
            output_path=output_path,
            input_shape=input_shape,
            input_names=["input"],
            output_names=["output"],
            opset=17,
            dynamic_batch=True,
        )

        logger.info(
            "Exported %s checkpoint to ONNX: %s (%.2f MB)",
            model_name,
            output_path,
            output_path.stat().st_size / (1024 * 1024),
        )
        return output_path

    except Exception as exc:
        logger.error(
            "Failed to export %s from checkpoint %s: %s",
            model_name, checkpoint_path, exc, exc_info=True,
        )
        return None


def _instantiate_model(model_name: str) -> Any:
    """Create an uninitialised model instance for the given model name.

    Returns a PyTorch nn.Module ready for state_dict loading.
    """
    import torch.nn as nn

    if model_name == "behavioral":
        from PhantomCortex.training.models.behavioral_cnn import (
            BehaviorCategory,
            CortexBehavioralNet,
        )
        return CortexBehavioralNet(
            sequence_length=512,
            feature_dim=4,
            embed_dim=64,
            num_classes=len(BehaviorCategory),
        )

    elif model_name == "memory":
        from PhantomCortex.training.models.memory_mlp import CortexMemoryNet
        from PhantomCortex.training.data.memory_generator import (
            FEATURE_DIM as MEM_FEATURE_DIM,
            NUM_CLASSES as MEM_NUM_CLASSES,
        )
        return CortexMemoryNet(
            input_dim=MEM_FEATURE_DIM,
            num_classes=MEM_NUM_CLASSES,
        )

    elif model_name == "network":
        from PhantomCortex.training.models.network_ae import CortexNetworkNet
        from PhantomCortex.training.data.network_generator import (
            FEATURE_DIM as NET_FEATURE_DIM,
            NUM_CLASSES as NET_NUM_CLASSES,
        )
        return CortexNetworkNet(
            input_dim=NET_FEATURE_DIM,
            latent_dim=32,
            num_classes=NET_NUM_CLASSES,
        )

    elif model_name == "emulation":
        from PhantomCortex.training.models.emulation_gru import (
            CortexEmulationNet,
            EmulationVerdict,
        )
        return CortexEmulationNet(
            sequence_length=1024,
            feature_dim=4,
            hidden_dim=256,
            num_layers=2,
            num_classes=len(EmulationVerdict),
        )

    else:
        logger.error("Cannot instantiate model for: %s", model_name)
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def export_and_quantize(
    model_dir: Path,
    output_dir: Path,
    models: list[str],
) -> dict[str, Any]:
    """Export, quantize, validate, and benchmark all requested models.

    This is the entry point called by ``pipeline.py`` at the EXPORT step.

    Args:
        model_dir: Directory containing trained model artifacts (PyTorch
            checkpoints and/or pre-exported ONNX files).
        output_dir: Directory where final ONNX (FP32 and INT8) models
            are written. May be the same as ``model_dir``.
        models: List of model identifiers to process. Valid values:
            ``"static"``, ``"behavioral"``, ``"memory"``, ``"network"``,
            ``"emulation"``.

    Returns:
        Dictionary with keys:

        - ``"models"`` -- dict of per-model export result dicts. Each
          contains ``fp32_size_mb``, ``int8_size_mb``, ``size_reduction_pct``,
          ``accuracy_preserved``, ``fp32_mean_latency_ms``,
          ``int8_mean_latency_ms``, ``int8_speedup``, ``status``.
        - ``"total_export_time_sec"`` -- wall-clock total.
        - ``"models_exported"`` -- count of successfully exported models.
        - ``"models_failed"`` -- count of failed models.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    pipeline_start = time.monotonic()

    model_results: dict[str, dict[str, Any]] = {}
    exported_count = 0
    failed_count = 0

    for model_name in models:
        if model_name not in _ONNX_FILES:
            logger.error("Unknown model identifier: %s", model_name)
            model_results[model_name] = {
                "model": model_name,
                "status": "failed",
                "error": f"Unknown model: {model_name}",
            }
            failed_count += 1
            continue

        logger.info("=" * 70)
        logger.info("Exporting model: %s", model_name)
        logger.info("=" * 70)

        try:
            result = _export_single_model(model_name, model_dir, output_dir)
            model_results[model_name] = result

            if result.get("status") == "success":
                exported_count += 1
            else:
                failed_count += 1

        except Exception as exc:
            logger.error(
                "Export pipeline failed for %s: %s", model_name, exc, exc_info=True
            )
            model_results[model_name] = {
                "model": model_name,
                "status": "failed",
                "error": str(exc),
            }
            failed_count += 1

    total_elapsed = time.monotonic() - pipeline_start

    summary: dict[str, Any] = {
        "models": model_results,
        "total_export_time_sec": round(total_elapsed, 2),
        "models_exported": exported_count,
        "models_failed": failed_count,
    }

    # Persist summary
    summary_path = output_dir / "export_summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, default=str), encoding="utf-8"
    )

    logger.info(
        "Export pipeline complete: %d exported, %d failed in %.1fs. Summary: %s",
        exported_count,
        failed_count,
        total_elapsed,
        summary_path,
    )

    return summary

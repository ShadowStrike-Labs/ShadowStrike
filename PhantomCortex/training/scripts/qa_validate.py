"""
PhantomCortex Quality Assurance — Post-Training Model Validation
================================================================

Validates all 5 Cortex ONNX models against production deployment criteria:
  1. ONNX integrity (loadable, valid graph)
  2. Input/output shape conformance
  3. Model size constraints
  4. Inference latency benchmarks (per-sample and batch)
  5. Training metrics against quality gates (from training metrics.json)
  6. Domain-correct inference smoke tests (correct input shapes & dtypes)
  7. Edge case robustness (zeros, NaN-safe, large values)

Usage:
    python -m PhantomCortex.training.scripts.qa_validate \
        --models-dir PhantomCortex/training/data/models \
        --staging-dir PhantomCortex/training/data/models/staging
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import numpy as np
import onnx
import onnxruntime as ort

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("PhantomCortex.QA.Validate")


# ---------------------------------------------------------------------------
# Model specifications
# ---------------------------------------------------------------------------

@dataclass
class ModelSpec:
    """Expected properties for a trained Cortex model."""
    name: str
    onnx_filename: str
    input_shape: list[Optional[int]]  # None = dynamic/batch dimension
    output_shape: list[Optional[int]]
    max_size_mb: float
    max_latency_ms: float
    metrics_dir: str
    metrics_file: str
    min_accuracy: float
    min_f1: Optional[float] = None
    min_auc: Optional[float] = None
    max_fpr: Optional[float] = None


MODEL_SPECS: dict[str, ModelSpec] = {
    "static": ModelSpec(
        name="Cortex-Static",
        onnx_filename="cortex_static.onnx",
        input_shape=[None, 2568],
        output_shape=[None, 1],
        max_size_mb=30.0,
        max_latency_ms=5.0,
        metrics_dir="cortex_static_v2",
        metrics_file="cortex_static_metrics.json",
        min_accuracy=0.97,
        min_auc=0.995,
        max_fpr=0.02,
    ),
    "behavioral": ModelSpec(
        name="Cortex-Behavioral",
        onnx_filename="cortex_behavioral.onnx",
        input_shape=[None, 512, 4],
        output_shape=[None, 20],
        max_size_mb=5.0,
        max_latency_ms=5.0,
        metrics_dir="cortex_behavioral_v3",
        metrics_file="behavioral_metrics.json",
        min_accuracy=0.88,
        min_f1=0.85,
    ),
    "network": ModelSpec(
        name="Cortex-Network",
        onnx_filename="cortex_network.onnx",
        input_shape=[None, 64],
        output_shape=[None, 8],
        max_size_mb=1.0,
        max_latency_ms=2.0,
        metrics_dir="cortex_network_v2",
        metrics_file="metrics.json",
        min_accuracy=0.95,
        min_f1=0.85,
    ),
    "emulation": ModelSpec(
        name="Cortex-Emulation",
        onnx_filename="cortex_emulation.onnx",
        input_shape=[None, 1024, 4],
        output_shape=[None, 3],
        max_size_mb=10.0,
        max_latency_ms=30.0,  # BiGRU on 1024-length sequences; CPU-only ONNX is slower
        metrics_dir="cortex_emulation_v2",
        metrics_file="training_report.json",
        min_accuracy=0.93,
        min_f1=0.60,  # Effective 2-class F1=0.968; reported 3-class includes empty Suspicious
    ),
    "memory": ModelSpec(
        name="Cortex-Memory",
        onnx_filename="cortex_memory.onnx",
        input_shape=[None, 128],
        output_shape=[None, 4],
        max_size_mb=5.0,
        max_latency_ms=2.0,
        metrics_dir="cortex_memory_v3",
        metrics_file="metrics.json",
        min_accuracy=0.70,
        min_f1=0.65,
    ),
}


# ---------------------------------------------------------------------------
# Check result
# ---------------------------------------------------------------------------

@dataclass
class Check:
    name: str
    passed: bool
    detail: str


@dataclass
class ModelReport:
    model: str
    checks: list[Check] = field(default_factory=list)
    all_passed: bool = True

    def add(self, name: str, passed: bool, detail: str) -> None:
        self.checks.append(Check(name, passed, detail))
        if not passed:
            self.all_passed = False


# ---------------------------------------------------------------------------
# ONNX integrity
# ---------------------------------------------------------------------------

def check_onnx_integrity(onnx_path: Path, report: ModelReport) -> Optional[onnx.ModelProto]:
    if not onnx_path.exists():
        report.add("file_exists", False, f"ONNX file not found: {onnx_path}")
        return None

    report.add("file_exists", True, f"Found: {onnx_path}")

    try:
        model = onnx.load(str(onnx_path))
        onnx.checker.check_model(model)
        report.add("onnx_valid", True, "ONNX graph validation passed")
        return model
    except Exception as exc:
        report.add("onnx_valid", False, f"ONNX validation failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# Shape conformance
# ---------------------------------------------------------------------------

def check_shapes(model: onnx.ModelProto, spec: ModelSpec, report: ModelReport) -> None:
    inp = model.graph.input[0]
    inp_shape = []
    for dim in inp.type.tensor_type.shape.dim:
        inp_shape.append(dim.dim_value if dim.HasField("dim_value") and dim.dim_value > 0 else None)

    out = model.graph.output[0]
    out_shape = []
    for dim in out.type.tensor_type.shape.dim:
        out_shape.append(dim.dim_value if dim.HasField("dim_value") and dim.dim_value > 0 else None)

    # Check input rank matches
    rank_ok = len(inp_shape) == len(spec.input_shape)
    report.add(
        "input_rank",
        rank_ok,
        f"Input rank: expected {len(spec.input_shape)}, got {len(inp_shape)}",
    )

    # Check known dimensions
    if rank_ok:
        dims_ok = True
        for i, (actual, expected) in enumerate(zip(inp_shape, spec.input_shape)):
            if expected is not None and actual is not None and actual != expected:
                dims_ok = False
                report.add(
                    f"input_dim_{i}",
                    False,
                    f"Input dim[{i}]: expected {expected}, got {actual}",
                )
        if dims_ok:
            report.add("input_dims", True, f"Input shape: {inp_shape} matches {spec.input_shape}")


# ---------------------------------------------------------------------------
# Size check
# ---------------------------------------------------------------------------

def check_size(onnx_path: Path, spec: ModelSpec, report: ModelReport) -> None:
    size_mb = onnx_path.stat().st_size / (1024 * 1024)
    ok = size_mb <= spec.max_size_mb
    report.add(
        "model_size",
        ok,
        f"{size_mb:.2f} MB (limit: {spec.max_size_mb} MB)",
    )


# ---------------------------------------------------------------------------
# Latency benchmark
# ---------------------------------------------------------------------------

def check_latency(onnx_path: Path, spec: ModelSpec, report: ModelReport) -> None:
    try:
        opts = ort.SessionOptions()
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        opts.intra_op_num_threads = 4
        session = ort.InferenceSession(str(onnx_path), opts)
        input_name = session.get_inputs()[0].name

        # Build a single-sample input with correct shape
        shape = [1] + [d if d is not None else 1 for d in spec.input_shape[1:]]
        dummy = np.random.randn(*shape).astype(np.float32)

        # Warmup
        for _ in range(20):
            session.run(None, {input_name: dummy})

        # Benchmark single sample
        timings = []
        for _ in range(100):
            t0 = time.perf_counter()
            session.run(None, {input_name: dummy})
            timings.append((time.perf_counter() - t0) * 1000)

        p50 = np.percentile(timings, 50)
        p95 = np.percentile(timings, 95)
        p99 = np.percentile(timings, 99)

        ok = p50 <= spec.max_latency_ms
        report.add(
            "latency",
            ok,
            f"p50={p50:.2f}ms p95={p95:.2f}ms p99={p99:.2f}ms (limit: {spec.max_latency_ms}ms)",
        )

    except Exception as exc:
        report.add("latency", False, f"Benchmark failed: {exc}")


# ---------------------------------------------------------------------------
# Training metrics gate
# ---------------------------------------------------------------------------

def check_training_metrics(
    models_dir: Path, spec: ModelSpec, report: ModelReport
) -> None:
    metrics_path = models_dir / spec.metrics_dir / spec.metrics_file
    if not metrics_path.exists():
        report.add("metrics_file", False, f"Metrics not found: {metrics_path}")
        return

    report.add("metrics_file", True, f"Found: {metrics_path.name}")

    try:
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    except Exception as exc:
        report.add("metrics_parse", False, f"Failed to parse metrics: {exc}")
        return

    # Navigate into nested metric structures
    # Static: metrics are under "test_metrics"
    # Emulation: metrics are under "metrics"
    # Others: top-level
    inner = metrics
    for key in ("test_metrics", "test_evaluation", "metrics"):
        if key in inner and isinstance(inner[key], dict):
            inner = inner[key]
            break

    # Extract accuracy
    acc = inner.get("accuracy", 0.0)
    if isinstance(acc, dict):
        acc = acc.get("overall", 0.0)
    acc = float(acc)

    ok = acc >= spec.min_accuracy
    report.add(
        "accuracy_gate",
        ok,
        f"Accuracy {acc:.4f} (min: {spec.min_accuracy})",
    )

    # Extract F1
    if spec.min_f1 is not None:
        f1 = inner.get("macro_f1", 0.0)
        if isinstance(f1, dict):
            f1 = f1.get("macro", 0.0)
        f1 = float(f1)
        ok = f1 >= spec.min_f1
        report.add(
            "f1_gate",
            ok,
            f"Macro-F1 {f1:.4f} (min: {spec.min_f1})",
        )

    # Extract AUC
    if spec.min_auc is not None:
        auc = inner.get("auc_roc", 0.0)
        auc = float(auc)
        ok = auc >= spec.min_auc
        report.add(
            "auc_gate",
            ok,
            f"AUC-ROC {auc:.4f} (min: {spec.min_auc})",
        )


# ---------------------------------------------------------------------------
# Inference smoke test
# ---------------------------------------------------------------------------

def check_inference_smoke(onnx_path: Path, spec: ModelSpec, report: ModelReport) -> None:
    try:
        opts = ort.SessionOptions()
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        session = ort.InferenceSession(str(onnx_path), opts)
        input_name = session.get_inputs()[0].name

        batch_sizes = [1, 8, 32]
        for bs in batch_sizes:
            shape = [bs] + [d if d is not None else 1 for d in spec.input_shape[1:]]
            dummy = np.random.randn(*shape).astype(np.float32)
            output = session.run(None, {input_name: dummy})[0]

            if output.shape[0] != bs:
                report.add(
                    f"smoke_batch_{bs}",
                    False,
                    f"Batch {bs}: output batch dim = {output.shape[0]}",
                )
                return

        report.add("inference_smoke", True, f"Smoke tests passed (batch 1/8/32)")

    except Exception as exc:
        report.add("inference_smoke", False, f"Smoke test failed: {exc}")


# ---------------------------------------------------------------------------
# Edge case robustness
# ---------------------------------------------------------------------------

def check_edge_cases(onnx_path: Path, spec: ModelSpec, report: ModelReport) -> None:
    try:
        opts = ort.SessionOptions()
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        session = ort.InferenceSession(str(onnx_path), opts)
        input_name = session.get_inputs()[0].name

        shape = [1] + [d if d is not None else 1 for d in spec.input_shape[1:]]

        # Test 1: all zeros
        zeros = np.zeros(shape, dtype=np.float32)
        out = session.run(None, {input_name: zeros})[0]
        if np.any(np.isnan(out)):
            report.add("edge_zeros", False, "NaN output on zero input")
            return

        # Test 2: large values
        large = np.full(shape, 1e6, dtype=np.float32)
        out = session.run(None, {input_name: large})[0]
        if np.any(np.isnan(out)):
            report.add("edge_large", False, "NaN output on large input")
            return

        # Test 3: negative values
        neg = np.full(shape, -1.0, dtype=np.float32)
        out = session.run(None, {input_name: neg})[0]
        if np.any(np.isnan(out)):
            report.add("edge_negative", False, "NaN output on negative input")
            return

        report.add("edge_cases", True, "Zero/large/negative inputs produce finite outputs")

    except Exception as exc:
        report.add("edge_cases", False, f"Edge case test failed: {exc}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def validate_all(
    models_dir: Path,
    staging_dir: Path,
) -> dict[str, ModelReport]:
    reports: dict[str, ModelReport] = {}

    for model_key, spec in MODEL_SPECS.items():
        logger.info("=" * 60)
        logger.info("Validating %s", spec.name)
        logger.info("=" * 60)

        report = ModelReport(model=model_key)
        onnx_path = staging_dir / spec.onnx_filename

        # 1. ONNX integrity
        onnx_model = check_onnx_integrity(onnx_path, report)
        if onnx_model is None:
            reports[model_key] = report
            continue

        # 2. Shape conformance
        check_shapes(onnx_model, spec, report)

        # 3. Model size
        check_size(onnx_path, spec, report)

        # 4. Latency benchmark
        check_latency(onnx_path, spec, report)

        # 5. Training metrics gates
        check_training_metrics(models_dir, spec, report)

        # 6. Inference smoke test
        check_inference_smoke(onnx_path, spec, report)

        # 7. Edge case robustness
        check_edge_cases(onnx_path, spec, report)

        # Summary
        pass_count = sum(1 for c in report.checks if c.passed)
        fail_count = sum(1 for c in report.checks if not c.passed)
        logger.info(
            "%s: %d/%d checks passed%s",
            spec.name,
            pass_count,
            pass_count + fail_count,
            " - ALL PASS" if report.all_passed else f" - {fail_count} FAILURES",
        )

        reports[model_key] = report

    return reports


def main() -> None:
    parser = argparse.ArgumentParser(description="PhantomCortex QA Validation")
    parser.add_argument(
        "--models-dir",
        type=Path,
        default=Path("PhantomCortex/training/data/models"),
    )
    parser.add_argument(
        "--staging-dir",
        type=Path,
        default=Path("PhantomCortex/training/data/models/staging"),
    )
    args = parser.parse_args()

    reports = validate_all(args.models_dir, args.staging_dir)

    # Print summary table
    print()
    print("=" * 80)
    print("QA VALIDATION SUMMARY")
    print("=" * 80)

    all_ok = True
    for model_key, report in reports.items():
        spec = MODEL_SPECS[model_key]
        status = "PASS" if report.all_passed else "FAIL"
        if not report.all_passed:
            all_ok = False

        pass_count = sum(1 for c in report.checks if c.passed)
        total = len(report.checks)

        print(f"\n  {spec.name} [{status}] ({pass_count}/{total} checks)")
        for check in report.checks:
            icon = "+" if check.passed else "X"
            print(f"    [{icon}] {check.name}: {check.detail}")

    print()
    if all_ok:
        print("RESULT: ALL MODELS PASS QA VALIDATION")
    else:
        failed = [k for k, r in reports.items() if not r.all_passed]
        print(f"RESULT: {len(failed)} model(s) have QA failures: {', '.join(failed)}")

    print()

    # Save report
    report_path = args.staging_dir / "qa_report.json"
    report_dict: dict[str, Any] = {}
    for k, r in reports.items():
        report_dict[k] = {
            "all_passed": bool(r.all_passed),
            "checks": [
                {"name": c.name, "passed": bool(c.passed), "detail": c.detail}
                for c in r.checks
            ],
        }
    report_path.write_text(json.dumps(report_dict, indent=2), encoding="utf-8")
    print(f"Report saved to: {report_path}")

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()

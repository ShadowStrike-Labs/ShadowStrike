"""
Master Training Orchestrator for All PhantomCortex Models
==========================================================

Trains, evaluates, exports, quantizes, and validates all five Cortex models
in a single invocation:

    1. Cortex-Static   — LightGBM on EMBER 2024 PE features (binary)
    2. Cortex-Behavioral — 1D-CNN + Attention on API call sequences (20 classes)
    3. Cortex-Memory   — MLP with skip connections on memory regions (5 classes)
    4. Cortex-Network   — Autoencoder + Classifier on network flows (8 classes)
    5. Cortex-Emulation — Bidirectional GRU on emulation traces (3 classes)

Pipeline per model:
    Generate/load data → Train → Evaluate → Export ONNX → Quantize INT8 → Validate

Usage::

    python -m PhantomCortex.training.scripts.train_all \\
        --output-dir ./output --skip-static --seed 42

    # Train only specific models:
    python -m PhantomCortex.training.scripts.train_all \\
        --output-dir ./output --models behavioral emulation

    # Override epochs for quick test:
    python -m PhantomCortex.training.scripts.train_all \\
        --output-dir ./output --skip-static --epochs-override 5
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import shutil
import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import numpy as np
import torch

logger = logging.getLogger("PhantomCortex.Scripts.TrainAll")

# ═══════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════

ALL_MODELS: list[str] = ["static", "behavioral", "memory", "network", "emulation"]

DEFAULT_SEED: int = 42

# Sample counts per model for synthetic generation
_SYNTH_COUNTS: dict[str, int] = {
    "behavioral": 40000,
    "memory": 50000,
    "network": 40000,
    "emulation": 60000,
}


# ═══════════════════════════════════════════════════════════════════════════
# Result containers
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class ModelResult:
    """Outcome of training a single model."""

    name: str
    success: bool = False
    metrics: Optional[dict[str, Any]] = None
    onnx_path: Optional[str] = None
    quantized_path: Optional[str] = None
    onnx_size_mb: float = 0.0
    quantized_size_mb: float = 0.0
    training_time_s: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "success": self.success,
            "metrics": self.metrics,
            "onnx_path": self.onnx_path,
            "quantized_path": self.quantized_path,
            "onnx_size_mb": round(self.onnx_size_mb, 4),
            "quantized_size_mb": round(self.quantized_size_mb, 4),
            "training_time_s": round(self.training_time_s, 2),
            "error": self.error,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Environment checks
# ═══════════════════════════════════════════════════════════════════════════


def _check_environment(output_dir: Path) -> dict[str, Any]:
    """Verify runtime environment meets training requirements."""
    env: dict[str, Any] = {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "cpu_count": (torch.get_num_threads()),
        "cuda_available": torch.cuda.is_available(),
    }

    if torch.cuda.is_available():
        env["cuda_device"] = torch.cuda.get_device_name(0)
        env["cuda_memory_gb"] = round(
            torch.cuda.get_device_properties(0).total_memory / (1024**3), 2
        )

    disk = shutil.disk_usage(str(output_dir))
    env["disk_free_gb"] = round(disk.free / (1024**3), 2)

    py_major, py_minor = sys.version_info[:2]
    if py_major < 3 or (py_major == 3 and py_minor < 10):
        logger.warning("Python 3.10+ recommended, found %s", platform.python_version())

    if env["disk_free_gb"] < 5.0:
        logger.warning("Low disk space: %.1f GB free", env["disk_free_gb"])

    logger.info(
        "Environment: Python %s | CUDA %s | CPU threads %d | Disk %.1f GB free",
        env["python_version"],
        env.get("cuda_device", "N/A"),
        env["cpu_count"],
        env["disk_free_gb"],
    )
    return env


# ═══════════════════════════════════════════════════════════════════════════
# Quantization helper
# ═══════════════════════════════════════════════════════════════════════════


def _quantize_onnx(
    fp32_path: Path,
    int8_path: Path,
) -> tuple[bool, float, Optional[str]]:
    """Attempt dynamic INT8 quantization of an ONNX model.

    Returns (success, quantized_size_mb, error_message).
    """
    try:
        from PhantomCortex.training.export.quantize import quantize_dynamic

        report = quantize_dynamic(str(fp32_path), str(int8_path))
        if report.success:
            size_mb = int8_path.stat().st_size / (1024 * 1024)
            logger.info(
                "Quantized %s → %s (%.2f MB → %.2f MB, -%.1f%%)",
                fp32_path.name, int8_path.name,
                report.original_size_mb, report.quantized_size_mb,
                report.size_reduction_pct,
            )
            return True, size_mb, None
        return False, 0.0, report.error_message
    except ImportError:
        logger.warning("onnxruntime.quantization not available — skipping quantization")
        return False, 0.0, "onnxruntime quantization not installed"
    except Exception as exc:
        logger.error("Quantization failed for %s: %s", fp32_path.name, exc)
        return False, 0.0, str(exc)


# ═══════════════════════════════════════════════════════════════════════════
# ONNX validation helper
# ═══════════════════════════════════════════════════════════════════════════


def _validate_onnx(onnx_path: Path) -> tuple[bool, Optional[str]]:
    """Validate an ONNX file can be loaded and executed."""
    try:
        import onnx
        import onnxruntime as ort

        model = onnx.load(str(onnx_path))
        onnx.checker.check_model(model)

        sess = ort.InferenceSession(str(onnx_path))
        inp = sess.get_inputs()[0]
        shape = [d if isinstance(d, int) else 1 for d in inp.shape]
        dummy = np.random.randn(*shape).astype(np.float32)
        outputs = sess.run(None, {inp.name: dummy})

        if outputs is None or len(outputs) == 0:
            return False, "ONNX model produced no outputs"
        logger.info("ONNX validation passed: %s (output shape %s)", onnx_path.name, outputs[0].shape)
        return True, None
    except Exception as exc:
        return False, str(exc)


# ═══════════════════════════════════════════════════════════════════════════
# Individual model trainers
# ═══════════════════════════════════════════════════════════════════════════


def _train_static(
    output_dir: Path,
    *,
    seed: int,
    device: str,
    epochs_override: Optional[int],
) -> ModelResult:
    """Train Cortex-Static (LightGBM on EMBER 2024).

    Uses the memory-mapped ember2024_loader to handle the 45 GB+ dataset
    without exceeding physical RAM.  Subsamples to 2M train / 500K test
    for a 31 GB system.
    """
    result = ModelResult(name="cortex_static")
    model_dir = output_dir / "static"
    model_dir.mkdir(parents=True, exist_ok=True)

    # RAM-safe caps: 2M * 2568 * 4B = ~20.5 GB (leaves headroom for LightGBM)
    MAX_TRAIN = 2_000_000
    MAX_TEST = 500_000

    try:
        from PhantomCortex.training.data.ember2024_loader import load_ember2024
        from PhantomCortex.training.models.static_lgbm import CortexStaticTrainer

        t0 = time.perf_counter()
        logger.info("Loading EMBER 2024 dataset (memmap + subsample)...")

        ember_dir = Path(__file__).resolve().parent.parent / "data" / "raw" / "ember2024_pe"
        if not ember_dir.exists():
            result.error = (
                f"EMBER 2024 data directory not found: {ember_dir}. "
                "Run vectorize_ember2024.py first."
            )
            logger.error(result.error)
            return result

        X_train, y_train, X_test, y_test = load_ember2024(
            data_dir=ember_dir,
            download=False,
            max_train_samples=MAX_TRAIN,
            max_test_samples=MAX_TEST,
            seed=seed,
        )

        n_features = X_train.shape[1]
        logger.info(
            "EMBER 2024 loaded: train=%d test=%d features=%d",
            X_train.shape[0], X_test.shape[0], n_features,
        )

        # Split 10% of training data for validation (early stopping)
        rng = np.random.default_rng(seed)
        n_total = len(y_train)
        n_val = max(1, int(n_total * 0.1))
        val_idx = rng.choice(n_total, size=n_val, replace=False)
        train_idx = np.setdiff1d(np.arange(n_total), val_idx)

        X_val = X_train[val_idx]
        y_val = y_train[val_idx]
        X_train = X_train[train_idx]
        y_train = y_train[train_idx]

        logger.info(
            "Final splits: train=%d val=%d test=%d features=%d",
            X_train.shape[0], X_val.shape[0], X_test.shape[0], n_features,
        )

        trainer = CortexStaticTrainer(
            seed=seed, device="cpu", feature_count=n_features,
        )
        model = trainer.train(
            X_train, y_train, X_val, y_val,
            early_stopping_rounds=epochs_override if epochs_override else 50,
        )
        report = trainer.evaluate(model, X_test, y_test)

        trainer.save_model(model, model_dir / "cortex_static")

        result.metrics = report.to_dict()
        result.training_time_s = time.perf_counter() - t0
        result.success = True
        logger.info(
            "Cortex-Static trained on EMBER 2024: AUC-ROC=%.6f, F1=%.4f (%.1fs)",
            report.auc_roc, report.f1, result.training_time_s,
        )
    except Exception as exc:
        result.error = traceback.format_exc()
        logger.error("Cortex-Static training failed: %s", exc)

    return result


def _train_behavioral(
    output_dir: Path,
    *,
    seed: int,
    device: str,
    epochs_override: Optional[int],
    batch_size: int,
    num_workers: int,
) -> ModelResult:
    """Train Cortex-Behavioral (CNN on synthetic API sequences)."""
    result = ModelResult(name="cortex_behavioral")
    model_dir = output_dir / "behavioral"
    model_dir.mkdir(parents=True, exist_ok=True)

    try:
        from PhantomCortex.training.data.dataset_utils import (
            compute_class_weights,
            create_dataloader,
            split_data,
        )
        from PhantomCortex.training.models.behavioral_cnn import (
            BehaviorCategory,
            CortexBehavioralTrainer,
        )

        t0 = time.perf_counter()
        n_samples = _SYNTH_COUNTS["behavioral"]
        n_classes = len(BehaviorCategory)
        seq_length = 512
        feat_dim = 4

        logger.info("Generating synthetic behavioral data: %d samples...", n_samples)
        rng = np.random.default_rng(seed)

        X = np.zeros((n_samples, seq_length, feat_dim), dtype=np.float32)
        y = np.zeros(n_samples, dtype=np.int64)

        samples_per_class = n_samples // n_classes
        idx = 0
        for cls_id in range(n_classes):
            for _ in range(samples_per_class):
                if idx >= n_samples:
                    break
                api_base = cls_id * 80
                for t in range(seq_length):
                    X[idx, t, 0] = float(rng.integers(api_base, api_base + 100) % 2000)
                    X[idx, t, 1] = float(rng.integers(0, 256))
                    X[idx, t, 2] = float(rng.integers(0, 256))
                    X[idx, t, 3] = float(rng.uniform(0, 100))

                noise_frac = rng.uniform(0.05, 0.15)
                n_noise = int(seq_length * noise_frac)
                noise_idx = rng.choice(seq_length, size=n_noise, replace=False)
                X[idx, noise_idx, 0] = rng.integers(0, 2000, size=n_noise).astype(np.float32)

                y[idx] = cls_id
                idx += 1

        shuffle = rng.permutation(idx)
        X, y = X[shuffle], y[shuffle]

        (X_tr, y_tr), (X_v, y_v), (X_te, y_te) = split_data(X, y, seed=seed)
        class_weights = compute_class_weights(y_tr)
        train_loader = create_dataloader(X_tr, y_tr, batch_size=batch_size, shuffle=True, num_workers=num_workers)
        val_loader = create_dataloader(X_v, y_v, batch_size=batch_size, shuffle=False, num_workers=num_workers)
        test_loader = create_dataloader(X_te, y_te, batch_size=batch_size, shuffle=False, num_workers=num_workers)

        epochs = epochs_override if epochs_override else 100
        trainer = CortexBehavioralTrainer(
            sequence_length=seq_length,
            feature_dim=feat_dim,
            num_classes=n_classes,
            device=device,
            seed=seed,
            log_dir=str(model_dir / "tensorboard"),
        )
        model = trainer.train(
            train_loader, val_loader,
            epochs=epochs,
            checkpoint_dir=str(model_dir / "checkpoints"),
            class_weights=class_weights,
        )
        report = trainer.evaluate(model, test_loader)

        onnx_path = model_dir / "cortex_behavioral.onnx"
        trainer.export_onnx(model, onnx_path, opset=17)

        result.onnx_path = str(onnx_path)
        result.onnx_size_mb = onnx_path.stat().st_size / (1024 * 1024)
        result.metrics = report.to_dict()
        result.training_time_s = time.perf_counter() - t0
        result.success = True

        logger.info(
            "Cortex-Behavioral trained: accuracy=%.4f, macro_f1=%.4f (%.1fs)",
            report.accuracy, report.macro_f1, result.training_time_s,
        )
    except Exception as exc:
        result.error = traceback.format_exc()
        logger.error("Cortex-Behavioral training failed: %s", exc)

    return result


def _train_memory(
    output_dir: Path,
    *,
    seed: int,
    device: str,
    epochs_override: Optional[int],
    batch_size: int,
    num_workers: int,
    dataset_mode: str = "synthetic",
    data_dir: Optional[str] = None,
) -> ModelResult:
    """Train Cortex-Memory (MLP on memory regions).

    dataset_mode:
        "synthetic" — generated class-mean distributions (default)
        "external"  — real CIC-MalMem-2022 + MemMal-D2024 Volatility data
        "hybrid"    — real data augmented with synthetic samples
    """
    result = ModelResult(name="cortex_memory")
    model_dir = output_dir / "memory"
    model_dir.mkdir(parents=True, exist_ok=True)

    try:
        from PhantomCortex.training.data.dataset_utils import (
            compute_class_weights,
            create_dataloader,
            split_data,
        )
        from PhantomCortex.training.models.memory_mlp import (
            CortexMemoryTrainer,
            MemoryRegionClass,
        )

        t0 = time.perf_counter()
        n_classes = len(MemoryRegionClass)
        input_dim = 128

        if dataset_mode in ("external", "hybrid"):
            from PhantomCortex.training.data.memory_external_loader import (
                load_memory_external_dataset,
            )

            raw_dir = data_dir or str(
                Path(__file__).resolve().parent.parent / "data" / "raw"
            )
            X, y, meta = load_memory_external_dataset(
                raw_dir, seed=seed, max_samples_per_class=30_000,
            )
            logger.info(
                "Loaded real-world memory data: %d samples from %s",
                X.shape[0], meta.get("source", "unknown"),
            )

            if dataset_mode == "hybrid":
                # Augment with synthetic for underrepresented classes
                rng = np.random.default_rng(seed)
                class_means = {
                    c: rng.standard_normal(input_dim).astype(np.float32) * 0.5
                    + float(c) for c in range(n_classes)
                }
                for cls in range(n_classes):
                    n_existing = int(np.sum(y == cls))
                    n_needed = max(0, 5000 - n_existing)
                    if n_needed > 0:
                        X_synth = (class_means[cls] +
                                   rng.standard_normal((n_needed, input_dim)).astype(np.float32) * 0.8)
                        y_synth = np.full(n_needed, cls, dtype=np.int64)
                        X = np.concatenate([X, X_synth], axis=0)
                        y = np.concatenate([y, y_synth], axis=0)
                        logger.info("Augmented class %d with %d synthetic samples", cls, n_needed)
        else:
            n_samples = _SYNTH_COUNTS["memory"]
            logger.info("Generating synthetic memory region data: %d samples...", n_samples)
            rng = np.random.default_rng(seed)

            X = np.zeros((n_samples, input_dim), dtype=np.float32)
            y = np.zeros(n_samples, dtype=np.int64)

            class_means = {
                0: rng.standard_normal(input_dim).astype(np.float32) * 0.5,
                1: rng.standard_normal(input_dim).astype(np.float32) * 0.5 + 2.0,
                2: rng.standard_normal(input_dim).astype(np.float32) * 0.5 - 1.5,
                3: rng.standard_normal(input_dim).astype(np.float32) * 0.5 + 1.0,
                4: rng.standard_normal(input_dim).astype(np.float32) * 0.5 - 2.0,
            }

            for i in range(n_samples):
                cls = int(rng.integers(0, n_classes))
                y[i] = cls
                X[i] = class_means[cls] + rng.standard_normal(input_dim).astype(np.float32) * 0.8

                if cls == 3:
                    X[i, -32:] = rng.uniform(7.5, 8.0, size=32).astype(np.float32)
                elif cls == 4:
                    X[i, -32:] = rng.uniform(6.5, 7.8, size=32).astype(np.float32)
                elif cls == 1:
                    X[i, -32:] = rng.uniform(4.0, 6.0, size=32).astype(np.float32)

            shuffle = rng.permutation(n_samples)
            X, y = X[shuffle], y[shuffle]

        (X_tr, y_tr), (X_v, y_v), (X_te, y_te) = split_data(X, y, seed=seed)
        class_weights = compute_class_weights(y_tr)
        train_loader = create_dataloader(X_tr, y_tr, batch_size=batch_size, shuffle=True, num_workers=num_workers)
        val_loader = create_dataloader(X_v, y_v, batch_size=batch_size, shuffle=False, num_workers=num_workers)
        test_loader = create_dataloader(X_te, y_te, batch_size=batch_size, shuffle=False, num_workers=num_workers)

        epochs = epochs_override if epochs_override else 50
        trainer = CortexMemoryTrainer(
            input_dim=input_dim,
            num_classes=n_classes,
            device=device,
            seed=seed,
            log_dir=str(model_dir / "tensorboard"),
        )
        model = trainer.train(
            train_loader, val_loader,
            epochs=epochs,
            checkpoint_dir=str(model_dir / "checkpoints"),
            class_weights=class_weights,
        )
        report = trainer.evaluate(model, test_loader)

        onnx_path = model_dir / "cortex_memory.onnx"
        trainer.export_onnx(model, onnx_path, opset=17)

        result.onnx_path = str(onnx_path)
        result.onnx_size_mb = onnx_path.stat().st_size / (1024 * 1024)
        result.metrics = report.to_dict()
        result.training_time_s = time.perf_counter() - t0
        result.success = True

        logger.info(
            "Cortex-Memory trained: accuracy=%.4f, macro_f1=%.4f (%.1fs)",
            report.accuracy, report.macro_f1, result.training_time_s,
        )
    except Exception as exc:
        result.error = traceback.format_exc()
        logger.error("Cortex-Memory training failed: %s", exc)

    return result


def _train_network(
    output_dir: Path,
    *,
    seed: int,
    device: str,
    epochs_override: Optional[int],
    batch_size: int,
    num_workers: int,
) -> ModelResult:
    """Train Cortex-Network (Autoencoder + Classifier on synthetic flows)."""
    result = ModelResult(name="cortex_network")
    model_dir = output_dir / "network"
    model_dir.mkdir(parents=True, exist_ok=True)

    try:
        from PhantomCortex.training.data.dataset_utils import (
            compute_class_weights,
            create_dataloader,
            split_data,
        )
        from PhantomCortex.training.models.network_ae import (
            CortexNetworkTrainer,
            NetworkThreatClass,
        )

        t0 = time.perf_counter()
        n_samples = _SYNTH_COUNTS["network"]
        n_classes = len(NetworkThreatClass)
        input_dim = 64

        logger.info("Generating synthetic network flow data: %d samples...", n_samples)
        rng = np.random.default_rng(seed)

        X = np.zeros((n_samples, input_dim), dtype=np.float32)
        y = np.zeros(n_samples, dtype=np.int64)

        class_centers = {}
        for cls_id in range(n_classes):
            class_centers[cls_id] = rng.standard_normal(input_dim).astype(np.float32) * 2.0

        n_normal = n_samples // 2
        for i in range(n_samples):
            if i < n_normal:
                cls = 0  # Normal
            else:
                cls = int(rng.integers(1, n_classes))
            y[i] = cls
            X[i] = class_centers[cls] + rng.standard_normal(input_dim).astype(np.float32) * 1.2

            if cls == 1:  # C2 Beacon — periodic timing features
                X[i, :8] = rng.uniform(0.8, 1.2, size=8).astype(np.float32)
            elif cls == 2:  # Exfiltration — large outbound
                X[i, 8:16] = rng.uniform(5.0, 10.0, size=8).astype(np.float32)
            elif cls == 4:  # Scanning — many connections
                X[i, 16:24] = rng.uniform(8.0, 15.0, size=8).astype(np.float32)

        shuffle = rng.permutation(n_samples)
        X, y = X[shuffle], y[shuffle]

        (X_tr, y_tr), (X_v, y_v), (X_te, y_te) = split_data(X, y, seed=seed)
        class_weights = compute_class_weights(y_tr)
        train_loader = create_dataloader(X_tr, y_tr, batch_size=batch_size, shuffle=True, num_workers=num_workers)
        val_loader = create_dataloader(X_v, y_v, batch_size=batch_size, shuffle=False, num_workers=num_workers)
        test_loader = create_dataloader(X_te, y_te, batch_size=batch_size, shuffle=False, num_workers=num_workers)

        epochs = epochs_override if epochs_override else 100
        trainer = CortexNetworkTrainer(
            input_dim=input_dim,
            latent_dim=32,
            num_classes=n_classes,
            device=device,
            seed=seed,
            log_dir=str(model_dir / "tensorboard"),
        )
        model = trainer.train(
            train_loader, val_loader,
            epochs=epochs,
            checkpoint_dir=str(model_dir / "checkpoints"),
            class_weights=class_weights,
        )
        report = trainer.evaluate(model, test_loader)

        onnx_path = model_dir / "cortex_network.onnx"
        trainer.export_onnx(model, onnx_path, opset=17)

        result.onnx_path = str(onnx_path)
        result.onnx_size_mb = onnx_path.stat().st_size / (1024 * 1024)
        result.metrics = report.to_dict()
        result.training_time_s = time.perf_counter() - t0
        result.success = True

        logger.info(
            "Cortex-Network trained: accuracy=%.4f, macro_f1=%.4f (%.1fs)",
            report.accuracy, report.macro_f1, result.training_time_s,
        )
    except Exception as exc:
        result.error = traceback.format_exc()
        logger.error("Cortex-Network training failed: %s", exc)

    return result


def _train_emulation(
    output_dir: Path,
    *,
    seed: int,
    device: str,
    epochs_override: Optional[int],
    batch_size: int,
    num_workers: int,
) -> ModelResult:
    """Train Cortex-Emulation (GRU on synthetic emulation traces)."""
    result = ModelResult(name="cortex_emulation")
    model_dir = output_dir / "emulation"
    model_dir.mkdir(parents=True, exist_ok=True)

    try:
        from PhantomCortex.training.data.dataset_utils import (
            compute_class_weights,
            create_dataloader,
            split_data,
        )
        from PhantomCortex.training.data.emulation_generator import (
            VERDICT_NAMES,
            generate_emulation_dataset,
        )
        from PhantomCortex.training.models.emulation_gru import (
            CortexEmulationTrainer,
            EmulationVerdict,
        )

        t0 = time.perf_counter()
        n_samples = _SYNTH_COUNTS["emulation"]

        logger.info("Generating synthetic emulation trace data: %d samples...", n_samples)
        X, y = generate_emulation_dataset(n_samples=n_samples, seed=seed)

        (X_tr, y_tr), (X_v, y_v), (X_te, y_te) = split_data(X, y, seed=seed)
        class_weights = compute_class_weights(y_tr)
        train_loader = create_dataloader(X_tr, y_tr, batch_size=batch_size, shuffle=True, num_workers=num_workers)
        val_loader = create_dataloader(X_v, y_v, batch_size=batch_size, shuffle=False, num_workers=num_workers)
        test_loader = create_dataloader(X_te, y_te, batch_size=batch_size, shuffle=False, num_workers=num_workers)

        epochs = epochs_override if epochs_override else 80
        trainer = CortexEmulationTrainer(
            sequence_length=1024,
            feature_dim=4,
            hidden_dim=256,
            num_layers=2,
            num_classes=len(EmulationVerdict),
            device=device,
            seed=seed,
            log_dir=str(model_dir / "tensorboard"),
        )
        model = trainer.train(
            train_loader, val_loader,
            epochs=epochs,
            checkpoint_dir=str(model_dir / "checkpoints"),
            class_weights=class_weights,
        )
        report = trainer.evaluate(model, test_loader)

        onnx_path = model_dir / "cortex_emulation.onnx"
        trainer.export_onnx(model, onnx_path, opset=17)

        result.onnx_path = str(onnx_path)
        result.onnx_size_mb = onnx_path.stat().st_size / (1024 * 1024)
        result.metrics = report.to_dict()
        result.training_time_s = time.perf_counter() - t0
        result.success = True

        logger.info(
            "Cortex-Emulation trained: accuracy=%.4f, macro_f1=%.4f (%.1fs)",
            report.accuracy, report.macro_f1, result.training_time_s,
        )
    except Exception as exc:
        result.error = traceback.format_exc()
        logger.error("Cortex-Emulation training failed: %s", exc)

    return result


# ═══════════════════════════════════════════════════════════════════════════
# Dispatcher
# ═══════════════════════════════════════════════════════════════════════════

_TRAINER_MAP = {
    "static": _train_static,
    "behavioral": _train_behavioral,
    "memory": _train_memory,
    "network": _train_network,
    "emulation": _train_emulation,
}


def _print_summary(
    results: list[ModelResult],
    env_info: dict[str, Any],
    total_time: float,
) -> None:
    """Print a formatted summary table to stdout."""
    sep = "=" * 80
    print(f"\n{sep}")
    print("  PhantomCortex Master Training Summary")
    print(sep)
    print(f"  Platform:   {env_info.get('platform', 'N/A')}")
    print(f"  Python:     {env_info.get('python_version', 'N/A')}")
    print(f"  CUDA:       {env_info.get('cuda_device', 'N/A')}")
    print(f"  Total time: {total_time:.1f}s ({total_time / 60:.1f}m)")
    print(sep)

    header = f"  {'Model':<22s} {'Status':<10s} {'Time':>8s}  {'Key Metric':>14s}  {'ONNX MB':>8s}  {'Q-MB':>6s}"
    print(header)
    print("  " + "-" * 76)

    for r in results:
        status = "OK" if r.success else "FAIL"
        time_str = f"{r.training_time_s:.0f}s" if r.training_time_s > 0 else "N/A"

        key_metric = "N/A"
        if r.metrics:
            if "macro_f1" in r.metrics:
                key_metric = f"F1={r.metrics['macro_f1']:.4f}"
            elif "auc_roc" in r.metrics:
                key_metric = f"AUC={r.metrics['auc_roc']:.6f}"
            elif "accuracy" in r.metrics:
                key_metric = f"Acc={r.metrics['accuracy']:.4f}"

        onnx_str = f"{r.onnx_size_mb:.2f}" if r.onnx_size_mb > 0 else "N/A"
        q_str = f"{r.quantized_size_mb:.2f}" if r.quantized_size_mb > 0 else "N/A"

        print(f"  {r.name:<22s} {status:<10s} {time_str:>8s}  {key_metric:>14s}  {onnx_str:>8s}  {q_str:>6s}")

        if r.error and not r.success:
            error_lines = r.error.strip().split("\n")
            last_line = error_lines[-1] if error_lines else "Unknown error"
            print(f"    └─ {last_line[:70]}")

    print(sep)
    n_ok = sum(1 for r in results if r.success)
    n_fail = len(results) - n_ok
    print(f"  {n_ok}/{len(results)} models trained successfully", end="")
    if n_fail > 0:
        print(f" ({n_fail} failed)")
    else:
        print()
    print(sep)


# ═══════════════════════════════════════════════════════════════════════════
# Main orchestration
# ═══════════════════════════════════════════════════════════════════════════


def run_all(
    *,
    output_dir: str,
    models: Optional[list[str]] = None,
    skip_static: bool = False,
    epochs_override: Optional[int] = None,
    batch_size: int = 128,
    device: Optional[str] = None,
    seed: int = DEFAULT_SEED,
    num_workers: int = 0,
    quantize: bool = True,
    validate: bool = True,
    dataset_mode: str = "synthetic",
    data_dir: Optional[str] = None,
) -> dict[str, Any]:
    """Execute the full multi-model training pipeline.

    Parameters
    ----------
    output_dir : str
        Root output directory.
    models : list of str, optional
        Which models to train (default: all). Options: static, behavioral,
        memory, network, emulation.
    skip_static : bool
        Skip Cortex-Static (avoids EMBER download).
    epochs_override : int, optional
        Override default epoch count for all models.
    batch_size : int
        Batch size for all PyTorch models.
    device : str, optional
        PyTorch device (auto-detected if None).
    seed : int
        Global reproducibility seed.
    num_workers : int
        DataLoader workers.
    quantize : bool
        Whether to quantize ONNX models to INT8.
    validate : bool
        Whether to validate ONNX models after export.
    dataset_mode : str
        "synthetic", "external", or "hybrid" — controls data source.
    data_dir : str, optional
        Root directory for external datasets.

    Returns
    -------
    dict with full training summary.
    """
    t_total = time.perf_counter()

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    resolved_device = device or ("cuda" if torch.cuda.is_available() else "cpu")

    # ── Environment check ────────────────────────────────────────────────
    env_info = _check_environment(out)

    # ── Determine which models to train ──────────────────────────────────
    if models is None:
        model_list = list(ALL_MODELS)
    else:
        model_list = [m.lower().strip() for m in models]
        invalid = set(model_list) - set(ALL_MODELS)
        if invalid:
            raise ValueError(f"Unknown model names: {invalid}. Valid: {ALL_MODELS}")

    if skip_static and "static" in model_list:
        model_list.remove("static")
        logger.info("Skipping Cortex-Static (--skip-static)")

    logger.info("Training models: %s", model_list)

    # ── Train each model sequentially ────────────────────────────────────
    results: list[ModelResult] = []

    for model_name in model_list:
        print(f"\n{'─' * 60}")
        print(f"  Training: {model_name.upper()}")
        print(f"{'─' * 60}")

        trainer_fn = _TRAINER_MAP[model_name]

        kwargs: dict[str, Any] = {
            "seed": seed,
            "device": resolved_device,
            "epochs_override": epochs_override,
        }
        if model_name != "static":
            kwargs["batch_size"] = batch_size
            kwargs["num_workers"] = num_workers

        # Pass dataset_mode and data_dir for models that support external data
        if model_name == "memory":
            kwargs["dataset_mode"] = dataset_mode
            kwargs["data_dir"] = data_dir

        model_result = trainer_fn(out, **kwargs)
        results.append(model_result)

        if model_result.success:
            # ── Quantize ─────────────────────────────────────────────
            if quantize and model_result.onnx_path:
                fp32 = Path(model_result.onnx_path)
                int8 = fp32.with_name(fp32.stem + "_int8.onnx")
                ok, size, err = _quantize_onnx(fp32, int8)
                if ok:
                    model_result.quantized_path = str(int8)
                    model_result.quantized_size_mb = size

            # ── Validate ─────────────────────────────────────────────
            if validate and model_result.onnx_path:
                onnx_to_validate = model_result.onnx_path
                ok, err = _validate_onnx(Path(onnx_to_validate))
                if not ok:
                    logger.warning("ONNX validation failed for %s: %s", model_name, err)

                if model_result.quantized_path:
                    ok_q, err_q = _validate_onnx(Path(model_result.quantized_path))
                    if not ok_q:
                        logger.warning(
                            "Quantized ONNX validation failed for %s: %s",
                            model_name, err_q,
                        )

    # ── Summary ──────────────────────────────────────────────────────────
    total_time = time.perf_counter() - t_total

    _print_summary(results, env_info, total_time)

    summary = {
        "environment": env_info,
        "models_requested": model_list,
        "models": [r.to_dict() for r in results],
        "total_time_s": round(total_time, 2),
        "total_time_m": round(total_time / 60, 2),
        "seed": seed,
        "device": resolved_device,
        "success_count": sum(1 for r in results if r.success),
        "failure_count": sum(1 for r in results if not r.success),
    }

    report_path = out / "training_summary.json"
    report_path.write_text(json.dumps(summary, indent=2, default=str))
    logger.info("Summary report saved to %s", report_path)

    return summary


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "PhantomCortex Master Training Orchestrator — train all 5 Cortex "
            "models (Static, Behavioral, Memory, Network, Emulation)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Train all models (skip EMBER download):\n"
            "  python -m PhantomCortex.training.scripts.train_all \\\n"
            "      --output-dir ./output --skip-static\n\n"
            "  # Train only specific models:\n"
            "  python -m PhantomCortex.training.scripts.train_all \\\n"
            "      --output-dir ./output --models behavioral emulation\n\n"
            "  # Quick test run with reduced epochs:\n"
            "  python -m PhantomCortex.training.scripts.train_all \\\n"
            "      --output-dir ./output --skip-static --epochs-override 3"
        ),
    )

    parser.add_argument(
        "--output-dir", type=str, required=True,
        help="Root directory for all training outputs",
    )
    parser.add_argument(
        "--skip-static", action="store_true",
        help="Skip Cortex-Static (avoids ~4GB EMBER download)",
    )
    parser.add_argument(
        "--models", type=str, nargs="+", default=None,
        choices=ALL_MODELS,
        help="Train only these models (default: all)",
    )
    parser.add_argument(
        "--epochs-override", type=int, default=None,
        help="Override epoch count for all models",
    )
    parser.add_argument("--batch-size", type=int, default=128, help="Batch size (default 128)")
    parser.add_argument("--device", type=str, default=None, help="PyTorch device (cpu/cuda)")
    parser.add_argument("--seed", type=int, default=42, help="Global random seed")
    parser.add_argument("--num-workers", type=int, default=0, help="DataLoader workers")
    parser.add_argument("--no-quantize", action="store_true", help="Skip INT8 quantization")
    parser.add_argument("--no-validate", action="store_true", help="Skip ONNX validation")
    parser.add_argument(
        "--dataset-mode", type=str, default="synthetic",
        choices=["synthetic", "external", "hybrid"],
        help="Data source mode: synthetic (default), external (real-world), hybrid (both)",
    )
    parser.add_argument(
        "--data-dir", type=str, default=None,
        help="Root directory for external datasets (default: training/data/raw)",
    )

    args = parser.parse_args()

    Path(args.output_dir).mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(
                Path(args.output_dir) / "train_all.log",
                mode="a",
            ),
        ],
    )

    summary = run_all(
        output_dir=args.output_dir,
        models=args.models,
        skip_static=args.skip_static,
        epochs_override=args.epochs_override,
        batch_size=args.batch_size,
        device=args.device,
        seed=args.seed,
        num_workers=args.num_workers,
        quantize=not args.no_quantize,
        validate=not args.no_validate,
        dataset_mode=args.dataset_mode,
        data_dir=args.data_dir,
    )

    n_fail = summary.get("failure_count", 0)
    if n_fail > 0:
        logger.warning("%d model(s) failed — check training_summary.json for details", n_fail)
        sys.exit(1)


if __name__ == "__main__":
    main()

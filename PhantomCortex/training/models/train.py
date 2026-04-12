"""
PhantomCortex Model Training Bridge
====================================

Pipeline-callable bridge module that invokes each model's training script
programmatically. Called by the pipeline orchestrator at the TRAIN step.

Public API::

    stats = train_models(
        models=["behavioral", "memory", "network", "emulation"],
        data_dir=Path("training/data/datasets"),
        output_dir=Path("training/data/models/staging"),
        full_retrain=True,
    )

Each model's ``run_training()`` is imported directly from its training
script and invoked with the same default hyperparameters as the CLI.
Static (LightGBM) uses a separate code path that goes through
``train_static.main()`` because its pipeline requires EMBER data loading,
Optuna HPO, calibration, and ONNX export steps that are tightly coupled.

Author: ShadowStrike-Labs contact@ShadowStrike.dev
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Optional

import torch

logger = logging.getLogger("PhantomCortex.Training.Bridge")

# ---------------------------------------------------------------------------
# Constants: default hyperparameters matching each training script's CLI
# ---------------------------------------------------------------------------

_BEHAVIORAL_DEFAULTS: dict[str, Any] = {
    "samples_per_class": 5_000,
    "sequence_length": 512,
    "dataset_mode": "hybrid",
    "noise_low": 0.10,
    "noise_high": 0.30,
    "failure_rate": 0.05,
    "epochs": 100,
    "batch_size": 256,
    "learning_rate": 1e-3,
    "weight_decay": 1e-4,
    "embed_dim": 64,
    "grad_clip": 1.0,
    "seed": 42,
    "onnx_opset": 17,
    "num_workers": -1,
}

_MEMORY_DEFAULTS: dict[str, Any] = {
    "samples_per_class": 10_000,
    "epochs": 50,
    "batch_size": 512,
    "learning_rate": 1e-3,
    "weight_decay": 1e-4,
    "grad_clip": 1.0,
    "seed": 42,
    "checkpoint_every": 10,
    "opset": 17,
}

_NETWORK_DEFAULTS: dict[str, Any] = {
    "samples_per_class": 10_000,
    "epochs": 100,
    "batch_size": 256,
    "learning_rate": 1e-3,
    "weight_decay": 1e-4,
    "grad_clip": 1.0,
    "recon_weight": 0.5,
    "latent_dim": 32,
    "seed": 42,
    "checkpoint_every": 10,
    "opset": 17,
}

_EMULATION_DEFAULTS: dict[str, Any] = {
    "n_samples": 60_000,
    "seq_length": 1024,
    "batch_size": 128,
    "epochs": 80,
    "hidden_dim": 256,
    "num_layers": 2,
    "learning_rate": 1e-3,
    "weight_decay": 1e-4,
    "grad_clip": 1.0,
    "seed": 42,
    "num_workers": 0,
    "checkpoint_every": 10,
}

_STATIC_DEFAULTS: dict[str, Any] = {
    "dataset": "ember2024-pe",
    "seed": 42,
    "n_jobs": -1,
    "early_stopping": 50,
    "threshold": 0.5,
    "hpo_trials": 100,
    "hpo_cv_folds": 5,
    "hpo_timeout": 3600,
    "opset": 17,
    "model_name": "cortex_static",
}

# Model name -> expected ONNX output filename
_ONNX_FILENAMES: dict[str, str] = {
    "static": "cortex_static.onnx",
    "behavioral": "cortex_behavioral.onnx",
    "memory": "cortex_memory.onnx",
    "network": "cortex_network.onnx",
    "emulation": "cortex_emulation.onnx",
}

KNOWN_MODELS: frozenset[str] = frozenset(_ONNX_FILENAMES.keys())


# ---------------------------------------------------------------------------
# GPU detection
# ---------------------------------------------------------------------------

def _detect_device() -> str:
    """Return the best available PyTorch device string."""
    if torch.cuda.is_available():
        gpu_name = torch.cuda.get_device_name(0)
        gpu_mem_gb = torch.cuda.get_device_properties(0).total_memory / (1024 ** 3)
        logger.info("GPU detected: %s (%.1f GiB)", gpu_name, gpu_mem_gb)
        return "cuda"
    logger.info("No CUDA GPU detected, falling back to CPU")
    return "cpu"


# ---------------------------------------------------------------------------
# Dataset freshness check (for incremental training)
# ---------------------------------------------------------------------------

def _dataset_has_new_data(model_name: str, data_dir: Path, output_dir: Path) -> bool:
    """Determine whether new training data exists since the last model was built.

    Compares the modification timestamp of the dataset directory against the
    modification timestamp of the ONNX model artifact. If no existing model
    artifact is found, treats the model as requiring training.

    Args:
        model_name: One of the KNOWN_MODELS identifiers.
        data_dir: Root directory containing datasets (may have per-model subdirs).
        output_dir: Directory where trained model artifacts are written.

    Returns:
        True if the model should be retrained, False otherwise.
    """
    onnx_filename = _ONNX_FILENAMES.get(model_name)
    if onnx_filename is None:
        return True

    model_path = output_dir / onnx_filename
    if not model_path.exists():
        logger.info(
            "Model artifact %s not found -- training required", model_path
        )
        return True

    model_mtime = model_path.stat().st_mtime

    # Check dataset directory for any file newer than the model
    dataset_dir = data_dir / model_name
    if not dataset_dir.is_dir():
        dataset_dir = data_dir

    for entry in dataset_dir.rglob("*"):
        if entry.is_file() and entry.stat().st_mtime > model_mtime:
            logger.info(
                "New data detected for %s: %s is newer than model (%.0f > %.0f)",
                model_name,
                entry.name,
                entry.stat().st_mtime,
                model_mtime,
            )
            return True

    logger.info(
        "No new data for %s -- skipping retrain (incremental mode)", model_name
    )
    return False


# ---------------------------------------------------------------------------
# Per-model training dispatchers
# ---------------------------------------------------------------------------

def _train_behavioral(output_dir: Path, data_dir: Path, device: str) -> dict[str, Any]:
    """Train the behavioral 1D-CNN model via its script's run_training()."""
    import argparse
    from PhantomCortex.training.scripts.train_behavioral import run_training

    model_output = str(output_dir / "behavioral")
    defaults = _BEHAVIORAL_DEFAULTS.copy()

    ns = argparse.Namespace(
        output_dir=model_output,
        data_dir=str(data_dir / "behavioral"),
        dataset_mode=defaults["dataset_mode"],
        no_download=False,
        no_cache=False,
        device=device,
        samples_per_class=defaults["samples_per_class"],
        sequence_length=defaults["sequence_length"],
        noise_low=defaults["noise_low"],
        noise_high=defaults["noise_high"],
        failure_rate=defaults["failure_rate"],
        epochs=defaults["epochs"],
        batch_size=defaults["batch_size"],
        learning_rate=defaults["learning_rate"],
        weight_decay=defaults["weight_decay"],
        embed_dim=defaults["embed_dim"],
        grad_clip=defaults["grad_clip"],
        seed=defaults["seed"],
        onnx_opset=defaults["onnx_opset"],
        num_workers=defaults["num_workers"],
        tensorboard=False,
        checkpoints=True,
        checkpoint_every=10,
    )

    t0 = time.monotonic()
    run_training(ns)
    elapsed = time.monotonic() - t0

    # Read metrics produced by the training script
    metrics_path = Path(model_output) / "behavioral_metrics.json"
    metrics: dict[str, Any] = {}
    if metrics_path.exists():
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))

    # Copy ONNX to output_dir root for pipeline consistency
    src_onnx = Path(model_output) / "cortex_behavioral.onnx"
    dst_onnx = output_dir / "cortex_behavioral.onnx"
    if src_onnx.exists() and src_onnx != dst_onnx:
        import shutil
        dst_onnx.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(src_onnx), str(dst_onnx))

    return {
        "model": "behavioral",
        "status": "success",
        "training_time_sec": round(elapsed, 2),
        "accuracy": metrics.get("accuracy", 0.0),
        "macro_f1": metrics.get("macro_f1", 0.0),
        "weighted_f1": metrics.get("weighted_f1", 0.0),
        "onnx_path": str(dst_onnx),
        "device": device,
    }


def _train_memory(output_dir: Path, data_dir: Path, device: str) -> dict[str, Any]:
    """Train the memory MLP model via its script's run_training()."""
    _ = data_dir
    from PhantomCortex.training.scripts.train_memory import run_training

    model_output = str(output_dir / "memory")
    defaults = _MEMORY_DEFAULTS.copy()

    t0 = time.monotonic()
    run_training(
        samples_per_class=defaults["samples_per_class"],
        epochs=defaults["epochs"],
        batch_size=defaults["batch_size"],
        learning_rate=defaults["learning_rate"],
        weight_decay=defaults["weight_decay"],
        grad_clip=defaults["grad_clip"],
        seed=defaults["seed"],
        device=device,
        output_dir=model_output,
        checkpoint_every=defaults["checkpoint_every"],
        opset=defaults["opset"],
    )
    elapsed = time.monotonic() - t0

    metrics_path = Path(model_output) / "metrics.json"
    metrics: dict[str, Any] = {}
    if metrics_path.exists():
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))

    src_onnx = Path(model_output) / "cortex_memory.onnx"
    dst_onnx = output_dir / "cortex_memory.onnx"
    if src_onnx.exists() and src_onnx != dst_onnx:
        import shutil
        dst_onnx.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(src_onnx), str(dst_onnx))

    return {
        "model": "memory",
        "status": "success",
        "training_time_sec": round(elapsed, 2),
        "accuracy": metrics.get("accuracy", 0.0),
        "macro_f1": metrics.get("macro_f1", 0.0),
        "onnx_path": str(dst_onnx),
        "device": device,
    }


def _train_network(output_dir: Path, data_dir: Path, device: str) -> dict[str, Any]:
    """Train the network autoencoder+classifier via its script's run_training()."""
    _ = data_dir
    from PhantomCortex.training.scripts.train_network import run_training

    model_output = str(output_dir / "network")
    defaults = _NETWORK_DEFAULTS.copy()

    t0 = time.monotonic()
    run_training(
        samples_per_class=defaults["samples_per_class"],
        epochs=defaults["epochs"],
        batch_size=defaults["batch_size"],
        learning_rate=defaults["learning_rate"],
        weight_decay=defaults["weight_decay"],
        grad_clip=defaults["grad_clip"],
        recon_weight=defaults["recon_weight"],
        seed=defaults["seed"],
        device=device,
        output_dir=model_output,
        checkpoint_every=defaults["checkpoint_every"],
        opset=defaults["opset"],
        latent_dim=defaults["latent_dim"],
    )
    elapsed = time.monotonic() - t0

    metrics_path = Path(model_output) / "metrics.json"
    metrics: dict[str, Any] = {}
    if metrics_path.exists():
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))

    src_onnx = Path(model_output) / "cortex_network.onnx"
    dst_onnx = output_dir / "cortex_network.onnx"
    if src_onnx.exists() and src_onnx != dst_onnx:
        import shutil
        dst_onnx.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(src_onnx), str(dst_onnx))

    return {
        "model": "network",
        "status": "success",
        "training_time_sec": round(elapsed, 2),
        "accuracy": metrics.get("accuracy", 0.0),
        "macro_f1": metrics.get("macro_f1", 0.0),
        "anomaly_auc": metrics.get("anomaly_auc", 0.0),
        "onnx_path": str(dst_onnx),
        "device": device,
    }


def _train_emulation(output_dir: Path, data_dir: Path, device: str) -> dict[str, Any]:
    """Train the emulation GRU model via its script's run_training()."""
    _ = data_dir
    from PhantomCortex.training.scripts.train_emulation import run_training

    model_output = str(output_dir / "emulation")
    defaults = _EMULATION_DEFAULTS.copy()

    t0 = time.monotonic()
    summary = run_training(
        output_dir=model_output,
        n_samples=defaults["n_samples"],
        seq_length=defaults["seq_length"],
        batch_size=defaults["batch_size"],
        epochs=defaults["epochs"],
        hidden_dim=defaults["hidden_dim"],
        num_layers=defaults["num_layers"],
        learning_rate=defaults["learning_rate"],
        weight_decay=defaults["weight_decay"],
        grad_clip=defaults["grad_clip"],
        device=device,
        seed=defaults["seed"],
        num_workers=defaults["num_workers"],
        checkpoint_every=defaults["checkpoint_every"],
        export_onnx=True,
    )
    elapsed = time.monotonic() - t0

    emu_metrics = summary.get("metrics", {})

    src_onnx = Path(model_output) / "cortex_emulation.onnx"
    dst_onnx = output_dir / "cortex_emulation.onnx"
    if src_onnx.exists() and src_onnx != dst_onnx:
        import shutil
        dst_onnx.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(src_onnx), str(dst_onnx))

    return {
        "model": "emulation",
        "status": "success",
        "training_time_sec": round(elapsed, 2),
        "accuracy": emu_metrics.get("accuracy", 0.0),
        "macro_f1": emu_metrics.get("macro_f1", 0.0),
        "onnx_path": str(dst_onnx),
        "device": device,
    }


def _train_static(output_dir: Path, data_dir: Path) -> dict[str, Any]:
    """Train the static LightGBM model via its script's main().

    The static pipeline is self-contained: it loads EMBER data, runs Optuna
    HPO, trains with early stopping, evaluates, exports ONNX, and quantizes.
    We call ``main()`` with a crafted argv so it writes artifacts into our
    target output directory.
    """
    from PhantomCortex.training.scripts.train_static import main as static_main

    model_output = str(output_dir / "cortex_static")
    defaults = _STATIC_DEFAULTS.copy()

    if defaults["dataset"] == "ember2024-pe":
        data_dir_str = str(data_dir / "ember2024_pe")
    else:
        data_dir_str = str(data_dir / "ember") if (data_dir / "ember").is_dir() else str(data_dir)

    argv = [
        "--output-dir", model_output,
        "--dataset", defaults["dataset"],
        "--data-dir", data_dir_str,
        "--seed", str(defaults["seed"]),
        "--n-jobs", str(defaults["n_jobs"]),
        "--early-stopping", str(defaults["early_stopping"]),
        "--threshold", str(defaults["threshold"]),
        "--hpo-trials", str(defaults["hpo_trials"]),
        "--hpo-cv-folds", str(defaults["hpo_cv_folds"]),
        "--hpo-timeout", str(defaults["hpo_timeout"]),
        "--opset", str(defaults["opset"]),
        "--model-name", defaults["model_name"],
    ]

    t0 = time.monotonic()
    static_main(argv)
    elapsed = time.monotonic() - t0

    # Read metrics saved by the static pipeline
    metrics_path = Path(model_output) / f"{defaults['model_name']}_metrics.json"
    metrics: dict[str, Any] = {}
    if metrics_path.exists():
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))

    test_metrics = metrics.get("test_metrics", {})

    src_onnx = Path(model_output) / f"{defaults['model_name']}.onnx"
    dst_onnx = output_dir / "cortex_static.onnx"
    if src_onnx.exists() and src_onnx != dst_onnx:
        import shutil
        dst_onnx.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(src_onnx), str(dst_onnx))

    return {
        "model": "static",
        "status": "success",
        "training_time_sec": round(elapsed, 2),
        "accuracy": test_metrics.get("accuracy", 0.0),
        "f1": test_metrics.get("f1", 0.0),
        "auc_roc": test_metrics.get("auc_roc", 0.0),
        "detection_rate": test_metrics.get("detection_rate", 0.0),
        "fpr_at_threshold": test_metrics.get("fpr_at_threshold", 0.0),
        "onnx_path": str(dst_onnx),
    }


# ---------------------------------------------------------------------------
# Dispatcher table
# ---------------------------------------------------------------------------

_TRAINERS: dict[str, Any] = {
    "behavioral": _train_behavioral,
    "memory": _train_memory,
    "network": _train_network,
    "emulation": _train_emulation,
    # static handled separately due to different call signature
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def train_models(
    models: list[str],
    data_dir: Path,
    output_dir: Path,
    full_retrain: bool = True,
) -> dict[str, Any]:
    """Train requested models and return per-model statistics.

    This is the entry point called by ``pipeline.py`` at the TRAIN step.

    Args:
        models: List of model identifiers to train. Valid values are
            ``"static"``, ``"behavioral"``, ``"memory"``, ``"network"``,
            ``"emulation"``.
        data_dir: Root directory containing training datasets. For the
            static model this should contain the EMBER dataset (or a
            subdirectory ``ember/``).
        output_dir: Directory where trained model artifacts (ONNX files,
            checkpoints, metrics JSON) are written.
        full_retrain: If True, retrain every requested model regardless
            of dataset freshness. If False, skip models whose datasets
            have not changed since the last training run.

    Returns:
        Dictionary with keys:

        - ``"models"`` -- dict of per-model result dicts, each containing
          ``status``, ``training_time_sec``, ``accuracy``, ``macro_f1``
          (or ``f1``), ``onnx_path``, and ``device``.
        - ``"total_training_time_sec"`` -- wall-clock total.
        - ``"models_trained"`` -- count of models actually trained.
        - ``"models_skipped"`` -- count skipped (incremental mode).
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Validate model names early
    unknown = set(models) - KNOWN_MODELS
    if unknown:
        raise ValueError(
            f"Unknown model identifiers: {sorted(unknown)}. "
            f"Valid models: {sorted(KNOWN_MODELS)}"
        )

    device = _detect_device()

    results: dict[str, dict[str, Any]] = {}
    trained_count = 0
    skipped_count = 0
    pipeline_start = time.monotonic()

    for model_name in models:
        logger.info("=" * 70)
        logger.info("Training model: %s", model_name)
        logger.info("=" * 70)

        # Incremental mode: skip if dataset hasn't changed
        if not full_retrain and not _dataset_has_new_data(model_name, data_dir, output_dir):
            results[model_name] = {
                "model": model_name,
                "status": "skipped",
                "reason": "no_new_data",
            }
            skipped_count += 1
            continue

        try:
            if model_name == "static":
                result = _train_static(output_dir, data_dir)
            else:
                trainer_fn = _TRAINERS[model_name]
                result = trainer_fn(output_dir, data_dir, device)

            results[model_name] = result
            trained_count += 1
            logger.info(
                "Model %s trained successfully in %.1fs (accuracy=%.4f)",
                model_name,
                result.get("training_time_sec", 0.0),
                result.get("accuracy", 0.0),
            )

        except Exception as exc:
            logger.error(
                "Training failed for model %s: %s", model_name, exc, exc_info=True
            )
            results[model_name] = {
                "model": model_name,
                "status": "failed",
                "error": str(exc),
            }

    total_elapsed = time.monotonic() - pipeline_start

    summary: dict[str, Any] = {
        "models": results,
        "total_training_time_sec": round(total_elapsed, 2),
        "models_trained": trained_count,
        "models_skipped": skipped_count,
        "device": device,
    }

    # Persist aggregate summary
    summary_path = output_dir / "training_summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, default=str), encoding="utf-8"
    )
    logger.info(
        "Training complete: %d trained, %d skipped in %.1fs. Summary: %s",
        trained_count,
        skipped_count,
        total_elapsed,
        summary_path,
    )

    return summary

"""
Cortex-Network Training Runner
================================

End-to-end training pipeline for the Cortex-Network autoencoder + classifier:
    1. Generate synthetic network flow data via network_generator
    2. Train CortexNetworkTrainer (autoencoder + classifier, joint loss)
    3. Evaluate on held-out test set
    4. Export best model to ONNX
    5. Save metrics report

Usage:
    python -m PhantomCortex.training.scripts.train_network
    python -m PhantomCortex.training.scripts.train_network --epochs 200 --gpu
    python -m PhantomCortex.training.scripts.train_network \\
        --samples-per-class 20000 --batch-size 512 --output-dir ./runs/network
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Optional

import numpy as np
import torch

from PhantomCortex.training.data.network_generator import (
    CLASS_NAMES,
    FEATURE_DIM,
    NUM_CLASSES,
    generate_network_dataset,
)
from PhantomCortex.training.data.unsw_nb15_loader import (
    load_unsw_nb15,
)
from PhantomCortex.training.data.dataset_utils import (
    compute_class_weights,
    create_dataloader,
    split_data,
)
from PhantomCortex.training.models.network_ae import CortexNetworkTrainer

logger = logging.getLogger("PhantomCortex.Scripts.TrainNetwork")


# ---------------------------------------------------------------------------
# Device detection
# ---------------------------------------------------------------------------


def _resolve_device(prefer_gpu: bool) -> str:
    """Detect best available device.

    Args:
        prefer_gpu: Whether to prefer GPU when available.

    Returns:
        Device string for PyTorch.
    """
    if prefer_gpu and torch.cuda.is_available():
        dev = "cuda"
        gpu_name = torch.cuda.get_device_name(0)
        gpu_mem = torch.cuda.get_device_properties(0).total_memory / (1024 ** 3)
        logger.info("GPU detected: %s (%.1f GB)", gpu_name, gpu_mem)
    else:
        dev = "cpu"
        if prefer_gpu:
            logger.warning("GPU requested but CUDA not available — falling back to CPU")
        else:
            logger.info("Using CPU (use --gpu to enable GPU)")
    return dev


# ---------------------------------------------------------------------------
# Training pipeline
# ---------------------------------------------------------------------------


def run_training(
    *,
    samples_per_class: int,
    epochs: int,
    batch_size: int,
    learning_rate: float,
    weight_decay: float,
    grad_clip: float,
    recon_weight: float,
    seed: int,
    device: str,
    output_dir: str,
    checkpoint_every: int,
    opset: int,
    latent_dim: int,
    dataset_mode: str = "real",
    unsw_data_dir: str | None = None,
    ae_pretrain_epochs: int = 50,
) -> None:
    """Execute the full Cortex-Network training pipeline.

    Args:
        samples_per_class: Samples per class for synthetic data.
        epochs: Maximum training epochs.
        batch_size: Training batch size.
        learning_rate: Peak learning rate.
        weight_decay: AdamW weight decay.
        grad_clip: Gradient clipping norm.
        recon_weight: Weight for reconstruction loss relative to classification.
        seed: Random seed for reproducibility.
        device: PyTorch device string.
        output_dir: Root output directory.
        checkpoint_every: Checkpoint save frequency (epochs).
        opset: ONNX opset version.
        latent_dim: Autoencoder latent dimension.
    """
    run_start = time.monotonic()
    out_path = Path(output_dir)
    checkpoint_dir = out_path / "checkpoints"
    onnx_path = out_path / "cortex_network.onnx"
    metrics_path = out_path / "metrics.json"
    log_dir = str(out_path / "tensorboard")

    out_path.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 70)
    logger.info("Cortex-Network Training Pipeline")
    logger.info("=" * 70)

    # ---- Step 1: Load data ----
    if dataset_mode == "real":
        logger.info("[1/4] Loading UNSW-NB15 real network data...")
        data_start = time.monotonic()
        X, y, unsw_meta = load_unsw_nb15(
            data_dir=unsw_data_dir,
            seed=seed,
            max_samples=500_000,
            input_dim=FEATURE_DIM,
        )
        data_elapsed = time.monotonic() - data_start
        logger.info(
            "  UNSW-NB15: %d samples, %d features in %.2fs",
            X.shape[0], X.shape[1], data_elapsed,
        )
        logger.info("  Class distribution: %s", unsw_meta.get("class_distribution", ""))

        (X_train, y_train), (X_val, y_val), (X_test, y_test) = split_data(X, y, seed=seed)
        train_loader = create_dataloader(
            X_train, y_train, batch_size=batch_size, shuffle=True, num_workers=0,
        )
        val_loader = create_dataloader(
            X_val, y_val, batch_size=batch_size, shuffle=False, num_workers=0,
        )
        test_loader = create_dataloader(
            X_test, y_test, batch_size=batch_size, shuffle=False, num_workers=0,
        )
    elif dataset_mode == "hybrid":
        logger.info("[1/4] Loading UNSW-NB15 + synthetic augmentation...")
        data_start = time.monotonic()
        X_real, y_real, unsw_meta = load_unsw_nb15(
            data_dir=unsw_data_dir,
            seed=seed,
            max_samples=500_000,
            input_dim=FEATURE_DIM,
        )
        logger.info("  UNSW-NB15 real: %d samples", X_real.shape[0])

        split_syn = generate_network_dataset(
            samples_per_class=samples_per_class,
            seed=seed,
            batch_size=batch_size,
            output_dir=str(out_path / "data"),
        )
        X_syn = np.concatenate([split_syn.X_train, split_syn.X_val, split_syn.X_test])
        y_syn = np.concatenate([split_syn.y_train, split_syn.y_val, split_syn.y_test])
        logger.info("  Synthetic: %d samples", y_syn.shape[0])

        X = np.concatenate((X_real, X_syn), axis=0)
        y = np.concatenate((y_real, y_syn), axis=0)
        data_elapsed = time.monotonic() - data_start
        logger.info("  Hybrid: %d total in %.2fs", y.shape[0], data_elapsed)

        (X_train, y_train), (X_val, y_val), (X_test, y_test) = split_data(X, y, seed=seed)
        train_loader = create_dataloader(
            X_train, y_train, batch_size=batch_size, shuffle=True, num_workers=0,
        )
        val_loader = create_dataloader(
            X_val, y_val, batch_size=batch_size, shuffle=False, num_workers=0,
        )
        test_loader = create_dataloader(
            X_test, y_test, batch_size=batch_size, shuffle=False, num_workers=0,
        )
    else:
        logger.info("[1/4] Generating synthetic network flow data...")
        data_start = time.monotonic()
        split = generate_network_dataset(
            samples_per_class=samples_per_class,
            seed=seed,
            batch_size=batch_size,
            output_dir=str(out_path / "data"),
        )
        data_elapsed = time.monotonic() - data_start
        logger.info(
            "  Data generated in %.2fs: train=%d val=%d test=%d",
            data_elapsed,
            len(split.X_train),
            len(split.X_val),
            len(split.X_test),
        )
        train_loader = split.train_loader
        val_loader = split.val_loader
        test_loader = split.test_loader

    # ---- Step 2: Train ----
    logger.info("[2/4] Training CortexNetworkNet (autoencoder + classifier)...")

    trainer = CortexNetworkTrainer(
        input_dim=FEATURE_DIM,
        latent_dim=latent_dim,
        num_classes=NUM_CLASSES,
        learning_rate=learning_rate,
        weight_decay=weight_decay,
        device=device,
        seed=seed,
        log_dir=log_dir,
    )

    train_start = time.monotonic()
    model = trainer.train(
        train_loader,
        val_loader,
        epochs=epochs,
        grad_clip=grad_clip,
        recon_weight=recon_weight,
        checkpoint_dir=str(checkpoint_dir),
        checkpoint_every=checkpoint_every,
    )
    train_elapsed = time.monotonic() - train_start

    logger.info("  Training completed in %.2fs", train_elapsed)

    # ---- Step 3: Evaluate ----
    logger.info("[3/4] Evaluating on test set...")

    eval_start = time.monotonic()
    report = trainer.evaluate(model, test_loader)
    eval_elapsed = time.monotonic() - eval_start

    logger.info("  Evaluation completed in %.2fs", eval_elapsed)
    logger.info("  Test accuracy:          %.4f", report.accuracy)
    logger.info("  Test macro-F1:          %.4f", report.macro_f1)
    logger.info("  Reconstruction loss:    %.6f", report.reconstruction_loss)
    logger.info("  Classification loss:    %.6f", report.classification_loss)
    logger.info("  Anomaly AUC:            %.4f", report.anomaly_auc)

    for cls_name in CLASS_NAMES:
        f1 = report.per_class_f1.get(cls_name, 0.0)
        prec = report.per_class_precision.get(cls_name, 0.0)
        rec = report.per_class_recall.get(cls_name, 0.0)
        logger.info(
            "    %s: F1=%.4f Prec=%.4f Rec=%.4f",
            cls_name,
            f1,
            prec,
            rec,
        )

    logger.info("  Confusion matrix:\n%s", report.confusion_matrix)

    # ---- Step 4: Export ----
    logger.info("[4/4] Exporting to ONNX...")

    trainer.export_onnx(model, onnx_path, opset=opset)

    total_elapsed = time.monotonic() - run_start

    # ---- Save metrics ----
    metrics = {
        **report.to_dict(),
        "training_config": {
            "samples_per_class": samples_per_class,
            "total_samples": samples_per_class * NUM_CLASSES,
            "epochs": epochs,
            "batch_size": batch_size,
            "learning_rate": learning_rate,
            "weight_decay": weight_decay,
            "grad_clip": grad_clip,
            "recon_weight": recon_weight,
            "latent_dim": latent_dim,
            "seed": seed,
            "device": device,
            "feature_dim": FEATURE_DIM,
            "num_classes": NUM_CLASSES,
            "class_names": CLASS_NAMES,
        },
        "timing": {
            "data_generation_sec": round(data_elapsed, 3),
            "training_sec": round(train_elapsed, 3),
            "evaluation_sec": round(eval_elapsed, 3),
            "total_sec": round(total_elapsed, 3),
        },
        "artifacts": {
            "onnx_model": str(onnx_path),
            "checkpoint_dir": str(checkpoint_dir),
            "tensorboard_dir": log_dir,
        },
    }

    metrics_path.write_text(json.dumps(metrics, indent=2, default=str), encoding="utf-8")
    logger.info("Metrics saved to %s", metrics_path)

    logger.info("=" * 70)
    logger.info("Pipeline complete in %.2fs", total_elapsed)
    logger.info("  ONNX model:   %s", onnx_path)
    logger.info("  Metrics:      %s", metrics_path)
    logger.info("  Checkpoints:  %s", checkpoint_dir)
    logger.info("  TensorBoard:  %s", log_dir)
    logger.info("=" * 70)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Train Cortex-Network autoencoder+classifier on synthetic network data",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--samples-per-class",
        type=int,
        default=10_000,
        help="Synthetic samples per class (used in synthetic/hybrid modes)",
    )
    parser.add_argument(
        "--dataset-mode",
        type=str,
        default="real",
        choices=("synthetic", "real", "hybrid"),
        help="Data source: 'real' uses UNSW-NB15, 'hybrid' adds synthetic augmentation.",
    )
    parser.add_argument(
        "--unsw-data-dir",
        type=str,
        default=None,
        help="UNSW-NB15 dataset directory (auto-detected if omitted).",
    )
    parser.add_argument(
        "--ae-pretrain-epochs",
        type=int,
        default=50,
        help="Autoencoder pretraining epochs on Normal traffic only.",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=200,
        help="Maximum training epochs",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=512,
        help="Training batch size",
    )
    parser.add_argument(
        "--learning-rate",
        type=float,
        default=5e-4,
        help="Peak learning rate",
    )
    parser.add_argument(
        "--weight-decay",
        type=float,
        default=1e-4,
        help="AdamW weight decay",
    )
    parser.add_argument(
        "--grad-clip",
        type=float,
        default=1.0,
        help="Gradient clipping max norm",
    )
    parser.add_argument(
        "--recon-weight",
        type=float,
        default=0.7,
        help="Reconstruction loss weight (classification weight is 1.0)",
    )
    parser.add_argument(
        "--latent-dim",
        type=int,
        default=32,
        help="Autoencoder latent dimension",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility",
    )
    parser.add_argument(
        "--gpu",
        action="store_true",
        default=False,
        help="Use GPU if available",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="runs/cortex_network",
        help="Output directory for model, metrics, checkpoints",
    )
    parser.add_argument(
        "--checkpoint-every",
        type=int,
        default=10,
        help="Save checkpoint every N epochs",
    )
    parser.add_argument(
        "--opset",
        type=int,
        default=17,
        help="ONNX opset version for export",
    )
    return parser


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    args = _build_parser().parse_args()
    device = _resolve_device(args.gpu)

    run_training(
        samples_per_class=args.samples_per_class,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        weight_decay=args.weight_decay,
        grad_clip=args.grad_clip,
        recon_weight=args.recon_weight,
        seed=args.seed,
        device=device,
        output_dir=args.output_dir,
        checkpoint_every=args.checkpoint_every,
        opset=args.opset,
        latent_dim=args.latent_dim,
        dataset_mode=args.dataset_mode,
        unsw_data_dir=args.unsw_data_dir,
        ae_pretrain_epochs=args.ae_pretrain_epochs,
    )


if __name__ == "__main__":
    main()

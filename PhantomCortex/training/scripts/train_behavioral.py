#!/usr/bin/env python3
"""
Cortex-Behavioral Training Runner
==================================

End-to-end training pipeline for the behavioural 1D-CNN malware classifier.

Workflow:
    1. Generate synthetic API-call-sequence data via ``BehavioralDataGenerator``.
    2. Instantiate ``CortexBehavioralTrainer`` and train the model.
    3. Evaluate on the held-out test set.
    4. Export to ONNX (opset 17) for C++ inference deployment.
    5. Persist metrics as JSON.

Usage
-----
::

    python -m PhantomCortex.training.scripts.train_behavioral \\
        --epochs 100 --batch-size 256 --samples-per-class 5000 \\
        --output-dir ./output/behavioral

All flags are optional — sensible defaults mirror ``training.yaml``.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

import torch

# ---------------------------------------------------------------------------
# Ensure the PhantomCortex package is importable when the script is invoked
# directly from the ``scripts/`` directory.
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
_TRAINING_DIR = _SCRIPT_DIR.parent
_CORTEX_DIR = _TRAINING_DIR.parent
_REPO_DIR = _CORTEX_DIR.parent
for _p in (_REPO_DIR, _CORTEX_DIR):
    _p_str = str(_p)
    if _p_str not in sys.path:
        sys.path.insert(0, _p_str)

from PhantomCortex.training.data.behavioral_generator import (  # noqa: E402
    BehavioralDataGenerator,
    GeneratorConfig,
)
from PhantomCortex.training.models.behavioral_cnn import (  # noqa: E402
    BehaviorCategory,
    CortexBehavioralTrainer,
    MetricsReport,
)

logger = logging.getLogger("PhantomCortex.Training.BehavioralRunner")


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _configure_logging(*, verbose: bool, log_file: Path | None) -> None:
    """Set up structured logging to stderr (and optionally a file)."""
    fmt = (
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    datefmt = "%Y-%m-%dT%H:%M:%S"
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(str(log_file), encoding="utf-8"))

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format=fmt,
        datefmt=datefmt,
        handlers=handlers,
        force=True,
    )


# ---------------------------------------------------------------------------
# Metrics persistence
# ---------------------------------------------------------------------------

def _save_metrics(report: MetricsReport, output_dir: Path) -> Path:
    """Serialise a MetricsReport to JSON and write to *output_dir*."""
    output_dir.mkdir(parents=True, exist_ok=True)
    metrics_path = output_dir / "behavioral_metrics.json"

    payload = report.to_dict()

    # Augment with human-readable class names for every per-class dict.
    for section_key in ("per_class_precision", "per_class_recall", "per_class_f1"):
        section = payload.get(section_key)
        if isinstance(section, dict):
            readable: dict[str, float] = {}
            for cls_name, val in section.items():
                readable[cls_name] = round(val, 6)
            payload[section_key] = readable

    metrics_path.write_text(
        json.dumps(payload, indent=2, default=str),
        encoding="utf-8",
    )
    logger.info("Metrics saved to %s", metrics_path)
    return metrics_path


# ---------------------------------------------------------------------------
# Main training orchestration
# ---------------------------------------------------------------------------

def run_training(args: argparse.Namespace) -> None:
    """Execute the full training pipeline."""
    wall_start = time.monotonic()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Device selection ─────────────────────────────────────────────
    if args.device is not None:
        device = args.device
    elif torch.cuda.is_available():
        device = "cuda"
    else:
        device = "cpu"
    logger.info("Device: %s", device)

    if device == "cuda":
        gpu_name = torch.cuda.get_device_name(0)
        gpu_mem = torch.cuda.get_device_properties(0).total_mem / (1024 ** 3)
        logger.info("GPU: %s (%.1f GiB)", gpu_name, gpu_mem)

    # ── Data generation ──────────────────────────────────────────────
    logger.info("=== Phase 1: Synthetic data generation ===")
    gen_cfg = GeneratorConfig(
        samples_per_class=args.samples_per_class,
        sequence_length=args.sequence_length,
        noise_ratio_low=args.noise_low,
        noise_ratio_high=args.noise_high,
        failure_rate=args.failure_rate,
        batch_size=args.batch_size,
        seed=args.seed,
        num_workers=args.num_workers,
    )
    generator = BehavioralDataGenerator(gen_cfg)
    train_loader, val_loader, test_loader, class_weights = (
        generator.generate_dataloaders()
    )
    logger.info(
        "Data ready — train batches=%d  val batches=%d  test batches=%d",
        len(train_loader),
        len(val_loader),
        len(test_loader),
    )

    # ── Trainer initialisation ───────────────────────────────────────
    logger.info("=== Phase 2: Model training ===")
    tensorboard_dir = str(output_dir / "tensorboard") if args.tensorboard else None
    checkpoint_dir = str(output_dir / "checkpoints") if args.checkpoints else None

    trainer = CortexBehavioralTrainer(
        sequence_length=args.sequence_length,
        feature_dim=4,
        embed_dim=args.embed_dim,
        num_classes=len(BehaviorCategory),
        learning_rate=args.learning_rate,
        weight_decay=args.weight_decay,
        device=device,
        seed=args.seed,
        log_dir=tensorboard_dir,
    )

    model = trainer.train(
        train_loader,
        val_loader,
        epochs=args.epochs,
        grad_clip=args.grad_clip,
        checkpoint_dir=checkpoint_dir,
        checkpoint_every=args.checkpoint_every,
        class_weights=class_weights,
    )

    # ── Evaluation ───────────────────────────────────────────────────
    logger.info("=== Phase 3: Test-set evaluation ===")
    report = trainer.evaluate(model, test_loader)

    logger.info(
        "Test results — loss=%.4f  acc=%.4f  macro_f1=%.4f  weighted_f1=%.4f",
        report.loss,
        report.accuracy,
        report.macro_f1,
        report.weighted_f1,
    )
    for cls_id in range(len(BehaviorCategory)):
        cls_name = BehaviorCategory(cls_id).name
        prec = report.per_class_precision.get(cls_name, 0.0)
        rec = report.per_class_recall.get(cls_name, 0.0)
        f1 = report.per_class_f1.get(cls_name, 0.0)
        logger.info(
            "  [%2d] %-20s  P=%.4f  R=%.4f  F1=%.4f",
            cls_id,
            cls_name,
            prec,
            rec,
            f1,
        )

    # ── Save metrics ─────────────────────────────────────────────────
    metrics_path = _save_metrics(report, output_dir)

    # ── ONNX export ──────────────────────────────────────────────────
    logger.info("=== Phase 4: ONNX export ===")
    onnx_path = output_dir / "cortex_behavioral.onnx"
    trainer.export_onnx(model, onnx_path, opset=args.onnx_opset)
    logger.info("ONNX model exported to %s", onnx_path)

    # ── Summary ──────────────────────────────────────────────────────
    wall_elapsed = time.monotonic() - wall_start
    logger.info(
        "=== Training complete ===  wall_time=%.1fs  metrics=%s  onnx=%s",
        wall_elapsed,
        metrics_path,
        onnx_path,
    )


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    p = argparse.ArgumentParser(
        description=(
            "Train the CortexBehavioral 1D-CNN malware classifier on "
            "synthetic API-call-sequence data."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Data generation
    data = p.add_argument_group("data generation")
    data.add_argument(
        "--samples-per-class",
        type=int,
        default=5_000,
        help="Samples per behavioural category.",
    )
    data.add_argument(
        "--sequence-length",
        type=int,
        default=512,
        help="API calls per sample.",
    )
    data.add_argument(
        "--noise-low",
        type=float,
        default=0.10,
        help="Minimum benign noise ratio.",
    )
    data.add_argument(
        "--noise-high",
        type=float,
        default=0.30,
        help="Maximum benign noise ratio.",
    )
    data.add_argument(
        "--failure-rate",
        type=float,
        default=0.05,
        help="Probability of injecting API error return codes.",
    )

    # Training
    train = p.add_argument_group("training")
    train.add_argument("--epochs", type=int, default=100)
    train.add_argument("--batch-size", type=int, default=256)
    train.add_argument("--learning-rate", type=float, default=1e-3)
    train.add_argument("--weight-decay", type=float, default=1e-4)
    train.add_argument("--embed-dim", type=int, default=64)
    train.add_argument("--grad-clip", type=float, default=1.0)
    train.add_argument("--seed", type=int, default=42)
    train.add_argument(
        "--device",
        type=str,
        default=None,
        help="Force device (cpu / cuda / cuda:0). Auto-detect if omitted.",
    )

    # Checkpointing
    ckpt = p.add_argument_group("checkpointing")
    ckpt.add_argument(
        "--checkpoints",
        action="store_true",
        default=False,
        help="Enable periodic checkpoint saving.",
    )
    ckpt.add_argument(
        "--checkpoint-every",
        type=int,
        default=10,
        help="Save checkpoint every N epochs.",
    )

    # Export
    export = p.add_argument_group("export")
    export.add_argument("--onnx-opset", type=int, default=17)

    # Output
    out = p.add_argument_group("output")
    out.add_argument(
        "--output-dir",
        type=str,
        default="./output/behavioral",
        help="Directory for model, metrics, and logs.",
    )
    out.add_argument(
        "--tensorboard",
        action="store_true",
        default=False,
        help="Enable TensorBoard logging.",
    )
    out.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Optional log file path.",
    )
    out.add_argument(
        "--num-workers",
        type=int,
        default=0,
        help="DataLoader worker processes.",
    )
    out.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable DEBUG-level logging.",
    )

    return p


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Parse CLI arguments and launch the training pipeline."""
    parser = build_parser()
    args = parser.parse_args()

    log_file = Path(args.log_file) if args.log_file else None
    _configure_logging(verbose=args.verbose, log_file=log_file)

    logger.info("CortexBehavioral training runner — ShadowStrike NGAV")
    logger.info("Arguments: %s", vars(args))

    try:
        run_training(args)
    except KeyboardInterrupt:
        logger.warning("Training interrupted by user")
        sys.exit(130)
    except Exception:
        logger.exception("Training failed with unhandled exception")
        sys.exit(1)


if __name__ == "__main__":
    main()

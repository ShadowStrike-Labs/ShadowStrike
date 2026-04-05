"""
Training Runner for Cortex-Emulation GRU Model
================================================

End-to-end training pipeline:
    1. Generate synthetic emulation trace data (or load from disk)
    2. Compute class weights for imbalanced dataset
    3. Train CortexEmulationTrainer (bidirectional GRU with attention)
    4. Evaluate on held-out test set
    5. Export trained model to ONNX

Usage::

    python -m PhantomCortex.training.scripts.train_emulation \\
        --output-dir ./output/emulation \\
        --epochs 80 --batch-size 128 --seed 42

    # Load pre-generated data instead of regenerating:
    python -m PhantomCortex.training.scripts.train_emulation \\
        --dataset-path ./data/emulation_dataset.npz \\
        --output-dir ./output/emulation
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

from PhantomCortex.training.data.dataset_utils import (
    compute_class_weights,
    create_dataloader,
    load_dataset,
    print_dataset_stats,
    save_dataset,
    split_data,
)
from PhantomCortex.training.data.emulation_generator import (
    VERDICT_NAMES,
    generate_emulation_dataset,
    get_emulation_dataloaders,
)
from PhantomCortex.training.models.emulation_gru import (
    CortexEmulationTrainer,
    EmulationVerdict,
    MetricsReport,
)

logger = logging.getLogger("PhantomCortex.Scripts.TrainEmulation")


# ---------------------------------------------------------------------------
# Main training routine
# ---------------------------------------------------------------------------


def run_training(
    *,
    output_dir: str,
    dataset_path: Optional[str] = None,
    n_samples: int = 60000,
    n_benign: Optional[int] = None,
    n_suspicious: Optional[int] = None,
    n_malicious: Optional[int] = None,
    seq_length: int = 1024,
    batch_size: int = 128,
    epochs: int = 80,
    hidden_dim: int = 256,
    num_layers: int = 2,
    learning_rate: float = 1e-3,
    weight_decay: float = 1e-4,
    grad_clip: float = 1.0,
    device: Optional[str] = None,
    seed: int = 42,
    num_workers: int = 0,
    checkpoint_every: int = 10,
    save_data: bool = False,
    export_onnx: bool = True,
) -> dict:
    """Execute the full Cortex-Emulation training pipeline.

    Parameters
    ----------
    output_dir : str
        Root output directory for checkpoints, models, and reports.
    dataset_path : str, optional
        Path to a pre-saved ``.npz`` dataset. If None, synthetic data
        is generated on the fly.
    n_samples : int
        Total number of synthetic samples (used when ``dataset_path`` is None).
    n_benign, n_suspicious, n_malicious : int, optional
        Per-class sample count overrides.
    seq_length : int
        Events per emulation trace (default 1024).
    batch_size : int
        Training batch size.
    epochs : int
        Maximum training epochs.
    hidden_dim : int
        GRU hidden dimension.
    num_layers : int
        GRU layers.
    learning_rate : float
        Initial learning rate.
    weight_decay : float
        AdamW weight decay.
    grad_clip : float
        Gradient clipping max norm.
    device : str, optional
        PyTorch device string (auto-detected if None).
    seed : int
        Global reproducibility seed.
    num_workers : int
        DataLoader workers.
    checkpoint_every : int
        Checkpoint frequency in epochs.
    save_data : bool
        Whether to persist the generated dataset.
    export_onnx : bool
        Whether to export the trained model to ONNX.

    Returns
    -------
    dict with training summary (metrics, paths, timing).
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    ckpt_dir = out / "checkpoints"
    ckpt_dir.mkdir(parents=True, exist_ok=True)
    log_dir = str(out / "tensorboard")

    summary: dict = {
        "model": "cortex_emulation",
        "seed": seed,
        "device": device or ("cuda" if torch.cuda.is_available() else "cpu"),
    }

    t_total = time.perf_counter()

    # ── 1. Data ──────────────────────────────────────────────────────────
    if dataset_path is not None:
        logger.info("Loading dataset from %s", dataset_path)
        X_tr, y_tr, X_val, y_val, X_te, y_te = load_dataset(dataset_path)
    else:
        logger.info("Generating synthetic emulation data...")
        t_gen = time.perf_counter()
        X, y = generate_emulation_dataset(
            n_samples=n_samples,
            seq_length=seq_length,
            seed=seed,
            n_benign=n_benign,
            n_suspicious=n_suspicious,
            n_malicious=n_malicious,
        )
        gen_time = time.perf_counter() - t_gen
        logger.info("Data generation completed in %.1fs", gen_time)
        summary["data_generation_time_s"] = round(gen_time, 2)

        (X_tr, y_tr), (X_val, y_val), (X_te, y_te) = split_data(X, y, seed=seed)

        if save_data:
            data_path = out / "emulation_dataset.npz"
            save_dataset(data_path, X_tr, y_tr, X_val, y_val, X_te, y_te)
            summary["dataset_path"] = str(data_path)

    # Dataset statistics
    y_all = np.concatenate([y_tr, y_val, y_te])
    print("\n=== Emulation Dataset Statistics ===")
    print_dataset_stats(y_all, VERDICT_NAMES)
    summary["train_samples"] = int(y_tr.shape[0])
    summary["val_samples"] = int(y_val.shape[0])
    summary["test_samples"] = int(y_te.shape[0])

    # ── 2. DataLoaders ───────────────────────────────────────────────────
    train_loader = create_dataloader(
        X_tr, y_tr, batch_size=batch_size, shuffle=True, num_workers=num_workers,
    )
    val_loader = create_dataloader(
        X_val, y_val, batch_size=batch_size, shuffle=False, num_workers=num_workers,
    )
    test_loader = create_dataloader(
        X_te, y_te, batch_size=batch_size, shuffle=False, num_workers=num_workers,
    )

    # ── 3. Class weights ─────────────────────────────────────────────────
    class_weights = compute_class_weights(y_tr)
    logger.info("Class weights: %s", class_weights.tolist())

    # ── 4. Train ─────────────────────────────────────────────────────────
    trainer = CortexEmulationTrainer(
        sequence_length=seq_length,
        feature_dim=4,
        hidden_dim=hidden_dim,
        num_layers=num_layers,
        num_classes=len(EmulationVerdict),
        learning_rate=learning_rate,
        weight_decay=weight_decay,
        device=device,
        seed=seed,
        log_dir=log_dir,
    )

    logger.info("Starting training: %d epochs, batch_size=%d", epochs, batch_size)
    t_train = time.perf_counter()
    model = trainer.train(
        train_loader,
        val_loader,
        epochs=epochs,
        grad_clip=grad_clip,
        checkpoint_dir=str(ckpt_dir),
        checkpoint_every=checkpoint_every,
        class_weights=class_weights,
    )
    train_time = time.perf_counter() - t_train
    logger.info("Training completed in %.1fs", train_time)
    summary["training_time_s"] = round(train_time, 2)

    # ── 5. Evaluate ──────────────────────────────────────────────────────
    logger.info("Evaluating on test set...")
    report: MetricsReport = trainer.evaluate(model, test_loader)

    print("\n=== Cortex-Emulation Test Results ===")
    print(f"  Loss:     {report.loss:.6f}")
    print(f"  Accuracy: {report.accuracy:.4f}")
    print(f"  Macro F1: {report.macro_f1:.4f}")
    print(f"\n  Per-class Precision: {report.per_class_precision}")
    print(f"  Per-class Recall:    {report.per_class_recall}")
    print(f"  Per-class F1:        {report.per_class_f1}")
    print(f"\n  Confusion Matrix:\n{report.confusion_matrix}")

    summary["metrics"] = report.to_dict()

    # ── 6. Export ────────────────────────────────────────────────────────
    if export_onnx:
        onnx_path = out / "cortex_emulation.onnx"
        logger.info("Exporting to ONNX: %s", onnx_path)
        trainer.export_onnx(model, onnx_path, opset=17)
        summary["onnx_path"] = str(onnx_path)
        summary["onnx_size_mb"] = round(onnx_path.stat().st_size / (1024 * 1024), 4)

    # ── 7. Save model state ──────────────────────────────────────────────
    state_path = out / "cortex_emulation_best.pt"
    torch.save(model.state_dict(), state_path)
    summary["model_state_path"] = str(state_path)

    # ── 8. Summary ───────────────────────────────────────────────────────
    total_time = time.perf_counter() - t_total
    summary["total_time_s"] = round(total_time, 2)

    report_path = out / "training_report.json"
    report_path.write_text(json.dumps(summary, indent=2, default=str))
    logger.info("Training report saved to %s", report_path)

    print(f"\n=== Training Complete ===")
    print(f"  Total time:  {total_time:.1f}s")
    print(f"  Best Macro F1: {report.macro_f1:.4f}")
    print(f"  Report: {report_path}")

    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train the Cortex-Emulation bidirectional GRU model.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m PhantomCortex.training.scripts.train_emulation \\\n"
            "      --output-dir ./output/emulation --epochs 80\n\n"
            "  python -m PhantomCortex.training.scripts.train_emulation \\\n"
            "      --dataset-path ./data/emulation.npz --output-dir ./output"
        ),
    )

    parser.add_argument(
        "--output-dir", type=str, required=True,
        help="Directory for checkpoints, ONNX model, and reports",
    )
    parser.add_argument("--dataset-path", type=str, default=None, help="Pre-saved .npz dataset")
    parser.add_argument("--n-samples", type=int, default=60000, help="Total synthetic samples")
    parser.add_argument("--n-benign", type=int, default=None, help="Benign count override")
    parser.add_argument("--n-suspicious", type=int, default=None, help="Suspicious count override")
    parser.add_argument("--n-malicious", type=int, default=None, help="Malicious count override")
    parser.add_argument("--seq-length", type=int, default=1024, help="Sequence length")
    parser.add_argument("--batch-size", type=int, default=128, help="Batch size")
    parser.add_argument("--epochs", type=int, default=80, help="Max training epochs")
    parser.add_argument("--hidden-dim", type=int, default=256, help="GRU hidden dimension")
    parser.add_argument("--num-layers", type=int, default=2, help="GRU layer count")
    parser.add_argument("--learning-rate", type=float, default=1e-3, help="Initial LR")
    parser.add_argument("--weight-decay", type=float, default=1e-4, help="AdamW weight decay")
    parser.add_argument("--grad-clip", type=float, default=1.0, help="Gradient clipping norm")
    parser.add_argument("--device", type=str, default=None, help="PyTorch device (cpu/cuda)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--num-workers", type=int, default=0, help="DataLoader workers")
    parser.add_argument("--checkpoint-every", type=int, default=10, help="Checkpoint interval")
    parser.add_argument("--save-data", action="store_true", help="Save generated data to .npz")
    parser.add_argument("--no-onnx", action="store_true", help="Skip ONNX export")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(
                Path(args.output_dir) / "train_emulation.log",
                mode="a",
            ) if Path(args.output_dir).exists() else logging.StreamHandler(sys.stdout),
        ],
    )

    run_training(
        output_dir=args.output_dir,
        dataset_path=args.dataset_path,
        n_samples=args.n_samples,
        n_benign=args.n_benign,
        n_suspicious=args.n_suspicious,
        n_malicious=args.n_malicious,
        seq_length=args.seq_length,
        batch_size=args.batch_size,
        epochs=args.epochs,
        hidden_dim=args.hidden_dim,
        num_layers=args.num_layers,
        learning_rate=args.learning_rate,
        weight_decay=args.weight_decay,
        grad_clip=args.grad_clip,
        device=args.device,
        seed=args.seed,
        num_workers=args.num_workers,
        checkpoint_every=args.checkpoint_every,
        save_data=args.save_data,
        export_onnx=not args.no_onnx,
    )


if __name__ == "__main__":
    main()

"""
Cortex-Memory: MLP with Skip Connections for Memory Region Classification
==========================================================================

Classifies memory regions by type: Benign, Shellcode, ROP chains,
Encrypted payloads, or Packed executables.

Architecture:
    128-dim input → FC layers [128→256→512→256→128→64→5]
    BatchNorm + GELU + Dropout(0.2) between layers
    Skip connections every 2 layers
    Kaiming initialization throughout
"""

from __future__ import annotations

import enum
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from numpy.typing import NDArray
from torch.optim.lr_scheduler import OneCycleLR
from torch.utils.data import DataLoader
from torch.utils.tensorboard import SummaryWriter

logger = logging.getLogger("PhantomCortex.MemoryTrainer")

DEFAULT_SEED: int = 42


# ---------------------------------------------------------------------------
# Memory region classes
# ---------------------------------------------------------------------------


class MemoryRegionClass(enum.IntEnum):
    """Classification targets for memory region analysis."""

    Benign = 0
    Shellcode = 1
    ROP = 2
    Encrypted = 3
    Packed = 4


NUM_MEMORY_CLASSES: int = len(MemoryRegionClass)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MetricsReport:
    """Evaluation metrics for memory region classifier."""

    loss: float
    accuracy: float
    per_class_precision: dict[str, float]
    per_class_recall: dict[str, float]
    per_class_f1: dict[str, float]
    macro_f1: float
    confusion_matrix: NDArray[np.int64]

    def to_dict(self) -> dict[str, Any]:
        return {
            "loss": self.loss,
            "accuracy": self.accuracy,
            "macro_f1": self.macro_f1,
            "per_class_precision": self.per_class_precision,
            "per_class_recall": self.per_class_recall,
            "per_class_f1": self.per_class_f1,
        }


# ---------------------------------------------------------------------------
# Residual FC block
# ---------------------------------------------------------------------------


class ResidualFCBlock(nn.Module):
    """Two-layer FC block with skip connection, BatchNorm, GELU, and Dropout."""

    def __init__(
        self,
        in_features: int,
        hidden_features: int,
        out_features: int,
        dropout: float = 0.2,
    ) -> None:
        super().__init__()
        self.fc1 = nn.Linear(in_features, hidden_features)
        self.bn1 = nn.BatchNorm1d(hidden_features)
        self.fc2 = nn.Linear(hidden_features, out_features)
        self.bn2 = nn.BatchNorm1d(out_features)
        self.dropout = nn.Dropout(dropout)

        # Skip projection if dimensions change
        self.skip_proj: Optional[nn.Linear] = None
        if in_features != out_features:
            self.skip_proj = nn.Linear(in_features, out_features, bias=False)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        residual = x if self.skip_proj is None else self.skip_proj(x)

        out = self.fc1(x)
        out = self.bn1(out)
        out = F.gelu(out)
        out = self.dropout(out)

        out = self.fc2(out)
        out = self.bn2(out)
        out = F.gelu(out + residual)
        return self.dropout(out)


# ---------------------------------------------------------------------------
# CortexMemoryNet
# ---------------------------------------------------------------------------


class CortexMemoryNet(nn.Module):
    """MLP with skip connections for memory region classification.

    Input:  (batch, 128) — 128 features per memory region
    Output: (batch, 5)   — logits for 5 memory region classes
    """

    def __init__(
        self,
        input_dim: int = 128,
        num_classes: int = NUM_MEMORY_CLASSES,
        dropout: float = 0.2,
    ) -> None:
        super().__init__()
        self.input_dim = input_dim
        self.num_classes = num_classes

        # Input normalization
        self.input_norm = nn.BatchNorm1d(input_dim)

        # Residual blocks (skip every 2 FC layers)
        # 128→256→512 (block 1)
        self.block1 = ResidualFCBlock(input_dim, 256, 512, dropout)
        # 512→256→128 (block 2)
        self.block2 = ResidualFCBlock(512, 256, 128, dropout)
        # 128→64→final (block 3)
        self.block3 = nn.Sequential(
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.GELU(),
            nn.Dropout(dropout),
        )

        # Classifier head
        self.head = nn.Linear(64, num_classes)

        self._init_weights()

    def _init_weights(self) -> None:
        """Kaiming initialization for all linear layers."""
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.kaiming_normal_(module.weight, nonlinearity="relu")
                if module.bias is not None:
                    nn.init.zeros_(module.bias)
            elif isinstance(module, nn.BatchNorm1d):
                nn.init.ones_(module.weight)
                nn.init.zeros_(module.bias)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass. x: (batch, input_dim)."""
        x = self.input_norm(x)
        x = self.block1(x)
        x = self.block2(x)
        x = self.block3(x)
        return self.head(x)


# ---------------------------------------------------------------------------
# Trainer
# ---------------------------------------------------------------------------


class CortexMemoryTrainer:
    """Training pipeline for the Cortex-Memory MLP classifier.

    Manages training with gradient clipping, 1-cycle LR scheduling,
    checkpointing, early stopping, and TensorBoard integration.
    """

    def __init__(
        self,
        *,
        input_dim: int = 128,
        num_classes: int = NUM_MEMORY_CLASSES,
        learning_rate: float = 1e-3,
        weight_decay: float = 1e-4,
        device: Optional[str] = None,
        seed: int = DEFAULT_SEED,
        log_dir: Optional[str] = None,
    ) -> None:
        self._input_dim = input_dim
        self._num_classes = num_classes
        self._lr = learning_rate
        self._weight_decay = weight_decay
        self._seed = seed

        self._device = torch.device(
            device
            if device is not None
            else ("cuda" if torch.cuda.is_available() else "cpu")
        )
        self._writer: Optional[SummaryWriter] = None
        if log_dir is not None:
            self._writer = SummaryWriter(log_dir=log_dir)

        self._set_seed()

    def _set_seed(self) -> None:
        torch.manual_seed(self._seed)
        np.random.seed(self._seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(self._seed)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False

    def build_model(self) -> nn.Module:
        """Construct and return the CortexMemoryNet on the target device."""
        model = CortexMemoryNet(
            input_dim=self._input_dim,
            num_classes=self._num_classes,
        )
        return model.to(self._device)

    def train(
        self,
        train_loader: DataLoader,
        val_loader: DataLoader,
        *,
        epochs: int = 50,
        grad_clip: float = 1.0,
        checkpoint_dir: Optional[str] = None,
        checkpoint_every: int = 10,
        class_weights: Optional[torch.Tensor] = None,
    ) -> nn.Module:
        """Full training loop with validation, checkpointing, and LR scheduling.

        Args:
            train_loader: DataLoader yielding (X, y) batches.
            val_loader: Validation DataLoader.
            epochs: Maximum training epochs.
            grad_clip: Max gradient norm for clipping.
            checkpoint_dir: Directory for periodic checkpoints.
            checkpoint_every: Save checkpoint every N epochs.
            class_weights: Per-class weights for imbalanced data.

        Returns:
            Best model by validation loss.
        """
        model = self.build_model()
        optimizer = torch.optim.AdamW(
            model.parameters(), lr=self._lr, weight_decay=self._weight_decay
        )

        total_steps = epochs * len(train_loader)
        scheduler = OneCycleLR(
            optimizer,
            max_lr=self._lr,
            total_steps=total_steps,
            pct_start=0.1,
            anneal_strategy="cos",
        )

        loss_fn = nn.CrossEntropyLoss(
            weight=class_weights.to(self._device) if class_weights is not None else None
        )

        best_val_loss = float("inf")
        best_state: Optional[dict[str, Any]] = None
        patience = 15
        patience_counter = 0

        if checkpoint_dir is not None:
            Path(checkpoint_dir).mkdir(parents=True, exist_ok=True)

        logger.info(
            "Training CortexMemory: %d epochs, device=%s, lr=%.1e",
            epochs,
            self._device,
            self._lr,
        )

        for epoch in range(1, epochs + 1):
            model.train()
            train_loss = 0.0
            train_correct = 0
            train_total = 0

            for batch_x, batch_y in train_loader:
                batch_x = batch_x.to(self._device, non_blocking=True)
                batch_y = batch_y.to(self._device, non_blocking=True)

                optimizer.zero_grad(set_to_none=True)
                logits = model(batch_x)
                loss = loss_fn(logits, batch_y)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), grad_clip)
                optimizer.step()
                scheduler.step()

                train_loss += loss.item() * batch_x.size(0)
                train_correct += (logits.argmax(dim=1) == batch_y).sum().item()
                train_total += batch_x.size(0)

            avg_train_loss = train_loss / max(train_total, 1)
            train_acc = train_correct / max(train_total, 1)

            val_loss, val_acc = self._validate_epoch(model, val_loader, loss_fn)

            if self._writer is not None:
                self._writer.add_scalars(
                    "loss", {"train": avg_train_loss, "val": val_loss}, epoch
                )
                self._writer.add_scalars(
                    "accuracy", {"train": train_acc, "val": val_acc}, epoch
                )

            if epoch % 10 == 0 or epoch == 1:
                logger.info(
                    "Epoch %3d/%d — train_loss=%.4f acc=%.4f | val_loss=%.4f acc=%.4f",
                    epoch,
                    epochs,
                    avg_train_loss,
                    train_acc,
                    val_loss,
                    val_acc,
                )

            if val_loss < best_val_loss:
                best_val_loss = val_loss
                best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
                patience_counter = 0
            else:
                patience_counter += 1

            if checkpoint_dir is not None and epoch % checkpoint_every == 0:
                ckpt_path = Path(checkpoint_dir) / f"memory_epoch_{epoch:04d}.pt"
                torch.save(
                    {
                        "epoch": epoch,
                        "model_state": model.state_dict(),
                        "optimizer_state": optimizer.state_dict(),
                        "val_loss": val_loss,
                    },
                    ckpt_path,
                )

            if patience_counter >= patience:
                logger.info("Early stopping at epoch %d", epoch)
                break

        if best_state is not None:
            model.load_state_dict(best_state)
            model = model.to(self._device)

        if self._writer is not None:
            self._writer.flush()

        logger.info("Training complete — best val_loss=%.6f", best_val_loss)
        return model

    @torch.no_grad()
    def _validate_epoch(
        self,
        model: nn.Module,
        loader: DataLoader,
        loss_fn: nn.Module,
    ) -> tuple[float, float]:
        model.eval()
        total_loss = 0.0
        correct = 0
        total = 0
        for batch_x, batch_y in loader:
            batch_x = batch_x.to(self._device, non_blocking=True)
            batch_y = batch_y.to(self._device, non_blocking=True)
            logits = model(batch_x)
            total_loss += loss_fn(logits, batch_y).item() * batch_x.size(0)
            correct += (logits.argmax(dim=1) == batch_y).sum().item()
            total += batch_x.size(0)
        return total_loss / max(total, 1), correct / max(total, 1)

    @torch.no_grad()
    def evaluate(self, model: nn.Module, test_loader: DataLoader) -> MetricsReport:
        """Evaluate model with per-class metrics and confusion matrix.

        Args:
            model: Trained CortexMemoryNet.
            test_loader: DataLoader yielding (X, y) batches.

        Returns:
            MetricsReport with detailed per-class breakdown.
        """
        model.eval()
        model = model.to(self._device)

        all_preds: list[NDArray[np.int64]] = []
        all_labels: list[NDArray[np.int64]] = []
        total_loss = 0.0
        total_samples = 0
        loss_fn = nn.CrossEntropyLoss()

        for batch_x, batch_y in test_loader:
            batch_x = batch_x.to(self._device, non_blocking=True)
            batch_y = batch_y.to(self._device, non_blocking=True)
            logits = model(batch_x)
            total_loss += loss_fn(logits, batch_y).item() * batch_x.size(0)
            total_samples += batch_x.size(0)
            all_preds.append(logits.argmax(dim=1).cpu().numpy())
            all_labels.append(batch_y.cpu().numpy())

        y_pred = np.concatenate(all_preds)
        y_true = np.concatenate(all_labels)

        cm = np.zeros((self._num_classes, self._num_classes), dtype=np.int64)
        for t, p in zip(y_true, y_pred):
            cm[t, p] += 1

        per_class_prec: dict[str, float] = {}
        per_class_rec: dict[str, float] = {}
        per_class_f1: dict[str, float] = {}
        f1_scores: list[float] = []

        for cls_idx in range(self._num_classes):
            cls_name = MemoryRegionClass(cls_idx).name
            tp = int(cm[cls_idx, cls_idx])
            fp = int(cm[:, cls_idx].sum() - tp)
            fn = int(cm[cls_idx, :].sum() - tp)

            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

            per_class_prec[cls_name] = prec
            per_class_rec[cls_name] = rec
            per_class_f1[cls_name] = f1
            f1_scores.append(f1)

        accuracy = float(np.trace(cm)) / max(int(cm.sum()), 1)

        return MetricsReport(
            loss=total_loss / max(total_samples, 1),
            accuracy=accuracy,
            per_class_precision=per_class_prec,
            per_class_recall=per_class_rec,
            per_class_f1=per_class_f1,
            macro_f1=float(np.mean(f1_scores)),
            confusion_matrix=cm,
        )

    def export_onnx(
        self,
        model: nn.Module,
        path: Union[str, Path],
        *,
        opset: int = 17,
    ) -> None:
        """Export trained model to ONNX format.

        Args:
            model: Trained CortexMemoryNet.
            path: Output .onnx file path.
            opset: ONNX opset version.
        """
        model.eval()
        model = model.to("cpu")

        dummy = torch.randn(1, self._input_dim)
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        torch.onnx.export(
            model,
            dummy,
            str(output_path),
            opset_version=opset,
            input_names=["memory_features"],
            output_names=["region_logits"],
            dynamic_axes={
                "memory_features": {0: "batch_size"},
                "region_logits": {0: "batch_size"},
            },
        )

        file_size_mb = output_path.stat().st_size / (1024 * 1024)
        logger.info(
            "Memory MLP exported to %s (%.2f MB, opset=%d)",
            output_path,
            file_size_mb,
            opset,
        )

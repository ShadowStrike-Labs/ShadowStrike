"""
Cortex-Behavioral: 1D-CNN + Multi-Head Attention Trainer
========================================================

Classifies API call sequences into 20 behavioral malware categories.
Input: sequences of 512 API calls with 4 features each (API hash,
argument pattern, return code, timing delta).

Architecture:
    Embedding → 1D Conv stack [64→128→256→128] → Multi-Head Self-Attention →
    Global Average Pool → FC head → 20-class softmax

Designed for real-time behavioral classification during process monitoring.
"""

from __future__ import annotations

import enum
import logging
import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Union

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from numpy.typing import NDArray
from torch.optim.lr_scheduler import CosineAnnealingWarmRestarts
from torch.utils.data import DataLoader
from torch.utils.tensorboard import SummaryWriter

logger = logging.getLogger("PhantomCortex.BehavioralTrainer")


# ---------------------------------------------------------------------------
# Behavior categories
# ---------------------------------------------------------------------------


class BehaviorCategory(enum.IntEnum):
    """Twenty behavioral categories for API sequence classification."""

    ProcessInjection = 0
    Ransomware = 1
    InfoStealer = 2
    Backdoor = 3
    Rootkit = 4
    Downloader = 5
    Dropper = 6
    Worm = 7
    Miner = 8
    Adware = 9
    Keylogger = 10
    RAT = 11
    BankTrojan = 12
    Spyware = 13
    Fileless = 14
    LateralMovement = 15
    Exfiltration = 16
    Persistence = 17
    PrivEsc = 18
    Benign = 19


NUM_BEHAVIOR_CLASSES: int = len(BehaviorCategory)
DEFAULT_SEED: int = 42


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MetricsReport:
    """Evaluation result container for multi-class behavioral model."""

    loss: float
    accuracy: float
    per_class_precision: dict[str, float]
    per_class_recall: dict[str, float]
    per_class_f1: dict[str, float]
    macro_f1: float
    weighted_f1: float
    confusion_matrix: NDArray[np.int64]

    def to_dict(self) -> dict[str, Any]:
        return {
            "loss": self.loss,
            "accuracy": self.accuracy,
            "macro_f1": self.macro_f1,
            "weighted_f1": self.weighted_f1,
            "per_class_precision": self.per_class_precision,
            "per_class_recall": self.per_class_recall,
            "per_class_f1": self.per_class_f1,
        }


# ---------------------------------------------------------------------------
# Multi-Head Self-Attention
# ---------------------------------------------------------------------------


class MultiHeadSelfAttention(nn.Module):
    """Scaled dot-product multi-head self-attention for 1-D feature maps."""

    def __init__(self, embed_dim: int, num_heads: int, dropout: float = 0.1) -> None:
        super().__init__()
        if embed_dim % num_heads != 0:
            raise ValueError(
                f"embed_dim ({embed_dim}) must be divisible by num_heads ({num_heads})"
            )
        self.num_heads = num_heads
        self.head_dim = embed_dim // num_heads
        self.scale = math.sqrt(self.head_dim)

        self.qkv_proj = nn.Linear(embed_dim, 3 * embed_dim)
        self.out_proj = nn.Linear(embed_dim, embed_dim)
        self.dropout = nn.Dropout(dropout)
        self.norm = nn.LayerNorm(embed_dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass. x: (batch, seq_len, embed_dim)."""
        residual = x
        batch, seq_len, _ = x.shape

        qkv = self.qkv_proj(x)
        qkv = qkv.reshape(batch, seq_len, 3, self.num_heads, self.head_dim)
        qkv = qkv.permute(2, 0, 3, 1, 4)  # (3, B, H, S, D)
        q, k, v = qkv.unbind(dim=0)

        attn_weights = torch.matmul(q, k.transpose(-2, -1)) / self.scale
        attn_weights = F.softmax(attn_weights, dim=-1)
        attn_weights = self.dropout(attn_weights)

        attn_out = torch.matmul(attn_weights, v)
        attn_out = attn_out.transpose(1, 2).reshape(batch, seq_len, -1)
        attn_out = self.out_proj(attn_out)
        attn_out = self.dropout(attn_out)

        return self.norm(attn_out + residual)


# ---------------------------------------------------------------------------
# Convolutional block
# ---------------------------------------------------------------------------


class ConvBlock(nn.Module):
    """1D convolution + BatchNorm + ReLU + Dropout."""

    def __init__(
        self,
        in_channels: int,
        out_channels: int,
        kernel_size: int,
        dropout: float = 0.3,
    ) -> None:
        super().__init__()
        self.conv = nn.Conv1d(
            in_channels, out_channels, kernel_size, padding=kernel_size // 2
        )
        self.bn = nn.BatchNorm1d(out_channels)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass. x: (batch, channels, seq_len)."""
        return self.dropout(F.relu(self.bn(self.conv(x))))


# ---------------------------------------------------------------------------
# CortexBehavioralNet
# ---------------------------------------------------------------------------


class CortexBehavioralNet(nn.Module):
    """1D-CNN + Multi-Head Self-Attention for API sequence classification.

    Input shape:  (batch, 512, 4)   — 512 API calls × 4 features
    Output shape: (batch, 20)       — softmax over 20 behavior categories
    """

    def __init__(
        self,
        sequence_length: int = 512,
        feature_dim: int = 4,
        embed_dim: int = 64,
        num_classes: int = NUM_BEHAVIOR_CLASSES,
        num_heads: int = 4,
        dropout: float = 0.3,
    ) -> None:
        super().__init__()
        self.sequence_length = sequence_length
        self.feature_dim = feature_dim
        self.num_classes = num_classes

        # Embedding projection: 4 raw features → embed_dim
        self.input_proj = nn.Sequential(
            nn.Linear(feature_dim, embed_dim),
            nn.LayerNorm(embed_dim),
            nn.ReLU(),
        )

        # Positional encoding (learned)
        self.pos_embedding = nn.Parameter(
            torch.randn(1, sequence_length, embed_dim) * 0.02
        )

        # 1D conv stack: operates on (batch, channels, seq_len)
        self.conv_stack = nn.Sequential(
            ConvBlock(embed_dim, 128, kernel_size=3, dropout=dropout),
            ConvBlock(128, 256, kernel_size=5, dropout=dropout),
            ConvBlock(256, 128, kernel_size=7, dropout=dropout),
            ConvBlock(128, 128, kernel_size=3, dropout=dropout),
        )

        # Multi-head self-attention over the conv output
        self.attention = MultiHeadSelfAttention(
            embed_dim=128, num_heads=num_heads, dropout=dropout
        )

        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, num_classes),
        )

        self._init_weights()

    def _init_weights(self) -> None:
        """Kaiming (He) initialization for conv layers, Xavier for linear."""
        for module in self.modules():
            if isinstance(module, nn.Conv1d):
                nn.init.kaiming_normal_(module.weight, nonlinearity="relu")
                if module.bias is not None:
                    nn.init.zeros_(module.bias)
            elif isinstance(module, nn.Linear):
                nn.init.xavier_uniform_(module.weight)
                if module.bias is not None:
                    nn.init.zeros_(module.bias)
            elif isinstance(module, (nn.BatchNorm1d, nn.LayerNorm)):
                nn.init.ones_(module.weight)
                nn.init.zeros_(module.bias)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass.

        Args:
            x: (batch, sequence_length, feature_dim) float tensor.

        Returns:
            Logits of shape (batch, num_classes).
        """
        # Project input features → embed_dim
        x = self.input_proj(x) + self.pos_embedding[:, : x.size(1), :]

        # Conv stack expects (batch, channels, seq_len)
        x = x.permute(0, 2, 1)
        x = self.conv_stack(x)

        # Back to (batch, seq_len, channels) for attention
        x = x.permute(0, 2, 1)
        x = self.attention(x)

        # Global average pooling
        x = x.mean(dim=1)

        return self.classifier(x)


# ---------------------------------------------------------------------------
# Trainer
# ---------------------------------------------------------------------------


class CortexBehavioralTrainer:
    """Training pipeline for the Cortex-Behavioral 1D-CNN model.

    Manages reproducible training with gradient clipping, LR scheduling,
    checkpointing, TensorBoard logging, and ONNX export.
    """

    def __init__(
        self,
        *,
        sequence_length: int = 512,
        feature_dim: int = 4,
        embed_dim: int = 64,
        num_classes: int = NUM_BEHAVIOR_CLASSES,
        learning_rate: float = 1e-3,
        weight_decay: float = 1e-4,
        device: Optional[str] = None,
        seed: int = DEFAULT_SEED,
        log_dir: Optional[str] = None,
    ) -> None:
        self._seq_len = sequence_length
        self._feat_dim = feature_dim
        self._embed_dim = embed_dim
        self._num_classes = num_classes
        self._lr = learning_rate
        self._weight_decay = weight_decay
        self._seed = seed

        self._device = torch.device(
            device
            if device is not None
            else ("cuda" if torch.cuda.is_available() else "cpu")
        )
        self._use_amp = self._device.type == "cuda"
        self._writer: Optional[SummaryWriter] = None
        if log_dir is not None:
            self._writer = SummaryWriter(log_dir=log_dir)

        self._set_seed()

    def _set_seed(self) -> None:
        torch.manual_seed(self._seed)
        np.random.seed(self._seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(self._seed)
            if hasattr(torch, "set_float32_matmul_precision"):
                torch.set_float32_matmul_precision("high")
            if hasattr(torch.backends.cuda.matmul, "allow_tf32"):
                torch.backends.cuda.matmul.allow_tf32 = True
            if hasattr(torch.backends.cudnn, "allow_tf32"):
                torch.backends.cudnn.allow_tf32 = True
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False

    # ------------------------------------------------------------------
    # Model construction
    # ------------------------------------------------------------------

    def build_model(self) -> nn.Module:
        """Construct and return the CortexBehavioralNet on the target device.

        Returns:
            Initialized CortexBehavioralNet.
        """
        model = CortexBehavioralNet(
            sequence_length=self._seq_len,
            feature_dim=self._feat_dim,
            embed_dim=self._embed_dim,
            num_classes=self._num_classes,
        )
        return model.to(self._device)

    # ------------------------------------------------------------------
    # Training loop
    # ------------------------------------------------------------------

    def train(
        self,
        train_loader: DataLoader,
        val_loader: DataLoader,
        *,
        epochs: int = 100,
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
            class_weights: Per-class weights for loss (handles imbalance).

        Returns:
            Best model (by validation loss) moved to the target device.
        """
        model = self.build_model()
        optimizer = torch.optim.AdamW(
            model.parameters(), lr=self._lr, weight_decay=self._weight_decay
        )
        scheduler = CosineAnnealingWarmRestarts(optimizer, T_0=10, T_mult=2)

        loss_fn = nn.CrossEntropyLoss(
            weight=class_weights.to(self._device) if class_weights is not None else None
        )
        scaler = torch.cuda.amp.GradScaler(enabled=self._use_amp)

        best_val_loss = float("inf")
        best_state: Optional[dict[str, Any]] = None
        patience = 15
        patience_counter = 0

        if checkpoint_dir is not None:
            Path(checkpoint_dir).mkdir(parents=True, exist_ok=True)

        logger.info(
            "Training CortexBehavioral: %d epochs, device=%s, lr=%.1e, amp=%s",
            epochs,
            self._device,
            self._lr,
            self._use_amp,
        )

        for epoch in range(1, epochs + 1):
            # --- Train phase ---
            model.train()
            train_loss = 0.0
            train_correct = 0
            train_total = 0

            for batch_x, batch_y in train_loader:
                batch_x = batch_x.to(self._device, non_blocking=True)
                batch_y = batch_y.to(self._device, non_blocking=True)

                optimizer.zero_grad(set_to_none=True)
                with torch.autocast(
                    device_type=self._device.type,
                    dtype=torch.float16,
                    enabled=self._use_amp,
                ):
                    logits = model(batch_x)
                    loss = loss_fn(logits, batch_y)
                scaler.scale(loss).backward()
                scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), grad_clip)
                scaler.step(optimizer)
                scaler.update()

                train_loss += loss.item() * batch_x.size(0)
                train_correct += (logits.argmax(dim=1) == batch_y).sum().item()
                train_total += batch_x.size(0)

            scheduler.step()
            avg_train_loss = train_loss / max(train_total, 1)
            train_acc = train_correct / max(train_total, 1)

            # --- Validation phase ---
            val_loss, val_acc = self._validate_epoch(model, val_loader, loss_fn)

            if self._writer is not None:
                self._writer.add_scalars(
                    "loss", {"train": avg_train_loss, "val": val_loss}, epoch
                )
                self._writer.add_scalars(
                    "accuracy", {"train": train_acc, "val": val_acc}, epoch
                )
                self._writer.add_scalar("lr", optimizer.param_groups[0]["lr"], epoch)

            if epoch % 10 == 0 or epoch == 1:
                logger.info(
                    "Epoch %3d/%d — train_loss=%.4f train_acc=%.4f | "
                    "val_loss=%.4f val_acc=%.4f | lr=%.2e",
                    epoch,
                    epochs,
                    avg_train_loss,
                    train_acc,
                    val_loss,
                    val_acc,
                    optimizer.param_groups[0]["lr"],
                )

            # --- Checkpointing ---
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
                patience_counter = 0
            else:
                patience_counter += 1

            if checkpoint_dir is not None and epoch % checkpoint_every == 0:
                ckpt_path = Path(checkpoint_dir) / f"behavioral_epoch_{epoch:04d}.pt"
                torch.save(
                    {
                        "epoch": epoch,
                        "model_state": model.state_dict(),
                        "optimizer_state": optimizer.state_dict(),
                        "scheduler_state": scheduler.state_dict(),
                        "val_loss": val_loss,
                    },
                    ckpt_path,
                )

            if patience_counter >= patience:
                logger.info("Early stopping at epoch %d (patience=%d)", epoch, patience)
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
            with torch.autocast(
                device_type=self._device.type,
                dtype=torch.float16,
                enabled=self._use_amp,
            ):
                logits = model(batch_x)
                batch_loss = loss_fn(logits, batch_y)
            total_loss += batch_loss.item() * batch_x.size(0)
            correct += (logits.argmax(dim=1) == batch_y).sum().item()
            total += batch_x.size(0)
        return total_loss / max(total, 1), correct / max(total, 1)

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    @torch.no_grad()
    def evaluate(
        self,
        model: nn.Module,
        test_loader: DataLoader,
    ) -> MetricsReport:
        """Evaluate model on test set with per-class metrics.

        Args:
            model: Trained CortexBehavioralNet.
            test_loader: DataLoader yielding (X, y) batches.

        Returns:
            MetricsReport with per-class and aggregate metrics.
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

            with torch.autocast(
                device_type=self._device.type,
                dtype=torch.float16,
                enabled=self._use_amp,
            ):
                logits = model(batch_x)
                batch_loss = loss_fn(logits, batch_y)
            total_loss += batch_loss.item() * batch_x.size(0)
            total_samples += batch_x.size(0)

            preds = logits.argmax(dim=1).cpu().numpy()
            labels = batch_y.cpu().numpy()
            all_preds.append(preds)
            all_labels.append(labels)

        y_pred = np.concatenate(all_preds)
        y_true = np.concatenate(all_labels)
        avg_loss = total_loss / max(total_samples, 1)

        # Confusion matrix
        cm = np.zeros(
            (self._num_classes, self._num_classes), dtype=np.int64
        )
        for t, p in zip(y_true, y_pred):
            cm[t, p] += 1

        # Per-class metrics
        per_class_prec: dict[str, float] = {}
        per_class_rec: dict[str, float] = {}
        per_class_f1: dict[str, float] = {}
        f1_scores: list[float] = []
        weighted_f1_sum = 0.0
        total_support = 0

        for cls_idx in range(self._num_classes):
            cls_name = BehaviorCategory(cls_idx).name
            tp = int(cm[cls_idx, cls_idx])
            fp = int(cm[:, cls_idx].sum() - tp)
            fn = int(cm[cls_idx, :].sum() - tp)
            support = int(cm[cls_idx, :].sum())

            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

            per_class_prec[cls_name] = prec
            per_class_rec[cls_name] = rec
            per_class_f1[cls_name] = f1
            f1_scores.append(f1)
            weighted_f1_sum += f1 * support
            total_support += support

        macro_f1 = float(np.mean(f1_scores))
        weighted_f1 = weighted_f1_sum / max(total_support, 1)

        accuracy = float(np.trace(cm)) / max(total_support, 1)

        return MetricsReport(
            loss=avg_loss,
            accuracy=accuracy,
            per_class_precision=per_class_prec,
            per_class_recall=per_class_rec,
            per_class_f1=per_class_f1,
            macro_f1=macro_f1,
            weighted_f1=weighted_f1,
            confusion_matrix=cm,
        )

    # ------------------------------------------------------------------
    # ONNX export
    # ------------------------------------------------------------------

    def export_onnx(
        self,
        model: nn.Module,
        path: Union[str, Path],
        *,
        opset: int = 17,
    ) -> None:
        """Export trained model to ONNX format for C++ inference.

        Args:
            model: Trained CortexBehavioralNet.
            path: Output .onnx file path.
            opset: ONNX opset version.
        """
        model.eval()
        model = model.to("cpu")

        dummy = torch.randn(1, self._seq_len, self._feat_dim)
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        torch.onnx.export(
            model,
            dummy,
            str(output_path),
            opset_version=opset,
            input_names=["api_sequence"],
            output_names=["behavior_logits"],
            dynamic_axes={
                "api_sequence": {0: "batch_size"},
                "behavior_logits": {0: "batch_size"},
            },
        )

        file_size_mb = output_path.stat().st_size / (1024 * 1024)
        logger.info(
            "ONNX model exported to %s (%.2f MB, opset=%d)",
            output_path,
            file_size_mb,
            opset,
        )

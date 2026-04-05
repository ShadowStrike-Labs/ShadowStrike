"""
Cortex-Emulation: Bidirectional GRU for Emulation Trace Verdicts
================================================================

Processes emulation traces (sequences of opcode, memory access, and API
events) through a bidirectional GRU with attention pooling to produce
a three-class verdict: Benign, Suspicious, or Malicious.

Architecture:
    Input: (batch, 1024, 4) — 1024 emulation events × 4 features
    Feature embeddings: opcode_cat(256)→64, mem_access(8)→64, api_id(2000)→64
    Concatenated: 4th feature raw → total 193-dim per timestep
    Bidirectional GRU: 2 layers, hidden=256, dropout=0.3
    Attention pooling: learned query over GRU outputs
    FC: 512 → 256 → 128 → 3
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

logger = logging.getLogger("PhantomCortex.EmulationTrainer")

DEFAULT_SEED: int = 42


# ---------------------------------------------------------------------------
# Emulation verdict classes
# ---------------------------------------------------------------------------


class EmulationVerdict(enum.IntEnum):
    """Three-class emulation trace verdict."""

    Benign = 0
    Suspicious = 1
    Malicious = 2


NUM_VERDICT_CLASSES: int = len(EmulationVerdict)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MetricsReport:
    """Evaluation metrics for emulation verdict model."""

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
# Attention pooling
# ---------------------------------------------------------------------------


class AttentionPooling(nn.Module):
    """Learned attention-weighted pooling over a sequence dimension."""

    def __init__(self, hidden_dim: int) -> None:
        super().__init__()
        self.query = nn.Linear(hidden_dim, 1, bias=False)
        self.norm = nn.LayerNorm(hidden_dim)

    def forward(
        self, x: torch.Tensor, mask: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        """Pool sequence via attention weights.

        Args:
            x: (batch, seq_len, hidden_dim)
            mask: (batch, seq_len) boolean — True for valid positions.

        Returns:
            (batch, hidden_dim) pooled representation.
        """
        scores = self.query(x).squeeze(-1)  # (batch, seq_len)

        if mask is not None:
            scores = scores.masked_fill(~mask, float("-inf"))

        weights = F.softmax(scores, dim=1).unsqueeze(-1)  # (batch, seq_len, 1)
        pooled = (x * weights).sum(dim=1)
        return self.norm(pooled)


# ---------------------------------------------------------------------------
# Feature embedding
# ---------------------------------------------------------------------------


class EmulationFeatureEmbedding(nn.Module):
    """Embed discrete emulation features into continuous space.

    Input features per timestep (4 total):
        [0] opcode_category (0..255)   → 64-dim embedding
        [1] memory_access    (0..7)    → 64-dim embedding
        [2] api_id           (0..1999) → 64-dim embedding
        [3] raw_value        (float)   → passed through linear(1→1)

    Output: 193-dim per timestep (64 + 64 + 64 + 1).
    """

    OPCODE_VOCAB: int = 256
    MEMACCESS_VOCAB: int = 8
    API_VOCAB: int = 2000
    EMBED_DIM: int = 64

    def __init__(self) -> None:
        super().__init__()
        self.opcode_emb = nn.Embedding(self.OPCODE_VOCAB, self.EMBED_DIM)
        self.memaccess_emb = nn.Embedding(self.MEMACCESS_VOCAB, self.EMBED_DIM)
        self.api_emb = nn.Embedding(self.API_VOCAB, self.EMBED_DIM)
        self.raw_proj = nn.Linear(1, 1, bias=False)

    @property
    def output_dim(self) -> int:
        return 3 * self.EMBED_DIM + 1  # 193

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Embed features.

        Args:
            x: (batch, seq_len, 4) — integer features (clamped to valid ranges).

        Returns:
            (batch, seq_len, 193) float tensor.
        """
        opcode = x[:, :, 0].long().clamp(0, self.OPCODE_VOCAB - 1)
        memaccess = x[:, :, 1].long().clamp(0, self.MEMACCESS_VOCAB - 1)
        api_id = x[:, :, 2].long().clamp(0, self.API_VOCAB - 1)
        raw_val = x[:, :, 3:4]  # keep dim for linear

        e_op = self.opcode_emb(opcode)
        e_mem = self.memaccess_emb(memaccess)
        e_api = self.api_emb(api_id)
        e_raw = self.raw_proj(raw_val)

        return torch.cat([e_op, e_mem, e_api, e_raw], dim=-1)


# ---------------------------------------------------------------------------
# CortexEmulationNet
# ---------------------------------------------------------------------------


class CortexEmulationNet(nn.Module):
    """Bidirectional GRU with attention pooling for emulation trace verdicts.

    Input:  (batch, 1024, 4) — emulation events
    Output: (batch, 3)       — logits for [Benign, Suspicious, Malicious]
    """

    def __init__(
        self,
        sequence_length: int = 1024,
        feature_dim: int = 4,
        hidden_dim: int = 256,
        num_layers: int = 2,
        num_classes: int = NUM_VERDICT_CLASSES,
        dropout: float = 0.3,
    ) -> None:
        super().__init__()
        self.sequence_length = sequence_length
        self.feature_dim = feature_dim
        self.num_classes = num_classes

        self.embedding = EmulationFeatureEmbedding()
        embed_out = self.embedding.output_dim  # 193

        self.gru = nn.GRU(
            input_size=embed_out,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )

        gru_out_dim = hidden_dim * 2  # bidirectional
        self.attention = AttentionPooling(gru_out_dim)

        self.classifier = nn.Sequential(
            nn.Linear(gru_out_dim, 256),
            nn.BatchNorm1d(256),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(256, 128),
            nn.BatchNorm1d(128),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(128, num_classes),
        )

        self._init_weights()

    def _init_weights(self) -> None:
        # Xavier for embeddings
        for emb in [
            self.embedding.opcode_emb,
            self.embedding.memaccess_emb,
            self.embedding.api_emb,
        ]:
            nn.init.xavier_uniform_(emb.weight)

        # Orthogonal init for GRU weights
        for name, param in self.gru.named_parameters():
            if "weight_ih" in name:
                nn.init.xavier_uniform_(param)
            elif "weight_hh" in name:
                nn.init.orthogonal_(param)
            elif "bias" in name:
                nn.init.zeros_(param)

        # Kaiming for FC layers
        for module in self.classifier.modules():
            if isinstance(module, nn.Linear):
                nn.init.kaiming_normal_(module.weight, nonlinearity="relu")
                if module.bias is not None:
                    nn.init.zeros_(module.bias)
            elif isinstance(module, nn.BatchNorm1d):
                nn.init.ones_(module.weight)
                nn.init.zeros_(module.bias)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass.

        Args:
            x: (batch, seq_len, 4) emulation events.

        Returns:
            (batch, num_classes) logits.
        """
        embedded = self.embedding(x)
        gru_out, _ = self.gru(embedded)
        pooled = self.attention(gru_out)
        return self.classifier(pooled)


# ---------------------------------------------------------------------------
# Trainer
# ---------------------------------------------------------------------------


class CortexEmulationTrainer:
    """Training pipeline for the Cortex-Emulation bidirectional GRU model.

    Full training loop with gradient clipping, cosine annealing, early
    stopping, checkpointing, and TensorBoard logging.
    """

    def __init__(
        self,
        *,
        sequence_length: int = 1024,
        feature_dim: int = 4,
        hidden_dim: int = 256,
        num_layers: int = 2,
        num_classes: int = NUM_VERDICT_CLASSES,
        learning_rate: float = 1e-3,
        weight_decay: float = 1e-4,
        device: Optional[str] = None,
        seed: int = DEFAULT_SEED,
        log_dir: Optional[str] = None,
    ) -> None:
        self._seq_len = sequence_length
        self._feat_dim = feature_dim
        self._hidden_dim = hidden_dim
        self._num_layers = num_layers
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
        """Construct and return CortexEmulationNet on the target device."""
        model = CortexEmulationNet(
            sequence_length=self._seq_len,
            feature_dim=self._feat_dim,
            hidden_dim=self._hidden_dim,
            num_layers=self._num_layers,
            num_classes=self._num_classes,
        )
        return model.to(self._device)

    def train(
        self,
        train_loader: DataLoader,
        val_loader: DataLoader,
        *,
        epochs: int = 80,
        grad_clip: float = 1.0,
        checkpoint_dir: Optional[str] = None,
        checkpoint_every: int = 10,
        class_weights: Optional[torch.Tensor] = None,
    ) -> nn.Module:
        """Full training loop with validation, checkpointing, and scheduling.

        Args:
            train_loader: DataLoader yielding (X, y) batches.
            val_loader: Validation DataLoader.
            epochs: Maximum training epochs.
            grad_clip: Max gradient norm for clipping.
            checkpoint_dir: Path for periodic checkpoints.
            checkpoint_every: Checkpoint frequency in epochs.
            class_weights: Per-class loss weights.

        Returns:
            Best model by validation loss.
        """
        model = self.build_model()
        optimizer = torch.optim.AdamW(
            model.parameters(), lr=self._lr, weight_decay=self._weight_decay
        )
        scheduler = CosineAnnealingWarmRestarts(optimizer, T_0=10, T_mult=2)

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
            "Training CortexEmulation: %d epochs, device=%s, hidden=%d, layers=%d",
            epochs,
            self._device,
            self._hidden_dim,
            self._num_layers,
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

                train_loss += loss.item() * batch_x.size(0)
                train_correct += (logits.argmax(dim=1) == batch_y).sum().item()
                train_total += batch_x.size(0)

            scheduler.step()
            avg_loss = train_loss / max(train_total, 1)
            train_acc = train_correct / max(train_total, 1)

            val_loss, val_acc = self._validate_epoch(model, val_loader, loss_fn)

            if self._writer is not None:
                self._writer.add_scalars(
                    "loss", {"train": avg_loss, "val": val_loss}, epoch
                )
                self._writer.add_scalars(
                    "accuracy", {"train": train_acc, "val": val_acc}, epoch
                )

            if epoch % 10 == 0 or epoch == 1:
                logger.info(
                    "Epoch %3d/%d — loss=%.4f acc=%.4f | val_loss=%.4f val_acc=%.4f",
                    epoch,
                    epochs,
                    avg_loss,
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
                ckpt_path = Path(checkpoint_dir) / f"emulation_epoch_{epoch:04d}.pt"
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
            model: Trained CortexEmulationNet.
            test_loader: DataLoader yielding (X, y) batches.

        Returns:
            MetricsReport with per-class breakdown.
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
            cls_name = EmulationVerdict(cls_idx).name
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
            model: Trained CortexEmulationNet.
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
            input_names=["emulation_trace"],
            output_names=["verdict_logits"],
            dynamic_axes={
                "emulation_trace": {0: "batch_size"},
                "verdict_logits": {0: "batch_size"},
            },
        )

        file_size_mb = output_path.stat().st_size / (1024 * 1024)
        logger.info(
            "Emulation GRU exported to %s (%.2f MB, opset=%d)",
            output_path,
            file_size_mb,
            opset,
        )

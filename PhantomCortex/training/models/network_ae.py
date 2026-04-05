"""
Cortex-Network: Autoencoder + Classifier for Network Anomaly Detection
=======================================================================

Dual-purpose model:
    1. Autoencoder trained on normal traffic — reconstruction error = anomaly score
    2. Classifier head on the latent space → 8 network threat categories

Architecture:
    Encoder:  input_dim → 128 → 64 → 32 (latent)
    Decoder:  32 → 64 → 128 → input_dim
    Classifier: 32 → 64 → 32 → 8 classes
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
from torch.optim.lr_scheduler import ReduceLROnPlateau
from torch.utils.data import DataLoader
from torch.utils.tensorboard import SummaryWriter

logger = logging.getLogger("PhantomCortex.NetworkTrainer")

DEFAULT_SEED: int = 42


# ---------------------------------------------------------------------------
# Network threat classes
# ---------------------------------------------------------------------------


class NetworkThreatClass(enum.IntEnum):
    """Network traffic classification targets."""

    Normal = 0
    C2Beacon = 1
    Exfiltration = 2
    LateralMovement = 3
    Scanning = 4
    DGADomain = 5
    DNSTunnel = 6
    CryptoMining = 7


NUM_NETWORK_CLASSES: int = len(NetworkThreatClass)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AnomalyResult:
    """Per-sample anomaly detection output."""

    reconstruction_error: float
    is_anomaly: bool
    predicted_class: int
    class_probabilities: NDArray[np.float64]


@dataclass(frozen=True)
class MetricsReport:
    """Evaluation metrics for the network model."""

    reconstruction_loss: float
    classification_loss: float
    accuracy: float
    per_class_precision: dict[str, float]
    per_class_recall: dict[str, float]
    per_class_f1: dict[str, float]
    macro_f1: float
    anomaly_auc: float
    confusion_matrix: NDArray[np.int64]

    def to_dict(self) -> dict[str, Any]:
        return {
            "reconstruction_loss": self.reconstruction_loss,
            "classification_loss": self.classification_loss,
            "accuracy": self.accuracy,
            "macro_f1": self.macro_f1,
            "anomaly_auc": self.anomaly_auc,
            "per_class_precision": self.per_class_precision,
            "per_class_recall": self.per_class_recall,
            "per_class_f1": self.per_class_f1,
        }


# ---------------------------------------------------------------------------
# Encoder
# ---------------------------------------------------------------------------


class Encoder(nn.Module):
    """Encoder: input_dim → 128 → 64 → 32 (latent)."""

    def __init__(self, input_dim: int, latent_dim: int = 32) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.BatchNorm1d(128),
            nn.GELU(),
            nn.Dropout(0.2),
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.GELU(),
            nn.Dropout(0.2),
            nn.Linear(64, latent_dim),
            nn.BatchNorm1d(latent_dim),
            nn.GELU(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------


class Decoder(nn.Module):
    """Decoder: 32 → 64 → 128 → input_dim."""

    def __init__(self, latent_dim: int = 32, output_dim: int = 64) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(latent_dim, 64),
            nn.BatchNorm1d(64),
            nn.GELU(),
            nn.Dropout(0.2),
            nn.Linear(64, 128),
            nn.BatchNorm1d(128),
            nn.GELU(),
            nn.Dropout(0.2),
            nn.Linear(128, output_dim),
        )

    def forward(self, z: torch.Tensor) -> torch.Tensor:
        return self.net(z)


# ---------------------------------------------------------------------------
# Classifier head
# ---------------------------------------------------------------------------


class ClassifierHead(nn.Module):
    """Classifier on latent space: 32 → 64 → 32 → 8."""

    def __init__(
        self, latent_dim: int = 32, num_classes: int = NUM_NETWORK_CLASSES
    ) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(latent_dim, 64),
            nn.BatchNorm1d(64),
            nn.GELU(),
            nn.Dropout(0.3),
            nn.Linear(64, 32),
            nn.BatchNorm1d(32),
            nn.GELU(),
            nn.Dropout(0.3),
            nn.Linear(32, num_classes),
        )

    def forward(self, z: torch.Tensor) -> torch.Tensor:
        return self.net(z)


# ---------------------------------------------------------------------------
# CortexNetworkNet
# ---------------------------------------------------------------------------


class CortexNetworkNet(nn.Module):
    """Autoencoder + Classifier for network traffic analysis.

    Forward pass returns (reconstructed, latent, class_logits).
    """

    def __init__(
        self,
        input_dim: int = 64,
        latent_dim: int = 32,
        num_classes: int = NUM_NETWORK_CLASSES,
    ) -> None:
        super().__init__()
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.num_classes = num_classes

        self.encoder = Encoder(input_dim, latent_dim)
        self.decoder = Decoder(latent_dim, input_dim)
        self.classifier = ClassifierHead(latent_dim, num_classes)

        self._init_weights()

    def _init_weights(self) -> None:
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.kaiming_normal_(module.weight, nonlinearity="relu")
                if module.bias is not None:
                    nn.init.zeros_(module.bias)
            elif isinstance(module, nn.BatchNorm1d):
                nn.init.ones_(module.weight)
                nn.init.zeros_(module.bias)

    def forward(
        self, x: torch.Tensor
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """Forward pass.

        Args:
            x: (batch, input_dim) float tensor.

        Returns:
            Tuple of (reconstructed, latent, class_logits).
        """
        latent = self.encoder(x)
        reconstructed = self.decoder(latent)
        class_logits = self.classifier(latent)
        return reconstructed, latent, class_logits

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        """Encode input to latent representation."""
        return self.encoder(x)

    def reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        """Compute per-sample reconstruction error (MSE)."""
        latent = self.encoder(x)
        reconstructed = self.decoder(latent)
        return ((x - reconstructed) ** 2).mean(dim=1)


# ---------------------------------------------------------------------------
# Trainer
# ---------------------------------------------------------------------------


class CortexNetworkTrainer:
    """Training pipeline for the Cortex-Network autoencoder + classifier.

    Supports two-phase training:
        Phase 1: Train autoencoder on normal traffic (unsupervised)
        Phase 2: Train classifier head on labeled traffic (supervised)
    Or joint training with combined loss.
    """

    def __init__(
        self,
        *,
        input_dim: int = 64,
        latent_dim: int = 32,
        num_classes: int = NUM_NETWORK_CLASSES,
        learning_rate: float = 1e-3,
        weight_decay: float = 1e-4,
        anomaly_threshold: float = 0.95,
        device: Optional[str] = None,
        seed: int = DEFAULT_SEED,
        log_dir: Optional[str] = None,
    ) -> None:
        self._input_dim = input_dim
        self._latent_dim = latent_dim
        self._num_classes = num_classes
        self._lr = learning_rate
        self._weight_decay = weight_decay
        self._anomaly_threshold = anomaly_threshold
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
        """Construct and return CortexNetworkNet on the target device."""
        model = CortexNetworkNet(
            input_dim=self._input_dim,
            latent_dim=self._latent_dim,
            num_classes=self._num_classes,
        )
        return model.to(self._device)

    # ------------------------------------------------------------------
    # Joint training
    # ------------------------------------------------------------------

    def train(
        self,
        train_loader: DataLoader,
        val_loader: DataLoader,
        *,
        epochs: int = 100,
        recon_weight: float = 1.0,
        cls_weight: float = 1.0,
        grad_clip: float = 1.0,
        checkpoint_dir: Optional[str] = None,
        checkpoint_every: int = 10,
        class_weights: Optional[torch.Tensor] = None,
    ) -> nn.Module:
        """Joint training of autoencoder + classifier with combined loss.

        The total loss is: ``recon_weight * MSE + cls_weight * CrossEntropy``.

        Args:
            train_loader: DataLoader yielding (X, y) batches.
            val_loader: Validation DataLoader.
            epochs: Maximum training epochs.
            recon_weight: Weight for reconstruction loss.
            cls_weight: Weight for classification loss.
            grad_clip: Max gradient norm.
            checkpoint_dir: Path for periodic checkpoints.
            checkpoint_every: Checkpoint frequency in epochs.
            class_weights: Per-class weights for cross-entropy.

        Returns:
            Best model by validation loss.
        """
        model = self.build_model()
        optimizer = torch.optim.AdamW(
            model.parameters(), lr=self._lr, weight_decay=self._weight_decay
        )
        scheduler = ReduceLROnPlateau(
            optimizer, mode="min", factor=0.5, patience=5, min_lr=1e-6
        )

        ce_loss_fn = nn.CrossEntropyLoss(
            weight=class_weights.to(self._device) if class_weights is not None else None
        )
        mse_loss_fn = nn.MSELoss()

        best_val_loss = float("inf")
        best_state: Optional[dict[str, Any]] = None
        patience = 20
        patience_counter = 0

        if checkpoint_dir is not None:
            Path(checkpoint_dir).mkdir(parents=True, exist_ok=True)

        logger.info(
            "Training CortexNetwork: %d epochs, device=%s, "
            "recon_weight=%.2f, cls_weight=%.2f",
            epochs,
            self._device,
            recon_weight,
            cls_weight,
        )

        for epoch in range(1, epochs + 1):
            model.train()
            train_recon = 0.0
            train_cls = 0.0
            train_correct = 0
            train_total = 0

            for batch_x, batch_y in train_loader:
                batch_x = batch_x.to(self._device, non_blocking=True)
                batch_y = batch_y.to(self._device, non_blocking=True)

                optimizer.zero_grad(set_to_none=True)
                reconstructed, _, class_logits = model(batch_x)

                loss_recon = mse_loss_fn(reconstructed, batch_x)
                loss_cls = ce_loss_fn(class_logits, batch_y)
                loss = recon_weight * loss_recon + cls_weight * loss_cls

                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), grad_clip)
                optimizer.step()

                batch_size = batch_x.size(0)
                train_recon += loss_recon.item() * batch_size
                train_cls += loss_cls.item() * batch_size
                train_correct += (class_logits.argmax(dim=1) == batch_y).sum().item()
                train_total += batch_size

            avg_recon = train_recon / max(train_total, 1)
            avg_cls = train_cls / max(train_total, 1)
            train_acc = train_correct / max(train_total, 1)

            val_recon, val_cls, val_acc = self._validate_epoch(
                model, val_loader, mse_loss_fn, ce_loss_fn
            )
            val_total = recon_weight * val_recon + cls_weight * val_cls
            scheduler.step(val_total)

            if self._writer is not None:
                self._writer.add_scalars(
                    "recon_loss", {"train": avg_recon, "val": val_recon}, epoch
                )
                self._writer.add_scalars(
                    "cls_loss", {"train": avg_cls, "val": val_cls}, epoch
                )
                self._writer.add_scalars(
                    "accuracy", {"train": train_acc, "val": val_acc}, epoch
                )

            if epoch % 10 == 0 or epoch == 1:
                logger.info(
                    "Epoch %3d/%d — recon=%.4f cls=%.4f acc=%.4f | "
                    "val_recon=%.4f val_cls=%.4f val_acc=%.4f",
                    epoch,
                    epochs,
                    avg_recon,
                    avg_cls,
                    train_acc,
                    val_recon,
                    val_cls,
                    val_acc,
                )

            if val_total < best_val_loss:
                best_val_loss = val_total
                best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
                patience_counter = 0
            else:
                patience_counter += 1

            if checkpoint_dir is not None and epoch % checkpoint_every == 0:
                ckpt_path = Path(checkpoint_dir) / f"network_epoch_{epoch:04d}.pt"
                torch.save(
                    {
                        "epoch": epoch,
                        "model_state": model.state_dict(),
                        "optimizer_state": optimizer.state_dict(),
                        "val_loss": val_total,
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

        logger.info("Training complete — best combined val_loss=%.6f", best_val_loss)
        return model

    @torch.no_grad()
    def _validate_epoch(
        self,
        model: nn.Module,
        loader: DataLoader,
        mse_fn: nn.Module,
        ce_fn: nn.Module,
    ) -> tuple[float, float, float]:
        model.eval()
        total_recon = 0.0
        total_cls = 0.0
        correct = 0
        total = 0
        for batch_x, batch_y in loader:
            batch_x = batch_x.to(self._device, non_blocking=True)
            batch_y = batch_y.to(self._device, non_blocking=True)
            recon, _, logits = model(batch_x)
            total_recon += mse_fn(recon, batch_x).item() * batch_x.size(0)
            total_cls += ce_fn(logits, batch_y).item() * batch_x.size(0)
            correct += (logits.argmax(dim=1) == batch_y).sum().item()
            total += batch_x.size(0)
        n = max(total, 1)
        return total_recon / n, total_cls / n, correct / n

    # ------------------------------------------------------------------
    # Phase 1: Autoencoder-only training on normal traffic
    # ------------------------------------------------------------------

    def train_autoencoder(
        self,
        normal_loader: DataLoader,
        *,
        epochs: int = 50,
        grad_clip: float = 1.0,
    ) -> nn.Module:
        """Train autoencoder on normal traffic only (unsupervised).

        After this phase, the reconstruction error baseline is established.
        Samples with high reconstruction error are flagged as anomalous.

        Args:
            normal_loader: DataLoader yielding normal traffic tensors (X only).
            epochs: Training epochs.
            grad_clip: Max gradient norm.

        Returns:
            Model with trained encoder/decoder (classifier untrained).
        """
        model = self.build_model()
        # Only optimize encoder + decoder
        ae_params = list(model.encoder.parameters()) + list(model.decoder.parameters())
        optimizer = torch.optim.AdamW(
            ae_params, lr=self._lr, weight_decay=self._weight_decay
        )
        mse_fn = nn.MSELoss()

        logger.info(
            "Phase 1: Autoencoder training on normal traffic (%d epochs)", epochs
        )

        for epoch in range(1, epochs + 1):
            model.train()
            total_loss = 0.0
            total_samples = 0

            for (batch_x,) in normal_loader:
                batch_x = batch_x.to(self._device, non_blocking=True)

                optimizer.zero_grad(set_to_none=True)
                latent = model.encoder(batch_x)
                recon = model.decoder(latent)
                loss = mse_fn(recon, batch_x)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(ae_params, grad_clip)
                optimizer.step()

                total_loss += loss.item() * batch_x.size(0)
                total_samples += batch_x.size(0)

            avg_loss = total_loss / max(total_samples, 1)
            if epoch % 10 == 0 or epoch == 1:
                logger.info(
                    "AE Epoch %3d/%d — recon_loss=%.6f", epoch, epochs, avg_loss
                )

        logger.info("Autoencoder pretraining complete")
        return model

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    @torch.no_grad()
    def evaluate(
        self,
        model: nn.Module,
        test_loader: DataLoader,
    ) -> MetricsReport:
        """Evaluate model on test set with reconstruction + classification metrics.

        Args:
            model: Trained CortexNetworkNet.
            test_loader: DataLoader yielding (X, y) batches.

        Returns:
            MetricsReport with reconstruction, classification, and anomaly metrics.
        """
        from sklearn.metrics import roc_auc_score

        model.eval()
        model = model.to(self._device)

        all_preds: list[NDArray[np.int64]] = []
        all_labels: list[NDArray[np.int64]] = []
        all_recon_errors: list[NDArray[np.float64]] = []
        total_recon_loss = 0.0
        total_cls_loss = 0.0
        total_samples = 0

        mse_fn = nn.MSELoss()
        ce_fn = nn.CrossEntropyLoss()

        for batch_x, batch_y in test_loader:
            batch_x = batch_x.to(self._device, non_blocking=True)
            batch_y = batch_y.to(self._device, non_blocking=True)

            recon, _, logits = model(batch_x)
            total_recon_loss += mse_fn(recon, batch_x).item() * batch_x.size(0)
            total_cls_loss += ce_fn(logits, batch_y).item() * batch_x.size(0)
            total_samples += batch_x.size(0)

            recon_err = ((batch_x - recon) ** 2).mean(dim=1).cpu().numpy()
            all_recon_errors.append(recon_err)
            all_preds.append(logits.argmax(dim=1).cpu().numpy())
            all_labels.append(batch_y.cpu().numpy())

        y_pred = np.concatenate(all_preds)
        y_true = np.concatenate(all_labels)
        recon_errors = np.concatenate(all_recon_errors)

        # Anomaly AUC: normal (class 0) vs all others
        is_anomaly = (y_true != NetworkThreatClass.Normal).astype(np.int32)
        if len(np.unique(is_anomaly)) > 1:
            anomaly_auc = float(roc_auc_score(is_anomaly, recon_errors))
        else:
            anomaly_auc = 0.0

        # Confusion matrix
        cm = np.zeros((self._num_classes, self._num_classes), dtype=np.int64)
        for t, p in zip(y_true, y_pred):
            cm[t, p] += 1

        per_class_prec: dict[str, float] = {}
        per_class_rec: dict[str, float] = {}
        per_class_f1: dict[str, float] = {}
        f1_scores: list[float] = []

        for cls_idx in range(self._num_classes):
            cls_name = NetworkThreatClass(cls_idx).name
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

        n = max(total_samples, 1)
        accuracy = float(np.trace(cm)) / max(int(cm.sum()), 1)

        return MetricsReport(
            reconstruction_loss=total_recon_loss / n,
            classification_loss=total_cls_loss / n,
            accuracy=accuracy,
            per_class_precision=per_class_prec,
            per_class_recall=per_class_rec,
            per_class_f1=per_class_f1,
            macro_f1=float(np.mean(f1_scores)),
            anomaly_auc=anomaly_auc,
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
            model: Trained CortexNetworkNet.
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
            input_names=["network_features"],
            output_names=["reconstructed", "latent", "class_logits"],
            dynamic_axes={
                "network_features": {0: "batch_size"},
                "reconstructed": {0: "batch_size"},
                "latent": {0: "batch_size"},
                "class_logits": {0: "batch_size"},
            },
        )

        file_size_mb = output_path.stat().st_size / (1024 * 1024)
        logger.info(
            "Network model exported to %s (%.2f MB, opset=%d)",
            output_path,
            file_size_mb,
            opset,
        )

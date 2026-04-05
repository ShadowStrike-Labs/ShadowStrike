"""
PhantomCortex Evaluation Metrics
=================================

Comprehensive metrics calculator for security ML models. Provides standard
classification metrics plus security-specific measures: FPR at threshold,
detection rate at low-FPR operating points, family-wise breakdown,
evasion resistance scoring, and automated report generation.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path
from typing import Any, Optional, Union

import numpy as np
import pandas as pd
from numpy.typing import NDArray
from sklearn.metrics import (
    accuracy_score,
    auc,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

logger = logging.getLogger("PhantomCortex.Evaluation.Metrics")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ThresholdMetrics:
    """Metrics computed at a specific decision threshold."""

    threshold: float
    accuracy: float
    precision: float
    recall: float
    f1: float
    fpr: float
    fnr: float
    detection_rate: float

    def to_dict(self) -> dict[str, float]:
        return {
            "threshold": self.threshold,
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "fpr": self.fpr,
            "fnr": self.fnr,
            "detection_rate": self.detection_rate,
        }


@dataclass(frozen=True)
class OperatingPointMetrics:
    """Detection rate at a specific FPR operating point."""

    target_fpr: float
    actual_fpr: float
    detection_rate: float
    threshold: float


@dataclass(frozen=True)
class FamilyMetrics:
    """Per-malware-family detection metrics."""

    family_name: str
    count: int
    detection_rate: float
    mean_score: float
    min_score: float


@dataclass(frozen=True)
class FullMetricsReport:
    """Complete evaluation report for a security ML model."""

    # Standard metrics
    accuracy: float
    precision: float
    recall: float
    f1: float
    auc_roc: float
    auc_pr: float

    # Security-specific
    threshold_metrics: ThresholdMetrics
    operating_points: list[OperatingPointMetrics]
    family_metrics: Optional[list[FamilyMetrics]]

    # Evasion resistance
    evasion_resistance_score: Optional[float]

    # Curves (for visualization)
    fpr_curve: NDArray[np.float64] = field(repr=False)
    tpr_curve: NDArray[np.float64] = field(repr=False)
    precision_curve: NDArray[np.float64] = field(repr=False)
    recall_curve: NDArray[np.float64] = field(repr=False)
    confusion_mat: NDArray[np.int64] = field(repr=False)

    # Timing
    evaluation_time_sec: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "auc_roc": self.auc_roc,
            "auc_pr": self.auc_pr,
            "threshold_metrics": self.threshold_metrics.to_dict(),
            "operating_points": [
                {
                    "target_fpr": op.target_fpr,
                    "actual_fpr": op.actual_fpr,
                    "detection_rate": op.detection_rate,
                    "threshold": op.threshold,
                }
                for op in self.operating_points
            ],
            "family_metrics": (
                [
                    {
                        "family": fm.family_name,
                        "count": fm.count,
                        "detection_rate": fm.detection_rate,
                        "mean_score": fm.mean_score,
                        "min_score": fm.min_score,
                    }
                    for fm in self.family_metrics
                ]
                if self.family_metrics is not None
                else None
            ),
            "evasion_resistance_score": self.evasion_resistance_score,
            "evaluation_time_sec": round(self.evaluation_time_sec, 3),
        }


# ---------------------------------------------------------------------------
# MetricsCalculator
# ---------------------------------------------------------------------------


class MetricsCalculator:
    """Comprehensive metrics engine for security-focused ML evaluation.

    Computes standard classification metrics, security-specific operating
    point analysis, per-family breakdowns, evasion resistance scores,
    and generates markdown + JSON reports.
    """

    def __init__(
        self,
        *,
        threshold: float = 0.5,
        target_fprs: Optional[list[float]] = None,
    ) -> None:
        """Initialize metrics calculator.

        Args:
            threshold: Default decision threshold for binary predictions.
            target_fprs: FPR values at which to report detection rate.
                Defaults to [0.01, 0.001, 0.0001] (1%, 0.1%, 0.01%).
        """
        self._threshold = threshold
        self._target_fprs = target_fprs or [0.01, 0.001, 0.0001]

    # ------------------------------------------------------------------
    # Full evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        y_true: NDArray[np.int32],
        y_scores: NDArray[np.float64],
        *,
        threshold: Optional[float] = None,
        family_labels: Optional[NDArray[np.object_]] = None,
    ) -> FullMetricsReport:
        """Run full evaluation pipeline on binary classification outputs.

        Args:
            y_true: Ground truth labels (0 = benign, 1 = malicious).
            y_scores: Model output scores/probabilities [0, 1].
            threshold: Override default decision threshold.
            family_labels: Per-sample malware family names (for family-wise
                breakdown; may be None for benign samples).

        Returns:
            FullMetricsReport with comprehensive metrics.
        """
        start_time = time.monotonic()
        thresh = threshold if threshold is not None else self._threshold

        if len(y_true) != len(y_scores):
            raise ValueError(
                f"Length mismatch: y_true={len(y_true)}, y_scores={len(y_scores)}"
            )
        if len(y_true) == 0:
            raise ValueError("Empty evaluation set")

        y_pred = (y_scores >= thresh).astype(np.int32)

        # Standard metrics
        accuracy = float(accuracy_score(y_true, y_pred))
        precision = float(precision_score(y_true, y_pred, zero_division=0))
        recall = float(recall_score(y_true, y_pred, zero_division=0))
        f1 = float(f1_score(y_true, y_pred, zero_division=0))

        # ROC
        fpr_arr, tpr_arr, roc_thresholds = roc_curve(y_true, y_scores)
        auc_roc = float(auc(fpr_arr, tpr_arr))

        # PR
        prec_arr, rec_arr, _ = precision_recall_curve(y_true, y_scores)
        auc_pr = float(auc(rec_arr, prec_arr))

        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)

        # Threshold-specific metrics
        benign_mask = y_true == 0
        mal_mask = y_true == 1
        fpr_at_thresh = float((y_pred[benign_mask] == 1).mean()) if benign_mask.any() else 0.0
        fnr_at_thresh = float((y_pred[mal_mask] == 0).mean()) if mal_mask.any() else 0.0
        det_rate = float((y_pred[mal_mask] == 1).mean()) if mal_mask.any() else 0.0

        thresh_metrics = ThresholdMetrics(
            threshold=thresh,
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1=f1,
            fpr=fpr_at_thresh,
            fnr=fnr_at_thresh,
            detection_rate=det_rate,
        )

        # Operating points: detection rate at target FPR values
        operating_points = self._compute_operating_points(
            fpr_arr, tpr_arr, roc_thresholds
        )

        # Family-wise metrics
        family_met: Optional[list[FamilyMetrics]] = None
        if family_labels is not None:
            family_met = self._compute_family_metrics(
                y_true, y_scores, family_labels, thresh
            )

        elapsed = time.monotonic() - start_time

        report = FullMetricsReport(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1=f1,
            auc_roc=auc_roc,
            auc_pr=auc_pr,
            threshold_metrics=thresh_metrics,
            operating_points=operating_points,
            family_metrics=family_met,
            evasion_resistance_score=None,
            fpr_curve=fpr_arr,
            tpr_curve=tpr_arr,
            precision_curve=prec_arr,
            recall_curve=rec_arr,
            confusion_mat=cm,
            evaluation_time_sec=elapsed,
        )

        logger.info(
            "Evaluation: AUC-ROC=%.6f AUC-PR=%.6f Acc=%.4f F1=%.4f "
            "FPR@%.2f=%.6f DR=%.4f (%.2fs)",
            auc_roc,
            auc_pr,
            accuracy,
            f1,
            thresh,
            fpr_at_thresh,
            det_rate,
            elapsed,
        )

        return report

    # ------------------------------------------------------------------
    # Operating points
    # ------------------------------------------------------------------

    def _compute_operating_points(
        self,
        fpr_arr: NDArray[np.float64],
        tpr_arr: NDArray[np.float64],
        thresholds: NDArray[np.float64],
    ) -> list[OperatingPointMetrics]:
        """Find detection rate at each target FPR level."""
        results: list[OperatingPointMetrics] = []

        for target_fpr in self._target_fprs:
            # Find the largest threshold where FPR <= target
            valid = fpr_arr <= target_fpr
            if not valid.any():
                results.append(
                    OperatingPointMetrics(
                        target_fpr=target_fpr,
                        actual_fpr=0.0,
                        detection_rate=0.0,
                        threshold=1.0,
                    )
                )
                continue

            idx = np.where(valid)[0][-1]
            actual_fpr = float(fpr_arr[idx])
            det_rate = float(tpr_arr[idx])

            # thresholds array is 1 shorter than fpr/tpr arrays
            thresh_val = float(thresholds[min(idx, len(thresholds) - 1)])

            results.append(
                OperatingPointMetrics(
                    target_fpr=target_fpr,
                    actual_fpr=actual_fpr,
                    detection_rate=det_rate,
                    threshold=thresh_val,
                )
            )

            logger.info(
                "Operating point @ FPR≤%.4f: DR=%.6f (actual FPR=%.6f, thresh=%.4f)",
                target_fpr,
                det_rate,
                actual_fpr,
                thresh_val,
            )

        return results

    # ------------------------------------------------------------------
    # Family-wise breakdown
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_family_metrics(
        y_true: NDArray[np.int32],
        y_scores: NDArray[np.float64],
        family_labels: NDArray[np.object_],
        threshold: float,
    ) -> list[FamilyMetrics]:
        """Compute per-malware-family detection metrics."""
        y_pred = (y_scores >= threshold).astype(np.int32)
        mal_mask = y_true == 1

        families: dict[str, list[int]] = {}
        scores_by_family: dict[str, list[float]] = {}

        for i in range(len(y_true)):
            if not mal_mask[i]:
                continue
            fam = str(family_labels[i]) if family_labels[i] is not None else "Unknown"
            families.setdefault(fam, []).append(int(y_pred[i]))
            scores_by_family.setdefault(fam, []).append(float(y_scores[i]))

        results: list[FamilyMetrics] = []
        for fam_name in sorted(families.keys()):
            preds = np.array(families[fam_name])
            scores = np.array(scores_by_family[fam_name])
            det_rate = float(preds.mean())
            results.append(
                FamilyMetrics(
                    family_name=fam_name,
                    count=len(preds),
                    detection_rate=det_rate,
                    mean_score=float(scores.mean()),
                    min_score=float(scores.min()),
                )
            )

        return results

    # ------------------------------------------------------------------
    # Evasion resistance scoring
    # ------------------------------------------------------------------

    def compute_evasion_resistance(
        self,
        y_true: NDArray[np.int32],
        original_scores: NDArray[np.float64],
        perturbed_scores: NDArray[np.float64],
        *,
        threshold: Optional[float] = None,
    ) -> float:
        """Score model's resistance to adversarial perturbation.

        Evasion resistance = 1 - (fraction of malicious samples that
        were correctly detected before perturbation but evade after).

        Args:
            y_true: Ground truth labels.
            original_scores: Model scores on unmodified samples.
            perturbed_scores: Model scores on adversarially perturbed samples.
            threshold: Decision threshold.

        Returns:
            Evasion resistance score in [0, 1] (higher = better).
        """
        thresh = threshold if threshold is not None else self._threshold
        mal_mask = y_true == 1
        if not mal_mask.any():
            return 1.0

        orig_detected = original_scores[mal_mask] >= thresh
        pert_detected = perturbed_scores[mal_mask] >= thresh

        # Samples that were detected but now evade
        evaded = orig_detected & ~pert_detected
        evasion_rate = float(evaded.sum()) / max(float(orig_detected.sum()), 1.0)
        resistance = 1.0 - evasion_rate

        logger.info(
            "Evasion resistance: %.4f (%.0f/%d originally detected, %d evaded)",
            resistance,
            orig_detected.sum(),
            mal_mask.sum(),
            evaded.sum(),
        )
        return resistance

    # ------------------------------------------------------------------
    # Optimal threshold search
    # ------------------------------------------------------------------

    @staticmethod
    def find_optimal_threshold(
        y_true: NDArray[np.int32],
        y_scores: NDArray[np.float64],
        *,
        max_fpr: float = 0.001,
    ) -> float:
        """Find highest detection rate threshold subject to FPR constraint.

        Args:
            y_true: Ground truth labels.
            y_scores: Model output scores.
            max_fpr: Maximum acceptable false positive rate.

        Returns:
            Optimal threshold value.
        """
        fpr_arr, tpr_arr, thresholds = roc_curve(y_true, y_scores)
        valid = fpr_arr <= max_fpr
        if not valid.any():
            logger.warning(
                "No threshold achieves FPR ≤ %.4f; returning 1.0", max_fpr
            )
            return 1.0

        idx = np.where(valid)[0][-1]
        optimal = float(thresholds[min(idx, len(thresholds) - 1)])
        logger.info(
            "Optimal threshold for FPR ≤ %.4f: %.6f (DR=%.6f, actual FPR=%.6f)",
            max_fpr,
            optimal,
            float(tpr_arr[idx]),
            float(fpr_arr[idx]),
        )
        return optimal

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    @staticmethod
    def generate_markdown_report(report: FullMetricsReport) -> str:
        """Generate a human-readable markdown evaluation report.

        Args:
            report: FullMetricsReport to format.

        Returns:
            Markdown-formatted string.
        """
        buf = StringIO()
        w = buf.write

        w("# PhantomCortex Model Evaluation Report\n\n")

        w("## Standard Metrics\n\n")
        w(f"| Metric    | Value    |\n")
        w(f"|-----------|----------|\n")
        w(f"| Accuracy  | {report.accuracy:.6f} |\n")
        w(f"| Precision | {report.precision:.6f} |\n")
        w(f"| Recall    | {report.recall:.6f} |\n")
        w(f"| F1        | {report.f1:.6f} |\n")
        w(f"| AUC-ROC   | {report.auc_roc:.6f} |\n")
        w(f"| AUC-PR    | {report.auc_pr:.6f} |\n\n")

        tm = report.threshold_metrics
        w(f"## Threshold Metrics (t={tm.threshold:.4f})\n\n")
        w(f"| Metric         | Value    |\n")
        w(f"|----------------|----------|\n")
        w(f"| FPR            | {tm.fpr:.6f} |\n")
        w(f"| FNR            | {tm.fnr:.6f} |\n")
        w(f"| Detection Rate | {tm.detection_rate:.6f} |\n\n")

        w("## Operating Points\n\n")
        w("| Target FPR | Actual FPR | Detection Rate | Threshold |\n")
        w("|------------|------------|----------------|-----------|\n")
        for op in report.operating_points:
            w(
                f"| {op.target_fpr:.4f}    | {op.actual_fpr:.6f}  | "
                f"{op.detection_rate:.6f}      | {op.threshold:.4f}   |\n"
            )
        w("\n")

        if report.family_metrics:
            w("## Family-wise Detection\n\n")
            w("| Family | Count | Detection Rate | Mean Score | Min Score |\n")
            w("|--------|-------|----------------|------------|----------|\n")
            for fm in report.family_metrics:
                w(
                    f"| {fm.family_name} | {fm.count} | "
                    f"{fm.detection_rate:.4f} | {fm.mean_score:.4f} | "
                    f"{fm.min_score:.4f} |\n"
                )
            w("\n")

        if report.evasion_resistance_score is not None:
            w(f"## Evasion Resistance: {report.evasion_resistance_score:.4f}\n\n")

        w("## Confusion Matrix\n\n")
        w("```\n")
        w(str(report.confusion_mat))
        w("\n```\n\n")

        w(f"*Evaluation completed in {report.evaluation_time_sec:.3f}s*\n")

        return buf.getvalue()

    @staticmethod
    def generate_json_report(report: FullMetricsReport) -> str:
        """Generate a machine-readable JSON evaluation report.

        Args:
            report: FullMetricsReport to serialize.

        Returns:
            Pretty-printed JSON string.
        """
        return json.dumps(report.to_dict(), indent=2, default=str)

    def save_reports(
        self,
        report: FullMetricsReport,
        output_dir: Union[str, Path],
        *,
        prefix: str = "evaluation",
    ) -> tuple[Path, Path]:
        """Save both markdown and JSON reports to disk.

        Args:
            report: FullMetricsReport to save.
            output_dir: Directory for report files.
            prefix: Filename prefix.

        Returns:
            Tuple of (markdown_path, json_path).
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        md_path = out / f"{prefix}_report.md"
        json_path = out / f"{prefix}_report.json"

        md_path.write_text(self.generate_markdown_report(report), encoding="utf-8")
        json_path.write_text(self.generate_json_report(report), encoding="utf-8")

        logger.info("Reports saved: %s, %s", md_path, json_path)
        return md_path, json_path

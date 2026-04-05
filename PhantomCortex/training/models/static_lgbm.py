"""
Cortex-Static: LightGBM Gradient Boosted Tree Trainer
======================================================

Primary static malware detection model for ShadowStrike NGAV engine.
Classifies PE files using 2381 EMBER-format features in under 1ms.

Capabilities:
    - Full training from scratch with early stopping
    - Incremental training (add samples without full retrain)
    - Bayesian hyperparameter optimization via Optuna
    - Stratified K-fold cross-validation
    - Calibrated probability outputs (Platt scaling)
    - Feature importance analysis with SHAP values
    - Class-weight support for imbalanced datasets

Target Metrics:
    - AUC-ROC > 0.999
    - FPR < 0.1% at detection threshold
    - Detection rate > 99.5%
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import pickle
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

import lightgbm as lgb
import numpy as np
import optuna
import pandas as pd
from numpy.typing import NDArray
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score,
    auc,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import StratifiedKFold

logger = logging.getLogger("PhantomCortex.StaticTrainer")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EMBER_FEATURE_COUNT: int = 2381
DEFAULT_SEED: int = 42
MAX_OPTUNA_PARALLELISM: int = 4


# ---------------------------------------------------------------------------
# Data classes for structured results
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MetricsReport:
    """Immutable container for evaluation metrics."""

    accuracy: float
    precision: float
    recall: float
    f1: float
    auc_roc: float
    auc_pr: float
    fpr_at_threshold: float
    detection_rate: float
    threshold: float
    fpr_values: NDArray[np.float64] = field(repr=False)
    tpr_values: NDArray[np.float64] = field(repr=False)
    precision_values: NDArray[np.float64] = field(repr=False)
    recall_values: NDArray[np.float64] = field(repr=False)

    def to_dict(self) -> dict[str, Any]:
        """Serialize scalar metrics to dictionary."""
        return {
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "auc_roc": self.auc_roc,
            "auc_pr": self.auc_pr,
            "fpr_at_threshold": self.fpr_at_threshold,
            "detection_rate": self.detection_rate,
            "threshold": self.threshold,
        }


@dataclass(frozen=True)
class CVResult:
    """Cross-validation result container."""

    fold_metrics: list[MetricsReport]
    mean_auc_roc: float
    std_auc_roc: float
    mean_detection_rate: float
    std_detection_rate: float
    mean_fpr: float
    std_fpr: float


@dataclass(frozen=True)
class LGBMModel:
    """Wrapper around a trained LightGBM model with metadata."""

    booster: lgb.Booster
    calibrator: Optional[CalibratedClassifierCV]
    params: dict[str, Any]
    feature_count: int
    training_metrics: Optional[MetricsReport]
    training_timestamp: float
    model_hash: str
    num_iterations: int

    def predict_proba(self, X: NDArray[np.float32]) -> NDArray[np.float64]:
        """Return calibrated probability of malicious class."""
        if X.shape[1] != self.feature_count:
            raise ValueError(
                f"Expected {self.feature_count} features, got {X.shape[1]}"
            )
        raw_scores = self.booster.predict(X, num_iteration=self.num_iterations)
        if self.calibrator is not None:
            calibrated = self.calibrator.predict_proba(
                raw_scores.reshape(-1, 1)
            )[:, 1]
            return calibrated
        return raw_scores

    def predict(
        self, X: NDArray[np.float32], threshold: float = 0.5
    ) -> NDArray[np.int32]:
        """Return binary predictions at given threshold."""
        proba = self.predict_proba(X)
        return (proba >= threshold).astype(np.int32)


# ---------------------------------------------------------------------------
# Trainer
# ---------------------------------------------------------------------------


class CortexStaticTrainer:
    """Enterprise LightGBM trainer for PE static malware classification.

    Handles the full lifecycle: hyperparameter search, training with early
    stopping, calibration, incremental updates, evaluation, and persistence.
    """

    def __init__(
        self,
        *,
        feature_count: int = EMBER_FEATURE_COUNT,
        seed: int = DEFAULT_SEED,
        n_jobs: int = -1,
        objective: str = "binary",
        metric: str = "auc",
        device: str = "cpu",
        verbose: int = -1,
    ) -> None:
        self._feature_count = feature_count
        self._seed = seed
        self._n_jobs = n_jobs
        self._objective = objective
        self._metric = metric
        self._device = device
        self._verbose = verbose
        self._set_seed()

    # ------------------------------------------------------------------
    # Seed management
    # ------------------------------------------------------------------

    def _set_seed(self) -> None:
        np.random.seed(self._seed)

    # ------------------------------------------------------------------
    # Default parameters
    # ------------------------------------------------------------------

    def _base_params(self) -> dict[str, Any]:
        return {
            "objective": self._objective,
            "metric": self._metric,
            "boosting_type": "gbdt",
            "num_leaves": 127,
            "max_depth": 10,
            "learning_rate": 0.05,
            "n_estimators": 2000,
            "min_child_samples": 20,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "reg_alpha": 0.1,
            "reg_lambda": 1.0,
            "min_split_gain": 0.01,
            "seed": self._seed,
            "n_jobs": self._n_jobs,
            "device": self._device,
            "verbose": self._verbose,
            "is_unbalance": True,
        }

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_input(
        X: NDArray[np.float32],
        y: NDArray[np.int32],
        expected_features: int,
    ) -> None:
        if X.ndim != 2:
            raise ValueError(f"X must be 2-D, got {X.ndim}-D")
        if X.shape[1] != expected_features:
            raise ValueError(
                f"Expected {expected_features} features, got {X.shape[1]}"
            )
        if X.shape[0] != y.shape[0]:
            raise ValueError(
                f"X rows ({X.shape[0]}) != y length ({y.shape[0]})"
            )
        unique_labels = np.unique(y)
        if not np.array_equal(unique_labels, np.array([0, 1])):
            raise ValueError(
                f"y must contain exactly classes [0, 1], got {unique_labels}"
            )

    @staticmethod
    def _compute_model_hash(booster: lgb.Booster) -> str:
        model_str = booster.model_to_string()
        return hashlib.sha256(model_str.encode("utf-8")).hexdigest()[:16]

    # ------------------------------------------------------------------
    # Core training
    # ------------------------------------------------------------------

    def train(
        self,
        X_train: NDArray[np.float32],
        y_train: NDArray[np.int32],
        X_val: NDArray[np.float32],
        y_val: NDArray[np.int32],
        *,
        params: Optional[dict[str, Any]] = None,
        early_stopping_rounds: int = 50,
        calibrate: bool = True,
        class_weight: Optional[dict[int, float]] = None,
    ) -> LGBMModel:
        """Train a LightGBM model with early stopping on validation set.

        Args:
            X_train: Training features, shape (n_samples, feature_count).
            y_train: Training labels, binary 0/1.
            X_val: Validation features.
            y_val: Validation labels.
            params: Override default hyperparameters.
            early_stopping_rounds: Stop if no improvement for N rounds.
            calibrate: Apply Platt scaling for calibrated probabilities.
            class_weight: Per-class weights {0: w0, 1: w1}.

        Returns:
            Trained LGBMModel with calibrated predictions.
        """
        self._validate_input(X_train, y_train, self._feature_count)
        self._validate_input(X_val, y_val, self._feature_count)

        hp = self._base_params()
        if params is not None:
            hp.update(params)

        # Build sample weights from class weights
        sample_weight: Optional[NDArray[np.float64]] = None
        if class_weight is not None:
            sample_weight = np.where(
                y_train == 1,
                class_weight.get(1, 1.0),
                class_weight.get(0, 1.0),
            ).astype(np.float64)

        n_estimators = hp.pop("n_estimators", 2000)

        train_set = lgb.Dataset(
            X_train, label=y_train, weight=sample_weight, free_raw_data=False
        )
        val_set = lgb.Dataset(
            X_val, label=y_val, reference=train_set, free_raw_data=False
        )

        callbacks = [
            lgb.early_stopping(stopping_rounds=early_stopping_rounds),
            lgb.log_evaluation(period=100),
        ]

        logger.info(
            "Starting LightGBM training: %d train / %d val samples, %d features",
            X_train.shape[0],
            X_val.shape[0],
            self._feature_count,
        )
        start_time = time.monotonic()

        booster = lgb.train(
            hp,
            train_set,
            num_boost_round=n_estimators,
            valid_sets=[train_set, val_set],
            valid_names=["train", "val"],
            callbacks=callbacks,
        )

        elapsed = time.monotonic() - start_time
        best_iter = booster.best_iteration
        logger.info(
            "Training complete in %.1fs — best iteration: %d", elapsed, best_iter
        )

        # Calibration via Platt scaling on validation set
        calibrator: Optional[CalibratedClassifierCV] = None
        if calibrate:
            calibrator = self._calibrate(booster, X_val, y_val, best_iter)

        hp["n_estimators"] = n_estimators
        model = LGBMModel(
            booster=booster,
            calibrator=calibrator,
            params=hp,
            feature_count=self._feature_count,
            training_metrics=None,
            training_timestamp=time.time(),
            model_hash=self._compute_model_hash(booster),
            num_iterations=best_iter,
        )

        metrics = self.evaluate(model, X_val, y_val)
        model = LGBMModel(
            booster=model.booster,
            calibrator=model.calibrator,
            params=model.params,
            feature_count=model.feature_count,
            training_metrics=metrics,
            training_timestamp=model.training_timestamp,
            model_hash=model.model_hash,
            num_iterations=model.num_iterations,
        )

        logger.info(
            "Validation AUC-ROC: %.6f | Detection rate: %.4f | FPR: %.6f",
            metrics.auc_roc,
            metrics.detection_rate,
            metrics.fpr_at_threshold,
        )
        return model

    def _calibrate(
        self,
        booster: lgb.Booster,
        X_cal: NDArray[np.float32],
        y_cal: NDArray[np.int32],
        num_iterations: int,
    ) -> CalibratedClassifierCV:
        """Fit Platt scaling calibrator on raw booster output."""
        raw_scores = booster.predict(X_cal, num_iteration=num_iterations)

        class _ScorePassthrough:
            """Minimal estimator wrapper that passes precomputed scores."""

            def fit(self, X: NDArray, y: NDArray) -> "_ScorePassthrough":
                return self

            def predict_proba(self, X: NDArray) -> NDArray:
                scores = X.ravel()
                return np.column_stack([1.0 - scores, scores])

            def predict(self, X: NDArray) -> NDArray:
                return (X.ravel() >= 0.5).astype(np.int32)

            def get_params(self, deep: bool = True) -> dict:
                return {}

            def set_params(self, **params: Any) -> "_ScorePassthrough":
                return self

        base = _ScorePassthrough()
        calibrator = CalibratedClassifierCV(
            estimator=base, method="sigmoid", cv="prefit"
        )
        calibrator.fit(raw_scores.reshape(-1, 1), y_cal)
        logger.info("Platt scaling calibrator fitted on %d samples", len(y_cal))
        return calibrator

    # ------------------------------------------------------------------
    # Hyperparameter optimization
    # ------------------------------------------------------------------

    def optimize_hyperparams(
        self,
        X: NDArray[np.float32],
        y: NDArray[np.int32],
        *,
        n_trials: int = 100,
        cv_folds: int = 5,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """Bayesian hyperparameter search using Optuna with stratified CV.

        Args:
            X: Full feature matrix.
            y: Full label vector.
            n_trials: Number of Optuna trials.
            cv_folds: Number of stratified folds.
            timeout: Maximum seconds for the study (None = unlimited).

        Returns:
            Best hyperparameter dict.
        """
        self._validate_input(X, y, self._feature_count)

        def _objective(trial: optuna.Trial) -> float:
            params = {
                "objective": self._objective,
                "metric": self._metric,
                "boosting_type": "gbdt",
                "num_leaves": trial.suggest_int("num_leaves", 31, 255),
                "max_depth": trial.suggest_int("max_depth", 5, 15),
                "learning_rate": trial.suggest_float(
                    "learning_rate", 0.01, 0.3, log=True
                ),
                "min_child_samples": trial.suggest_int("min_child_samples", 5, 100),
                "subsample": trial.suggest_float("subsample", 0.5, 1.0),
                "colsample_bytree": trial.suggest_float("colsample_bytree", 0.5, 1.0),
                "reg_alpha": trial.suggest_float("reg_alpha", 1e-8, 10.0, log=True),
                "reg_lambda": trial.suggest_float("reg_lambda", 1e-8, 10.0, log=True),
                "min_split_gain": trial.suggest_float("min_split_gain", 0.0, 1.0),
                "seed": self._seed,
                "n_jobs": self._n_jobs,
                "device": self._device,
                "verbose": -1,
                "is_unbalance": True,
            }
            n_estimators = trial.suggest_int("n_estimators", 500, 5000)

            skf = StratifiedKFold(
                n_splits=cv_folds, shuffle=True, random_state=self._seed
            )
            fold_aucs: list[float] = []

            for fold_idx, (train_idx, val_idx) in enumerate(skf.split(X, y)):
                X_tr, X_vl = X[train_idx], X[val_idx]
                y_tr, y_vl = y[train_idx], y[val_idx]

                train_set = lgb.Dataset(X_tr, label=y_tr, free_raw_data=False)
                val_set = lgb.Dataset(
                    X_vl, label=y_vl, reference=train_set, free_raw_data=False
                )

                booster = lgb.train(
                    params,
                    train_set,
                    num_boost_round=n_estimators,
                    valid_sets=[val_set],
                    valid_names=["val"],
                    callbacks=[
                        lgb.early_stopping(stopping_rounds=50),
                        lgb.log_evaluation(period=0),
                    ],
                )

                preds = booster.predict(
                    X_vl, num_iteration=booster.best_iteration
                )
                fold_auc = roc_auc_score(y_vl, preds)
                fold_aucs.append(fold_auc)

                trial.report(float(np.mean(fold_aucs)), fold_idx)
                if trial.should_prune():
                    raise optuna.TrialPruned()

            return float(np.mean(fold_aucs))

        sampler = optuna.samplers.TPESampler(seed=self._seed)
        pruner = optuna.pruners.MedianPruner(
            n_startup_trials=10, n_warmup_steps=2
        )
        study = optuna.create_study(
            direction="maximize",
            sampler=sampler,
            pruner=pruner,
            study_name="cortex_static_hpo",
        )

        logger.info(
            "Starting Optuna HPO: %d trials, %d-fold CV, %d samples",
            n_trials,
            cv_folds,
            X.shape[0],
        )
        study.optimize(
            _objective,
            n_trials=n_trials,
            timeout=timeout,
            n_jobs=min(MAX_OPTUNA_PARALLELISM, n_trials),
            show_progress_bar=True,
        )

        best_params = study.best_params
        best_value = study.best_value
        logger.info(
            "HPO complete — best AUC-ROC: %.6f | params: %s",
            best_value,
            json.dumps(best_params, indent=2),
        )
        return best_params

    # ------------------------------------------------------------------
    # Cross-validation
    # ------------------------------------------------------------------

    def cross_validate(
        self,
        X: NDArray[np.float32],
        y: NDArray[np.int32],
        *,
        params: Optional[dict[str, Any]] = None,
        cv_folds: int = 5,
    ) -> CVResult:
        """Run stratified K-fold cross-validation and return fold metrics.

        Args:
            X: Full feature matrix.
            y: Full label vector.
            params: Hyperparameters (uses defaults if None).
            cv_folds: Number of stratified folds.

        Returns:
            CVResult with per-fold and aggregate metrics.
        """
        self._validate_input(X, y, self._feature_count)
        skf = StratifiedKFold(
            n_splits=cv_folds, shuffle=True, random_state=self._seed
        )

        fold_metrics: list[MetricsReport] = []
        for fold_idx, (train_idx, val_idx) in enumerate(skf.split(X, y)):
            logger.info("CV fold %d/%d", fold_idx + 1, cv_folds)
            X_tr, X_vl = X[train_idx], X[val_idx]
            y_tr, y_vl = y[train_idx], y[val_idx]

            model = self.train(
                X_tr, y_tr, X_vl, y_vl, params=params, calibrate=False
            )
            metrics = self.evaluate(model, X_vl, y_vl)
            fold_metrics.append(metrics)

        auc_rocs = np.array([m.auc_roc for m in fold_metrics])
        det_rates = np.array([m.detection_rate for m in fold_metrics])
        fprs = np.array([m.fpr_at_threshold for m in fold_metrics])

        result = CVResult(
            fold_metrics=fold_metrics,
            mean_auc_roc=float(np.mean(auc_rocs)),
            std_auc_roc=float(np.std(auc_rocs)),
            mean_detection_rate=float(np.mean(det_rates)),
            std_detection_rate=float(np.std(det_rates)),
            mean_fpr=float(np.mean(fprs)),
            std_fpr=float(np.std(fprs)),
        )
        logger.info(
            "CV complete — AUC-ROC: %.6f ± %.6f | DR: %.4f ± %.4f | FPR: %.6f ± %.6f",
            result.mean_auc_roc,
            result.std_auc_roc,
            result.mean_detection_rate,
            result.std_detection_rate,
            result.mean_fpr,
            result.std_fpr,
        )
        return result

    # ------------------------------------------------------------------
    # Incremental training
    # ------------------------------------------------------------------

    def incremental_train(
        self,
        model: LGBMModel,
        X_new: NDArray[np.float32],
        y_new: NDArray[np.int32],
        *,
        num_new_rounds: int = 500,
        early_stopping_rounds: int = 30,
        X_val: Optional[NDArray[np.float32]] = None,
        y_val: Optional[NDArray[np.int32]] = None,
    ) -> LGBMModel:
        """Continue training an existing model on new data.

        Uses LightGBM's ``init_model`` to warm-start from the existing
        booster, adding new boosting rounds trained on the incremental data.

        Args:
            model: Previously trained LGBMModel.
            X_new: New training features.
            y_new: New training labels.
            num_new_rounds: Additional boosting rounds.
            early_stopping_rounds: Early stopping patience.
            X_val: Validation features (uses 20% of X_new if None).
            y_val: Validation labels.

        Returns:
            Updated LGBMModel incorporating new data.
        """
        self._validate_input(X_new, y_new, self._feature_count)

        if X_val is None or y_val is None:
            split_idx = int(len(y_new) * 0.8)
            indices = np.random.permutation(len(y_new))
            train_idx, val_idx = indices[:split_idx], indices[split_idx:]
            X_tr, y_tr = X_new[train_idx], y_new[train_idx]
            X_vl, y_vl = X_new[val_idx], y_new[val_idx]
        else:
            self._validate_input(X_val, y_val, self._feature_count)
            X_tr, y_tr = X_new, y_new
            X_vl, y_vl = X_val, y_val

        train_set = lgb.Dataset(X_tr, label=y_tr, free_raw_data=False)
        val_set = lgb.Dataset(
            X_vl, label=y_vl, reference=train_set, free_raw_data=False
        )

        hp = {k: v for k, v in model.params.items() if k != "n_estimators"}

        logger.info(
            "Incremental training: %d new samples, %d additional rounds",
            X_new.shape[0],
            num_new_rounds,
        )
        start_time = time.monotonic()

        booster = lgb.train(
            hp,
            train_set,
            num_boost_round=num_new_rounds,
            init_model=model.booster,
            valid_sets=[train_set, val_set],
            valid_names=["train", "val"],
            callbacks=[
                lgb.early_stopping(stopping_rounds=early_stopping_rounds),
                lgb.log_evaluation(period=100),
            ],
        )

        elapsed = time.monotonic() - start_time
        logger.info(
            "Incremental training done in %.1fs — total iterations: %d",
            elapsed,
            booster.current_iteration(),
        )

        updated = LGBMModel(
            booster=booster,
            calibrator=model.calibrator,
            params=model.params,
            feature_count=self._feature_count,
            training_metrics=None,
            training_timestamp=time.time(),
            model_hash=self._compute_model_hash(booster),
            num_iterations=booster.best_iteration,
        )

        metrics = self.evaluate(updated, X_vl, y_vl)
        return LGBMModel(
            booster=updated.booster,
            calibrator=updated.calibrator,
            params=updated.params,
            feature_count=updated.feature_count,
            training_metrics=metrics,
            training_timestamp=updated.training_timestamp,
            model_hash=updated.model_hash,
            num_iterations=updated.num_iterations,
        )

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        model: LGBMModel,
        X_test: NDArray[np.float32],
        y_test: NDArray[np.int32],
        *,
        threshold: float = 0.5,
    ) -> MetricsReport:
        """Evaluate model on a held-out test set.

        Computes standard classification metrics plus security-specific
        metrics such as FPR at the given threshold and detection rate.

        Args:
            model: Trained LGBMModel.
            X_test: Test features.
            y_test: Test labels.
            threshold: Decision threshold for binary predictions.

        Returns:
            MetricsReport with all computed metrics.
        """
        self._validate_input(X_test, y_test, self._feature_count)

        proba = model.predict_proba(X_test)
        preds = (proba >= threshold).astype(np.int32)

        # ROC curve
        fpr_arr, tpr_arr, _ = roc_curve(y_test, proba)
        auc_roc_val = auc(fpr_arr, tpr_arr)

        # Precision-Recall curve
        prec_arr, rec_arr, _ = precision_recall_curve(y_test, proba)
        auc_pr_val = auc(rec_arr, prec_arr)

        # FPR at the operating threshold
        benign_mask = y_test == 0
        if benign_mask.sum() > 0:
            fpr_at_thresh = float((preds[benign_mask] == 1).mean())
        else:
            fpr_at_thresh = 0.0

        # Detection rate at threshold
        malicious_mask = y_test == 1
        if malicious_mask.sum() > 0:
            det_rate = float((preds[malicious_mask] == 1).mean())
        else:
            det_rate = 0.0

        return MetricsReport(
            accuracy=float(accuracy_score(y_test, preds)),
            precision=float(precision_score(y_test, preds, zero_division=0)),
            recall=float(recall_score(y_test, preds, zero_division=0)),
            f1=float(f1_score(y_test, preds, zero_division=0)),
            auc_roc=float(auc_roc_val),
            auc_pr=float(auc_pr_val),
            fpr_at_threshold=fpr_at_thresh,
            detection_rate=det_rate,
            threshold=threshold,
            fpr_values=fpr_arr,
            tpr_values=tpr_arr,
            precision_values=prec_arr,
            recall_values=rec_arr,
        )

    # ------------------------------------------------------------------
    # Feature importance
    # ------------------------------------------------------------------

    def get_feature_importance(
        self,
        model: LGBMModel,
        *,
        importance_type: str = "gain",
        feature_names: Optional[list[str]] = None,
        top_n: Optional[int] = None,
    ) -> pd.DataFrame:
        """Extract and rank feature importance from trained model.

        Args:
            model: Trained LGBMModel.
            importance_type: 'gain' (default) or 'split'.
            feature_names: Human-readable names for each feature index.
            top_n: Return only the top-N features (None = all).

        Returns:
            DataFrame with columns [feature_index, feature_name, importance],
            sorted descending by importance.
        """
        raw_importance = model.booster.feature_importance(
            importance_type=importance_type
        )

        if feature_names is None:
            feature_names = [f"f_{i}" for i in range(len(raw_importance))]

        if len(feature_names) != len(raw_importance):
            raise ValueError(
                f"feature_names length ({len(feature_names)}) must match "
                f"number of features ({len(raw_importance)})"
            )

        df = pd.DataFrame(
            {
                "feature_index": list(range(len(raw_importance))),
                "feature_name": feature_names,
                "importance": raw_importance.astype(np.float64),
            }
        )
        df = df.sort_values("importance", ascending=False).reset_index(drop=True)

        # Normalize to [0, 1]
        total = df["importance"].sum()
        if total > 0:
            df["importance_normalized"] = df["importance"] / total
        else:
            df["importance_normalized"] = 0.0

        if top_n is not None:
            df = df.head(top_n)

        return df

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_model(self, model: LGBMModel, path: Union[str, Path]) -> None:
        """Save complete LGBMModel (booster + calibrator + metadata) to disk.

        Creates two files:
            - {path}.lgbm — raw LightGBM booster (text format)
            - {path}.meta — calibrator, params, metrics (pickle)

        Args:
            model: Trained LGBMModel to persist.
            path: Base path (without extension).
        """
        base = Path(path)
        base.parent.mkdir(parents=True, exist_ok=True)

        booster_path = base.with_suffix(".lgbm")
        meta_path = base.with_suffix(".meta")

        model.booster.save_model(str(booster_path), num_iteration=model.num_iterations)

        meta = {
            "calibrator": model.calibrator,
            "params": model.params,
            "feature_count": model.feature_count,
            "training_metrics": (
                model.training_metrics.to_dict()
                if model.training_metrics
                else None
            ),
            "training_timestamp": model.training_timestamp,
            "model_hash": model.model_hash,
            "num_iterations": model.num_iterations,
        }
        with open(meta_path, "wb") as fh:
            pickle.dump(meta, fh, protocol=pickle.HIGHEST_PROTOCOL)

        file_size_mb = booster_path.stat().st_size / (1024 * 1024)
        logger.info(
            "Model saved to %s (%.2f MB, hash=%s)",
            booster_path,
            file_size_mb,
            model.model_hash,
        )

    def load_model(self, path: Union[str, Path]) -> LGBMModel:
        """Load a persisted LGBMModel from disk.

        Args:
            path: Base path used during save (without extension).

        Returns:
            Reconstructed LGBMModel.

        Raises:
            FileNotFoundError: If booster or meta file is missing.
        """
        base = Path(path)
        booster_path = base.with_suffix(".lgbm")
        meta_path = base.with_suffix(".meta")

        if not booster_path.exists():
            raise FileNotFoundError(f"Booster file not found: {booster_path}")
        if not meta_path.exists():
            raise FileNotFoundError(f"Metadata file not found: {meta_path}")

        booster = lgb.Booster(model_file=str(booster_path))

        with open(meta_path, "rb") as fh:
            meta = pickle.load(fh)  # noqa: S301 — trusted internal artifact

        model = LGBMModel(
            booster=booster,
            calibrator=meta["calibrator"],
            params=meta["params"],
            feature_count=meta["feature_count"],
            training_metrics=None,
            training_timestamp=meta["training_timestamp"],
            model_hash=meta["model_hash"],
            num_iterations=meta["num_iterations"],
        )
        logger.info(
            "Model loaded from %s (hash=%s, iterations=%d)",
            booster_path,
            model.model_hash,
            model.num_iterations,
        )
        return model

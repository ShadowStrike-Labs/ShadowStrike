"""
Cortex-Static Training Runner
==============================

End-to-end training pipeline for the ShadowStrike Cortex-Static malware
detection model using the EMBER 2018 dataset and LightGBM gradient boosted
trees.

Stages:
    1. Load EMBER 2018 dataset (download if needed)
    2. Bayesian hyperparameter optimisation (Optuna, stratified CV)
    3. Train final model with best parameters + early stopping
    4. Evaluate on held-out test set
    5. Export to ONNX (opset 17)
    6. Quantize to INT8 (dynamic quantization)
    7. Persist model, metrics, and quantization report

Usage:
    python -m PhantomCortex.training.scripts.train_static
    python -m PhantomCortex.training.scripts.train_static --data-dir /data/ember
    python -m PhantomCortex.training.scripts.train_static --hpo-trials 50 --hpo-timeout 1800
    python -m PhantomCortex.training.scripts.train_static --skip-hpo --params '{"num_leaves":127}'
    python -m PhantomCortex.training.scripts.train_static --output-dir ./artifacts
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np
import structlog
from sklearn.model_selection import StratifiedShuffleSplit

# ---------------------------------------------------------------------------
# Structured logging configuration — must run before any logger calls
# ---------------------------------------------------------------------------

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(0),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

log = structlog.get_logger("phantomcortex.train_static")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCRIPT_DIR = Path(__file__).resolve().parent
_TRAINING_DIR = _SCRIPT_DIR.parent
_DEFAULT_OUTPUT_DIR = _TRAINING_DIR / "data" / "models" / "cortex_static"

FEATURE_COUNT: int = 2381
VALIDATION_FRACTION: float = 0.10
DEFAULT_HPO_TRIALS: int = 100
DEFAULT_HPO_CV_FOLDS: int = 5
DEFAULT_HPO_TIMEOUT: int = 3600
DEFAULT_THRESHOLD: float = 0.5


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="train_static",
        description=(
            "Train Cortex-Static LightGBM malware classifier on the EMBER "
            "2018 dataset with Optuna hyperparameter optimisation, ONNX "
            "export, and INT8 quantization."
        ),
    )

    # --- data ---
    parser.add_argument(
        "--data-dir",
        type=str,
        default=None,
        help=(
            "Path to directory containing the EMBER dataset (or where it "
            "should be downloaded). Default: training/data/raw"
        ),
    )
    parser.add_argument(
        "--no-download",
        action="store_true",
        help="Do not download EMBER automatically; fail if absent.",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable NPZ cache for the EMBER loader.",
    )

    # --- hyperparameter optimisation ---
    parser.add_argument(
        "--skip-hpo",
        action="store_true",
        help="Skip Optuna HPO and train with default (or --params) values.",
    )
    parser.add_argument(
        "--hpo-trials",
        type=int,
        default=DEFAULT_HPO_TRIALS,
        help=f"Number of Optuna trials (default: {DEFAULT_HPO_TRIALS}).",
    )
    parser.add_argument(
        "--hpo-cv-folds",
        type=int,
        default=DEFAULT_HPO_CV_FOLDS,
        help=f"CV folds for HPO (default: {DEFAULT_HPO_CV_FOLDS}).",
    )
    parser.add_argument(
        "--hpo-timeout",
        type=int,
        default=DEFAULT_HPO_TIMEOUT,
        help=f"HPO timeout in seconds (default: {DEFAULT_HPO_TIMEOUT}).",
    )
    parser.add_argument(
        "--params",
        type=str,
        default=None,
        help="JSON string of LightGBM hyperparameters to override.",
    )

    # --- training ---
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42).",
    )
    parser.add_argument(
        "--n-jobs",
        type=int,
        default=-1,
        help="Parallelism for LightGBM (-1 = all cores).",
    )
    parser.add_argument(
        "--early-stopping",
        type=int,
        default=50,
        help="Early stopping rounds (default: 50).",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
        help=f"Decision threshold for evaluation (default: {DEFAULT_THRESHOLD}).",
    )

    # --- output ---
    parser.add_argument(
        "--output-dir",
        type=str,
        default=None,
        help=(
            "Directory for all output artifacts (model, ONNX, metrics). "
            "Default: training/data/models/cortex_static"
        ),
    )
    parser.add_argument(
        "--model-name",
        type=str,
        default="cortex_static",
        help="Base filename for saved artefacts (default: cortex_static).",
    )

    # --- ONNX / quantization ---
    parser.add_argument(
        "--opset",
        type=int,
        default=17,
        help="ONNX opset version (default: 17).",
    )
    parser.add_argument(
        "--skip-quantize",
        action="store_true",
        help="Skip INT8 quantization step.",
    )

    return parser


# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------


def _load_data(
    args: argparse.Namespace,
) -> tuple[
    np.ndarray, np.ndarray, np.ndarray, np.ndarray
]:
    """Stage 1: Load EMBER dataset."""
    from PhantomCortex.training.data.ember_loader import load_ember

    log.info(
        "stage.data_load.start",
        data_dir=args.data_dir,
        download=not args.no_download,
    )
    t0 = time.monotonic()

    X_train, y_train, X_test, y_test = load_ember(
        data_dir=args.data_dir,
        download=not args.no_download,
        cache=not args.no_cache,
    )

    elapsed = time.monotonic() - t0
    log.info(
        "stage.data_load.complete",
        train_samples=X_train.shape[0],
        test_samples=X_test.shape[0],
        features=X_train.shape[1],
        train_benign=int((y_train == 0).sum()),
        train_malicious=int((y_train == 1).sum()),
        test_benign=int((y_test == 0).sum()),
        test_malicious=int((y_test == 1).sum()),
        elapsed_sec=round(elapsed, 2),
    )
    return X_train, y_train, X_test, y_test


def _split_validation(
    X_train: np.ndarray,
    y_train: np.ndarray,
    *,
    val_fraction: float = VALIDATION_FRACTION,
    seed: int = 42,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Split training data into train/validation with stratification."""
    splitter = StratifiedShuffleSplit(
        n_splits=1, test_size=val_fraction, random_state=seed
    )
    train_idx, val_idx = next(splitter.split(X_train, y_train))

    X_tr = X_train[train_idx]
    y_tr = y_train[train_idx]
    X_val = X_train[val_idx]
    y_val = y_train[val_idx]

    log.info(
        "validation_split",
        train_samples=X_tr.shape[0],
        val_samples=X_val.shape[0],
        val_fraction=val_fraction,
    )
    return X_tr, y_tr, X_val, y_val


def _run_hpo(
    trainer: Any,
    X_train: np.ndarray,
    y_train: np.ndarray,
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Stage 2: Bayesian hyperparameter optimisation via Optuna."""
    log.info(
        "stage.hpo.start",
        trials=args.hpo_trials,
        cv_folds=args.hpo_cv_folds,
        timeout_sec=args.hpo_timeout,
    )
    t0 = time.monotonic()

    best_params = trainer.optimize_hyperparams(
        X_train,
        y_train,
        n_trials=args.hpo_trials,
        cv_folds=args.hpo_cv_folds,
        timeout=args.hpo_timeout,
    )

    elapsed = time.monotonic() - t0
    log.info(
        "stage.hpo.complete",
        best_params=best_params,
        elapsed_sec=round(elapsed, 2),
    )
    return best_params


def _train_model(
    trainer: Any,
    X_tr: np.ndarray,
    y_tr: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    params: dict[str, Any] | None,
    args: argparse.Namespace,
) -> Any:
    """Stage 3: Train the final model with best (or provided) parameters."""
    log.info(
        "stage.train.start",
        train_samples=X_tr.shape[0],
        val_samples=X_val.shape[0],
        early_stopping=args.early_stopping,
        params_source="hpo" if params else "default",
    )
    t0 = time.monotonic()

    model = trainer.train(
        X_tr,
        y_tr,
        X_val,
        y_val,
        params=params,
        early_stopping_rounds=args.early_stopping,
        calibrate=True,
    )

    elapsed = time.monotonic() - t0
    log.info(
        "stage.train.complete",
        iterations=model.num_iterations,
        model_hash=model.model_hash,
        elapsed_sec=round(elapsed, 2),
    )
    return model


def _evaluate_model(
    trainer: Any,
    model: Any,
    X_test: np.ndarray,
    y_test: np.ndarray,
    threshold: float,
) -> dict[str, Any]:
    """Stage 4: Evaluate on the held-out test set."""
    log.info(
        "stage.evaluate.start",
        test_samples=X_test.shape[0],
        threshold=threshold,
    )
    t0 = time.monotonic()

    metrics = trainer.evaluate(model, X_test, y_test, threshold=threshold)
    metrics_dict = metrics.to_dict()

    elapsed = time.monotonic() - t0
    log.info(
        "stage.evaluate.complete",
        auc_roc=metrics_dict["auc_roc"],
        auc_pr=metrics_dict["auc_pr"],
        accuracy=metrics_dict["accuracy"],
        precision=metrics_dict["precision"],
        recall=metrics_dict["recall"],
        f1=metrics_dict["f1"],
        fpr_at_threshold=metrics_dict["fpr_at_threshold"],
        detection_rate=metrics_dict["detection_rate"],
        elapsed_sec=round(elapsed, 2),
    )
    return metrics_dict


def _export_onnx(
    model: Any,
    output_dir: Path,
    model_name: str,
    opset: int,
) -> Path:
    """Stage 5: Export trained LightGBM booster to ONNX."""
    from PhantomCortex.training.export.to_onnx import export_lgbm_to_onnx

    onnx_path = output_dir / f"{model_name}.onnx"

    log.info(
        "stage.onnx_export.start",
        output=str(onnx_path),
        opset=opset,
        feature_count=FEATURE_COUNT,
    )
    t0 = time.monotonic()

    export_lgbm_to_onnx(
        model.booster,
        onnx_path,
        feature_count=FEATURE_COUNT,
        opset=opset,
    )

    size_mb = onnx_path.stat().st_size / (1024 * 1024)
    elapsed = time.monotonic() - t0
    log.info(
        "stage.onnx_export.complete",
        path=str(onnx_path),
        size_mb=round(size_mb, 2),
        elapsed_sec=round(elapsed, 2),
    )
    return onnx_path


def _quantize_int8(
    onnx_path: Path,
    output_dir: Path,
    model_name: str,
) -> dict[str, Any]:
    """Stage 6: Dynamic INT8 quantization of the ONNX model."""
    from PhantomCortex.training.export.quantize import quantize_dynamic

    quantized_path = output_dir / f"{model_name}_int8.onnx"

    log.info(
        "stage.quantize.start",
        input=str(onnx_path),
        output=str(quantized_path),
    )
    t0 = time.monotonic()

    report = quantize_dynamic(onnx_path, quantized_path)

    elapsed = time.monotonic() - t0
    report_dict = report.to_dict()

    if report.success:
        log.info(
            "stage.quantize.complete",
            original_mb=report.original_size_mb,
            quantized_mb=report.quantized_size_mb,
            reduction_pct=report.size_reduction_pct,
            elapsed_sec=round(elapsed, 2),
        )
    else:
        log.error(
            "stage.quantize.failed",
            error=report.error_message,
            elapsed_sec=round(elapsed, 2),
        )

    return report_dict


def _save_artifacts(
    trainer: Any,
    model: Any,
    output_dir: Path,
    model_name: str,
    metrics_dict: dict[str, Any],
    hpo_params: dict[str, Any] | None,
    quantize_report: dict[str, Any] | None,
    args: argparse.Namespace,
    total_elapsed: float,
) -> None:
    """Stage 7: Persist model, metrics, and run metadata."""
    output_dir.mkdir(parents=True, exist_ok=True)
    model_base = output_dir / model_name

    # Save native LightGBM model
    trainer.save_model(model, model_base)
    log.info("model.saved", path=str(model_base))

    # Assemble full run report
    report: dict[str, Any] = {
        "model_name": model_name,
        "model_hash": model.model_hash,
        "num_iterations": model.num_iterations,
        "feature_count": FEATURE_COUNT,
        "seed": args.seed,
        "threshold": args.threshold,
        "hpo_enabled": not args.skip_hpo,
        "hpo_trials": args.hpo_trials if not args.skip_hpo else 0,
        "hpo_best_params": hpo_params,
        "training_params": model.params,
        "test_metrics": metrics_dict,
        "quantization": quantize_report,
        "total_elapsed_sec": round(total_elapsed, 2),
    }

    metrics_path = output_dir / f"{model_name}_metrics.json"
    metrics_path.write_text(
        json.dumps(report, indent=2, default=str), encoding="utf-8"
    )
    log.info("metrics.saved", path=str(metrics_path))


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    """Run the full Cortex-Static training pipeline."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    output_dir = (
        Path(args.output_dir) if args.output_dir else _DEFAULT_OUTPUT_DIR
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    pipeline_start = time.monotonic()
    log.info(
        "pipeline.start",
        output_dir=str(output_dir),
        model_name=args.model_name,
        seed=args.seed,
    )

    # ---- Lazy import to surface import errors early -----------------------
    try:
        from PhantomCortex.training.models.static_lgbm import (
            CortexStaticTrainer,
        )
    except ImportError as exc:
        log.error(
            "pipeline.import_error",
            error=str(exc),
            hint=(
                "Ensure PhantomCortex is installed or PYTHONPATH includes "
                "the repository root."
            ),
        )
        sys.exit(1)

    # ---- 1. Load data -----------------------------------------------------
    X_train_full, y_train_full, X_test, y_test = _load_data(args)

    # ---- 2. Instantiate trainer -------------------------------------------
    trainer = CortexStaticTrainer(
        feature_count=FEATURE_COUNT,
        seed=args.seed,
        n_jobs=args.n_jobs,
    )

    # ---- 3. Hyperparameter optimisation -----------------------------------
    hpo_params: dict[str, Any] | None = None

    if args.params:
        try:
            hpo_params = json.loads(args.params)
            log.info("params.override", params=hpo_params)
        except json.JSONDecodeError as exc:
            log.error("params.parse_error", raw=args.params, error=str(exc))
            sys.exit(1)

    if not args.skip_hpo:
        optuna_best = _run_hpo(trainer, X_train_full, y_train_full, args)
        if hpo_params is not None:
            optuna_best.update(hpo_params)
        hpo_params = optuna_best

    # ---- 4. Train/val split -----------------------------------------------
    X_tr, y_tr, X_val, y_val = _split_validation(
        X_train_full,
        y_train_full,
        val_fraction=VALIDATION_FRACTION,
        seed=args.seed,
    )

    # ---- 5. Final training ------------------------------------------------
    model = _train_model(trainer, X_tr, y_tr, X_val, y_val, hpo_params, args)

    # ---- 6. Evaluation on test set ----------------------------------------
    metrics_dict = _evaluate_model(
        trainer, model, X_test, y_test, args.threshold
    )

    # ---- 7. ONNX export ---------------------------------------------------
    onnx_path = _export_onnx(
        model, output_dir, args.model_name, args.opset
    )

    # ---- 8. INT8 quantization ---------------------------------------------
    quantize_report: dict[str, Any] | None = None
    if not args.skip_quantize:
        quantize_report = _quantize_int8(
            onnx_path, output_dir, args.model_name
        )

    # ---- 9. Save all artifacts --------------------------------------------
    total_elapsed = time.monotonic() - pipeline_start
    _save_artifacts(
        trainer,
        model,
        output_dir,
        args.model_name,
        metrics_dict,
        hpo_params,
        quantize_report,
        args,
        total_elapsed,
    )

    log.info(
        "pipeline.complete",
        total_elapsed_sec=round(total_elapsed, 2),
        auc_roc=metrics_dict["auc_roc"],
        detection_rate=metrics_dict["detection_rate"],
        fpr=metrics_dict["fpr_at_threshold"],
        output_dir=str(output_dir),
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()

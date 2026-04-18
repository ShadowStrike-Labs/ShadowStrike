"""
PhantomCortex Training Pipeline Orchestrator
=============================================

Nightly automation that runs the full training lifecycle end-to-end:
feed sync → feature extraction → dataset merge → train → evaluate →
export → validate → stage → report.

Usage:
    python -m PhantomCortex.training.pipeline --incremental --report
    python -m PhantomCortex.training.pipeline --full-train --model static
    python -m PhantomCortex.training.pipeline --feed-sync-only
    python -m PhantomCortex.training.pipeline --evaluate-only --report
    python -m PhantomCortex.training.pipeline --export-only
    python -m PhantomCortex.training.pipeline --dry-run
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import shutil
import signal
import sys
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any

import structlog
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ROOT_DIR = Path(__file__).resolve().parent
_CONFIG_DIR = _ROOT_DIR / "config"
_DATA_DIR = _ROOT_DIR / "data"
_DEFAULT_DEPLOYMENT_CFG = _CONFIG_DIR / "deployment.yaml"
_LOCK_FILE = _ROOT_DIR / ".pipeline.lock"
_CHECKPOINT_FILE = _DATA_DIR / ".pipeline_checkpoint.json"
_MIN_DISK_SPACE_GB = 10.0

console = Console()
logger = structlog.get_logger("phantomcortex.pipeline")


# ---------------------------------------------------------------------------
# Enums & data classes
# ---------------------------------------------------------------------------

class PipelineMode(Enum):
    FULL_TRAIN = auto()
    INCREMENTAL = auto()
    EVALUATE_ONLY = auto()
    EXPORT_ONLY = auto()
    FEED_SYNC_ONLY = auto()


class StepName(Enum):
    FEED_SYNC = "feed_sync"
    FEATURE_EXTRACT = "feature_extract"
    DATASET_MERGE = "dataset_merge"
    TRAIN = "train"
    EVALUATE = "evaluate"
    EXPORT = "export"
    VALIDATE = "validate"
    STAGE = "stage"
    REPORT = "report"


# Ordered list of steps for each mode.
_MODE_STEPS: dict[PipelineMode, list[StepName]] = {
    PipelineMode.FULL_TRAIN: [
        StepName.FEED_SYNC,
        StepName.FEATURE_EXTRACT,
        StepName.DATASET_MERGE,
        StepName.TRAIN,
        StepName.EVALUATE,
        StepName.EXPORT,
        StepName.VALIDATE,
        StepName.STAGE,
        StepName.REPORT,
    ],
    PipelineMode.INCREMENTAL: [
        StepName.FEED_SYNC,
        StepName.FEATURE_EXTRACT,
        StepName.DATASET_MERGE,
        StepName.TRAIN,
        StepName.EVALUATE,
        StepName.EXPORT,
        StepName.VALIDATE,
        StepName.STAGE,
        StepName.REPORT,
    ],
    PipelineMode.EVALUATE_ONLY: [
        StepName.EVALUATE,
        StepName.REPORT,
    ],
    PipelineMode.EXPORT_ONLY: [
        StepName.EXPORT,
        StepName.VALIDATE,
        StepName.STAGE,
    ],
    PipelineMode.FEED_SYNC_ONLY: [
        StepName.FEED_SYNC,
    ],
}

# Models recognized by the pipeline.
KNOWN_MODELS = ("static", "behavioral", "memory", "network", "emulation")


@dataclass
class StepResult:
    """Outcome of a single pipeline step."""

    name: str
    success: bool
    duration_s: float = 0.0
    error: str | None = None
    metrics: dict[str, Any] = field(default_factory=dict)


@dataclass
class QualityGates:
    """Thresholds that a trained model must pass before deployment."""

    min_auc_roc: float = 0.995
    max_fpr_at_001: float = 0.001
    min_detection_rate: float = 0.995
    max_model_size_mb: float = 20.0
    max_inference_ms: float = 5.0
    max_regression_pct: float = 0.5


@dataclass
class DeploymentConfig:
    """Parsed deployment.yaml."""

    staging_dir: Path
    production_dir: Path
    backup_dir: Path
    max_backups: int
    quality_gates: QualityGates
    versioning_scheme: str
    auto_increment: str
    manifest_file: str
    email_enabled: bool
    email_smtp: str
    email_recipients: list[str]
    webhook_enabled: bool
    webhook_url: str


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class PipelineError(Exception):
    """Base exception for pipeline failures."""


class LockAcquisitionError(PipelineError):
    """Another pipeline instance is already running."""


class DiskSpaceError(PipelineError):
    """Insufficient disk space to proceed."""


class QualityGateError(PipelineError):
    """Trained model failed one or more quality gates."""


class RollbackTriggered(PipelineError):
    """New model regressed — rolled back to previous version."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _available_disk_gb(path: Path) -> float:
    """Return free disk space in GiB for the volume containing *path*."""
    usage = shutil.disk_usage(str(path))
    return usage.free / (1024 ** 3)


def _load_deployment_config(path: Path) -> DeploymentConfig:
    """Parse deployment.yaml and return a typed config object."""
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    dep = raw.get("deployment", {})
    qg = dep.get("quality_gates", {})
    ver = dep.get("versioning", {})
    notif = dep.get("notifications", {})
    email = notif.get("email", {})
    webhook = notif.get("webhook", {})

    base = path.parent.parent  # training/

    return DeploymentConfig(
        staging_dir=(base / dep.get("staging_dir", "data/models/staging")).resolve(),
        production_dir=(base / dep.get("production_dir", "data/models/production")).resolve(),
        backup_dir=(base / dep.get("backup_dir", "data/models/backup")).resolve(),
        max_backups=int(dep.get("max_backups", 5)),
        quality_gates=QualityGates(
            min_auc_roc=float(qg.get("min_auc_roc", 0.995)),
            max_fpr_at_001=float(qg.get("max_fpr_at_001", 0.001)),
            min_detection_rate=float(qg.get("min_detection_rate", 0.995)),
            max_model_size_mb=float(qg.get("max_model_size_mb", 20.0)),
            max_inference_ms=float(qg.get("max_inference_ms", 5.0)),
            max_regression_pct=float(qg.get("max_regression_pct", 0.5)),
        ),
        versioning_scheme=ver.get("scheme", "semver"),
        auto_increment=ver.get("auto_increment", "minor"),
        manifest_file=ver.get("manifest_file", "model_manifest.json"),
        email_enabled=bool(email.get("enabled", False)),
        email_smtp=email.get("smtp_server", ""),
        email_recipients=list(email.get("recipients", [])),
        webhook_enabled=bool(webhook.get("enabled", False)),
        webhook_url=webhook.get("url", ""),
    )


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)


def _read_json(path: Path) -> Any:
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _timestamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Lock file management
# ---------------------------------------------------------------------------

class _PipelineLock:
    """File-based lock to prevent concurrent pipeline runs.

    Stores PID + timestamp so stale locks from crashed processes can be
    detected and overridden after a configurable timeout.
    """

    _STALE_THRESHOLD_S = 3600 * 6  # 6 hours

    def __init__(self, lock_path: Path) -> None:
        self._path = lock_path

    def acquire(self) -> None:
        if self._path.exists():
            try:
                info = json.loads(self._path.read_text(encoding="utf-8"))
                pid = info.get("pid")
                ts = info.get("timestamp", "")
                age_s = (
                    datetime.datetime.now(datetime.timezone.utc)
                    - datetime.datetime.fromisoformat(ts)
                ).total_seconds() if ts else float("inf")

                if self._pid_alive(pid) and age_s < self._STALE_THRESHOLD_S:
                    raise LockAcquisitionError(
                        f"Pipeline already running (PID {pid}, started {ts}). "
                        f"Remove {self._path} if this is stale."
                    )
                logger.warning(
                    "overriding_stale_lock",
                    stale_pid=pid,
                    age_hours=round(age_s / 3600, 1),
                )
            except (json.JSONDecodeError, KeyError, ValueError):
                logger.warning("corrupt_lock_file_overridden", path=str(self._path))

        self._path.parent.mkdir(parents=True, exist_ok=True)
        _write_json(self._path, {"pid": os.getpid(), "timestamp": _timestamp()})
        logger.info("lock_acquired", pid=os.getpid())

    def release(self) -> None:
        try:
            if self._path.exists():
                self._path.unlink()
                logger.info("lock_released")
        except OSError as exc:
            logger.warning("lock_release_failed", error=str(exc))

    @staticmethod
    def _pid_alive(pid: int | None) -> bool:
        if pid is None:
            return False
        try:
            if platform.system() == "Windows":
                import ctypes
                kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
                handle = kernel32.OpenProcess(0x100000, False, pid)  # SYNCHRONIZE
                if handle:
                    kernel32.CloseHandle(handle)
                    return True
                return False
            else:
                os.kill(pid, 0)
                return True
        except (OSError, PermissionError):
            return False


# ---------------------------------------------------------------------------
# Checkpoint (resume-from-last-successful-step)
# ---------------------------------------------------------------------------

@dataclass
class _Checkpoint:
    run_id: str
    mode: str
    completed_steps: list[str]
    started_at: str
    last_update: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "mode": self.mode,
            "completed_steps": self.completed_steps,
            "started_at": self.started_at,
            "last_update": self.last_update,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> _Checkpoint:
        return cls(
            run_id=d["run_id"],
            mode=d["mode"],
            completed_steps=list(d.get("completed_steps", [])),
            started_at=d.get("started_at", ""),
            last_update=d.get("last_update", ""),
        )


def _load_checkpoint() -> _Checkpoint | None:
    data = _read_json(_CHECKPOINT_FILE)
    if data is None:
        return None
    try:
        return _Checkpoint.from_dict(data)
    except (KeyError, TypeError):
        return None


def _save_checkpoint(ckpt: _Checkpoint) -> None:
    ckpt.last_update = _timestamp()
    _write_json(_CHECKPOINT_FILE, ckpt.to_dict())


def _clear_checkpoint() -> None:
    if _CHECKPOINT_FILE.exists():
        _CHECKPOINT_FILE.unlink()


# ---------------------------------------------------------------------------
# Notification helpers
# ---------------------------------------------------------------------------

def _send_webhook(url: str, payload: dict[str, Any]) -> None:
    """Fire-and-forget webhook POST. Failures are logged, never raised."""
    if not url:
        return
    try:
        import requests
        resp = requests.post(url, json=payload, timeout=30)
        logger.info("webhook_sent", status_code=resp.status_code)
    except Exception as exc:  # noqa: BLE001
        logger.warning("webhook_failed", error=str(exc))


def _send_email(smtp_server: str, recipients: list[str], subject: str, body: str) -> None:
    """Best-effort email notification. Failures are logged, never raised."""
    if not smtp_server or not recipients:
        return
    try:
        import smtplib
        from email.mime.text import MIMEText

        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = "phantomcortex@shadowstrike.local"
        msg["To"] = ", ".join(recipients)
        with smtplib.SMTP(smtp_server, timeout=30) as srv:
            srv.send_message(msg)
        logger.info("email_sent", recipients=recipients)
    except Exception as exc:  # noqa: BLE001
        logger.warning("email_failed", error=str(exc))


# ---------------------------------------------------------------------------
# Model versioning
# ---------------------------------------------------------------------------

def _read_manifest(path: Path) -> dict[str, Any]:
    data = _read_json(path)
    return data if isinstance(data, dict) else {}


def _bump_version(current: str, increment: str) -> str:
    """Increment a semver string. Returns '0.1.0' if *current* is empty."""
    if not current:
        return "0.1.0"
    parts = current.split(".")
    if len(parts) != 3:
        return "0.1.0"
    major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
    if increment == "major":
        return f"{major + 1}.0.0"
    if increment == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


# ---------------------------------------------------------------------------
# Backup / rollback
# ---------------------------------------------------------------------------

def _backup_production_models(cfg: DeploymentConfig) -> Path | None:
    """Copy current production models to backup dir. Returns backup path."""
    if not cfg.production_dir.exists() or not any(cfg.production_dir.iterdir()):
        logger.info("no_production_models_to_backup")
        return None

    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = cfg.backup_dir / ts
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copytree(cfg.production_dir, dest, dirs_exist_ok=True)
    logger.info("production_models_backed_up", dest=str(dest))

    _prune_backups(cfg.backup_dir, cfg.max_backups)
    return dest


def _prune_backups(backup_dir: Path, keep: int) -> None:
    """Remove oldest backups beyond *keep* most recent."""
    if not backup_dir.exists():
        return
    entries = sorted(
        [d for d in backup_dir.iterdir() if d.is_dir()],
        key=lambda p: p.name,
        reverse=True,
    )
    for old in entries[keep:]:
        shutil.rmtree(old, ignore_errors=True)
        logger.info("pruned_old_backup", path=str(old))


def _rollback(backup_path: Path | None, cfg: DeploymentConfig) -> None:
    """Restore production models from *backup_path*."""
    if backup_path is None or not backup_path.exists():
        logger.error("rollback_impossible_no_backup")
        return
    if cfg.production_dir.exists():
        shutil.rmtree(cfg.production_dir, ignore_errors=True)
    shutil.copytree(backup_path, cfg.production_dir, dirs_exist_ok=True)
    logger.warning("rollback_completed", source=str(backup_path))


# ---------------------------------------------------------------------------
# Individual pipeline steps
# ---------------------------------------------------------------------------
# Each step is a method on PhantomCortexPipeline.  They share a common
# signature: (self) -> StepResult.  Heavy lifting is delegated to sub-modules
# in the feeds/, features/, models/, evaluation/, export/ packages — which
# are not yet implemented.  The orchestrator detects their absence gracefully
# and records a clear error message so operators know exactly which module to
# build next.

def _safe_import(module_path: str) -> Any:
    """Attempt to import *module_path*; return None on failure."""
    try:
        import importlib
        return importlib.import_module(module_path)
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# Pipeline class
# ---------------------------------------------------------------------------

class PhantomCortexPipeline:
    """End-to-end training pipeline orchestrator.

    Designed for unattended nightly execution.  Every step logs structured
    events, records timing, and writes a checkpoint so the run can be resumed
    after an interruption.
    """

    def __init__(
        self,
        mode: PipelineMode,
        *,
        target_models: tuple[str, ...] | None = None,
        generate_report: bool = False,
        dry_run: bool = False,
        resume: bool = False,
        config_path: Path = _DEFAULT_DEPLOYMENT_CFG,
    ) -> None:
        self._mode = mode
        self._target_models = target_models or KNOWN_MODELS
        self._generate_report = generate_report
        self._dry_run = dry_run
        self._resume = resume
        self._cfg = _load_deployment_config(config_path)
        self._lock = _PipelineLock(_LOCK_FILE)
        self._results: list[StepResult] = []
        self._backup_path: Path | None = None
        self._run_id = f"run-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        self._interrupted = False

        for model in self._target_models:
            if model not in KNOWN_MODELS:
                raise PipelineError(f"Unknown model '{model}'. Known: {', '.join(KNOWN_MODELS)}")

    # -- public entry point -------------------------------------------------

    def run(self) -> list[StepResult]:
        """Execute the pipeline according to the configured mode."""
        signal.signal(signal.SIGINT, self._handle_interrupt)
        if platform.system() != "Windows":
            signal.signal(signal.SIGTERM, self._handle_interrupt)

        steps = list(_MODE_STEPS[self._mode])
        if not self._generate_report and StepName.REPORT in steps:
            steps.remove(StepName.REPORT)

        self._print_banner(steps)

        if self._dry_run:
            console.print("[bold green]Dry-run complete — configuration is valid.[/]")
            return []

        self._preflight_checks()
        self._lock.acquire()
        try:
            self._run_steps(steps)
        finally:
            self._lock.release()

        all_ok = all(r.success for r in self._results)
        if all_ok and not self._interrupted:
            _clear_checkpoint()

        self._print_summary()
        self._notify()
        return self._results

    # -- internals ----------------------------------------------------------

    def _handle_interrupt(self, signum: int, _frame: Any) -> None:
        self._interrupted = True
        logger.warning("pipeline_interrupted", signal=signum)
        console.print("\n[bold yellow]Pipeline interrupted — saving checkpoint…[/]")

    def _preflight_checks(self) -> None:
        free_gb = _available_disk_gb(_DATA_DIR)
        logger.info("disk_space_check", free_gb=round(free_gb, 2), required_gb=_MIN_DISK_SPACE_GB)
        if free_gb < _MIN_DISK_SPACE_GB:
            raise DiskSpaceError(
                f"Only {free_gb:.1f} GiB free on {_DATA_DIR.drive or _DATA_DIR.anchor}; "
                f"need at least {_MIN_DISK_SPACE_GB} GiB."
            )

        for d in (self._cfg.staging_dir, self._cfg.production_dir, self._cfg.backup_dir):
            d.mkdir(parents=True, exist_ok=True)

    def _run_steps(self, steps: list[StepName]) -> None:
        skip_set: set[str] = set()
        if self._resume:
            ckpt = _load_checkpoint()
            if ckpt and ckpt.mode == self._mode.name:
                skip_set = set(ckpt.completed_steps)
                logger.info("resuming_from_checkpoint", skipping=sorted(skip_set))

        ckpt = _Checkpoint(
            run_id=self._run_id,
            mode=self._mode.name,
            completed_steps=[],
            started_at=_timestamp(),
            last_update=_timestamp(),
        )

        dispatch: dict[StepName, Any] = {
            StepName.FEED_SYNC: self._step_feed_sync,
            StepName.FEATURE_EXTRACT: self._step_feature_extract,
            StepName.DATASET_MERGE: self._step_dataset_merge,
            StepName.TRAIN: self._step_train,
            StepName.EVALUATE: self._step_evaluate,
            StepName.EXPORT: self._step_export,
            StepName.VALIDATE: self._step_validate,
            StepName.STAGE: self._step_stage,
            StepName.REPORT: self._step_report,
        }

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task_id = progress.add_task("Pipeline", total=len(steps))

            for step in steps:
                if self._interrupted:
                    _save_checkpoint(ckpt)
                    break

                if step.value in skip_set:
                    progress.advance(task_id)
                    continue

                progress.update(task_id, description=f"[{step.value}]")
                result = self._execute_step(step, dispatch[step])
                self._results.append(result)

                if result.success:
                    ckpt.completed_steps.append(step.value)
                    _save_checkpoint(ckpt)
                else:
                    logger.error("step_failed", step=step.value, error=result.error)
                    if step in (StepName.TRAIN, StepName.EVALUATE, StepName.VALIDATE):
                        self._attempt_rollback()
                    _save_checkpoint(ckpt)
                    break

                progress.advance(task_id)

    def _execute_step(self, step: StepName, fn: Any) -> StepResult:
        logger.info("step_started", step=step.value)
        t0 = time.monotonic()
        try:
            result: StepResult = fn()
            result.duration_s = time.monotonic() - t0
            logger.info(
                "step_completed",
                step=step.value,
                success=result.success,
                duration_s=round(result.duration_s, 2),
            )
            return result
        except Exception as exc:  # noqa: BLE001
            elapsed = time.monotonic() - t0
            logger.exception("step_exception", step=step.value)
            return StepResult(
                name=step.value, success=False, duration_s=elapsed, error=str(exc)
            )

    def _attempt_rollback(self) -> None:
        if self._backup_path:
            console.print("[bold red]Quality gate failure — rolling back…[/]")
            _rollback(self._backup_path, self._cfg)

    # -----------------------------------------------------------------------
    # Step implementations
    # -----------------------------------------------------------------------

    def _step_feed_sync(self) -> StepResult:
        """Download new samples from all enabled threat-intel feeds."""
        feeds_mod = _safe_import("PhantomCortex.training.feeds.sync")
        if feeds_mod is None:
            return self._stub_result(
                "feed_sync",
                "Feed sync module not found (PhantomCortex.training.feeds.sync). "
                "Feed ingestion infrastructure has not been built yet.",
            )

        try:
            stats: dict[str, Any] = feeds_mod.sync_all(data_dir=_DATA_DIR / "feeds")
            return StepResult(name="feed_sync", success=True, metrics=stats)
        except Exception as exc:  # noqa: BLE001
            return StepResult(name="feed_sync", success=False, error=str(exc))

    def _step_feature_extract(self) -> StepResult:
        """Run PE / behavioral feature extraction on new samples."""
        feat_mod = _safe_import("PhantomCortex.training.features.extract")
        if feat_mod is None:
            return self._stub_result(
                "feature_extract",
                "Feature extraction module not found (PhantomCortex.training.features.extract). "
                "Feature engineering infrastructure has not been built yet.",
            )

        try:
            stats = feat_mod.extract_all(
                raw_dir=_DATA_DIR / "raw",
                output_dir=_DATA_DIR / "processed",
                models=self._target_models,
            )
            return StepResult(name="feature_extract", success=True, metrics=stats)
        except Exception as exc:  # noqa: BLE001
            return StepResult(name="feature_extract", success=False, error=str(exc))

    def _step_dataset_merge(self) -> StepResult:
        """Combine newly extracted features with the existing training set."""
        merge_mod = _safe_import("PhantomCortex.training.features.merge")
        if merge_mod is None:
            return self._stub_result(
                "dataset_merge",
                "Dataset merge module not found (PhantomCortex.training.features.merge). "
                "Dataset management infrastructure has not been built yet.",
            )

        try:
            stats = merge_mod.merge(
                processed_dir=_DATA_DIR / "processed",
                dataset_dir=_DATA_DIR / "datasets",
            )
            return StepResult(name="dataset_merge", success=True, metrics=stats)
        except Exception as exc:  # noqa: BLE001
            return StepResult(name="dataset_merge", success=False, error=str(exc))

    def _step_train(self) -> StepResult:
        """Train or fine-tune all target models."""
        self._backup_path = _backup_production_models(self._cfg)

        train_mod = _safe_import("PhantomCortex.training.models.train")
        if train_mod is None:
            return self._stub_result(
                "train",
                "Training module not found (PhantomCortex.training.models.train). "
                "Model training infrastructure has not been built yet.",
            )

        try:
            full_retrain = self._mode == PipelineMode.FULL_TRAIN
            stats = train_mod.train_models(
                models=self._target_models,
                data_dir=_DATA_DIR / "datasets",
                output_dir=self._cfg.staging_dir,
                full_retrain=full_retrain,
            )
            return StepResult(name="train", success=True, metrics=stats)
        except Exception as exc:  # noqa: BLE001
            return StepResult(name="train", success=False, error=str(exc))

    def _step_evaluate(self) -> StepResult:
        """Run the full evaluation suite against staged models."""
        eval_mod = _safe_import("PhantomCortex.training.evaluation.evaluate")
        if eval_mod is None:
            return self._stub_result(
                "evaluate",
                "Evaluation module not found (PhantomCortex.training.evaluation.evaluate). "
                "Evaluation infrastructure has not been built yet.",
            )

        try:
            model_dir = self._cfg.staging_dir if self._cfg.staging_dir.exists() else self._cfg.production_dir
            report: dict[str, Any] = eval_mod.evaluate_all(
                model_dir=model_dir,
                data_dir=_DATA_DIR / "datasets",
                models=self._target_models,
            )
            return StepResult(name="evaluate", success=True, metrics=report)
        except Exception as exc:  # noqa: BLE001
            return StepResult(name="evaluate", success=False, error=str(exc))

    def _step_export(self) -> StepResult:
        """Convert trained models to ONNX and quantize to INT8."""
        export_mod = _safe_import("PhantomCortex.training.export.onnx_export")
        if export_mod is None:
            return self._stub_result(
                "export",
                "Export module not found (PhantomCortex.training.export.onnx_export). "
                "ONNX export infrastructure has not been built yet.",
            )

        try:
            stats = export_mod.export_and_quantize(
                model_dir=self._cfg.staging_dir,
                output_dir=self._cfg.staging_dir,
                models=self._target_models,
            )
            return StepResult(name="export", success=True, metrics=stats)
        except Exception as exc:  # noqa: BLE001
            return StepResult(name="export", success=False, error=str(exc))

    def _step_validate(self) -> StepResult:
        """Run deployment validation checks against quality gates."""
        gates = self._cfg.quality_gates
        failures: list[str] = []
        metrics: dict[str, Any] = {}

        for model_name in self._target_models:
            onnx_path = self._cfg.staging_dir / f"cortex_{model_name}.onnx"
            if not onnx_path.exists():
                failures.append(f"{model_name}: ONNX file not found at {onnx_path}")
                continue

            size_mb = onnx_path.stat().st_size / (1024 * 1024)
            metrics[f"{model_name}_size_mb"] = round(size_mb, 2)

            if size_mb > gates.max_model_size_mb:
                failures.append(
                    f"{model_name}: model size {size_mb:.1f} MB exceeds limit {gates.max_model_size_mb} MB"
                )

            latency_ms = self._benchmark_inference(onnx_path)
            metrics[f"{model_name}_inference_ms"] = round(latency_ms, 2)

            if latency_ms > gates.max_inference_ms:
                failures.append(
                    f"{model_name}: inference {latency_ms:.1f} ms exceeds limit {gates.max_inference_ms} ms"
                )

            eval_result = self._find_eval_metrics(model_name)
            if eval_result:
                auc = eval_result.get("auc_roc", 0.0)
                fpr = eval_result.get("fpr_at_001", 1.0)
                dr = eval_result.get("detection_rate", 0.0)
                metrics[f"{model_name}_auc_roc"] = auc
                metrics[f"{model_name}_fpr_at_001"] = fpr
                metrics[f"{model_name}_detection_rate"] = dr

                if auc < gates.min_auc_roc:
                    failures.append(f"{model_name}: AUC-ROC {auc:.4f} below {gates.min_auc_roc}")
                if fpr > gates.max_fpr_at_001:
                    failures.append(f"{model_name}: FPR@0.1% {fpr:.4f} exceeds {gates.max_fpr_at_001}")
                if dr < gates.min_detection_rate:
                    failures.append(f"{model_name}: detection rate {dr:.4f} below {gates.min_detection_rate}")

                regression = self._check_regression(model_name, eval_result)
                if regression is not None and regression > gates.max_regression_pct:
                    failures.append(
                        f"{model_name}: AUC-ROC regressed {regression:.2f}% vs previous "
                        f"(limit {gates.max_regression_pct}%)"
                    )

        if failures:
            for f in failures:
                logger.error("quality_gate_failed", detail=f)
            return StepResult(
                name="validate",
                success=False,
                error=f"{len(failures)} quality gate(s) failed",
                metrics=metrics,
            )

        return StepResult(name="validate", success=True, metrics=metrics)

    def _step_stage(self) -> StepResult:
        """Promote staged models to the production directory."""
        if not self._cfg.staging_dir.exists() or not any(self._cfg.staging_dir.iterdir()):
            return StepResult(
                name="stage", success=False, error="Staging directory is empty — nothing to promote."
            )

        _backup_production_models(self._cfg)

        if self._cfg.production_dir.exists():
            shutil.rmtree(self._cfg.production_dir)
        shutil.copytree(self._cfg.staging_dir, self._cfg.production_dir)

        manifest_path = self._cfg.production_dir / self._cfg.manifest_file
        manifest = _read_manifest(manifest_path)
        prev_version = manifest.get("version", "")
        new_version = _bump_version(prev_version, self._cfg.auto_increment)

        manifest.update({
            "version": new_version,
            "promoted_at": _timestamp(),
            "run_id": self._run_id,
            "models": list(self._target_models),
        })
        _write_json(manifest_path, manifest)

        logger.info("models_staged", version=new_version, dest=str(self._cfg.production_dir))
        return StepResult(
            name="stage",
            success=True,
            metrics={"version": new_version, "models": list(self._target_models)},
        )

    def _step_report(self) -> StepResult:
        """Generate metrics report in Markdown and JSON."""
        report_dir = _DATA_DIR / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        json_path = report_dir / f"report_{ts}.json"
        md_path = report_dir / f"report_{ts}.md"

        report_data = self._build_report_data()
        _write_json(json_path, report_data)

        md_content = self._render_markdown_report(report_data)
        md_path.write_text(md_content, encoding="utf-8")

        logger.info("report_generated", json=str(json_path), markdown=str(md_path))
        return StepResult(
            name="report",
            success=True,
            metrics={"json_path": str(json_path), "md_path": str(md_path)},
        )

    # -----------------------------------------------------------------------
    # Validation helpers
    # -----------------------------------------------------------------------

    def _benchmark_inference(self, onnx_path: Path) -> float:
        """Return median inference time in ms for a single ONNX model.

        Falls back to a file-size heuristic if onnxruntime is unavailable.
        """
        try:
            import numpy as np
            import onnxruntime as ort

            sess = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
            inp_meta = sess.get_inputs()
            feeds: dict[str, Any] = {}
            for meta in inp_meta:
                shape = [d if isinstance(d, int) else 1 for d in meta.shape]
                dtype = np.float32 if "float" in meta.type else np.int64
                feeds[meta.name] = np.random.randn(*shape).astype(dtype)

            # Warmup
            for _ in range(5):
                sess.run(None, feeds)

            timings: list[float] = []
            for _ in range(50):
                t0 = time.perf_counter()
                sess.run(None, feeds)
                timings.append((time.perf_counter() - t0) * 1000)

            return float(np.median(timings))
        except ImportError:
            logger.warning("onnxruntime_not_available_using_size_heuristic")
            size_mb = onnx_path.stat().st_size / (1024 * 1024)
            return min(size_mb * 0.5, 10.0)

    def _find_eval_metrics(self, model_name: str) -> dict[str, Any] | None:
        """Look for evaluation metrics written by the evaluate step."""
        for result in self._results:
            if result.name == "evaluate" and result.metrics:
                # evaluate_all() stores per-model results under "models"
                per_model = result.metrics.get("models", {})
                if model_name in per_model:
                    return per_model[model_name]  # type: ignore[no-any-return]
        return None

    def _check_regression(self, model_name: str, current: dict[str, Any]) -> float | None:
        """Return percentage AUC-ROC regression vs the production manifest, or None."""
        manifest_path = self._cfg.production_dir / self._cfg.manifest_file
        manifest = _read_manifest(manifest_path)
        prev_metrics = manifest.get("metrics", {}).get(model_name, {})
        prev_auc = prev_metrics.get("auc_roc")
        if prev_auc is None:
            return None
        current_auc = current.get("auc_roc", 0.0)
        if prev_auc == 0:
            return None
        drop_pct = ((prev_auc - current_auc) / prev_auc) * 100
        return max(drop_pct, 0.0)

    @staticmethod
    def _stub_result(name: str, message: str) -> StepResult:
        """Return a failing StepResult for an unimplemented sub-module."""
        logger.warning("module_not_implemented", step=name, detail=message)
        return StepResult(name=name, success=False, error=message)

    # -----------------------------------------------------------------------
    # Reporting
    # -----------------------------------------------------------------------

    def _build_report_data(self) -> dict[str, Any]:
        return {
            "run_id": self._run_id,
            "mode": self._mode.name,
            "target_models": list(self._target_models),
            "generated_at": _timestamp(),
            "host": platform.node(),
            "python": platform.python_version(),
            "steps": [
                {
                    "name": r.name,
                    "success": r.success,
                    "duration_s": round(r.duration_s, 2),
                    "error": r.error,
                    "metrics": r.metrics,
                }
                for r in self._results
            ],
            "overall_success": all(r.success for r in self._results),
            "total_duration_s": round(sum(r.duration_s for r in self._results), 2),
        }

    @staticmethod
    def _render_markdown_report(data: dict[str, Any]) -> str:
        lines: list[str] = [
            f"# PhantomCortex Pipeline Report",
            "",
            f"**Run ID:** `{data['run_id']}`  ",
            f"**Mode:** {data['mode']}  ",
            f"**Generated:** {data['generated_at']}  ",
            f"**Host:** {data['host']}  ",
            f"**Overall:** {'✅ PASS' if data['overall_success'] else '❌ FAIL'}  ",
            f"**Total duration:** {data['total_duration_s']:.1f}s  ",
            "",
            "## Steps",
            "",
            "| Step | Status | Duration | Error |",
            "|------|--------|----------|-------|",
        ]
        for step in data["steps"]:
            status = "✅" if step["success"] else "❌"
            err = step.get("error") or ""
            if len(err) > 60:
                err = err[:57] + "…"
            lines.append(
                f"| {step['name']} | {status} | {step['duration_s']:.1f}s | {err} |"
            )

        lines.append("")
        lines.append("## Metrics")
        lines.append("")
        for step in data["steps"]:
            if step["metrics"]:
                lines.append(f"### {step['name']}")
                lines.append("```json")
                lines.append(json.dumps(step["metrics"], indent=2, default=str))
                lines.append("```")
                lines.append("")

        return "\n".join(lines) + "\n"

    # -----------------------------------------------------------------------
    # Terminal output
    # -----------------------------------------------------------------------

    def _print_banner(self, steps: list[StepName]) -> None:
        table = Table(title="PhantomCortex Pipeline", show_header=True)
        table.add_column("Parameter", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("Run ID", self._run_id)
        table.add_row("Mode", self._mode.name)
        table.add_row("Models", ", ".join(self._target_models))
        table.add_row("Steps", " → ".join(s.value for s in steps))
        table.add_row("Report", str(self._generate_report))
        table.add_row("Dry Run", str(self._dry_run))

        free_gb = _available_disk_gb(_DATA_DIR)
        table.add_row("Disk Free", f"{free_gb:.1f} GiB")

        console.print(Panel(table, border_style="blue"))

    def _print_summary(self) -> None:
        table = Table(title="Pipeline Summary")
        table.add_column("Step", style="cyan")
        table.add_column("Status")
        table.add_column("Duration", justify="right")
        table.add_column("Error")

        for r in self._results:
            status = "[green]PASS[/]" if r.success else "[red]FAIL[/]"
            table.add_row(r.name, status, f"{r.duration_s:.1f}s", r.error or "")

        total = sum(r.duration_s for r in self._results)
        ok = all(r.success for r in self._results)
        table.add_row("TOTAL", "[green]PASS[/]" if ok else "[red]FAIL[/]", f"{total:.1f}s", "")

        console.print(Panel(table, border_style="green" if ok else "red"))

    # -----------------------------------------------------------------------
    # Notifications
    # -----------------------------------------------------------------------

    def _notify(self) -> None:
        ok = all(r.success for r in self._results)
        subject = f"PhantomCortex {'✅ PASS' if ok else '❌ FAIL'} — {self._run_id}"
        body = f"Pipeline {self._mode.name} completed {'successfully' if ok else 'with failures'}.\n"
        for r in self._results:
            status = "PASS" if r.success else "FAIL"
            body += f"  {r.name}: {status} ({r.duration_s:.1f}s)"
            if r.error:
                body += f" — {r.error}"
            body += "\n"

        if self._cfg.webhook_enabled:
            _send_webhook(self._cfg.webhook_url, {
                "run_id": self._run_id,
                "mode": self._mode.name,
                "success": ok,
                "summary": body,
            })

        if self._cfg.email_enabled:
            _send_email(self._cfg.email_smtp, self._cfg.email_recipients, subject, body)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="PhantomCortex.training.pipeline",
        description="PhantomCortex nightly training pipeline orchestrator.",
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--full-train", action="store_const", dest="mode", const=PipelineMode.FULL_TRAIN,
        help="Full retrain from scratch.",
    )
    mode_group.add_argument(
        "--incremental", action="store_const", dest="mode", const=PipelineMode.INCREMENTAL,
        help="Fine-tune with new data only.",
    )
    mode_group.add_argument(
        "--evaluate-only", action="store_const", dest="mode", const=PipelineMode.EVALUATE_ONLY,
        help="Run evaluation on current models.",
    )
    mode_group.add_argument(
        "--export-only", action="store_const", dest="mode", const=PipelineMode.EXPORT_ONLY,
        help="Export and quantize current models.",
    )
    mode_group.add_argument(
        "--feed-sync-only", action="store_const", dest="mode", const=PipelineMode.FEED_SYNC_ONLY,
        help="Sync threat-intel feeds only.",
    )

    parser.add_argument(
        "--model", dest="models", action="append", default=None,
        choices=list(KNOWN_MODELS),
        help="Target a single model (may be repeated). Default: all models.",
    )
    parser.add_argument("--report", action="store_true", help="Generate metrics report.")
    parser.add_argument("--dry-run", action="store_true", help="Validate config and exit.")
    parser.add_argument("--resume", action="store_true", help="Resume from last checkpoint.")
    parser.add_argument(
        "--config", type=Path, default=_DEFAULT_DEPLOYMENT_CFG,
        help="Path to deployment.yaml.",
    )
    parser.add_argument(
        "--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level.",
    )
    return parser


def _configure_logging(level: str) -> None:
    """Set up structlog with human-readable console output."""
    import logging

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level, logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    _configure_logging(args.log_level)

    target_models = tuple(args.models) if args.models else None

    pipeline = PhantomCortexPipeline(
        mode=args.mode,
        target_models=target_models,
        generate_report=args.report,
        dry_run=args.dry_run,
        resume=args.resume,
        config_path=args.config,
    )

    try:
        results = pipeline.run()
    except PipelineError as exc:
        console.print(f"[bold red]Pipeline error:[/] {exc}")
        logger.error("pipeline_fatal", error=str(exc))
        return 1
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Aborted by user.[/]")
        return 130

    if results and not all(r.success for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

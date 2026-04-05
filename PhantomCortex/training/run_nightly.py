"""
PhantomCortex Nightly Training Pipeline Entrypoint
===================================================

Production entrypoint for unattended, scheduled retraining of all
PhantomCortex ML models.  Designed to run at 02:00 via Windows Task
Scheduler on enterprise endpoints.

Usage:
    python -m PhantomCortex.training.run_nightly --mode nightly
    python -m PhantomCortex.training.run_nightly --mode full --models static,behavioral
    python -m PhantomCortex.training.run_nightly --dry-run
    python -m PhantomCortex.training.run_nightly --install-task
    python -m PhantomCortex.training.run_nightly --uninstall-task

Author: ShadowStrike-Labs contact@ShadowStrike.dev
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import logging.handlers
import os
import platform
import shutil
import signal
import smtplib
import subprocess
import sys
import time
import traceback
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

import structlog
import yaml

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ROOT_DIR = Path(__file__).resolve().parent
_DEFAULT_CONFIG = _ROOT_DIR / "nightly_config.yaml"
_LOCK_FILE = _ROOT_DIR / ".nightly.lock"
_STALE_LOCK_HOURS = 6

_PRODUCTION_DIR = Path(r"C:\ProgramData\ShadowStrike\Models")
_STAGING_DIR = Path(r"C:\ProgramData\ShadowStrike\Models\staging")

_ALL_MODELS = ("static", "behavioral", "memory", "network", "emulation")

_EXIT_SUCCESS = 0
_EXIT_FAILURE = 1
_EXIT_PARTIAL = 2

_TASK_NAME = "ShadowStrike-PhantomCortex-Nightly"
_MIN_DISK_GB = 10.0
_LOG_RETENTION_DAYS = 30

logger = structlog.get_logger("phantomcortex.nightly")

# ---------------------------------------------------------------------------
# Structured logging setup
# ---------------------------------------------------------------------------


def _configure_logging(level_name: str, log_file: Path | None) -> None:
    """Configure dual console + file structured logging."""
    numeric_level = getattr(logging, level_name.upper(), logging.INFO)

    handlers: list[logging.Handler] = []

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(numeric_level)
    handlers.append(console_handler)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            str(log_file),
            maxBytes=100 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(numeric_level)
        handlers.append(file_handler)

    logging.basicConfig(
        level=numeric_level,
        handlers=handlers,
        format="%(message)s",
        force=True,
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )


# ---------------------------------------------------------------------------
# Lock management
# ---------------------------------------------------------------------------


def _acquire_lock() -> None:
    """Acquire an exclusive file lock; override if stale."""
    if _LOCK_FILE.exists():
        try:
            info = json.loads(_LOCK_FILE.read_text(encoding="utf-8"))
            pid = info.get("pid")
            ts_str = info.get("timestamp", "")
            if ts_str:
                lock_time = datetime.datetime.fromisoformat(ts_str)
                age_hours = (
                    datetime.datetime.now(datetime.timezone.utc) - lock_time
                ).total_seconds() / 3600.0
            else:
                age_hours = float("inf")

            if _pid_alive(pid) and age_hours < _STALE_LOCK_HOURS:
                raise SystemExit(
                    f"[ABORT] Pipeline already running (PID {pid}, "
                    f"started {ts_str}).  Remove {_LOCK_FILE} if stale."
                )
            logger.warning(
                "overriding_stale_lock",
                stale_pid=pid,
                age_hours=round(age_hours, 1),
            )
        except (json.JSONDecodeError, KeyError, ValueError):
            logger.warning("corrupt_lock_file_overridden", path=str(_LOCK_FILE))

    _LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "pid": os.getpid(),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(
            timespec="seconds"
        ),
    }
    _LOCK_FILE.write_text(json.dumps(payload), encoding="utf-8")
    logger.info("lock_acquired", pid=os.getpid(), path=str(_LOCK_FILE))


def _release_lock() -> None:
    """Release the pipeline lock file."""
    try:
        if _LOCK_FILE.exists():
            _LOCK_FILE.unlink()
            logger.info("lock_released")
    except OSError as exc:
        logger.warning("lock_release_failed", error=str(exc))


def _pid_alive(pid: int | None) -> bool:
    """Check whether a process is still running."""
    if pid is None:
        return False
    try:
        if platform.system() == "Windows":
            import ctypes

            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            handle = kernel32.OpenProcess(0x100000, False, pid)
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
# System checks
# ---------------------------------------------------------------------------


def _check_disk_space(path: Path, min_gb: float) -> float:
    """Return free GiB; raise SystemExit if below threshold."""
    try:
        usage = shutil.disk_usage(str(path))
    except OSError:
        usage = shutil.disk_usage(str(Path.home()))
    free_gb = usage.free / (1024**3)
    if free_gb < min_gb:
        raise SystemExit(
            f"[ABORT] Insufficient disk: {free_gb:.1f} GiB free, "
            f"need {min_gb:.1f} GiB on {path.anchor}"
        )
    return free_gb


def _detect_gpu() -> dict[str, Any]:
    """Probe CUDA availability; returns info dict."""
    info: dict[str, Any] = {"available": False, "device_count": 0, "devices": []}
    try:
        import torch

        info["available"] = torch.cuda.is_available()
        info["device_count"] = torch.cuda.device_count()
        for idx in range(info["device_count"]):
            props = torch.cuda.get_device_properties(idx)
            info["devices"].append(
                {
                    "name": props.name,
                    "total_memory_mb": round(props.total_memory / (1024**2)),
                }
            )
    except ImportError:
        info["torch_available"] = False
    return info


def _system_info_banner(gpu: dict[str, Any], disk_gb: float) -> str:
    """Build a multi-line system information banner."""
    try:
        import psutil

        ram_gb = round(psutil.virtual_memory().total / (1024**3), 1)
    except ImportError:
        ram_gb = 0.0

    lines = [
        "=" * 64,
        "  PhantomCortex Nightly Pipeline",
        "=" * 64,
        f"  Host      : {platform.node()}",
        f"  OS        : {platform.platform()}",
        f"  Python    : {platform.python_version()}",
        f"  PID       : {os.getpid()}",
        f"  RAM       : {ram_gb} GiB",
        f"  Disk free : {disk_gb:.1f} GiB",
    ]
    if gpu["available"]:
        for dev in gpu["devices"]:
            lines.append(
                f"  GPU       : {dev['name']} ({dev['total_memory_mb']} MB)"
            )
    else:
        lines.append("  GPU       : Not available (CPU-only mode)")
    lines.append("=" * 64)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------


def _load_config(path: Path | None) -> dict[str, Any]:
    """Load and validate the nightly YAML config file."""
    if path is None:
        path = _DEFAULT_CONFIG
    if not path.exists():
        logger.warning("config_not_found_using_defaults", path=str(path))
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise SystemExit(f"[ABORT] Config file {path} is not a valid YAML mapping")
    return data


def _resolve_production_dir(cli_override: str | None, cfg: dict[str, Any]) -> Path:
    dirs = cfg.get("directories", {})
    if cli_override:
        return Path(cli_override)
    return Path(dirs.get("production", str(_PRODUCTION_DIR)))


def _resolve_staging_dir(cli_override: str | None, cfg: dict[str, Any]) -> Path:
    dirs = cfg.get("directories", {})
    if cli_override:
        return Path(cli_override)
    return Path(dirs.get("staging", str(_STAGING_DIR)))


def _resolve_log_file(cli_override: str | None, cfg: dict[str, Any]) -> Path:
    if cli_override:
        return Path(cli_override)
    log_dir_name = cfg.get("directories", {}).get("logs", "logs")
    log_dir = _ROOT_DIR / log_dir_name
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d")
    return log_dir / f"nightly_{today}.log"


def _parse_models(raw: str | None) -> tuple[str, ...]:
    """Parse comma-separated model list; validate names."""
    if not raw:
        return _ALL_MODELS
    names = [m.strip() for m in raw.split(",") if m.strip()]
    for name in names:
        if name not in _ALL_MODELS:
            raise SystemExit(
                f"[ABORT] Unknown model '{name}'. "
                f"Valid: {', '.join(_ALL_MODELS)}"
            )
    return tuple(names)


# ---------------------------------------------------------------------------
# Mode mapping
# ---------------------------------------------------------------------------


def _resolve_pipeline_mode(mode_str: str) -> Any:
    """Map CLI mode string to PipelineMode enum from pipeline.py."""
    from PhantomCortex.training.pipeline import PipelineMode

    mapping = {
        "nightly": PipelineMode.INCREMENTAL,
        "full": PipelineMode.FULL_TRAIN,
        "evaluate": PipelineMode.EVALUATE_ONLY,
    }
    result = mapping.get(mode_str)
    if result is None:
        raise SystemExit(f"[ABORT] Unknown mode '{mode_str}'")
    return result


# ---------------------------------------------------------------------------
# Pipeline execution
# ---------------------------------------------------------------------------


_interrupted = False


def _signal_handler(signum: int, _frame: Any) -> None:
    global _interrupted
    _interrupted = True
    logger.warning("signal_received", signal=signum)


def _run_pipeline(args: argparse.Namespace, cfg: dict[str, Any]) -> int:
    """Core execution: instantiate pipeline, run, return exit code."""
    from PhantomCortex.training.pipeline import (
        PhantomCortexPipeline,
        PipelineError,
    )

    mode = _resolve_pipeline_mode(args.mode)
    models = _parse_models(args.models)
    production_dir = _resolve_production_dir(args.production_dir, cfg)
    staging_dir = _resolve_staging_dir(args.staging_dir, cfg)

    for d in (production_dir, staging_dir):
        d.mkdir(parents=True, exist_ok=True)

    skip_feeds = args.skip_feeds
    skip_training = args.skip_training

    pipeline = PhantomCortexPipeline(
        mode=mode,
        target_models=models,
        generate_report=True,
        dry_run=args.dry_run,
        resume=False,
        config_path=args.config if args.config else _ROOT_DIR / "config" / "deployment.yaml",
    )

    # Override deployment paths if the user specified custom directories.
    pipeline._cfg.production_dir = production_dir  # noqa: SLF001
    pipeline._cfg.staging_dir = staging_dir  # noqa: SLF001

    # Wire webhook/email from CLI overrides into the pipeline config.
    if args.notify_webhook:
        pipeline._cfg.webhook_enabled = True  # noqa: SLF001
        pipeline._cfg.webhook_url = args.notify_webhook  # noqa: SLF001
    if args.notify_email:
        pipeline._cfg.email_enabled = True  # noqa: SLF001
        pipeline._cfg.email_recipients = [args.notify_email]  # noqa: SLF001

    t_start = time.monotonic()

    try:
        results = pipeline.run()
    except PipelineError as exc:
        logger.error("pipeline_error", error=str(exc))
        _send_failure_notification(args, cfg, str(exc), time.monotonic() - t_start)
        return _EXIT_FAILURE
    except KeyboardInterrupt:
        logger.warning("pipeline_aborted_by_user")
        return _EXIT_FAILURE

    elapsed = time.monotonic() - t_start

    if not results:
        # Dry-run or empty result set
        return _EXIT_SUCCESS

    all_ok = all(r.success for r in results)
    any_ok = any(r.success for r in results)

    _print_summary(results, elapsed)
    _send_completion_notification(args, cfg, results, elapsed)

    if all_ok:
        return _EXIT_SUCCESS
    if any_ok:
        return _EXIT_PARTIAL
    return _EXIT_FAILURE


# ---------------------------------------------------------------------------
# Summary + notifications
# ---------------------------------------------------------------------------


def _print_summary(results: list[Any], elapsed: float) -> None:
    """Print a plain-text summary suitable for log capture."""
    print("\n" + "=" * 64)
    print("  NIGHTLY PIPELINE SUMMARY")
    print("=" * 64)
    for r in results:
        status = "PASS" if r.success else "FAIL"
        line = f"  [{status}] {r.name:<20s}  {r.duration_s:>7.1f}s"
        if r.error:
            line += f"  -- {r.error[:60]}"
        print(line)
    overall = "PASS" if all(r.success for r in results) else "FAIL"
    print("-" * 64)
    print(f"  OVERALL: {overall}   Total: {elapsed:.1f}s")
    print("=" * 64 + "\n")


def _build_webhook_payload(
    results: list[Any], elapsed: float, success: bool
) -> dict[str, Any]:
    """Build a JSON-serializable payload for webhook notification."""
    return {
        "source": "PhantomCortex-Nightly",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(
            timespec="seconds"
        ),
        "host": platform.node(),
        "success": success,
        "elapsed_seconds": round(elapsed, 1),
        "steps": [
            {
                "name": r.name,
                "success": r.success,
                "duration_s": round(r.duration_s, 2),
                "error": r.error,
            }
            for r in results
        ],
    }


def _send_webhook(url: str, payload: dict[str, Any], timeout: int = 30) -> None:
    """Fire-and-forget webhook POST.  Failures are logged, never raised."""
    try:
        import urllib.request

        data = json.dumps(payload, default=str).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            logger.info("webhook_sent", status=resp.status)
    except Exception as exc:  # noqa: BLE001
        logger.warning("webhook_failed", error=str(exc))


def _send_email_notification(
    cfg: dict[str, Any],
    recipient: str,
    subject: str,
    body: str,
) -> None:
    """Best-effort email via SMTP.  Failures are logged, never raised."""
    notif = cfg.get("notifications", {}).get("email", {})
    smtp_server = notif.get("smtp_server", "")
    smtp_port = notif.get("smtp_port", 25)
    use_tls = notif.get("use_tls", False)
    sender = notif.get("sender", "phantomcortex@shadowstrike.local")

    if not smtp_server:
        logger.warning("email_skipped_no_smtp_server")
        return

    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = recipient

        with smtplib.SMTP(smtp_server, smtp_port, timeout=30) as srv:
            if use_tls:
                srv.starttls()
            srv.send_message(msg)
        logger.info("email_sent", recipient=recipient)
    except Exception as exc:  # noqa: BLE001
        logger.warning("email_failed", recipient=recipient, error=str(exc))


def _send_completion_notification(
    args: argparse.Namespace,
    cfg: dict[str, Any],
    results: list[Any],
    elapsed: float,
) -> None:
    """Dispatch webhook and email after a completed run."""
    success = all(r.success for r in results)
    tag = "PASS" if success else "FAIL"

    if args.notify_webhook:
        payload = _build_webhook_payload(results, elapsed, success)
        _send_webhook(args.notify_webhook, payload)

    if args.notify_email:
        subject = f"PhantomCortex Nightly [{tag}] - {platform.node()}"
        lines = [f"Pipeline completed: {tag}", f"Elapsed: {elapsed:.1f}s", ""]
        for r in results:
            s = "PASS" if r.success else "FAIL"
            lines.append(f"  [{s}] {r.name} ({r.duration_s:.1f}s)")
            if r.error:
                lines.append(f"        Error: {r.error}")
        _send_email_notification(cfg, args.notify_email, subject, "\n".join(lines))


def _send_failure_notification(
    args: argparse.Namespace,
    cfg: dict[str, Any],
    error_msg: str,
    elapsed: float,
) -> None:
    """Dispatch error notifications when the pipeline raised a fatal error."""
    if args.notify_webhook:
        payload = {
            "source": "PhantomCortex-Nightly",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(
                timespec="seconds"
            ),
            "host": platform.node(),
            "success": False,
            "elapsed_seconds": round(elapsed, 1),
            "error": error_msg,
        }
        _send_webhook(args.notify_webhook, payload)

    if args.notify_email:
        subject = f"PhantomCortex Nightly [FATAL] - {platform.node()}"
        body = f"Pipeline failed with fatal error:\n\n{error_msg}\n\nElapsed: {elapsed:.1f}s"
        _send_email_notification(cfg, args.notify_email, subject, body)


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------


def _cleanup_old_logs(log_dir: Path, retention_days: int) -> None:
    """Remove log files older than *retention_days*."""
    if not log_dir.exists():
        return
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        days=retention_days
    )
    removed = 0
    for entry in log_dir.iterdir():
        if not entry.is_file():
            continue
        try:
            mtime = datetime.datetime.fromtimestamp(
                entry.stat().st_mtime, tz=datetime.timezone.utc
            )
            if mtime < cutoff:
                entry.unlink()
                removed += 1
        except OSError:
            pass
    if removed:
        logger.info("old_logs_cleaned", removed=removed, retention_days=retention_days)


def _cleanup_temp(cfg: dict[str, Any]) -> None:
    """Remove the temp working directory if it exists."""
    temp_name = cfg.get("directories", {}).get("temp", "data/tmp")
    temp_dir = _ROOT_DIR / temp_name
    if temp_dir.exists():
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
            logger.info("temp_cleaned", path=str(temp_dir))
        except OSError as exc:
            logger.warning("temp_cleanup_failed", error=str(exc))


# ---------------------------------------------------------------------------
# Windows Task Scheduler
# ---------------------------------------------------------------------------


def install_scheduled_task(python_exe: str | None = None) -> int:
    """Register a Windows Task Scheduler entry for nightly 02:00 runs.

    Returns 0 on success, 1 on failure.
    """
    if platform.system() != "Windows":
        print("[ERROR] Task Scheduler is only available on Windows.")
        return 1

    if python_exe is None:
        python_exe = sys.executable

    script_path = str(Path(__file__).resolve())
    run_time = "02:00"
    task_name = _TASK_NAME

    # schtasks XML is the most reliable way to create tasks with full control.
    xml_template = (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
        "  <RegistrationInfo>\n"
        "    <Description>PhantomCortex nightly ML model retraining pipeline</Description>\n"
        "    <Author>ShadowStrike-Labs</Author>\n"
        "  </RegistrationInfo>\n"
        "  <Triggers>\n"
        "    <CalendarTrigger>\n"
        "      <StartBoundary>2024-01-01T{run_time}:00</StartBoundary>\n"
        "      <Enabled>true</Enabled>\n"
        "      <ScheduleByDay>\n"
        "        <DaysInterval>1</DaysInterval>\n"
        "      </ScheduleByDay>\n"
        "    </CalendarTrigger>\n"
        "  </Triggers>\n"
        "  <Principals>\n"
        "    <Principal>\n"
        "      <UserId>S-1-5-18</UserId>\n"
        "      <RunLevel>HighestAvailable</RunLevel>\n"
        "    </Principal>\n"
        "  </Principals>\n"
        "  <Settings>\n"
        "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n"
        "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n"
        "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n"
        "    <AllowHardTerminate>true</AllowHardTerminate>\n"
        "    <StartWhenAvailable>true</StartWhenAvailable>\n"
        "    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n"
        "    <WakeToRun>true</WakeToRun>\n"
        "    <ExecutionTimeLimit>PT12H</ExecutionTimeLimit>\n"
        "    <Priority>4</Priority>\n"
        "  </Settings>\n"
        "  <Actions>\n"
        "    <Exec>\n"
        "      <Command>{python_exe}</Command>\n"
        '      <Arguments>"{script_path}" --mode nightly --log-level INFO</Arguments>\n'
        "      <WorkingDirectory>{work_dir}</WorkingDirectory>\n"
        "    </Exec>\n"
        "  </Actions>\n"
        "</Task>"
    ).format(
        run_time=run_time,
        python_exe=python_exe,
        script_path=script_path,
        work_dir=str(_ROOT_DIR),
    )

    xml_path = _ROOT_DIR / ".nightly_task.xml"
    try:
        xml_path.write_text(xml_template, encoding="utf-16")

        result = subprocess.run(
            [
                "schtasks.exe",
                "/Create",
                "/TN",
                task_name,
                "/XML",
                str(xml_path),
                "/F",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            print(f"[ERROR] schtasks failed: {result.stderr.strip()}")
            return 1

        print(f"[OK] Scheduled task '{task_name}' installed for daily {run_time}.")
        return 0
    except FileNotFoundError:
        print("[ERROR] schtasks.exe not found. Run from an elevated prompt.")
        return 1
    except subprocess.TimeoutExpired:
        print("[ERROR] schtasks.exe timed out.")
        return 1
    finally:
        if xml_path.exists():
            try:
                xml_path.unlink()
            except OSError:
                pass


def uninstall_scheduled_task() -> int:
    """Remove the PhantomCortex nightly scheduled task.

    Returns 0 on success, 1 on failure.
    """
    if platform.system() != "Windows":
        print("[ERROR] Task Scheduler is only available on Windows.")
        return 1

    try:
        result = subprocess.run(
            ["schtasks.exe", "/Delete", "/TN", _TASK_NAME, "/F"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            print(f"[ERROR] schtasks failed: {result.stderr.strip()}")
            return 1
        print(f"[OK] Scheduled task '{_TASK_NAME}' removed.")
        return 0
    except FileNotFoundError:
        print("[ERROR] schtasks.exe not found.")
        return 1
    except subprocess.TimeoutExpired:
        print("[ERROR] schtasks.exe timed out.")
        return 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_nightly",
        description=(
            "PhantomCortex nightly retraining entrypoint.  "
            "Orchestrates feed sync, training, evaluation, export, "
            "quality gates, staging, and notifications."
        ),
    )

    parser.add_argument(
        "--mode",
        choices=("nightly", "full", "evaluate"),
        default="nightly",
        help="Pipeline execution mode (default: nightly).",
    )
    parser.add_argument(
        "--models",
        type=str,
        default=None,
        help="Comma-separated model names to process (default: all 5).",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to nightly YAML config file.",
    )
    parser.add_argument(
        "--production-dir",
        type=str,
        default=None,
        help="Override production model directory.",
    )
    parser.add_argument(
        "--staging-dir",
        type=str,
        default=None,
        help="Override staging model directory.",
    )
    parser.add_argument(
        "--skip-feeds",
        action="store_true",
        help="Skip feed sync (offline environments).",
    )
    parser.add_argument(
        "--skip-training",
        action="store_true",
        help="Skip training; run eval + export only.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate configuration and exit without running.",
    )
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        default="INFO",
        help="Logging verbosity (default: INFO).",
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Log file path (default: logs/nightly_YYYYMMDD.log).",
    )
    parser.add_argument(
        "--notify-webhook",
        type=str,
        default=None,
        help="Webhook URL for completion notifications.",
    )
    parser.add_argument(
        "--notify-email",
        type=str,
        default=None,
        help="Email address for completion notifications.",
    )
    parser.add_argument(
        "--install-task",
        action="store_true",
        help="Install Windows Task Scheduler entry and exit.",
    )
    parser.add_argument(
        "--uninstall-task",
        action="store_true",
        help="Remove Windows Task Scheduler entry and exit.",
    )

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # ---- Task Scheduler management (exit early) ---------------------------
    if args.install_task:
        return install_scheduled_task()
    if args.uninstall_task:
        return uninstall_scheduled_task()

    # ---- Load config ------------------------------------------------------
    cfg = _load_config(args.config or _DEFAULT_CONFIG)
    nightly_cfg = cfg.get("pipeline", {})
    res_cfg = cfg.get("resources", {})
    log_cfg = cfg.get("logging", {})

    min_disk = res_cfg.get("min_disk_gb", _MIN_DISK_GB)
    retention_days = log_cfg.get("retention_days", _LOG_RETENTION_DAYS)

    # ---- Logging ----------------------------------------------------------
    log_file = _resolve_log_file(args.log_file, cfg)
    _configure_logging(args.log_level, log_file)

    logger.info(
        "nightly_start",
        mode=args.mode,
        models=args.models or "all",
        dry_run=args.dry_run,
        pid=os.getpid(),
    )

    # ---- Signal handling --------------------------------------------------
    signal.signal(signal.SIGINT, _signal_handler)
    if platform.system() != "Windows":
        signal.signal(signal.SIGTERM, _signal_handler)

    # ---- Pre-flight -------------------------------------------------------
    try:
        disk_gb = _check_disk_space(_ROOT_DIR, min_disk)
    except SystemExit as exc:
        logger.error("preflight_disk_check_failed", error=str(exc))
        raise

    gpu_info = _detect_gpu()
    banner = _system_info_banner(gpu_info, disk_gb)
    print(banner)
    logger.info("system_info", gpu_available=gpu_info["available"], disk_gb=round(disk_gb, 1))

    # ---- Validate models early --------------------------------------------
    if args.models:
        try:
            _parse_models(args.models)
        except SystemExit:
            raise

    # ---- Dry run ----------------------------------------------------------
    if args.dry_run:
        print("\n[DRY RUN] Configuration validated successfully. Exiting.")
        logger.info("dry_run_complete")
        return _EXIT_SUCCESS

    # ---- Acquire lock -----------------------------------------------------
    try:
        _acquire_lock()
    except SystemExit:
        logger.error("lock_acquisition_failed")
        raise

    exit_code = _EXIT_FAILURE
    try:
        exit_code = _run_pipeline(args, cfg)
    except Exception:
        logger.error("unhandled_exception", traceback=traceback.format_exc())
        exit_code = _EXIT_FAILURE
    finally:
        _release_lock()
        _cleanup_temp(cfg)
        log_dir = log_file.parent if log_file else _ROOT_DIR / "logs"
        _cleanup_old_logs(log_dir, retention_days)

    status_label = {0: "SUCCESS", 1: "FAILURE", 2: "PARTIAL"}.get(exit_code, "UNKNOWN")
    logger.info("nightly_exit", exit_code=exit_code, status=status_label)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

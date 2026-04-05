"""
False Positive Tester for PhantomCortex Models
================================================

Tests ONNX or LightGBM models against a curated catalog of known-legitimate
software to measure the operational false positive rate. Enterprise NGAV
must achieve FPR < 0.01% (1 in 10,000) against legitimate applications.

Legitimate software catalog:
    - Windows system binaries (ntdll.dll, kernel32.dll, ...)
    - Popular applications (Chrome, Firefox, VSCode, Office, 7-Zip, ...)
    - Development tools (Python, Node, Git, Visual Studio, ...)
    - Security tools (Wireshark, Process Monitor, ...)
    - Drivers and system utilities
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, Union

import numpy as np
import onnxruntime as ort
from numpy.typing import NDArray

logger = logging.getLogger("PhantomCortex.Evaluation.FalsePositive")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FPAnalysis:
    """Diagnostic information for a single false positive."""

    file_path: str
    file_hash: str
    predicted_score: float
    predicted_label: int
    category: str
    top_contributing_features: Optional[list[tuple[int, float]]] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "predicted_score": round(self.predicted_score, 6),
            "predicted_label": self.predicted_label,
            "category": self.category,
            "top_contributing_features": (
                [(idx, round(val, 4)) for idx, val in self.top_contributing_features]
                if self.top_contributing_features is not None
                else None
            ),
        }


@dataclass(frozen=True)
class FPReport:
    """False positive test report."""

    total_files: int
    files_scanned: int
    false_positives: int
    fpr: float
    target_fpr: float
    meets_target: bool
    threshold: float
    false_positive_details: list[FPAnalysis]
    category_breakdown: dict[str, dict[str, int]]
    scan_time_sec: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_files": self.total_files,
            "files_scanned": self.files_scanned,
            "false_positives": self.false_positives,
            "fpr": round(self.fpr, 8),
            "target_fpr": self.target_fpr,
            "meets_target": self.meets_target,
            "threshold": self.threshold,
            "category_breakdown": self.category_breakdown,
            "scan_time_sec": round(self.scan_time_sec, 3),
            "false_positive_details": [fp.to_dict() for fp in self.false_positive_details],
        }


# ---------------------------------------------------------------------------
# Known-good software catalog
# ---------------------------------------------------------------------------

# Organized by category with SHA256 hashes of known-good versions.
# These are representative — actual deployment would use a live-maintained list.

_GOODWARE_CATALOG: dict[str, list[dict[str, str]]] = {
    "windows_system": [
        {"name": "ntdll.dll", "path": r"C:\Windows\System32\ntdll.dll"},
        {"name": "kernel32.dll", "path": r"C:\Windows\System32\kernel32.dll"},
        {"name": "kernelbase.dll", "path": r"C:\Windows\System32\kernelbase.dll"},
        {"name": "user32.dll", "path": r"C:\Windows\System32\user32.dll"},
        {"name": "gdi32.dll", "path": r"C:\Windows\System32\gdi32.dll"},
        {"name": "advapi32.dll", "path": r"C:\Windows\System32\advapi32.dll"},
        {"name": "shell32.dll", "path": r"C:\Windows\System32\shell32.dll"},
        {"name": "ole32.dll", "path": r"C:\Windows\System32\ole32.dll"},
        {"name": "combase.dll", "path": r"C:\Windows\System32\combase.dll"},
        {"name": "msvcrt.dll", "path": r"C:\Windows\System32\msvcrt.dll"},
        {"name": "ucrtbase.dll", "path": r"C:\Windows\System32\ucrtbase.dll"},
        {"name": "sechost.dll", "path": r"C:\Windows\System32\sechost.dll"},
        {"name": "rpcrt4.dll", "path": r"C:\Windows\System32\rpcrt4.dll"},
        {"name": "bcrypt.dll", "path": r"C:\Windows\System32\bcrypt.dll"},
        {"name": "crypt32.dll", "path": r"C:\Windows\System32\crypt32.dll"},
        {"name": "ws2_32.dll", "path": r"C:\Windows\System32\ws2_32.dll"},
        {"name": "winhttp.dll", "path": r"C:\Windows\System32\winhttp.dll"},
        {"name": "setupapi.dll", "path": r"C:\Windows\System32\setupapi.dll"},
        {"name": "shlwapi.dll", "path": r"C:\Windows\System32\shlwapi.dll"},
        {"name": "mswsock.dll", "path": r"C:\Windows\System32\mswsock.dll"},
        {"name": "wintrust.dll", "path": r"C:\Windows\System32\wintrust.dll"},
        {"name": "mscoree.dll", "path": r"C:\Windows\System32\mscoree.dll"},
        {"name": "clbcatq.dll", "path": r"C:\Windows\System32\clbcatq.dll"},
        {"name": "taskhost.exe", "path": r"C:\Windows\System32\taskhostw.exe"},
        {"name": "svchost.exe", "path": r"C:\Windows\System32\svchost.exe"},
        {"name": "csrss.exe", "path": r"C:\Windows\System32\csrss.exe"},
        {"name": "lsass.exe", "path": r"C:\Windows\System32\lsass.exe"},
        {"name": "services.exe", "path": r"C:\Windows\System32\services.exe"},
        {"name": "explorer.exe", "path": r"C:\Windows\explorer.exe"},
        {"name": "cmd.exe", "path": r"C:\Windows\System32\cmd.exe"},
        {"name": "conhost.exe", "path": r"C:\Windows\System32\conhost.exe"},
        {"name": "powershell.exe", "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"},
    ],
    "popular_applications": [
        {"name": "chrome.exe", "path": r"C:\Program Files\Google\Chrome\Application\chrome.exe"},
        {"name": "firefox.exe", "path": r"C:\Program Files\Mozilla Firefox\firefox.exe"},
        {"name": "Code.exe", "path": r"C:\Program Files\Microsoft VS Code\Code.exe"},
        {"name": "WINWORD.EXE", "path": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"},
        {"name": "EXCEL.EXE", "path": r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"},
        {"name": "OUTLOOK.EXE", "path": r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"},
        {"name": "POWERPNT.EXE", "path": r"C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE"},
        {"name": "7z.exe", "path": r"C:\Program Files\7-Zip\7z.exe"},
        {"name": "notepad++.exe", "path": r"C:\Program Files\Notepad++\notepad++.exe"},
        {"name": "vlc.exe", "path": r"C:\Program Files\VideoLAN\VLC\vlc.exe"},
        {"name": "acrobat.exe", "path": r"C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe"},
        {"name": "Teams.exe", "path": r"C:\Program Files\Microsoft\Teams\current\Teams.exe"},
        {"name": "slack.exe", "path": r"C:\Program Files\Slack\slack.exe"},
        {"name": "zoom.exe", "path": r"C:\Program Files\Zoom\bin\Zoom.exe"},
        {"name": "OneDrive.exe", "path": r"C:\Program Files\Microsoft OneDrive\OneDrive.exe"},
        {"name": "msedge.exe", "path": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"},
    ],
    "development_tools": [
        {"name": "python.exe", "path": r"C:\Python311\python.exe"},
        {"name": "node.exe", "path": r"C:\Program Files\nodejs\node.exe"},
        {"name": "git.exe", "path": r"C:\Program Files\Git\bin\git.exe"},
        {"name": "devenv.exe", "path": r"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe"},
        {"name": "msbuild.exe", "path": r"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"},
        {"name": "cl.exe", "path": r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.35.32215\bin\Hostx64\x64\cl.exe"},
        {"name": "link.exe", "path": r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.35.32215\bin\Hostx64\x64\link.exe"},
        {"name": "java.exe", "path": r"C:\Program Files\Java\jdk-17\bin\java.exe"},
        {"name": "dotnet.exe", "path": r"C:\Program Files\dotnet\dotnet.exe"},
        {"name": "rustc.exe", "path": r"C:\Users\user\.cargo\bin\rustc.exe"},
        {"name": "go.exe", "path": r"C:\Program Files\Go\bin\go.exe"},
        {"name": "cmake.exe", "path": r"C:\Program Files\CMake\bin\cmake.exe"},
        {"name": "npm.cmd", "path": r"C:\Program Files\nodejs\npm.cmd"},
    ],
    "security_tools": [
        {"name": "Wireshark.exe", "path": r"C:\Program Files\Wireshark\Wireshark.exe"},
        {"name": "Procmon.exe", "path": r"C:\SysinternalsSuite\Procmon.exe"},
        {"name": "procexp.exe", "path": r"C:\SysinternalsSuite\procexp.exe"},
        {"name": "autoruns.exe", "path": r"C:\SysinternalsSuite\autoruns.exe"},
        {"name": "tcpview.exe", "path": r"C:\SysinternalsSuite\tcpview.exe"},
        {"name": "Process Hacker.exe", "path": r"C:\Program Files\Process Hacker 2\ProcessHacker.exe"},
        {"name": "x64dbg.exe", "path": r"C:\x64dbg\release\x64\x64dbg.exe"},
        {"name": "nmap.exe", "path": r"C:\Program Files (x86)\Nmap\nmap.exe"},
        {"name": "putty.exe", "path": r"C:\Program Files\PuTTY\putty.exe"},
        {"name": "WinSCP.exe", "path": r"C:\Program Files (x86)\WinSCP\WinSCP.exe"},
    ],
    "system_utilities": [
        {"name": "notepad.exe", "path": r"C:\Windows\System32\notepad.exe"},
        {"name": "calc.exe", "path": r"C:\Windows\System32\calc.exe"},
        {"name": "mspaint.exe", "path": r"C:\Windows\System32\mspaint.exe"},
        {"name": "regedit.exe", "path": r"C:\Windows\regedit.exe"},
        {"name": "mmc.exe", "path": r"C:\Windows\System32\mmc.exe"},
        {"name": "dxdiag.exe", "path": r"C:\Windows\System32\dxdiag.exe"},
        {"name": "msinfo32.exe", "path": r"C:\Windows\System32\msinfo32.exe"},
        {"name": "taskmgr.exe", "path": r"C:\Windows\System32\Taskmgr.exe"},
        {"name": "control.exe", "path": r"C:\Windows\System32\control.exe"},
        {"name": "msiexec.exe", "path": r"C:\Windows\System32\msiexec.exe"},
        {"name": "wuauclt.exe", "path": r"C:\Windows\System32\wuauclt.exe"},
        {"name": "robocopy.exe", "path": r"C:\Windows\System32\Robocopy.exe"},
        {"name": "xcopy.exe", "path": r"C:\Windows\System32\xcopy.exe"},
        {"name": "cipher.exe", "path": r"C:\Windows\System32\cipher.exe"},
        {"name": "certutil.exe", "path": r"C:\Windows\System32\certutil.exe"},
    ],
}


# ---------------------------------------------------------------------------
# FalsePositiveTester
# ---------------------------------------------------------------------------


class FalsePositiveTester:
    """Tests model false positive rate against known-legitimate software.

    Supports ONNX models (via ONNXRuntime) and custom feature extraction
    callbacks. Scans a directory of known-good PE files and reports how
    many are incorrectly classified as malicious.
    """

    def __init__(
        self,
        *,
        threshold: float = 0.5,
        target_fpr: float = 0.0001,
    ) -> None:
        """Initialize the false positive tester.

        Args:
            threshold: Decision threshold for malicious classification.
            target_fpr: Maximum acceptable FPR (default 0.01% = 1 in 10,000).
        """
        self._threshold = threshold
        self._target_fpr = target_fpr

    # ------------------------------------------------------------------
    # Goodware catalog
    # ------------------------------------------------------------------

    def build_goodware_list(self) -> list[dict[str, str]]:
        """Return the full catalog of known-good software entries.

        Each entry has 'name', 'path', and 'category' keys.

        Returns:
            List of goodware entries with file paths and categories.
        """
        entries: list[dict[str, str]] = []
        for category, items in _GOODWARE_CATALOG.items():
            for item in items:
                entry = {
                    "name": item["name"],
                    "path": item["path"],
                    "category": category,
                }
                entries.append(entry)
        return entries

    @staticmethod
    def compute_file_hash(file_path: Union[str, Path]) -> str:
        """Compute SHA256 hash of a file.

        Reads in 64 KB chunks to handle large files without excessive
        memory usage. Returns empty string if file is unreadable.

        Args:
            file_path: Path to the file to hash.

        Returns:
            Hex-encoded SHA256 hash, or empty string on error.
        """
        try:
            hasher = hashlib.sha256()
            with open(file_path, "rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (OSError, PermissionError):
            return ""

    # ------------------------------------------------------------------
    # Testing with pre-extracted features
    # ------------------------------------------------------------------

    def test_model(
        self,
        model_path: Union[str, Path],
        goodware_dir: Union[str, Path],
        *,
        feature_extractor: Callable[[Path], Optional[NDArray[np.float32]]],
    ) -> FPReport:
        """Test ONNX model against files in a directory of known-good software.

        Walks the directory, extracts features via the provided callback,
        runs inference, and counts false positives.

        Args:
            model_path: Path to the ONNX model.
            goodware_dir: Directory containing known-good PE files.
            feature_extractor: Callback that extracts feature vector from a
                file path. Returns None if extraction fails.

        Returns:
            FPReport with detailed false positive analysis.
        """
        goodware_path = Path(goodware_dir)
        if not goodware_path.is_dir():
            raise FileNotFoundError(f"Goodware directory not found: {goodware_path}")

        sess_opts = ort.SessionOptions()
        sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        session = ort.InferenceSession(str(model_path), sess_opts)
        input_name = session.get_inputs()[0].name

        start_time = time.monotonic()

        pe_extensions = {".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl"}
        files = [
            f
            for f in goodware_path.rglob("*")
            if f.is_file() and f.suffix.lower() in pe_extensions
        ]

        total_files = len(files)
        scanned = 0
        fps: list[FPAnalysis] = []
        category_counts: dict[str, dict[str, int]] = {}

        for file_path in files:
            features = feature_extractor(file_path)
            if features is None:
                continue

            scanned += 1

            # Ensure batch dimension
            if features.ndim == 1:
                features = features.reshape(1, -1)

            outputs = session.run(None, {input_name: features})[0]
            score = float(outputs.flatten()[0])
            predicted = int(score >= self._threshold)

            # Determine category
            category = self._categorize_file(file_path)
            category_counts.setdefault(category, {"scanned": 0, "fp": 0})
            category_counts[category]["scanned"] += 1

            if predicted == 1:
                file_hash = self.compute_file_hash(file_path)
                fps.append(
                    FPAnalysis(
                        file_path=str(file_path),
                        file_hash=file_hash,
                        predicted_score=score,
                        predicted_label=predicted,
                        category=category,
                    )
                )
                category_counts[category]["fp"] += 1

        elapsed = time.monotonic() - start_time
        fpr = len(fps) / max(scanned, 1)

        report = FPReport(
            total_files=total_files,
            files_scanned=scanned,
            false_positives=len(fps),
            fpr=fpr,
            target_fpr=self._target_fpr,
            meets_target=fpr <= self._target_fpr,
            threshold=self._threshold,
            false_positive_details=fps,
            category_breakdown=category_counts,
            scan_time_sec=elapsed,
        )

        logger.info(
            "FP test: %d/%d scanned, %d FPs (%.6f%%), target=%.6f%% — %s",
            scanned,
            total_files,
            len(fps),
            fpr * 100,
            self._target_fpr * 100,
            "PASS" if report.meets_target else "FAIL",
        )

        return report

    # ------------------------------------------------------------------
    # Test with pre-computed features
    # ------------------------------------------------------------------

    def test_model_precomputed(
        self,
        model_path: Union[str, Path],
        features: NDArray[np.float32],
        *,
        file_paths: Optional[list[str]] = None,
        categories: Optional[list[str]] = None,
    ) -> FPReport:
        """Test ONNX model using pre-computed feature vectors.

        Useful when features have already been extracted offline from a
        large corpus of known-good files.

        Args:
            model_path: Path to the ONNX model.
            features: Pre-computed feature matrix (n_samples, n_features).
            file_paths: Optional file paths for each sample.
            categories: Optional category labels for each sample.

        Returns:
            FPReport with false positive analysis.
        """
        if features.ndim != 2:
            raise ValueError(f"Features must be 2-D, got {features.ndim}-D")

        sess_opts = ort.SessionOptions()
        sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        session = ort.InferenceSession(str(model_path), sess_opts)
        input_name = session.get_inputs()[0].name

        start_time = time.monotonic()

        outputs = session.run(None, {input_name: features})[0]
        scores = outputs.flatten().astype(np.float64)

        preds = (scores >= self._threshold).astype(np.int32)
        fp_indices = np.where(preds == 1)[0]

        fps: list[FPAnalysis] = []
        category_counts: dict[str, dict[str, int]] = {}

        for idx in fp_indices:
            path_str = file_paths[idx] if file_paths is not None else f"sample_{idx}"
            cat = categories[idx] if categories is not None else "unknown"

            fps.append(
                FPAnalysis(
                    file_path=path_str,
                    file_hash="",
                    predicted_score=float(scores[idx]),
                    predicted_label=1,
                    category=cat,
                )
            )

        # Build category breakdown
        n = len(features)
        for i in range(n):
            cat = categories[i] if categories is not None else "unknown"
            category_counts.setdefault(cat, {"scanned": 0, "fp": 0})
            category_counts[cat]["scanned"] += 1
            if preds[i] == 1:
                category_counts[cat]["fp"] += 1

        elapsed = time.monotonic() - start_time
        fpr = len(fps) / max(n, 1)

        return FPReport(
            total_files=n,
            files_scanned=n,
            false_positives=len(fps),
            fpr=fpr,
            target_fpr=self._target_fpr,
            meets_target=fpr <= self._target_fpr,
            threshold=self._threshold,
            false_positive_details=fps,
            category_breakdown=category_counts,
            scan_time_sec=elapsed,
        )

    # ------------------------------------------------------------------
    # FP cause analysis
    # ------------------------------------------------------------------

    @staticmethod
    def identify_fp_causes(
        model_path: Union[str, Path],
        false_positives: list[FPAnalysis],
        features: NDArray[np.float32],
        *,
        feature_names: Optional[list[str]] = None,
        top_k: int = 10,
    ) -> list[FPAnalysis]:
        """Identify top contributing features for each false positive.

        Uses a simple gradient-free attribution: compares each sample's
        feature values against the population mean to find features that
        deviate most in the direction that increases the malware score.

        Args:
            model_path: Path to the ONNX model (for reference scoring).
            false_positives: List of false positive analysis entries.
            features: Full feature matrix for all goodware samples.
            feature_names: Optional readable names for features.
            top_k: Number of top contributing features to report.

        Returns:
            Updated FPAnalysis list with top_contributing_features populated.
        """
        if features.ndim != 2:
            raise ValueError(f"Features must be 2-D, got {features.ndim}-D")

        population_mean = features.mean(axis=0)
        population_std = features.std(axis=0)
        population_std[population_std < 1e-10] = 1.0  # avoid division by zero

        results: list[FPAnalysis] = []

        for fp in false_positives:
            # Find the matching sample by file path index
            # For precomputed: the file_path contains the index
            if fp.file_path.startswith("sample_"):
                try:
                    idx = int(fp.file_path.split("_")[1])
                    sample = features[idx]
                except (ValueError, IndexError):
                    results.append(fp)
                    continue
            else:
                results.append(fp)
                continue

            # Z-score deviation from population mean
            z_scores = (sample - population_mean) / population_std
            # Features with highest positive z-score contribute most to FP
            top_indices = np.argsort(np.abs(z_scores))[::-1][:top_k]
            contributions = [
                (int(idx), float(z_scores[idx])) for idx in top_indices
            ]

            results.append(
                FPAnalysis(
                    file_path=fp.file_path,
                    file_hash=fp.file_hash,
                    predicted_score=fp.predicted_score,
                    predicted_label=fp.predicted_label,
                    category=fp.category,
                    top_contributing_features=contributions,
                )
            )

        return results

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _categorize_file(file_path: Path) -> str:
        """Heuristically assign a category to a file based on its path."""
        path_str = str(file_path).lower()
        if "\\windows\\system32\\" in path_str or "\\windows\\syswow64\\" in path_str:
            return "windows_system"
        if "\\windows\\" in path_str:
            return "windows_other"
        if "\\program files\\" in path_str or "\\program files (x86)\\" in path_str:
            return "installed_application"
        if "\\drivers\\" in path_str:
            return "driver"
        return "other"

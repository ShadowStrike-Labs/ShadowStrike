"""
PE Feature Extraction — EMBER-Compatible 2381-Feature Extractor
================================================================
Extracts a fixed-length feature vector from raw PE file bytes for the
Cortex-Static LightGBM malware classifier.  Feature layout is wire-compatible
with EMBER v2 so models trained on EMBER data can be deployed directly.

Feature groups (total 2381):
    ByteHistogram          256   Normalized byte-value distribution
    ByteEntropyHistogram   256   Joint byte-value / local-entropy histogram
    StringExtractor        104   Printable-string statistics
    GeneralFileInfo         10   High-level PE metadata
    HeaderFileInfo          62   COFF + Optional header fields (hashed)
    SectionInfo            255   Per-section stats via feature hashing
    ImportsInfo           1280   Import libraries + functions (hashed)
    ExportsInfo            128   Export function names (hashed)
    DataDirectories         30   Size/RVA of 15 PE data directories

References:
    Saxe & Berlin, 2015  — https://arxiv.org/pdf/1508.03096.pdf
    Anderson & Roth, 2018 — EMBER dataset (github.com/elastic/ember)
"""

from __future__ import annotations

import hashlib
import logging
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Sequence, Union

import numpy as np

try:
    import lief

    _LIEF_MAJOR, _LIEF_MINOR, _ = (int(x) for x in lief.__version__.split(".")[:3])
    _LIEF_EXPORT_OBJECT: bool = _LIEF_MAJOR > 0 or (_LIEF_MAJOR == 0 and _LIEF_MINOR >= 10)
    _LIEF_HAS_SIGNATURE: bool = _LIEF_MAJOR > 0 or (_LIEF_MAJOR == 0 and _LIEF_MINOR >= 11)
    _LIEF_GE_012: bool = _LIEF_MAJOR > 0 or (_LIEF_MAJOR == 0 and _LIEF_MINOR >= 12)
    _LIEF_AVAILABLE = True
except ImportError:
    _LIEF_AVAILABLE = False
    _LIEF_EXPORT_OBJECT = False
    _LIEF_HAS_SIGNATURE = False
    _LIEF_GE_012 = False

from sklearn.feature_extraction import FeatureHasher

logger = logging.getLogger("phantomcortex.features.pe")

# ---------------------------------------------------------------------------
# Maximum raw-string length kept per import/export to cap memory usage
# ---------------------------------------------------------------------------
_MAX_NAME_LEN: int = 10_000


# ═══════════════════════════════════════════════════════════════════════════
# Base class
# ═══════════════════════════════════════════════════════════════════════════
class FeatureType(ABC):
    """Base for every feature group."""

    name: str = ""
    dim: int = 0

    def __repr__(self) -> str:
        return f"{self.name}({self.dim})"

    @abstractmethod
    def raw_features(self, bytez: bytes, lief_binary: Any) -> Any:
        """Return a JSON-serialisable representation of raw features."""

    @abstractmethod
    def process_raw_features(self, raw_obj: Any) -> np.ndarray:
        """Convert raw features into a fixed-length float32 vector."""

    def feature_vector(self, bytez: bytes, lief_binary: Any) -> np.ndarray:
        """Convenience: raw → processed in one call."""
        return self.process_raw_features(self.raw_features(bytez, lief_binary))


# ═══════════════════════════════════════════════════════════════════════════
# Group 1 — ByteHistogram  (256)
# ═══════════════════════════════════════════════════════════════════════════
class ByteHistogram(FeatureType):
    """Normalised frequency of every byte value across the entire file."""

    name = "histogram"
    dim = 256

    def raw_features(self, bytez: bytes, lief_binary: Any) -> List[int]:
        counts = np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256)
        return counts.tolist()

    def process_raw_features(self, raw_obj: List[int]) -> np.ndarray:
        counts = np.array(raw_obj, dtype=np.float32)
        total = counts.sum()
        if total > 0.0:
            counts /= total
        return counts


# ═══════════════════════════════════════════════════════════════════════════
# Group 2 — ByteEntropyHistogram  (256)
# ═══════════════════════════════════════════════════════════════════════════
class ByteEntropyHistogram(FeatureType):
    """
    2-D joint histogram of (entropy_bucket, coarse_byte_value).

    Sliding window of *window* bytes, advancing by *step* bytes.  For each
    window the local entropy (quantised into 16 bins) and the coarse
    byte-value histogram (256 → 16 bins via >>4) are accumulated into a
    16×16 matrix which is then flattened to 256 features and normalised.
    """

    name = "byteentropy"
    dim = 256

    def __init__(self, step: int = 1024, window: int = 2048) -> None:
        self.window = window
        self.step = step

    def _entropy_bin_counts(self, block: np.ndarray) -> tuple[int, np.ndarray]:
        c = np.bincount(block >> 4, minlength=16)
        p = c.astype(np.float64) / self.window
        nz = p > 0
        # ×2 because we collapsed 256→16 (lost 4 bits → half the information)
        H = float(-np.sum(p[nz] * np.log2(p[nz]))) * 2.0
        Hbin = min(int(H * 2), 15)
        return Hbin, c

    def raw_features(self, bytez: bytes, lief_binary: Any) -> List[int]:
        output = np.zeros((16, 16), dtype=np.int64)
        a = np.frombuffer(bytez, dtype=np.uint8)
        if a.shape[0] < self.window:
            Hbin, c = self._entropy_bin_counts(a)
            output[Hbin, :] += c
        else:
            shape = (((a.shape[0] - self.window) // self.step) + 1, self.window)
            strides = (a.strides[0] * self.step, a.strides[0])
            blocks = np.lib.stride_tricks.as_strided(a, shape=shape, strides=strides)
            for block in blocks:
                Hbin, c = self._entropy_bin_counts(block)
                output[Hbin, :] += c

        return output.flatten().tolist()

    def process_raw_features(self, raw_obj: List[int]) -> np.ndarray:
        counts = np.array(raw_obj, dtype=np.float32)
        total = counts.sum()
        if total > 0.0:
            counts /= total
        return counts


# ═══════════════════════════════════════════════════════════════════════════
# Group 3 — StringExtractor  (104)
# ═══════════════════════════════════════════════════════════════════════════
class StringExtractor(FeatureType):
    """
    Statistics over printable-ASCII strings extracted from the raw byte
    stream.  Produces 104 features:
        numstrings, avlength, printables, printable_char_dist(96),
        entropy, paths, urls, registry, MZ
    """

    name = "strings"
    dim = 104  # 1 + 1 + 1 + 96 + 1 + 1 + 1 + 1 + 1

    _RE_STRINGS = re.compile(rb"[\x20-\x7f]{5,}")
    _RE_PATHS = re.compile(rb"c:\\", re.IGNORECASE)
    _RE_URLS = re.compile(rb"https?://", re.IGNORECASE)
    _RE_REGISTRY = re.compile(rb"HKEY_")
    _RE_MZ = re.compile(rb"MZ")

    def raw_features(self, bytez: bytes, lief_binary: Any) -> Dict[str, Any]:
        allstrings: List[bytes] = self._RE_STRINGS.findall(bytez)
        if allstrings:
            string_lengths = [len(s) for s in allstrings]
            avlength = sum(string_lengths) / len(string_lengths)
            as_shifted = [b - 0x20 for b in b"".join(allstrings)]
            c = np.bincount(as_shifted, minlength=96)
            csum = int(c.sum())
            p = c.astype(np.float64) / csum
            nz = p > 0
            H = float(-np.sum(p[nz] * np.log2(p[nz])))
        else:
            avlength = 0
            c = np.zeros(96, dtype=np.float32)
            H = 0.0
            csum = 0

        return {
            "numstrings": len(allstrings),
            "avlength": avlength,
            "printabledist": c.tolist(),
            "printables": csum,
            "entropy": H,
            "paths": len(self._RE_PATHS.findall(bytez)),
            "urls": len(self._RE_URLS.findall(bytez)),
            "registry": len(self._RE_REGISTRY.findall(bytez)),
            "MZ": len(self._RE_MZ.findall(bytez)),
        }

    def process_raw_features(self, raw_obj: Dict[str, Any]) -> np.ndarray:
        hist_div = float(raw_obj["printables"]) if raw_obj["printables"] > 0 else 1.0
        return np.hstack([
            raw_obj["numstrings"],
            raw_obj["avlength"],
            raw_obj["printables"],
            np.asarray(raw_obj["printabledist"], dtype=np.float32) / hist_div,
            raw_obj["entropy"],
            raw_obj["paths"],
            raw_obj["urls"],
            raw_obj["registry"],
            raw_obj["MZ"],
        ]).astype(np.float32)


# ═══════════════════════════════════════════════════════════════════════════
# Group 4 — GeneralFileInfo  (10)
# ═══════════════════════════════════════════════════════════════════════════
class GeneralFileInfo(FeatureType):
    """High-level metadata: sizes, boolean flags, symbol/import/export counts."""

    name = "general"
    dim = 10

    def raw_features(self, bytez: bytes, lief_binary: Any) -> Dict[str, int]:
        if lief_binary is None:
            return {
                "size": len(bytez),
                "vsize": 0,
                "has_debug": 0,
                "exports": 0,
                "imports": 0,
                "has_relocations": 0,
                "has_resources": 0,
                "has_signature": 0,
                "has_tls": 0,
                "symbols": 0,
            }

        has_sig: int
        if _LIEF_HAS_SIGNATURE:
            has_sig = int(lief_binary.has_signatures)
        else:
            has_sig = int(lief_binary.has_signature)  # type: ignore[attr-defined]

        return {
            "size": len(bytez),
            "vsize": lief_binary.virtual_size,
            "has_debug": int(lief_binary.has_debug),
            "exports": len(lief_binary.exported_functions),
            "imports": len(lief_binary.imported_functions),
            "has_relocations": int(lief_binary.has_relocations),
            "has_resources": int(lief_binary.has_resources),
            "has_signature": has_sig,
            "has_tls": int(lief_binary.has_tls),
            "symbols": len(lief_binary.symbols),
        }

    def process_raw_features(self, raw_obj: Dict[str, int]) -> np.ndarray:
        return np.array([
            raw_obj["size"],
            raw_obj["vsize"],
            raw_obj["has_debug"],
            raw_obj["exports"],
            raw_obj["imports"],
            raw_obj["has_relocations"],
            raw_obj["has_resources"],
            raw_obj["has_signature"],
            raw_obj["has_tls"],
            raw_obj["symbols"],
        ], dtype=np.float32)


# ═══════════════════════════════════════════════════════════════════════════
# Group 5 — HeaderFileInfo  (62)
# ═══════════════════════════════════════════════════════════════════════════
class HeaderFileInfo(FeatureType):
    """COFF + Optional header fields, categorical values feature-hashed."""

    name = "header"
    dim = 62

    @staticmethod
    def _empty_raw() -> Dict[str, Dict[str, Any]]:
        return {
            "coff": {"timestamp": 0, "machine": "", "characteristics": []},
            "optional": {
                "subsystem": "",
                "dll_characteristics": [],
                "magic": "",
                "major_image_version": 0,
                "minor_image_version": 0,
                "major_linker_version": 0,
                "minor_linker_version": 0,
                "major_operating_system_version": 0,
                "minor_operating_system_version": 0,
                "major_subsystem_version": 0,
                "minor_subsystem_version": 0,
                "sizeof_code": 0,
                "sizeof_headers": 0,
                "sizeof_heap_commit": 0,
            },
        }

    def raw_features(self, bytez: bytes, lief_binary: Any) -> Dict[str, Dict[str, Any]]:
        raw_obj = self._empty_raw()
        if lief_binary is None:
            return raw_obj

        raw_obj["coff"]["timestamp"] = lief_binary.header.time_date_stamps
        raw_obj["coff"]["machine"] = str(lief_binary.header.machine).split(".")[-1]
        raw_obj["coff"]["characteristics"] = [
            str(c).split(".")[-1] for c in lief_binary.header.characteristics_list
        ]
        opt = lief_binary.optional_header
        raw_obj["optional"]["subsystem"] = str(opt.subsystem).split(".")[-1]
        raw_obj["optional"]["dll_characteristics"] = [
            str(c).split(".")[-1] for c in opt.dll_characteristics_lists
        ]
        raw_obj["optional"]["magic"] = str(opt.magic).split(".")[-1]
        raw_obj["optional"]["major_image_version"] = opt.major_image_version
        raw_obj["optional"]["minor_image_version"] = opt.minor_image_version
        raw_obj["optional"]["major_linker_version"] = opt.major_linker_version
        raw_obj["optional"]["minor_linker_version"] = opt.minor_linker_version
        raw_obj["optional"]["major_operating_system_version"] = opt.major_operating_system_version
        raw_obj["optional"]["minor_operating_system_version"] = opt.minor_operating_system_version
        raw_obj["optional"]["major_subsystem_version"] = opt.major_subsystem_version
        raw_obj["optional"]["minor_subsystem_version"] = opt.minor_subsystem_version
        raw_obj["optional"]["sizeof_code"] = opt.sizeof_code
        raw_obj["optional"]["sizeof_headers"] = opt.sizeof_headers
        raw_obj["optional"]["sizeof_heap_commit"] = opt.sizeof_heap_commit

        return raw_obj

    def process_raw_features(self, raw_obj: Dict[str, Dict[str, Any]]) -> np.ndarray:
        coff = raw_obj["coff"]
        opt = raw_obj["optional"]
        return np.hstack([
            coff["timestamp"],
            FeatureHasher(10, input_type="string").transform([[coff["machine"]]]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([coff["characteristics"]]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([[opt["subsystem"]]]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([opt["dll_characteristics"]]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([[opt["magic"]]]).toarray()[0],
            opt["major_image_version"],
            opt["minor_image_version"],
            opt["major_linker_version"],
            opt["minor_linker_version"],
            opt["major_operating_system_version"],
            opt["minor_operating_system_version"],
            opt["major_subsystem_version"],
            opt["minor_subsystem_version"],
            opt["sizeof_code"],
            opt["sizeof_headers"],
            opt["sizeof_heap_commit"],
        ]).astype(np.float32)


# ═══════════════════════════════════════════════════════════════════════════
# Group 6 — SectionInfo  (255)
# ═══════════════════════════════════════════════════════════════════════════
class SectionInfo(FeatureType):
    """
    Section metadata feature-hashed into 255 features:
        5 aggregate stats + 5×50 hashed section attributes.
    """

    name = "section"
    dim = 5 + 50 + 50 + 50 + 50 + 50  # 255

    @staticmethod
    def _properties(s: Any) -> List[str]:
        return [str(c).split(".")[-1] for c in s.characteristics_lists]

    def raw_features(self, bytez: bytes, lief_binary: Any) -> Dict[str, Any]:
        if lief_binary is None:
            return {"entry": "", "sections": []}

        try:
            if _LIEF_GE_012:
                section = lief_binary.section_from_rva(
                    lief_binary.entrypoint - lief_binary.imagebase
                )
                if section is None:
                    raise lief.not_found
                entry_section = section.name
            else:
                entry_section = lief_binary.section_from_offset(lief_binary.entrypoint).name
        except Exception:
            entry_section = ""
            for s in lief_binary.sections:
                if lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE in s.characteristics_lists:
                    entry_section = s.name
                    break

        sections_raw: List[Dict[str, Any]] = []
        for s in lief_binary.sections:
            sections_raw.append({
                "name": s.name,
                "size": s.size,
                "entropy": s.entropy,
                "vsize": s.virtual_size,
                "props": self._properties(s),
            })

        return {"entry": entry_section, "sections": sections_raw}

    def process_raw_features(self, raw_obj: Dict[str, Any]) -> np.ndarray:
        sections = raw_obj["sections"]
        general = [
            len(sections),
            sum(1 for s in sections if s["size"] == 0),
            sum(1 for s in sections if s["name"] == ""),
            sum(1 for s in sections if "MEM_READ" in s["props"] and "MEM_EXECUTE" in s["props"]),
            sum(1 for s in sections if "MEM_WRITE" in s["props"]),
        ]

        section_sizes = [(s["name"], s["size"]) for s in sections]
        section_entropy = [(s["name"], s["entropy"]) for s in sections]
        section_vsize = [(s["name"], s["vsize"]) for s in sections]

        section_sizes_h = FeatureHasher(50, input_type="pair").transform([section_sizes]).toarray()[0]
        section_entropy_h = FeatureHasher(50, input_type="pair").transform([section_entropy]).toarray()[0]
        section_vsize_h = FeatureHasher(50, input_type="pair").transform([section_vsize]).toarray()[0]
        entry_name_h = FeatureHasher(50, input_type="string").transform([raw_obj["entry"]]).toarray()[0]

        characteristics = [
            p for s in sections for p in s["props"] if s["name"] == raw_obj["entry"]
        ]
        characteristics_h = FeatureHasher(50, input_type="string").transform([characteristics]).toarray()[0]

        return np.hstack([
            general,
            section_sizes_h,
            section_entropy_h,
            section_vsize_h,
            entry_name_h,
            characteristics_h,
        ]).astype(np.float32)


# ═══════════════════════════════════════════════════════════════════════════
# Group 7 — ImportsInfo  (1280)
# ═══════════════════════════════════════════════════════════════════════════
class ImportsInfo(FeatureType):
    """
    Feature-hashed import information: 256 bins for library names,
    1024 bins for fully-qualified (library:function) pairs → 1280 total.
    """

    name = "imports"
    dim = 1280

    def raw_features(self, bytez: bytes, lief_binary: Any) -> Dict[str, List[str]]:
        imports: Dict[str, List[str]] = {}
        if lief_binary is None:
            return imports

        for lib in lief_binary.imports:
            if lib.name not in imports:
                imports[lib.name] = []
            for entry in lib.entries:
                if entry.is_ordinal:
                    imports[lib.name].append(f"ordinal{entry.ordinal}")
                else:
                    imports[lib.name].append(entry.name[:_MAX_NAME_LEN])
        return imports

    def process_raw_features(self, raw_obj: Dict[str, List[str]]) -> np.ndarray:
        libraries = list({lib.lower() for lib in raw_obj.keys()})
        libraries_h = FeatureHasher(256, input_type="string").transform([libraries]).toarray()[0]

        imports = [
            f"{lib.lower()}:{func}"
            for lib, funcs in raw_obj.items()
            for func in funcs
        ]
        imports_h = FeatureHasher(1024, input_type="string").transform([imports]).toarray()[0]

        return np.hstack([libraries_h, imports_h]).astype(np.float32)


# ═══════════════════════════════════════════════════════════════════════════
# Group 8 — ExportsInfo  (128)
# ═══════════════════════════════════════════════════════════════════════════
class ExportsInfo(FeatureType):
    """Feature-hashed exported function names (128 bins)."""

    name = "exports"
    dim = 128

    def raw_features(self, bytez: bytes, lief_binary: Any) -> List[str]:
        if lief_binary is None:
            return []

        if _LIEF_EXPORT_OBJECT:
            return [exp.name[:_MAX_NAME_LEN] for exp in lief_binary.exported_functions]
        return [exp[:_MAX_NAME_LEN] for exp in lief_binary.exported_functions]

    def process_raw_features(self, raw_obj: List[str]) -> np.ndarray:
        return FeatureHasher(128, input_type="string").transform([raw_obj]).toarray()[0].astype(np.float32)


# ═══════════════════════════════════════════════════════════════════════════
# Group 9 — DataDirectories  (30)
# ═══════════════════════════════════════════════════════════════════════════
class DataDirectories(FeatureType):
    """Size and virtual address for each of the 15 PE data directories."""

    name = "datadirectories"
    dim = 30  # 15 × 2

    _NAME_ORDER: List[str] = [
        "EXPORT_TABLE",
        "IMPORT_TABLE",
        "RESOURCE_TABLE",
        "EXCEPTION_TABLE",
        "CERTIFICATE_TABLE",
        "BASE_RELOCATION_TABLE",
        "DEBUG",
        "ARCHITECTURE",
        "GLOBAL_PTR",
        "TLS_TABLE",
        "LOAD_CONFIG_TABLE",
        "BOUND_IMPORT",
        "IAT",
        "DELAY_IMPORT_DESCRIPTOR",
        "CLR_RUNTIME_HEADER",
    ]

    def raw_features(self, bytez: bytes, lief_binary: Any) -> List[Dict[str, Any]]:
        if lief_binary is None:
            return []

        output: List[Dict[str, Any]] = []
        for dd in lief_binary.data_directories:
            output.append({
                "name": str(dd.type).replace("DATA_DIRECTORY.", ""),
                "size": dd.size,
                "virtual_address": dd.rva,
            })
        return output

    def process_raw_features(self, raw_obj: List[Dict[str, Any]]) -> np.ndarray:
        features = np.zeros(2 * len(self._NAME_ORDER), dtype=np.float32)
        for i in range(len(self._NAME_ORDER)):
            if i < len(raw_obj):
                features[2 * i] = raw_obj[i]["size"]
                features[2 * i + 1] = raw_obj[i]["virtual_address"]
        return features


# ═══════════════════════════════════════════════════════════════════════════
# Orchestrator — PEFeatureExtractor
# ═══════════════════════════════════════════════════════════════════════════
class PEFeatureExtractor:
    """
    Extract 2381 EMBER-compatible features from raw PE bytes.

    Supports EMBER feature versions 1 and 2.  Version 2 (default) includes
    DataDirectories and is the production default for Cortex-Static.

    Usage::

        extractor = PEFeatureExtractor(feature_version=2)
        vec = extractor.feature_vector(raw_bytes)   # ndarray (2381,)
        raw = extractor.raw_features(raw_bytes)      # JSON-serialisable dict
        vec = extractor.process_raw_features(raw)    # ndarray from raw dict

    The two-stage raw → processed pipeline lets callers serialise raw features
    for later reprocessing (e.g. after changing normalisation) without re-parsing.
    """

    def __init__(
        self,
        feature_version: int = 2,
        print_feature_warning: bool = True,
    ) -> None:
        if not _LIEF_AVAILABLE:
            raise ImportError(
                "The 'lief' package is required for PE feature extraction. "
                "Install it with:  pip install lief"
            )

        self._features: List[FeatureType] = [
            ByteHistogram(),
            ByteEntropyHistogram(),
            StringExtractor(),
            GeneralFileInfo(),
            HeaderFileInfo(),
            SectionInfo(),
            ImportsInfo(),
            ExportsInfo(),
        ]

        if feature_version == 1:
            if print_feature_warning and not lief.__version__.startswith("0.8.3"):
                logger.warning(
                    "EMBER v1 features were computed with lief 0.8.3; "
                    "found %s — minor inconsistencies possible",
                    lief.__version__,
                )
        elif feature_version == 2:
            self._features.append(DataDirectories())
            if print_feature_warning and not lief.__version__.startswith("0.9.0"):
                logger.info(
                    "EMBER v2 features were computed with lief 0.9.0; "
                    "found %s — minor inconsistencies possible",
                    lief.__version__,
                )
        else:
            raise ValueError(f"Unsupported EMBER feature version: {feature_version}")

        self.dim: int = sum(fe.dim for fe in self._features)
        self.feature_version: int = feature_version

    # -- public API --------------------------------------------------------

    def raw_features(self, bytez: bytes) -> Dict[str, Any]:
        """Parse *bytez* and return a JSON-serialisable dict of raw features."""
        lief_binary = self._parse_pe(bytez)
        features: Dict[str, Any] = {"sha256": hashlib.sha256(bytez).hexdigest()}
        for fe in self._features:
            try:
                features[fe.name] = fe.raw_features(bytez, lief_binary)
            except Exception:
                logger.debug(
                    "Feature group '%s' failed on sample %s; using default",
                    fe.name,
                    features["sha256"][:16],
                    exc_info=True,
                )
                features[fe.name] = fe.raw_features(bytez, None)
        return features

    def process_raw_features(self, raw_obj: Dict[str, Any]) -> np.ndarray:
        """Convert a raw-features dict to a fixed-length float32 vector."""
        parts: List[np.ndarray] = []
        for fe in self._features:
            try:
                parts.append(fe.process_raw_features(raw_obj[fe.name]))
            except Exception:
                logger.debug(
                    "process_raw_features failed for '%s'; zero-filling",
                    fe.name,
                    exc_info=True,
                )
                parts.append(np.zeros(fe.dim, dtype=np.float32))
        return np.hstack(parts).astype(np.float32)

    def feature_vector(self, bytez: bytes) -> np.ndarray:
        """End-to-end: raw bytes → float32 feature vector (2381,)."""
        return self.process_raw_features(self.raw_features(bytez))

    @property
    def feature_names(self) -> List[str]:
        """Return ordered list of human-readable feature names."""
        names: List[str] = []
        for fe in self._features:
            for i in range(fe.dim):
                names.append(f"{fe.name}_{i}")
        return names

    # -- internal ----------------------------------------------------------

    @staticmethod
    def _parse_pe(bytez: bytes) -> Optional[Any]:
        """
        Parse raw bytes into a lief PE binary, returning None on failure.
        Gracefully handles malformed, packed, and truncated samples.
        """
        lief_errors = (
            lief.bad_format,
            lief.bad_file,
            lief.pe_error,
            lief.parser_error,
            lief.read_out_of_bound,
            RuntimeError,
        )
        try:
            binary = lief.PE.parse(list(bytez))
            return binary
        except lief_errors as exc:
            logger.info("lief parse failed: %s", exc)
            return None
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            logger.warning("Unexpected lief error: %s", exc, exc_info=True)
            return None

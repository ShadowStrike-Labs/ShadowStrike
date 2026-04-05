"""
PhantomCortex Feature Extraction Engine
========================================
Enterprise-grade feature extraction for ShadowStrike's ML malware detection pipeline.

Feature extractors:
    - PEFeatureExtractor: 2381 EMBER-compatible features from PE binaries
    - BehavioralFeatureExtractor: API call sequence encoding for Cortex-Behavioral CNN
    - MemoryFeatureExtractor: Memory region analysis (128 features)
    - NetworkFeatureExtractor: Network flow feature extraction
    - EmulationFeatureExtractor: PhantomEmulator execution trace encoding
"""

from PhantomCortex.training.features.pe_features import (
    PEFeatureExtractor,
    ByteHistogram,
    ByteEntropyHistogram,
    StringExtractor,
    GeneralFileInfo,
    HeaderFileInfo,
    SectionInfo,
    ImportsInfo,
    ExportsInfo,
    DataDirectories,
)
from PhantomCortex.training.features.behavioral_features import BehavioralFeatureExtractor
from PhantomCortex.training.features.memory_features import MemoryFeatureExtractor
from PhantomCortex.training.features.network_features import NetworkFeatureExtractor
from PhantomCortex.training.features.emulation_features import EmulationFeatureExtractor

__all__ = [
    "PEFeatureExtractor",
    "ByteHistogram",
    "ByteEntropyHistogram",
    "StringExtractor",
    "GeneralFileInfo",
    "HeaderFileInfo",
    "SectionInfo",
    "ImportsInfo",
    "ExportsInfo",
    "DataDirectories",
    "BehavioralFeatureExtractor",
    "MemoryFeatureExtractor",
    "NetworkFeatureExtractor",
    "EmulationFeatureExtractor",
]

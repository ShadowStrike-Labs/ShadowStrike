"""
PhantomCortex Training Models
=============================

Enterprise-grade ML models for ShadowStrike's NGAV malware detection engine.

Models:
    - CortexStaticTrainer: LightGBM gradient boosted trees for PE static analysis
    - CortexBehavioralTrainer: 1D-CNN + Attention for API call sequence classification
    - CortexMemoryTrainer: MLP with skip connections for memory region classification
    - CortexNetworkTrainer: Autoencoder + Classifier for network anomaly detection
    - CortexEmulationTrainer: Bidirectional GRU for emulation trace verdicts
"""

from PhantomCortex.training.models.static_lgbm import CortexStaticTrainer
from PhantomCortex.training.models.behavioral_cnn import CortexBehavioralTrainer
from PhantomCortex.training.models.memory_mlp import CortexMemoryTrainer
from PhantomCortex.training.models.network_ae import CortexNetworkTrainer
from PhantomCortex.training.models.emulation_gru import CortexEmulationTrainer

__all__ = [
    "CortexStaticTrainer",
    "CortexBehavioralTrainer",
    "CortexMemoryTrainer",
    "CortexNetworkTrainer",
    "CortexEmulationTrainer",
]

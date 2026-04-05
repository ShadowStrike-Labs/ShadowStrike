"""
PhantomCortex — ShadowStrike AI/ML Detection Engine
====================================================

Multi-model ensemble for enterprise malware detection:
- Cortex-Static: PE file classification (LightGBM)
- Cortex-Behavioral: API sequence analysis (1D-CNN + Attention)
- Cortex-Memory: Memory pattern detection (MLP)
- Cortex-Network: Network anomaly detection (Autoencoder)
- Cortex-Emulation: Emulation trace verdict (GRU)

All models deploy as ONNX Runtime INT8 for <5ms inference on any CPU.
"""
__version__ = "0.1.0"
__author__ = "ShadowStrike-Labs"

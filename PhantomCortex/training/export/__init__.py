"""
PhantomCortex Export Pipeline
=============================

ONNX export, INT8 quantization, and deployment validation for all Cortex models.
Ensures every model exported meets latency, accuracy, and size constraints
before deployment to ShadowStrike endpoints.
"""

from PhantomCortex.training.export.to_onnx import (
    export_lgbm_to_onnx,
    export_pytorch_to_onnx,
    validate_onnx_model,
    get_model_metadata,
)
from PhantomCortex.training.export.quantize import (
    quantize_dynamic,
    quantize_static,
    compare_accuracy,
    benchmark_inference,
)
from PhantomCortex.training.export.validate import (
    validate_model,
    regression_test,
    benchmark_latency,
)

__all__ = [
    "export_lgbm_to_onnx",
    "export_pytorch_to_onnx",
    "validate_onnx_model",
    "get_model_metadata",
    "quantize_dynamic",
    "quantize_static",
    "compare_accuracy",
    "benchmark_inference",
    "validate_model",
    "regression_test",
    "benchmark_latency",
]

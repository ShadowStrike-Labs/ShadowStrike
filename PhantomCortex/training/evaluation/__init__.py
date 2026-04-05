"""
PhantomCortex Evaluation Suite
==============================

Comprehensive evaluation for security ML models including standard metrics,
security-specific metrics (FPR at threshold, detection rates), false positive
testing against legitimate software, and adversarial evasion resistance testing.
"""

from PhantomCortex.training.evaluation.metrics import MetricsCalculator
from PhantomCortex.training.evaluation.false_positive_test import FalsePositiveTester
from PhantomCortex.training.evaluation.adversarial_test import AdversarialTester

__all__ = [
    "MetricsCalculator",
    "FalsePositiveTester",
    "AdversarialTester",
]

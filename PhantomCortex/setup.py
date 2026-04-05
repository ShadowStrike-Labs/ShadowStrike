from setuptools import setup, find_packages

setup(
    name="phantomcortex",
    version="0.1.0",
    author="ShadowStrike-Labs",
    author_email="contact@ShadowStrike.dev",
    description="PhantomCortex — ShadowStrike AI/ML Detection Engine",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "torch>=2.2.0",
        "lightgbm>=4.3.0",
        "scikit-learn>=1.4.0",
        "onnx>=1.15.0",
        "onnxruntime>=1.17.0",
        "onnxmltools>=1.12.0",
        "lief>=0.14.0",
        "numpy>=1.26.0",
        "pandas>=2.2.0",
        "optuna>=3.5.0",
        "mlflow>=2.11.0",
        "aiohttp>=3.9.0",
        "pyyaml>=6.0.1",
        "structlog>=24.1.0",
    ],
)

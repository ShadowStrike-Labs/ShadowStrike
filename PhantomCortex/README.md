# PhantomCortex — ShadowStrike AI/ML Detection Engine

PhantomCortex is the machine-learning subsystem of ShadowStrike NGAV. It provides a
multi-model ensemble that classifies PE executables, behavioral API traces, memory
patterns, network flows, and emulation outputs — producing a unified malware verdict
in under 5 ms on commodity hardware.

All models are trained offline, exported to **ONNX Runtime INT8**, and shipped as
static artifacts alongside ShadowStrike engine updates.

---

## Architecture

```
                         ┌──────────────────────┐
                         │    Input Streams      │
                         └──┬───┬───┬───┬───┬───┘
                            │   │   │   │   │
             ┌──────────────┘   │   │   │   └──────────────┐
             ▼                  ▼   │   ▼                  ▼
   ┌─────────────────┐ ┌──────────┐│┌──────────┐ ┌─────────────────┐
   │  Cortex-Static  │ │ Cortex-  │││ Cortex-  │ │ Cortex-Emulation│
   │   (LightGBM)    │ │Behavioral│││ Network  │ │     (GRU)       │
   │  PE features →  │ │(1D-CNN + ││ (Auto-   │ │ Emulation trace │
   │  malware prob.  │ │Attention)│││ encoder) │ │   → verdict     │
   └────────┬────────┘ └────┬─────┘│└────┬─────┘ └───────┬─────────┘
            │                │      │     │               │
            │                │      ▼     │               │
            │                │ ┌─────────┐│               │
            │                │ │ Cortex- ││               │
            │                │ │ Memory  ││               │
            │                │ │  (MLP)  ││               │
            │                │ └────┬────┘│               │
            │                │      │     │               │
            ▼                ▼      ▼     ▼               ▼
         ┌──────────────────────────────────────────────────┐
         │              Ensemble Aggregator                 │
         │  Weighted average + confidence calibration       │
         └──────────────────────┬───────────────────────────┘
                                │
                                ▼
                     ┌─────────────────────┐
                     │   Unified Verdict   │
                     │  CLEAN / MALICIOUS  │
                     │  + confidence score │
                     └─────────────────────┘
```

---

## Models

| Model              | Input                  | Architecture          | Purpose                      |
|--------------------|------------------------|-----------------------|------------------------------|
| **Cortex-Static**  | PE header + sections   | LightGBM (gradient-boosted trees) | Fast static classification   |
| **Cortex-Behavioral** | API call sequences  | 1D-CNN + Attention    | Runtime behavior analysis    |
| **Cortex-Memory**  | Memory region patterns | MLP (3 hidden layers) | In-memory threat detection   |
| **Cortex-Network** | Network flow features  | Autoencoder (anomaly) | C2 / exfil detection         |
| **Cortex-Emulation** | Emulation traces     | GRU (recurrent)       | Packed / obfuscated payloads |

All models export to **ONNX** and are quantized to **INT8** via ONNX Runtime /
Intel Neural Compressor for < 5 ms inference on any x86-64 CPU.

---

## Dataset Strategy

PhantomCortex uses **specialized datasets per model family** rather than forcing a
single shared corpus across unrelated telemetry:

| Model | Training data strategy |
|-------|------------------------|
| **Cortex-Static** | EMBER2024 PE subsets (commercial-friendly Apache-2.0 dataset) |
| **Cortex-Behavioral** | Hybrid external API-trace corpus: Mal-API-2019 family traces + MalbehavD-V1 benign traces, with synthetic backfill for internal classes not covered by public labels |
| **Cortex-Memory** | Internal / synthetic until a commercial-friendly raw-memory corpus matches the 128-feature contract |
| **Cortex-Network** | Internal / synthetic until a commercial-friendly flow corpus cleanly maps to the network threat taxonomy |
| **Cortex-Emulation** | Internal / synthetic until a commercial-friendly emulation-trace corpus is verified |

This preserves model specialization and avoids weakening production classifiers with
dataset/schema mismatches.

---

## Quick Start

```bash
# 1. Install dependencies (Python >=3.11)
cd PhantomCortex
pip install -r requirements.txt

# 2. Sync threat-intelligence feeds
python -m PhantomCortex.training.pipeline --feed-sync-only

# 3. Run a full training cycle
python -m PhantomCortex.training.pipeline --full-train --report

# 4. Export and quantize models to ONNX INT8
python -m PhantomCortex.training.pipeline --export-only

# 5. Run evaluation only
python -m PhantomCortex.training.pipeline --evaluate-only --report
```

---

## Training Pipeline

The pipeline orchestrator (`training/pipeline.py`) executes the nightly automation:

| Step | Name             | Description                                       |
|------|------------------|---------------------------------------------------|
| 1    | **Feed Sync**    | Download new samples from all enabled feeds        |
| 2    | **Feature Extract** | Run PE / behavioral feature extraction          |
| 3    | **Dataset Merge** | Combine new features with the existing training set |
| 4    | **Train**        | Retrain or fine-tune all models                    |
| 5    | **Evaluate**     | Full evaluation suite (AUC, FPR, detection rate)   |
| 6    | **Export**       | Convert to ONNX + quantize to INT8                |
| 7    | **Validate**     | Deployment validation checks (size, latency, quality gates) |
| 8    | **Stage**        | Copy to deployment directory if all checks pass    |
| 9    | **Report**       | Generate metrics report (Markdown + JSON)          |

### Modes

| Flag                | Behavior                                 |
|---------------------|------------------------------------------|
| `--full-train`      | Full retrain from scratch                |
| `--incremental`     | Fine-tune with new data only             |
| `--evaluate-only`   | Run evaluation on current models         |
| `--export-only`     | Export and quantize current models        |
| `--feed-sync-only`  | Sync feeds without training              |
| `--model <name>`    | Target a single model (e.g. `static`)    |
| `--report`          | Generate metrics report after completion |
| `--dry-run`         | Validate config and exit                 |

### Safety Features

- **Lock file** prevents concurrent pipeline runs.
- **Disk space check** before large downloads or training.
- **Model backup** created before every retrain.
- **Automatic rollback** if the new model regresses beyond the configured threshold.
- **Interruption recovery** — the pipeline records its last successful step and can
  resume from that point.

---

## Deployment

Models flow through three directories:

```
training/data/models/staging/      ← pipeline writes here
training/data/models/production/   ← promoted after quality gates pass
training/data/models/backup/       ← previous production models
```

Quality gates are defined in `training/config/deployment.yaml`:

| Gate                  | Default  |
|-----------------------|----------|
| Min AUC-ROC           | 0.995    |
| Max FPR @ 0.1%        | 0.001    |
| Min detection rate    | 0.995    |
| Max model size        | 20 MB    |
| Max inference latency | 5.0 ms   |
| Max regression vs prev| 0.5%     |

---

## Configuration

All pipeline configuration lives in `training/config/`:

| File               | Purpose                                          |
|--------------------|--------------------------------------------------|
| `deployment.yaml`  | Quality gates, versioning, scheduling, notifications |

Environment variables (`.env`):

| Variable                        | Description                          |
|---------------------------------|--------------------------------------|
| `PHANTOMCORTEX_DATA_DIR`        | Override default data directory       |
| `PHANTOMCORTEX_LOG_LEVEL`       | Logging level (DEBUG / INFO / WARN)  |
| `PHANTOMCORTEX_MLFLOW_URI`      | MLflow tracking server URI           |
| `PHANTOMCORTEX_WEBHOOK_URL`     | Webhook URL for notifications        |

---

## Project Structure

```
PhantomCortex/
├── __init__.py
├── pyproject.toml
├── setup.py
├── requirements.txt
├── README.md
├── .gitignore
├── inference/              # C++ ONNX Runtime inference headers
├── training/
│   ├── __init__.py
│   ├── pipeline.py         # Nightly orchestrator
│   ├── config/
│   │   └── deployment.yaml
│   ├── data/
│   │   ├── raw/
│   │   ├── processed/
│   │   ├── feeds/
│   │   └── models/
│   ├── evaluation/
│   ├── export/
│   ├── features/
│   ├── feeds/
│   └── models/
```

---

## Contributing

1. All model changes must include an evaluation report.
2. Quality gates are non-negotiable — they protect production endpoints.
3. New feeds require a corresponding feature-extraction module.
4. Use `structlog` for all pipeline logging.
5. Run `ruff check` and `mypy --strict` before submitting.

---

## License

Proprietary — ShadowStrike-Labs. All rights reserved.

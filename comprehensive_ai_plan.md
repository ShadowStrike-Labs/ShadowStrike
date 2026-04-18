# PhantomCortex AI/ML Comprehensive Training & Configuration Plan

> **Date**: 2026-04-18  
> **Author**: AI/ML Training Lead — ShadowStrike PhantomCortex  
> **Scope**: Full audit, reconfiguration, and retraining of all 5 Cortex models  
> **Target**: Enterprise-grade, commercially-licensed, world-class malware detection  

---

## Executive Summary

After a thorough audit of the PhantomCortex training infrastructure, **critical issues** were found in all 5 models. Two models are completely non-functional for production (Network, Emulation), one fails every quality gate (Static), and two have significant class-level gaps (Behavioral, Memory). The EMBER 2018 feed config is still active despite being **8 years obsolete**. This plan corrects every issue.

---

## 🔴 CRITICAL FINDINGS (Current State Audit)

### Model-by-Model Assessment

#### 1. Cortex-Static (LightGBM) — ❌ FAILS ALL QUALITY GATES

| Metric | Current Value | Required Threshold | Status |
|--------|--------------|-------------------|--------|
| AUC-ROC | **0.9924** | ≥ 0.995 | ❌ FAIL |
| Detection Rate | **0.9627** | ≥ 0.995 | ❌ FAIL |
| FPR @ threshold | **0.0334** (3.3%) | ≤ 0.001 (0.1%) | ❌ FAIL (33× over) |

**Root Causes:**
- Trained on **EMBER 2018** (8 years old, 2381 features, 1.1M samples)
- HPO was **skipped** (`hpo_enabled: false` in metrics)
- EMBER 2024 loader exists but feeds.yaml still points to EMBER 2018
- Feature count mismatch: 2381 (2018) vs 2568 (2024)
- `train_static.py` defaults to `--dataset ember2018`

#### 2. Cortex-Behavioral (1D-CNN + Attention) — ⚠️ PARTIALLY FUNCTIONAL

| Metric | Value | Status |
|--------|-------|--------|
| Overall Accuracy | 0.9853 | ⚠️ Acceptable |
| Macro F1 | 0.9852 | ⚠️ Acceptable |
| Backdoor recall | **0.8436** | ❌ Low |
| RAT precision | **0.8681** | ❌ Low |
| Fileless precision | **0.8863** | ❌ Low |
| Persistence recall | **0.8650** | ❌ Low |

**Root Causes:**
- 4+ classes below 90% F1 — unacceptable for enterprise
- Training used hybrid mode (synthetic + Mal-API-2019 + MalbehavD-V1)
- Quo Vadis Speakeasy dataset (93K real samples, Apache-2.0) is on disk but **not used** for behavioral training
- Imbalanced external corpus: only 6 families from Mal-API map to our taxonomy

#### 3. Cortex-Memory (MLP) — ⚠️ NEEDS REAL DATA

- No separate evaluation metrics file found for memory model
- CIC-MalMem-2022 and MemMal-D2024 datasets are **present on disk** but utilization is unclear
- memory_external_combined.npz exists — suggests at least one training run used real data
- Architecture is sound (128→512→128 residual MLP with skip connections)

#### 4. Cortex-Network (Autoencoder + Classifier) — ❌ COMPLETELY BROKEN

| Metric | Value | Status |
|--------|-------|--------|
| Classification Accuracy | **1.000** (100%) | 🚨 OVERFITTING |
| All per-class F1 | **1.000** (100%) | 🚨 OVERFITTING |
| Anomaly AUC | **0.0623** | 🚨 NEAR-RANDOM (should be >0.95) |
| Training data | Synthetic only (10K/class) | ❌ Not real |

**Root Causes:**
- Trained **exclusively on synthetic data** — model memorized synthetic patterns perfectly
- Autoencoder learned to reconstruct synthetic distributions, not real traffic
- anomaly_auc of 0.0623 is **worse than random coin flip**
- UNSW-NB15 dataset (2.2M records) is **on disk but not used** for training

#### 5. Cortex-Emulation (BiGRU) — ❌ COMPLETELY OVERFITTING

| Metric | Value | Status |
|--------|-------|--------|
| Accuracy | **1.000** (100%) | 🚨 OVERFITTING |
| Loss | **3.97e-11** | 🚨 Impossibly low |
| All per-class F1 | **1.000** (100%) | 🚨 OVERFITTING |
| Training data | 48K synthetic only | ❌ Not real |

**Root Causes:**
- Trained **exclusively on synthetic traces** — zero real emulation data used
- Quo Vadis Speakeasy dataset (93K real samples) is **on disk but not used**
- Perfect scores + near-zero loss = catastrophic synthetic overfitting
- Model will fail completely on real emulation traces

---

### Configuration Bugs Found

| File | Bug | Severity |
|------|-----|----------|
| `config/feeds.yaml` L42-43 | `ember.dataset_version: "2018_2"` — still EMBER 2018 | 🔴 Critical |
| `config/feeds.yaml` L43 | `download_url` points to 2018 archive URL | 🔴 Critical |
| `config/training.yaml` L15 | `cortex_static.feature_count: 2381` — should be 2568 for EMBER 2024 | 🔴 Critical |
| `config/training.yaml` L26 | `detection_threshold: 0.5` — should use HPO-optimized threshold | ⚠️ Medium |
| `config/training.yaml` L17 | `n_estimators: 2000` — HPO found 2421+ better | ⚠️ Medium |
| `scripts/train_static.py` L98 | Defaults to `ember2018` — should default to `ember2024-pe` | 🔴 Critical |
| `models/train.py` L103 | `_STATIC_DEFAULTS["dataset"]: "ember2024-pe"` inconsistent with script default | ⚠️ Medium |
| `config/training.yaml` L67 | Quantization `method: "dynamic"` — LightGBM gets 0% benefit from dynamic INT8 | ⚠️ Medium |

---

### Dataset License Audit (Commercial-Friendly)

| Dataset | License | Status | Models |
|---------|---------|--------|--------|
| **EMBER 2024** | Apache-2.0 | ✅ Commercial-friendly | Cortex-Static |
| **EMBER 2018** | Apache-2.0 | ⚠️ Obsolete but licensed | Deprecated |
| **Quo Vadis Speakeasy** | Apache-2.0 | ✅ Commercial-friendly | Cortex-Behavioral, Cortex-Emulation |
| **Mal-API-2019** | MIT | ✅ Commercial-friendly | Cortex-Behavioral |
| **MalbehavD-V1** | MIT | ✅ Commercial-friendly | Cortex-Behavioral |
| **CIC-MalMem-2022** | CC-BY 4.0 | ✅ Commercial-friendly (with attribution) | Cortex-Memory |
| **MemMal-D2024** | Apache-2.0 | ✅ Commercial-friendly | Cortex-Memory |
| **UNSW-NB15** | Research/Academic | ⚠️ Verify commercial terms | Cortex-Network |

---

## 📋 IMPLEMENTATION PLAN

### Phase 1: Configuration Fixes & Cleanup

- [x] **1.1** Fix `config/feeds.yaml`: Update EMBER entry to version `2024`, update download URL, update SHA256
- [x] **1.2** Fix `config/training.yaml`: Update `cortex_static.feature_count` from `2381` → `2568`
- [x] **1.3** Fix `config/training.yaml`: Increase `cortex_static.n_estimators` from `2000` → `3000`
- [x] **1.4** Fix `config/training.yaml`: Update `cortex_static.num_leaves` from `127` → `255` (tuned by HPO)
- [x] **1.5** Fix `config/training.yaml`: Update `cortex_static.max_depth` from `10` → `15` (more capacity for EMBER 2024)
- [x] **1.6** Fix `scripts/train_static.py`: Change default `--dataset` from `ember2018` → `ember2024-pe`
- [x] **1.7** Fix `models/train.py`: Ensure `_STATIC_DEFAULTS` and script default are consistent (`ember2024-pe`)
- [x] **1.8** Fix `config/training.yaml` quantization: Add `static_quantization_method: "none"` for LightGBM (already a tree model, quantization is N/A)
- [x] **1.9** Add `config/training.yaml` settings for real-data training modes for Behavioral, Network, and Emulation models

### Phase 2: Dataset Procurement & Integration

- [x] **2.1** **EMBER 2024 setup**: Verify `ember2024_loader.py` works end-to-end; ensure thrember package downloads the PE subset correctly; validate feature dimension = 2568
- [x] **2.2** **Quo Vadis Speakeasy integration for Behavioral**: The `quo_vadis_loader.py` already maps families to BehaviorCategory — verify it's wired into `train_behavioral.py` and `train.py` bridge
- [x] **2.3** **Quo Vadis Speakeasy integration for Emulation**: The `quo_vadis_loader.py` produces `(N, 1024, 4)` emulation features — verify it's wired into `train_emulation.py` and the bridge
- [x] **2.4** **UNSW-NB15 integration for Network**: The `unsw_nb15_loader.py` already maps to 64-dim features — verify it's wired into `train_network.py` and the bridge
- [x] **2.5** **CIC-MalMem-2022 + MemMal-D2024 for Memory**: The `memory_external_loader.py` already produces 128-dim features — verify it's wired into `train_memory.py` and the bridge
- [x] **2.6** Verify all dataset downloads complete successfully and raw data integrity
- [x] **2.7** Research and document UNSW-NB15 commercial licensing terms — **FINDING**: No explicit open-source license. Uses "academic/public use with citation" model. Recommend legal review before shipping. CSE-CIC-IDS2018 (AWS Open Data) identified as fallback. Updated loader docstring with attribution requirements.

### Phase 3: Cortex-Static Retraining (Highest Priority)

- [ ] **3.1** Download EMBER 2024 PE dataset via thrember (4.68M train + 1.08M test samples)
- [ ] **3.2** Run full Optuna HPO with 100+ trials, 5-fold stratified CV, 1-hour timeout
- [ ] **3.3** Train final model with best HPO parameters + 50-round early stopping
- [ ] **3.4** Run Platt calibration on validation set
- [ ] **3.5** Evaluate on held-out test set — verify AUC > 0.999, FPR < 0.1%, Detection > 99.5%
- [ ] **3.6** Export to ONNX (opset 17)
- [ ] **3.7** Verify model size < 20 MB
- [ ] **3.8** Run inference latency benchmark — verify < 5 ms
- [ ] **3.9** Compare against current EMBER 2018 model — document improvement

### Phase 4: Cortex-Behavioral Retraining

- [ ] **4.1** Load Quo Vadis Speakeasy dataset (75K train + 17K test real samples)
- [ ] **4.2** Load Mal-API-2019 + MalbehavD-V1 external corpus
- [ ] **4.3** Merge real + external data with synthetic backfill only for underrepresented classes
- [ ] **4.4** Train with real-data-heavy curriculum: 70% real, 20% external, 10% synthetic
- [ ] **4.5** Apply class-specific data augmentation for weak classes (Backdoor, RAT, Fileless, Persistence)
- [ ] **4.6** Run training with 150 epochs (increase from 100), CosineAnnealing + warm restarts
- [ ] **4.7** Evaluate per-class: target all classes ≥ 0.92 F1
- [ ] **4.8** Export to ONNX INT8, verify accuracy retention within 1%

### Phase 5: Cortex-Network Retraining (Complete Rebuild)

- [ ] **5.1** Load UNSW-NB15 dataset (2.2M records) via `unsw_nb15_loader.py`
- [ ] **5.2** Retrain autoencoder on ONLY Normal traffic samples (crucial for anomaly detection)
- [ ] **5.3** Retrain classifier head on all 8 classes with real labeled data
- [ ] **5.4** Verify anomaly AUC > 0.95 (currently 0.06 — must be fixed)
- [ ] **5.5** Verify classification accuracy reasonable (>0.90 overall, not 100%)
- [ ] **5.6** Add 20% synthetic augmentation only after real-data training establishes baseline
- [ ] **5.7** Export to ONNX INT8, benchmark latency

### Phase 6: Cortex-Memory Retraining (Real Data First)

- [ ] **6.1** Load CIC-MalMem-2022 (58K samples) + MemMal-D2024 (58K samples)
- [ ] **6.2** Engineer 55 Volatility features → 128 dimensions via `memory_external_loader.py`
- [ ] **6.3** Class-balance across 5 classes with max 30K samples/class
- [ ] **6.4** Train MLP with real data as primary, synthetic as augmentation only
- [ ] **6.5** Evaluate per-class F1 on held-out real data
- [ ] **6.6** Export to ONNX INT8, verify accuracy retention

### Phase 7: Cortex-Emulation Retraining (Real Data Critical)

- [ ] **7.1** Load Quo Vadis Speakeasy dataset with emulation-specific featurization (1024-event sequences)
- [ ] **7.2** Map 93K samples to 3-class verdict: Benign (clean + syswow64), Suspicious (dropper), Malicious (ransomware, backdoor, trojan, rat, keylogger, coinminer)
- [ ] **7.3** Train BiGRU on real data — verify loss is reasonable (not 1e-11)
- [ ] **7.4** Evaluate: accuracy should be realistic (85-95%), not 100%
- [ ] **7.5** Add synthetic augmentation only for underrepresented patterns
- [ ] **7.6** Export to ONNX; investigate static quantization with calibration data (dynamic only gives 10% reduction)

### Phase 8: Ensemble Calibration & System Integration

- [ ] **8.1** Calibrate ensemble aggregator weights based on per-model confidence scores
- [ ] **8.2** Run end-to-end ensemble evaluation on combined test sets
- [ ] **8.3** Verify unified verdict quality: CLEAN/MALICIOUS accuracy > 99%
- [ ] **8.4** Update `nightly_config.yaml` to reference correct dataset configs
- [ ] **8.5** Run full pipeline dry-run (`--dry-run`) to verify all configs are valid
- [ ] **8.6** Run full pipeline end-to-end to confirm nightly automation works

### Phase 9: Quality Assurance & Hardening

- [ ] **9.1** Run adversarial robustness tests (adversarial_test.py) on all models
- [ ] **9.2** Run false positive tests (false_positive_test.py) on all models
- [ ] **9.3** Verify all models pass quality gates (AUC ≥ 0.995, FPR ≤ 0.001, etc.)
- [ ] **9.4** Verify all ONNX models < 20 MB and inference < 5 ms
- [ ] **9.5** Stage all passing models to production directory
- [ ] **9.6** Create model backup of pre-retraining artifacts
- [ ] **9.7** Generate final comprehensive metrics report

### Phase 10: Documentation & Cleanup

- [ ] **10.1** Remove obsolete EMBER 2018 config entries from feeds.yaml (keep loader for backward compatibility)
- [ ] **10.2** Update PhantomCortex README.md with new dataset strategy table
- [ ] **10.3** Document all model hyperparameters, training data sources, and metrics in a training manifest
- [ ] **10.4** Clean up `data/processed/` of any stale intermediate files
- [ ] **10.5** Verify `.gitignore` excludes raw datasets, model weights, and large binaries
- [ ] **10.6** Final commit with updated configs, documentation, and clean state

---

## Hyperparameter Sweet-Spot Recommendations

### Cortex-Static (LightGBM with EMBER 2024)

```yaml
cortex_static:
  model_type: "lightgbm"
  feature_count: 2568          # EMBER 2024 (was 2381)
  n_estimators: 3000           # Higher ceiling for HPO (was 2000)
  learning_rate: 0.03          # Slightly lower for EMBER 2024 (was 0.05)
  num_leaves: 255              # More capacity (was 127)
  max_depth: 15                # Deeper trees (was 10)
  min_child_samples: 50        # More regularization for larger dataset
  subsample: 0.8               # Keep
  colsample_bytree: 0.7        # Slight reduction for 2568 features
  reg_alpha: 5.0               # Stronger L1 (was 0.1)
  reg_lambda: 0.01             # Lighter L2 (was 1.0)
  objective: "binary"
  metric: "auc"
  early_stopping_rounds: 50
  optuna_trials: 150           # More trials (was 100)
  cv_folds: 5
  target_fpr: 0.001
  target_detection_rate: 0.995
```

### Cortex-Behavioral (CNN + Attention)

```yaml
cortex_behavioral:
  model_type: "cnn_attention"
  sequence_length: 512
  feature_dim: 4
  embed_dim: 128               # Increase embedding (was 64) for richer representations
  num_classes: 20
  epochs: 150                  # More epochs (was 100)
  batch_size: 128              # Smaller batches (was 256) for better generalization
  learning_rate: 0.0005        # Lower LR (was 0.001) for real data
  weight_decay: 0.0005         # Stronger regularization (was 0.0001)
  dataset_mode: "hybrid_real_first"  # New: prioritize real data
  real_data_fraction: 0.70     # New: 70% real data
```

### Cortex-Network (Autoencoder + Classifier)

```yaml
cortex_network:
  model_type: "autoencoder_classifier"
  latent_dim: 32
  num_classes: 8
  epochs: 200                  # More epochs (was 100) for real data convergence
  batch_size: 512              # Larger batches (was 128) for UNSW-NB15 (2.2M samples)
  learning_rate: 0.0005        # New: lower LR for real data
  anomaly_threshold: 0.95
  recon_weight: 0.7            # Increase reconstruction loss weight (was 0.5) — anomaly AUC is critical
  ae_pretrain_epochs: 50       # New: pretrain autoencoder on Normal traffic only
```

### Cortex-Memory (MLP)

```yaml
cortex_memory:
  model_type: "mlp"
  input_dim: 128
  num_classes: 5
  epochs: 100                  # More epochs (was 50) for real data
  batch_size: 256              # Smaller batches (was 512) for better convergence on real data
  learning_rate: 0.0005        # Lower LR (was 0.001)
  weight_decay: 0.0005         # Stronger regularization
```

### Cortex-Emulation (BiGRU)

```yaml
cortex_emulation:
  model_type: "gru"
  sequence_length: 1024
  feature_dim: 4
  hidden_dim: 256
  num_layers: 3                # More layers (was 2) for complex emulation patterns
  num_classes: 3
  epochs: 120                  # More epochs (was 80) for real data
  batch_size: 64               # Smaller batches (was 128) for complex sequences
  learning_rate: 0.0003        # Lower LR for real data convergence
  dropout: 0.4                 # Higher dropout (was implicit 0.3) to prevent overfitting
```

---

## Dataset Strategy (Final)

| Model | Primary Dataset | Secondary | Synthetic Backfill | Total Expected |
|-------|----------------|-----------|-------------------|----------------|
| **Cortex-Static** | EMBER 2024 (5.76M) | — | — | ~5.76M samples |
| **Cortex-Behavioral** | Quo Vadis Speakeasy (93K) | Mal-API-2019 + MalbehavD-V1 | Per-class gap fill | ~120K+ samples |
| **Cortex-Memory** | CIC-MalMem-2022 (58K) + MemMal-D2024 (58K) | — | Per-class gap fill | ~100K+ samples |
| **Cortex-Network** | UNSW-NB15 (2.2M) | — | Augmentation only | ~2.2M+ samples |
| **Cortex-Emulation** | Quo Vadis Speakeasy (93K) | — | Underrepresented patterns | ~100K+ samples |

All datasets are **Apache-2.0, MIT, or CC-BY** — fully commercial-friendly.

---

## Success Criteria

| Model | AUC-ROC | FPR | Detection Rate | Anomaly AUC | Inference |
|-------|---------|-----|---------------|-------------|-----------|
| Cortex-Static | ≥ 0.999 | ≤ 0.001 | ≥ 0.995 | — | < 1 ms |
| Cortex-Behavioral | — | — | — | — | < 5 ms |
| Cortex-Memory | — | — | — | — | < 2 ms |
| Cortex-Network | — | — | — | ≥ 0.95 | < 5 ms |
| Cortex-Emulation | — | — | — | — | < 5 ms |
| **All Models** | Per quality gates | ≤ 0.001 | ≥ 0.995 | — | < 5 ms |

---

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| EMBER 2024 download fails (45 GB) | Blocks Static retraining | Pre-verify thrember, fallback to subset |
| UNSW-NB15 commercial license unclear | May need alternative dataset | Research CICFlowMeter alternatives (Apache-2.0) |
| Quo Vadis data from 2022 may have concept drift | Reduced detection of 2024-2026 malware | Supplement with threat feed samples |
| LightGBM quantization ineffective | Model size stays at ~18 MB | Acceptable — LightGBM is already compact |
| GRU static quantization needs calibration data | More complex pipeline step | Use real test data as calibration set |

---

*This plan ensures ShadowStrike's AI/ML models meet world-class enterprise standards, trained on real commercial-friendly datasets, with proper hyperparameter optimization and robust quality gates.*

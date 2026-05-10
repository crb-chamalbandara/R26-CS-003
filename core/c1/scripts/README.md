# C1 Phase 1 ML Scripts

## Build manifest/code dataset from CRX

```bash
python core/c1/scripts/build_manifest_dataset.py \
  --benign-dir core/c1/data/GoogleChromeExtension/benign/benign \
  --malware-dir core/c1/data/GoogleChromeExtension/malware/malware \
  --output core/c1/data/manifest_dataset.csv
```

## Prepare the dataset

```bash
python core/c1/scripts/prepare_data.py \
  --input core/c1/data/manifest_dataset.csv \
  --output core/c1/data/dataset_clean.csv \
  --label-col label
```

## Train the model

```bash
python core/c1/scripts/train_model.py \
  --input core/c1/data/dataset_clean.csv \
  --model-out core/c1/models/extension_detector_model.pkl \
  --label-col label
```

# HOVSS-PQ

**Human-Verifiable Visual Secret Sharing through a Modular Framework for Post-Quantum Authentication and Device-Independent Integrity Verification**

[![DOI](https://zenodo.org/badge/1462724654.svg)](https://doi.org/10.5281/zenodo.24351102)

**Repository:** https://github.com/mahmoudrokaya/HOVSS-PQ-  
**Zenodo record displayed by the integration:** https://doi.org/10.5281/zenodo.24351103  
**DOI badge target supplied by Zenodo:** https://doi.org/10.5281/zenodo.24351102

> **Citation note:** The two DOI identifiers above were supplied by the Zenodo GitHub integration. Confirm their concept/version relationship and the applicable release tag on the Zenodo record before selecting a DOI for a manuscript citation. For exact reproducibility, cite the DOI of the particular release used.

## Overview

Visual secret sharing (VSS) distributes an image across shares that can be combined to recover a recognizable representation. However, recognizable reconstruction alone does not establish that the shares were legitimately issued, that the reconstructed content has not been changed, or that an unaided observer can reliably detect tampering.

**HOVSS-PQ** is a modular research framework investigating these distinct requirements through mathematical analysis, adversarial counterexamples, digital experiments, optical-disturbance simulation, ML-DSA-65 electronic issuer authentication, and synthetic-observer evaluation. It studies the conditions needed to connect authenticated enrollment to a physically observable reconstruction without assuming that independently successful components form a secure end-to-end protocol.

**Research status:** This repository documents component-level feasibility and limitations. It does **not** claim a proven post-quantum optical authentication protocol or completed human-participant validation.

## Research objectives

1. Characterize confidentiality and authorized reconstruction in visual secret sharing.
2. Test whether content changes, share substitution, and reconstruction ambiguity can evade proposed integrity mechanisms.
3. Assess ML-DSA-65 for **electronic** issuer-enrollment authentication, separately from optical content binding.
4. Measure sensitivity to alignment and optical disturbances in computational models.
5. Evaluate synthetic-observer discrimination without conflating it with measured human performance.
6. Make experimental assumptions, source artifacts, and limitations traceable for independent reproduction.

## Reported findings

The following values are reported in the associated research manuscript. They are **not** independently reverified by this README; consult the archived result files and experiment records for their provenance.

| Evaluation | Reported result | Interpretation |
|---|---:|---|
| Masked-reference public-view total variation | 0.0 | Equality of the evaluated distributions; not a universal secrecy proof |
| Masked-reference content modifications | 3,072 / 3,072 rejected | Exact **digital** verification under tested conditions |
| Separable-tag content modifications | 3,072 / 3,072 accepted | Demonstrates an integrity weakness in the tested construction |
| Adaptive forgery | 0.500 (one private challenge); 0.750 (two adaptive attempts) | Specific attack settings, not general protocol probabilities |
| Ideal digital reconstruction | 100% pixel agreement | Ideal aligned computational case |
| One-pixel displacement | 0.7492 pixel error rate | Sensitivity to registration error in the evaluated setup |
| ML-DSA-65 checks | 15 / 15 passed | Electronic verification only; optical binding unproven |
| C16 synthetic-observer benchmark | 546 images × 9 conditions × 100 observers × 10 repetitions = 4,914,000 synthetic decisions | Simulated decisions, **not** human-participant trials |
| C16 ROC-AUC | 0.998168498 | Synthetic-observer discrimination under the evaluated conditions |
| C16 balanced accuracy | approximately 0.9982 | Synthetic-observer metric, not human reliability |

## Repository organization

```text
HOVSS-PQ-/
├── README.md
├── CITATION.cff
├── LICENSE                         # Verify software license before reuse
├── LICENSE-DATA-CC-BY-4.0          # Original eligible research data/documentation
├── requirements.txt
├── environment.yml
├── pyproject.toml
├── code/
│   ├── C01-C16/                    # Organization may differ in the actual repository
│   ├── F1-F8/
│   └── utilities/
├── configs/
│   ├── README.md
│   ├── default.yaml
│   ├── security/
│   ├── optical/
│   ├── perception/
│   ├── experiments/                # C01–C16, F01–F08 configuration records
│   └── publication/                # tables.yaml, figures.yaml
├── data/
│   └── README.md
├── results/
│   ├── README.md
│   ├── tables/
│   ├── figures/
│   └── summaries/
├── archives/
├── metadata/
│   ├── manifest.csv
│   ├── excluded_files.csv
│   └── summary.json
└── docs/
    ├── REPRODUCIBILITY.md
    ├── EXPERIMENT_INDEX.md
    ├── DATA_AVAILABILITY.md
    └── SECURITY_SCOPE.md
```

The tree describes the **intended organization**. Some paths may be absent, empty, or differently nested in a particular release. The archive's actual file listing and `metadata/manifest.csv` are authoritative once populated and audited. A directory or YAML template alone does not demonstrate the presence of executable code or source data.

## Experimental coverage

The project tracks **C01–C16** computational/security experiments and **F01–F08** feasibility studies or reference constructions. The research manuscript discusses the F1–F7 computational baselines: conventional (2,2) sharing, parity/syndrome verification, independent audit patterns, sparse inspection, ideal full-field comparison, multiplicative optical transmission, and registration-aware comparison.

Use [`docs/EXPERIMENT_INDEX.md`](docs/EXPERIMENT_INDEX.md) for experiment descriptions and evidence status. Experiment-specific settings are documented under [`configs/experiments/`](configs/experiments/); some records are templates and must be checked against original scripts and logs before being treated as historical execution configurations.

## Installation

A Python 3.11 environment is proposed for repository use; the exact historical environment should be established from the original execution records.

**Conda:**

```bash
conda env create -f environment.yml
conda activate hovss-pq
```

The environment name must match the actual `environment.yml`. Alternatively, install from `requirements.txt` in a fresh Python virtual environment:

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Dependency specifications are provisional unless tested against the archived code. If YAML parsing is required, install `PyYAML` or include it in the environment specification.

## Reproducing the experiments

1. Download the **specific Zenodo release** or check out the matching Git tag.
2. Inspect [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md) and [`docs/EXPERIMENT_INDEX.md`](docs/EXPERIMENT_INDEX.md).
3. Confirm that required input datasets and scripts are present; review [`docs/DATA_AVAILABILITY.md`](docs/DATA_AVAILABILITY.md).
4. Verify file hashes against the populated manifest, where available.
5. Identify the corresponding source script, command, random seed, and environment for each experiment.
6. Execute in a separate output directory without overwriting archived evidence.
7. Compare results with the archived tables, figures, and summaries; record discrepancies and numerical tolerances.

**Do not assume that experimental scripts directly accept YAML files.** Configuration documents may be reconstructed specifications rather than parameters consumed by the original implementation. No universal one-command reproduction interface is asserted here.

## Data and result availability

The manuscript describes a benchmark of **546 images**: 500 BSDS500, 39 USC-SIPI, and seven synthetic patterns, standardized to 128 × 128 pixels where applicable. Redistribution of third-party source images depends on their respective licenses. Check the actual archive before assuming every source image, generated share, or intermediate artifact is included.

- Data notes: [`data/README.md`](data/README.md)
- Availability and licensing: [`docs/DATA_AVAILABILITY.md`](docs/DATA_AVAILABILITY.md)
- Results guide: [`results/README.md`](results/README.md)
- Tables 2–6: [`results/tables/`](results/tables/)
- Figures 6–8: [`results/figures/`](results/figures/)
- File inventory and exclusions: [`metadata/`](metadata/)

Some artifacts may be omitted because of licensing, privacy, file-size limits, or incomplete experimental collection. Empty or template metadata files must be populated before making completeness claims.

## Security scope and limitations

HOVSS-PQ deliberately separates:

- **Confidentiality:** what unauthorized share holders can infer.
- **Reconstruction correctness:** whether authorized shares recover the intended representation.
- **Share and content integrity:** whether unauthorized substitutions or content changes are detected.
- **Issuer authentication:** whether the enrolled electronic statement has a valid ML-DSA signature.
- **Optical integrity:** whether the observed physical reconstruction is bound to that authenticated statement.
- **Human verification:** whether real observers can reliably make the prescribed decision under physical viewing conditions.

The electronic signature checks do not establish optical authenticity. Ideal pixelwise digital comparison is not an unaided human-verification mechanism. The C16 results arise from synthetic observers and cannot be reported as human-participant accuracy. Printable prototypes and proposed human-study protocols do not constitute completed physical overlay measurements or human trials. Static visual observations also cannot reliably distinguish an exact copy when all evidence available to the observer is identical.

See [`docs/SECURITY_SCOPE.md`](docs/SECURITY_SCOPE.md) for detailed trust assumptions and claim boundaries.

## Citation and permanent archive

**GitHub:** https://github.com/mahmoudrokaya/HOVSS-PQ-  
**Zenodo record shown in integration:** https://doi.org/10.5281/zenodo.24351103  
**Badge DOI target:** https://doi.org/10.5281/zenodo.24351102

For a published experiment or manuscript, use the **version DOI** that resolves to the exact archived release analyzed. Verify the DOI-to-tag association in Zenodo before publication. The repository also includes [`CITATION.cff`](CITATION.cff), which should be kept consistent with the archive metadata, author list, and version.

## Licensing

The repository may contain software, original research data, generated results, documentation, and third-party datasets with **different licensing conditions**. Consult the applicable license files and dataset notices before reuse. The presence of `LICENSE-DATA-CC-BY-4.0` does not automatically license the source code or third-party datasets under CC BY 4.0. Confirm and document the intended software license separately.

## Research references

- NIST, **FIPS 204: Module-Lattice-Based Digital Signature Standard**: https://doi.org/10.6028/NIST.FIPS.204
- Naor and Shamir, **Visual Cryptography**: https://doi.org/10.1007/BFb0053419
- Zenodo, **GitHub integration**: https://help.zenodo.org/docs/github/
- Citation File Format: https://citation-file-format.github.io/

## Contact and contributions

For questions about the experiments, use the GitHub repository's Issues feature. When reporting a reproduction problem, include the release tag, relevant experiment ID, environment details, execution command, and observed-versus-expected output. Contributions should preserve provenance and avoid silently changing archived historical results.

---

**HOVSS-PQ** provides a traceable framework for investigating the gap between confidential visual reconstruction, authenticated digital enrollment, and trustworthy physical human observation.

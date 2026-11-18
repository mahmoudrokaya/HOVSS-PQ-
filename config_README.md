# HOVSS-PQ — Experimental Configurations

**Human-Verifiable Visual Secret Sharing through a Modular Framework for Post-Quantum Authentication and Device-Independent Integrity Verification**

## 1. Overview

The `configs/` directory contains configuration specifications and parameter records for the experiments supporting the HOVSS-PQ research framework.

Its purpose is to document the experimental settings used to evaluate visual secret sharing, integrity verification, adversarial security, post-quantum authentication, optical reconstruction, and perceptual verification.

These configurations support scientific transparency, experimental traceability, and reproducibility of the results reported in the associated manuscript.

**Important:** Configuration files must distinguish parameters verified from completed experiments from settings proposed for future experiments. The presence of a configuration file does not establish that the corresponding script consumed it during execution.

## 2. Directory Structure

The recommended organization is:

```text
configs/
├── README.md
├── default.yaml
│
├── security/
│   ├── visual_secret_sharing.yaml
│   ├── integrity_verification.yaml
│   ├── adversarial_attacks.yaml
│   └── post_quantum_authentication.yaml
│
├── optical/
│   ├── reconstruction.yaml
│   ├── registration.yaml
│   └── print_simulation.yaml
│
├── perception/
│   ├── synthetic_observers.yaml
│   └── human_study_protocol.yaml
│
├── experiments/
│   ├── C01.yaml ... C16.yaml
│   └── F01.yaml ... F08.yaml
│
└── publication/
    ├── tables.yaml
    └── figures.yaml
```

This structure is a proposed organization. Individual files should be added only when corresponding experimental information is available.

## 3. Configuration Categories

### 3.1 General Settings

`default.yaml` contains common settings, including dataset locations, output directories, execution parameters, and random seeds where applicable.

Paths should be relative to the repository root whenever possible.

### 3.2 Security Configurations

The `security/` directory documents parameters associated with:

- Visual secret sharing and reconstruction operators.
- Content-binding and integrity verification.
- Adversarial attacks and challenge-response mechanisms.
- Post-quantum issuer authentication using ML-DSA.

The configurations must explicitly distinguish digital authentication from optical integrity verification.

### 3.3 Optical Configurations

The `optical/` directory records settings for reconstruction, image registration, geometric displacement, and simulated printing disturbances.

Relevant parameters may include image dimensions, displacement magnitude, alignment methods, interpolation, ink spreading, and evaluation metrics.

Physical experimental measurements must be distinguished from computational simulations.

### 3.4 Perceptual Verification Configurations

The `perception/` directory describes synthetic-observer simulations and planned human-verification protocols.

Synthetic-observer configurations may document simulation conditions, observer models, repetitions, and decision thresholds.

Human-study configurations must distinguish planned protocols from completed participant experiments. Planned participant counts and trials must not be reported as observed results.

### 3.5 Individual Experiment Configurations

The `experiments/` directory contains experiment-specific parameter records for the C-series and F-series studies.

Each record should identify the experiment, its implementation, inputs, parameters, outputs, evaluation metrics, and execution status.

### 3.6 Publication Configurations

The `publication/` directory connects experimental artifacts to the manuscript.

- `tables.yaml` maps Tables 2–6 to their source data, calculations, and generating scripts.
- `figures.yaml` maps Figures 6–8 to their input data, plotting procedures, and generated files.

These mappings require verification against the final manuscript and archived results.

## 4. Configuration Provenance

Every configuration should declare one of the following provenance types:

| Type | Definition |
|---|---|
| `executed` | Configuration demonstrably consumed by the original experiment |
| `reconstructed` | Parameters recovered from source code, logs, or experimental records |
| `proposed` | Settings intended for future experiments and not yet executed |

A reconstructed configuration must identify the source from which each parameter was obtained.

Parameters that cannot be verified must remain unspecified rather than being estimated or invented.

## 5. Recommended Configuration Metadata

Each experiment configuration should include the following information where available:

| Field | Description |
|---|---|
| `experiment_id` | Unique experiment identifier |
| `status` | Completed, partially completed, or planned |
| `provenance_type` | Executed, reconstructed, or proposed |
| `source_script` | Python implementation |
| `input_files` | Required datasets and supporting files |
| `parameters` | Verified experimental settings |
| `random_seed` | Recorded random seed, if applicable |
| `output_files` | Generated experimental artifacts |
| `metrics` | Evaluation measures |
| `environment` | Relevant software and dependency versions |
| `source_evidence` | Script, log, or record supporting the configuration |

## 6. Example Configuration

The following is an illustrative template, not a verified configuration from a completed HOVSS-PQ experiment.

```yaml
experiment_id: CXX
status: unknown
provenance_type: proposed

source_script: null

input_files: []

parameters:
  random_seed: null
  reconstruction_operator: null
  verification_method: null

output_files: []

metrics: []

environment:
  python_version: null
  dependency_file: environment.yml

source_evidence: []

notes: >
  Replace all placeholders with verified experimental
  information before publication.
```

The experiment identifier `CXX` is a placeholder and must be replaced with the actual experiment identifier.

## 7. Reproducing an Experiment

The recommended reproduction procedure is:

1. Identify the experiment configuration in `configs/experiments/`.
2. Locate the corresponding implementation under `code/`.
3. Confirm that all required input files are available.
4. Verify the Python environment and dependencies.
5. Review the configuration provenance and recorded parameters.
6. Execute the experiment using its documented command.
7. Compare generated outputs with the archived results.
8. Verify file integrity using the repository manifest and checksums.

**Configuration support:** Existing experimental scripts may not accept YAML configuration files directly. Where necessary, the recorded parameters must be applied using the script's documented command-line arguments or original implementation settings.

Do not assume that passing a YAML file to a script is supported unless the script explicitly implements that functionality.

## 8. Manuscript Reproducibility

The configuration directory supports the verification of findings reported in Section 5 of the HOVSS-PQ manuscript.

The principal evaluation areas include:

- Confidentiality and content-integrity assessment.
- Mathematical reconstruction ambiguity.
- Adversarial forgery and adaptive attacks.
- Post-quantum electronic enrollment verification.
- Optical registration and reconstruction robustness.
- Computational and synthetic-observer performance.

Each reported numerical result should be traceable to the original experimental input, implementation, configuration, and output.

The publication mapping files should provide this traceability for Tables 2–6 and Figures 6–8.

## 9. Experimental Integrity and Limitations

The following principles apply to all configuration records:

- Do not modify historical experimental parameters without documenting the change.
- Do not substitute proposed settings for parameters used in completed experiments.
- Do not treat simulated observations as physical measurements.
- Do not treat synthetic-observer results as human-participant evidence.
- Do not interpret successful ML-DSA verification as proof of optical content binding.
- Do not claim reproducibility until the experiment has been successfully rerun and its outputs verified.

Any discrepancies between archived results and reproduced outputs should be documented.

## 10. Versioning and Archiving

Configurations supporting a published result should be preserved in the corresponding versioned GitHub release and Zenodo archive.

When parameters change, the updated configuration should document the revision and its effect on the experimental procedure.

Where feasible, configuration files should be accompanied by checksums, environment information, and an experiment-to-result mapping.

The Zenodo DOI for the relevant release should be cited when referencing the archived research artifacts.

## 11. Related Repository Resources

| Resource | Purpose |
|---|---|
| `../README.md` | Main research repository overview |
| `../code/` | Experimental implementations |
| `../data/` | Experimental input datasets |
| `../results/` | Evaluation outputs and published results |
| `../archives/` | Archived experimental packages |
| `../metadata/manifest.csv` | File inventory and SHA-256 checksums |
| `../environment.yml` | Conda environment specification |
| `../requirements.txt` | Python dependencies |

## 12. References

- NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard: https://doi.org/10.6028/NIST.FIPS.204
- Python Packaging User Guide: https://packaging.python.org/
- Conda Environment Management: https://docs.conda.io/projects/conda/en/latest/user-guide/tasks/manage-environments.html
- Zenodo Documentation: https://help.zenodo.org/

---

**HOVSS-PQ — Reproducible configurations for mathematical, computational, adversarial, and optical security evaluation.**

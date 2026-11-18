# HOVSS-PQ

**Human-Verifiable Visual Secret Sharing through a Modular Framework for Post-Quantum Authentication and Device-Independent Integrity Verification**

HOVSS-PQ is a research framework investigating the integration of visual secret sharing (VSS), post-quantum cryptographic authentication, content integrity, and human-observable verification.

This repository provides research implementations, experimental datasets, adversarial evaluations, mathematical validation artifacts, and computational results supporting the associated scientific manuscript.

The project emphasizes reproducible security evaluation and the distinction between confidential reconstruction, cryptographic authenticity, optical integrity, and human-verification reliability.

## 1. Research Objectives

The research investigates whether visual secret sharing can be extended beyond confidential image reconstruction toward trustworthy authentication and integrity verification.

The primary objectives are to:

1. Investigate the mathematical feasibility of integrating visual secret sharing with content-bound authentication.
2. Identify security weaknesses arising from reconstruction ambiguity, share substitution, and insufficient integrity binding.
3. Evaluate adversarial resistance under different verification constructions.
4. Investigate the integration of post-quantum digital signatures using ML-DSA.
5. Quantify reconstruction sensitivity to optical disturbances and geometric misalignment.
6. Evaluate computational perceptual discrimination and establish a foundation for subsequent human-participant experiments.
7. Provide reproducible implementations and experimental evidence supporting the reported findings.

## 2. Research Contributions

The HOVSS-PQ research provides:

- **Modular security framework:** A structured evaluation of confidentiality, reconstruction correctness, digital authentication, optical integrity, and human-observable verification.
- **Mathematical feasibility analysis:** Counterexamples and construction-level investigations identifying limitations in visual reconstruction and authentication binding.
- **Adversarial security evaluation:** Experiments investigating content modification, forgery acceptance, and adaptive verification attempts.
- **Post-quantum enrollment authentication:** Experimental verification using the standardized ML-DSA-65 signature algorithm.
- **Optical robustness assessment:** Evaluation of registration errors and reconstruction degradation.
- **Perceptual verification benchmarking:** Computational and synthetic-observer experiments investigating the discrimination of authentic and manipulated reconstructions.
- **Reproducibility artifacts:** Source code, experimental inputs, configurations, results, and supporting documentation.

The framework is a research and feasibility assessment. It does not claim a formally proven end-to-end post-quantum optical authentication protocol.

## 3. Repository Structure

The repository is organized into the following directories:

```text
HOVSS-PQ/
├── README.md
├── LICENSE
├── LICENSE-DATA-CC-BY-4.0
├── CITATION.cff
├── requirements.txt
├── .gitignore
├── code/
├── configs/
├── data/
├── results/
├── archives/
├── metadata/
└── docs/
```

| Directory | Description |
|---|---|
| `code/` | Experimental implementations and analysis scripts |
| `configs/` | Experiment configurations and parameters |
| `data/` | Research datasets and experimental inputs |
| `results/` | Computational outputs, evaluation summaries, figures, and tables |
| `archives/` | ZIP packages containing experimental artifacts |
| `metadata/` | File manifests, checksums, and collection reports |
| `docs/` | Methodology, reproducibility instructions, and supporting documentation |

Some directories or files may be introduced in subsequent releases. The repository manifest should be consulted for the exact contents of each archived version.

## 4. Experimental Framework

The experimental investigations cover several complementary components.

### 4.1 Mathematical and Security Analysis

- Visual reconstruction correctness and ambiguity.
- Content-binding requirements.
- Share substitution and forgery resistance.
- Public-reference information leakage.
- Adaptive adversarial behavior.

### 4.2 Post-Quantum Authentication

The framework investigates issuer enrollment authentication using ML-DSA-65, as standardized in NIST FIPS 204.

Successful digital signature verification establishes authenticity of the signed electronic record under the relevant cryptographic assumptions. It does not independently establish the authenticity of a physical optical reconstruction.

Reference: https://doi.org/10.6028/NIST.FIPS.204

### 4.3 Optical Reconstruction

Experiments examine:

- Authorized reconstruction accuracy.
- Geometric registration errors.
- Pixel displacement.
- Optical distortion and simulated printing effects.
- Robustness of verification decisions.

### 4.4 Human-Oriented Verification

The framework includes computational perceptual benchmarks and synthetic-observer simulations.

These experiments provide preliminary evidence about perceptual separability but must not be interpreted as actual human-participant validation.

Physical-overlay measurements and controlled human-participant studies are required for that purpose.

## 5. Selected Experimental Findings

The following findings summarize the evaluated experimental conditions reported in the associated research.

| Evaluation | Reported result |
|---|---|
| Masked-reference public-view leakage | Total variation distance = 0.0 |
| Masked-reference content modification | 3,072/3,072 modifications rejected |
| Separable-tag content modification | 3,072/3,072 modifications accepted |
| Single private-challenge forgery acceptance | 0.500 |
| Two-attempt adaptive forgery acceptance | 0.750 |
| Ideal authorized reconstruction | 100% pixel agreement |
| One-pixel displacement | Pixel error rate = 0.7492 |
| ML-DSA-65 electronic verification | 15/15 checks passed |
| Synthetic-observer benchmark | ROC-AUC ≈ 0.9982 |

These measurements are specific to their experimental constructions, datasets, attack models, and evaluation conditions.

They do not establish universal security guarantees or validated human authentication performance.

## 6. Installation and Environment

### 6.1 Requirements

- Python 3
- Required Python libraries specified by the individual experimental scripts
- Access to the corresponding experimental inputs and configurations

The exact Python version and dependency versions should be recorded in a verified environment specification before the first archival release.

### 6.2 Clone the Repository

```bash
git clone https://github.com/OWNER/HOVSS-PQ.git
cd HOVSS-PQ
```

Replace `OWNER` with the actual GitHub account or organization.

### 6.3 Create a Virtual Environment

```bash
python -m venv .venv
```

Windows:

```powershell
.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
source .venv/bin/activate
```

### 6.4 Install Dependencies

Once the verified `requirements.txt` is available:

```bash
pip install -r requirements.txt
```

Some experiments may require additional libraries or environment-specific configuration.

## 7. Reproducing the Experiments

The recommended reproduction procedure is:

1. Identify the experiment corresponding to the manuscript result.
2. Locate its implementation in `code/`.
3. Identify the required inputs in `data/` or `archives/`.
4. Review the experiment configuration and parameters.
5. Execute the relevant script in the documented environment.
6. Compare the generated outputs with the corresponding results.
7. Verify file integrity using the repository manifest and SHA-256 checksums.

The experimental archive may contain ZIP packages instead of duplicate individual files.

**Important:** The repository should not be considered fully reproducible until the executable commands, dependencies, input mappings, and expected outputs have been independently checked.

A detailed experiment-to-result mapping is intended for `docs/EXPERIMENT_INDEX.md`, with execution instructions in `docs/REPRODUCIBILITY.md`.

## 8. Data and Result Availability

Research data, source code, and experimental results are provided to support scientific transparency and independent validation.

Some large files, redundant outputs, or restricted materials may not be included in the GitHub repository.

The repository's collection manifest identifies the included files and their checksums. The exclusion report documents files omitted during artifact collection.

Users should not assume that an omitted file is unnecessary for reproducing every experiment.

## 9. Security Scope and Limitations

HOVSS-PQ investigates the feasibility of combining multiple security mechanisms.

The following distinctions are essential:

- Successful visual reconstruction does not prove share authenticity.
- Digital signature verification does not automatically guarantee optical content integrity.
- Computational classification accuracy does not establish human-observer reliability.
- Security results obtained under specific attack models do not imply universal adversarial resistance.
- Synthetic optical simulations do not replace physical printing and overlay experiments.

The framework should therefore be regarded as a research prototype and evaluation platform, not as a production-ready security system.

## 10. Licensing

The original research datasets, experimental results, figures, and associated data documentation are released under:

**Creative Commons Attribution 4.0 International (CC BY 4.0)**

License: https://creativecommons.org/licenses/by/4.0/

See `LICENSE-DATA-CC-BY-4.0` for the repository's data licensing notice.

Software source code requires a separately designated software license. Unless an applicable license is explicitly provided, no general permission to reuse the software should be inferred from the data license.

Third-party materials remain subject to their original licensing terms.

## 11. Citation

If you use this repository, its datasets, implementations, or experimental findings, please cite the associated scientific publication and the archived Zenodo release.

**Manuscript title:**

*Human-Verifiable Visual Secret Sharing through a Modular Framework for Post-Quantum Authentication and Device-Independent Integrity Verification*

**Zenodo DOI:** To be assigned after the first archived release.

**Publication DOI:** To be updated following publication.

A machine-readable citation record will be provided through `CITATION.cff`.

## 12. Archiving and Versioning

The repository is intended to be archived through Zenodo using versioned GitHub releases.

Each archived release should preserve:

- Source code and configurations.
- Required experimental data.
- Reproducible results.
- Documentation and licensing information.
- A manifest identifying the archived artifacts.

The Zenodo version-specific DOI should be used when citing the exact research artifacts supporting a published manuscript.

## 13. Research Integrity and Responsible Use

The repository is intended for scientific research, educational use, reproducibility assessment, and security-method evaluation.

Users should distinguish experimentally demonstrated results from theoretical objectives, simulated observations, and future validation requirements.

Security-sensitive implementations should undergo independent review before practical deployment.

## 14. References and Resources

- Naor, M., and Shamir, A. (1995). *Visual Cryptography*. https://doi.org/10.1007/BFb0053419
- NIST (2024). *FIPS 204: Module-Lattice-Based Digital Signature Standard*. https://doi.org/10.6028/NIST.FIPS.204
- Creative Commons. *Attribution 4.0 International*. https://creativecommons.org/licenses/by/4.0/
- GitHub Documentation. https://docs.github.com/
- Zenodo Documentation. https://help.zenodo.org/

---

**HOVSS-PQ — Research toward post-quantum-compatible, human-verifiable visual integrity authentication.**

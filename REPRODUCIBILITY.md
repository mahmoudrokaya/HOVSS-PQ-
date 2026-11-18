# HOVSS-PQ — Reproducibility Guide

## Purpose and evidence levels
This guide accompanies *Human-Verifiable Visual Secret Sharing through a Modular Framework for Post-Quantum Authentication and Device-Independent Integrity Verification* (HOVSS-PQ). The manuscript separates mathematical arguments, completed digital simulations, instrumented optical simulations, prepared print prototypes, and prospective physical/human studies. These are **not interchangeable evidence levels**.

The existence of this guide, configuration templates, or an archived ZIP does **not** mean all experiments have been rerun independently. A reproducibility claim requires executable source, original inputs, exact parameters, software versions, output artifacts, and successful comparison with reported results.

## Repository identity and archived version
- **GitHub:** https://github.com/mahmoudrokaya/HOVSS-PQ-
- **Zenodo DOI displayed by the repository integration:** https://doi.org/10.5281/zenodo.24351103
- **Zenodo badge target:** https://doi.org/10.5281/zenodo.24351102
- **Badge:** [![DOI](https://zenodo.org/badge/1462724654.svg)](https://doi.org/10.5281/zenodo.24351102)

The two identifiers are taken from the repository owner's Zenodo interface. Check the Zenodo landing pages to establish which identifier refers to the exact archived release and which covers all versions. **Do not assume a release tag, commit SHA, or archived content without checking.** A later GitHub commit does not retroactively modify an existing Zenodo release.

To reproduce a published result, download the **version-specific Zenodo archive** corresponding to the manuscript, or check out the exact GitHub release tag and commit. Record both identifiers in the reproduction report.

## Expected repository structure

```text
HOVSS-PQ/
  code/                  # Experiment implementations and utilities
  configs/               # Common, security, optical, perceptual, and per-experiment YAML
  data/                  # Source and derived datasets; consult data/README.md
  results/
    tables/              # Supporting Tables 2–6
    figures/             # Supporting Figures 6–8
    summaries/           # Derived metrics and audit summaries
  archives/              # Original experiment packages where retained
  metadata/
    manifest.csv         # Included-file inventory and SHA-256 values
    excluded_files.csv   # Exclusion audit
    summary.json         # Collection summary
  docs/
```

Paths above are **intended locations**, not a claim that every artifact has been populated.

## Dataset and experimental context
The manuscript describes 546 images: 500 BSDS500, 39 USC-SIPI, and seven synthetic patterns, standardized to 128 × 128 where applicable. It describes nine simulated conditions, 100 synthetic observers, ten repetitions, and a reported fixed seed of `20261116` for the benchmark. These settings must be verified against the executable C16 implementation before being treated as a complete reproduction recipe.

## Reproduction procedure
1. Open the archived Zenodo record, identify its **version-specific DOI**, and obtain the corresponding release snapshot. Record its GitHub release tag, commit SHA (if available), archive filename, and SHA-256 checksum. Do not use the moving `main` branch as a substitute for a fixed release.
2. Check `metadata/manifest.csv` against actual files and review `metadata/excluded_files.csv` for missing required inputs. An empty template manifest is **not** an audit.
3. Create the environment using `environment.yml` or `requirements.txt`, then record Python, library, operating-system, and cryptographic-backend versions. These dependency specifications must be tested against the actual scripts.
4. Read `configs/default.yaml`, the relevant `configs/experiments/Cxx.yaml` or `Fxx.yaml`, and the applicable domain configuration. A YAML file is documentation unless the corresponding script explicitly loads it.
5. Identify the source script, data input, CLI invocation, random seed, and output directory from the actual experiment record. Do **not** invent a generic command or assume `--config` is supported.
6. Run the experiment in a clean output directory without overwriting archived results. Capture logs, commands, environment, and hashes.
7. Recompute summary statistics from raw outputs, and compare them to the manuscript with stated numerical tolerances and denominators.
8. Document mismatches, omitted data, stochastic variation, and unverified findings in a reproducibility report.

### Suggested environment setup (only after validating dependencies)

```bash
conda env create -f environment.yml
conda activate hovss-pq
# Or, with a compatible Python environment:
python -m pip install -r requirements.txt
```

The actual Conda environment name must be read from `environment.yml`; `hovss-pq` above is illustrative. If the environment name differs, activate the name specified in the file.

## Manuscript artifact mapping

| Manuscript item | Reported topic | Experiment reference |
|---|---|---|
| Table 2 | Exact confidentiality and forgery | C01–C03 |
| Figure 6 | Forgery acceptance across challenge/public-mask conditions | C06–C09 |
| Table 3 | Construction feasibility | C12 |
| Table 4 | Reconstruction and optical disturbance | C11 |
| Figure 7 | Pooled simulated reconstruction pixel errors | C11 |
| Table 5 | Adversarial and computational verification | Verify exact contributing scripts |
| Figure 8 | Nine-condition synthetic-observer acceptance rates | C16 v4 |
| Table 6 | Physical preparation, human verification, construction selection | Verify supporting records; distinguish planned work |

See `EXPERIMENT_INDEX.md` and `configs/publication/{tables,figures}.yaml` for traceability records. Mappings are manuscript-derived; they are not proof that source artifacts have been included.

## Critical distinctions
- The reported ML-DSA-65 checks (15/15) are **electronic** verification checks, not proof of issuer-authenticated optical reconstruction.
- The C16 benchmark reports **4,914,000 synthetic decisions**, not human-participant decisions.
- Print-ready C13 prototypes do not establish completed physical overlay measurements.
- The C14 participant study is prospective unless dated participant-level records and required approvals establish otherwise.
- Digital registration and full-field comparison are **instrumented baselines**, not unaided human verification.

## Minimal reproduction report
For each reproduced experiment, record: archive DOI and release tag; Git commit (when known); file hashes; Python and package versions; operating system; script path and exact command; config and random seed; input IDs; number of observations/trials; output file paths; computed metrics; comparison tolerance; and pass/fail or unresolved status. Archive this report separately from the original results.

## Verification checklist
- [ ] All input files present and licensed for redistribution
- [ ] Manifest hashes recomputed from actual files
- [ ] Exact script-to-config mapping verified
- [ ] Seeds and software versions recorded
- [ ] Tables 2–6 independently regenerated
- [ ] Figures 6–8 independently regenerated
- [ ] No simulated outcomes labeled physical or human
- [ ] Any exclusions and failed reproductions disclosed

## Methodological references
- [NIST FIPS 204: ML-DSA](https://doi.org/10.6028/NIST.FIPS.204)
- [GitHub documentation](https://docs.github.com/en/repositories)
- [Zenodo–GitHub integration](https://help.zenodo.org/docs/github/)
- [Conda environments](https://docs.conda.io/projects/conda/en/latest/user-guide/tasks/manage-environments.html)

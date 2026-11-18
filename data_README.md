HOVSS-PQ — Data Directory
Project: Human-Verifiable Visual Secret Sharing through a Modular Framework for Post-Quantum Authentication and Device-Independent Integrity Verification
Purpose
The data/ directory contains or references the inputs required to reproduce the HOVSS-PQ experiments. It separates original source datasets from derived visual shares, evaluation inputs, synthetic observations, and physical pilot records. Dataset availability and experimental completion must be established from actual archived files, not inferred from this directory structure.
Recommended organization
data/
├── README.md
├── source/                 # Original input images and source datasets
├── processed/              # Documented preprocessing outputs
├── shares/                 # Generated visual secret-sharing pairs
├── integrity/              # References, witnesses, tags, and attack inputs
├── optical/                # Printable assets and digital optical simulations
├── perception/             # Synthetic-observer inputs and labels
├── physical_pilot/         # Physical print/overlay records, if collected
├── human_study/            # Approved, de-identified human-study data, if collected
└── manifests/              # Dataset indexes, provenance, and checksums
These subdirectories are proposed; create only those supported by available artifacts. Files may instead reside in archives/ or be documented by a manifest when an archive is preferred to duplicate copies.
Dataset inventory
Maintain a dataset inventory with the following fields, as applicable:
Field	Meaning
dataset_id	Stable dataset identifier
description	Data content and purpose
source	Original source or generation script
version	Dataset or processing version
license	Applicable license and restrictions
experiment_ids	Related C-series or F-series experiments
relative_path	Path within the repository or archive
file_count	Verified number of files
sha256	File checksum or checksum-manifest reference
status	available, external, planned, or unavailable


Do not populate counts, paths, licenses, or dataset descriptions by assumption. Where an upstream dataset is not redistributable, provide its official access instructions and any necessary preprocessing steps rather than copying restricted files.
Data categories
Original input data
Retain source filenames and provenance wherever practical. Record any image resizing, thresholding, color conversion, sampling, or dataset partitioning applied before experiments.
Derived visual shares and integrity artifacts
Generated shares, references, tags, and witnesses should be linked to their source images, generating scripts, construction parameters, and random seeds when applicable. Keep private authentication keys and other secrets out of the public repository.
Optical simulation and printable assets
Distinguish digital transformations (translation, rotation, scaling, blur, or printing simulations) from physical printing, alignment, and smartphone photography. Printable files and calibration graphics are not evidence that a physical test was performed.
Synthetic-observer data
Record the image IDs, experimental conditions, synthetic-observer model, repetitions, labels, decisions, and aggregation procedure. The manuscript reports 546 images, 9 conditions, 100 synthetic observers, and 10 repetitions, corresponding to 4,914,000 synthetic decisions. These figures are reported research results and must be independently verified against the archived C16 outputs. They are not human-participant observations.
Physical and human-study data
The C13 printable prototype and C14 human-study protocol should be distinguished from completed measurements. Do not report physical overlays, photographs, participant trials, or human accuracy statistics unless corresponding records actually exist. For any future participant data, obtain the required ethical approvals and consent, de-identify records, and review sharing restrictions before release.
Experiment traceability
Each experiment-specific configuration in ../configs/experiments/ should identify its input dataset(s), expected outputs, and source scripts. The shared configuration files in ../configs/security/, ../configs/optical/, and ../configs/perception/ describe the relevant experimental domains; they do not establish which parameters were used historically.

For every published result, aim to preserve this chain:
Source dataset → preprocessing → experiment configuration
               → source script → generated result → manuscript table/figure
The mappings in ../configs/publication/tables.yaml and ../configs/publication/figures.yaml should be checked against the final manuscript before release.
File integrity and reproducibility
1. Use repository-relative paths rather than local Windows drive letters.
2. Preserve original inputs and do not overwrite archived results.
3. Generate SHA-256 checksums for released files and verify them after copying or extraction.
4. Record the exact script, command, environment, and random seed used to generate derived data.
5. Detect duplicate content before including both a ZIP archive and its extracted files.
6. Check ZIP contents for unsafe extraction paths before unpacking.
7. Document missing, excluded, or externally hosted files explicitly.
A 25 MiB per-file limit was used as a repository collection preference, not as a scientific exclusion criterion. Any larger artifact necessary for reproduction must be documented and made accessible through an appropriate release or data repository when licensing and privacy permit.
Data dictionary and formats
Preferred interoperable formats include CSV and JSON for tabular records and metadata, PNG/TIFF for lossless image artifacts, and NumPy or MATLAB formats when required by the original code. A ZIP archive may package related experiment files. Each structured dataset should include a schema or data dictionary explaining variable names, units, labels, missing values, and row-level independence assumptions.

Do not treat repeated decisions from the same source image or synthetic observer as independent human observations when calculating uncertainty.
Licensing and redistribution
The repository's proposed data-documentation license is Creative Commons Attribution 4.0 (CC BY 4.0), subject to confirmation that the project has rights to license each included artifact. Third-party datasets retain their original licenses. A data license does not automatically license the software in ../code/.

Review all datasets for copyright, personal information, biometric or clinical content, and contractual restrictions before public distribution.
Pre-release checklist
- [ ] Every included dataset has an identified source and permitted distribution status.
- [ ] Experiment-to-input mappings have been verified.
- [ ] Dataset sizes and counts match actual files.
- [ ] SHA-256 manifests are generated and checked.
- [ ] Duplicate archive/extracted-file copies are resolved.
- [ ] Missing files and external dependencies are documented.
- [ ] Synthetic, simulated, physical, and human data are clearly distinguished.
- [ ] Sensitive information and secret keys are excluded.
- [ ] The release has been tested against the documented reproduction procedure.
Related files
- [`../README.md`](../README.md) — repository overview
- [`../configs/README.md`](../configs/README.md) — configuration provenance and organization
- [`../code/`](../code/) — experimental implementations
- [`../results/`](../results/) — experiment outputs
- [`../archives/`](../archives/) — packaged experimental artifacts
- [`../metadata/`](../metadata/) — inventories, checksums, and audit records
References
- FAIR Guiding Principles for scientific data management and stewardship
- Zenodo documentation
- Creative Commons Attribution 4.0 International
- NIST FIPS 204: Module-Lattice-Based Digital Signature Standard
Status: Documentation template. Dataset inventories, file paths, licenses, and experiment mappings require verification against the actual repository contents before publication.

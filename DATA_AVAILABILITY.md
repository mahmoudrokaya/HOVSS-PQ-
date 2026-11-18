# HOVSS-PQ — Data Availability and Provenance

## Public repository and persistent archive
The HOVSS-PQ GitHub repository is connected to Zenodo and a DOI has been displayed in the Zenodo integration interface.

- **GitHub repository:** https://github.com/mahmoudrokaya/HOVSS-PQ-
- **Zenodo DOI displayed for the repository:** https://doi.org/10.5281/zenodo.24351103
- **DOI linked by Zenodo's generated badge:** https://doi.org/10.5281/zenodo.24351102
- **DOI badge:** [![DOI](https://zenodo.org/badge/1462724654.svg)](https://doi.org/10.5281/zenodo.24351102)

**DOI verification:** The identifiers above are reproduced from the Zenodo page supplied by the repository owner. Confirm the version-specific DOI, concept DOI, release tag, authors, and actual deposited files on the Zenodo record before citing a specific release. The DOI is not evidence that all expected datasets or outputs are included.

Zenodo archives a GitHub release snapshot, not subsequent changes to the GitHub default branch. For reproducible access, use the release-specific archived record and document its release tag and commit SHA. Consult `../data/README.md` and `../metadata/manifest.csv` when populated.

## Dataset composition reported in the manuscript

| Source | Reported count | Notes |
|---|---:|---|
| BSDS500 | 500 | Original distribution rights must be checked |
| USC-SIPI | 39 | Original distribution rights must be checked |
| Synthetic patterns | 7 | Provenance and generation scripts must be supplied |
| **Total** | **546** | 128 × 128 standardization where applicable |

The counts describe the **manuscript benchmark**, not a verified inventory of files currently present in the repository. Redistribution of third-party images is subject to each source's license and terms; citation alone does not grant redistribution rights.

## Data classes
1. **Third-party input images:** identify source, retrieval date, version, license, original identifier, and transformations. If redistribution is restricted, supply a retrieval procedure and reproducible preprocessing rather than copying the images into the release.
2. **Synthetic patterns:** publish the generator, seed, parameters, and generated images where rights permit.
3. **Visual shares and reconstructions:** publish original/derived labels, share-pair relationships, alignment parameters, and content hashes. Do not confuse digital overlays with physical captures.
4. **Attack trials and simulation results:** include attack type, threat assumptions, acceptance decisions, trial denominators, conditions, and seeds.
5. **C16 synthetic-observer results:** label all decisions as simulated. The manuscript reports 4,914,000 simulated decisions and ROC-AUC ≈ 0.9982; confirm original files and score derivation before release.
6. **C13 physical pilot:** printable share packages can be distributed as prototypes; measured calibration bars, overlay photographs, and observations must not be claimed unless collected.
7. **C14 human study:** protocol and blank observation forms are **not** participant data. Do not publish identifiable participant information; confirm ethics, consent, and data-sharing permissions before any participant-level release.

## Included, excluded, and oversized files
The repository collection policy has favored ZIP archives when they replace duplicate individual content and has excluded individual files larger than **25 MiB** from the planned GitHub-oriented collection. These are packaging decisions, not scientific exclusion criteria. Required but omitted experimental inputs must be documented in `metadata/excluded_files.csv` with a lawful retrieval route or alternate archive location. Do not claim complete reproduction if required data are absent.

## Integrity and audit
- Populate `metadata/manifest.csv` from actual included files, recording relative path, size, SHA-256, source/provenance, and category.
- Record excluded items and their reasons in `metadata/excluded_files.csv`.
- Populate `metadata/summary.json` with measured counts and collection rules; template `null` values must not be treated as zero.
- Verify archive integrity, avoid duplicate storage, and preserve original experimental artifacts.
- Record exact preprocessing and split definitions. Image-level separation matters for C16's held-out evaluation.

## Licensing
`LICENSE-DATA-CC-BY-4.0` is intended to govern **original material owned by the research authors only**, subject to the actual license declaration. It does not override the licenses of BSDS500, USC-SIPI, or other third-party materials. Software licensing must be declared separately in `LICENSE` and should not be inferred from the data license.

## Citation and access
- GitHub repository: https://github.com/mahmoudrokaya/HOVSS-PQ-
- Zenodo DOI shown in the integration interface: https://doi.org/10.5281/zenodo.24351103
- Zenodo badge target: https://doi.org/10.5281/zenodo.24351102
- Exact version DOI and release tag: **confirm on the archived record**
- Manuscript DOI: **not provided; do not infer one**
- Release commit, archive checksum, and access date: **record when independently verified**

For a paper's reproducibility statement, prefer the DOI of the exact version used. Verify that the archived ZIP contains the required inputs, scripts, and results; third-party datasets may need separate retrieval.

## References
- [Creative Commons Attribution 4.0](https://creativecommons.org/licenses/by/4.0/)
- [Zenodo GitHub integration](https://help.zenodo.org/docs/github/)
- [GitHub repository documentation](https://docs.github.com/en/repositories)

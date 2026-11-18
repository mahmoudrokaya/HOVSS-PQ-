# HOVSS-PQ — Results Archive

## Scope

This directory is the publication-facing index for experimental results supporting **Section 5** of *Human-Verifiable Visual Secret Sharing through a Modular Framework for Post-Quantum Authentication and Device-Independent Integrity Verification*.

**This package contains documentation and empty result directories only.** The original experiment outputs, plots, tables, and raw measurements have not been provided for incorporation. No numerical results or visualizations have been fabricated. Add verified source artifacts before claiming that this archive reproduces the manuscript.

## Structure

```text
results/
├── README.md
├── tables/       # Supporting datasets and outputs for Tables 2–6
├── figures/      # Source data and generated plots for Figures 6–8
└── summaries/    # Experiment summaries and verification reports
```

## Manuscript table map

| Table | Caption in uploaded manuscript | Experiment linkage |
|---|---|---|
| 2 | Exact confidentiality and forgery results | C01–C03 |
| 3 | Construction feasibility outcomes | C12 |
| 4 | Reconstruction and optical disturbance results | C11 |
| 5 | Adversarial and computational verification results | Confirm exact experiment-to-row mapping |
| 6 | Physical preparation, human verification, and construction-selection outcomes | Confirm exact experiment-to-row mapping |

## Manuscript figure map

| Figure | Caption in uploaded manuscript | Experiment linkage |
|---|---|---|
| 6 | Forgery acceptance probabilities under challenge-dependent and public-mask verification conditions | C06–C09 |
| 7 | Pooled reconstruction pixel error rates under selected simulated optical disturbances | C11 |
| 8 | Synthetic-observer acceptance rates under nine simulated optical and modification conditions | C16 v4 |

The manuscript describes Figure 7 as using **549 image records per condition**. This is a figure-specific record count and should not be silently replaced with the 546-image overall benchmark size. Verify it against the original C11 output.

## Evidence levels and limitations

Keep separate: mathematical or algebraic results; digital computational experiments; simulated optical disturbances; printable prototypes; actual physical measurements; and actual human-observer data. Synthetic-observer decisions are **not** human-participant observations. ML-DSA electronic verification does **not** establish optical content authentication. The manuscript identifies physical and human validation as outstanding; do not create completed-study datasets from planned protocols.

## Required contents for each published result

For every table or figure, archive the underlying source data, the generating script or exact command, verified input paths, configuration, software versions, random seed if used, and a SHA-256 manifest. Prefer paths relative to the repository root. Where outputs are already present in `archives/` or another canonical location, reference them rather than creating duplicate copies.

## Reproduction procedure

1. Locate the relevant experiment in `configs/experiments/` and the corresponding implementation in `code/`.
2. Confirm dataset licenses and input hashes against `metadata/manifest.csv`.
3. Execute the documented experiment in the recorded environment.
4. Regenerate the relevant table or figure from raw outputs.
5. Compare values, sample counts, captions, and visual outputs with the final manuscript.
6. Record discrepancies in `summaries/` without overwriting archived originals.

## Status

**Documentation scaffold only; reproducibility not yet verified.** The table and figure captions above were extracted from the uploaded manuscript `Complete_Revised_Methods(4).docx`. Update this map if the manuscript changes.

# HOVSS-PQ — Experiment Index

## Status and provenance
This index combines **manuscript-supported experiment relationships** with a directory inventory convention. It does not certify that the corresponding scripts, raw results, or per-experiment YAML files have been inspected or executed. The repository uses C01–C16 and F01–F08 identifiers; individual experiment details must be reconciled with the original code and logs.

Status terms: **reported** = described in manuscript; **proposed** = protocol only; **unverified** = source mapping or raw output not checked; **physical pending** = print/measurement evidence not established; **human pending** = no completed human-participant evidence established.

## C-series inventory

| ID | Manuscript-grounded association | Evidence / next action |
|---|---|---|
| C01 | Table 2: exact confidentiality/forgery group | Confirm individual role and files |
| C02 | Table 2: exact confidentiality/forgery group | Confirm individual role and files |
| C03 | Table 2: exact confidentiality/forgery group | Confirm individual role and files |
| C04 | Not uniquely identified from table/figure captions | Inspect original scripts |
| C05 | Not uniquely identified from table/figure captions | Inspect original scripts |
| C06 | Figure 6: challenge/public-mask forgery group | Confirm individual condition |
| C07 | Figure 6: challenge/public-mask forgery group | Confirm individual condition |
| C08 | Figure 6: challenge/public-mask forgery group | Confirm individual condition |
| C09 | Figure 6: challenge/public-mask forgery group | Confirm individual condition |
| C10 | Not uniquely identified from table/figure captions | Inspect original scripts |
| C11 | Table 4 and Figure 7: simulated reconstruction/optical disturbance | Reported; verify records and scripts |
| C12 | Table 3: construction feasibility | Reported; verify records and scripts |
| C13 | Printable share prototypes / physical pilot preparation | Print-ready ≠ physical measurement completed |
| C14 | Prospective human-verification study package | Planned ≠ completed participant study |
| C15 | Not uniquely identified from table/figure captions | Inspect original scripts |
| C16 | Figure 8: nine-condition synthetic-observer benchmark (v4) | Reported synthetic simulation, not human data |

### C16 benchmark (reported, pending raw-output audit)
- Images: **546** (500 BSDS500, 39 USC-SIPI, seven synthetic).
- Conditions: **9**; synthetic observers: **100**; repetitions: **10**.
- Total simulated decisions: **546 × 9 × 100 × 10 = 4,914,000**.
- Reported ROC-AUC: approximately **0.9982**.
- The manuscript's Section 4.1 reports seed **20261116** for the benchmark; verify its exact scope in code.

## F-series inventory

| ID | Contribution described in manuscript | Limitation / evidence boundary |
|---|---|---|
| F01 | Conventional private (2,2) sharing and OR reconstruction | OR masking; known-content reference recovery |
| F02 | Digital parity/syndrome baseline | Public parity can be recomputed |
| F03 | Independent optical audit baseline | Audit can remain valid after content modification |
| F04 | Sparse inspection and exact sampling probabilities | Localized edits can evade sampling |
| F05 | Ideal full-field mismatch benchmark | Requires trusted expected image and digital comparison |
| F06 | Multiplicative optical transmission model | Noise sensitivity; no origin authentication |
| F07 | Registration-aware computational benchmark | Digital alignment, blind regions, external trust |
| F08 | Not documented in the manuscript's F1–F7 comparison | Confirm existence, method, and evidence before claiming results |

The manuscript describes **F1–F7** as the seven computational reference implementations; a repository `F08.yaml` may exist as a template, but its presence does not demonstrate an eighth completed study.

## Publication mapping

| Item | Manuscript caption/topic | Associated studies |
|---|---|---|
| Table 2 | Exact confidentiality and forgery results | C01–C03 |
| Table 3 | Construction feasibility outcomes | C12 |
| Table 4 | Reconstruction and optical disturbance results | C11 |
| Table 5 | Adversarial and computational verification results | Verify detailed mapping |
| Table 6 | Physical preparation, human verification, construction selection | Verify status per row |
| Figure 6 | Forgery acceptance probabilities | C06–C09 |
| Figure 7 | Pooled pixel error under simulated disturbances | C11 |
| Figure 8 | Synthetic-observer acceptance across nine conditions | C16 v4 |

## Required per-experiment audit fields
For every `configs/experiments/{ID}.yaml`, record: source script and checksum; exact CLI invocation; inputs and licenses; preprocessing; random seed and versions; attack model; outputs and hashes; evaluation denominators; manuscript link; and one of `executed`, `reconstructed`, or `proposed` provenance types.

## Related files
- [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md)
- [`DATA_AVAILABILITY.md`](DATA_AVAILABILITY.md)
- [`SECURITY_SCOPE.md`](SECURITY_SCOPE.md)
- `../configs/experiments/`
- `../configs/publication/tables.yaml`
- `../configs/publication/figures.yaml`

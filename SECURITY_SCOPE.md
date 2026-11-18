# HOVSS-PQ — Security Scope, Assumptions, and Claim Boundaries

## Scope
HOVSS-PQ studies whether confidential visual shares, issuer authentication, content integrity, optical reconstruction, and human-oriented verification can be combined into a trustworthy device-independent inspection procedure. It is a **modular research and feasibility framework**, not a demonstrated end-to-end post-quantum optical-authentication protocol.

## Separate security properties

| Property | What must be established | Current evidence boundary |
|---|---|---|
| Unauthorized-share confidentiality | Complete unauthorized view reveals no protected secret under the specified model | Evaluated constructions and distributions only; public references can leak content |
| Reconstruction correctness | Authorized shares reconstruct the intended content | Ideal digital performance does not imply physical robustness |
| Share authenticity | Presented shares originate from authorized issuance | Recognizable OR reconstruction is not sufficient |
| Content integrity | Meaningful unauthorized changes are rejected under a defined policy | Depends on construction, reference trust, and attack model |
| Issuer authentication | Authorized issuer signed a canonical enrollment record | ML-DSA-65 electronic verification only |
| Optical integrity | Issuer authorization is inseparably coupled to the physical optical response | Not demonstrated as an end-to-end guarantee |
| Human verification | Unaided observers reliably distinguish legitimate and forged physical presentations | Synthetic observer data are not human validation |

## Trust boundaries
- **Offline issuer:** signing key and issuance procedure are assumed protected for the baseline model.
- **Enrollment record/reference:** an independently authenticated reference may be used, but its custody and adversary visibility must be stated. A publicly printable pattern is not automatically trusted.
- **Distributed shares:** adversaries may modify, substitute, reproduce, or collude using shares according to the declared attack game.
- **Inspection ceremony:** the intended device-independent procedure uses prescribed physical superposition and unaided observation. Digital signature checks, software registration, and pixelwise XOR comparisons are **outside** this ceremony.
- **Physical environment:** illumination, alignment, substrate, printing, blur, and observer variability can change the visible output.

## Attack classes
The manuscript considers content modification, share substitution, unauthorized collusion, known-content reference recovery, recomputable public parity/audit patterns, adaptive verification attempts, reference manipulation, misregistration, and exact optical copying. An attack outcome is meaningful only with a declared adversary view, protected trust state, modification severity, verification rule, and trial denominator.

## Manuscript-reported observations (not universal proofs)
- Masked-reference construction: total-variation distance **0.0** for the evaluated public-view distributions; **3,072/3,072** content-changing submissions rejected under **exact digital** verification.
- Separable-tag construction: **3,072/3,072** corresponding modifications accepted, illustrating absent effective content binding in the evaluated test.
- Integrated-witness evaluation: **2,031/14,336** tested changes accepted; confirm original trial semantics and raw records.
- Adaptive forgery: reported acceptance **0.500** for one private challenge and **0.750** for two adaptive attempts under the tested challenge model.
- Ideal authorized digital reconstruction: **100% pixel agreement**; one-pixel displacement produced **0.7492** reconstruction pixel error in the reported test.
- ML-DSA-65 enrollment: **15/15 electronic verification checks** passed. This does not prove issuer-to-optical binding.
- C16: **4,914,000 synthetic decisions** and ROC-AUC approximately **0.9982**. This is not a human-participant measurement.

These figures are transcribed from the manuscript context and require raw-result verification before an archival reproducibility claim.

## Mathematical limitations
**Non-injective reconstruction:** Different share configurations can produce the same Boolean-OR reconstruction; recognizing the output does not authenticate the shares.

**Observational equivalence:** If an authorized presentation and an unauthorized presentation produce the same distribution of all observations available to the verifier under the same trusted reference, no static observation-only decision can reliably distinguish them. Exact copying or complete replacement of unprotected trusted objects requires an additional protected property, fresh challenge, or a narrower claim.

**Component composition:** Confidential VSS plus a valid post-quantum digital signature does not automatically produce post-quantum-secure visual authentication. A concrete issuer-to-optical encoding and construction-specific security argument are required.

**Digital/physical separation:** The F1/F5/F6/F7 combination is a computational reference (private sharing, ideal full-field comparison, transmission model, and digitally assisted registration), not a completed human-only authentication scheme.

## Evidence labels and prohibited inferences
Use explicit labels: **mathematically proved**, **digitally simulated**, **instrumented optical simulation**, **physically measured**, **human-participant observed**, or **planned**. Do not promote a result to a stronger evidence class without the corresponding records.

Do **not** claim:
- Universal secrecy from a single zero-TV measurement.
- Universal forgery resistance from finite exact-digital tests.
- Optical authenticity from ML-DSA electronic signature verification.
- Physical performance from simulated printing or digitally registered images.
- Human discrimination from synthetic observers.
- Exact-copy resistance from a static visual pattern alone.

## Required evidence for stronger claims
1. Specify complete canonical issuer binding and a concrete optical encoder, including all protected metadata and reference trust assumptions.
2. Prove or bound unauthorized acceptance under a clearly defined attack game and content-change severity.
3. Measure manufactured optical layers across prespecified physical conditions.
4. Conduct ethically approved human-observer testing, recording false acceptance/rejection, uncertainty, decision time, and repeated-measures dependence.
5. Reproduce numerical results from archived scripts, datasets, parameters, and outputs.

## References
- [NIST FIPS 204: Module-Lattice-Based Digital Signature Standard](https://doi.org/10.6028/NIST.FIPS.204)
- [Naor and Shamir, Visual Cryptography](https://doi.org/10.1007/BFb0053419)
- [NIST Computer Security Resource Center](https://csrc.nist.gov/)

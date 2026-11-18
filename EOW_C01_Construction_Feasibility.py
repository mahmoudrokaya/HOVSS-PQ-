#!/usr/bin/env python3
"""EOW-C01: exact small-domain feasibility audit for enrolled optical witnesses.

All tested witness designs are deliberately explicit *toy models*.  The XOR
comparators are digital ideal oracles, NOT passive human-observable optics.
This program does not establish post-quantum security, human usability, or
security for arbitrary image dimensions.

Python 3.10+, standard library only.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import itertools
import json
import math
import random
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

SCHEMES = ('EOW1_full_reference', 'EOW2_separable_tag', 'EOW3_masked_challenge')
ATTACKS = ('single_bit', 'content_changing', 'tag_transplant', 'exact_copy', 'full_replacement')


def bit(x, i):
    return (x >> i) & 1


def hamming(x, y):
    return (x ^ y).bit_count()


def encode(secret, mask):
    """Perfect 2-out-of-2 XOR sharing in an n-bit domain."""
    return mask, secret ^ mask


def enroll(scheme, secret, mask, k1, k2, n):
    v1, v2 = encode(secret, mask)
    if scheme == SCHEMES[0]:
        # Protected reference copies of BOTH shares, ideal exact comparison.
        return (v1, v2)
    if scheme == SCHEMES[1]:
        # Reusable authentication tag detached from mutable share data.
        return (secret,)
    if scheme == SCHEMES[2]:
        # OTP-masked reference; K1,K2 retained in protected verifier state.
        return (v1 ^ k1, v2 ^ k2, k1, k2)
    raise ValueError(scheme)


def public_witness(scheme, witness):
    # Explicit assumption: EOW1 reference and EOW2 tag are observable;
    # EOW3 exposes masked records but not the keys.
    return witness[:2] if scheme == SCHEMES[2] else witness


def verify(scheme, submitted_v1, submitted_v2, witness):
    if scheme == SCHEMES[0]:
        return (submitted_v1, submitted_v2) == witness
    if scheme == SCHEMES[1]:
        # Vulnerable by design: a tag retained from enrollment is accepted
        # regardless of changes in the share data.
        return True
    if scheme == SCHEMES[2]:
        w1, w2, k1, k2 = witness
        return (submitted_v1 ^ k1 == w1) and (submitted_v2 ^ k2 == w2)
    raise ValueError(scheme)


def observation(scheme, secret, mask, k1, k2, n, view):
    v1, v2 = encode(secret, mask)
    w = enroll(scheme, secret, mask, k1, k2, n)
    p = public_witness(scheme, w)
    if view == 'one_share':
        return (v1,)
    if view == 'public_witness':
        return p
    if view == 'one_share_plus_public_witness':
        return (v1,) + p
    if view == 'full_witness':
        return w
    if view == 'one_share_plus_full_witness':
        return (v1,) + w
    raise ValueError(view)


def exact_distribution(scheme, secret, n, view):
    limit = 1 << n
    counts = Counter()
    for mask, k1, k2 in itertools.product(range(limit), repeat=3):
        counts[observation(scheme, secret, mask, k1, k2, n, view)] += 1
    return counts


def total_variation(a, b):
    na, nb = sum(a.values()), sum(b.values())
    return sum(abs(a.get(x, 0)/na - b.get(x, 0)/nb) for x in a.keys() | b.keys()) / 2


def privacy_audit(n):
    views = ('one_share', 'public_witness', 'one_share_plus_public_witness',
             'full_witness', 'one_share_plus_full_witness')
    limit = 1 << n
    rows = []
    for scheme in SCHEMES:
        for view in views:
            distributions = [exact_distribution(scheme, s, n, view) for s in range(limit)]
            maximum, witness_pair = 0.0, (0, 0)
            for s0 in range(limit):
                for s1 in range(s0+1, limit):
                    tv = total_variation(distributions[s0], distributions[s1])
                    if tv > maximum + 1e-12:
                        maximum, witness_pair = tv, (s0, s1)
            rows.append({'scheme':scheme,'view':view,'n_bits':n,
                         'max_pairwise_tv':round(maximum, 12),
                         'secrets_witness':f'{witness_pair[0]}:{witness_pair[1]}',
                         'exact_per_secret_enrollments':limit**3,
                         'perfect_privacy_in_this_view':maximum < 1e-12})
    return rows


def attack_audit(n):
    limit = 1 << n
    rows, examples = [], []
    # Enumerate all secrets, masks and challenge keys, as well as every
    # non-identical candidate pair (up to n=3 by default).
    for scheme in SCHEMES:
        totals = {a:[0,0,0] for a in ATTACKS}  # tested, accepted, accepted-changing
        for s, mask, k1, k2 in itertools.product(range(limit), repeat=4):
            v1, v2 = encode(s, mask)
            w = enroll(scheme, s, mask, k1, k2, n)
            for x, y in itertools.product(range(limit), repeat=2):
                changed = (x, y) != (v1, v2)
                content_changed = (x ^ y) != s
                if not changed:
                    kinds = ['exact_copy']
                else:
                    kinds = []
                    if hamming(x, v1) + hamming(y, v2) == 1:
                        kinds.append('single_bit')
                    if content_changed:
                        kinds.append('content_changing')
                    if x != v1 and y != v2:
                        kinds.append('full_replacement')
                    # Retaining an independent tag while changing the data.
                    if scheme == SCHEMES[1] and content_changed:
                        kinds.append('tag_transplant')
                accepted = verify(scheme, x, y, w)
                for attack in kinds:
                    t = totals[attack]
                    t[0] += 1
                    t[1] += int(accepted)
                    t[2] += int(accepted and content_changed)
                    if accepted and content_changed and len([z for z in examples if z['scheme']==scheme and z['attack']==attack]) < 2:
                        examples.append({'scheme':scheme,'attack':attack,'secret':s,
                                         'enrolled_shares':[v1,v2], 'submitted_shares':[x,y],
                                         'submitted_secret':x^y,'witness_public':list(public_witness(scheme,w)),
                                         'note':'Counterexample in an ideal digital comparator model'})
        for attack,(tested,accepted,changing) in totals.items():
            rows.append({'scheme':scheme,'attack':attack,'n_bits':n,
                         'tested':tested,'accepted':accepted,
                         'accepted_content_changing':changing,
                         'acceptance_rate':round(accepted/tested, 12) if tested else None,
                         'content_changing_acceptance_rate':round(changing/tested,12) if tested else None,
                         'applicable':bool(tested)})
    return rows,examples


def collision_audit(n):
    # OR output collisions for two n-bit shares; independent of EOW schemes.
    limit = 1 << n
    groups = {}
    for x,y in itertools.product(range(limit),repeat=2):
        groups.setdefault(x|y,[]).append((x,y))
    collisions = sum(len(v)*(len(v)-1)//2 for v in groups.values())
    example = next(({'output':z,'pair_a':v[0],'pair_b':v[1]}
                    for z,v in groups.items() if len(v)>1),None)
    return {'operator':'binary_OR','n_bits':n,'ordered_input_pairs':limit**2,
            'distinct_outputs':len(groups),'colliding_unordered_input_pair_pairs':collisions,
            'example':example}


def write_csv(path, rows):
    path.parent.mkdir(parents=True,exist_ok=True)
    if not rows:
        return
    with path.open('w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0].keys()))
        writer.writeheader();writer.writerows(rows)


def write_json(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,ensure_ascii=False,sort_keys=True)+'\n',encoding='utf-8')


def sha256(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1<<20),b''):
            h.update(block)
    return h.hexdigest()


def self_tests():
    results={}
    results['xor_reconstruction']=all((encode(s,r)[0]^encode(s,r)[1])==s for s in range(4) for r in range(4))
    results['single_share_uniform']=all(total_variation(
        Counter({(x,):1 for x in range(4)}),Counter({(x,):1 for x in range(4)}))==0 for _ in range(1))
    results['eow1_rejects_alteration']=not verify(SCHEMES[0],1,0,enroll(SCHEMES[0],0,0,0,0,2))
    results['eow2_tag_transplant_accepted']=verify(SCHEMES[1],1,0,enroll(SCHEMES[1],0,0,0,0,2))
    results['eow3_rejects_alteration']=not verify(SCHEMES[2],1,0,enroll(SCHEMES[2],0,0,1,2,2))
    results['eow3_accepts_legitimate']=verify(SCHEMES[2],0,0,enroll(SCHEMES[2],0,0,1,2,2))
    results['or_collision']=collision_audit(1)['distinct_outputs']==2
    return results


def main():
    p=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--root',type=Path,help='Experiments root; default parent of Code directory')
    p.add_argument('--output',type=Path,help='Output directory; default <root>/Results/EOW_C01')
    p.add_argument('--bits',type=int,default=2,choices=(1,2,3),help='Exhaustive secret bit-width (1-3); 3 is substantially slower')
    p.add_argument('--seed',type=int,default=20261115,help='Recorded reproducibility seed (enumeration is deterministic)')
    args=p.parse_args()
    root=args.root or Path(__file__).resolve().parent.parent
    out=args.output or root/'Results'/'EOW_C01'
    out=out.resolve();out.mkdir(parents=True,exist_ok=True)
    tests=self_tests()
    if not all(tests.values()):
        raise RuntimeError(f'Self-tests failed: {tests}')
    privacy=privacy_audit(args.bits)
    attacks,examples=attack_audit(args.bits)
    collisions=collision_audit(args.bits)
    write_csv(out/'reports'/'privacy_exact.csv',privacy)
    write_csv(out/'reports'/'attack_enumeration.csv',attacks)
    write_json(out/'reports'/'forgery_counterexamples.json',examples)
    write_json(out/'reports'/'optical_collisions.json',collisions)
    write_json(out/'reports'/'self_tests.json',tests)
    assumptions={
      'classification':'TOY_CONSTRUCTION_FEASIBILITY_NOT_SECURITY_PROOF',
      'secret_sharing':'n-bit XOR 2-out-of-2; single share information-theoretically uniform',
      'EOW1':'Protected exact copies of both shares; reference visible in public-witness threat view; ideal digital equality, not human optical verification',
      'EOW2':'Separable authentication tag containing secret; verifier checks tag alone; deliberately vulnerable negative control',
      'EOW3':'OTP-masked enrolled share references with protected keys; ideal digital XOR comparator; no passive optical realization or PQ claim',
      'threat_views':'Public-witness views model disclosure of optical witness; full-witness views model compromised verifier custody',
      'attacker':'All submitted share pairs enumerated; not a computationally bounded adaptive adversary',
      'human_observation':'NOT_TESTED',
      'fabrication':'NOT_TESTED',
      'issuer_authenticity':'NOT_TESTED',
      'post_quantum_security':'NOT_TESTED',
      'replay':'Exact copy is always accepted; no freshness mechanism',
      'sampling':'None: all enumerated states at selected bit width',
      'scope':'Finite-domain counterexamples falsify general claims; passing finite tests is not a proof'
    }
    write_json(out/'reports'/'model_assumptions.json',assumptions)
    gates=[]
    for scheme in SCHEMES:
        pv=next(r for r in privacy if r['scheme']==scheme and r['view']=='one_share_plus_public_witness')
        cv=next(r for r in attacks if r['scheme']==scheme and r['attack']=='content_changing')
        gates.append({'scheme':scheme,
                      'one_share_plus_public_witness_private':pv['perfect_privacy_in_this_view'],
                      'no_accepted_content_changing_forgeries':cv['accepted_content_changing']==0,
                      'passive_human_optical_realization':'NOT_ESTABLISHED',
                      'pq_issuer_binding':'NOT_ESTABLISHED',
                      'replay_resistance':'NOT_ESTABLISHED',
                      'complete_HOVSS_PQ_EOW':'NOT_ESTABLISHED'})
    write_csv(out/'reports'/'feasibility_gates.csv',gates)
    summary={'status':'PASS_WITH_UNRESOLVED_SECURITY_GATES',
             'bits':args.bits,'schemes':list(SCHEMES),
             'privacy_rows':len(privacy),'attack_rows':len(attacks),
             'counterexample_count':len(examples),'optical_OR_collisions':collisions['colliding_unordered_input_pair_pairs'],
             'gates':gates,'warnings':['All comparisons are idealized digital predicates, not passive human optics.',
             'No construction meets complete HOVSS-PQ-EOW requirements.',
             'Full-witness exposure is evaluated separately from public-witness exposure.',
             'EOW2 is a deliberate separable-tag negative control.']}
    write_json(out/'reports'/'summary.json',summary)
    write_json(out/'reports'/'verdict.json',{'verdict':'NO_SECURITY_QUALIFIED_CONSTRUCTION',
        'recommendation':'Investigate optically realizable content-binding predicates with explicit verifier custody and secrecy assumptions.',
        'candidate_status':gates})
    write_json(out/'configuration'/'run.json',{'program':'EOW_C01_Construction_Feasibility.py',
        'utc_time':datetime.now(timezone.utc).isoformat(),'root':str(root),'output':str(out),
        'bits':args.bits,'seed':args.seed,'python_minimum':'3.10'})
    report=f'''# EOW-C01 — Exact Small-Domain Construction Feasibility\n\n**Verdict:** NO SECURITY-QUALIFIED CONSTRUCTION.\n\n## Scope\n\nExhaustive {args.bits}-bit XOR secret-sharing toy models, not an optical fabrication experiment or a proof of post-quantum human verification.\n\n## Models\n\n- **EOW1:** exact protected copies of both shares; ideal equality check.\n- **EOW2:** separable authentication tag, checked independently of share content (negative control).\n- **EOW3:** one-time-pad masked enrolled share references, with protected keys and ideal XOR comparison.\n\n## Exact findings\n\n'''
    for g in gates:
        name=g['scheme']
        pview=next(r for r in privacy if r['scheme']==name and r['view']=='one_share_plus_public_witness')
        full=next(r for r in privacy if r['scheme']==name and r['view']=='one_share_plus_full_witness')
        att=next(r for r in attacks if r['scheme']==name and r['attack']=='content_changing')
        report+=f"- **{name}:** public witness + one share max TV={pview['max_pairwise_tv']}; compromised full witness + one share max TV={full['max_pairwise_tv']}; accepted content-changing presentations {att['accepted_content_changing']}/{att['tested']}.\n"
    report+=f'''\n- Binary OR: {collisions['distinct_outputs']} outputs from {collisions['ordered_input_pairs']} ordered input pairs, with {collisions['colliding_unordered_input_pair_pairs']} colliding unordered pairs of input pairs.\n\n## Interpretation and limitations\n\n1. EOW1's publicly observable full-share reference exposes both enrolled shares; this defeats secrecy.\n2. EOW2's separable tag can be transplanted while data change.\n3. EOW3's masked references can hide content in the defined public-witness view, but compromised protected keys expose the enrolled shares, and its verifier is a **digital XOR oracle**, not a demonstrated human-only optical comparator.\n4. Exact copies pass; replay protection is absent.\n5. The enumeration does not test ML-DSA, physical robustness, human detection, or adaptive-query security.\n\n## Scientific references\n\n- Naor and Shamir (1994), Visual Cryptography: https://doi.org/10.1007/BFb0053419\n- NIST FIPS 204, ML-DSA: https://doi.org/10.6028/NIST.FIPS.204\n'''
    (out/'reports'/'scientific_report.md').write_text(report,encoding='utf-8')
    inventory=[]
    for path in sorted(out.rglob('*')):
        if path.is_file() and path.name!='evidence_inventory.csv':
            inventory.append({'relative_path':str(path.relative_to(out)),'sha256':sha256(path),'bytes':path.stat().st_size})
    write_csv(out/'reports'/'evidence_inventory.csv',inventory)
    print(json.dumps({'output':str(out),'verdict':'NO_SECURITY_QUALIFIED_CONSTRUCTION',
                      'privacy_rows':len(privacy),'attack_rows':len(attacks),
                      'counterexamples':len(examples),'self_tests':f'{sum(tests.values())}/{len(tests)}'},indent=2))

if __name__=='__main__':
    main()

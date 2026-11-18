#!/usr/bin/env python3
"""EOW_C04: exhaustive *ideal passive-OR* full-share witness audit.

This is a falsification-oriented computational model, not a secure optical
construction, physical measurement, human study, or post-quantum signature test.
Python >=3.10; standard library only.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import itertools
import json
import sys
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

SOURCES = {
    'Naor_Shamir': 'https://doi.org/10.1007/BFb0053419',
    'NIST_FIPS_204': 'https://doi.org/10.6028/NIST.FIPS.204',
}
MODELS = ('witness_A', 'witness_not_A', 'witness_B', 'witness_not_B', 'witness_all_clear')
OBSERVERS = ('exact_subpixels', 'per_pixel_black_count')


def save_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def save_csv(path, rows, fields):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def bit(x, i):
    return (x >> i) & 1


def bits(x, n):
    return ''.join(str(bit(x, i)) for i in range(n))


def complement(x, n):
    return x ^ ((1 << n) - 1)


def encode(secret, pad, n):
    """Classic (2,2) VSS: each pixel expands to two subpixels.

    A_i is 10 or 01; B_i=A_i for white and its complement for black.
    Both marginal share distributions are secret-independent.
    """
    a = b = 0
    for i in range(n):
        a_bit = bit(pad, i)
        for j in range(2):
            v = 1 if j == a_bit else 0
            a |= v << (2 * i + j)
            b |= (v ^ bit(secret, i)) << (2 * i + j)
    return a, b


def witness(model, a, b, width):
    if model == 'witness_A':
        return a
    if model == 'witness_not_A':
        return complement(a, width)
    if model == 'witness_B':
        return b
    if model == 'witness_not_B':
        return complement(b, width)
    if model == 'witness_all_clear':
        return 0
    raise ValueError(model)


def black_counts(stack, n):
    return tuple(bit(stack, 2*i) + bit(stack, 2*i+1) for i in range(n))


def observe(stack, n, observer):
    return stack if observer == 'exact_subpixels' else black_counts(stack, n)


def visible_content(a, b, n):
    """Classify OR stack as black iff both subpixels are black.

    Off-codeword stacks are deliberately assigned this fixed threshold; the
    threshold is a modeling choice, NOT a measured human decision rule.
    """
    counts = black_counts(a | b, n)
    return sum((int(count == 2) << i) for i, count in enumerate(counts))


def total_variation(p, q):
    return 0.5 * sum(abs(p.get(k, 0) - q.get(k, 0)) for k in set(p) | set(q))


def distribution_view(n, model, secret, view):
    """Uniform enrollment pad; no private witness mask exists in C04."""
    out = Counter()
    for pad in range(1 << n):
        a, b = encode(secret, pad, n)
        w = witness(model, a, b, 2*n)
        if view == 'share_A':
            key = (a,)
        elif view == 'share_B':
            key = (b,)
        elif view == 'witness_only':
            key = (w,)
        elif view == 'share_A_and_witness':
            key = (a, w)
        elif view == 'share_B_and_witness':
            key = (b, w)
        else:
            raise ValueError(view)
        out[key] += 1
    denom = 1 << n
    return {key: val/denom for key, val in out.items()}


def privacy_audit(n):
    views = ('share_A', 'share_B', 'witness_only', 'share_A_and_witness', 'share_B_and_witness')
    rows = []
    for model in MODELS:
        for view in views:
            distributions = [distribution_view(n, model, s, view) for s in range(1 << n)]
            max_tv, pair = 0.0, (0, 0)
            for s0 in range(1 << n):
                for s1 in range(s0 + 1, 1 << n):
                    tv = total_variation(distributions[s0], distributions[s1])
                    if tv > max_tv:
                        max_tv, pair = tv, (s0, s1)
            rows.append({'model':model, 'view':view, 'max_tv':max_tv,
                         'example_secret_0':pair[0], 'example_secret_1':pair[1],
                         'perfect_privacy_in_this_view':max_tv == 0})
    return rows


def shift_right_zero(x, width, steps=1):
    return (x << steps) & ((1 << width) - 1)


def attack_audit(n):
    """Enumerate every B' for every enrolled (secret,pad), keeping A and W fixed.

    Counts are exhaustive enumeration frequencies, NOT probabilistic success
    against a randomized adversary. Reports both OR-visible changes and
    underlying XOR-data changes to avoid equating those notions.
    """
    width = 2*n
    all_b = range(1 << width)
    rows, examples = [], []
    for model in MODELS:
        for observer in OBSERVERS:
            counts = Counter()
            exemplar = None
            for secret in range(1 << n):
                for pad in range(1 << n):
                    a, b = encode(secret, pad, n)
                    w = witness(model, a, b, width)
                    expected = observe(b | w, n, observer)
                    baseline_visible = visible_content(a, b, n)
                    for bp in all_b:
                        if bp == b:
                            continue
                        counts['modified'] += 1
                        accepted = observe(bp | w, n, observer) == expected
                        visible_changed = visible_content(a, bp, n) != baseline_visible
                        xor_changed = (a ^ bp) != (a ^ b)
                        valid_share = all(black_counts(bp, n)[i] == 1 for i in range(n))
                        if accepted:
                            counts['accepted_modified'] += 1
                        if visible_changed:
                            counts['visible_content_changed'] += 1
                        if accepted and visible_changed:
                            counts['accepted_visible_content_changed'] += 1
                            if exemplar is None:
                                exemplar = {'model':model,'observer':observer,'secret':bits(secret,n),
                                            'share_A':bits(a,width),'share_B':bits(b,width),
                                            'witness':bits(w,width),'forged_B':bits(bp,width),
                                            'original_visible':bits(baseline_visible,n),
                                            'forged_visible':bits(visible_content(a,bp,n),n),
                                            'valid_one_black_per_pixel':valid_share,
                                            'original_witness_stack':bits(b|w,width),
                                            'forged_witness_stack':bits(bp|w,width)}
                        if accepted and xor_changed:
                            counts['accepted_xor_data_changed'] += 1
                        if valid_share:
                            counts['valid_codeword_modifications'] += 1
                            if accepted and visible_changed:
                                counts['accepted_visible_change_valid_codeword'] += 1
                        if (bp | w) == (b | w):
                            counts['exact_or_collision'] += 1
            row = {'model':model, 'observer':observer, 'bits':n,
                   'enrollments':(1 << (2*n)), **dict(counts)}
            for key in ('modified','accepted_modified','visible_content_changed',
                        'accepted_visible_content_changed','accepted_xor_data_changed',
                        'valid_codeword_modifications','accepted_visible_change_valid_codeword',
                        'exact_or_collision'):
                row.setdefault(key, 0)
            row['accepted_visible_change_fraction_of_modified'] = (
                row['accepted_visible_content_changed']/row['modified'] if row['modified'] else 0)
            row['accepted_visible_change_fraction_of_visible_changes'] = (
                row['accepted_visible_content_changed']/row['visible_content_changed']
                if row['visible_content_changed'] else 0)
            rows.append(row)
            if exemplar:
                examples.append(exemplar)
    return rows, examples


def legitimate_stress(n):
    """Deterministic one-subpixel shift and single-black-subpixel dropout.

    These are logical perturbations, NOT physically calibrated millimeters,
    noise, human perception, or fabrication measurements.
    """
    rows = []
    width = 2*n
    for model in MODELS:
        for observer in OBSERVERS:
            for perturbation in ('unaltered', 'shift_one_subpixel_zero_fill', 'drop_one_black_subpixel'):
                total = rejected = 0
                for secret in range(1 << n):
                    for pad in range(1 << n):
                        a,b = encode(secret,pad,n)
                        w = witness(model,a,b,width)
                        expected = observe(b|w,n,observer)
                        if perturbation == 'unaltered':
                            candidates = [b]
                        elif perturbation == 'shift_one_subpixel_zero_fill':
                            candidates = [shift_right_zero(b,width)]
                        else:
                            candidates = [b & ~(1 << j) for j in range(width) if bit(b,j)]
                        for bp in candidates:
                            total += 1
                            rejected += observe(bp|w,n,observer) != expected
                rows.append({'model':model,'observer':observer,'perturbation':perturbation,
                             'trials':total,'rejected':rejected,'rejection_fraction':rejected/total})
    return rows


def c03_audit(source):
    if not source:
        return {'status':'NOT_PROVIDED'}
    path = Path(source)
    if not path.exists():
        return {'status':'MISSING','path':str(path)}
    if path.is_file() and path.suffix.lower() == '.zip':
        with zipfile.ZipFile(path) as z:
            candidates = [x for x in z.namelist() if x.endswith('/reports/verdict.json')]
            if not candidates:
                return {'status':'INVALID_NO_VERDICT','path':str(path)}
            verdict = json.loads(z.read(candidates[0]))
        digest = sha256(path.read_bytes())
        return {'status':'LOADED_ZIP','path':str(path),'sha256':digest,'upstream_verdict':verdict}
    candidates = list(path.rglob('reports/verdict.json'))
    if not candidates:
        return {'status':'INVALID_NO_VERDICT','path':str(path)}
    verdict = json.loads(candidates[0].read_text(encoding='utf-8'))
    return {'status':'LOADED_DIRECTORY','path':str(path),
            'sha256_verdict':sha256(candidates[0].read_bytes()),'upstream_verdict':verdict}


def self_tests():
    tests = []
    def check(name, cond):
        tests.append({'test':name,'passed':bool(cond)})
    for s in range(2):
        for pad in range(2):
            a,b=encode(s,pad,1)
            check(f'VSS_reconstruction_s{s}_pad{pad}', visible_content(a,b,1)==s)
    check('single_share_A_distribution', distribution_view(1,'witness_A',0,'share_A') == distribution_view(1,'witness_A',1,'share_A'))
    check('single_share_B_distribution', distribution_view(1,'witness_A',0,'share_B') == distribution_view(1,'witness_A',1,'share_B'))
    check('OR_collision', (2|0)==(2|2))
    check('complement_mask', complement(0b01,2)==0b10)
    check('optical_observer_distinction', observe(0b01,1,'exact_subpixels') != observe(0b10,1,'exact_subpixels') and observe(0b01,1,'per_pixel_black_count') == observe(0b10,1,'per_pixel_black_count'))
    check('witness_B_public_no_extra_privacy_loss', total_variation(distribution_view(1,'witness_B',0,'share_B_and_witness'), distribution_view(1,'witness_B',1,'share_B_and_witness'))==0)
    return tests


def main():
    p=argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument('--bits',type=int,default=2,help='Number of secret pixels (1..4)')
    p.add_argument('--root',type=Path,help='Experiments root; default inferred from Code/ location')
    p.add_argument('--output',type=Path,help='Output directory')
    p.add_argument('--c03',type=Path,help='Prior C03 results directory or ZIP')
    p.add_argument('--strict-c03',action='store_true',help='Require readable C03 verdict')
    args=p.parse_args()
    if not 1 <= args.bits <= 4:
        p.error('--bits must be between 1 and 4 (exhaustive search)')
    root=args.root or Path(__file__).resolve().parent.parent
    out=args.output or root/'Results'/'EOW_C04'
    source=args.c03 or (root/'Results'/'EOW_C03')
    upstream=c03_audit(source)
    if args.strict_c03 and not upstream['status'].startswith('LOADED'):
        p.error('C03 source not readable: '+upstream['status'])
    tests=self_tests()
    if not all(t['passed'] for t in tests):
        raise RuntimeError('Internal self-test failed')
    privacy=privacy_audit(args.bits)
    attacks, examples=attack_audit(args.bits)
    stress=legitimate_stress(args.bits)
    gates=[]
    for model in MODELS:
        pub=[r for r in privacy if r['model']==model and r['view']=='share_B_and_witness'][0]
        attack=[r for r in attacks if r['model']==model and r['observer']=='exact_subpixels'][0]
        gates.extend([
            {'model':model,'gate':'share_B_plus_accessible_witness_privacy',
             'status':'PASS_TOY' if pub['max_tv']==0 else 'FAIL_TOY',
             'evidence':f"max_tv={pub['max_tv']}"},
            {'model':model,'gate':'content_changing_OR_forgery',
             'status':'PASS_ENUMERATED' if attack['accepted_visible_content_changed']==0 else 'FAIL_ENUMERATED',
             'evidence':f"accepted={attack['accepted_visible_content_changed']}; tested={attack['modified']}"},
            {'model':model,'gate':'human_optical_verification','status':'NOT_TESTED',
             'evidence':'Optical OR is simulated; exact subpixel observer is an oracle'},
            {'model':model,'gate':'post_quantum_issuer_binding','status':'NOT_TESTED',
             'evidence':'No signing, trusted enrollment, or physical signature verification'},
            {'model':model,'gate':'replay_resistance','status':'FAIL_STATIC_MODEL',
             'evidence':'Exact copied B reproduces identical OR witness observation'},
        ])
    verdict={'execution':'PASS','security':'NO_SECURITY_QUALIFIED_CONSTRUCTION',
             'human_validation':'NOT_PERFORMED','physical_validation':'NOT_PERFORMED',
             'pq_authentication':'NOT_PERFORMED',
             'interpretation':'Ideal OR comparison is not a demonstrated unaided human authentication mechanism.'}
    assumptions={
        'encoding':'Classic 2-of-2 Naor-Shamir, two subpixels per secret pixel; uniform independent pad',
        'optical_operator':'Ideal opaque black=1 OR stacking, perfect alignment, binary transparency',
        'observation_exact':'Exact bitwise OR stack, requires superhuman/digital subpixel discrimination',
        'observation_coarse':'Black subpixel count per expanded pixel, idealized count not measured human perception',
        'reconstruction':'OR(A,B) black iff two black subpixels in each expanded pixel',
        'adversary':'Keeps enrolled A and W fixed, enumerates all replacements B prime including invalid codewords',
        'privacy':'Exact distributions over all secret values and uniform pad; witness exposure is view-dependent',
        'stress':'One subpixel shift or dropout are logical perturbations, not calibrated physical disturbances',
        'critical_limitation':'Same optical response as reconstruction does not imply issuer authentication; OR masking can hide changed share bits',
        'no_human_or_pq_claim':True,
    }
    run={'script':'EOW_C04_Full_Share_Witness.py','utc':datetime.now(timezone.utc).isoformat(),
         'python':sys.version.split()[0],'bits':args.bits,'root':str(root),'output':str(out),
         'upstream_status':upstream['status'],'sources':SOURCES}
    save_json(out/'configuration'/'run.json',run)
    save_json(out/'reports'/'c03_source_audit.json',upstream)
    save_json(out/'reports'/'model_assumptions.json',assumptions)
    save_json(out/'reports'/'self_tests.json',{'passed':sum(x['passed'] for x in tests),'total':len(tests),'tests':tests})
    save_csv(out/'reports'/'privacy_exact.csv',privacy,list(privacy[0]))
    save_csv(out/'reports'/'attack_enumeration.csv',attacks,list(attacks[0]))
    save_csv(out/'reports'/'legitimate_perturbations.csv',stress,list(stress[0]))
    save_csv(out/'reports'/'feasibility_gates.csv',gates,list(gates[0]))
    save_json(out/'reports'/'content_changing_counterexamples.json',examples)
    save_json(out/'reports'/'verdict.json',verdict)
    summary={'bits':args.bits,'enrolled_instances':1 << (2*args.bits),
             'tested_modified_B_per_model':(1 << (2*args.bits))*( (1 << (2*args.bits))-1),
             'self_tests_passed':len(tests),'privacy_rows':len(privacy),
             'attack_rows':len(attacks),'stress_rows':len(stress),'gate_rows':len(gates),
             'counterexample_count':len(examples),'verdict':verdict['security']}
    save_json(out/'reports'/'summary.json',summary)
    md=['# EOW_C04 — Full-Share Witness: Falsification-Oriented Audit','',
        '## Scope','',
        'This is an exhaustive **toy-model simulation** of two-subpixel Naor–Shamir VSS,',
        'a full-share witness and binary OR stacking. It is not a physical or human experiment.','',
        'A protected enrolled witness may still leak the secret if compromised or made public.','',
        '## Security interpretation','',
        '* A fixed reference does not by itself establish issuer authenticity.',
        '* Exact optical equality is an ideal computational observer, not a demonstrated human capability.',
        '* OR stacking is many-to-one; the report distinguishes underlying share/XOR changes from visibly reconstructed OR-content changes.',
        '* An exact copy is accepted by all static comparators.',
        '* Privacy views explicitly include the witness, since an enrolled artifact can leak information.',
        '* Logical shift/dropout stress is not physically calibrated.', '',
        '## Exhaustive results','',
        '| Witness | Observer | Accepted visible-content changes | Modified candidates |','|---|---|---:|---:|']
    for row in attacks:
        md.append(f"| {row['model']} | {row['observer']} | {row['accepted_visible_content_changed']} | {row['modified']} |")
    md += ['', '## Public-witness leakage with B','',
           '| Witness | Maximum TV |','|---|---:|']
    for row in privacy:
        if row['view']=='share_B_and_witness':
            md.append(f"| {row['model']} | {row['max_tv']:.3f} |")
    md += ['', '## Decision','',
           '**NO_SECURITY_QUALIFIED_CONSTRUCTION.** Passing an idealized OR integrity test is insufficient to claim human-verifiable issuer authenticity or post-quantum optical security.','',
           '## References','',
           f"- Naor and Shamir: {SOURCES['Naor_Shamir']}",
           f"- NIST FIPS 204: {SOURCES['NIST_FIPS_204']}",'']
    (out/'reports'/'scientific_report.md').write_text('\n'.join(md),encoding='utf-8')
    print(json.dumps({'output':str(out),'summary':summary},indent=2))

if __name__=='__main__':
    main()

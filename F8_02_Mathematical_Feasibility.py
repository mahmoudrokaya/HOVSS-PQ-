#!/usr/bin/env python3
"""F8_02: exact finite-domain mathematical feasibility and optical-equivalence audit.

Standalone, standard-library-only, read-only with respect to prior experiment outputs.
This is an audit of the *classical* (2,2) Naor--Shamir 2-subpixel basis,
not a proof or implementation of HOVSS-PQ optical origin authentication.

Use --help for controls.  Outputs are written under Results/F8_02.
"""
from __future__ import annotations
import argparse
import collections
import csv
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import platform
import random
import sys
import time
from datetime import datetime, timezone

VERSION = '1.0.0'
# Each row has one black and one white subpixel. Column permutation randomizes shares.
# For m=0 the rows agree; for m=1 they are complementary.
BASIS = {0: ((1, 0), (1, 0)), 1: ((1, 0), (0, 1))}


def bit_or(a, b):
    return tuple(x | y for x, y in zip(a, b))


def bit_xor(a, b):
    return tuple(x ^ y for x, y in zip(a, b))


def hamming(a, b):
    return sum(x != y for x, y in zip(a, b))


def codewords(m):
    """Exactly two equally likely random column permutations per pixel."""
    a, b = BASIS[m]
    return ((a, b), (a[::-1], b[::-1]))


def encode(bits, coins):
    a, b = [], []
    for m, c in zip(bits, coins):
        x, y = codewords(m)[c]
        a.extend(x)
        b.extend(y)
    return tuple(a), tuple(b)


def reconstruct(shares):
    return bit_or(*shares)


def all_bits(n):
    return itertools.product((0, 1), repeat=n)


def exact_privacy(n):
    """Exact distributions for either single share, for every secret of n pixels."""
    base = None
    compared = 0
    max_tv = 0.0
    for secret in all_bits(n):
        dist = (collections.Counter(), collections.Counter())
        for coins in all_bits(n):
            s1, s2 = encode(secret, coins)
            dist[0][s1] += 1
            dist[1][s2] += 1
        if base is None:
            base = dist
        for j in (0, 1):
            a, b = base[j], dist[j]
            total = 2**n
            tv = sum(abs(a.get(k, 0) - b.get(k, 0)) for k in a.keys() | b.keys()) / (2 * total)
            max_tv = max(max_tv, tv)
            compared += 1
    return {'secret_pixels': n, 'secret_patterns': 2**n,
            'coin_vectors_per_secret': 2**n, 'single_share_views_tested': compared,
            'max_exact_total_variation': max_tv, 'pass': max_tv == 0,
            'scope': 'F1 (2,2) basis, one unauthorized share; reference not included'}


def full_audit(n, max_witnesses, seed):
    """Exhaust all 2^n secrets and 2^n issuance coin vectors.

    For each authentic share pair, flip each one of its 4n subpixels, and
    enumerate every possible *one-pixel two-subpixel replacement* in each share.
    The latter is a complete local alphabet search, not a full-share search.
    """
    counters = collections.Counter()
    witnesses = []
    per_secret = []
    rng = random.Random(seed)
    for secret in all_bits(n):
        sc = collections.Counter()
        for coins in all_bits(n):
            s1, s2 = encode(secret, coins)
            actual = reconstruct((s1, s2))
            expected = tuple(v for bit in secret for v in (1, 1) if bit)  # not used
            # Legitimate OR contrast: white secret -> 1 black/2; black -> 2 black/2.
            assert all(sum(actual[2*i:2*i+2]) == (2 if m else 1)
                       for i, m in enumerate(secret))
            counters['authentic_issuances'] += 1
            sc['authentic_issuances'] += 1
            for share_index in (0, 1):
                source = (s1, s2)[share_index]
                other = (s2, s1)[share_index]
                for bit_index in range(2*n):
                    tampered = list(source)
                    tampered[bit_index] ^= 1
                    forged = reconstruct((tuple(tampered), other))
                    masked = forged == actual
                    counters['single_subpixel_attacks'] += 1
                    sc['single_subpixel_attacks'] += 1
                    if masked:
                        counters['single_subpixel_masked'] += 1
                        sc['single_subpixel_masked'] += 1
                        if len(witnesses) < max_witnesses:
                            witnesses.append({'type': 'single_subpixel_masked',
                                'secret': ''.join(map(str, secret)), 'coins': ''.join(map(str, coins)),
                                'share_index': share_index, 'bit_index': bit_index,
                                'original_shares': [list(s1), list(s2)],
                                'modified_share': tampered,
                                'original_observation': list(actual),
                                'forged_observation': list(forged)})
                # Enumerate all local 2-bit replacements except unchanged pattern.
                for pixel in range(n):
                    start = 2*pixel
                    for replacement in all_bits(2):
                        if tuple(source[start:start+2]) == replacement:
                            continue
                        tampered = list(source)
                        tampered[start:start+2] = replacement
                        forged = reconstruct((tuple(tampered), other))
                        counters['local_replacement_attacks'] += 1
                        sc['local_replacement_attacks'] += 1
                        if forged == actual:
                            counters['local_replacement_masked'] += 1
                            sc['local_replacement_masked'] += 1
            # Known secret + one share determines other share for this basis.
            recovered = []
            for i, m in enumerate(secret):
                original = s1[2*i:2*i+2]
                recovered.extend(original if m == 0 else tuple(1-x for x in original))
            counters['known_content_recovery_trials'] += 1
            if tuple(recovered) == s2:
                counters['known_content_recovery_success'] += 1
            else:
                raise AssertionError('Known-content recovery property violated')
            # Full substitution: a freshly sampled independent valid pair for same public target.
            # Such a pair has the same ideal *reconstructed content class*, but not
            # necessarily the same subpixel OR bitmap. We distinguish both cases.
            other_coins = tuple(1-x for x in coins)
            r1, r2 = encode(secret, other_coins)
            replacement = reconstruct((r1, r2))
            counters['full_pair_replacements'] += 1
            if replacement == actual:
                counters['full_pair_exact_or_collisions'] += 1
            if all(sum(replacement[2*i:2*i+2]) == sum(actual[2*i:2*i+2]) for i in range(n)):
                counters['full_pair_same_decoded_secret'] += 1
        per_secret.append({'secret': ''.join(map(str, secret)), **dict(sc)})
    d = dict(counters)
    d['single_subpixel_mask_rate'] = d['single_subpixel_masked'] / d['single_subpixel_attacks']
    d['local_replacement_mask_rate'] = d['local_replacement_masked'] / d['local_replacement_attacks']
    d['full_pair_exact_or_collision_rate'] = d['full_pair_exact_or_collisions'] / d['full_pair_replacements']
    d['full_pair_same_decoded_secret_rate'] = d['full_pair_same_decoded_secret'] / d['full_pair_replacements']
    return d, witnesses, per_secret


def operator_collision_audit():
    """Exhaust all 16 two-layer binary patterns of width 2 for OR, XOR, product."""
    outputs = {}
    for op, fn in [('OR', bit_or), ('XOR_IDEAL_DIGITAL', bit_xor),
                   ('MULTIPLICATIVE_BINARY_TRANSMISSION', lambda a,b: tuple(x*y for x,y in zip(a,b)))]:
        groups = collections.defaultdict(list)
        for a in all_bits(2):
            for b in all_bits(2):
                groups[fn(a,b)].append((a,b))
        collision_pairs = sum(len(v)*(len(v)-1)//2 for v in groups.values())
        outputs[op] = {'input_pairs': 16, 'distinct_outputs': len(groups),
                       'colliding_unordered_pairs': collision_pairs,
                       'max_equivalence_class_size': max(map(len,groups.values())),
                       'injective': collision_pairs == 0,
                       'model_status': ('DIGITAL_ONLY' if op.startswith('XOR') else
                                        'IDEAL_BINARY_OPTICAL_SURROGATE')}
    return outputs


def two_three_screen():
    """Tests an explicit *naive* (2,3) proposal, not arbitrary (2,3) schemes.

    Naive proposal: issue independent (2,2) shares to (1,2), (1,3), (2,3)
    for the same secret; each participant holds the two incident shares.
    Any single participant then sees one share of two independent pairs.
    Every authorized pair can reconstruct at least one pair, but this has
    2 pair-shares per participant and no cryptographic issuer authentication.
    """
    edges = [(0,1),(0,2),(1,2)]
    for secret in (0,1):
        for coins in all_bits(3):
            edge_shares = {e:codewords(secret)[coin] for e,coin in zip(edges,coins)}
            for participant in range(3):
                view = tuple(edge_shares[e][0 if e[0]==participant else 1]
                             for e in edges if participant in e)
                # exactly 2 individual (1,0)/(0,1) masks
                assert all(sum(v)==1 for v in view)
            for pair in edges:
                a,b = edge_shares[pair]
                assert sum(bit_or(a,b)) == (2 if secret else 1)
    return {'construction':'independent pairwise (2,2) replication for 3 participants',
            'scope':'1 secret pixel; 3 independent pair coins; 2 local masks per participant',
            'all_authorized_pairs_reconstruct':True,
            'single_participant_privacy':'holds by independent uniform pair masks',
            'pixel_expansion_per_participant':4,
            'issuer_authentication':'NOT_PROVIDED',
            'general_2_of_3_basis_proof':'NOT_CLAIMED',
            'limitation':'Each authorized pair must identify its common edge; no origin binding'}


def find_root(cli_root):
    if cli_root:
        return Path(cli_root).expanduser().resolve()
    # Script normally lives under Experiments/Code.
    here = Path(__file__).resolve().parent
    if here.name.lower() == 'code':
        return here.parent
    return here


def write_json(p, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, ensure_ascii=False, default=str) + '\n', encoding='utf-8')


def write_csv(p, rows):
    p.parent.mkdir(parents=True, exist_ok=True)
    rows = list(rows)
    if not rows:
        return
    keys = list(dict.fromkeys(k for r in rows for k in r))
    with p.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--root', default=None, help='Experiments root (default: parent of Code directory)')
    ap.add_argument('--output', default=None, help='Output folder (default: Results/F8_02)')
    ap.add_argument('--max-secret-pixels', type=int, default=4, help='Exact (2,2) secret length 1..N; max 10')
    ap.add_argument('--max-witnesses', type=int, default=30)
    ap.add_argument('--seed', type=int, default=20261114)
    ap.add_argument('--strict-data', action='store_true', help='Require F8_01 passed and 546 images')
    ap.add_argument('--side', type=int, default=128, help='Compatibility metadata only; no image processing')
    ap.add_argument('--trials', type=int, default=30, help='Compatibility metadata only; exact audit is deterministic')
    ap.add_argument('--image-limit', type=int, default=0, help='Compatibility metadata only; no image processing')
    args = ap.parse_args(argv)
    if not 1 <= args.max_secret_pixels <= 10:
        ap.error('--max-secret-pixels must be 1..10; exhaustive cost grows exponentially')
    if args.max_witnesses < 0:
        ap.error('--max-witnesses must be nonnegative')
    root = find_root(args.root)
    out = Path(args.output).resolve() if args.output else root/'Results'/'F8_02'
    start = time.perf_counter()
    audit_path = root/'Results'/'F8_01'/'reports'/'summary.json'
    prior = None
    warnings = []
    if audit_path.is_file():
        try:
            prior = json.loads(audit_path.read_text(encoding='utf-8'))
        except Exception as e:
            warnings.append('F8_01 summary unreadable: '+str(e))
    if args.strict_data and (not prior or not prior.get('data_audit_passed') or prior.get('total_valid_images') != 546):
        raise SystemExit('STRICT-DATA FAILURE: F8_01 summary missing or did not validate 546 images: '+str(audit_path))
    if not prior:
        warnings.append('F8_01 not found: standalone exact mathematical audit proceeds; dataset not validated here')
    config = {'program':'F8_02_Mathematical_Feasibility', 'version':VERSION,
              'timestamp_utc':datetime.now(timezone.utc).isoformat(), 'root':str(root),
              'output':str(out), 'seed':args.seed, 'max_secret_pixels':args.max_secret_pixels,
              'max_witnesses':args.max_witnesses, 'strict_data':args.strict_data,
              'side_metadata_only':args.side, 'trials_metadata_only':args.trials,
              'image_limit_metadata_only':args.image_limit,
              'python':sys.version, 'platform':platform.platform(),
              'baseline':'Naor-Shamir (2,2) 2-subpixel basis',
              'scope':'finite exhaustive audit; not a PQ optical authentication protocol'}
    write_json(out/'configuration'/'run.json',config)
    privacy, case_rows, witnesses = [], [], []
    totals = collections.Counter()
    for n in range(1,args.max_secret_pixels+1):
        p = exact_privacy(n)
        d, w, rows = full_audit(n, max(0,args.max_witnesses-len(witnesses)), args.seed)
        privacy.append(p)
        case_rows.append({'secret_pixels':n, **d})
        witnesses.extend(w)
        write_csv(out/'mathematical_validation'/f'per_secret_n{n}.csv',rows)
        print(f'Exact {n}-pixel audit: {d["authentic_issuances"]} issuances; '
              f'{d["single_subpixel_attacks"]} single-subpixel attacks; '
              f'{d["single_subpixel_masked"]} masked', flush=True)
    op = operator_collision_audit()
    two_three = two_three_screen()
    # Publicly known target + one share is sufficient to reconstruct the partner
    # in the F1 basis, and a publicly recomputable tag cannot prove issuer origin.
    write_json(out/'mathematical_validation'/'privacy_exact.json',privacy)
    write_json(out/'mathematical_validation'/'optical_operator_collisions.json',op)
    write_json(out/'mathematical_validation'/'two_of_three_replication.json',two_three)
    write_json(out/'mathematical_validation'/'counterexamples.json',witnesses)
    write_csv(out/'reports'/'exact_cases.csv',case_rows)
    write_json(out/'reports'/'attack_model.json',{
        'attacker_capabilities':['one-share bit modification','one-pixel share replacement',
                                 'known-secret and one-share recovery','full pair replacement'],
        'excluded':['compromising independently authenticated physical reference',
                    'quantum computational attacks','real-world fabrication and human decisions'],
        'important_distinction':'Changing a physical share does not always change the protected secret or the OR observation',
        'exact_copy':'No static observation-only verifier can distinguish an exact optical duplicate under identical trusted information',
        'public_anchor':'Publicly reproducible anchors provide no independent issuer origin authentication'} )
    summary = {'F8_01_validated_dataset':bool(prior and prior.get('data_audit_passed')),
               'F8_01_total_images':prior.get('total_valid_images') if prior else None,
               'exact_secret_lengths_tested':list(range(1,args.max_secret_pixels+1)),
               'privacy':privacy, 'attack_counts':case_rows,
               'optical_operators':op, 'two_of_three':two_three,
               'counterexamples_saved':len(witnesses),
               'elapsed_seconds':round(time.perf_counter()-start,3),
               'warnings':warnings}
    verdict = {
        'classical_2of2_single_share_privacy':'EXHAUSTIVELY_VERIFIED_FINITE_DOMAIN',
        'classical_2of2_authorized_reconstruction':'EXHAUSTIVELY_VERIFIED_FINITE_DOMAIN',
        'single_subpixel_optical_soundness':'COUNTEREXAMPLE_FOUND' if any(x['single_subpixel_masked'] for x in case_rows) else 'NO_COUNTEREXAMPLE_IN_DOMAIN',
        'local_share_replacement_soundness':'COUNTEREXAMPLE_FOUND' if any(x['local_replacement_masked'] for x in case_rows) else 'NO_COUNTEREXAMPLE_IN_DOMAIN',
        'known_content_partner_share_secrecy':'FAILED_EXACT_RECOVERY',
        'unconditional_exact_copy_origin_authentication':'IMPOSSIBLE_IDENTICAL_OBSERVATION',
        'general_2of3_security':'NOT_ESTABLISHED_ONLY_EXPLICIT_REPLICATION_EXAMPLE',
        'post_quantum_issuer_binding':'NOT_IMPLEMENTED',
        'optical_issuer_authentication':'NOT_ESTABLISHED',
        'human_only_verification':'NOT_TESTED',
        'physical_hardware':'NOT_TESTED',
        'scope':'Finite-domain exact baseline and impossibility counterexamples; not a universal impossibility proof for all possible constructions',
        'errors':0}
    write_json(out/'reports'/'summary.json',summary)
    write_json(out/'reports'/'verdict.json',verdict)
    write_json(out/'reports'/'scan_errors.json',[])
    readme = f'''# F8_02 Mathematical Feasibility and Impossibility Audit

Version: {VERSION}

This program exhaustively enumerates F1-style classical (2,2) visual secret
sharing for secret lengths 1 through {args.max_secret_pixels}, with all 2^n
secret patterns and all 2^n independent random column choices. It audits
single-share privacy, reconstruction contrast, single-subpixel changes, all
single-pixel replacement masks, and known-content partner-share recovery.

The two-of-three analysis concerns only an explicitly described pairwise
replication candidate, not all (2,3) visual secret sharing schemes.

The ideal digital XOR operator is *not* passive transparency stacking.
Binary multiplicative transmission is a simplified physical surrogate, not
fabricated hardware. All reported optical collisions are exact in these
finite binary models only.

An identical physical optical observation under identical trust information
cannot authenticate the origin of an exact copy. This does not establish an
impossibility for challenge-based or physically unclonable systems under
other trust assumptions.

No ML-DSA, physical measurements, or human studies were performed.

Files:
- mathematical_validation/privacy_exact.json
- mathematical_validation/optical_operator_collisions.json
- mathematical_validation/two_of_three_replication.json
- mathematical_validation/counterexamples.json
- mathematical_validation/per_secret_n*.csv
- reports/exact_cases.csv
- reports/attack_model.json
- reports/summary.json
- reports/verdict.json
'''
    (out/'README.md').write_text(readme,encoding='utf-8')
    print(json.dumps({'output':str(out),'max_secret_pixels':args.max_secret_pixels,
                      'single_subpixel_attacks':sum(x['single_subpixel_attacks'] for x in case_rows),
                      'masked_single_subpixel_attacks':sum(x['single_subpixel_masked'] for x in case_rows),
                      'known_content_recovery':'EXACT',
                      'issuer_authentication':'NOT_ESTABLISHED',
                      'elapsed_seconds':summary['elapsed_seconds']},indent=2))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

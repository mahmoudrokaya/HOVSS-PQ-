#!/usr/bin/env python3
"""EOW_C06 — decisive *toy-model* challenge-dependent optical integrity test.

Classical (2,2) Naor–Shamir shares; independent random binary OR challenge
masks, enrolled expected OR responses, exact-OR and per-pixel black-count
observers. Computes exact finite-domain optimal precommit attacks, public-mask
attacks, fixed-mask verification-oracle attacks (up to two attempts), and
independent fresh-challenge multi-round attacks. Evaluates confidentiality
under explicitly different witness disclosures.

IMPORTANT: The expected response is stored in trusted private state and checked
by a DIGITAL idealized observer. This is not an unaided human optical verifier,
a physical prototype, a cryptographic proof for arbitrary n, or an ML-DSA test.
Python >=3.10; standard library only.
"""
from __future__ import annotations
import argparse, csv, hashlib, itertools, json, sys, zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

OBSERVERS = ('exact_or', 'black_count')
CITATIONS = {
    'Naor and Shamir (1994)': 'https://doi.org/10.1007/BFb0053419',
    'NIST FIPS 204': 'https://doi.org/10.6028/NIST.FIPS.204',
}

def encode(secret: int, pad: int, n: int) -> tuple[int, int]:
    a = b = 0
    for i in range(n):
        for j in range(2):
            v = int(j == ((pad >> i) & 1))
            a |= v << (2*i+j)
            b |= (v ^ ((secret >> i) & 1)) << (2*i+j)
    return a, b

def obs(b: int, mask: int, n: int, observer: str):
    x = b | mask
    if observer == 'exact_or':
        return x
    if observer == 'black_count':
        return tuple(((x >> (2*i)) & 1) + ((x >> (2*i+1)) & 1) for i in range(n))
    raise ValueError(observer)

def reconstructed(a: int, b: int, n: int) -> tuple[int, ...]:
    return obs(b, a, n, 'black_count')

def tv_max(dists: dict[int, Counter]) -> float:
    result = 0.0
    for x, y in itertools.combinations(dists, 2):
        a, b = dists[x], dists[y]
        sa, sb = sum(a.values()), sum(b.values())
        result = max(result, 0.5 * sum(abs(a[k]/sa - b[k]/sb)
                                        for k in a.keys() | b.keys()))
    return result

def confidentiality(n: int) -> list[dict]:
    """Exact distributions over uniform secret-sharing pad and challenge mask.

    A is the publicly exposed share; B is protected. Enrollment uses the
    genuine B and stores expected optical observation. The challenge mask and
    expected observation may be private or exposed as defined by each view.
    """
    d = 1 << n
    m = 1 << (2*n)
    rows = []
    for observer in OBSERVERS:
        views = {name: {s: Counter() for s in range(d)} for name in (
            'public_A_only', 'A_and_mask_only', 'A_and_expected_only',
            'A_mask_and_expected', 'A_and_B_compromised')}
        for s, pad, mask in itertools.product(range(d), range(d), range(m)):
            a, b = encode(s, pad, n)
            expected = obs(b, mask, n, observer)
            for name, view in (
                ('public_A_only', (a,)),
                ('A_and_mask_only', (a, mask)),
                ('A_and_expected_only', (a, expected)),
                ('A_mask_and_expected', (a, mask, expected)),
                ('A_and_B_compromised', (a, b)),
            ):
                views[name][s][view] += 1
        for name, distributions in views.items():
            rows.append({'observer': observer, 'view': name,
                         'max_total_variation': tv_max(distributions),
                         'secrets': d, 'enrollment_samples_per_secret': d*m})
    return rows

def bit_count(x: int) -> int:
    return x.bit_count()

def attacks(n: int, max_queries: int) -> tuple[list[dict], list[dict], list[dict]]:
    """Exhaustive in secret/pad/mask/candidate for n<=3.

    Candidate must change reconstructed OR-black-count content with A fixed.
    Success set is all masks that accept the submitted candidate. For a fixed
    hidden mask, up to two online oracle attempts win if either query accepts.
    The attacker knows A and B in this conservative integrity game, but not
    the private challenge mask or expected response. This is stronger than
    an attacker who knows only A. For independent fresh challenges, each
    attempt draws a new mask, with a fixed precommit candidate each round.
    """
    width = 2*n
    masks = 1 << width
    secrets = 1 << n
    rows, counterexamples, detail = [], [], []
    for observer in OBSERVERS:
        stats = Counter()
        p_sums = Counter()
        max_p = 0.0
        worst_example = None
        for s in range(secrets):
            for pad in range(secrets):
                a, b = encode(s, pad, n)
                original = reconstructed(a, b, n)
                candidates = [r for r in range(masks)
                              if r != b and reconstructed(a, r, n) != original]
                if not candidates:
                    continue
                # Exact mask-bitset of accepted challenges per candidate.
                acceptance = {}
                for r in candidates:
                    good = 0
                    for mask in range(masks):
                        if obs(r, mask, n, observer) == obs(b, mask, n, observer):
                            good |= 1 << mask
                    acceptance[r] = good
                best_r = max(candidates, key=lambda r: (bit_count(acceptance[r]), -r))
                best_set = acceptance[best_r]
                best_one = bit_count(best_set)
                all_mask_union = 0
                public_vulnerable_masks = 0
                for mask in range(masks):
                    if any((acceptance[r] >> mask) & 1 for r in candidates):
                        public_vulnerable_masks += 1
                for success_set in acceptance.values():
                    all_mask_union |= success_set
                assert public_vulnerable_masks == bit_count(all_mask_union)
                # Exact optimal two online attempts against one persistent mask.
                # The first query's failure reveals that the mask is not in
                # its success set; a second query can cover remaining masks.
                best_two = best_one
                pair = (best_r, best_r)
                if max_queries >= 2:
                    for r1, r2 in itertools.combinations_with_replacement(candidates, 2):
                        count = bit_count(acceptance[r1] | acceptance[r2])
                        if count > best_two:
                            best_two, pair = count, (r1, r2)
                p = best_one/masks
                p2 = best_two/masks
                stats['instances'] += 1
                stats['candidates'] += len(candidates)
                stats['public_mask_vulnerable'] += public_vulnerable_masks
                stats['mask_total'] += masks
                p_sums['one'] += p
                p_sums['two_static'] += p2
                for q in range(1, max_queries+1):
                    # Fresh independent mask each attempt; optimal p is the
                    # same after any failed query because masks are IID.
                    p_sums[f'fresh_{q}'] += 1-(1-p)**q
                if p > max_p:
                    max_p = p
                    worst_example = (s,pad,a,b,best_r,best_set)
                if len(counterexamples) < 12 and best_one:
                    witness_mask = next(mask for mask in range(masks)
                                        if (best_set >> mask) & 1)
                    counterexamples.append({
                        'observer':observer,'secret':format(s,f'0{n}b'),
                        'pad':format(pad,f'0{n}b'),
                        'share_A':format(a,f'0{width}b'),
                        'share_B':format(b,f'0{width}b'),
                        'forged_B':format(best_r,f'0{width}b'),
                        'passing_mask':format(witness_mask,f'0{width}b'),
                        'original_content':list(original),
                        'forged_content':list(reconstructed(a,best_r,n)),
                        'optimal_single_challenge_probability':p,
                        'note':'One accepted content-changing counterexample; expected response is private.'})
                detail.append({'observer':observer,'secret':s,'pad':pad,
                               'eligible_content_changing_replacements':len(candidates),
                               'best_one_mask_count':best_one,
                               'best_two_mask_count':best_two,
                               'public_mask_vulnerable_count':public_vulnerable_masks,
                               'total_masks':masks,
                               'best_replacement_B':best_r,
                               'best_two_replacements':list(pair)})
        count = stats['instances']
        if not count:
            raise RuntimeError('No content-changing candidate found')
        rows.append({
            'observer':observer,'bits':n,'instances':count,
            'masks_per_instance':masks,
            'candidate_count_total':stats['candidates'],
            'public_fixed_mask_optimal_success_fraction':stats['public_mask_vulnerable']/stats['mask_total'],
            'private_fresh_precommit_one_mean_success':p_sums['one']/count,
            'private_fresh_precommit_one_worst_success':max_p,
            'fixed_hidden_mask_two_oracle_attempts_mean_success':p_sums['two_static']/count,
            **{f'fresh_independent_{q}_attempts_mean_success':p_sums[f'fresh_{q}']/count
               for q in range(1,max_queries+1)},
            'legitimate_acceptance':'1.0 (unperturbed ideal observer)',
        })
    return rows, detail, counterexamples

def logical_defects(n: int) -> list[dict]:
    """One-bit changes to legitimate submitted B with enrollment unchanged.

    No claim that a bit flip is a physically calibrated registration defect.
    """
    rows=[]
    masks=1 << (2*n)
    for observer in OBSERVERS:
        accepted=total=0
        for s, pad, mask, position in itertools.product(
                range(1<<n),range(1<<n),range(masks),range(2*n)):
            _, b=encode(s,pad,n)
            changed=b^(1<<position)
            total += 1
            accepted += obs(changed,mask,n,observer)==obs(b,mask,n,observer)
        rows.append({'observer':observer,'perturbation':'flip_one_B_subpixel',
                     'total':total,'accepted':accepted,'rejected':total-accepted,
                     'rejection_fraction':(total-accepted)/total})
    return rows

def source_audit(path: Path|None) -> dict:
    if path is None:
        return {'status':'NOT_PROVIDED'}
    path=Path(path)
    if path.is_dir():
        matches=[path/'reports'/'verdict.json',path/'EOW_C05'/'reports'/'verdict.json']
        for f in matches:
            if f.is_file():
                raw=f.read_bytes()
                return {'status':'LOADED','location':str(f),'sha256':hashlib.sha256(raw).hexdigest(),
                        'verdict':json.loads(raw)}
    elif path.is_file() and zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            matches=[name for name in z.namelist() if name.endswith('EOW_C05/reports/verdict.json')]
            if matches:
                raw=z.read(matches[0])
                return {'status':'LOADED','location':str(path),'member':matches[0],
                        'sha256':hashlib.sha256(raw).hexdigest(),'verdict':json.loads(raw)}
    return {'status':'MISSING_VERDICT','location':str(path)}

def tests() -> dict:
    result={}
    for n in (1,2,3):
        for s in range(1<<n):
            for pad in range(1<<n):
                a,b=encode(s,pad,n)
                assert reconstructed(a,b,n)==tuple(1+((s>>i)&1) for i in range(n))
    result['vss_correctness']='PASS'
    assert obs(0,1,1,'exact_or')==obs(1,1,1,'exact_or')
    result['or_collision']='PASS'
    assert obs(1,0,1,'black_count')==obs(2,0,1,'black_count')
    result['black_count_collision']='PASS'
    assert obs(0,0,1,'exact_or')!=obs(1,0,1,'exact_or')
    result['unmasked_bit_detection']='PASS'
    assert obs(0,3,1,'exact_or')==obs(1,3,1,'exact_or')
    result['masked_bit_invisibility']='PASS'
    assert tv_max({0:Counter({0:2,1:2}),1:Counter({0:1,1:1})})==0
    result['tv_normalization']='PASS'
    assert 1-(1-0.25)**2==0.4375
    result['independent_challenge_formula']='PASS'
    assert bit_count(0b0011|0b1100)==4
    result['adaptive_union_logic']='PASS'
    return result

def dump_json(p:Path,obj):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n',encoding='utf-8')

def dump_csv(p:Path,rows:list[dict]):
    p.parent.mkdir(parents=True,exist_ok=True)
    if not rows:
        raise ValueError('No CSV rows')
    fields=list(rows[0])
    with p.open('w',encoding='utf-8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bits',type=int,default=3,help='1..3; exhaustive finite-domain analysis')
    ap.add_argument('--queries',type=int,default=2,help='1..2; adaptive fixed-mask analysis exact up to 2')
    ap.add_argument('--root',type=Path,help='Experiments root; default parent of script directory')
    ap.add_argument('--output',type=Path,help='Output directory; overrides root/Results/EOW_C06')
    ap.add_argument('--c05',type=Path,help='EOW_C05 directory or ZIP for upstream audit')
    ap.add_argument('--strict-c05',action='store_true',help='Require readable C05 verdict')
    args=ap.parse_args()
    if args.bits not in (1,2,3): ap.error('--bits must be 1, 2, or 3')
    if args.queries not in (1,2): ap.error('--queries must be 1 or 2')
    root=args.root or Path(__file__).resolve().parent.parent
    out=args.output or root/'Results'/'EOW_C06'
    reports=out/'reports'
    upstream=source_audit(args.c05 or root/'Results'/'EOW_C05')
    if args.strict_c05 and upstream['status']!='LOADED':
        ap.error('C05 verdict not found; specify --c05 with C05 folder or ZIP')
    test_results=tests()
    privacy=confidentiality(args.bits)
    attack_rows,detail,counterexamples=attacks(args.bits,args.queries)
    defects=logical_defects(args.bits)
    gates=[]
    for row in attack_rows:
        observer=row['observer']
        gates.extend([
            {'observer':observer,'gate':'unperturbed_correctness','status':'PASS_TOY','evidence':'All original responses accepted'},
            {'observer':observer,'gate':'precommit_integrity','status':'FAIL_TOY','evidence':row['private_fresh_precommit_one_worst_success']},
            {'observer':observer,'gate':'human_passive_observability','status':'NOT_ESTABLISHED','evidence':'Trusted digital expected-response comparison'},
            {'observer':observer,'gate':'issuer_binding','status':'NOT_TESTED','evidence':'No ML-DSA enrollment'},
            {'observer':observer,'gate':'replay_freshness','status':'NOT_ESTABLISHED','evidence':'Fresh challenge does not authenticate physical custody'},
            {'observer':observer,'gate':'physical_robustness','status':'NOT_ESTABLISHED','evidence':'Logical bit flip only'},
        ])
    assumptions={
        'protocol':'Enroll valid (A,B); keep private mask and expected O(B,mask). Attacker commits to replacement Bprime before a uniform random challenge mask is selected. Trusted comparator checks O(Bprime,mask)==expected.',
        'observers':list(OBSERVERS),
        'attack_knowledge':'Conservative strong attacker knows both A and original B but cannot alter private enrolled expected responses or see future masks.',
        'content_change':'Reconstructed per-secret-pixel black counts O(A,Bprime) differ from O(A,B).',
        'public_fixed':'Attacker learns mask before selecting replacement; expected response assumed trusted and immutable.',
        'fresh_private':'Attacker selects one replacement before independent uniform challenge mask; exact optimal success maximized over all eligible replacements.',
        'fixed_hidden_adaptive':'The same unknown mask is reused; up to two online verification queries. Success if any queried content-changing candidate is accepted; optimal mask coverage via candidate-set unions.',
        'fresh_multiple':'Independent uniform masks each attempt; attacker may choose replacement after previous failures but those failures reveal nothing about the next independent mask. Success = 1-(1-pmax)^q.',
        'privacy':'Uniform secret-sharing pad and challenge mask; exact TV of specified public and compromised views.',
        'limits':[
            'No human observer; private expected response compared by trusted digital equality or black-count equality.',
            'Random OR mask is not a demonstrated practical optically human-readable challenge.',
            'Uniform masks include all-black masks that hide all B bits.',
            'No physical optics, calibrated perturbation, ML-DSA, signature binding, or challenge freshness enforcement.',
            'No proof of negligible forgery for arbitrary security parameter.',
            'Attack enumeration covers arbitrary Bprime in full 2^(2n) domain; does not constrain Bprime to valid VSS share codebook.',
            'Online oracle success counts accepted queries; a real verifier may impose lockout.',
            'Privacy disclosure of enrolled expected responses can leak secret information; test separate views.',
        ],'references':CITATIONS}
    verdict={
        'execution':'PASS','research_verdict':'NO_SECURITY_QUALIFIED_CONSTRUCTION',
        'challenge_integrity':'FAILED_TOY_OPTIMAL_ATTACK',
        'human_optical_authentication':'NOT_ESTABLISHED',
        'post_quantum_issuer_authentication':'NOT_TESTED',
        'universal_impossibility_theorem':'NOT_CLAIMED',
        'next_step':'C07 privacy/leakage and threat-view refinement; do not claim challenge-dependent optical integrity.'}
    dump_json(out/'configuration'/'run.json',{
        'script':'EOW_C06_Challenge_Witness.py','bits':args.bits,'queries':args.queries,
        'python':sys.version.split()[0],'time_utc':datetime.now(timezone.utc).isoformat(),
        'output':str(out),'upstream_status':upstream['status']})
    dump_json(reports/'c05_source_audit.json',upstream)
    dump_json(reports/'model_assumptions.json',assumptions)
    dump_json(reports/'self_tests.json',{'passed':len(test_results),'total':len(test_results),'checks':test_results})
    dump_csv(reports/'attack_games.csv',attack_rows)
    dump_csv(reports/'attack_instances.csv',detail)
    dump_csv(reports/'privacy_exact.csv',privacy)
    dump_csv(reports/'logical_defects.csv',defects)
    dump_csv(reports/'feasibility_gates.csv',gates)
    dump_json(reports/'content_changing_counterexamples.json',counterexamples)
    dump_json(reports/'verdict.json',verdict)
    summary={'bits':args.bits,'queries':args.queries,'self_tests_passed':len(test_results),
             'attack_instances':len(detail),'attack_observers':len(attack_rows),
             'privacy_rows':len(privacy),'counterexamples':len(counterexamples),
             'c05_source_status':upstream['status'],'research_verdict':verdict['research_verdict']}
    dump_json(reports/'summary.json',summary)
    lines=['# EOW_C06 — Challenge-Dependent Optical Integrity Diagnostic','',
           '**Verdict:** `NO_SECURITY_QUALIFIED_CONSTRUCTION` (finite toy-model evidence).','',
           'The challenge is drawn **after** adversarial commitment. The expected optical response is a **private trusted digital reference**, not a demonstrated unaided human verification step.','',
           '## Optimal integrity games','',
           '| Observer | Public fixed mask: vulnerable mask fraction | Fresh private: optimal mean | Fresh private: worst case | Fixed hidden: 2 online attempts |',
           '|---|---:|---:|---:|---:|']
    for r in attack_rows:
        lines.append('| {} | {:.6f} | {:.6f} | {:.6f} | {:.6f} |'.format(
            r['observer'],r['public_fixed_mask_optimal_success_fraction'],
            r['private_fresh_precommit_one_mean_success'],
            r['private_fresh_precommit_one_worst_success'],
            r['fixed_hidden_mask_two_oracle_attempts_mean_success']))
    lines+=['','## Exact privacy across distinct views','',
            '| Observer | View | Maximum TV |','|---|---|---:|']
    for r in privacy:
        lines.append('| {} | {} | {:.6f} |'.format(r['observer'],r['view'],r['max_total_variation']))
    lines+=['','## Interpretation','',
            '- Public fixed challenge: a chosen replacement may exploit an observed OR collision.',
            '- Fresh challenge: exact best precommit attack probability is **not** necessarily negligible.',
            '- Repeated fresh challenges: the success probability increases with the number of allowed attempts.',
            '- Reusing a hidden challenge: online oracle feedback enables coverage of more masks.',
            '- Expected-response disclosure is assessed separately from the limited public-A-only secrecy game.',
            '- A digital equality test is not proof of human-only optical authentication.',
            '- One-bit perturbations are logical sensitivity checks, not fabrication/registration measurements.',
            '','## References','',
            '- [Naor and Shamir, Visual Cryptography](https://doi.org/10.1007/BFb0053419)',
            '- [NIST FIPS 204](https://doi.org/10.6028/NIST.FIPS.204)']
    (reports/'scientific_report.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(json.dumps(summary,indent=2))
    for row in attack_rows:
        print(row['observer'], 'fresh-optimal mean=',round(row['private_fresh_precommit_one_mean_success'],6),
              'worst=',round(row['private_fresh_precommit_one_worst_success'],6),
              'public-vulnerable=',round(row['public_fixed_mask_optimal_success_fraction'],6))
    return 0

if __name__=='__main__':
    raise SystemExit(main())

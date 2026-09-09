#!/usr/bin/env python3
"""RITA-oracle comparison (plan U7): RITA (Active Countermeasures) is the FOSS
oracle these detectors are validated against. This diffs OUR beacon/long-conn
verdicts against a RITA export on the same traffic and reports agreement.

  python rita_oracle_compare.py --ours findings.jsonl --rita rita_beacons.json

`--ours`  : one finding JSON per line (as emitted to ndr.finding.candidate.v1).
`--rita`  : RITA's beacon export (list of {"src","dst"} or {"fqdn"}); produce it by
            running RITA over the Zeek logs for the same capture. Without --rita the
            script prints how to generate it (RITA is an operator/CI step, not bundled).
"""
import argparse, json, sys

def _ours_c2(path):
    dsts = set()
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        f = json.loads(line)
        if f.get("detector_id") in ("beacon", "beacon_fqdn", "long_connection", "long_connection_cumulative"):
            for e in json.loads(f["entities"]):
                if e.get("type") in ("ip", "domain") and e.get("role") in ("dst", "c2"):
                    dsts.add(e["value"])
    return dsts

def _rita(path):
    out = set()
    for r in json.load(open(path)):
        out.add(r.get("dst") or r.get("fqdn") or r.get("dest"))
    return out - {None}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ours", required=True)
    ap.add_argument("--rita")
    a = ap.parse_args()
    ours = _ours_c2(a.ours)
    if not a.rita:
        print("No --rita export given. Generate one by running RITA over the Zeek")
        print("logs for the same capture and exporting its beacons, then re-run with")
        print("--rita. Our C2 destinations flagged:", sorted(ours))
        return
    rita = _rita(a.rita)
    both = ours & rita
    print(f"ours={len(ours)} rita={len(rita)} agree={len(both)}")
    print(f"  only ours : {sorted(ours - rita)}")
    print(f"  only rita : {sorted(rita - ours)}")
    if ours | rita:
        print(f"  agreement : {len(both) / len(ours | rita):.0%}")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""The plan's Compute Engine quotas against the project's (deploy/gcp/preflight.sh).

    quota-check.py REGION REGION_JSON PROJECT_JSON NEED...

REGION_JSON: `gcloud compute regions describe REGION --format=json`;
PROJECT_JSON: `gcloud compute project-info describe --format=json`.
NEED: KEY=N, the plan's needs: od_cpus_FAMILY / spot_cpus_FAMILY (vCPUs on
demand and on Spot, per quota metric such as C2D_CPUS or CPUS),
od_lssd_gb / spot_lssd_gb, ssd_gb (pd-balanced boot disks), addresses,
instances. Spot VMs use PREEMPTIBLE_CPUS (and PREEMPTIBLE_LOCAL_SSD_GB)
when the region grants any, else the on-demand quotas. Prints one row per
quota and, for each one short, what to request and where. Exit 1 when one
is short.
"""
import json
import sys

NAMES = {
    "CPUS": "CPUs",
    "C2D_CPUS": "C2D CPUs",
    "N2_CPUS": "N2 CPUs",
    "N2D_CPUS": "N2D CPUs",
    "C2_CPUS": "C2 CPUs",
    "C3D_CPUS": "C3D CPUs",
    "PREEMPTIBLE_CPUS": "Preemptible CPUs",
    "LOCAL_SSD_TOTAL_GB": "Local SSD (GB)",
    "PREEMPTIBLE_LOCAL_SSD_GB": "Preemptible Local SSD (GB)",
    "SSD_TOTAL_GB": "Persistent Disk SSD (GB)",
    "IN_USE_ADDRESSES": "In-use regional external IPv4 addresses",
    "INSTANCES": "VM instances",
    "CPUS_ALL_REGIONS": "CPUs (all regions)",
}


def quotas(path):
    with open(path) as f:
        return {q["metric"]: (float(q.get("limit", 0)), float(q.get("usage", 0))) for q in json.load(f).get("quotas", [])}


def main():
    region, rpath, ppath = sys.argv[1:4]
    need = {}
    for kv in sys.argv[4:]:
        k, v = kv.split("=", 1)
        need[k] = int(v)
    reg, glob = quotas(rpath), quotas(ppath)
    req = {}  # (metric, scope) -> needed
    pre = reg.get("PREEMPTIBLE_CPUS", (0, 0))[0] > 0
    spot_total = 0
    for k, v in need.items():
        if k.startswith("od_cpus_"):
            req[(k[8:], region)] = req.get((k[8:], region), 0) + v
        elif k.startswith("spot_cpus_"):
            spot_total += v
            m = "PREEMPTIBLE_CPUS" if pre else k[10:]
            req[(m, region)] = req.get((m, region), 0) + v
    lssd_pre = reg.get("PREEMPTIBLE_LOCAL_SSD_GB", (0, 0))[0] > 0
    req[("LOCAL_SSD_TOTAL_GB", region)] = need.get("od_lssd_gb", 0) + (0 if lssd_pre else need.get("spot_lssd_gb", 0))
    if lssd_pre and need.get("spot_lssd_gb", 0):
        req[("PREEMPTIBLE_LOCAL_SSD_GB", region)] = need["spot_lssd_gb"]
    req[("SSD_TOTAL_GB", region)] = need.get("ssd_gb", 0)
    req[("IN_USE_ADDRESSES", region)] = need.get("addresses", 0)
    req[("INSTANCES", region)] = need.get("instances", 0)
    cpus = sum(v for k, v in need.items() if "_cpus_" in k)
    req[("CPUS_ALL_REGIONS", "global")] = cpus
    print(f"   Spot VMs count against {'PREEMPTIBLE_CPUS (the region grants it)' if pre else 'the on-demand CPU quotas (no PREEMPTIBLE_CPUS in the region)'}: {spot_total} vCPUs")
    print(f"   {'quota':<26} {'where':<12} {'limit':>7} {'in use':>7} {'free':>7} {'needed':>7}")
    short = []
    for (metric, scope), n in req.items():
        if n <= 0:
            continue
        lim, use = (glob if scope == "global" else reg).get(metric, (None, None))
        if lim is None:
            print(f"   {metric:<26} {scope:<12} {'?':>7} {'?':>7} {'?':>7} {n:>7}  NOT LISTED")
            short.append((metric, scope, n, 0))
            continue
        free = lim - use
        ok = free >= n
        print(f"   {metric:<26} {scope:<12} {lim:>7.0f} {use:>7.0f} {free:>7.0f} {n:>7}  {'ok' if ok else 'SHORT'}")
        if not ok:
            short.append((metric, scope, n, use))
    if glob.get("CPUS_ALL_REGIONS", (99, 0))[0] <= 12:
        print("   (CPUs in all regions is 12 or less: a free-trial or new project. Upgrade the billing account to a paid one first;")
        print("    a free-trial account cannot ask for more quota. docs/REPRODUCE.md, Google Cloud.)")
    if not short:
        print("preflight: every quota the plan needs is free")
        return 0
    print()
    print("preflight: ask for more quota before create.sh (it is free; an answer takes minutes to two days):")
    print("   Console > IAM & Admin > Quotas & System Limits, filter Service: Compute Engine API, then by the name below,")
    print("   tick it, Edit quotas, and enter at least the new limit. The quotas:")
    for metric, scope, n, use in short:
        print(f"   - {NAMES.get(metric, metric)} ({metric}), {'region ' + scope if scope != 'global' else 'global'}: new limit >= {int(use + n)}")
    return 1


if __name__ == "__main__":
    sys.exit(main())

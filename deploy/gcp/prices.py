#!/usr/bin/env python3
"""Current Google Cloud list prices for the kit's estimate (deploy/gcp/estimate.sh --live).

    prices.py REGION MACHINE_TYPE... < pages

stdin: the Cloud Billing Catalog API's SKU pages for Compute Engine
(services/6F81-5844-456A/skus, USD), one JSON document per line. stdout, one
line each, USD an hour:

    type MACHINE_TYPE ONDEMAND SPOT
    lssd_gb_month ONDEMAND SPOT
    pd_gb_month PRICE
    ip_hour ONDEMAND SPOT

A machine type is priced from its family's per-vCPU and per-GiB SKUs in
REGION (c2d-standard-16: 16 vCPUs, 64 GiB). Anything not found is left out:
the estimate then refuses to price it rather than call it free.
"""
import json
import re
import sys

# GiB of memory per vCPU of the predefined shapes.
SHAPE_GIB = {"standard": 4, "highcpu": 1, "highmem": 8}
# A few families sell other shapes: c2d-highcpu has 2 GiB a vCPU.
FAMILY_SHAPE_GIB = {("c2d", "highcpu"): 2, ("n2d", "highcpu"): 1, ("c2", "standard"): 4}


def unit_price(sku):
    try:
        rate = sku["pricingInfo"][0]["pricingExpression"]["tieredRates"][-1]["unitPrice"]
        return int(rate.get("units", 0) or 0) + rate.get("nanos", 0) / 1e9
    except (KeyError, IndexError, TypeError, ValueError):
        return None


def main():
    region, types = sys.argv[1], sys.argv[2:]
    skus = []
    for line in sys.stdin:
        line = line.strip()
        if line:
            skus.extend(json.loads(line).get("skus", []))
    here = [s for s in skus if region in s.get("serviceRegions", [])]

    def find(pattern):
        rx = re.compile(pattern)
        for s in here:
            if rx.search(s.get("description", "")):
                p = unit_price(s)
                if p is not None:
                    return p
        return None

    for t in types:
        m = re.fullmatch(r"([a-z0-9]+)-([a-z]+)-([0-9]+)", t)
        if not m:
            continue
        fam, shape, n = m.group(1), m.group(2), int(m.group(3))
        gib = FAMILY_SHAPE_GIB.get((fam, shape), SHAPE_GIB.get(shape))
        if gib is None:
            continue
        F = re.escape(fam.upper())
        out = []
        for spot in (False, True):
            pre = "^Spot Preemptible " if spot else "^"
            core = find(pre + F + r"( AMD| Intel| Arm)? Instance Core running in")
            ram = find(pre + F + r"( AMD| Intel| Arm)? Instance Ram running in")
            out.append(None if core is None or ram is None else n * core + n * gib * ram)
        if None not in out:
            print(f"type {t} {out[0]:.6f} {out[1]:.6f}")
    lssd = find(r"^SSD backed Local Storage( in |$)")
    lssd_spot = find(r"^SSD backed Local Storage attached to Spot Preemptible VMs")
    if lssd is not None:
        print(f"lssd_gb_month {lssd:.6f} {lssd_spot if lssd_spot is not None else lssd:.6f}")
    pd = find(r"^Balanced PD Capacity")
    if pd is not None:
        print(f"pd_gb_month {pd:.6f}")
    ip = find(r"^External IP Charge on a Standard VM")
    ip_spot = find(r"^External IP Charge on a Spot Preemptible VM")
    if ip is not None:
        print(f"ip_hour {ip:.6f} {ip_spot if ip_spot is not None else ip:.6f}")


if __name__ == "__main__":
    main()

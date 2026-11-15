#!/usr/bin/env python3
"""Monthly edge cost model: in-cluster ingress-nginx vs Application Gateway v2 (+AGIC)
vs Application Gateway for Containers (AGC), with and without WAF.

  ./cost_model.py                       # live Azure Retail Prices API, westeurope
  ./cost_model.py --region eastus2
  ./cost_model.py --offline             # snapshot taken 2026-10-28 (westeurope)

Everything here is list price (PAYG, USD). Treat the output as a decision aid, not a quote:
capacity-unit consumption depends on your traffic shape, TLS mix and WAF rule hits.
"""
import argparse
import json
import math
import urllib.parse
import urllib.request

HOURS = 730
API = "https://prices.azure.com/api/retail/prices"

# (productName, meterName) -> key
METERS = {
    ("Application Gateway for Containers", "Standard AGC"): "agc",
    ("Application Gateway for Containers", "Standard Association"): "agc_assoc",
    ("Application Gateway for Containers", "Standard Frontend"): "agc_fe",
    ("Application Gateway for Containers", "Standard Capacity Units"): "agc_cu",
    ("Application Gateway for Containers WAF", "Standard AGC"): "agcw",
    ("Application Gateway for Containers WAF", "Standard Association"): "agcw_assoc",
    ("Application Gateway for Containers WAF", "Standard Frontend"): "agcw_fe",
    ("Application Gateway for Containers WAF", "Standard Capacity Units"): "agcw_cu",
    ("Application Gateway Standard v2", "Standard Fixed Cost"): "agw",
    ("Application Gateway Standard v2", "Standard Capacity Units"): "agw_cu",
    ("Application Gateway WAF v2", "Standard Fixed Cost"): "agww",
    ("Application Gateway WAF v2", "Standard Capacity Units"): "agww_cu",
}

SNAPSHOT_WESTEUROPE_2026_10_28 = {
    "agc": 0.022, "agc_assoc": 0.156, "agc_fe": 0.013, "agc_cu": 0.0104,
    "agcw": 0.04, "agcw_assoc": 0.281, "agcw_fe": 0.023, "agcw_cu": 0.019,
    "agw": 0.26, "agw_cu": 0.008, "agww": 0.468, "agww_cu": 0.0144,
    "vm_d4ds_v5": 0.272,
}

LB_DATA_PER_GB = 0.005  # Standard Load Balancer data processed (global list price)

SCENARIOS = [
    # name, avg Mbps, avg concurrent connections, frontends (public entry points)
    ("S - one product, 3 apps", 5, 1_000, 1),
    ("M - shared platform, 20 apps", 50, 10_000, 2),
    ("L - busy estate, 60 apps", 300, 50_000, 2),
]


def fetch(region):
    prices = {}
    flt = (f"serviceName eq 'Application Gateway' and armRegionName eq '{region}' "
           "and priceType eq 'Consumption'")
    url = f"{API}?$filter={urllib.parse.quote(flt)}"
    while url:
        with urllib.request.urlopen(url, timeout=30) as r:
            data = json.load(r)
        for it in data["Items"]:
            key = METERS.get((it["productName"], it["meterName"]))
            if key:
                prices[key] = it["unitPrice"]
        url = data.get("NextPageLink")
    flt = (f"serviceName eq 'Virtual Machines' and armRegionName eq '{region}' and priceType eq 'Consumption' "
           "and armSkuName eq 'Standard_D4ds_v5' and productName eq 'Virtual Machines Ddsv5 Series' "
           "and skuName eq 'Standard_D4ds_v5'")
    with urllib.request.urlopen(f"{API}?$filter={urllib.parse.quote(flt)}", timeout=30) as r:
        items = json.load(r)["Items"]
    if items:
        prices["vm_d4ds_v5"] = items[0]["unitPrice"]
    missing = (set(METERS.values()) | {"vm_d4ds_v5"}) - prices.keys()
    if missing:
        raise SystemExit(f"meters not found in {region}: {sorted(missing)} (use --offline)")
    return prices


def traffic_cu(mbps, conns):
    # 1 CU = 2,500 persistent connections or 2.22 Mbps, whichever needs more.
    return max(conns / 2500, mbps / 2.22)


def model(p, mbps, conns, frontends, a):
    cu = traffic_cu(mbps, conns)
    gb = mbps * 3600 * HOURS / 8 / 1000
    vcpu_h = p["vm_d4ds_v5"] / 4
    out = {}

    # ingress-nginx in cluster: controller replicas reserve node capacity + LB data processing.
    replicas = max(a.nginx_min_replicas, math.ceil(mbps / a.nginx_mbps_per_replica))
    out["ingress-nginx (in-cluster)"] = (replicas * a.nginx_vcpu * vcpu_h * HOURS + gb * LB_DATA_PER_GB, None)

    # AppGW v2: fixed + CU; min instance count reserves 10 CU per instance (zone-redundant prod => 2+).
    agw_cu = max(cu, a.appgw_min_instances * 10)
    agw_waf_cu = max(cu * a.waf_cu_factor, a.appgw_min_instances * 10)
    out["App Gateway Standard_v2 + AGIC"] = ((p["agw"] + agw_cu * p["agw_cu"]) * HOURS, None)
    out["App Gateway WAF_v2 + AGIC"] = (None, (p["agww"] + agw_waf_cu * p["agww_cu"]) * HOURS)

    # AGC: resource + 1 association + N frontends + CU. With WAF every meter moves to the WAF rate.
    out["AGC"] = ((p["agc"] + p["agc_assoc"] + frontends * p["agc_fe"] + cu * p["agc_cu"]) * HOURS, None)
    out["AGC + WAF"] = (None, (p["agcw"] + p["agcw_assoc"] + frontends * p["agcw_fe"]
                               + cu * a.waf_cu_factor * p["agcw_cu"]) * HOURS)
    return cu, out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--region", default="westeurope")
    ap.add_argument("--offline", action="store_true", help="use the 2026-10-28 westeurope snapshot")
    ap.add_argument("--appgw-min-instances", type=int, default=2)
    ap.add_argument("--waf-cu-factor", type=float, default=1.5,
                    help="extra CU burned by WAF inspection (assumption; measure yours)")
    ap.add_argument("--nginx-min-replicas", type=int, default=3)
    ap.add_argument("--nginx-vcpu", type=float, default=1.0, help="vCPU reserved per controller replica")
    ap.add_argument("--nginx-mbps-per-replica", type=float, default=200)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    p = dict(SNAPSHOT_WESTEUROPE_2026_10_28) if a.offline else fetch(a.region)
    region = "westeurope (snapshot 2026-10-28)" if a.offline else a.region
    report = {"region": region, "prices_per_hour": p, "scenarios": []}
    for name, mbps, conns, fes in SCENARIOS:
        cu, res = model(p, mbps, conns, fes, a)
        report["scenarios"].append({"name": name, "mbps": mbps, "connections": conns, "frontends": fes,
                                    "traffic_cu": round(cu, 2),
                                    "monthly_usd": {k: [None if v is None else round(v, 2) for v in t]
                                                    for k, t in res.items()}})
    if a.json:
        print(json.dumps(report, indent=2))
        return

    print(f"Region: {region}   (USD/month, {HOURS} h, PAYG list price)\n")
    for s in report["scenarios"]:
        print(f"### {s['name']}: {s['mbps']} Mbps avg, {s['connections']:,} conns, "
              f"{s['frontends']} frontend(s), ~{s['traffic_cu']} CU\n")
        print("| Option | No WAF | With WAF |")
        print("|---|---:|---:|")
        for k, (nw, w) in s["monthly_usd"].items():
            f = lambda v: "-" if v is None else f"${v:,.0f}"
            print(f"| {k} | {f(nw)} | {f(w)} |")
        print()
    print("Assumptions: AppGW min instances=%d (10 CU each reserved), WAF CU factor=%.1f, "
          "nginx %d+ replicas x %.1f vCPU on D4ds_v5. People cost (patching, CVEs, on-call) excluded."
          % (a.appgw_min_instances, a.waf_cu_factor, a.nginx_min_replicas, a.nginx_vcpu))


if __name__ == "__main__":
    main()

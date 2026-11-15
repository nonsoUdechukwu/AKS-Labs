#!/usr/bin/env python3
"""Classify ingress-nginx Ingresses by how hard they are to move to Gateway API on
Azure Application Gateway for Containers (AGC).

  kubectl get ingress -A -o json | ./nginx_inventory.py -
  ./nginx_inventory.py legacy/ingress-nginx.yaml --format json

Verdicts (worst wins per Ingress):
  core     -> expressible with standard Gateway API (HTTPRoute filters / weights / matches)
  policy   -> needs an AGC policy CRD or Azure WAF rule (RoutePolicy, HealthCheckPolicy, WAF ...)
  manual   -> needs a human decision / redesign but is achievable on AGC
  blocker  -> no AGC equivalent today; keep on another data plane or redesign the app

Exit code 2 when any blocker is found so the script can gate a pipeline.
"""
import argparse
import json
import re
import sys

P = "nginx.ingress.kubernetes.io/"
RANK = {"core": 0, "policy": 1, "manual": 2, "blocker": 3}
LEGACY_CLASSES = {"nginx", "webapprouting.kubernetes.azure.com", "nginx-internal"}

# annotation suffix -> (verdict, target on AGC)
RULES = {
    "ssl-redirect": ("core", "HTTPRoute RequestRedirect on :80 listener"),
    "force-ssl-redirect": ("core", "HTTPRoute RequestRedirect on :80 listener"),
    "permanent-redirect": ("core", "RequestRedirect statusCode 301"),
    "permanent-redirect-code": ("core", "RequestRedirect statusCode"),
    "temporal-redirect": ("core", "RequestRedirect statusCode 302"),
    "app-root": ("core", "RequestRedirect on exact '/'"),
    "canary": ("core", "merge into one HTTPRoute with weighted backendRefs"),
    "canary-weight": ("core", "backendRefs[].weight"),
    "canary-weight-total": ("core", "backendRefs[].weight"),
    "canary-by-header": ("core", "rule with headers match"),
    "canary-by-header-value": ("core", "rule with headers match"),
    "canary-by-cookie": ("manual", "no cookie match in Gateway API; use header match or app flag"),
    "upstream-vhost": ("core", "RequestHeaderModifier set Host / URLRewrite hostname"),
    "x-forwarded-prefix": ("core", "RequestHeaderModifier"),
    "mirror-target": ("core", "RequestMirror filter"),
    "proxy-read-timeout": ("policy", "RoutePolicy timeouts.routeTimeout (semantics differ: verify)"),
    "proxy-send-timeout": ("policy", "RoutePolicy timeouts.routeTimeout (semantics differ: verify)"),
    "proxy-connect-timeout": ("policy", "RoutePolicy timeouts"),
    "affinity": ("policy", "RoutePolicy sessionAffinity"),
    "affinity-mode": ("policy", "RoutePolicy sessionAffinity"),
    "session-cookie-name": ("policy", "RoutePolicy sessionAffinity application-cookie"),
    "session-cookie-max-age": ("policy", "RoutePolicy sessionAffinity cookieDuration"),
    "session-cookie-expires": ("policy", "RoutePolicy sessionAffinity cookieDuration"),
    "session-cookie-path": ("manual", "not configurable on AGC affinity cookie"),
    "whitelist-source-range": ("policy", "WAF custom rule IPMatch (RemoteAddr)"),
    "allowlist-source-range": ("policy", "WAF custom rule IPMatch (RemoteAddr)"),
    "denylist-source-range": ("policy", "WAF custom rule IPMatch Block"),
    "proxy-body-size": ("policy", "WAF max_request_body_size / file_upload_limit (only with WAF)"),
    "backend-protocol": ("policy", "HTTPS -> alb BackendTLSPolicy; GRPC -> GRPCRoute"),
    "proxy-ssl-secret": ("policy", "alb BackendTLSPolicy (backend mTLS)"),
    "proxy-ssl-verify": ("policy", "alb BackendTLSPolicy"),
    "auth-tls-secret": ("policy", "FrontendTLSPolicy verify.caCertificateRef (frontend mTLS)"),
    "auth-tls-verify-client": ("policy", "FrontendTLSPolicy verify"),
    "limit-rps": ("policy", "WAF rate-limit custom rule (per client IP, coarser)"),
    "limit-rpm": ("policy", "WAF rate-limit custom rule"),
    "limit-connections": ("manual", "no per-connection limit; use WAF rate limit"),
    "enable-cors": ("manual", "handle CORS in the app or ResponseHeaderModifier"),
    "cors-allow-origin": ("manual", "handle CORS in the app or ResponseHeaderModifier"),
    "custom-http-errors": ("manual", "no custom error pages at the edge; handle in app"),
    "default-backend": ("manual", "catch-all HTTPRoute rule"),
    "proxy-buffering": ("manual", "not configurable; usually safe to drop"),
    "proxy-buffer-size": ("manual", "not configurable; usually safe to drop"),
    "service-upstream": ("manual", "AGC always targets pod IPs; drop"),
    "ssl-passthrough": ("blocker", "no TLS passthrough / TLSRoute on AGC"),
    "auth-url": ("blocker", "no external auth at the edge; move to oauth2-proxy in front of the app or app-level auth"),
    "auth-signin": ("blocker", "no external auth at the edge"),
    "auth-type": ("blocker", "no basic auth at the edge; move to app/IdP"),
    "configuration-snippet": ("manual", "raw NGINX config: re-express intent (headers -> HeaderModifier filters)"),
    "server-snippet": ("manual", "raw NGINX config: re-express intent by hand"),
    "stream-snippet": ("blocker", "L4 not supported on AGC"),
    "modsecurity-snippet": ("manual", "re-express as Azure WAF custom rule / exclusion"),
    "enable-modsecurity": ("policy", "WebApplicationFirewallPolicy (DRS 2.1)"),
    "enable-owasp-core-rules": ("policy", "WebApplicationFirewallPolicy (DRS 2.1, not CRS)"),
}

CAPTURE = re.compile(r"\$\d")
REGEX_CHARS = re.compile(r"[\\^$()|\[\]{}*+?]")


def load(path):
    text = sys.stdin.read() if path == "-" else open(path, encoding="utf-8").read()
    try:
        doc = json.loads(text)
        docs = doc.get("items", [doc]) if isinstance(doc, dict) else doc
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore
        except ImportError:
            sys.exit("YAML input needs PyYAML; or pipe `kubectl get ingress -A -o json`")
        docs = []
        for d in yaml.safe_load_all(text):
            if d and d.get("kind") == "List":
                docs.extend(d.get("items", []))
            elif d:
                docs.append(d)
    return [d for d in docs if d.get("kind", "Ingress") == "Ingress"]


def ingress_class(ing):
    spec = ing.get("spec") or {}
    ann = (ing.get("metadata") or {}).get("annotations") or {}
    return spec.get("ingressClassName") or ann.get("kubernetes.io/ingress.class", "")


def analyse(ing, internal_classes):
    md = ing.get("metadata") or {}
    ann = md.get("annotations") or {}
    findings = []

    def add(verdict, key, target):
        findings.append({"verdict": verdict, "item": key, "agc": target})

    cls = ingress_class(ing)
    if cls in internal_classes:
        add("blocker", f"class {cls}", "AGC frontends are public only today; keep App Routing/Istio internal gateway or AppGW v2")

    use_regex = ann.get(P + "use-regex") == "true"
    for k, v in sorted(ann.items()):
        if not k.startswith(P):
            continue
        s = k[len(P):]
        if s == "use-regex":
            continue
        if s == "rewrite-target":
            if CAPTURE.search(v):
                add("manual", k, "capture groups: rewrite as URLRewrite ReplacePrefixMatch if the regex is really a prefix")
            else:
                add("core", k, "URLRewrite ReplaceFullPath/ReplacePrefixMatch")
            continue
        verdict, target = RULES.get(s, ("manual", "unknown annotation: review"))
        add(verdict, k, target)

    for rule in (ing.get("spec") or {}).get("rules") or []:
        for p in ((rule.get("http") or {}).get("paths")) or []:
            path = p.get("path", "/")
            if (use_regex or p.get("pathType") == "ImplementationSpecific") and REGEX_CHARS.search(path):
                add("manual", f"path {path}", "AGC supports Exact/PathPrefix only: reduce to prefix or split routes")
            for port in [((p.get("backend") or {}).get("service") or {}).get("port") or {}]:
                if not port:
                    add("manual", f"path {path}", "non-Service backend: AGC routes to Services only")

    worst = max((f["verdict"] for f in findings), key=RANK.get, default="core")
    return {
        "namespace": md.get("namespace", "default"),
        "name": md.get("name"),
        "class": cls,
        "verdict": worst,
        "findings": findings,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="file with Ingress YAML/JSON, or '-' for stdin")
    ap.add_argument("--format", choices=["md", "json"], default="md")
    ap.add_argument("--internal-class", action="append", default=[],
                    help="ingress classes served by an internal (private) load balancer")
    ap.add_argument("--all-classes", action="store_true", help="include non-nginx ingress classes")
    a = ap.parse_args()

    results = [analyse(i, set(a.internal_class)) for i in load(a.input)
               if a.all_classes or ingress_class(i) in LEGACY_CLASSES | set(a.internal_class)]
    summary = {v: sum(r["verdict"] == v for r in results) for v in RANK}

    if a.format == "json":
        json.dump({"summary": summary, "ingresses": results}, sys.stdout, indent=2)
        print()
    else:
        print("| Ingress | Class | Ingress verdict | Item verdict | Item | AGC equivalent |")
        print("|---|---|---|---|---|---|")
        for r in results:
            ref = f"{r['namespace']}/{r['name']}"
            for f in r["findings"] or [{"verdict": "core", "item": "-", "agc": "plain host/path routing"}]:
                item = f["item"].replace("|", "\\|")
                print(f"| {ref} | {r['class']} | {r['verdict']} | {f['verdict']} | `{item}` | {f['agc']} |")
        print()
        print("Summary: " + ", ".join(f"{k}={v}" for k, v in summary.items()))
    return 2 if summary["blocker"] else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env bash
# Compare the legacy ingress-nginx endpoint with the new AGC frontend for the same
# Host/paths *before* moving DNS. Uses --resolve/--connect-to so no DNS change is needed.
#
#   ./cutover-check.sh shop.contoso.example <nginx-lb-ip> <agc-frontend-fqdn> / /api/version /admin
#
# Exit 1 if any path differs in status code (or if AGC redirect/TLS behaviour differs).
set -euo pipefail

if [[ $# -lt 4 ]]; then
  echo "usage: $0 <host> <nginx-ip> <agc-fqdn> <path> [path...]" >&2
  exit 64
fi

host=$1 nginx_ip=$2 agc_fqdn=$3
shift 3

probe() { # <connect-to target> <scheme> <path> -> "code size redirect"
  local target=$1 scheme=$2 path=$3 port=443
  [[ $scheme == http ]] && port=80
  curl -sk -o /dev/null --max-time 10 \
    --connect-to "${host}:${port}:${target}:${port}" \
    -w '%{http_code} %{size_download} %{redirect_url}' \
    "${scheme}://${host}${path}" || echo "000 0 -"
}

fail=0
printf '%-8s %-24s %-22s %-22s %s\n' SCHEME PATH NGINX AGC RESULT
for path in "$@"; do
  for scheme in http https; do
    old=$(probe "$nginx_ip" "$scheme" "$path")
    new=$(probe "$agc_fqdn" "$scheme" "$path")
    read -r oc _ ol <<<"$old"
    read -r nc _ nl <<<"$new"
    verdict=OK
    # 301 vs 308 for http->https is an accepted, intentional difference.
    if [[ $scheme == http && $oc =~ ^30[1278]$ && $nc =~ ^30[1278]$ ]]; then
      [[ ${ol:-} == "${nl:-}" ]] || verdict="DIFF(location)"
    elif [[ $oc != "$nc" ]]; then
      verdict="DIFF(status)"
    fi
    [[ $verdict == OK ]] || fail=1
    printf '%-8s %-24s %-22s %-22s %s\n' "$scheme" "$path" "$oc" "$nc" "$verdict"
  done
done

# TLS sanity on the new frontend: protocol floor from FrontendTLSPolicy 2023-06-S.
if curl -sk -o /dev/null --max-time 10 --tls-max 1.1 \
  --connect-to "${host}:443:${agc_fqdn}:443" "https://${host}/" 2>/dev/null; then
  echo "WARN: AGC accepted TLS <= 1.1 for ${host}"
  fail=1
else
  echo "TLS <= 1.1 rejected on AGC: OK"
fi

exit "$fail"

#!/usr/bin/env bash
# ============================================================
#  test-docker-install.sh
# ============================================================
# Container-based verification of the Docker install guide in
# ../data-pipeline-doctor.sh.
#
# For each base image we:
#   1. mount the doctor script read-only inside the container,
#   2. source it (the entry point is guarded, so no menu launches),
#   3. run _dpd_detect_os and assert the detected family is correct,
#   4. run the matching dpd_install_<family> function with
#      DPD_INSTALL_TEST=1 so the systemctl/usermod tail is skipped,
#   5. assert the docker client binary is present afterwards.
#
# KNOWN LIMITATION: starting dockerd inside an unprivileged, non-systemd
# container is not possible, so the daemon-start step (systemctl enable
# --now docker) is intentionally NOT exercised here. We verify OS
# detection + repo setup + docker package installation only.
#
# This script is repo-only — it is NOT shipped to Data Pipeline nodes.
#
# Usage:
#   tests/test-docker-install.sh                 # run all images
#   tests/test-docker-install.sh ubuntu:22.04    # run one image (by name)
# ============================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCTOR="$SCRIPT_DIR/../data-pipeline-doctor.sh"

if [[ ! -f "$DOCTOR" ]]; then
    echo "FATAL: cannot find data-pipeline-doctor.sh at $DOCTOR" >&2
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "FATAL: Docker daemon not reachable — this harness needs Docker on the host." >&2
    exit 1
fi

# ------------------------------------------------------------
# Corporate TLS-intercepting proxy support (e.g. Zscaler).
# Some networks MITM outbound TLS. Base images won't trust the proxy's
# root CA, so package mirrors (notably cdn.amazonlinux.com) fail with
# "unable to get local issuer certificate". This is an environment
# artifact, NOT a bug in the install logic — on a real node the proxy CA
# is already trusted. To exercise the *unmodified* install commands, we
# grab whatever cert chain the proxy presents for a package mirror and
# inject it into each container's trust store before installing.
# Vendor-neutral: if there's no proxy, the grabbed chain is the real one
# and injecting it is harmless.
PROXY_CHAIN=""
if command -v openssl >/dev/null 2>&1; then
    PROXY_CHAIN="$(mktemp -t dpd-proxy-ca.XXXXXX)"
    openssl s_client -showcerts -connect cdn.amazonlinux.com:443 \
        -servername cdn.amazonlinux.com </dev/null 2>/dev/null \
        | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' > "$PROXY_CHAIN" || true
    if [[ -s "$PROXY_CHAIN" ]]; then
        echo "Detected outbound TLS chain ($(grep -c 'BEGIN CERT' "$PROXY_CHAIN") certs) — will trust it inside test containers."
    else
        rm -f "$PROXY_CHAIN"; PROXY_CHAIN=""
    fi
fi
trap '[[ -n "$PROXY_CHAIN" ]] && rm -f "$PROXY_CHAIN"' EXIT

# image | expected family | install fn
IMAGES=(
    "ubuntu:22.04|debian|dpd_install_debian"
    "ubuntu:24.04|debian|dpd_install_debian"
    "debian:12|debian|dpd_install_debian"
    "rockylinux:9|rhel|dpd_install_rhel"
    "almalinux:9|rhel|dpd_install_rhel"
    "quay.io/centos/centos:stream9|rhel|dpd_install_rhel"
    "redhat/ubi9:latest|rhel|dpd_install_rhel"
    "amazonlinux:2|amazon|dpd_install_amazon"
    "amazonlinux:2023|amazon|dpd_install_amazon"
)

# Optional single-image filter
FILTER="${1:-}"

# The script that runs INSIDE each container.
#   $1 = expected family   $2 = install function name
read -r -d '' IN_CONTAINER <<'EOS' || true
set -uo pipefail
expected_family="$1"; install_fn="$2"

# Trust the host's outbound TLS chain if it was mounted (corporate proxy).
if [[ -s /tmp/proxy-ca.pem ]]; then
    if command -v update-ca-trust >/dev/null 2>&1; then          # rhel / amazon
        cp /tmp/proxy-ca.pem /etc/pki/ca-trust/source/anchors/dpd-proxy.pem
        update-ca-trust 2>/dev/null || true
    elif command -v update-ca-certificates >/dev/null 2>&1; then # debian
        mkdir -p /usr/local/share/ca-certificates
        cp /tmp/proxy-ca.pem /usr/local/share/ca-certificates/dpd-proxy.crt
        update-ca-certificates 2>/dev/null || true
    else
        cp /tmp/proxy-ca.pem /etc/pki/ca-trust/source/anchors/dpd-proxy.pem 2>/dev/null || true
    fi
fi

source /dpd.sh || { echo "RESULT: FAIL (could not source doctor script)"; exit 1; }

_dpd_detect_os
echo "DETECTED: family=$DPD_OS_FAMILY id=$DPD_OS_ID ver=$DPD_OS_VER"
if [[ "$DPD_OS_FAMILY" != "$expected_family" ]]; then
    echo "RESULT: FAIL (family mismatch: got '$DPD_OS_FAMILY', want '$expected_family')"
    exit 1
fi

# Run the install (DPD_INSTALL_TEST=1 skips the systemctl/usermod tail).
# 'yes' answers the confirm() prompt inside docker_install_guide if used;
# here we call the install fn directly so no prompt is involved.
if ! "$install_fn"; then
    echo "RESULT: FAIL ($install_fn returned non-zero)"
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "RESULT: FAIL (docker binary not present after install)"
    exit 1
fi
echo "DOCKER_VERSION: $(docker --version 2>/dev/null || echo unknown)"
echo "RESULT: PASS"
EOS

pass=0; fail=0
declare -a SUMMARY=()

run_one() {
    local entry="$1"
    local img="${entry%%|*}"
    local rest="${entry#*|}"
    local fam="${rest%%|*}"
    local fn="${rest##*|}"

    echo
    echo "============================================================"
    echo "  Testing: $img   (expect family=$fam → $fn)"
    echo "============================================================"

    local out rc ca_mount=()
    [[ -n "$PROXY_CHAIN" ]] && ca_mount=(-v "$PROXY_CHAIN:/tmp/proxy-ca.pem:ro")
    out=$(docker run --rm \
        -v "$DOCTOR:/dpd.sh:ro" \
        ${ca_mount[@]+"${ca_mount[@]}"} \
        -e DPD_INSTALL_TEST=1 \
        "$img" \
        bash -c "$IN_CONTAINER" _ "$fam" "$fn" 2>&1)
    rc=$?

    echo "$out"

    if [[ $rc -eq 0 ]] && grep -q "RESULT: PASS" <<<"$out"; then
        pass=$((pass+1)); SUMMARY+=("PASS  $img")
    else
        fail=$((fail+1)); SUMMARY+=("FAIL  $img")
    fi
}

for entry in "${IMAGES[@]}"; do
    img="${entry%%|*}"
    if [[ -n "$FILTER" && "$img" != "$FILTER" ]]; then continue; fi
    run_one "$entry"
done

echo
echo "============================================================"
echo "  SUMMARY"
echo "============================================================"
for line in "${SUMMARY[@]}"; do echo "  $line"; done
echo "------------------------------------------------------------"
echo "  $pass passed, $fail failed"
echo "  NOTE: daemon-start (systemctl) is not exercised in containers;"
echo "        this verifies OS detection + repo setup + package install."
echo "============================================================"

[[ $fail -eq 0 ]]

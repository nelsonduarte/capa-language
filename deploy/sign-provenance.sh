#!/usr/bin/env bash
# sign-provenance.sh
#
# End-to-end example of emitting a SLSA Build L1 provenance
# attestation from a Capa file and signing it with cosign,
# which lifts the artefact to SLSA Build L2 (signed provenance).
#
# Capa stays independent of any specific signing service: the
# language emits the standard in-toto Statement v1 + SLSA
# Provenance v1.0 envelope, and any cosign / sigstore / minisign
# tooling can sign it. This script uses cosign in its simplest
# keypair-based mode.
#
# Usage:
#   ./deploy/sign-provenance.sh path/to/program.capa
#
# Requirements:
#   - capa CLI on PATH (or python -m capa)
#   - cosign installed (https://docs.sigstore.dev/cosign/installation/)
#   - a cosign keypair at $COSIGN_KEY (defaults to ./cosign.key)
#
# Output (written next to the input file):
#   program.capa.provenance.json    the unsigned attestation
#   program.capa.provenance.json.sig  the cosign signature
#   program.capa.provenance.json.cert  the cosign-issued certificate
#                                     (when using Sigstore keyless)

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "usage: $0 <program.capa>" >&2
    exit 2
fi

INPUT="$1"
COSIGN_KEY="${COSIGN_KEY:-./cosign.key}"

if [ ! -f "$INPUT" ]; then
    echo "sign-provenance: input not found: $INPUT" >&2
    exit 2
fi

if ! command -v cosign >/dev/null 2>&1; then
    cat >&2 <<EOF
sign-provenance: cosign is not on your PATH.
                 Install it from https://docs.sigstore.dev/cosign/installation/
                 or via your package manager (brew, apt, choco).
EOF
    exit 2
fi

# 1. Generate the SLSA Build L1 provenance attestation.
PROVENANCE="${INPUT}.provenance.json"
echo "sign-provenance: emitting provenance to $PROVENANCE"
if command -v capa >/dev/null 2>&1; then
    capa --provenance "$INPUT" > "$PROVENANCE"
else
    python -m capa --provenance "$INPUT" > "$PROVENANCE"
fi

# 2. Sign it. Three modes:
#    (a) Keypair-based: signs with $COSIGN_KEY.
#    (b) Keyless (Sigstore): cosign sign-blob --yes "$PROVENANCE"
#        Requires browser-based OIDC, certificate transparency log.
#    (c) Air-gapped: cosign sign-blob --key file://"$COSIGN_KEY"
#        Standard for offline / private deployments.
#
# This script uses mode (c) by default; flip to keyless for
# Sigstore-backed public-chain signing.
echo "sign-provenance: signing with $COSIGN_KEY"
if [ ! -f "$COSIGN_KEY" ]; then
    cat >&2 <<EOF
sign-provenance: cosign key not found at $COSIGN_KEY.
                 Generate one with:
                     cosign generate-key-pair
                 or set COSIGN_KEY to point at an existing private key.
EOF
    exit 2
fi

cosign sign-blob \
    --key "$COSIGN_KEY" \
    --output-signature "${PROVENANCE}.sig" \
    --yes \
    "$PROVENANCE"

echo "sign-provenance: signed."
echo "sign-provenance:   attestation: $PROVENANCE"
echo "sign-provenance:   signature:   ${PROVENANCE}.sig"

# 3. Verification step (sanity check).
echo "sign-provenance: verifying..."
cosign verify-blob \
    --key "${COSIGN_KEY}.pub" \
    --signature "${PROVENANCE}.sig" \
    "$PROVENANCE"

echo "sign-provenance: ok. The attestation is now SLSA Build L2"
echo "                 (provenance generated, distributed, and signed)."

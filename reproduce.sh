#!/usr/bin/env bash
# GF-V1 Stage 11 — one-shot reproduction pipeline.
#
# The public bsc-dataseed full nodes serve historical state only for a few
# minutes, so the anchor, the payload generation and the Foundry run must
# execute back-to-back. This script chains them.
#
# Requirements:
#   - foundry (forge) on PATH
#   - python3 with pycryptodome (for the anchor script)
#   - BSC_REPO env var pointing at a bnb-chain/bsc @ 947ba1c checkout
#     (with CGO-capable Go; used for the payload generator)
set -euo pipefail
cd "$(dirname "$0")"

RPC="${FORK_RPC:-https://bsc-dataseed.bnbchain.org}"
BSC_REPO="${BSC_REPO:?set BSC_REPO to your bnb-chain/bsc checkout}"

echo "[1/3] re-anchoring live state (read-only RPC: $RPC)"
S11_RPC="$RPC" python3 scripts/s11_reanchor.py

echo "[2/3] generating attack payloads"
(cd "$BSC_REPO" && CGO_ENABLED=1 go run ./cmd/gfpayload)

echo "[3/3] Foundry mainnet-fork tests"
cd bnb_submission_gfv1_foundry
FORK_RPC="$RPC" forge test -vvvv

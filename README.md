# GF-V1 — Foundry mainnet-fork PoC + Go real-precompile oracle

**Internal Threshold Inconsistency in GnfdLightClient Skip Path** — 50% validator
coalition takes over the bridge trust root and drains the BSC TokenHub vault
(10,748.4947 of 10,748.4958 BNB in the executed run).

Read `REPORT.md` first — especially **§6.1 (the precompile disclosure)**: Foundry's
EVM does not implement BSC's chain-specific precompiles 0x66/0x67, so the fork test
bridges them with disclosed Solidity implementations whose cryptographic verdicts
are bound to the Go oracle that executed the REAL precompiles on the identical
inputs.

## What was executed (final coherent run, 2026-10-22 19:20 UTC)

| Layer | Command | Result |
|---|---|---|
| Foundry fork (Layer 1) | `forge test -vvvv` | **5/5 PASS** — full attack + 4 controls on a BSC mainnet fork at block 129,184,839 |
| Go oracle (Layer 2) | `go test ./consensus/parlia/ -run 'TestP5S2_GFV1_GoOracle' -v -count=1` | **PASS** — real precompiles 0x66/0x67 on the deployed bytecode, identical payloads; drain figures byte-identical to Layer 1 |

Both layers drained **10,748,494,735,067,211,401,699 wei**; TokenHub residual
**9.75×10¹⁴ wei**; RelayerHub received 2 relay fees credited to the attacker's own relayer.

## Requirements

- [Foundry](https://getfoundry.sh) (`foundryup`; forge 1.8.6 used)
- Go 1.25+ with CGO (for the generator and the oracle; needs a
  `bnb-chain/bsc @ 947ba1c` checkout with `testdata/p5s1/` runtime hexes —
  `go_oracle/` here documents the placement)
- A BSC mainnet RPC. Default: `https://bsc-dataseed.bnbchain.org`
  (override with `FORK_RPC=...`)

## Important: state retention on public full nodes

The public `bsc-dataseed` full nodes serve historical state only for a very
recent window (measured < ~3 minutes at time of work). The shipped
`reanchor.json` + `payloads.json` pair therefore documents the executed run;
to re-run against today's chain you must regenerate first (the whole pipeline
takes ~40 seconds and is chained by `reproduce.sh`):

```bash
./reproduce.sh
```

which runs, in order:

```bash
python3 scripts/s11_reanchor.py            # 1. read-only re-anchor -> reanchor.json
(cd $BSC_REPO && CGO_ENABLED=1 go run ./cmd/gfpayload)  # 2. payloads.json
(cd bnb_submission_gfv1_foundry && forge test -vvvv)    # 3. mainnet-fork tests
```

## Directory map

```
REPORT.md                    this report
README.md                    this file
reproduce.sh                 one-shot pipeline (anchor -> generate -> forge test)
reanchor.json                raw RPC state dump at the anchor block (provenance)
payloads.json                exact attack payloads + expected values (copy also in foundry test/)
oracle_output.json           Go-oracle capture (real precompile outputs; payloadsSha-bound)
bnb_submission_gfv1_foundry/ Layer 1 — Foundry project (forks mainnet)
  foundry.toml               rpc endpoint, via_ir, fs_permissions
  src/PB.sol                 minimal protobuf wire-format reader (cometbft fork protos)
  src/BridgeCometBFTValidate.sol  disclosed 0x67 bridge (semantics + oracle binding)
  src/BridgeBLSVerify.sol    disclosed 0x66 bridge (format + oracle binding)
  test/GFV1.t.sol            the 5 tests (attack + controls; see REPORT.md §6.2)
  test/payloads.json         consumed by the tests (also at package root)
  test/reanchor.json         consumed by the tests (also at package root)
cmd/generate_payloads/main.go  Go payload generator (place in bsc repo to run)
go_oracle/p5s2_oracle_test.go  Go oracle test (place in bsc repo consensus/parlia/)
go_oracle/testdata/p5s1/*.hex   deployed mainnet runtime bytecode (sha256-anchored in reanchor.json)
scripts/s11_reanchor.py      read-only live-state re-anchoring
logs/                        verbatim outputs of the final coherent run
```

## The five Foundry tests

1. `test_01_deployedContract_rejectsTwoOfFourCountQuorum` — no scaffolding at
   all: the deployed contract's own 75%-count package quorum, proven on
   unmodified mainnet fork state.
2. `test_02_full_attack_drains_tokenhub` — the attack: 2-colluder collusion
   simulation (vm.store of two tracked-set slots) → skip-path `syncLightBlock`
   at H0+2 → forged packages → vault drain → 12 h warp → withdraw.
3. `test_03_control_adjacent_height_rejected` — the same phantom at H0+1 is
   rejected by `nextValidatorSetHash` pinning.
4. `test_04_control_single_colluder_rejected` — one colluder (25% power) is
   rejected by the 1/3 trust level.
5. `test_05_control_no_collusion_rejected` — the real tracked set rejects the
   phantom commit (0 tallied power).

## Go oracle placement (Layer 2)

```bash
# inside your bnb-chain/bsc @ 947ba1c checkout:
cp <this-package>/go_oracle/p5s2_oracle_test.go consensus/parlia/
cp <this-package>/cmd/generate_payloads/main.go (into cmd/gfpayload/main.go)
mkdir -p consensus/parlia/testdata/p5s1
cp <this-package>/go_oracle/testdata/p5s1/*.hex consensus/parlia/testdata/p5s1/
export GF_ANCHOR=<this-package>/reanchor.json
CGO_ENABLED=1 go test ./consensus/parlia/ -run 'TestP5S2_GFV1_GoOracle' -v -count=1
```

The oracle asserts, against the REAL precompiles: no-collusion / single-colluder /
adjacent-height rejections with exact reasons, MAIN acceptance at 50% power with
byte-identical output capture, real-0x66 verdicts on both packages, and the full
takeover + drain + withdraw flow.

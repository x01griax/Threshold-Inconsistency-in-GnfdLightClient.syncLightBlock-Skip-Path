# Internal Threshold Inconsistency in GnfdLightClient Skip Path Allows 50% Validator Coalition to Drain the BSC TokenHub Vault

**Program:** BNB Chain Bug Bounty
**Target:** Greenfield↔BSC cross-chain bridge (deployed mainnet bytecode)
**Severity (researcher's own calibration):** Critical — full drainage of the BSC-side bridge vault (10,748+ BNB at time of reporting) by a 2-of-4 validator coalition. See §8 for the honest case-against, §9 for the dedicated CometBFT trust-model objection and the calibrated defect framing.
**Report date:** 2026-10-23
**PoC format:** Foundry mainnet-fork test (per program requirements), cross-validated by a Go harness that executes the **real BSC precompiles 0x66/0x67** on the identical inputs. `reanchor.json` (the raw RPC state dump) is included in this package to prove the live state.
**Researcher stance:** independent security researcher; all analysis read-only; no transaction was ever sent to mainnet or testnet — every execution below ran locally: the Foundry test against a **mainnet fork** at a pinned block, and the Go oracle against the exact deployed mainnet bytecode, both fetched read-only.

---

## 1. Summary

The BSC side of the Greenfield↔BSC bridge enforces **two mutually inconsistent thresholds over the same trust domain**:

1. **The package-attestation path** — the bridge's own statement of how much validator agreement a cross-chain effect requires — demands **3-of-4 validators by COUNT (75%)**. In `GnfdLightClient.verifyPackage`, a package is only valid if it carries a BLS aggregate signature from validators whose count satisfies `bitCount > (validatorSet.length * 2) / 3` (GnfdLightClient.sol, line 138), verified by BSC precompile 0x66 (`blsSignatureVerify` / `FastAggregateVerify`).

2. **The sibling light-client sync path** in the same contract — `GnfdLightClient.syncLightBlock` — hands over the **entire attestation trust root** (the tracked validator set, every validator's BLS vote key and relayer address, `gnfdHeight`, and the `nextValidatorSetHash` pin) for **2-of-4 validators by POWER (50%)** whenever the submitted light block is non-adjacent to the tracked height ("skip path"). The skip path is verified by BSC precompile 0x67 (`cometBFTLightBlockValidatePasteur` → `ApplyLightBlock` → `VerifyCommitLightTrusting` at cometbft's `light.DefaultTrustLevel` = **1/3 of tracked voting power**, plus `VerifyCommitLight` at 2/3 of the *attacker-chosen new set*), and — unlike the adjacent path — **does not check `nextValidatorSetHash` at all**.

On the live tracked validator set (4 validators × 1,000 power, equal powers, anchored at block 129,184,839 with the raw dump included as `reanchor.json`), the skip path therefore accepts **exactly half the coalition** that the package path demands. A 2-validator coalition can replace the tracked set with attacker-controlled entries, after which the attacker set signs every package itself — the 75% count quorum becomes attacker-signed theater with zero marginal trust.

**Executed impact (Foundry mainnet-fork PoC + Go-oracle cross-validation):** after the skip-path takeover, forged `TransferInSynPackage`s carrying the attacker set's aggregate BLS signature (bit-set 0b1111, satisfying the 3-of-4 count quorum) drain the BSC-side `TokenHub` vault: a 999 BNB package pays out **immediately**; a 9,749.4947 BNB package (the vault remainder after package 1, its relay fee, and a 1×10¹⁵ wei accounting margin) is time-locked by the live `largeTransferLimit` = 1,000 BNB / `lockPeriod` = 12 h policy and is withdrawn via `TokenHub.withdrawUnlockedToken` after the 12 h window. **Net extraction: 10,748.4947 BNB of the 10,748.4958 BNB vault (99.99999%) — identical to the wei in both the Foundry fork run and the Go real-precompile run.** The uncollected remainder is exact: 9.75×10¹⁴ wei (0.000975 BNB) stays in TokenHub as the intentional accounting margin, and two relay fees (5×10¹³ wei = 0.00005 BNB total) accrue in `RelayerHub` **credited to the attacker's own relayer** and recoverable via `claimReward` — i.e., every practically recoverable wei of the vault is extracted.

Supporting controls, all executed in both PoC layers: the **identical** phantom light block at the *adjacent* height (`gnfdHeight + 1`) is **rejected** by the `nextValidatorSetHash` pinning (direct real-precompile error: `validators hash mismatch`); a **single** colluding validator (25% power) is **rejected** by the 1/3 trusting threshold (real-precompile error: `invalid commit -- insufficient voting power: got 1000, needed more than 1333`); the **unpatched** (no-collusion) tracked set rejects the phantom commit with `got 0, needed more than 1333`; and the deployed contract's own count quorum reverts a 2-of-4 bitset with `no majority validators` **on the unmodified mainnet fork, with no test scaffolding involved at all** (test_01).

---

## 2. Affected contracts (live mainnet; anchored at block 129,184,839; bytecode verified identical to the block-129,168,066 capture)

| Contract (proxy) | Address | EIP-1967 implementation | Runtime code size / sha256 | versionInfo |
|---|---|---|---|---|
| CrossChain | `0x77e719b714be09F70D484AB81F70D02B0E182f7d` | `0xde20f2ec19ed41d61458ceb7d1c5f7ee02285556` | 20,044 B / `546d15de665dc57b835495cfaf8ee562fb09b48fca956c631d57ad4318e2a464` | 200_004 |
| **GnfdLightClient (vulnerable)** | `0x433bB48Bd86c089375e53b2E2873A9C4bC0e986B` | `0x5437783e736382bf4ed8136dcfa13fc3ef5660df` | 10,796 B / `839589ee28749e5a175a6dfd70a59bf074c6fee27373144e4db22233f43a2c98` | 400_002 |
| TokenHub (drained) | `0xeA97dF87E6c7F68C9f95A69dA79E19B834823F25` | `0xac2936ba03f46a6a03ba2245e45e61e1c4ecb22f` | 9,893 B / `e6d26acaa8007989c2ef97d7d1a03b1410b090a3a5d2aaee2d1d656febcd0e56` | 300_004 |
| RelayerHub | `0x31C477F05CE58bB81A9FB4b8c00560f1cBe185d1` | `0x00ea54a82ae011dabfa91811912e66f7be69eb59` | 2,923 B / `1241624f1e3149f9ea83c032e8c737731a3bf107660cce0eefc707487a849d7a` | 500_002 |
| GovHub | `0x1c9766EbcA1f38A06A04947129B394bF7FEc4599` | `0xacc4387e4279a4e6c0647e1f47dc67c258134310` | 6,495 B / `0702fd8287bf3f6566e29f1cedc17c3d91334e0119a026722f4ab6e543c7aeae` | 100_002 |

All five implementations match `bnb-chain/greenfield-contracts` master @ `68e06d0` by `versionInfo` (CrossChain 200_004, GnfdLightClient 400_002, TokenHub 300_004, RelayerHub 500_002). The verification precompiles are BSC system precompiles **0x67** (`cometBFTLightBlockValidatePasteur`, Pasteur-era) and **0x66** (`blsSignatureVerify`), as implemented in `bnb-chain/bsc` @ `947ba1c` (`core/vm/lightclient/v2`).

Live state at the anchor block (full raw dump: `reanchor.json` in this package): tracked validator set = **4 validators × power 1,000** (equal powers); `gnfdHeight` = 37,971,385; `chainID` = `greenfield_1017-1`; TokenHub balance = **10,748,495,760,067,211,401,699 wei (10,748.4958 BNB)**; `channelReceiveSequenceMap[1]` = 2,051; `largeTransferLimit` = 1,000 BNB; `lockPeriod` = 43,200 s; `isSuspended` = false.

---

## 3. Root cause

### 3.1 The two thresholds, side by side

**Path A — package attestation (count-based, 75% on the live set).** `GnfdLightClient.verifyPackage` (GnfdLightClient.sol:121-142):

```solidity
for (uint256 i = 0; i < validatorSet.length; i++) {
    if ((_validatorSetBitMap & (0x1 << i)) != 0) {
        bitCount++;
        input = abi.encodePacked(input, validatorSet[i].relayerBlsKey);
    }
}
require(bitCount > (validatorSet.length * 2) / 3, "no majority validators");  // line 138
(bool success, bytes memory result) = PACKAGE_VERIFY_CONTRACT.staticcall(input); // precompile 0x66
```

For the live N=4 tracked validators this requires **bitCount ≥ 3** (3-of-4 = 75% by count), with a valid BLS aggregate signature from exactly those validators over `keccak256(payload)`.

**Path B — light-client sync, skip branch (power-based, >1/3 of tracked power).** `GnfdLightClient.syncLightBlock` (GnfdLightClient.sol:89-119) forwards `consensusStateBytes || lightBlock` to precompile 0x67, which decodes and calls `ApplyLightBlock` (`bsc/core/vm/lightclient/v2/lightclient.go:162-210`):

```go
if cs.Height == uint64(block.Height-1) {
    // ADJACENT path: the new set must be the pinned successor
    if !bytes.Equal(cs.NextValidatorSetHash, block.ValidatorsHash) {
        return false, fmt.Errorf("validators hash mismatch, ...")
    }
    err := block.ValidatorSet.VerifyCommitLight(...)           // 2/3 of the OLD set
} else {
    // SKIP path (>1 block gap): NO nextValidatorSetHash check
    err := cs.ValidatorSet.VerifyCommitLightTrusting(cs.ChainID, block.Commit, light.DefaultTrustLevel) // >1/3 of OLD power
    if err != nil { return false, err }
    err = block.ValidatorSet.VerifyCommitLight(...)            // 2/3 of the NEW (attacker-chosen) set
}
// on success: cs.Height, cs.NextValidatorSetHash, cs.ValidatorSet = attacker-controlled
```

The skip branch requires:
- `VerifyCommitLightTrusting` at `light.DefaultTrustLevel` = `Fraction{1, 3}` → strictly more than **1,333 of the 4,000 tracked voting power** (two colluding validators at 1,000 each = 2,000 → passes), and
- `VerifyCommitLight` at 2/3 of the **new** set's power — a set the attacker constructs, so the attacker's own keys supply the remaining signatures.

Nothing in the skip branch constrains the new set to the pinned successor: `cs.NextValidatorSetHash` is only *read* on the adjacent branch; on the skip branch it is simply **overwritten** with the attacker's set hash (lightclient.go:201).

### 3.2 The internal inconsistency

Both paths gate changes to the *same* trust domain — the set of keys whose BLS signatures authorize cross-chain effects on BSC:

| | Package path (`verifyPackage`) | Skip path (`syncLightBlock`, non-adjacent) |
|---|---|---|
| What it authorizes | One cross-chain package | The entire trust root: validator set, BLS vote keys, relayer map, `gnfdHeight`, `nextValidatorSetHash` |
| Threshold basis | **COUNT** of tracked validators | **POWER** of tracked validators |
| Required on live set | **3-of-4 (75%)** | **>1/3 power → 2-of-4 (50%)** |
| Set-choice constraint | n/a (fixed tracked set) | **None** — attacker-chosen new set, no pinning |
| Suspension gate | `whenNotSuspended` (via `handlePackage`) | **none** (`syncLightBlock` has no `whenNotSuspended`) |

A change that Path A would price at 75% by count can be obtained through Path B for 50% by power. Once Path B hands over the root, Path A's quorum is evaluated against the attacker's set — the attacker signs with all 4 attacker keys (bit-set 0b1111), and every subsequent "75%-attested" package is forged by the coalition alone.

### 3.3 Why the skip branch is the defect locus (design-intent evidence)

The adjacent branch's `nextValidatorSetHash` pinning shows the design intent: *validator-set changes must flow through pinned successors committed by the previous set*. The skip branch bypasses exactly that pinning while performing exactly the operation the pinning protects (a validator-set replacement). The inconsistency is not between the bridge and some external standard, but **inside the bridge's own two verification paths deployed by the same upgrade** — the same contract that demands 75% count for a single package transfer accepts 50% power for the keys that validate all packages.

---

## 4. Impact

- **Full drainage of the BSC-side bridge vault.** Executed in both PoC layers: 10,748.4947 of 10,748.4958 BNB (99.99999%) extracted. At time of reporting the vault holds the bulk of BSC-side liquidity backing Greenfield↔BSC transfers of BNB.
- **Unlimited forged attestations post-takeover.** The attacker set can mint any valid package (transfers-in, channel updates on the gov channel, multi-message batches). The PoC exercises the transfer-in path; the same signature authority extends to every handler reachable through `handlePackage`.
- **Mitigation asymmetry (runtime-observed):** emergency `CrossChain.suspend()` requires the same relayer class that is complicit; `syncLightBlock` is **not** gated by `whenNotSuspended`, so a suspension cannot block the takeover itself, only later `handlePackage` submissions; and the relayer map is rewritten by the takeover (all four honest relayers are unmapped; attacker relayers are mapped).
- **12 h lock is a delay, not a defense:** transfers ≥ 1,000 BNB are locked and withdrawn via `withdrawUnlockedToken` after the window; sub-1,000 BNB packages pay out immediately and can be batched arbitrarily (the PoC demonstrates both).
- **Additional DoS primitive observed during earlier testing (lower severity, included for completeness):** pre-takeover, any 2 of the 4 validator relayers can pass the `cancelTransfer` proposal quorum to `cancelTransferIn`, which **burns** (not refunds) a victim's locked transfer-in — a loss-of-funds vector for user locks that does not require the full takeover (executed in the Stage-10 Go harness; source included).

**Coalition required:** any 2 of the 4 live tracked validators (their ed25519 consensus keys sign a phantom commit), plus one currently-registered relayer EOA to submit `syncLightBlock` (each validator's own relayer qualifies). On the live equal-power set this is 50% of tracked power and 50% of tracked count.

---

## 5. Attack prerequisites (what an attacker needs on mainnet today)

1. **Coalition:** any 2 of the 4 live tracked validators (their ed25519 consensus keys), plus one currently-registered relayer address (each validator's own relayer qualifies) to submit `syncLightBlock`.
2. **Phantom cometbft light block:** proto `LightBlock`, chainID `greenfield_1017-1`, height = current `gnfdHeight` + 2 (any gap ≥ 2), `Validators` = `NextValidators` = the attacker set (entries may reuse the colluders' ed25519 keys while substituting attacker BLS keys and relayer addresses), all `ValidateBasic` fields valid; the commit is signed by the 2 colluders plus enough attacker keys to reach 2/3 of the new set's power.
3. **Sync:** `GnfdLightClient.syncLightBlock(lbBytes, gnfdHeight+2)` from a registered relayer EOA. Note: no `whenNotSuspended` gate on this function.
4. **Forged packages:** `CrossChain.handlePackage(payload, aggBlsSig, bitSet)` with payload `src=1017, dst=56, ch=1, seq=channelReceiveSequenceMap[1]` (2,051 at the anchor, i.e., the next expected sequence), `type=0x00` (SYN), `eventTime` ≥ 30 s stale (satisfies the non-in-turn relayer timing branch), `relayFee` ≤ 1 BNB, load = `abi.encode(uint256 amount, address recipient, address refundAddr)`; bit-set 0b1111 with the aggregate BLS signature over `keccak256(payload)` from the attacker set's keys.
5. **Amounts:** < 1,000 BNB per package → immediate payout; ≥ 1,000 BNB → 12 h lock → `withdrawUnlockedToken(recipient)`.

No greenfield-side cooperation is required: nothing on the BSC side queries Greenfield for the block's existence — the commit is only signatures over canonical `VoteSignBytes`, which the colluders produce.

---

## 6. Proof of Concept

The PoC has **two layers that must be read together** (a tooling constraint of the BSC precompiles, disclosed up front in §6.1):

- **Layer 1 — Foundry mainnet fork (`bnb_submission_gfv1_foundry/`)**: a `forge test` suite that forks BSC mainnet at the anchor block and reproduces the entire attack against the **real deployed contracts and real chain state** (real validator set, real TokenHub balance, real sequences). This is the program-required PoC format.
- **Layer 2 — Go oracle (`go_oracle/` + `oracle_output.json`)**: a Go harness that executes the **exact deployed mainnet bytecode** with the **real BSC system precompiles 0x66/0x67 active** (`bnb-chain/bsc` `core/vm`, `params.BSCChainConfig`), on the **identical attack payloads**, capturing the real precompiles' exact outputs and verdicts. This layer is the execution-level ground truth that binds Layer 1's precompile bridge (§6.1).

Both layers produced byte-identical results on the final run: takeover at `gnfdHeight+2` with 2,000/4,000 tracked power, and a drain of 10,748,494,735,067,211,401,699 wei.

### 6.1 The precompile disclosure (read this first)

Foundry's fork EVM (upstream revm) **does not implement BSC's chain-specific precompiles 0x66/0x67** — this was verified empirically at the start of this work: on a stock foundry fork of BSC mainnet, low-level calls to 0x66 and 0x67 with garbage input **succeed with empty returndata** (empty-account behavior), while the same calls against a real BSC node **revert** (`execution reverted` — active precompile). Consequently, *any* Foundry fork test of this bridge would fail at GnfdLightClient's `require(success && result.length > 0, "header validate failed")` even for legitimate traffic — not because the attack fails, but because Foundry cannot execute BSC precompiles at all.

The PoC therefore bridges the two precompiles with two **auditable, disclosed Solidity contracts** (`src/BridgeCometBFTValidate.sol`, `src/BridgeBLSVerify.sol`), installed at 0x67/0x66 via `vm.etch`:

- **BridgeCometBFTValidate (0x67)** re-implements the precompile's *verification semantics from first principles*: full input parsing (`32B csLen || consensus state || LightBlock`), cometbft protobuf parsing of the LightBlock, chain-id and height gating, the **adjacent-path `nextValidatorSetHash` pinning**, the **skip-path `VerifyCommitLightTrusting` power math against the tracked set (trust level 1/3, address lookup via `sha256(ed25519 pubkey)[:20]`, double-vote guard)**, the `VerifyCommitLight` power math against the new set (2/3, by index), the validator-uniqueness checks, and the exact `EncodeLightBlockValidationResult` output derivation.
- **BridgeBLSVerify (0x66)** mirrors the real precompile's input-format contract and return conventions (`0x01` on success, empty on failure).
- The **only** thing not re-implemented in Solidity is the cryptographic signature validity itself (ed25519 commit signatures / BLS12-381 FastAggregateVerify). Instead, each bridge enforces a **binding gate**: the exact commit signature set (and each `(msgHash, sig, pubkeys)` triple for 0x66) must match a hash registered from `payloads.json` — and those hashes were produced by **Layer 2, which executed the REAL 0x67/0x66 precompiles on these exact inputs** and recorded the real verdicts in `oracle_output.json` (`precompile067ReturnMain`, `precompile066Verified`; `payloadsSha` in that file matches the shipped `payloads.json` byte-for-byte).

The binding is checked in the OTHER direction too: `test_02` asserts that after the takeover, the light client's `consensusStateBytes()` equals `payloads.json: consensusState.expectedNewAfterSync` — which is the **byte-identical new consensus state the real 0x67 precompile returned in the Go-oracle run** (the Go test asserts this equality against its own captured precompile output before writing it). If the Solidity bridge's derivation deviated from the real precompile by a single byte, the test would fail.

### 6.2 What the Foundry tests prove (5/5 PASS in the final run)

| Test | What it proves | Result |
|---|---|---|
| `test_01_deployedContract_rejectsTwoOfFourCountQuorum` | **The deployed contract's own count quorum on the unmodified mainnet fork** — a `handlePackage` with a 2-of-4 validator bitset reverts `no majority validators` **before any precompile involvement and with no test scaffolding** (no bridges etched, no state touched). This is the bridge's own 75%-count requirement, proven directly on mainnet state. | PASS |
| `test_02_full_attack_drains_tokenhub` | **The full attack on the mainnet fork:** collusion simulated by vm.storing 2 colluder ed25519 consensus pubkeys over tracked validators #0/#1 (the ONLY state manipulation outside deployed code — models possession of two validators' signing keys); `syncLightBlock(phantom, H0+2)` through a real relayer **replaces the tracked set** (asserted validator-by-validator against the declared attacker set); two forged `TransferInSynPackage`s **drain the vault**; 12 h warp + `withdrawUnlockedToken` completes the extraction. Final asserts: attacker balance = 10,748,494,735,067,211,401,699 wei; TokenHub residual = 9.75×10¹⁴ wei; RelayerHub delta = 2 relay fees. | PASS |
| `test_03_control_adjacent_height_rejected` | The identical phantom at `gnfdHeight+1` is rejected: direct bridge probe reverts `validators hash mismatch`; contract-level `syncLightBlock` reverts `header validate failed`; state unchanged. (Mirrors the real precompile's behavior in the Go oracle.) | PASS |
| `test_04_control_single_colluder_rejected` | The identical phantom with only ONE colluder key in the tracked set (25% power): direct bridge probe reverts `invalid commit -- insufficient voting power`; contract-level sync reverts; state unchanged. (The Go oracle's real 0x67 rejects the same input with `insufficient voting power: got 1000, needed more than 1333`.) | PASS |
| `test_05_control_no_collusion_rejected` | The REAL tracked set (no patch at all) rejects the phantom commit (0 tallied power): both the bridge and the Go oracle's real precompile reject. | PASS |

### 6.3 What the Go oracle proves (execution-level ground truth)

`go_oracle/p5s2_oracle_test.go` (run inside `bnb-chain/bsc` @ `947ba1c`, Go 1.25.0, CGO on) executes the deployed bytecode with the real precompiles on the reanchored live state and the identical payloads (`payloadsSha` binding):

1. **Direct 0x67 probes** on the four inputs:
   - no-collusion (real tracked set + phantom commit): **REJECTED** — `invalid commit -- insufficient voting power: got 0, needed more than 1333`;
   - single-colluder (25% power): **REJECTED** — `insufficient voting power: got 1000, needed more than 1333`;
   - adjacent height (H0+1): **REJECTED** — `validators hash mismatch`;
   - **MAIN (50% power, skip height H0+2): ACCEPTED** — and the returned bytes equal, byte-for-byte, the generator's expected new consensus state (`oracle_output.json: precompile067ReturnMain`).
2. **Contract-level takeover + drain through the real precompiles**: `syncLightBlock` succeeds via a real tracked relayer; the tracked set is replaced; both forged packages pass the real 0x66 (`ret = 0x01` each, captured in `precompile066Verified`); the attacker extracts 10,748,494,735,067,211,401,699 wei; TokenHub residual = 9.75×10¹⁴ wei.

The earlier Stage-1/4 harness (shipped as `p5s1_greenfield_bridge_test.go` in the previous submission; 7/7 PASS) additionally covers the non-collusive authorization battery (H-Q1) and the 2-relayer `cancelTransfer` burn — those results carry over unchanged and are summarized in §4.

### 6.4 Attacker-set construction (how one object satisfies both verifiers)

New validator set = `[colluder A ed-key + attacker BLS/relayer, colluder B ed-key + attacker BLS/relayer, attacker key 3, attacker key 4]`, each power 1,000. Commit entries 0/1 are signed by the two colluders' ed25519 keys — these two signatures carry 2,000 of the 4,000 **old** tracked power past the 1,333 (1/3) `VerifyCommitLightTrusting` threshold, and simultaneously count toward the new set's indices in `VerifyCommitLight` (2/3-of-new-set, where entries 2/3 supply the rest with attacker keys). `ValidatorsHash` = `NextValidatorsHash` = hash of this set (satisfies `LightBlock.ValidateBasic`). This is the crux object: one commit, one new set, both thresholds satisfied by a 2-validator coalition.

### 6.5 Reproduction

**Layer 1 (Foundry, primary):**

```bash
cd bnb_submission_gfv1_foundry
forge test -vvvv          # forks BSC mainnet at the block recorded in test/reanchor.json
```

Prerequisites: `foundryup` (forge 1.8.6 used), a BSC mainnet RPC whose node still serves state at the anchored block. **Important:** the public `bsc-dataseed.bnbchain.org` full nodes retain queried state for only a few minutes, so the shipped `reanchor.json`/`payloads.json` pair is historical evidence of the executed run — to re-run against today's chain, regenerate first (the whole pipeline takes ~40 s):

```bash
python3 scripts/s11_reanchor.py              # re-anchor + write reanchor.json (read-only RPC)
(cd <your bnb-chain/bsc clone> && CGO_ENABLED=1 go run ./cmd/gfpayload)   # regenerate payloads.json
cd bnb_submission_gfv1_foundry && forge test -vvvv
```

`reproduce.sh` in this package chains the three steps.

**Layer 2 (Go oracle):** copy `go_oracle/p5s2_oracle_test.go` (and `testdata/` + `cmd/gfpayload/` from this package) into a `bnb-chain/bsc` @ `947ba1c` checkout, then:

```bash
CGO_ENABLED=1 go test ./consensus/parlia/ -run 'TestP5S2_GFV1_GoOracle' -v -count=1
```

### 6.6 Provenance records

- `reanchor.json` — the raw RPC state dump at the anchor block (block number/hash/timestamp, all five proxies + EIP-1967 impl addresses + code sha256, the full tracked validator set with pubkeys/powers/relayers/BLS keys, `consensusStateBytes` raw, `gnfdHeight`, `nextValidatorSetHash`, CrossChain sequences + handler map, TokenHub balance/limits). The test's `setUp` asserts the fork matches this file byte-for-byte before doing anything.
- `payloads.json` — the exact attack payloads (phantom light blocks, forged packages, signatures, calldata) plus every expected value; `sha256 = ddbe669f…` (the `payloadsSha` recorded in `oracle_output.json` matches).
- `oracle_output.json` — the Go oracle's captured real-precompile outputs/verdicts for these exact payloads.
- `logs/forge_final_run.txt`, `logs/go_oracle_final_run.txt` — verbatim outputs of the final coherent run (anchor → generate → oracle → forge test, executed back-to-back at 2026-10-22T19:20Z).

---

## 7. Suggested remediation

1. **Pin the successor on skip syncs too:** reject any `syncLightBlock` whose new `ValidatorSet.Hash()` differs from the tracked `nextValidatorSetHash` unless the transition is proven through a chain of *adjacent* pinned headers (the standard cometbft light-client bisection). The adjacent branch already implements the pinning; the skip branch should not be able to replace the set without it.
2. **Raise/align the trust level with the bridge's own package quorum:** if the package path demands >2/3 by count, the trust-root transfer should demand at least the same fraction by power (e.g., `VerifyCommitLightTrusting` at 2/3, or a bridge-governed `trustLevel`), eliminating the internal inconsistency.
3. **Gate `syncLightBlock` with `whenNotSuspended`** so the emergency suspension path can actually contain a light-client takeover in progress.
4. (Defense-in-depth) On Greenfield-side, monitor `GnfdLightClient.SyncLightBlock` events for non-adjacent heights and validator-set changes that do not match the greenfield-side canonical set; slash-and-coordination response must beat the 12 h lock window for large transfers (immediate payouts below `largeTransferLimit` cannot be clawed back cross-chain).

---

## 8. Honest case-against (mandatory self-assessment)

The strongest arguments **against** this being a valid bounty finding, stated without softening:

1. **1/3 is the standard cometbft/IBC light-client trust level.** `light.DefaultTrustLevel` = `Fraction{1, 3}` is the industry-standard trusting level for skip-period light-client verification — the same default in upstream cometbft and the IBC tendermint light client. Verifying a skip against 1/3 of previously-trusted power is the *documented design* of the cometbft light client, not a coding error. A reviewer can reasonably read this report as "the system works as cometbft specifies."
2. **2-of-4 = 50% exceeds the BFT Byzantine threshold.** The attack requires validator misbehavior (signing a phantom block) by a coalition holding **more than 1/3 of voting power** — beyond what the BFT trust model is designed to tolerate. Under the stated trust assumption (<1/3 Byzantine), the skip path is sound. Our own single-colluder control confirms the mechanism engages exactly at the designed 1/3 boundary (1,000 power rejected; 2,000 passes).
3. **Phantom-block double-signing is slashable on Greenfield post-hoc.** Two validators signing a commit for a height that never finalized constitutes equivocation evidence the Greenfield chain can slash. Counterpoint (for completeness, not advocacy): post-hoc slashing does not recover BSC-side funds — extraction completes within the 12 h lock window (or instantly below 1,000 BNB per package), and no cross-chain clawback of already-paid BNB exists.
4. **Severity tiering risk.** The program's top language reserves the highest tier for actors without special trust ("by anyone", signature-verification flaws exploitable without validator keys). This finding requires a 2-validator coalition — a privileged actor class.

## 9. Addressing the CometBFT trust model objection

A reviewer may note that the 1/3 trust level is standard for CometBFT skip verification, and that a 50% collusion exceeds the <1/3 BFT assumption. However, this finding is **not** about breaking the CometBFT BFT assumption; it is about an **internal contradiction in the bridge's own threshold architecture**.

The bridge's package-attestation path explicitly demands **>2/3 by COUNT (75% for 4 validators)** to authorize a fund transfer. If the bridge's security model was truly governed solely by the 1/3 light-client trust level, it would not have implemented a 75% count quorum for packages. Furthermore, the adjacent-height sync path **does pin `nextValidatorSetHash`**, proving the designers intended to constrain validator set changes. The skip path's failure to pin the successor hash allows a 50% coalition to bypass the bridge's own stated 75% security requirement for moving funds. **This is a defect in the bridge's implementation of the light client, not merely a CometBFT assumption.**

Three additional points sharpen why the "documented CometBFT trust model" reply does not dissolve this finding:

- **The bridge is not a passive consumer of the 1/3 level — it is the relying party that defines what the level protects.** Upstream CometBFT's 1/3 trusting level exists to let a *light client track consensus* under an assumed honest supermajority. Here, the output of that tracking *is* the attestation trust root for a vault holding 10,748+ BNB. The bridge's designers evidently understood the sensitivity: they wrapped the package path in a stricter 75%-by-count quorum of their own. The same contract then lets 50% of power rewrite that quorum's denominator. Whatever CometBFT documents about 1/3, the bridge itself does not treat the tracked set as something 50% of power may replace — the adjacent-path pinning proves it.
- **The inconsistency is executable, not hypothetical.** Both thresholds were exercised against the deployed bytecode: the same coalition (2-of-4) that the package path rejects (`no majority validators`, test_01, on unmodified mainnet state) is accepted by the sibling path for the strictly stronger effect of replacing the entire trust root (test_02). The single-colluder control (25%, rejected by the real precompile with `got 1000, needed more than 1333`) confirms the boundary is the power math, not an artifact.
- **The remediation is local to the bridge.** Raising the bridge's skip-path trust level to 2/3, or requiring pinned-successor bisection on skips, changes nothing about CometBFT's protocol; it aligns the bridge's two internal gates. A defect whose fix is "make the contract consistent with itself" is a defect in the contract.

**Calibrated position.** The defensible framing is not "the 1/3 trust level exists" but "the bridge's two sibling paths implement mutually inconsistent thresholds over the same trust domain": the package-attestation path prices a cross-chain effect at 75% by count, while the skip path sells the keys that define that 75% for 50% by power. After the transfer, the 75% count quorum is satisfied by signatures the coalition itself creates; the package path's stronger threshold is not a defense the system actually has, but a property it only appears to have. Whether triage classifies this as a vulnerability (our reading: an internal threshold inconsistency that collapses the bridge's stated security boundary to half its advertised cost) or as an accepted cometbft-standard trust assumption (the §8 rebuttal) is a judgment we leave to the program with both positions stated.

---

## 10. Files in this submission

| File | Purpose |
|---|---|
| `REPORT.md` | This report |
| `README.md` | How to run both PoC layers locally (environment, commands, expected output) |
| `reproduce.sh` | One-shot pipeline: re-anchor → generate payloads → forge test |
| `reanchor.json` | **Raw RPC state dump at the anchor block** (proves the live state; consumed by the test's setUp and by the generator) |
| `payloads.json` | The exact attack payloads (phantom light blocks, forged packages + BLS signatures, calldata, expected values) — also at `bnb_submission_gfv1_foundry/test/payloads.json` |
| `oracle_output.json` | Go-oracle capture: real 0x67 return bytes, real 0x66 verdicts, takeover/drain results for these exact payloads (`payloadsSha` binds it to `payloads.json`) |
| `bnb_submission_gfv1_foundry/` | **Layer 1**: the Foundry project (foundry.toml, src/PB.sol, src/BridgeCometBFTValidate.sol, src/BridgeBLSVerify.sol, test/GFV1.t.sol, test/*.json, lib/forge-std) |
| `cmd/generate_payloads/main.go` | **Go payload generator** (reads `reanchor.json`, emits `payloads.json`; place in a `bnb-chain/bsc` checkout to run) |
| `go_oracle/p5s2_oracle_test.go` | **Layer 2**: the Go oracle test (real precompiles on the deployed bytecode; place in `consensus/parlia/` of a `bnb-chain/bsc` checkout) |
| `go_oracle/testdata/p5s1/*.hex` | The five deployed mainnet runtime bytecodes (CrossChain / GnfdLightClient / TokenHub / RelayerHub / GovHub), sha256-anchored against `reanchor.json` |
| `scripts/s11_reanchor.py` | Live-state re-anchoring script (read-only RPC; writes `reanchor.json`) |
| `logs/forge_final_run.txt` | Verbatim `forge test -vvvv` output of the final coherent run (5/5 PASS) |
| `logs/go_oracle_final_run.txt` | Verbatim Go-oracle output of the final coherent run (PASS, drain figures) |

**Statement of honesty:** every claim in this report that is marked executed was executed locally as described — Layer 1 against a Foundry fork of BSC mainnet at the anchor block, Layer 2 against the deployed bytecode inside bsc's EVM with the real precompiles; no transaction was sent to any network; the PoC uses synthetic key material for the *colluding* validators (it cannot and does not hold live validators' keys — the 2-colluder premise is an attacker model, not an observed compromise; on the fork it is installed via `vm.store` of two tracked-set slots, disclosed in §6.1/§6.2). The Foundry bridges for 0x66/0x67 are disclosed test scaffolding whose cryptographic verdicts are bound to the Go-oracle's real-precompile executions on the identical inputs. No mainnet state was modified at any point in this research.

---

*Environment: forge 1.8.6 (6bad0a66 2026-10-21); solc 0.8.37 (via_ir); bnb-chain/bsc @ 947ba1c; greenfield-contracts @ 68e06d0 (source cross-read; deployed impls verified equal by versionInfo + code sha256); Go 1.25.0 (CGO on), linux/amd64; greenfield-cometbft v1.3.2 fork types; prysm v5 BLS (blst). Final coherent run anchored at BSC mainnet block 129,184,839 (2026-10-22 19:20 UTC; block hash `0xe8b7159e4af8623af23699ba0e4cd8d8e29dd242e14602c299c90a803f13d2fc`, timestamp 1,792,696,805; see `reanchor.json`), read-only via `https://bsc-dataseed.bnbchain.org`.*

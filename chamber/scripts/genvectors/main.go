// Golden-vector generator for chamber's Gno.land compatibility tests.
//
// Usage: go run . <output-dir> <addpkg-fixture-dir>
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/gnolang/gno/gno.land/pkg/sdk/vm"
	gno "github.com/gnolang/gno/gnovm/pkg/gnolang"
	"github.com/gnolang/gno/tm2/pkg/amino"
	"github.com/gnolang/gno/tm2/pkg/crypto"
	"github.com/gnolang/gno/tm2/pkg/crypto/bip39"
	"github.com/gnolang/gno/tm2/pkg/crypto/hd"
	"github.com/gnolang/gno/tm2/pkg/crypto/multisig"
	"github.com/gnolang/gno/tm2/pkg/crypto/secp256k1"
	"github.com/gnolang/gno/tm2/pkg/sdk/auth"
	"github.com/gnolang/gno/tm2/pkg/sdk/bank"
	"github.com/gnolang/gno/tm2/pkg/std"
)

type derived struct {
	Path      string `json:"path"`
	PrivHex   string `json:"priv_hex"`
	PubHex    string `json:"pub_hex"`
	Address   string `json:"address"`
	PubBech32 string `json:"pub_bech32"`
	// Amino binary encoding of the public key as a google.protobuf.Any,
	// which is what the bech32 "gpub" string wraps.
	PubAnyHex string `json:"pub_any_hex"`
}

type keyVectors struct {
	Mnemonic string    `json:"mnemonic"`
	SeedHex  string    `json:"seed_hex"`
	Derived  []derived `json:"derived"`
	SignMsg  string    `json:"sign_msg"`
	SignHex  string    `json:"sign_hex"`
}

// signerVector is one signature applied to a transaction: which derived key
// signed, with which replay-protection values, and what it produced.
type signerVector struct {
	Path          string `json:"path"`
	Address       string `json:"address"`
	AccountNumber uint64 `json:"account_number"`
	Sequence      uint64 `json:"sequence"`
	SignBytesHex  string `json:"sign_bytes_hex"`
	SignatureHex  string `json:"signature_hex"`
	// The key signed as a session account of the tx signer (`gnokey sign
	// --session`): the numbers above are the session account's, and the
	// signature carries the key's address as session_addr.
	Session bool `json:"session,omitempty"`
}

type txVector struct {
	Name    string `json:"name"`
	ChainID string `json:"chain_id"`
	// Whether the signed tx passes std.Tx.ValidateBasic (gnokey sign refuses
	// to save a tx that doesn't).
	Valid bool `json:"valid"`
	// tx.GetSigners(), in order.
	Signers []string `json:"signers"`
	// amino.MarshalJSON of the unsigned tx, as `gnokey maketx` prints it.
	UnsignedJSON string         `json:"unsigned_json"`
	Signatures   []signerVector `json:"signatures"`
	// amino.MarshalJSON of the signed tx, as `gnokey sign` saves it.
	SignedJSON string `json:"signed_json"`
	// amino.Marshal of the signed tx, what `gnokey broadcast` sends.
	SignedBinHex string `json:"signed_bin_hex"`
	// Set for the multisig case: how the single Signature above was built.
	Multisig *multisigVector `json:"multisig,omitempty"`
}

// memberSignature is one multisig member's `gnokey sign --output-document`.
type memberSignature struct {
	Path    string `json:"path"`
	Address string `json:"address"`
	// amino.MarshalJSON of the member's std.Signature.
	SignatureJSON string `json:"signature_json"`
	SignatureHex  string `json:"signature_hex"`
}

type multisigVector struct {
	Threshold int `json:"threshold"`
	// Member paths in the order they appear in the multisig key
	// (sorted by address, gnokey's default).
	MemberPaths []string `json:"member_paths"`
	// amino.MarshalJSONAny of the multisig public key.
	PubKeyJSON   string `json:"pubkey_json"`
	PubKeyAnyHex string `json:"pubkey_any_hex"`
	Address      string `json:"address"`
	PubBech32    string `json:"pub_bech32"`
	// The multisig account's own replay-protection values, used by every member.
	AccountNumber    uint64            `json:"account_number"`
	Sequence         uint64            `json:"sequence"`
	SignBytesHex     string            `json:"sign_bytes_hex"`
	MemberSignatures []memberSignature `json:"member_signatures"`
	// multisig.Multisignature.Marshal(), the combined signature bytes.
	CombinedSignatureHex string `json:"combined_signature_hex"`
}

type txVectors struct {
	Mnemonic string     `json:"mnemonic"`
	Cases    []txVector `json:"cases"`
}

const (
	message  = "gnochamber signing test vector"
	mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon art"
)

// key is a derived secp256k1 key and its BIP44 path.
type key struct {
	path string
	priv secp256k1.PrivKeySecp256k1
}

func (k key) pub() secp256k1.PubKeySecp256k1 {
	return k.priv.PubKey().(secp256k1.PubKeySecp256k1)
}

func (k key) address() crypto.Address {
	return k.pub().Address()
}

// signer pairs a key with the account values it signs with.
type signer struct {
	key           key
	accountNumber uint64
	sequence      uint64
	session       bool
}

// txCase is a tx to sign and who signs it. Signers must be listed in the
// order tx.GetSigners() returns them, which is what gnokey expects too.
type txCase struct {
	name    string
	chainID string
	tx      std.Tx
	signers []signer
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go run . <output-dir> <addpkg-fixture-dir>")
		os.Exit(1)
	}
	outDir := os.Args[1]
	fixtureDir := os.Args[2]

	if !bip39.IsMnemonicValid(mnemonic) {
		fmt.Fprintln(os.Stderr, "invalid mnemonic")
		os.Exit(1)
	}

	// Derive the BIP39 seed without passphrase and the BIP32 master
	// key/chain code that every path below is derived from.
	seed := bip39.NewSeed(mnemonic, "")
	master, chainCode := hd.ComputeMastersFromSeed(seed)
	keyAt := func(account, index uint32) key {
		path := hd.NewFundraiserParams(account, crypto.CoinType, index).String()
		privBz, err := hd.DerivePrivateKeyForPath(master, chainCode, path)
		if err != nil {
			panic(err)
		}

		return key{path: path, priv: secp256k1.PrivKeySecp256k1(privBz)}
	}

	writeJSON(filepath.Join(outDir, "keys.json"), genKeys(seed, keyAt))
	writeJSON(filepath.Join(outDir, "txs.json"), genTxs(keyAt, fixtureDir))
}

func genKeys(seed []byte, keyAt func(account, index uint32) key) keyVectors {
	vec := keyVectors{
		Mnemonic: mnemonic,
		SeedHex:  hex.EncodeToString(seed),
	}

	// Account/index pairs: two indices under account 0, plus one each
	// from non-zero accounts.
	paths := []struct{ account, index uint32 }{
		{0, 0}, {0, 1}, {1, 0}, {5, 7},
	}
	for _, p := range paths {
		k := keyAt(p.account, p.index)
		pubKey := k.pub()
		vec.Derived = append(vec.Derived, derived{
			Path:      k.path,
			PrivHex:   hex.EncodeToString(k.priv[:]),
			PubHex:    hex.EncodeToString(pubKey[:]),
			Address:   k.address().String(),
			PubBech32: crypto.PubKeyToBech32(pubKey),
			PubAnyHex: hex.EncodeToString(pubKey.Bytes()),
		})
	}

	// Sign a known message with the account 0 / index 0 key so the Rust
	// side can verify its signing implementation against a known signature.
	sig, err := keyAt(0, 0).priv.Sign([]byte(message))
	if err != nil {
		panic(err)
	}

	vec.SignMsg = message
	vec.SignHex = hex.EncodeToString(sig)
	return vec
}

func genTxs(keyAt func(account, index uint32) key, fixtureDir string) txVectors {
	alice := keyAt(0, 0)
	bob := keyAt(0, 1)
	carol := keyAt(1, 0)
	fee := std.NewFee(200000, std.MustParseCoin("1000000ugnot"))

	// A Gno file body exercising every JSON escaping rule that matters:
	// HTML-sensitive chars, quotes, backslashes, tabs, newlines, the U+2028
	// line separator and non-ASCII text.
	runBody := "package main\n\n" +
		"func main() {\n" +
		"\tif a < b && c > d {\n" +
		"\t\tprintln(\"ok \\\"quoted\\\" back\\\\slash\")\n" +
		"\t}\n" +
		"\t// line separator and ünïcödé ☃\n" +
		"}\n"

	cases := []txCase{
		{
			name:    "send",
			chainID: "dev",
			tx: std.Tx{
				Msgs: []std.Msg{bank.MsgSend{
					FromAddress: alice.address(),
					ToAddress:   bob.address(),
					// Unsorted on purpose: ParseCoins sorts by denom.
					Amount: std.MustParseCoins("1000000ugnot,5000atom"),
				}},
				Fee:  fee,
				Memo: "",
			},
			signers: []signer{{alice, 8, 3, false}},
		},
		{
			name:    "call_with_args",
			chainID: "test5",
			tx: std.Tx{
				Msgs: []std.Msg{vm.MsgCall{
					Caller:  alice.address(),
					PkgPath: "gno.land/r/demo/boards",
					Func:    "CreateBoard",
					Args:    []string{"my board", "<b>&\"quoted\"</b>", ""},
				}},
				Fee:  fee,
				Memo: "hello",
			},
			signers: []signer{{alice, 12, 0, false}},
		},
		{
			name:    "call_no_args",
			chainID: "dev",
			tx: std.Tx{
				Msgs: []std.Msg{vm.MsgCall{
					Caller:  alice.address(),
					Send:    std.MustParseCoins("100ugnot"),
					PkgPath: "gno.land/r/demo/users",
					Func:    "Register",
				}},
				Fee:  std.NewFee(500000, std.MustParseCoin("1ugnot")),
				Memo: "",
			},
			signers: []signer{{alice, 8, 4, false}},
		},
		{
			name:    "run",
			chainID: "dev",
			tx: std.Tx{
				Msgs: []std.Msg{vm.MsgRun{
					Caller:     alice.address(),
					MaxDeposit: std.MustParseCoins("1000ugnot"),
					Package: &std.MemPackage{
						Name:  "main",
						Files: []*std.MemFile{{Name: "main.gno", Body: runBody}},
					},
				}},
				Fee:  fee,
				Memo: "",
			},
			signers: []signer{{alice, 8, 5, false}},
		},
		{
			name:    "addpkg",
			chainID: "dev",
			tx: std.Tx{
				Msgs: []std.Msg{vm.MsgAddPackage{
					Creator: alice.address(),
					Package: &std.MemPackage{
						Name: "hello",
						Path: "gno.land/r/demo/hello",
						Files: []*std.MemFile{
							{Name: "README.md", Body: "# hello\n"},
							{Name: "hello.gno", Body: "package hello\n\nfunc Render(path string) string {\n\treturn \"<h1>Hello & welcome</h1>\"\n}\n"},
						},
						// What gnokey stamps on every package it reads from disk
						Type: gno.MPUserAll,
					},
				}},
				Fee:  fee,
				Memo: "<&>   ünïcode",
			},
			signers: []signer{{alice, 8, 6, false}},
		},
		{
			// The same package read from a directory the way `gnokey maketx
			// addpkg -pkgdir` does, to pin the file selection and ordering rules.
			name:    "addpkg_dir",
			chainID: "dev",
			tx: std.Tx{
				Msgs: []std.Msg{vm.MsgAddPackage{
					Creator: alice.address(),
					Package: gno.MustReadMemPackage(fixtureDir, "gno.land/r/demo/hello", gno.MPUserAll),
					Send:    std.MustParseCoins("1ugnot"),
				}},
				Fee:  fee,
				Memo: "",
			},
			signers: []signer{{alice, 8, 9, false}},
		},
		{
			// A master key authorizing bob's key as a session, all fields set.
			name:    "create_session",
			chainID: "dev",
			tx: std.Tx{
				Msgs: []std.Msg{auth.MsgCreateSession{
					Creator:     alice.address(),
					SessionKey:  bob.pub(),
					ExpiresAt:   1_800_000_000,
					AllowPaths:  []string{"vm/exec:gno.land/r/demo/boards", "bank/send"},
					SpendLimit:  std.MustParseCoins("1000000ugnot"),
					SpendPeriod: 86400,
				}},
				Fee:  fee,
				Memo: "",
			},
			signers: []signer{{alice, 8, 10, false}},
		},
		{
			// The minimal form: no expiry, wildcard paths, no spending, so the
			// omitempty fields are absent.
			name:    "create_session_minimal",
			chainID: "dev",
			tx: std.Tx{
				Msgs: []std.Msg{auth.MsgCreateSession{
					Creator:    alice.address(),
					SessionKey: carol.pub(),
					AllowPaths: []string{"*"},
				}},
				Fee:  fee,
				Memo: "",
			},
			signers: []signer{{alice, 8, 11, false}},
		},
		{
			name:    "revoke_session",
			chainID: "dev",
			tx: std.Tx{
				Msgs: []std.Msg{auth.MsgRevokeSession{
					Creator:    alice.address(),
					SessionKey: bob.pub(),
				}},
				Fee:  fee,
				Memo: "",
			},
			signers: []signer{{alice, 8, 12, false}},
		},
		{
			name:    "revoke_all_sessions",
			chainID: "dev",
			tx: std.Tx{
				Msgs: []std.Msg{auth.MsgRevokeAllSessions{
					Creator: alice.address(),
				}},
				Fee:  fee,
				Memo: "",
			},
			signers: []signer{{alice, 8, 13, false}},
		},
		{
			// A send from alice signed by bob's key acting as her session
			// account, with the session account's own number and sequence.
			name:    "session_send",
			chainID: "dev",
			tx: std.Tx{
				Msgs: []std.Msg{bank.MsgSend{
					FromAddress: alice.address(),
					ToAddress:   carol.address(),
					Amount:      std.MustParseCoins("10ugnot"),
				}},
				Fee:  fee,
				Memo: "via session",
			},
			signers: []signer{{bob, 30, 2, true}},
		},
		{
			// Invalid per ValidateBasic (fee coin has no denom), but it pins
			// the binary encoding of a fully omitted Fee.
			name:    "zero_fee",
			chainID: "dev",
			tx: std.Tx{
				Msgs: []std.Msg{bank.MsgSend{
					FromAddress: alice.address(),
					ToAddress:   bob.address(),
					Amount:      std.MustParseCoins("1ugnot"),
				}},
				Fee:  std.Fee{},
				Memo: "",
			},
			signers: []signer{{alice, 8, 7, false}},
		},
		{
			// Two distinct signers plus a repeated one, to pin GetSigners'
			// dedup/order and the multi-signature encoding.
			name:    "two_signers",
			chainID: "dev",
			tx: std.Tx{
				Msgs: []std.Msg{
					bank.MsgSend{FromAddress: alice.address(), ToAddress: bob.address(), Amount: std.MustParseCoins("10ugnot")},
					bank.MsgSend{FromAddress: bob.address(), ToAddress: alice.address(), Amount: std.MustParseCoins("20ugnot")},
					bank.MsgSend{FromAddress: alice.address(), ToAddress: bob.address(), Amount: std.MustParseCoins("30ugnot")},
				},
				Fee:  fee,
				Memo: "multi",
			},
			signers: []signer{{alice, 8, 8, false}, {bob, 9, 0, false}},
		},
	}

	vec := txVectors{Mnemonic: mnemonic}
	for _, c := range cases {
		vec.Cases = append(vec.Cases, genTx(c))
	}

	vec.Cases = append(vec.Cases, genMultisigTx(fee, []key{alice, bob, carol}, []key{alice, carol}, bob))
	return vec
}

// genMultisigTx builds a 2-of-3 multisig account from members, has some of
// them sign a MsgSend from it, and combines the signatures like
// `gnokey multisign` does.
func genMultisigTx(fee std.Fee, members []key, signing []key, to key) txVector {
	const (
		threshold     = 2
		chainID       = "dev"
		accountNumber = uint64(20)
		sequence      = uint64(1)
	)

	// gnokey add --multisig sorts members by address unless --nosort
	sort.Slice(members, func(i, j int) bool {
		return members[i].address().Compare(members[j].address()) < 0
	})

	pubKeys := make([]crypto.PubKey, len(members))
	memberPaths := make([]string, len(members))
	for i, m := range members {
		pubKeys[i] = m.pub()
		memberPaths[i] = m.path
	}

	multiPub := multisig.NewPubKeyMultisigThreshold(threshold, pubKeys)
	tx := std.Tx{
		Msgs: []std.Msg{bank.MsgSend{
			FromAddress: multiPub.Address(),
			ToAddress:   to.address(),
			Amount:      std.MustParseCoins("500ugnot"),
		}},
		Fee:  fee,
		Memo: "multisig",
	}
	out := txVector{
		Name:         "multisig_2of3",
		ChainID:      chainID,
		UnsignedJSON: string(amino.MustMarshalJSON(tx)),
		Signers:      []string{multiPub.Address().String()},
		// The member signatures live under Multisig; keep this a list, not null
		Signatures: []signerVector{},
	}

	signBytes, err := tx.GetSignBytes(chainID, accountNumber, sequence)
	if err != nil {
		panic(err)
	}

	msigVec := &multisigVector{
		Threshold:     threshold,
		MemberPaths:   memberPaths,
		PubKeyJSON:    string(amino.MustMarshalJSONAny(multiPub)),
		PubKeyAnyHex:  hex.EncodeToString(multiPub.Bytes()),
		Address:       multiPub.Address().String(),
		PubBech32:     crypto.PubKeyToBech32(multiPub),
		AccountNumber: accountNumber,
		Sequence:      sequence,
		SignBytesHex:  hex.EncodeToString(signBytes),
	}

	msig := multisig.NewMultisig(len(members))
	for _, s := range signing {
		sig, err := s.priv.Sign(signBytes)
		if err != nil {
			panic(err)
		}

		doc := std.Signature{PubKey: s.pub(), Signature: sig}
		msigVec.MemberSignatures = append(msigVec.MemberSignatures, memberSignature{
			Path:          s.path,
			Address:       s.address().String(),
			SignatureJSON: string(amino.MustMarshalJSON(doc)),
			SignatureHex:  hex.EncodeToString(sig),
		})
		if err := msig.AddSignatureFromPubKey(sig, s.pub(), pubKeys); err != nil {
			panic(err)
		}
	}
	combined := msig.Marshal()
	msigVec.CombinedSignatureHex = hex.EncodeToString(combined)

	tx.Signatures = []std.Signature{{PubKey: multiPub, Signature: combined}}
	out.Multisig = msigVec
	out.Valid = tx.ValidateBasic() == nil
	out.SignedJSON = string(amino.MustMarshalJSON(tx))
	out.SignedBinHex = hex.EncodeToString(amino.MustMarshal(tx))
	return out
}

func genTx(c txCase) txVector {
	tx := c.tx
	tx.Signatures = nil

	out := txVector{
		Name:         c.name,
		ChainID:      c.chainID,
		UnsignedJSON: string(amino.MustMarshalJSON(tx)),
	}
	for _, addr := range tx.GetSigners() {
		out.Signers = append(out.Signers, addr.String())
	}

	// Sign exactly as gnokey does: sign bytes from the SignDoc, then the
	// keybase signs them and the signature is appended.
	for _, s := range c.signers {
		signBytes, err := tx.GetSignBytes(c.chainID, s.accountNumber, s.sequence)
		if err != nil {
			panic(err)
		}

		sig, err := s.key.priv.Sign(signBytes)
		if err != nil {
			panic(err)
		}

		signature := std.Signature{
			PubKey:    s.key.pub(),
			Signature: sig,
		}
		if s.session {
			// What `gnokey sign --session` does
			signature.SessionAddr = s.key.address()
		}

		tx.Signatures = append(tx.Signatures, signature)
		out.Signatures = append(out.Signatures, signerVector{
			Path:          s.key.path,
			Address:       s.key.address().String(),
			AccountNumber: s.accountNumber,
			Sequence:      s.sequence,
			SignBytesHex:  hex.EncodeToString(signBytes),
			SignatureHex:  hex.EncodeToString(sig),
			Session:       s.session,
		})
	}

	out.Valid = tx.ValidateBasic() == nil
	out.SignedJSON = string(amino.MustMarshalJSON(tx))
	out.SignedBinHex = hex.EncodeToString(amino.MustMarshal(tx))
	return out
}

func writeJSON(path string, v any) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}

	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	// Keep the vectors readable: don't HTML-escape the JSON we wrap
	// around gno's output (gno's own escaping inside the strings is kept).
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
}

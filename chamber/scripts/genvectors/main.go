package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/gnolang/gno/tm2/pkg/crypto"
	"github.com/gnolang/gno/tm2/pkg/crypto/bip39"
	"github.com/gnolang/gno/tm2/pkg/crypto/hd"
	"github.com/gnolang/gno/tm2/pkg/crypto/secp256k1"
)

type derived struct {
	Path      string `json:"path"`
	PrivHex   string `json:"priv_hex"`
	PubHex    string `json:"pub_hex"`
	Address   string `json:"address"`
	PubBech32 string `json:"pub_bech32"`
}

type vector struct {
	Mnemonic string    `json:"mnemonic"`
	SeedHex  string    `json:"seed_hex"`
	Derived  []derived `json:"derived"`
	SignMsg  string    `json:"sign_msg"`
	SignHex  string    `json:"sign_hex"`
}

const (
	message  = "gnochamber signing test vector"
	mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon art"
)

func main() {
	if !bip39.IsMnemonicValid(mnemonic) {
		fmt.Fprintln(os.Stderr, "invalid mnemonic")
		os.Exit(1)
	}

	// Derive the BIP39 seed wothout passphrase and the BIP32
	// master key/chain code that every path below is derived from.
	seed := bip39.NewSeed(mnemonic, "")
	master, chainCode := hd.ComputeMastersFromSeed(seed)
	vec := vector{
		Mnemonic: mnemonic,
		SeedHex:  hex.EncodeToString(seed),
	}

	// Define account/index pairs, two indices under account 0,
	// plus one each from non-zero accounts.
	paths := []struct {
		account, index uint32
	}{
		{0, 0}, {0, 1}, {1, 0}, {5, 7},
	}
	for _, p := range paths {
		params := hd.NewFundraiserParams(p.account, crypto.CoinType, p.index)
		path := params.String()
		privBz, err := hd.DerivePrivateKeyForPath(master, chainCode, path)
		if err != nil {
			panic(err)
		}

		privKey := secp256k1.PrivKeySecp256k1(privBz)
		pubKey := privKey.PubKey().(secp256k1.PubKeySecp256k1)
		vec.Derived = append(vec.Derived, derived{
			Path:      path,
			PrivHex:   hex.EncodeToString(privBz[:]),
			PubHex:    hex.EncodeToString(pubKey[:]),
			Address:   pubKey.Address().String(),
			PubBech32: crypto.PubKeyToBech32(pubKey),
		})
	}

	// Sign a known message with the account 0 / index 0 key so the Rust
	// side can verify its signing implementation against a known signature.
	firstPriv, _ := hd.DerivePrivateKeyForPath(
		master,
		chainCode,
		hd.NewFundraiserParams(0, crypto.CoinType, 0).String(),
	)
	privKey := secp256k1.PrivKeySecp256k1(firstPriv)
	sig, err := privKey.Sign([]byte(message))
	if err != nil {
		panic(err)
	}

	vec.SignMsg = message
	vec.SignHex = hex.EncodeToString(sig)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(vec); err != nil {
		panic(err)
	}
}

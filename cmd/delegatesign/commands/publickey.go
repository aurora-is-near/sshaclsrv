package commands

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base32"
	"fmt"
	"os"

	"github.com/aurora-is-near/sshaclsrv/src/delegatesign"
)

// PublicKey displays a public key for a private key.
// Params: <keyfile>
func PublicKey(params ...string) {
	if len(params) != 1 {
		Error("Missing parameter: keyfile.\n\nAsk for help.\n\n")
	}
	l, err := ReadFile(params[0])
	if err != nil {
		Error("Cannot read key %s: %s\n", params[0], err)
	}
	switch len(l) {
	case 1:
		privkey := ed25519.PrivateKey(l[0])
		pubkey := privkey.Public().(ed25519.PublicKey)
		Output("# Public key\n%s\n", base32.StdEncoding.EncodeToString(pubkey))
	case 2:
		privkey := ed25519.PrivateKey(l[0])
		pubkey := privkey.Public().(ed25519.PublicKey)
		delKey := delegatesign.DelegatedKey(l[1])
		master, sub, until, err := delKey.Contents()
		if err != nil {
			Error("Cannot read key %s: %s\n", params[0], err)
		}
		if !bytes.Equal(pubkey, sub) {
			Error("Cannot read key %s: Corrupt delegation\n", params[0])
		}
		Output("# Public key\n%s\n# Delegated until '%s' to:\n%s\n",
			base32.StdEncoding.EncodeToString(pubkey),
			formatTime(until),
			base32.StdEncoding.EncodeToString(master))
	default:
		Error("Cannot read key %s: Unknown format\n", params[0])
	}
}

// HelpPublicKey provides help for PublicKey.
func HelpPublicKey() {
	_, _ = fmt.Fprintf(os.Stdout, "\n%s publickey <keyfile>\n"+
		"     Show public key for key in <keyfile>\n\n", os.Args[0])
	os.Exit(0)
}

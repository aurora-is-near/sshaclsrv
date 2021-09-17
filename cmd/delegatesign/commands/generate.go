package commands

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"os"
)

// Generate a key.
// Params: <privatekeyfile>
func Generate(params ...string) {
	var err error
	var privateKey ed25519.PrivateKey
	var publicKey ed25519.PublicKey
	if len(params) != 1 {
		Error("Missing parameter: privatekeyfile.\n\nAsk for help.\n\n")
	}
	if publicKey, privateKey, err = ed25519.GenerateKey(rand.Reader); err != nil {
		Error("Cannot generate key: %s\n", err)
	}
	pub := base32.StdEncoding.EncodeToString(publicKey)
	pks := base32.StdEncoding.EncodeToString(privateKey)
	if err := WriteFile(params[0], "# Private Key %s\n%s\n", identity(), pks); err != nil {
		Error("Cannot write key to file %s: %s\n", params[0], err)
	}
	Output("# Public key\n%s\n", pub)
}

// HelpGenerate provides help for Generate.
func HelpGenerate() {
	_, _ = fmt.Fprintf(os.Stdout, "\n%s generate <privatekeyfile>\n"+
		"     Generate a new private key and store it in <privatekeyfile>\n\n", os.Args[0])
	os.Exit(0)
}

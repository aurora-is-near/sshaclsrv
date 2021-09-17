package commands

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/aurora-is-near/sshaclsrv/src/delegatesign"
)

func signParseParams(params ...string) (io.Reader, string, bool) {
	if len(params) < 1 {
		Error("Missing parameter: <delegationfile>.\n\nAsk for help.\n\n")
	}
	if len(params) == 1 {
		return os.Stdin, params[0], false
	}
	b := new(bytes.Buffer)
	_, _ = b.WriteString(params[1])
	return b, params[0], true
}

// Sign message with a delegated key.
// Params: <delegationfile> [message]
func Sign(params ...string) {
	input, privkeyFile, includeMessage := signParseParams(params...)
	l, err := ReadFile(privkeyFile)
	if err != nil || len(l) != 2 {
		Error("Cannot read delegated private key %s: %s\n", privkeyFile, err)
	}
	privkey := ed25519.PrivateKey(l[0])
	delKey := delegatesign.DelegatedKey(l[1])
	_, pub, _, err := delKey.Contents()
	if err != nil {
		Error("Cannot read delegated private key %s: %s\n", privkeyFile, err)
	}
	if !bytes.Equal(pub, privkey.Public().(ed25519.PublicKey)) {
		Error("Cannot read delegated private key %s: Corrupted\n", privkeyFile)
	}
	msg, err := io.ReadAll(input)
	if err != nil {
		Error("Cannot read input: %s", err)
	}
	sig := delKey.Sign(privkey, msg)
	if includeMessage {
		Output("%s:%s\n", base64.StdEncoding.EncodeToString(sig), msg)
	} else {
		Output("%s\n", base64.StdEncoding.EncodeToString(sig))
	}
}

// HelpSign provides help for sign.
func HelpSign() {
	_, _ = fmt.Fprintf(os.Stdout, "\n%s sign <delegationfile> [message]\n"+
		"     Sign message (or stdin) with private key read from <delegationfile>.\n\n", os.Args[0])
	os.Exit(0)
}

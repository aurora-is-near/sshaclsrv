package commands

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"os"
	"time"

	"github.com/aurora-is-near/sshaclsrv/src/util"

	"github.com/aurora-is-near/sshaclsrv/src/delegatesign"
)

func delegateParseParams(params ...string) (time.Duration, string, string) {
	if len(params) < 2 {
		Error("Missing parameter(s).\n\nAsk for help.\n\n")
	}
	if len(params) == 2 {
		return time.Hour * 24, params[0], params[1]
	}
	dur, err := time.ParseDuration(params[0])
	if err != nil {
		Error("Cannot parse duration '%s': %s", params[0], err)
	}
	return dur, params[1], params[2]
}

// Delegate a key.
// Params: [<duration=1 day>] <privatekeyfile> <delegationfile>
func Delegate(params ...string) {
	var err error
	var privateKey ed25519.PrivateKey
	var publicKey ed25519.PublicKey
	dur, privkeyFile, delegateKeyFile := delegateParseParams(params...)
	l, err := util.ReadFile(privkeyFile)
	if err != nil || len(l) != 1 || len(l[0]) != 64 {
		Error("Cannot read private key %s: %s\n", privkeyFile, err)
	}
	if publicKey, privateKey, err = ed25519.GenerateKey(rand.Reader); err != nil {
		Error("Cannot generate key: %s\n", err)
	}
	pks := base32.StdEncoding.EncodeToString(privateKey)
	until := time.Now().Add(dur)
	dk := delegatesign.DelegateKey(ed25519.PrivateKey(l[0]), publicKey, until)
	dks := base32.StdEncoding.EncodeToString(dk)
	if err := util.WriteFile(delegateKeyFile, "# Delegated Key until %s\n%s\n%s\n", formatTime(until), pks, dks); err != nil {
		Error("Cannot write key to file %s: %s\n", delegateKeyFile, err)
	}
	Output("# Public key\n%s\n", base32.StdEncoding.EncodeToString(publicKey))
}

// HelpDelegate provides help for Delegate.
func HelpDelegate() {
	_, _ = fmt.Fprintf(os.Stdout, "\n%s delegate [<duration=1 day>] <privatekeyfile> <delegationfile>\n"+
		"     Delegate from private key in <privatekeyfile> to <delegationfile>\n\n", os.Args[0])
	os.Exit(0)
}

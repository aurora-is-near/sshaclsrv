package commands

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/aurora-is-near/sshaclsrv/src/util"
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
	privkey, delKey, err := util.GetKey(privkeyFile)
	if err != nil {
		Error("%s", err)
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

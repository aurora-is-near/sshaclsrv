package main

import (
	"fmt"
	"os"
	"path"

	"github.com/aurora-is-near/sshaclsrv/cmd/delegatesign/commands"
)

func argError() {
	commands.Error("%s: Missing parameters.\n\nAsk for help (-h, --help)\n\n", os.Args[0])
}

func main() {
	os.Args[0] = path.Base(os.Args[0])
	if len(os.Args) < 2 {
		argError()
	}
	if len(os.Args) < 3 && (os.Args[1] == "help" || os.Args[1] == "-h" || os.Args[1] == "--help") {
		help()
	}
	switch os.Args[1] {
	case "help", "-h", "--help":
		help()
	case "gen", "generate":
		commands.Generate(os.Args[2:]...)
	case "del", "delegate":
		commands.Delegate(os.Args[2:]...)
	case "sig", "sign":
		commands.Sign(os.Args[2:]...)
	case "pub", "publickey", "key":
		commands.PublicKey(os.Args[2:]...)
	default:
		argError()
	}
}

func help() {
	if len(os.Args) < 3 {
		_, _ = fmt.Fprintf(os.Stdout, helpString, os.Args[0])
		os.Exit(0)
	}
	switch os.Args[2] {
	case "gen", "generate":
		commands.HelpGenerate()
	case "del", "delegate":
		commands.HelpDelegate()
	case "sig", "sign":
		commands.HelpSign()
	case "pub", "publickey", "key":
		commands.HelpPublicKey()
	default:
		commands.Error("%s: Unknown command: %s\n\nAsk for help (-h, --help)\n\n", os.Args[0], os.Args[2])
	}
}

var helpString = `%s usage and help:

Simple delegated signing tool

Commands:
   gen(enrate)      Generate new keypair.
   del(egate)       Delegate signatures.
   sig(n)           Sign.
   pub(lickey)      Show public key.
   help             Get this help.
   help <command>   Get help for any command.

`

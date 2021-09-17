package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/aurora-is-near/sshaclsrv/src/fileperm"

	"github.com/aurora-is-near/sshaclsrv/src/gosshacl"
)

// Settings contain global settings for the program.
type Settings struct {
	URL       string
	Token     string
	PublicKey ed25519.PublicKey
	KeyFile   string
	Hostname  string
}

var config = &Settings{
	URL:       "https://127.0.0.1:9100",
	Token:     "password for httpauth",
	PublicKey: func() ed25519.PublicKey { p, _, _ := ed25519.GenerateKey(rand.Reader); return p }(),
	KeyFile:   "/etc/ssh/sshacl.keys",
	Hostname:  "",
}

var (
	configFile  string
	username    string
	fingerprint string
	generate    bool
)

func readConfig(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := fileperm.PermissionCheck(f); err != nil {
		return err
	}
	d, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	return json.Unmarshal(d, config)
}

func init() {
	flag.StringVar(&configFile, "c", "/etc/sshd/sshacl.cfg", "path to configuration file")
	flag.StringVar(&username, "u", "", "username")
	flag.StringVar(&fingerprint, "f", "", "fingerprint")
	flag.BoolVar(&generate, "g", false, "generate example config")
}

func main() {
	flag.Parse()
	if generate {
		d, _ := json.MarshalIndent(config, "  ", "")
		_, _ = os.Stdout.Write(d)
		_, _ = os.Stdout.Write([]byte("\n"))
		os.Exit(0)
	}
	if username == "" || fingerprint == "" || configFile == "" {
		_, _ = fmt.Fprintf(os.Stderr, "%s -u <username> -f <fingerprint>\n", os.Args[0])
		os.Exit(1)
	}
	if err := readConfig(configFile); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error reading configfile: %s\n", err)
		os.Exit(1)
	}
	if config.Hostname == "" {
		var hostname string
		var err error
		if hostname, err = os.Hostname(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "cannot determine hostname: %s\n", err)
			os.Exit(1)
		}
		config.Hostname = hostname
	}
	if config.URL != "" && len(config.PublicKey) >= ed25519.PublicKeySize {
		remote := gosshacl.NewRemote(config.URL, config.PublicKey, config.Token, config.Hostname)
		err := remote.FindEntry(os.Stdout, username, fingerprint)
		switch err {
		case nil, gosshacl.ErrNotFound:
			os.Exit(0)
		case gosshacl.ErrFallback:
		default:
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	if err := gosshacl.FindEntryFromFile(config.KeyFile, os.Stdout, config.Hostname, username, fingerprint); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Exit(0)
}

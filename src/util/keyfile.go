package util

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base32"
	"fmt"
	"io"
	"os"

	"github.com/aurora-is-near/sshaclsrv/src/delegatesign"
)

// WriteFile writes i... to filename using format. Files are readonly and will not overwrite.
func WriteFile(filename, format string, i ...interface{}) error {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0400)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := fmt.Fprintf(f, format, i...); err != nil {
		return err
	}
	return nil
}

// ReadFile reads contents from filename, skipping comments and decoding remaining lines with base32.
func ReadFile(filename string) (lines [][]byte, err error) {
	ret := make([][]byte, 0, 3)
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	buf := bufio.NewReader(f)
	for {
		l, err := buf.ReadString('\n')
		if len(l) > 0 {
			if l[0] == '#' {
				continue
			}
			lB, err := base32.StdEncoding.DecodeString(l)
			if err != nil {
				return nil, fmt.Errorf("cannot decode: %s", err)
			}
			ret = append(ret, lB)
		}
		if err == io.EOF {
			return ret, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// GetKey gets a delegated keypair from file.
func GetKey(privkeyFile string) (privateKey ed25519.PrivateKey, delegatedKey delegatesign.DelegatedKey, err error) {
	l, err := ReadFile(privkeyFile)
	if err != nil || len(l) != 2 {
		return nil, nil, fmt.Errorf("cannot read delegated private key %s: %s", privkeyFile, err)
	}
	privkey := ed25519.PrivateKey(l[0])
	delKey := delegatesign.DelegatedKey(l[1])
	_, pub, _, err := delKey.Contents()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read delegated private key %s: %s", privkeyFile, err)
	}
	if !bytes.Equal(pub, privkey.Public().(ed25519.PublicKey)) {
		return nil, nil, fmt.Errorf("cannot read delegated private key %s: Corrupted", privkeyFile)
	}
	return privkey, delKey, nil
}

package sshkey

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"
)

var (
	// ErrNoKey is returned if parsing did not find a key.
	ErrNoKey = errors.New("no key found")
	// ErrMissingQuote is returned if a quoted option is lacking a closing quote.
	ErrMissingQuote = errors.New("missing quote")
	// ErrGarbage is returned if the key contains trailing garbage.
	ErrGarbage = errors.New("trailing garbage")
	// ErrInconsistentType is returned if the human-readable and the machine-readable key types do not match.
	ErrInconsistentType = errors.New("inconsistent key type")
	// ErrOption is returned if an option has a wrong format/value.
	ErrOption = errors.New("option wrong format")
	// ErrUnknownOption is returned when an unknown option is encountered.
	ErrUnknownOption = errors.New("unknown option")
	// ErrFormat is returned if formatting of values, especially expiry-time, is wrong.
	ErrFormat = errors.New("invalid format")
)

func trimRunesLeft(s []rune, trimFunc func(rune) bool) []rune {
	if len(s) == 0 {
		return s
	}
	for i, r := range s {
		if !trimFunc(r) {
			return s[i:]
		}
	}
	if trimFunc(s[0]) {
		return s[0:0]
	}
	return s
}

func fingerprintSHA256(pubKey ssh.PublicKey) string {
	sha256sum := sha256.Sum256(pubKey.Marshal())
	hash := base64.RawStdEncoding.EncodeToString(sha256sum[:])
	return hash
}

// Key is an annotaed SSH key.
type Key struct {
	Options     Options
	Key         ssh.PublicKey
	Comment     string
	NotAfter    time.Time
	Fingerprint string
}

// ApplyToString applies opts to a key and returns the authorized-key formatted result.
func (key Key) ApplyToString(opts Options) string {
	s := make([]string, 0, 2)
	if t := opts.Apply(key.Options).String(); len(t) > 0 {
		s = append(s, t)
	}
	if t := string(bytes.TrimRight(ssh.MarshalAuthorizedKey(key.Key), "\n")); len(t) > 0 {
		s = append(s, t)
	}
	return strings.Join(s, " ")
}

// ParseKey parses an authorized-key formatted key.
func ParseKey(s string) (key *Key, err error) {
	key = new(Key)
	key.Options = make(Options, 0, 10)
	q := trimRunesLeft([]rune(s), unicode.IsSpace)
	for {
		if isKey(q) {
			f := strings.Fields(string(q))
			if len(f) < 2 {
				return nil, ErrNoKey
			}
			if len(f) > 2 {
				key.Comment = f[2]
			}
			if len(f) > 3 {
				return nil, ErrGarbage
			}
			k, err := base64.StdEncoding.DecodeString(f[1])
			if err != nil {
				return nil, err
			}
			if key.Key, err = ssh.ParsePublicKey(k); err != nil {
				return nil, err
			}
			if key.Key.Type() != f[0] {
				return nil, ErrInconsistentType
			}
			key.Fingerprint = fingerprintSHA256(key.Key)
			return key, nil
		}
		rem, optKey, optVal, optQuoted, err := parseOption(q)
		if err != nil {
			return key, err
		}
		optValI, err := verifyOption(optKey, optVal, optQuoted)
		if err != nil {
			return key, err
		}
		if optKey == "expiry-time" {
			key.NotAfter = optValI.(time.Time)
		} else {
			key.Options = append(key.Options, Option{Key: optKey, Value: optValI})
		}
		q = trimRunesLeft(rem, unicode.IsSpace)
	}
}

// ParseOptions parses options as if they are from an authorized-keys file, it does not fail on missing keys.
func ParseOptions(s string) (options Options, err error) {
	options = make(Options, 0, 10)
	q := trimRunesLeft([]rune(s), unicode.IsSpace)
	for {
		rem, optKey, optVal, optQuoted, pErr := parseOption(q)
		if pErr == nil || pErr == ErrNoKey {
			if len(optKey) > 0 {
				optValI, err := verifyOption(optKey, optVal, optQuoted)
				if err != nil {
					return options, err
				}
				options = append(options, Option{Key: optKey, Value: optValI})
			}
			if pErr == ErrNoKey {
				return options, nil
			}
		}
		q = trimRunesLeft(rem, unicode.IsSpace)
	}
}

func runeSliceHasPrefix(body, prefix []rune) bool {
	if len(body) < len(prefix) {
		return false
	}
	for i, r := range prefix {
		if r != body[i] {
			return false
		}
	}
	return true
}

func parseOption(s []rune) (remainder []rune, key, value string, quoted bool, err error) {
	for i, r := range s {
		if unicode.IsSpace(r) {
			return s[i+1:], string(s[:i]), "", false, nil
		}
		if r == '=' && i < len(s)-1 {
			rem, value, quoted, err := parseValue(s[i+1:])
			return rem, string(s[:i]), value, quoted, err
		}
	}
	return nil, string(s), "", false, ErrNoKey
}

func parseValue(s []rune) (remainder []rune, value string, quoted bool, err error) {
	var quoteChar rune
	var escaped bool
	if s[0] == '"' || s[0] == '\'' {
		quoteChar = s[0]
		quoted = true
	}
	for i, r := range s[1:] {
		if !quoted && unicode.IsSpace(r) {
			return s[i+1:], string(s[:i+1]), quoted, nil
		} else if quoted {
			if escaped {
				escaped = false
				continue
			}
			if r == '\\' {
				escaped = true
				continue
			}
			if r == quoteChar {
				return s[i+2:], string(s[1 : i+1]), quoted, nil
			}

		}
	}
	if quoted {
		return nil, string(s), quoted, ErrMissingQuote
	}
	return nil, string(s), quoted, nil
}

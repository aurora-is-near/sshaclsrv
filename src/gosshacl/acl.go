package gosshacl

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/aurora-is-near/sshaclsrv/src/delegatesign"
)

const (
	lineDelim         = '\n'
	fieldDelim        = ':'
	comment           = '#'
	rolloverExtension = ".rollover"
	expireTimeFormat  = "20060102150405"
)

var (
	killTime, _ = time.Parse(expireTimeFormat, "19110103000000")
)

// Testing instrumentation.
func hostname() (string, error) {
	return os.Hostname()
}

// Testing instrumentation.
var hostnamefunc = hostname

type aclEntry struct {
	Hostname      string
	User          string
	KeyHash       string
	NotAfter      time.Time
	AuthorizedKey string
}

func (e aclEntry) String() string {
	var tS string
	if !e.NotAfter.IsZero() {
		tS = e.NotAfter.Format(expireTimeFormat)
	}
	return fmt.Sprintf("%s:%s:%s:%s:%s", e.Hostname, e.User, e.KeyHash, tS, e.AuthorizedKey)
}

func (e aclEntry) Sign(publicKey delegatesign.DelegatedKey, privateKey ed25519.PrivateKey) string {
	msg := e.String()
	sig := base64.StdEncoding.EncodeToString(publicKey.Sign(privateKey, []byte(msg)))
	return fmt.Sprintf("%s:%s", sig, msg)
}

const (
	userFieldHostname = iota
	userFieldUsername
	userFieldKeyHash
	userFieldExpireTime
	userFieldAuthorizedKey
)

func parseExpire(e []byte) time.Time {
	var expt time.Time
	var err error
	if len(e) > 0 {
		if expt, err = time.Parse(expireTimeFormat, string(e)); err != nil {
			return killTime
		}
		return expt
	}
	return time.Time{}
}

func newEntry(fields [][]byte) *aclEntry {
	if len(fields) < 4 || len(fields[userFieldHostname]) == 0 || len(fields[userFieldUsername]) == 0 || len(fields[userFieldKeyHash]) == 0 {
		return nil
	}
	authkey := string(bytes.Join(fields[userFieldAuthorizedKey:], []byte{fieldDelim}))
	if len(authkey) == 0 {
		return nil
	}
	ret := new(aclEntry)
	ret.Hostname = string(fields[userFieldHostname])
	ret.User = string(fields[userFieldUsername])
	ret.KeyHash = string(fields[userFieldKeyHash])
	ret.NotAfter = parseExpire(fields[userFieldExpireTime])
	ret.AuthorizedKey = authkey
	return ret
}

// replacement for bytes.FieldsFunc since the latter does not include empty fields.
func cutFields(d []byte, f func(rune) bool) [][]byte {
	var prev int
	ret := make([][]byte, 0, 4)
	if len(d) == 0 {
		return ret
	}
	for i, e := range d {
		if f(rune(e)) {
			ret = append(ret, d[prev:i])
			prev = i + 1
		}
	}
	if len(d[prev:]) > 0 || f(rune(d[prev-1])) {
		ret = append(ret, d[prev:])
	}
	return ret
}

func parseLine(line []byte) *aclEntry {
	if len(line) == 0 {
		return nil
	}
	line = bytes.TrimFunc(line, func(r rune) bool { return unicode.IsSpace(r) })
	if line[0] == comment {
		return nil
	}
	fields := cutFields(line, func(r rune) bool { return r == fieldDelim })
	return newEntry(fields)
}

func modRegex(s string) string {
	return "^" + strings.Replace(strings.Replace(s, ".", "\\.", -1), "*", "[^.]*", -1) + "$"
}

func matchLine(line []byte, host, user, key string) (*aclEntry, bool) {
	e := parseLine(line)
	if e == nil {
		return nil, false
	}
	if e.Hostname != "*" && e.Hostname != host {
		x, err := regexp.Compile(modRegex(e.Hostname))
		if err != nil {
			return nil, false
		}
		if !x.Match([]byte(host)) {
			return nil, false
		}
	}
	if e.User != user {
		return nil, false
	}
	if !e.NotAfter.IsZero() && e.NotAfter.Before(time.Now()) {
		return nil, false
	}
	if e.KeyHash != key || key == "" || e.KeyHash == "" {
		return nil, false
	}
	return e, true
}

func splitKey(key string) string {
	f := strings.FieldsFunc(key, func(r rune) bool { return r == fieldDelim })
	if len(f) < 2 {
		return ""
	}
	return f[1]
}

func findEntry(r io.Reader, user, key string) ([]*aclEntry, error) {
	var line []byte
	var err error
	var ret []*aclEntry
	host, err := hostnamefunc()
	if err != nil {
		return nil, ErrNotFound
	}
	b := bufio.NewReader(r)
	for {
		line, err = b.ReadBytes(lineDelim)
		if e, ok := matchLine(line, host, user, splitKey(key)); ok && e != nil {
			ret = append(ret, e)
		}
		if err != nil {
			if len(ret) > 0 {
				return ret, nil
			}
			if err == io.EOF {
				return nil, ErrNotFound
			}
			return nil, err
		}
	}
}

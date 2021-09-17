// Package gosshacl implements file based access control for SSH (authorizedkeyscommand).
//
// File format:
//    <hostname>:<user>:<sha256_of_key>:<valid from>:<valid to>:[<authorized key entry>]
package gosshacl

import (
	_ "crypto/sha256" // Link sha256.
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/aurora-is-near/sshaclsrv/src/fileperm"
)

var (
	// ErrNotFound is returned if no matching entry could be found.
	ErrNotFound = errors.New("not found")
	// // ErrInvalidExpire is returned if parsing expiry time fails.
	// ErrInvalidExpire = errors.New("invalid expire format")
)

// AuthorizedFile is a file containing authorization information.
type AuthorizedFile os.File

// New opens a file or its rollover.
func New(filename string) (*AuthorizedFile, error) {
	var err error
	var f *os.File
	if f, err = os.Open(filename); err != nil {
		if f, err = os.Open(filename + rolloverExtension); err != nil {
			return nil, err
		}
	}
	if err := fileperm.PermissionCheck(f); err != nil {
		return nil, err
	}
	return (*AuthorizedFile)(f), nil
}

// Close the file.
func (kf *AuthorizedFile) Close() {
	_ = (*os.File)(kf).Close()
}

// FindEntry finds valid entries in the file that match user and key (its sha256 fingerprint).
// It returns the authorized-keys entries that match.
func (kf *AuthorizedFile) FindEntry(w io.Writer, hostname, user, key string) error {
	return FindEntry((*os.File)(kf), w, hostname, user, key)
}

// FindEntryFromFile searches a file for matching keys and writes them to w.
func FindEntryFromFile(filename string, w io.Writer, hostname, user, key string) error {
	kf, err := New(filename)
	if err != nil {
		return err
	}
	defer kf.Close()
	return kf.FindEntry(w, hostname, user, key)
}

// FindEntry searches r for matching keys and writes them to w.
func FindEntry(r io.Reader, w io.Writer, hostname, user, key string) error {
	e, err := findEntry(r, hostname, user, key)
	if len(e) == 0 {
		return err
	}
	for _, s := range e {
		if _, err := fmt.Fprintln(w, s.AuthorizedKey); err != nil {
			return err
		}
	}
	return nil
}

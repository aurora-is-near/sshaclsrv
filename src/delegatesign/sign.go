// Package delegatesign contains delegated signing functionality.
// A master-key signs a sub-key that can then sign until a specified date.
package delegatesign

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"time"
)

const (
	timeLength      = 8
	signatureLength = ed25519.SignatureSize
	keyLength       = ed25519.PublicKeySize
	masterKeyLength = keyLength
	subKeyLength    = keyLength
	masterKeyStart  = delegatedKeyHeaderStart
	masterKeyEnd    = masterKeyStart + masterKeyLength
	subKeyStart     = masterKeyEnd
	subKeyEnd       = subKeyStart + subKeyLength
	notAfterStart   = subKeyEnd
	notAfterEnd     = notAfterStart + timeLength
	signatureStart  = notAfterEnd
	signatureEnd    = signatureStart + signatureLength

	delegatedKeyHeaderStart  = 0
	delegatedKeyHeaderEnd    = delegatedKeyHeaderStart + delegatedKeyHeaderLength
	delegatedKeyHeaderLength = masterKeyLength + subKeyLength + timeLength

	// DelegatedKeyLength is the length of a delegated key.
	DelegatedKeyLength = delegatedKeyHeaderLength + signatureLength
	delegatedKeyBegin  = 0
	delegatedKeyEnd    = delegatedKeyBegin + DelegatedKeyLength
	delegatedSigBegin  = delegatedKeyEnd
	delegatedSigEnd    = delegatedKeyEnd + signatureLength

	// DelegatedSignatureLength is the length of a delegated signature.
	DelegatedSignatureLength = DelegatedKeyLength + signatureLength
)

// Errors
var (
	ErrFormat    = errors.New("delegatesign: invalid key format")
	ErrExpired   = errors.New("delegatesign: expired delegation")
	ErrSignature = errors.New("delegatesign: delegation signature invalid")
)
var (
	byteOrder = binary.LittleEndian
)

// DelegatedKey contains: Master-PublicKey, Sub-PublicKey, NotAfter (unixtime), Master-PublicKey-Signature
type DelegatedKey []byte

// DelegateKey creates a key delegation from masterPrivateKey to subPublicKey with notAfter determining after which time the key shall not be valid anymore.
func DelegateKey(masterPrivateKey ed25519.PrivateKey, subPublicKey ed25519.PublicKey, notAfter time.Time) DelegatedKey {
	key := make([]byte, DelegatedKeyLength)
	copy(key[masterKeyStart:masterKeyEnd], masterPrivateKey.Public().(ed25519.PublicKey))
	copy(key[subKeyStart:subKeyEnd], subPublicKey)
	if !notAfter.IsZero() {
		byteOrder.PutUint64(key[notAfterStart:notAfterEnd], uint64(notAfter.Unix()))
	}
	sig := ed25519.Sign(masterPrivateKey, key[delegatedKeyHeaderStart:delegatedKeyHeaderEnd])
	copy(key[signatureStart:signatureEnd], sig)
	return key
}

func isZeroSlice(d []byte) bool {
	for _, b := range d {
		if b != 0x00 {
			return false
		}
	}
	return true
}

// Key returns the embedded keys in a DelegatedKey while verifying that signature and notAfter are valid
func (delegatedKey DelegatedKey) Key() (masterPublicKey, subPublicKey ed25519.PublicKey, err error) {
	masterPublicKey, subPublicKey, _, err = delegatedKey.Contents()
	return masterPublicKey, subPublicKey, err
}

// Contents returns the embedded contents of the key.
func (delegatedKey DelegatedKey) Contents() (masterPublicKey, subPublicKey ed25519.PublicKey, until time.Time, err error) {
	until, err = delegatedKey.Until()
	masterPublicKey = ed25519.PublicKey(delegatedKey[masterKeyStart:masterKeyEnd])
	if !ed25519.Verify(masterPublicKey, delegatedKey[delegatedKeyHeaderStart:delegatedKeyHeaderEnd], delegatedKey[signatureStart:signatureEnd]) {
		return nil, nil, until, ErrSignature
	}
	subPublicKey = ed25519.PublicKey(delegatedKey[subKeyStart:subKeyEnd])
	return masterPublicKey, subPublicKey, until, err
}

// Until returns the time until which the delegation is valid. Does NOT verify the delegation.
func (delegatedKey DelegatedKey) Until() (time.Time, error) {
	if len(delegatedKey) != DelegatedKeyLength {
		return time.Time{}, ErrFormat
	}
	if !isZeroSlice(delegatedKey[notAfterStart:notAfterEnd]) {
		notAfterBin := int64(byteOrder.Uint64(delegatedKey[notAfterStart:notAfterEnd]))
		notAfter := time.Unix(notAfterBin, 0)
		if !notAfter.IsZero() && notAfter.Before(time.Now()) {
			return time.Time{}, ErrExpired
		}
		return notAfter, nil
	}
	return time.Time{}, nil
}

// Delegator returns the master public key embedded in the DelegatedKey.
func (delegatedKey DelegatedKey) Delegator() ed25519.PublicKey {
	if len(delegatedKey) != DelegatedKeyLength {
		return make([]byte, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(delegatedKey[masterKeyStart:masterKeyEnd])
}

// DelegatedSignature is a signature that contains delegation information.
type DelegatedSignature []byte

// Sign msg with delegatedKey and privateKey.
func (delegatedKey DelegatedKey) Sign(privateKey ed25519.PrivateKey, msg []byte) DelegatedSignature {
	sig := ed25519.Sign(privateKey, msg)
	sigX := make([]byte, DelegatedSignatureLength)
	copy(sigX[delegatedKeyBegin:delegatedKeyEnd], delegatedKey)
	copy(sigX[delegatedSigBegin:delegatedSigEnd], sig)
	return sigX
}

// Key returns the embedded key from a signature.
func (delegatedSig DelegatedSignature) Key() DelegatedKey {
	return DelegatedKey(delegatedSig[delegatedKeyBegin:delegatedKeyEnd])
}

// Verify that the delegatedSig is a valid delegated signature of publicKey over msg.
func (delegatedSig DelegatedSignature) Verify(publicKey ed25519.PublicKey, msg []byte) (subPublicKey ed25519.PublicKey, ok bool) {
	if len(delegatedSig) != DelegatedSignatureLength {
		return nil, false
	}
	if subtle.ConstantTimeCompare(delegatedSig.Key().Delegator(), publicKey) == 0 {
		return nil, false
	}
	_, sub, err := delegatedSig.Key().Key()
	if err != nil {
		return nil, false
	}
	if ed25519.Verify(sub, msg, delegatedSig[delegatedSigBegin:delegatedSigEnd]) {
		return sub, true
	}
	return nil, false
}

package delegatesign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func copySlice(d []byte) []byte {
	r := make([]byte, len(d))
	copy(r, d)
	return r
}

func flipBit(d []byte, bit int) []byte {
	p := bit / 8
	d[p] = d[p] ^ (0x01 << (bit % 8))
	return d
}

func TestDelegate(t *testing.T) {
	masterPub, masterPriv, _ := ed25519.GenerateKey(rand.Reader)
	subPub, _, _ := ed25519.GenerateKey(rand.Reader)
	dkey := DelegateKey(masterPriv, subPub, time.Now().Add(time.Hour))
	masterPubT, subPubT, err := dkey.Key()
	if err != nil {
		t.Errorf("Delegation failed: %s", err)
	}
	if !bytes.Equal(masterPubT, masterPub) {
		t.Error("MasterPublicKey corrupt")
	}
	if !bytes.Equal(subPubT, subPub) {
		t.Error("SubPublicKey corrupt")
	}
	dkey = DelegateKey(masterPriv, subPub, time.Now().Add(time.Hour*-1))
	_, _, err = dkey.Key()
	if err == nil {
		t.Errorf("Expiration ignored: %s", err)
	}
	dkey = DelegateKey(masterPriv, subPub, time.Time{})
	_, _, err = dkey.Key()
	if err != nil {
		t.Errorf("Delegation failed zerotime: %s", err)
	}
	for i := 0; i < len(dkey)*8; i++ {
		tkey := flipBit(copySlice(dkey), i)
		if _, _, err := DelegatedKey(tkey).Key(); err == nil {
			if err == ErrExpired {
				continue
			}
			t.Errorf("Malable bit: %d", i)
		}
	}
}

func TestDelegateSign(t *testing.T) {
	msg := []byte("test msg")
	masterPub, masterPriv, _ := ed25519.GenerateKey(rand.Reader)
	subPub, subPriv, _ := ed25519.GenerateKey(rand.Reader)
	dkey := DelegateKey(masterPriv, subPub, time.Now().Add(time.Hour))
	sig := dkey.Sign(subPriv, msg)
	if sub, ok := sig.Verify(masterPub, msg); !ok {
		t.Error("Verification failure")
	} else if !bytes.Equal(sub, subPub) {
		t.Error("Wrong embedded subkey")
	}
}

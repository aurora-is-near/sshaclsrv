package gosshacl

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aurora-is-near/sshaclsrv/src/delegatesign"
)

func TestRemoteParse(t *testing.T) {
	masterPub, masterPriv, _ := ed25519.GenerateKey(rand.Reader)
	subPub, subPriv, _ := ed25519.GenerateKey(rand.Reader)
	delkey := delegatesign.DelegateKey(masterPriv, subPub, time.Now().Add(time.Minute))
	hostnamefunc = hostnameTest
	e := &aclEntry{
		Hostname:      "localhost",
		User:          "root",
		KeyHash:       tkhc,
		AuthorizedKey: tk,
	}
	e.NotAfter, _ = time.Parse(expireTimeFormat, "21091222030101")
	entry := e.Sign(delkey, subPriv)
	buf := new(bytes.Buffer)
	buf.Write([]byte(entry))
	remote := NewRemote("https://127.0.0.1:9100", masterPub, "")
	w := new(bytes.Buffer)
	if err := remote.parseResponse(w, buf, "localhost", "root", tkhc); err != nil {
		t.Errorf("parseResponse: %s", err)
	}
	if strings.TrimSpace(w.String()) != ok {
		t.Error("wrong key")
	}
}

type handler struct {
	f func(w http.ResponseWriter, r *http.Request)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.f(w, r)
}

func TestRemote(t *testing.T) {
	masterPub, masterPriv, _ := ed25519.GenerateKey(rand.Reader)
	subPub, subPriv, _ := ed25519.GenerateKey(rand.Reader)
	delkey := delegatesign.DelegateKey(masterPriv, subPub, time.Now().Add(time.Minute))
	hostnamefunc = hostnameTest
	e := &aclEntry{
		Hostname:      "localhost",
		User:          "root",
		KeyHash:       tkhc,
		AuthorizedKey: tk,
	}
	e.NotAfter, _ = time.Parse(expireTimeFormat, "21091222030101")
	entry := e.Sign(delkey, subPriv)
	server := &http.Server{
		Addr: "127.0.0.1:9100",
		Handler: &handler{f: func(w http.ResponseWriter, r *http.Request) {
			if r.URL.String() != "/RFqtJf2QzWNTc1nh8A1q7giSaFoZSurk5q5uZp91MPM/localhost/root" {
				t.Error("Wrong URL")
			}
			_, _ = w.Write([]byte(entry))
		}},
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	go func() {
		if err := server.ListenAndServe(); err != nil {
			fmt.Println(err)
		}
	}()
	time.Sleep(time.Second / 2)
	remote := NewRemote("http://127.0.0.1:9100", masterPub, "")
	w := new(bytes.Buffer)
	if err := remote.FindEntry(w, "root", tkhc); err != nil {
		t.Fatalf("FindEntry: %s", err)
	}
	if strings.TrimSpace(w.String()) != ok {
		t.Error("wrong key")
	}
}

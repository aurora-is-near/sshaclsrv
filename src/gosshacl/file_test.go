package gosshacl

import (
	"bytes"
	"testing"
	"time"
)

var (
	tk   = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJcOEAu5+f9pPqRM6rZWbWUsh/uV8lWpXjYSwy1QrvtuyyJTYtVJkVxl+Kry0UC/SaqYayt9jnEXaBEZLXLeS2w="
	tkhc = "RFqtJf2QzWNTc1nh8A1q7giSaFoZSurk5q5uZp91MPM"
	tkh  = "SHA256:" + tkhc
	te   = "localhost:root:RFqtJf2QzWNTc1nh8A1q7giSaFoZSurk5q5uZp91MPM:21091222030101:ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJcOEAu5+f9pPqRM6rZWbWUsh/uV8lWpXjYSwy1QrvtuyyJTYtVJkVxl+Kry0UC/SaqYayt9jnEXaBEZLXLeS2w="
	ok   = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJcOEAu5+f9pPqRM6rZWbWUsh/uV8lWpXjYSwy1QrvtuyyJTYtVJkVxl+Kry0UC/SaqYayt9jnEXaBEZLXLeS2w="
)

func TestEntry(t *testing.T) {
	e := &aclEntry{
		Hostname:      "localhost",
		User:          "root",
		KeyHash:       tkhc,
		AuthorizedKey: tk,
	}
	e.NotAfter, _ = time.Parse(expireTimeFormat, "21091222030101")
	if e.String() != te {
		t.Error("Formatting aclEntry")
	}
}

func TestFindEntryHash(t *testing.T) {
	b := new(bytes.Buffer)
	w := new(bytes.Buffer)
	b.WriteString(te + "\n" + te)
	if err := FindEntry(b, w, "localhost", "root", string(tkh)); err != nil {
		t.Fatalf("FindEntry: %s", err)
	}
}

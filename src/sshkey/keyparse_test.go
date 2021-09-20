package sshkey

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
)

func TestParse(t *testing.T) {
	td := "permitopen=\"127.0.0.1:8080\" permitopen=\"127.0.0.1:8081\" expiry-time=\"20210923\" ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJcOEAu5+f9pPqRM6rZWbWUsh/uV8lWpXjYSwy1QrvtuyyJTYtVJkVxl+Kry0UC/SaqYayt9jnEXaBEZLXLeS2w= gregory@primachoreoffal.com"
	key, err := ParseKey(td)
	if err != nil {
		t.Errorf("Parse: %s", err)
	}
	spew.Dump(key.Fingerprint, key.NotAfter)
}

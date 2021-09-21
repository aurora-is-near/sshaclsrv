package model

import (
	"testing"
)

func TestRecursive(t *testing.T) {
	notFunc := func(dir string) bool { return false }
	if err := cleanFSTree("/tmp/compile.3898433458/", notFunc, "/tmp/compile.3898433458/users/Johann"); err != nil {
		t.Errorf("cleanFSTree: %s", err)
	}
}

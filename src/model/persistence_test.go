package model

import (
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"
)

var users = map[UserName][]string{
	"Johann": {
		"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJcOEAu5+f9pPqRM6rZWbWUsh/uV8lWpXjYSwy1QrvtuyyJTYtVJkVxl+Kry0UC/SaqYayt9jnEXaBEZLXLeS2w=",
	},
}

var delegatedKey = `# Delegated Key until 2031-09-27 21:32:25
LSN6QD5WO3MYOIVIWI7W64TXLJHGKQ4Q2NFWVHMRI6TXPS4LYWUT5YHSZ2S5HGSXHE77EN55RGIHZVQBJRSOHNL3QUOU3G3JXKEKFOQ=
TPLNJGKCBLEOPNCYUGOKQJVKAR52IRQIUU35YYJKTII5I74WFROD5YHSZ2S5HGSXHE77EN55RGIHZVQBJRSOHNL3QUOU3G3JXKEKFOTJ3YQHIAAAAAAED7IBJ7MOTMVLLJWTVBRNOIPFHBPRWBKQEWWW3NGPYY36J45Y5DIOQUEYQKGJ722CJROUZ4TUCLR5OGOKZWT7B2VV2H7V4YFP3M6BB4======`

func mkUserFiles(dir string) error {
	_ = os.Mkdir(dir, 0700)
	for user, keys := range users {
		if err := ioutil.WriteFile(path.Join(dir, string(user)), []byte(strings.Join(keys, "\n")), 0400); err != nil {
			return err
		}
	}
	return nil
}

func TestPersistence_CompileAll(t *testing.T) {
	dir, err := ioutil.TempDir(os.TempDir(), "compile.*")
	if err != nil {
		t.Fatalf("TempDir: %s", err)
	}
	userDir := path.Join(dir, "users")
	if err := mkUserFiles(userDir); err != nil {
		t.Fatalf("UserDir: %s", err)
	}
	modelFile := path.Join(dir, "model.cfg")
	keyFile := path.Join(dir, "delegate.key")
	baseDir := path.Join(dir, "public")
	if err := ioutil.WriteFile(modelFile, []byte(data), 0400); err != nil {
		t.Errorf("Write mode: %s", err)
	}
	if err := ioutil.WriteFile(keyFile, []byte(delegatedKey), 0400); err != nil {
		t.Errorf("Write key: %s", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	// fmt.Println(dir)
	pers := Persistence{
		ModelFile: modelFile,
		UserDir:   userDir,
		BaseDir:   baseDir,
		KeyFile:   keyFile,
	}
	if warnings, err := pers.CompileAndStore(); err != nil {
		t.Fatalf("CompileAndStore: %s", err)
	} else if len(warnings) > 0 {
		// fmt.Println(warnings)
	}
	if warnings, err := pers.Update(); err != nil {
		t.Fatalf("Update: %s", err)
	} else if len(warnings) > 0 {
		// fmt.Println(warnings)
	}
}

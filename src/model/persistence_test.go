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

var delegatedKey = `# Delegated Key until 2021-09-22 01:22:03
ZKTR3NLYB7T7OQAXYGKIYWO72TQH57RU2SNPO7TD6LIHWN5Z3OAZZHXBOBFZCGD7UOSNQ5FT7HF6RDW7CASEKIGKOXAHGQM4WAVDEJA=
XNCK7HW4S7FKGD2AJ4D636KZG4FYGHB2ZMXM356WYIFFQJRI7TLJZHXBOBFZCGD7UOSNQ5FT7HF6RDW7CASEKIGKOXAHGQM4WAVDEJB3QVFGCAAAAAANPSM6UGPT3TL2DBHVQAPZIASNVKT4L66DJXEEILEB2IWOZ7EJ5DQJW5MSFCO3EYZSPRUADKI4GYNIBEHXEUIBP5D74BLX24OAQTKJAU======`

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
	modelCache := path.Join(dir, "model.cache")
	keyFile := path.Join(dir, "delegate.key")
	baseDir := path.Join(dir, "public")
	keyDir := path.Join(baseDir, "key")
	hostDir := path.Join(baseDir, "host")
	if err := ioutil.WriteFile(modelFile, []byte(data), 0400); err != nil {
		t.Errorf("Write mode: %s", err)
	}
	if err := ioutil.WriteFile(keyFile, []byte(delegatedKey), 0400); err != nil {
		t.Errorf("Write key: %s", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	// fmt.Println(dir)
	pers := Persistence{
		ModelFile:      modelFile,
		ModelCacheFile: modelCache,
		UserDir:        userDir,
		BaseDir:        baseDir,
		KeyFile:        keyFile,
		PerKeyDir:      keyDir,
		PerHostDir:     hostDir,
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

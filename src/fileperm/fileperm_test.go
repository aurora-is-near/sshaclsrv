package fileperm

import (
	"io/fs"
	"io/ioutil"
	os "os"
	"path"
	"testing"
)

func TestWriteable(t *testing.T) {
	const writeable = fs.FileMode(uint32(0b1110010010))
	f, err := ioutil.TempFile(os.TempDir(), "go_permcheck_testuid.*")
	if err != nil {
		t.Fatalf("Cannot create temporary file: %s", err)
	}
	defer func() { _ = os.Remove(f.Name()) }()
	defer func() { _ = f.Close() }()
	_ = f.Chmod(writeable)
	if err := PermissionCheck(f); err != ErrWriteable {
		t.Errorf("group/other write bits not detected: %s", err)
	}
}

func TestIrregular(t *testing.T) {
	f, err := os.Open("/etc/")
	if err != nil {
		t.Fatalf("Cannot open file: %s", err)
	}
	defer func() { _ = f.Close() }()
	if err := PermissionCheck(f); err != ErrIrregular {
		t.Error("Irregular file not detected")
	}
}

func TestUIDOwnerSelf(t *testing.T) {
	f, err := ioutil.TempFile(os.TempDir(), "go_permcheck_testuid.*")
	if err != nil {
		t.Fatalf("Cannot create temporary file: %s", err)
	}
	defer func() { _ = os.Remove(f.Name()) }()
	defer func() { _ = f.Close() }()
	if err := PermissionCheck(f); err != nil {
		t.Errorf("error on self owned regular file: %s", err)
	}
}

func TestUIDOwnerOther(t *testing.T) {
	fn := "/tmp/go_permcheck_testuid.wrongowner"
	f, err := os.Open(fn)
	if err != nil {
		t.Skipf("Test file does not exist. Create %s and change owner", fn)
		return
	}
	defer func() { _ = os.Remove(f.Name()) }()
	defer func() { _ = f.Close() }()
	if err := PermissionCheck(f); err != ErrOwner {
		t.Errorf("invalid owner not detected: %s", err)
	}
}

func TestUIDOwnerRoot(t *testing.T) {
	fn := "/etc/passwd"
	f, err := os.Open(fn)
	if err != nil {
		t.Fatalf("Cannot open file: %s", err)
	}
	defer func() { _ = f.Close() }()
	if err := PermissionCheck(f); err != nil {
		t.Errorf("error on root owned regular file: %s", err)
	}
}

func TestSymlink(t *testing.T) {
	d, err := ioutil.TempDir(os.TempDir(), "go_permcheck_testuid.*")
	if err != nil {
		t.Fatalf("Cannot create temporary directory: %s", err)
	}
	defer func() { _ = os.RemoveAll(d) }()
	dfile := path.Join(d, "dest")
	sfile := path.Join(d, "link")
	dest, err := os.Create(dfile)
	if err != nil {
		t.Fatalf("Cannot create file in temporary directory: %s", err)
	}
	_ = dest.Close()
	if err := os.Symlink(dfile, sfile); err != nil {
		t.Fatalf("Cannot create symlink: %s", err)
	}
	f, err := os.Open(sfile)
	if err != nil {
		t.Fatalf("Cannot open file: %s", err)
	}
	defer func() { _ = f.Close() }()
	if err := PermissionCheck(f); err == nil {
		t.Errorf("symlink not detected")
	}
}

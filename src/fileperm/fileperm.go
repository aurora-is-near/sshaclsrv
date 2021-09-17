// Package fileperm contains functions to check permissions on files.
package fileperm

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

var (
	ErrWriteable = errors.New("other than user can write")
	ErrIrregular = errors.New("not a regular file")
	ErrOwner     = errors.New("not owned by root or process")
)

func modeCheck(mode fs.FileMode) error {
	const writePerm = fs.FileMode(uint32(0b1000010010))
	if mode&os.ModeSymlink == os.ModeSymlink {
		fmt.Println("SYMLINK")
	}
	if mode&writePerm != 0 {
		return ErrWriteable
	}
	if mode&(^os.ModeType) != mode {
		return ErrIrregular
	}
	return nil
}

func linkCheck(filename string) error {
	if s, err := os.Readlink(filename); err == nil && len(s) == 0 {
		return nil
	}
	return ErrIrregular
}

// PermissionCheck verifies that an open file is 1) Regular 2) Not writeable by group/other 3) Owned by root or eUID.
// Both the file handle and the full path to file are required. The file must have been opened by absolute path.
func PermissionCheck(file *os.File) error {
	var err error
	var info os.FileInfo
	if info, err = file.Stat(); err != nil {
		return err
	}
	mode := info.Mode()
	if err := modeCheck(mode); err != nil {
		return err
	}
	if s, ok := info.Sys().(*syscall.Stat_t); ok {
		if s.Uid != 0 && int(s.Uid) != os.Geteuid() {
			return ErrOwner
		}
	}
	if err := linkCheck(file.Name()); err != nil {
		return err
	}
	return nil
}

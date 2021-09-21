package model

import (
	"io"
	"os"
	"path"
	"strings"
)

const minimumPathDepths = 2

type fsEntry struct {
	isDir    bool
	fullPath string
}

type fsStream chan fsEntry

// cleanFSTree removes files and empty directories (recursively) as long as yesFunc returns true for them.
func cleanFSTree(base string, yesFunc func(removeDir string) bool, dir ...string) error {
	var err error
	var skip bool
	c := getEntries(dir...)
	for m := range c {
		if !skip && (yesFunc == nil || yesFunc(m.fullPath)) {
			if err = recursiveRemove(base, m.fullPath); err != nil {
				skip = true
			}
		}
	}
	return err
}

func getEntries(dir ...string) fsStream {
	c := make(fsStream, 10)
	go func() {
		for _, d := range dir {
			recursiveDir(c, d)
		}
		close(c)
	}()
	return c
}

func recursiveDir(c fsStream, dir string) {
	var hasEntries bool
	f, err := os.Open(dir)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return
	}
	if !info.IsDir() {
		c <- fsEntry{fullPath: dir}
		return
	}
DirLoop:
	for {
		entries, err := f.Readdir(100)
		if len(entries) > 0 {
			hasEntries = true
			for _, e := range entries {
				p := path.Join(dir, e.Name())
				if e.IsDir() {
					recursiveDir(c, p)
				} else {
					c <- fsEntry{fullPath: p}
				}
			}
		}
		if err != nil {
			break DirLoop
		}
	}
	if !hasEntries {
		c <- fsEntry{fullPath: dir, isDir: true}
	}
}

// Remove one path element at a time, until hitting base.
func recursiveRemove(base, target string) error {
	base = path.Clean(base)
	elements := strings.FieldsFunc(base, func(r rune) bool { return r == os.PathSeparator })
	if len(elements) < minimumPathDepths {
		return ErrShortPath
	}
	target = path.Clean(target)
	for {
		parentDir := path.Dir(target)
		if len(target) == 0 || len(target) <= len(base) || !strings.HasPrefix(target, base) {
			return nil
		}
		f, err := os.Open(target)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		info, err := f.Stat()
		if err != nil {
			return err
		}
		if info.IsDir() {
			entries, err := f.Readdirnames(3)
			if err != nil && err != io.EOF {
				return err
			}
			if len(entries) > 0 {
				return nil
			}
		}
		if err := os.Remove(target); err != nil {
			return err
		}
		target = path.Clean(parentDir)
	}
}

package model

import (
	"os"
	"path"
	"strings"
)

func (persistence *Persistence) genPaths(row *ConfigRow, keyFingerprint string) (server, user string) {
	return path.Clean(path.Join(persistence.perHostDir, string(row.Server))), path.Clean(path.Join(persistence.perKeyDir, keyFingerprint, string(row.Server), string(row.SystemUser)))
}

type fileData map[string][]string

func (data fileData) store() (existingFiles, error) {
	var lastError error
	keepFiles := make(existingFiles)
	for filePath, content := range data {
		fullDir := path.Dir(filePath)
		if info, err := os.Stat(fullDir); err != nil || !info.IsDir() {
			if err := os.MkdirAll(fullDir, 0700); err != nil {
				lastError = err
			}
		}
		contentB := []byte(strings.Join(content, "\n"))
		if err := writeFile(filePath, contentB, 0600); err != nil {
			lastError = err
		}
		keepFiles[filePath] = true
	}
	return keepFiles, lastError
}

type existingFiles map[string]bool

func (keep existingFiles) cleanup(baseDir string, subDirs ...string) error {
	yesFunc := func(removeDir string) bool {
		keepFile, _ := keep[removeDir]
		if !keepFile {
			keep[removeDir] = !keepFile
		}
		return !keepFile
	}
	return cleanFSTree(baseDir, yesFunc, subDirs...)
}

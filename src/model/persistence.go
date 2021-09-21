package model

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/aurora-is-near/sshaclsrv/src/util"

	"github.com/aurora-is-near/sshaclsrv/src/delegatesign"

	"github.com/aurora-is-near/sshaclsrv/src/sshkey"

	"gopkg.in/yaml.v2"
)

// Persistence is the model persistence layer.
type Persistence struct {
	ModelFile      string // File containing the model.
	ModelCacheFile string // File to cache the compiled model to.
	UserDir        string // Directory containing one file per user which in turn contains one ssh-key per line.
	BaseDir        string // Directory containing PerKeyDir and PerHostDir
	PerKeyDir      string // http(s)://<fqdn/path>/key/<sshfingerprint>/<hostname>/<systemuser>
	PerHostDir     string // http(s)://<fqdn/path>/server/<hostname>
	KeyFile        string // File containing delegation key and private key

	privateKey   ed25519.PrivateKey
	delegatedKey delegatesign.DelegatedKey
}

func (persistence *Persistence) dirValid() error {
	baseDir := path.Clean(persistence.BaseDir)
	perKeyDir := path.Clean(persistence.PerKeyDir)
	perHostDir := path.Clean(persistence.PerHostDir)
	if !strings.HasPrefix(perKeyDir, baseDir) || !strings.HasPrefix(perHostDir, baseDir) {
		return ErrBaseDir
	}
	return nil
}

func (persistence *Persistence) getKey() error {
	var err error
	persistence.privateKey, persistence.delegatedKey, err = util.GetKey(persistence.KeyFile)
	return err
}

func writeFile(filename string, data []byte, perm fs.FileMode) error {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return nil
}

type keyCache map[UserName][]*sshkey.Key

func newKeyCache() keyCache {
	return make(keyCache)
}

func (cache keyCache) getKeys(dir string, user UserName) ([]*sshkey.Key, error) {
	var inheritErr error
	if e, ok := cache[user]; ok {
		return e, nil
	}
	d, err := ioutil.ReadFile(path.Join(dir, string(user)))
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)
	buf.Write(d)
	ret := make([]*sshkey.Key, 0, 10)
ReadLoop:
	for {
		l, err := buf.ReadString('\n')
		if len(l) > 0 {
			k, err := sshkey.ParseKey(l)
			if err != nil {
				inheritErr = err
				break ReadLoop
			}
			ret = append(ret, k)
		}
		if err != nil {
			if err == io.EOF {
				break ReadLoop
			}
			inheritErr = err
			break ReadLoop
		}
	}
	cache[user] = ret
	return ret, inheritErr
}

// CompileAndStore model and store to files.
func (persistence *Persistence) CompileAndStore() ([]string, error) {
	modelSrc := SystemACL{}
	d, err := ioutil.ReadFile(persistence.ModelFile)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(d, &modelSrc); err != nil {
		return nil, err
	}
	warnings, rows, err := modelSrc.toRows()
	if err != nil {
		return nil, err
	}
	if d, err = json.MarshalIndent(rows, "", "  "); err != nil {
		return warnings, err
	}
	if err := writeFile(persistence.ModelCacheFile, d, 0600); err != nil {
		return warnings, err
	}
	return persistence.store(rows, warnings)
}

func (persistence *Persistence) store(rows CompiledRows, warnings []string) ([]string, error) {
	w2, files, err := persistence.genLines(rows)
	warnings = append(warnings, w2...)
	if err != nil {
		return warnings, err
	}
	keepfiles, err := files.store()
	if err != nil {
		return warnings, err
	}
	if err := keepfiles.cleanup(persistence.BaseDir, persistence.PerKeyDir, persistence.PerHostDir); err != nil {
		return warnings, err
	}
	return warnings, nil
}

func (persistence *Persistence) genLines(rows CompiledRows) ([]string, fileData, error) {
	if err := persistence.getKey(); err != nil {
		return nil, nil, err
	}
	lines := make(fileData)
	keyCache := newKeyCache()
	warnings := make([]string, 0, 10)
	users, _ := rows.split()
	for user, perUserRows := range users {
	KeyRowLoop:
		for _, accessRow := range perUserRows {
			keys, err := keyCache.getKeys(persistence.UserDir, user)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("Failed to get keys for '%s': %s", user, err))
				continue KeyRowLoop
			}
			if len(keys) == 0 {
				warnings = append(warnings, fmt.Sprintf("User '%s' has no keys.", user))
				continue KeyRowLoop
			}
			for _, key := range keys {
				serverPath, userPath := persistence.genPaths(accessRow, key.Fingerprint)
				tl := TimeList{time.Now().Add(accessRow.Expire), key.NotAfter}
				sort.Sort(tl)
				f := []string{string(accessRow.Server), string(accessRow.SystemUser), key.Fingerprint, sshkey.ExpireTimeToString(tl[0]), key.ApplyToString(accessRow.sshoptions)}
				preLine := strings.Join(f, ":")
				sig := persistence.delegatedKey.Sign(persistence.privateKey, []byte(preLine))
				signedLine := fmt.Sprintf("%s:%s", base64.StdEncoding.EncodeToString(sig), preLine)
				lines[userPath] = []string{signedLine}
				if e, ok := lines[serverPath]; ok {
					lines[serverPath] = append(e, signedLine)
				} else {
					e := make([]string, 1, 10)
					e[0] = signedLine
					lines[serverPath] = e
				}
			}
		}
	}
	return warnings, lines, nil
}

// Update keys only from compiled model.
func (persistence *Persistence) Update() ([]string, error) {
	d, err := ioutil.ReadFile(persistence.ModelCacheFile)
	if err != nil {
		return nil, err
	}
	rows := make(CompiledRows, 0, 10)
	if err := json.Unmarshal(d, &rows); err != nil {
		return nil, err
	}
	return persistence.store(rows, make([]string, 0, 10))
}
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/aurora-is-near/sshaclsrv/src/model"
)

// Config contains the configuration necessary for operation.
var Config = &model.Persistence{
	ModelFile:      "/path/to/model.cfg",
	ModelCacheFile: "/path/to/model.cache",
	UserDir:        "/path/to/userdir",
	BaseDir:        "/path/to/basedir",
	PerKeyDir:      "/path/to/basedir/perkey/",
	PerHostDir:     "/path/to/basedir/perhost/",
	KeyFile:        "/path/to/signKeyfile",
}

const (
	defaultString = "<configfile.json>"
)

var (
	updateFile  string
	compileFile string
	configGen   string
)

func init() {
	flag.StringVar(&updateFile, "update", defaultString, "update model")
	flag.StringVar(&compileFile, "compile", defaultString, "compile model")
	flag.StringVar(&configGen, "mkconfig", defaultString, "generate configfile")
}

func flagEmpty(s string) bool {
	return s == "" || s == defaultString
}

func exampleConfig() error {
	d, err := json.MarshalIndent(Config, "", "  ")
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(configGen, d, 0600); err != nil {
		return err
	}
	return nil
}

func readConfig(filename string) error {
	d, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(d, Config); err != nil {
		return err
	}
	return nil
}

func main() {
	var err error
	var warnings []string
	flag.Parse()
	if (flagEmpty(updateFile) && flagEmpty(compileFile)) || (flagEmpty(updateFile) && flagEmpty(configGen)) || (flagEmpty(compileFile) && flagEmpty(configGen)) {
		_, _ = fmt.Fprintf(os.Stderr, "Cannot use more than one of --update, --compile, or --mkconfig.\n\n")
		os.Exit(1)
	}
	switch {
	case !flagEmpty(configGen):
		err = exampleConfig()
	case !flagEmpty(updateFile):
		if err = readConfig(updateFile); err == nil {
			warnings, err = Config.Update()
		}
	case !flagEmpty(compileFile):
		if err = readConfig(compileFile); err == nil {
			warnings, err = Config.CompileAndStore()
		}
	}
	if len(warnings) > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n\n", strings.Join(warnings, "\n"))
	}
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %s\n\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

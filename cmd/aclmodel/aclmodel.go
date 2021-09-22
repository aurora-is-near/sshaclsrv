package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/aurora-is-near/sshaclsrv/cmd/aclmodel/server"

	"github.com/aurora-is-near/sshaclsrv/src/model"
)

// Config contains the configuration necessary for operation.
var Config = &model.Persistence{
	ModelFile: "/path/to/model.yaml",
	UserDir:   "/path/to/users",
	BaseDir:   "/path/to/basedir",
	KeyFile:   "/path/to/signKeyfile",
}

const (
	defaultString = "<configfile.json>"
)

var (
	updateFile  string
	compileFile string
	configGen   string
	listen      bool
	port        uint
)

func init() {
	flag.StringVar(&updateFile, "update", defaultString, "update model")
	flag.StringVar(&compileFile, "compile", defaultString, "compile model")
	flag.StringVar(&configGen, "mkconfig", defaultString, "generate configfile")
	flag.BoolVar(&listen, "s", false, "serve via http. For debugging")
	flag.UintVar(&port, "p", 9103, "listen on 127.0.0.1:<port>")
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
	if (!flagEmpty(updateFile) && !flagEmpty(compileFile)) || (!flagEmpty(updateFile) && !flagEmpty(configGen)) || (!flagEmpty(compileFile) && !flagEmpty(configGen)) {
		_, _ = fmt.Fprintf(os.Stderr, "Cannot use more than one of --update, --compile, or --mkconfig.\n\n")
		os.Exit(1)
	}
	if listen && !flagEmpty(configGen) {
		_, _ = fmt.Fprintf(os.Stderr, "Listen cannot be used with --mkconfig.\n\n")
		os.Exit(1)
	}
	if listen && port < 1024 {
		_, _ = fmt.Fprintf(os.Stderr, "Please select a non-privileged port.\n\n")
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
	if listen {
		server.Start(int(port), Config.BaseDir)
	}
	os.Exit(0)
}

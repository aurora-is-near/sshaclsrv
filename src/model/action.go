package model

import (
	"time"

	"github.com/aurora-is-near/sshaclsrv/src/stringduration"
)

// Action describes an activity on a server.
type Action struct {
	name ActionName
	// User is the system username to which to grant access.
	User string `yaml:"User"`
	// Expire enforced expiration of authenticated ssh keys.
	Expire time.Duration `yaml:"Expire"`
	// Push determines if keys for this role are deployed to the servers proactively.
	Push bool `yaml:"Push"`
	// Options contains a list of ssh-authorized-keys options.
	Options string `yaml:"Options"`
}

// UnmarshalYAML parses an Action from YAML.
func (action *Action) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var err error
	type ActionT struct {
		User    string `yaml:"User"`
		Expire  string `yaml:"Expire"`
		Push    bool   `yaml:"Push"`
		Options string `yaml:"Options"`
	}
	var tmp ActionT
	if err := unmarshal(&tmp); err != nil {
		return err
	}
	if action.Expire, err = stringduration.Parse(tmp.Expire); err != nil {
		return err
	}
	action.User = tmp.User
	action.Push = tmp.Push
	action.Options = tmp.Options
	return nil
}

package model

import (
	"time"

	"github.com/aurora-is-near/sshaclsrv/src/stringduration"
)

// User is an organization user/person.
type User struct {
	name UserName
	// NotAfter prevents authentication of the user after a date.
	NotAfter time.Time `yaml:"NotAfter"`
	// Expire enforces expiration for authenticated keys.
	Expire time.Duration `yaml:"Expire"`
	Roles  []RoleName    `yaml:"Roles"`
}

// UnmarshalYAML parses YAML into User.
func (user *User) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var err error
	type UserT struct {
		Expire string     `yaml:"Expire"`
		Roles  []RoleName `yaml:"Roles"`
	}
	var tmp UserT
	if err := unmarshal(&tmp); err != nil {
		return err
	}
	if user.Expire, err = stringduration.Parse(tmp.Expire); err != nil {
		return err
	}
	user.Roles = tmp.Roles
	return nil
}

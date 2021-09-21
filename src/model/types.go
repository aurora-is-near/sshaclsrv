package model

import "errors"

var (
	// ErrShortPath is returned when trying to clean up a directory structure that is not deep enough.
	ErrShortPath = errors.New("refusing to operate on a short path")
	// ErrBaseDir is returned if the baseDir is wrongly configured.
	ErrBaseDir = errors.New("baseDir must be the prefix of perKeyDir and perUserDir")
)

// ServerName is the name of a server. FQDN.
type ServerName string

// ActionName is the name of an available action.
type ActionName string

// UserName is a user/person within the organization.
type UserName string

// RoleName is a role that refers to a collection of available actions.
type RoleName string

// ServerMatch is a glob pattern to match one or more servers.
type ServerMatch string

// SystemUserName refers to a system user on a node.
type SystemUserName string

// SystemACL is the model from which to generate permission rows.
type SystemACL struct {
	Servers map[ServerName]*Server             `yaml:"Servers"`
	Actions map[ActionName]*Action             `yaml:"Actions"`
	Users   map[UserName]*User                 `yaml:"Users"`
	Roles   map[RoleName]map[ServerMatch]*Role `yaml:"Roles"`
}

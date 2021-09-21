package model

import (
	"fmt"
	"strings"

	"github.com/aurora-is-near/sshaclsrv/src/sshkey"

	"github.com/aurora-is-near/sshaclsrv/src/hostmatch"
)

func validServerName(server ServerName) bool {
	return !strings.ContainsAny(string(server), "/\\:")
}

func validUserName(user UserName) bool {
	return !strings.ContainsAny(string(user), "/\\:")
}

func validSystemUserName(user SystemUserName) bool {
	return !strings.ContainsAny(string(user), "/\\:")
}

func (acl *SystemACL) validate() error {
	systemusers := make(map[SystemUserName]bool)
	for server, actions := range acl.Servers {
		if !validServerName(server) {
			return fmt.Errorf("server '%s' contains illegal characters", server)
		}
		actions.servername = server
		for _, action := range actions.Actions {
			if _, ok := acl.Actions[action]; !ok {
				return fmt.Errorf("server '%s' references unknown action '%s'", server, action)
			}
		}
	}
	for name, action := range acl.Actions {
		var err error
		action.name = name
		if !validSystemUserName(action.User) {
			return fmt.Errorf("action '%s' contains systemuser '%s' with illegal characters", action.name, action.User)
		}
		if action.sshoptions, err = sshkey.ParseOptions(action.Options); err != nil {
			return fmt.Errorf("Action '%s' contains invalid options '%s'. %s", action.name, action.Options, err)
		}
		if _, ok := systemusers[action.User]; ok {
			return fmt.Errorf("action '%s' contains duplicate systemuser '%s'", name, action.User)
		}
		systemusers[action.User] = true
	}
	for name, user := range acl.Users {
		user.name = name
		if !validUserName(name) {
			return fmt.Errorf("username '%s' contains illegal characters", name)
		}
		for _, role := range user.Roles {
			if _, ok := acl.Roles[role]; !ok {
				return fmt.Errorf("user '%s' references unknown role '%s'", name, role)
			}
		}
	}
	for rolename, server := range acl.Roles {
		for serverdesc, actions := range server {
			actions.role = rolename
			actions.serverDesc = serverdesc
			for _, action := range actions.Actions {
				if _, ok := acl.Actions[action]; !ok {
					return fmt.Errorf("role '%s', server '%s' references unknown action '%s'", rolename, serverdesc, action)
				}
			}
		}
	}
	return nil
}

func (acl *SystemACL) warnings() []string {
	ret := make([]string, 0, 10)
	servers := make([]*Server, 0, len(acl.Servers))
	for _, server := range acl.Servers {
		servers = append(servers, server)
	}
	serverdescList := make(map[ServerMatch][]*Server)
	for rolename, serversList := range acl.Roles {
		for serverdesc, serverDescA := range serversList {
			if serverList, ok := serverdescList[serverdesc]; ok {
				serverDescA.servers = serverList
			} else {
				matches := make([]*Server, 0, 10)
				pat := hostmatch.Compile(string(serverdesc))
				for _, server := range servers {
					if pat.Match(string(server.servername)) {
						matches = append(matches, server)
					}
				}
				serverdescList[serverdesc] = matches
				serverDescA.servers = matches
			}
			if len(serverDescA.servers) == 0 {
				ret = append(ret, fmt.Sprintf("role '%s',serverdesc '%s' does not match any servers", rolename, serverdesc))
			}
		}
	}
	return nil
}

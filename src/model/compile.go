package model

import (
	"time"

	"github.com/aurora-is-near/sshaclsrv/src/sshkey"
)

// ConfigRow contains one access description.
type ConfigRow struct {
	// Push determines if keys for this role are deployed to the servers proactively.
	Push bool
	// Server is the name of the server.
	Server ServerName
	// User is the organization user/person with access.
	User UserName
	// SystemUser is the user on the system.
	SystemUser SystemUserName
	// Expire enforces expiration of authenticated keys.
	Expire time.Duration
	// Options are ssh-authorized-keys options to apply.
	Options    string
	sshoptions sshkey.Options
}

// CompiledRows contains the compiled model.
type CompiledRows []*ConfigRow

func (rows CompiledRows) split() (byUser map[UserName]CompiledRows, byServer map[ServerName]CompiledRows) {
	byUser, byServer = make(map[UserName]CompiledRows), make(map[ServerName]CompiledRows)
	for _, row := range rows {
		if row.Push {
			if e, ok := byServer[row.Server]; ok {
				e = append(e, row)
				byServer[row.Server] = e
			} else {
				e := make(CompiledRows, 1, 10)
				e[0] = row
				byServer[row.Server] = e
			}
		}
		if e, ok := byUser[row.User]; ok {
			e = append(e, row)
			byUser[row.User] = e
		} else {
			e := make(CompiledRows, 1, 10)
			e[0] = row
			byUser[row.User] = e
		}

	}
	return byUser, byServer
}

func minExpire(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func noZeroExpire(a, b time.Duration) time.Duration {
	if a != 0 {
		return a
	}
	return b
}

func minExpireNoZero(a, b time.Duration) time.Duration {
	if a != 0 && b != 0 {
		return minExpire(a, b)
	}
	return noZeroExpire(a, b)
}

func (acl *SystemACL) toRows() (warnings []string, rows CompiledRows, err error) {
	if err := acl.validate(); err != nil {
		return nil, nil, err
	}
	warnings = acl.warnings()
	configs := make(CompiledRows, 0, 10)
UserLoop:
	for _, user := range acl.Users {
		if !user.NotAfter.IsZero() && user.NotAfter.Before(time.Now()) {
			continue UserLoop
		}
		for _, userRole := range user.Roles {
			if role, ok := acl.Roles[userRole]; ok {
				for _, serverMatch := range role {
					for _, serverAction := range serverMatch.Actions {
						if actionDetail, ok := acl.Actions[serverAction]; ok {
							for _, server := range serverMatch.servers {
								for _, specificAction := range server.Actions {
									if specificAction == serverAction {
										configs = append(configs, &ConfigRow{
											Server:     server.servername,
											Push:       actionDetail.Push,
											SystemUser: actionDetail.User,
											User:       user.name,
											Expire:     minExpireNoZero(actionDetail.Expire, user.Expire),
											Options:    actionDetail.Options,
											sshoptions: actionDetail.sshoptions,
										})
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return warnings, configs, nil
}

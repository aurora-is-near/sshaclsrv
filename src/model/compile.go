package model

import (
	"time"
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
	SystemUser string
	// Expire enforces expiration of authenticated keys.
	Expire time.Duration
	// Options are ssh-authorized-keys options to apply.
	Options string
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

func (acl *SystemACL) toRows() (warnings []string, rows []*ConfigRow, err error) {
	if err := acl.validate(); err != nil {
		return nil, nil, err
	}
	warnings = acl.warnings()
	configs := make([]*ConfigRow, 0, 10)
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

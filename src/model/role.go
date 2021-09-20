package model

// Role specifies a list of actions assigned to a user.
type Role struct {
	Actions    []ActionName
	servers    []*Server
	role       RoleName
	serverDesc ServerMatch
}

// UnmarshalYAML parses YAML into Role.
func (serverAction *Role) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var tmp []ActionName
	if err := unmarshal(&tmp); err != nil {
		return err
	}
	serverAction.Actions = tmp
	return nil
}

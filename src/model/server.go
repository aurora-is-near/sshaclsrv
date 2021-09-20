package model

// Server is a server within the authenticated domain.
type Server struct {
	// Actions are actions that are available on the server.
	Actions    []ActionName
	servername ServerName
}

// UnmarshalYAML parses YAML into Server.
func (server *Server) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var tmp []ActionName
	if err := unmarshal(&tmp); err != nil {
		return err
	}
	server.Actions = tmp
	return nil
}

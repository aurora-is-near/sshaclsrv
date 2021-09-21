package commands

import (
	"fmt"
	"os"
	"os/user"
	"time"
)

const timeFormat = "2006-01-02 15:04:05"

func formatTime(t time.Time) string {
	return t.Format(timeFormat)
}

func identity() string {
	var username, hostname string
	u, err := user.Current()
	if err == nil {
		username = u.Username
	}
	hostname, _ = os.Hostname()
	return fmt.Sprintf("(generated at '%s' by '%s'@'%s')", formatTime(time.Now()), username, hostname)
}

// Error displays an error to stderr and exits with code 1.
func Error(format string, i ...interface{}) {
	_, _ = fmt.Fprintf(os.Stderr, format, i...)
	os.Exit(1)
}

// Output displays a message on stdout and exits with code 0.
func Output(format string, i ...interface{}) {
	_, _ = fmt.Fprintf(os.Stderr, format, i...)
	os.Exit(0)
}

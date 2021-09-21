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

// WriteFile writes i... to filename using format. Files are readonly and will not overwrite.
func WriteFile(filename, format string, i ...interface{}) error {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0400)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := fmt.Fprintf(f, format, i...); err != nil {
		return err
	}
	return nil
}

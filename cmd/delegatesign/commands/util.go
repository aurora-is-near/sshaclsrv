package commands

import (
	"bufio"
	"encoding/base32"
	"fmt"
	"io"
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

// ReadFile reads contents from filename, skipping comments and decoding remaining lines with base32.
func ReadFile(filename string) (lines [][]byte, err error) {
	ret := make([][]byte, 0, 3)
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	buf := bufio.NewReader(f)
	for {
		l, err := buf.ReadString('\n')
		if len(l) > 0 {
			if l[0] == '#' {
				continue
			}
			lB, err := base32.StdEncoding.DecodeString(l)
			if err != nil {
				return nil, fmt.Errorf("cannot decode %s: %s", filename, err)
			}
			ret = append(ret, lB)
		}
		if err == io.EOF {
			return ret, nil
		}
		if err != nil {
			return nil, fmt.Errorf("cannot read %s: %s", filename, err)
		}
	}
}

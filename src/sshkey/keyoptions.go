package sshkey

import (
	"fmt"
	"strings"
	"time"
)

const (
	sshKeyExpireFormatShort    = "20060102"       // YYYYMMDD
	sshKeyExpireFormatTime     = "200601021504"   // YYYYMMDDHHMM
	sshKeyExpireFormatTimeLong = "20060102150405" // YYYYMMDDHHMMSS
	sshKeyExpireFormatISO      = "2006-01-02 15:04:05"
)

func parseExpireTime(expireString string) (time.Time, error) {
	switch len(expireString) {
	case len(sshKeyExpireFormatShort):
		return time.Parse(sshKeyExpireFormatShort, expireString)
	case len(sshKeyExpireFormatTime):
		return time.Parse(sshKeyExpireFormatTime, expireString)
	case len(sshKeyExpireFormatTimeLong):
		return time.Parse(sshKeyExpireFormatTimeLong, expireString)
	default:
		if strings.ContainsAny(expireString, ":-") {
			return time.Parse(sshKeyExpireFormatISO, expireString)
		}
		return time.Time{}, ErrFormat
	}
}

// Option is a single ssh-authorized-keys option.
type Option struct {
	Key   string
	Value OptionValue
}

// Options is a list of Option.
type Options []Option

func (options Options) String() string {
	r := make([]string, 0, len(options))
	for _, opt := range options {
		switch opt.Value.(type) {
		case BoolOption:
			r = append(r, opt.Key)
		case StringOption:
			if opt.Key == "expiry-time" {
				continue
			}
			r = append(r, fmt.Sprintf("%s=\"%s\"", opt.Key, opt.Value.String()))
		}
	}
	return strings.Join(r, " ")
}

// OptionValue is the value an Option can take.
type OptionValue interface {
	String() string
}

// BoolOption is a bool.
type BoolOption bool

// String returns a string representation of BoolOption.
func (boolOpt BoolOption) String() string {
	if boolOpt {
		return "true"
	}
	return "false"
}

// StringOption is a string.
type StringOption string

// String returns a string representation of StringOption.
func (StringOpt StringOption) String() string {
	return string(StringOpt)
}

func verifyOption(key, value string, quoted bool) (valueI OptionValue, err error) {
	switch key {
	case "agent-forwarding", "cert-authority", "no-agent-forwarding", "no-port-forwarding", "no-pty",
		"no-user-rc", "no-X11-forwarding", "port-forwarding", "pty", "no-touch-required",
		"verify-required", "restrict", "user-rc", "X11-forwarding":
		if quoted {
			return StringOption(value), ErrOption
		}
		return BoolOption(true), nil
	case "permitlisten", "permitopen", "principals", "command", "environment", "from", "tunnel":
		if !quoted {
			return StringOption(value), ErrOption
		}
		return StringOption(value), nil
	case "expiry-time":
		return parseExpireTime(value)
	default:
		return nil, ErrUnknownOption
	}
}

func (options Options) toMap() map[string]OptionValue {
	r := make(map[string]OptionValue)
	for _, v := range options {
		r[v.Key] = v.Value
	}
	return r
}

// Apply "options" to "fromKey" options and return the new list of Option. "options" is the authoritative filter that
// limits "fromKey" options.
func (options Options) Apply(fromKey Options) Options {
	applyOptions := options.toMap()
	keyOptions := fromKey.toMap()
	for k, v := range applyOptions {
		_ = v
		switch k {
		case "no-agent-forwarding":
			delete(keyOptions, "agent-forwarding")
		case "no-pty":
			delete(keyOptions, "pty")
		case "no-port-forwarding":
			delete(keyOptions, "port-forwarding")
		case "no-user-rc":
			delete(keyOptions, "user-rc")
		case "no-X11-forwarding":
			delete(keyOptions, "X11-forwarding")
		}
	}
	ret := make(Options, 0, len(keyOptions)+len(options))
	for i, v := range fromKey {
		switch v.Key {
		case "permitopen", "permitlisten":
			continue
		}
		if _, ok := keyOptions[v.Key]; ok {
			ret = append(ret, fromKey[i])
		}
	}
	return append(ret, options...)
}

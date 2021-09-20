// Package stringduration extends formatting for durations as strings.
package stringduration

import (
	"fmt"
	"time"
)

// Parse a duration (like time.Duration), but additionally support D(ay), W(eek), M(onth), Y(year) being aware of calendar accuracy.
func Parse(s string) (time.Duration, error) {
	var ret time.Duration
	var dur time.Duration
	var err error
	var symbol, lastSymbol byte
	rem := []rune(s)
	lastSymbol = 255
ParseLoop:
	for {
		rem, symbol, dur, err = parseNextDuration(rem)
		if err != nil {
			return 0, err
		}
		if symbol >= lastSymbol {
			return 0, fmt.Errorf("duplicate or unordered multiplier")
		}
		lastSymbol = symbol
		ret += dur
		if len(rem) < 1 {
			break ParseLoop
		}
	}
	return ret, nil
}

// Distance returns the duration between "now" and multiples of year/month/day. If now is zerotime, the current time is used.
func Distance(year, month, day int, now time.Time) time.Duration {
	if now.IsZero() {
		now = time.Now()
	}
	next := time.Date(now.Year()+year, now.Month()+time.Month(month), now.Day()+day, now.Hour(), now.Minute(), now.Second(), now.Nanosecond(), now.Location())
	return next.Sub(now)
}

func nextS(s []rune, i int) bool {
	if i > len(s)-1 {
		return false
	}
	return s[i+1] == 's'
}

func parseNextDuration(s []rune) (rem []rune, mul byte, d time.Duration, err error) {
	var multiplier time.Duration
	var multiplierSymbol byte
	var value time.Duration
	var add time.Duration
	var last int
ParseLoop:
	for i, r := range s {
		switch r {
		case '-', ' ', ':':
			continue ParseLoop
		case 'n':
			if !nextS(s, i) {
				return s, 0, 0, fmt.Errorf("unknown multiplier '%s'", string(r))
			}
			multiplier = time.Nanosecond
			multiplierSymbol = 7
			last = i + 1
			break ParseLoop
		case 'u', 'µ':
			if !nextS(s, i) {
				return s, 0, 0, fmt.Errorf("unknown multiplier '%s'", string(r))
			}
			multiplier = time.Microsecond
			multiplierSymbol = 8
			last = i + 1
			break ParseLoop
		case 's':
			multiplier = time.Second
			multiplierSymbol = 10
			last = i
			break ParseLoop
		case 'm':
			if nextS(s, i) {
				multiplier = time.Millisecond
				multiplierSymbol = 9
				last = i + 1
				break ParseLoop
			}
			multiplier = time.Minute
			last = i
			multiplierSymbol = 11
			break ParseLoop
		case 'h':
			multiplier = time.Hour
			last = i
			multiplierSymbol = 12
			break ParseLoop
		case 'D', 'd':
			multiplier = 1
			last = i
			multiplierSymbol = 13
			value = Distance(0, 0, int(value), time.Time{})
			break ParseLoop
		case 'W', 'w':
			multiplier = 1
			last = i
			multiplierSymbol = 14
			value = Distance(0, 0, int(value)*7, time.Time{})
			break ParseLoop
		case 'M':
			multiplier = 1
			last = i
			multiplierSymbol = 15
			value = Distance(0, int(value), 0, time.Time{})
			break ParseLoop
		case 'Y', 'y':
			multiplier = 1
			last = i
			multiplierSymbol = 16
			value = Distance(int(value), 0, 0, time.Time{})
			break ParseLoop
		case '0':
			add = 0
		case '1':
			add = 1
		case '2':
			add = 2
		case '3':
			add = 3
		case '4':
			add = 4
		case '5':
			add = 5
		case '6':
			add = 6
		case '7':
			add = 7
		case '8':
			add = 8
		case '9':
			add = 9
		default:
			return s, 0, 0, fmt.Errorf("unknown multiplier '%s'", string(r))
		}
		value = add + value*10
		last = i
	}
	return s[last+1:], multiplierSymbol, multiplier * value, nil
}

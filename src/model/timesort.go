package model

import "time"

// TimeList is a list of time values.
type TimeList []time.Time

// Len returns the length of the list.
func (tl TimeList) Len() int { return len(tl) }

// Swap entries in the list.
func (tl TimeList) Swap(i, j int) { tl[i], tl[j] = tl[j], tl[i] }

// Less returns the smaller of two times, defining time.Zero as maximum.
func (tl TimeList) Less(i, j int) bool {
	if tl[j].IsZero() {
		return true
	}
	if tl[i].IsZero() {
		return false
	}
	return tl[i].Before(tl[j])
}

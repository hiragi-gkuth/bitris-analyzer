package analyze

import (
	"fmt"
	"time"
)

// OnTime is per TimeSlot threshold map
type OnTime struct {
	Entire    time.Duration
	Divisions int
	m         map[int64]float64
	unit      int64
}

// NewOnTime returns new one
func NewOnTime(entireDuration time.Duration, divisions int) *OnTime {
	return &OnTime{
		Entire:    entireDuration,
		Divisions: divisions,
		unit:      entireDuration.Nanoseconds() / int64(divisions),
		m:         make(map[int64]float64),
	}
}

// Set sets threshold for time
func (o *OnTime) Set(t time.Time, threshold float64) {
	offset, _ := time.ParseDuration(fmt.Sprintf("%dns", t.UnixNano()%o.Entire.Nanoseconds()))
	index := offset.Nanoseconds() / o.unit
	o.m[index] = threshold
}

// Get gets threshold for time
func (o *OnTime) Get(t time.Time) (float64, bool) {
	offset, _ := time.ParseDuration(fmt.Sprintf("%dns", t.UnixNano()%o.Entire.Nanoseconds()))
	index := offset.Nanoseconds() / o.unit
	threshold, ok := o.m[index]
	return threshold, ok
}

package threshold

import (
	"time"
)

// OnTime is per TimeSlot threshold map
type OnTime struct {
	Entire    time.Duration
	Divisions int
	m         map[int64]float64
	unit      time.Duration
}

// NewOnTime returns new one
func NewOnTime(entireDuration time.Duration, divisions int) *OnTime {
	return &OnTime{
		Entire:    entireDuration,
		Divisions: divisions,
		unit:      entireDuration / time.Duration(divisions),
		m:         make(map[int64]float64),
	}
}

// Set sets threshold for time
func (o *OnTime) Set(t time.Time, threshold float64) {
	index := t.Truncate(time.Duration(o.unit)).Unix() % int64(o.Entire.Seconds())
	o.m[index] = threshold
}

// Get gets threshold for time
func (o *OnTime) Get(t time.Time) (float64, bool) {
	index := t.Truncate(time.Duration(o.unit)).Unix() % int64(o.Entire.Seconds())
	threshold, ok := o.m[index]
	return threshold, ok
}

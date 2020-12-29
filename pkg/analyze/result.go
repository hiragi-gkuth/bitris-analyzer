package analyze

import (
	"net"
	"time"
)

// Result is analyze result
type Result struct {
	BaseThreshold float64
	OnIP          OnIP
	OnTime        OnTime
}

// OnIP is per IP threshold map
type OnIP map[*net.IPNet]float64

// OnTime is per TimeSlot threshold map
type OnTime map[TimeRange]float64

// TimeRange specifies duration of EntireDuration
type TimeRange struct {
	Entire time.Duration
	Begin  time.Duration
	End    time.Duration
}

// type OnIPTime map[]float64 TODO: implement

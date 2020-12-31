package analyze

import "time"

// Threshold is analyzed thresholds per IP, Time and so on
type Threshold struct {
	BaseThreshold float64
	OnIP          *OnIP
	OnTime        *OnTime
}

// NewThreshold return new one
func NewThreshold(subnetMask int, entireDuration time.Duration, divisions int) *Threshold {
	return &Threshold{
		BaseThreshold: 0.0,
		OnIP:          NewOnIP(subnetMask),
		OnTime:        NewOnTime(entireDuration, divisions),
	}
}

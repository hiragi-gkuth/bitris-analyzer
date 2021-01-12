package summarizer

import (
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/authlog"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/net"
)

// ByIPTimeSummary is ip and time summary for authlogs
type ByIPTimeSummary struct {
	IP     net.IP
	Auths  authlog.AuthInfoSlice
	ByTime ByTimeSummaryMap
}

// ByIPTimeSummarySlice is slice of
type ByIPTimeSummarySlice []ByIPTimeSummary

// ByIPTimeSummaryMap is map of
type ByIPTimeSummaryMap map[net.IP]ByIPTimeSummary

// ByIPTime summarize auths by IP and then, Time
func ByIPTime(auths authlog.AuthInfoSlice, subnetMask int, interval time.Duration, divisions int) ByIPTimeSummarySlice {
	byIPTimeSummSlice := ByIPTimeSummarySlice{}
	for _, ipSumm := range ByIP(auths, subnetMask) {
		byTimeSummSlice := ByTime(ipSumm.Auths, interval, divisions)
		byIPTimeSumm := ByIPTimeSummary{
			IP:     ipSumm.IP,
			Auths:  ipSumm.Auths,
			ByTime: byTimeSummSlice.ToMap(),
		}
		byIPTimeSummSlice = append(byIPTimeSummSlice, byIPTimeSumm)
	}
	return byIPTimeSummSlice
}

// ToMap convert ByIPTimeSummarySlice to Map
func (bit ByIPTimeSummarySlice) ToMap() ByIPTimeSummaryMap {
	m := make(ByIPTimeSummaryMap)
	for _, summ := range bit {
		m[summ.IP] = summ
	}
	return m
}

// ToSlice convert ByIPTimeSummaryMap to Slice
func (bit ByIPTimeSummaryMap) ToSlice() ByIPTimeSummarySlice {
	s := ByIPTimeSummarySlice{}
	for _, summ := range bit {
		s = append(s, ByIPTimeSummary{
			IP:     summ.IP,
			ByTime: summ.ByTime,
		})
	}
	return s
}

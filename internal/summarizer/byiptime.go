package summarizer

import (
	"github.com/hiragi-gkuth/bitris-analyzer/internal/net"
)

// ByIPTimeSummary is ip and time summary for authlogs
type ByIPTimeSummary struct {
	byIPTime map[net.IP]ByTimeSummaryMap
}

// func ByIPTime(auths authlog.AuthInfoSlice, subnetMask int, interval time.Duration, divisions int) ByIPTimeSummary {
// }

// Package analyze is provide bitris analyze features
package analyze

import (
	"fmt"
	"net"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/analyzer"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/summarizer"
)

// Analyze structure contains all of analyze stuffs
type Analyze struct {
	ServerID      string
	LogServerHost string
	LogServerPort int
}

// Analyzer interface implements all of analyze features
type Analyzer interface {
}

// New returns new Analyzer
func New(serverID string, logServerHost string, logServerPort int) Analyzer {
	return &Analyze{
		ServerID:      serverID,
		LogServerHost: logServerHost,
		LogServerPort: logServerPort,
	}
}

// Analyze do analysis
func (a *Analyze) Analyze() Result {
	withRTT := false
	mask := 16
	authLogs, regularLogs := a.fetchAuthLogs(24 * time.Hour)

	result := Result{
		OnIP:   make(OnIP),
		OnTime: make(OnTime),
	}

	// calc per IP map
	for _, summ := range summarizer.ByIP(authLogs, mask) {
		calculator := analyzer.NewThresholdCalculator(summ.Auths, regularLogs, withRTT)
		threshold := calculator.CalcBestThreshold(0.1, 1.5, 0.01)
		subnet := summ.IP.SubnetMask(mask)
		_, ipnet, _ := net.ParseCIDR(fmt.Sprintf("%v/%v", subnet, mask))
		result.OnIP[ipnet] = threshold.Authtime
	}
	// calc per Time map
	for _, summ := range summarizer.ByTime(authLogs, 24*time.Hour, 24) {
		calculator := analyzer.NewThresholdCalculator(summ.Auths, regularLogs, withRTT)
		threshold := calculator.CalcBestThreshold(0.1, 1.5, 0.01)
		timeRange := TimeRange{
			Entire: 24 * time.Hour,
			Begin:  summ.Slot.Begin(),
			End:    summ.Slot.End(),
		}
		result.OnTime[timeRange] = threshold.Authtime
	}
	// calc base threshold
	calculator := analyzer.NewThresholdCalculator(authLogs, regularLogs, withRTT)
	threshold := calculator.CalcBestThreshold(0.1, 1.5, 0.01)
	result.BaseThreshold = threshold.Authtime

	return result
}

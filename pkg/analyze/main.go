// Package analyze is provide bitris analyze features
package analyze

import (
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
	SubnetMask    net.IPMask
}

// Analyzer interface implements all of analyze features
type Analyzer interface {
	Analyze(subnetMask int, entireDuration time.Duration, divisions int) Threshold
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
func (a *Analyze) Analyze(subnetMask int, entireDuration time.Duration, divisions int) Threshold {
	withRTT := false
	mask := 16
	authLogs, regularLogs := a.fetchAuthLogs(24 * time.Hour)

	thresholds := NewThreshold(subnetMask, entireDuration, divisions)

	// calc per IP threshold
	for _, summ := range summarizer.ByIP(authLogs, mask) {
		calculator := analyzer.NewThresholdCalculator(summ.Auths, regularLogs, withRTT)
		threshold := calculator.CalcBestThreshold(0.1, 1.5, 0.01)

		thresholds.OnIP.Set(summ.IP.String(), threshold.Authtime)
	}
	// calc per Time threshold
	for _, summ := range summarizer.ByTime(authLogs, 24*time.Hour, 24) {
		calculator := analyzer.NewThresholdCalculator(summ.Auths, regularLogs, withRTT)
		threshold := calculator.CalcBestThreshold(0.1, 1.5, 0.01)

		thresholds.OnTime.Set(time.Now(), threshold.Authtime)

	}
	// calc per IP Time threshold

	// calc base threshold
	calculator := analyzer.NewThresholdCalculator(authLogs, regularLogs, withRTT)
	threshold := calculator.CalcBestThreshold(0.1, 1.5, 0.01)
	thresholds.BaseThreshold = threshold.Authtime

	return *thresholds
}

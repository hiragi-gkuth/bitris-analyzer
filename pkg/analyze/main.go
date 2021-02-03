// Package analyze is provide bitris analyze features
package analyze

import (
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/analyzer"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/summarizer"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/threshold"
)

// Analyze structure contains all of analyze stuffs
type Analyze struct {
	Param Param
}

// Analyzer interface implements all of analyze features
type Analyzer interface {
	Analyze(subnetMask int, entireDuration time.Duration, divisions int) *threshold.Threshold
}

// New returns new Analyzer
func New(param Param) Analyzer {
	return &Analyze{
		Param: param,
	}
}

// Analyze do analysis
func (a *Analyze) Analyze(subnetMask int, entireDuration time.Duration, divisions int) *threshold.Threshold {
	withRTT := false
	authLogs, regularLogs := a.fetchAuthLogs(a.Param.AnalyzeDuration)

	thresholds := threshold.New(subnetMask, entireDuration, divisions)

	// calc per IP threshold
	for _, summ := range summarizer.ByIP(authLogs, subnetMask) {
		calculator := analyzer.NewThresholdCalculator(summ.Auths, regularLogs, withRTT)
		threshold := calculator.CalcBestThreshold(a.Param.SearchBegin, a.Param.SearchEnd, a.Param.SearchStep)

		thresholds.OnIP.Set(summ.IP.String(), threshold.Authtime)
	}
	// calc per Time threshold
	for _, summ := range summarizer.ByTime(authLogs, entireDuration, divisions) {
		if len(summ.Auths) == 0 {
			continue
		}
		calculator := analyzer.NewThresholdCalculator(summ.Auths, regularLogs, withRTT)
		threshold := calculator.CalcBestThreshold(a.Param.SearchBegin, a.Param.SearchEnd, a.Param.SearchStep)

		thresholds.OnTime.Set(summ.Auths[0].AuthAt, threshold.Authtime)

	}
	// calc per IP Time threshold
	for _, summ := range summarizer.ByIPTime(authLogs, subnetMask, entireDuration, divisions) {
		key := summ.IP.String()

		calculatorIP := analyzer.NewThresholdCalculator(summ.Auths, regularLogs, withRTT)
		thresholdForIP := calculatorIP.CalcBestThreshold(a.Param.SearchBegin, a.Param.SearchEnd, a.Param.SearchStep)
		thresholds.OnIPTime.SetForIP(key, thresholdForIP.Authtime)
		for _, timeSumm := range summ.ByTime {
			if len(timeSumm.Auths) == 0 { // サマリに一つも攻撃がなければスキップする
				continue
			}
			calculatorTime := analyzer.NewThresholdCalculator(timeSumm.Auths, regularLogs, withRTT)
			thresholdForTime := calculatorTime.CalcBestThreshold(a.Param.SearchBegin, a.Param.SearchEnd, a.Param.SearchStep)
			thresholds.OnIPTime.SetForIPTime(key, timeSumm.Auths[0].AuthAt, thresholdForTime.Authtime)
		}
	}
	// calc base threshold
	calculator := analyzer.NewThresholdCalculator(authLogs, regularLogs, withRTT)
	threshold := calculator.CalcBestThreshold(a.Param.SearchBegin, a.Param.SearchEnd, a.Param.SearchStep)
	thresholds.BaseThreshold = threshold.Authtime

	return thresholds
}

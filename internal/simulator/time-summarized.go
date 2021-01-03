package simulator

import (
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/analyzer"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/authlog"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/summarizer"
)

func (s Simulator) calcTimeSummarizedPerformance(analyzeData, testData, regulars authlog.AuthInfoSlice) Result {
	// calc base threshold
	baseCalculator := analyzer.NewThresholdCalculator(analyzeData, s.regulars, s.withRTT)
	baseThreshold := baseCalculator.CalcBestThreshold(0.0, 1.5, 0.001)

	// TODO: shit of shit implement
	// DO NOT CHANGE THIS PARAMETERS
	interval := 24 * time.Hour
	division := 24

	/* construct time-threshold map */
	timeThresholdTable := make(map[string]analyzer.Detections)
	for _, summary := range summarizer.ByTime(analyzeData, interval, division) {
		calculator := analyzer.NewThresholdCalculator(summary.Auths, s.regulars, s.withRTT)
		threshold := calculator.CalcBestThreshold(0.0, 1.5, 0.001)

		timeThresholdTable[summary.Key()] = threshold
	}

	/* check performance */
	// detection rate
	detectedCount := 0
	useDefaultCount := 0
	for _, attack := range testData {
		key := summarizer.GetKeyFromAuthAt(attack.AuthAt, interval, division)
		threshold, ok := timeThresholdTable[key]
		if !ok { // 見つけられなかったらデフォルトのしきい値を使用
			threshold = baseThreshold
			useDefaultCount++
		}
		if s.selectAuthtime(attack) < threshold.Authtime {
			detectedCount++
		}
	}
	detectionRate := float64(detectedCount) / float64(len(testData))
	hitRate := 1.0 - float64(useDefaultCount)/float64(len(testData))

	// misdetection rate
	misDetectedCount := 0
	for _, regular := range s.regulars {
		if s.selectAuthtime(regular) < baseThreshold.Authtime {
			misDetectedCount++
		}
	}
	misDetectionRate := float64(misDetectedCount) / float64(len(s.regulars))

	return Result{
		BaseThreshold:    baseThreshold.Authtime,
		HitRate:          hitRate,
		DetectionRate:    detectionRate,
		MisDetectionRate: misDetectionRate,
		Performance:      detectionRate - misDetectionRate,
	}
}

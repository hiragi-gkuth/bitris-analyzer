package simulator

import (
	"github.com/hiragi-gkuth/bitris-analyzer/internal/analyzer"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/authlog"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/summarizer"
)

func (s Simulator) calcTimeSummarizedPerformance(analyzeData, testData, regulars authlog.AuthInfoSlice) Result {
	// calc base threshold
	baseCalculator := analyzer.NewThresholdCalculator(analyzeData, s.regulars, s.withRTT)
	baseThreshold := baseCalculator.CalcBestThreshold(0.0, 1.5, 0.001)

	/* construct time-threshold map */
	timeThresholdTable := make(map[string]analyzer.Detections)
	for _, summary := range summarizer.ByTime(analyzeData, s.entireDuration, s.divisions) {
		if len(summary.Auths) == 0 { // サマリ結果が0なら解析しない
			continue
		}
		calculator := analyzer.NewThresholdCalculator(summary.Auths, s.regulars, s.withRTT)
		threshold := calculator.CalcBestThreshold(0.0, 1.5, 0.001)

		timeThresholdTable[summary.Key()] = threshold
	}

	/* check performance */
	// detection rate
	detectedCount := 0
	useDefaultCount := 0
	for _, attack := range testData {
		key := summarizer.GetKeyFromAuthAt(attack.AuthAt, s.entireDuration, s.divisions)
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

	if s.verbose {
		s.logger.SetPrefix("[simulator:timesum]")
		s.logger.Printf("base: %.3f, hit: %.3f, detec: %.3f, misDetec: %.3f, perf: %.3f\n",
			baseThreshold.Authtime,
			hitRate,
			detectionRate,
			misDetectionRate,
			detectionRate-misDetectionRate)
		s.logger.SetPrefix("[simulator]")
	}

	return Result{
		BaseThreshold:    baseThreshold.Authtime,
		HitRate:          hitRate,
		DetectionRate:    detectionRate,
		MisDetectionRate: misDetectionRate,
		Performance:      detectionRate - misDetectionRate,
	}
}

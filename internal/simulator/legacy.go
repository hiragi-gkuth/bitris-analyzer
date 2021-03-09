package simulator

import (
	"github.com/hiragi-gkuth/bitris-analyzer/internal/analyzer"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/authlog"
)

func (s Simulator) calcLegacyMethodPerformance(analyzeData, testData, regularAuths authlog.AuthInfoSlice) Result {
	calculator := analyzer.NewThresholdCalculator(analyzeData, s.regularAuths, s.withRTT)
	bestDetect := calculator.CalcBestThreshold(0.0, 1.5, 0.001)
	threshold := bestDetect

	// check actual Performance
	// detection rate
	detectedCount := 0
	for _, attack := range testData {
		if s.selectAuthtime(attack) < threshold.Authtime {
			detectedCount++
		}
	}
	detectionRate := float64(detectedCount) / float64(len(testData))
	// misdetection rate
	misDetectedCount := 0
	for _, regular := range s.regularAuths {
		if s.selectAuthtime(regular) < threshold.Authtime {
			misDetectedCount++
		}
	}
	misDetectionRate := float64(misDetectedCount) / float64(len(s.regularAuths))

	if s.verbose {
		s.logger.SetPrefix("[simulator:legacy]")
		s.logger.Printf("base: %.3f, hit: %.3f, detec: %.3f, misDetec: %.3f, perf: %.3f\n",
			threshold.Authtime,
			0.0,
			detectionRate,
			misDetectionRate,
			detectionRate-misDetectionRate)
		s.logger.SetPrefix("[simulator]")
	}

	return Result{
		BaseThreshold:    threshold.Authtime,
		DetectionRate:    detectionRate,
		MisDetectionRate: misDetectionRate,
		Performance:      detectionRate - misDetectionRate,
	}
}

package simulator

import (
	"github.com/hiragi-gkuth/bitris-analyzer/internal/analyzer"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/authlog"
)

func (s Simulator) calcLegacyMethodPerformance(analyzeData, testData, regulars authlog.AuthInfoSlice) Result {
	calculator := analyzer.NewThresholdCalculator(analyzeData, s.regulars, s.withRTT)
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
	for _, regular := range s.regulars {
		if s.selectAuthtime(regular) < threshold.Authtime {
			misDetectedCount++
		}
	}
	misDetectionRate := float64(misDetectedCount) / float64(len(s.regulars))

	return Result{
		BaseThreshold:    threshold.Authtime,
		DetectionRate:    detectionRate,
		MisDetectionRate: misDetectionRate,
		Performance:      detectionRate - misDetectionRate,
	}
}

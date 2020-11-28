package simulator

import (
	"fmt"

	"github.com/hiragi-gkuth/bitris-analyzer/pkg/analyzer"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/authlog"
)

func (s Simulator) calcLegacyMethodPerformance(aAttacks, tAttacks, regulars authlog.AuthInfoSlice) SimulationResult {
	calculator := analyzer.NewThresholdCalculator(aAttacks, regulars, s.WithRTT)
	bestDetect := calculator.CalcBestThreshold(0.0, 1.5, 0.001)
	threshold := bestDetect

	// check actual Performance
	// detection rate
	detectedCount := 0
	for _, attack := range tAttacks {
		if s.selectAuthtime(attack) < threshold.Authtime {
			detectedCount++
		}
	}
	detectionRate := float64(detectedCount) / float64(len(tAttacks))
	// misdetection rate
	misDetectedCount := 0
	for _, regular := range regulars {
		if s.selectAuthtime(regular) < threshold.Authtime {
			misDetectedCount++
		}
	}
	misDetectionRate := float64(misDetectedCount) / float64(len(regulars))

	fmt.Printf("      > DetecRate: %.3f\n", detectionRate)
	fmt.Printf("      > MisDetecRate: %.3f\n", misDetectionRate)
	fmt.Printf("      > Performance: %.3f\n", detectionRate-misDetectionRate)
	fmt.Printf("      > HitRate: %.3f\n", 0.0)

	return SimulationResult{
		BaseThreshold:    threshold.Authtime,
		DetectionRate:    detectionRate,
		MisDetectionRate: misDetectionRate,
		Performance:      detectionRate - misDetectionRate,
	}
}

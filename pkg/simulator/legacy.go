package simulator

import (
	"fmt"

	"github.com/hiragi-gkuth/bitris-analyzer/pkg/analyzer"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/authlog"
)

func (s Simulator) showLegacyMethodPerformance(aAttacks, tAttacks, regulars authlog.AuthInfoSlice) {
	calclator := analyzer.NewThresholdCalculator(aAttacks, regulars, s.WithRTT)
	bestDetect := calclator.CalcBestThreshold(0.0, 1.5, 0.01)
	threshold := bestDetect.Authtime

	// check actual Performance
	// detection rate
	detectedCount := 0
	for _, attack := range tAttacks {
		if s.selectAuthtime(attack) < threshold {
			detectedCount++
		}
	}
	detectionRate := float64(detectedCount) / float64(len(tAttacks))
	// misdetection rate
	misDetectedCount := 0
	for _, regular := range regulars {
		if s.selectAuthtime(regular) < threshold {
			misDetectedCount++
		}
	}
	misDetectionRate := float64(misDetectedCount) / float64(len(regulars))

	fmt.Printf("\tLegacyMode: FixedThreshold: %.3f, DetectionRate: %.1f%%, MisDetectionRate: %.1f%%\n",
		threshold,
		detectionRate*100,
		misDetectionRate*100)
}

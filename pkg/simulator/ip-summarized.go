package simulator

import (
	"fmt"

	"github.com/hiragi-gkuth/bitris-analyzer/pkg/analyzer"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/authlog"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/net"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/summarizer"
)

func (s Simulator) calcIPSummarizedPerformance(aAttacks, tAttacks, regulars authlog.AuthInfoSlice) SimulationResult {
	// calc base threshold
	baseCalculator := analyzer.NewThresholdCalculator(aAttacks, regulars, s.WithRTT)
	baseThreshold := baseCalculator.CalcBestThreshold(0.0, 1.5, 0.001)

	/* construct ip-threshold map */
	ipThresholdTable := make(map[net.IP]analyzer.Detections)
	for _, summary := range summarizer.ByIP(aAttacks, s.SubnetMask) {
		calculator := analyzer.NewThresholdCalculator(summary.Auths, regulars, s.WithRTT)
		threshold := calculator.CalcBestThreshold(0.0, 1.5, 0.001)
		subnet := summary.IP.SubnetMask(s.SubnetMask)
		ipThresholdTable[subnet] = threshold
	}

	/* check performance */
	// detection rate
	detectedCount := 0
	useDefaultCount := 0
	for _, attack := range tAttacks {
		subnet := attack.IP.SubnetMask(s.SubnetMask)
		threshold, ok := ipThresholdTable[subnet]
		if !ok { // 見つけられなかったらデフォルトのしきい値を使用
			threshold = baseThreshold
			useDefaultCount++
		}
		if s.selectAuthtime(attack) < threshold.Authtime {
			detectedCount++
		}
	}
	detectionRate := float64(detectedCount) / float64(len(tAttacks))
	hitRate := 1.0 - float64(useDefaultCount)/float64(len(tAttacks))

	// misdetection rate
	misDetectedCount := 0
	for _, regular := range regulars {
		if s.selectAuthtime(regular) < baseThreshold.Authtime {
			misDetectedCount++
		}
	}
	misDetectionRate := float64(misDetectedCount) / float64(len(regulars))

	fmt.Printf("      > DetecRate: %.3f\n", detectionRate)
	fmt.Printf("      > MisDetecRate: %.3f\n", misDetectionRate)
	fmt.Printf("      > Performance: %.3f\n", detectionRate-misDetectionRate)
	fmt.Printf("      > HitRate: %.3f\n", hitRate)

	return SimulationResult{
		BaseThreshold:    baseThreshold.Authtime,
		HitRate:          hitRate,
		DetectionRate:    detectionRate,
		MisDetectionRate: misDetectionRate,
		Performance:      detectionRate - misDetectionRate,
	}
}

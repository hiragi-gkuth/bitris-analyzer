package simulator

import (
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/analyzer"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/authlog"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/net"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/summarizer"
)

func (s Simulator) calcIPSummarizedPerformance(analyzeData, testData, regulars authlog.AuthInfoSlice) Result {
	// calc base threshold
	baseCalculator := analyzer.NewThresholdCalculator(analyzeData, s.regulars, s.withRTT)
	baseThreshold := baseCalculator.CalcBestThreshold(0.0, 1.5, 0.001)

	/* construct ip-threshold map */
	ipThresholdTable := make(map[net.IP]analyzer.Detections)
	for _, summary := range summarizer.ByIP(analyzeData, s.subnetMask) {
		calculator := analyzer.NewThresholdCalculator(summary.Auths, s.regulars, s.withRTT)
		threshold := calculator.CalcBestThreshold(0.0, 1.5, 0.001)
		subnet := summary.IP.SubnetMask(s.subnetMask)
		ipThresholdTable[subnet] = threshold
	}

	/* check performance */
	// detection rate
	detectedCount := 0
	useDefaultCount := 0
	for _, attack := range testData {
		subnet := attack.IP.SubnetMask(s.subnetMask)
		threshold, ok := ipThresholdTable[subnet]
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

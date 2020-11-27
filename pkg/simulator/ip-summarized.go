package simulator

import (
	"fmt"

	"github.com/hiragi-gkuth/bitris-analyzer/pkg/analyzer"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/authlog"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/net"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/summarizer"
)

func (s Simulator) showIPSummarizedPerformance(aAttacks, tAttacks, regulars authlog.AuthInfoSlice) {
	// calc base threshold
	bcalcer := analyzer.NewThresholdCalculator(aAttacks, regulars, s.WithRTT)
	baseThreshold := bcalcer.CalcBestThreshold(0.0, 1.5, 0.01)

	// construct ip-threshold map
	ipThresholdTable := make(map[net.IP]analyzer.Detections)
	summarized := summarizer.ByIP(aAttacks, 16)
	for _, summary := range summarized {
		calculator := analyzer.NewThresholdCalculator(summary.Auths, regulars, s.WithRTT)
		threshold := calculator.CalcBestThreshold(0.0, 1.5, 0.01)
		subnet := summary.IP.SubnetMask(16)
		ipThresholdTable[subnet] = threshold
	}

	// check performance
	detectedCount := 0
	useDefaultCount := 0
	for _, attack := range tAttacks {
		subnet := attack.IP.SubnetMask(16)
		threshold, ok := ipThresholdTable[subnet]
		if !ok { // 見つけられなかったらデフォルトのしきい値を使用
			threshold = baseThreshold
			useDefaultCount++
		}
		if s.selectAuthtime(attack) < threshold.Authtime {
			detectedCount++
		}
	}

	//pp.Println(ipThresholdTable)
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

	fmt.Printf("\tIPSummariedMode: BaseThreshold: %.3f, HitRate: %.1f%%, DetectionRate: %.1f%%, MisDetectionRate: %.1f%%\n",
		baseThreshold.Authtime,
		hitRate*100,
		detectionRate*100,
		misDetectionRate*100)
}

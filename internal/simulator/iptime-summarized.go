package simulator

import (
	"github.com/hiragi-gkuth/bitris-analyzer/internal/analyzer"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/authlog"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/net"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/summarizer"
)

type ipTimeThreshold struct {
	ip        net.IP
	threshold analyzer.Detections
	m         map[string]analyzer.Detections
}

func (s Simulator) calcIPTimeSummarizedPerformance(analyzeData, testData, regularAuths authlog.AuthInfoSlice) Result {
	// calc base threshold
	baseCalculator := analyzer.NewThresholdCalculator(analyzeData, s.regularAuths, s.withRTT)
	baseThreshold := baseCalculator.CalcBestThreshold(0.0, 1.5, 0.001)

	/* construct ip-threshold map */
	ipTimeThreMap := make(map[net.IP]ipTimeThreshold)
	for _, ipSumm := range summarizer.ByIPTime(analyzeData, s.subnetMask, s.entireDuration, s.divisions) {
		m := make(map[string]analyzer.Detections)
		calclatorIP := analyzer.NewThresholdCalculator(ipSumm.Auths, regularAuths, s.withRTT)
		for _, timeSumm := range ipSumm.ByTime {
			if len(timeSumm.Auths) < 8 { // サマリに一つも攻撃がなければスキップする
				continue
			}
			calculator := analyzer.NewThresholdCalculator(timeSumm.Auths, s.regularAuths, s.withRTT)
			threshold := calculator.CalcBestThreshold(0.0, 1.5, 0.001)
			m[timeSumm.Key()] = threshold
		}
		ipTimeThreMap[ipSumm.IP] = ipTimeThreshold{
			ip:        ipSumm.IP,
			threshold: calclatorIP.CalcBestThreshold(0.0, 1.5, 0.001),
			m:         m,
		}
	}
	timeThresholdTable := make(map[string]analyzer.Detections)
	for _, summary := range summarizer.ByTime(analyzeData, s.entireDuration, s.divisions) {
		if len(summary.Auths) == 0 { // サマリ結果が0なら解析しない
			continue
		}
		calculator := analyzer.NewThresholdCalculator(summary.Auths, s.regularAuths, s.withRTT)
		threshold := calculator.CalcBestThreshold(0.0, 1.5, 0.001)

		timeThresholdTable[summary.Key()] = threshold
	}

	/* check performance */
	// detection rate
	detectedCount := 0
	useDefaultCount := 0
	ipHitCount := 0
	iptimeHitCount := 0
	timeHitCount := 0

	c := 0
	for _, attack := range testData {
		c++
		threshold := analyzer.Detections{}
		ipThreshold := analyzer.Detections{}
		subnet := attack.IP.SubnetMask(s.subnetMask)

		if ipTimeThre, ok := ipTimeThreMap[subnet]; !ok { // IPを見つけられなかったら時間帯ごとのしきい値を使用
			key := summarizer.GetKeyFromAuthAt(attack.AuthAt, s.entireDuration, s.divisions)

			threshold, timeOk := timeThresholdTable[key]
			if !timeOk { // 時間ごとのしきい値も見つけられなかったらデフォルトのしきい値
				useDefaultCount++
				threshold = baseThreshold
			}
			ipThreshold = threshold
			timeHitCount++
		} else { // IP に対するしきい値は見つけた
			ipThreshold = ipTimeThre.threshold
			ipHitCount++
			// 次にそのIPのある特定時間に対するしきい値を探す．あったらそれをしきい値とする
			key := summarizer.GetKeyFromAuthAt(attack.AuthAt, s.entireDuration, s.divisions)
			threshold, ok = ipTimeThre.m[key]
			if !ok { // 無かったらIPに対するしきい値を設定
				threshold = ipTimeThre.threshold
				// fmt.Printf("IPdetec but noTime: %s at [%v]%v\n", ipTimeThre.ip, key, attack.AuthAt.UTC().Format("01/02 15:04:05"))
			} else {
				iptimeHitCount++
				// fmt.Printf("IPdetec and found : %s at [%v]%v threshold: %.3f\n", ipTimeThre.ip, key, attack.AuthAt.UTC().Format("01/02 15:04:05"), threshold.Authtime)
			}
		}
		judge := s.selectAuthtime(attack) < threshold.Authtime
		judgeByIP := s.selectAuthtime(attack) < ipThreshold.Authtime
		if judge || judgeByIP { // TODO: invalid
			detectedCount++
		}

		degCnt := 0
		impCnt := 0
		if judge && !judgeByIP {
			// key := summarizer.GetKeyFromAuthAt(attack.AuthAt, s.entireDuration, s.divisions)
			// fmt.Printf("Improve: %.3f -> %.3f(%.3f)[%v]\n", ipThreshold.Authtime, threshold.Authtime, attack.Authtime, key)
			impCnt++
		}
		if !judge && judgeByIP {
			// key := summarizer.GetKeyFromAuthAt(attack.AuthAt, s.entireDuration, s.divisions)
			// fmt.Printf("Degrade: %.3f -> %.3f(%.3f)[%v]\n", ipThreshold.Authtime, threshold.Authtime, attack.Authtime, key)
			degCnt++
		}
	}
	detectionRate := float64(detectedCount) / float64(len(testData))
	hitRate := 1.0 - float64(useDefaultCount)/float64(len(testData))

	// tlen := float64(len(testData))
	// fmt.Printf("ipHit: %.2f, timeHit: %.2f(byIP: %.2f)\n", float64(ipHitCount)/tlen, float64(timeHitCount)/tlen, float64(timeHitCount)/float64(ipHitCount))
	// fmt.Printf("Degrated: %d, Improved: %d\n", degCnt, impCnt)
	// misdetection rate
	misDetectedCount := 0
	for _, regular := range s.regularAuths {
		if s.selectAuthtime(regular) < baseThreshold.Authtime {
			misDetectedCount++
		}
	}
	misDetectionRate := float64(misDetectedCount) / float64(len(s.regularAuths))

	if s.verbose {
		s.logger.SetPrefix("[simulator:iptimesum]")
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

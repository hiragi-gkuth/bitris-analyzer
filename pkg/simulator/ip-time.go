// Package simulator は，各種Bitrisシステムを使って様々なデータを取得，表示する操作をする
package simulator

import (
	"fmt"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/pkg/analyzer"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/db"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/plotter"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/summarizer"
)

// ShowIPAndTimeSummariedThreshold は，IPと時間帯ごとのそれぞれの最善しきい値を計算して出力する
func ShowIPAndTimeSummariedThreshold() {
	begin, _ := time.Parse(dateTimeFormat, "2020-10-01 00:00:00")
	end := begin.Add(24 * time.Hour * 7)

	bitris := db.NewDB(db.Uehara)
	attacks := bitris.FetchBetween(begin, end)
	regulars := bitris.FetchSuccessSamples()
	fmt.Printf("len: %v. summarying...\n", len(attacks))
	now := time.Now()
	summarySlice := summarizer.ByIP(attacks, 16)
	fmt.Printf("summaried. len: %v. time: %v\n", len(summarySlice), time.Since(now))

	filter := 700
	for _, summary := range summarySlice {
		if len(summary.Auths) < filter {
			continue
		}
		calculator := analyzer.NewThresholdCalculator(summary.Auths, regulars, true)
		detections := calculator.CalcBestThreshold(0.0, 1.5, 0.01)
		detectionsSlice := calculator.CalcDetectionRateInRange(0.0, 1.5, 0.01)
		fmt.Printf("count: %d, ip: %s, best: %.3f, perf: %.3f\n", len(summary.Auths), summary.IP, detections.Authtime, detections.Performance())
		plotter.DetectionGraph(detectionsSlice, summary.IP.String())
	}

	for _, summary := range summarySlice {
		if len(summary.Auths) < filter {
			continue
		}
		fmt.Printf("%s\n", summary.IP.String())
		for _, tsummary := range summarizer.ByTime(summary.Auths, 24*time.Hour, 24) {
			calculator := analyzer.NewThresholdCalculator(tsummary.Auths, regulars, true)
			detections := calculator.CalcBestThreshold(0.0, 1.5, 0.01)

			fmt.Printf("%02.1f - %02.1f\tlen: %05d, best: %.3f, detection: %.3f%%, misdetection: %.3f%%, perf: %.3f \n",
				tsummary.Slot.Begin().Hours(),
				tsummary.Slot.End().Hours(),
				len(tsummary.Auths),
				detections.Authtime,
				detections.DetectionRate*100,
				detections.MisDetectionRate*100,
				detections.Performance())
		}
	}
}

// ShowPerfomanceDifferenceOfIPSummariedAndOverall は，全体のしきい値による性能評価値と，
// IPアドレスごとに分類したあとの評価値の比較を行う
func ShowPerfomanceDifferenceOfIPSummariedAndOverall(begin, end time.Time) {
	bitris := db.NewDB(db.Uehara)
	allAttacks := bitris.FetchBetween(begin, end)
	regulars := bitris.FetchSuccessSamples()

	// calc overall threshold
	overallCalcer := analyzer.NewThresholdCalculator(allAttacks, regulars, true)
	overallThreshold := overallCalcer.CalcBestThreshold(0.0, 1.5, 0.01)

	fmt.Printf("overall threshold: %.3f, performance: %.3f\n", overallThreshold.Authtime, overallThreshold.Performance())

	// calc IP summaried threshold
	summariedThresholds := analyzer.DetectionsSlice{}
	for _, summary := range summarizer.ByIP(allAttacks, 16) {
		calcer := analyzer.NewThresholdCalculator(summary.Auths, regulars, true)
		threshold := calcer.CalcBestThreshold(0.0, 1.5, 0.01)
		summariedThresholds = append(summariedThresholds, &threshold)
	}
	perfScore := 0.0

	for _, threshold := range summariedThresholds {
		perfScore += threshold.Performance()
	}
	perfScore /= float64(len(summariedThresholds))

	fmt.Printf("summaried threshold: %.3f, performance: %.3f\n", 0.0, perfScore)
}

func TestPerformanceByUsingPreviousThresholds(interval time.Duration, begin, end time.Time) {
	// 	bitris := db.NewDB(db.Uehara)
}

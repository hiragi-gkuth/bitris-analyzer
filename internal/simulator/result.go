package simulator

import (
	"fmt"
	"time"
)

// Result は，シミュレーション結果を格納する型
type Result struct {
	BaseThreshold    float64
	HitRate          float64
	DetectionRate    float64
	MisDetectionRate float64
	Performance      float64
	CalcTime         time.Duration
}

// Results は，結果のまとめ
type Results struct {
	Begin           time.Time
	End             time.Time
	AnalysisPeriod  time.Duration
	OperationPeriod time.Duration
	FilteredRatio   float64
	Of              map[SimulateType]Result
}

// Show shows result to stdout
func (r Results) Show() {
	fmt.Printf("SimulateRange: %v - %v\n", r.Begin, r.End)
	fmt.Printf("Periods: analyze %v - operation %v\n", r.AnalysisPeriod, r.OperationPeriod)
	for simType, result := range r.Of {
		fmt.Printf("%v: base: %.3f, hit: %.3f, detec: %.3f, mis: %.3f, perf: %.3f\n",
			simType,
			result.BaseThreshold,
			result.HitRate,
			result.DetectionRate,
			result.MisDetectionRate,
			result.Performance)

	}
}

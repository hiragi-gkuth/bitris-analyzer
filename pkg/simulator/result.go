package simulator

import "time"

// SimulationResult は，シミュレーション結果を格納する型
type SimulationResult struct {
	BaseThreshold    float64
	HitRate          float64
	DetectionRate    float64
	MisDetectionRate float64
	Performance      float64
}

// SimulationResults は，結果のまとめ
type SimulationResults struct {
	Begin         time.Time
	End           time.Time
	FilteredRatio float64
	Results       map[SimulationType]SimulationResult
}

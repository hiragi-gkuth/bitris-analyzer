package simulator

import "time"

// Result は，シミュレーション結果を格納する型
type Result struct {
	BaseThreshold    float64
	HitRate          float64
	DetectionRate    float64
	MisDetectionRate float64
	Performance      float64
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

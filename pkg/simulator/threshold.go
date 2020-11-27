package simulator

import "github.com/hiragi-gkuth/bitris-analyzer/pkg/analyzer"

// Threshold は，OpenSSHサーバ上におけるしきい値のデータ構造を模倣する構造体
type Threshold struct {
	Base    float64
	Offsets map[interface{}]float64
}

func contructThresholdFromDetects(allDetects, summariedDetects analyzer.DetectionsSlice) *Threshold {
	baseSec := 0.0
	for _, detect := range allDetects {
		baseSec += detect.Authtime
	}
	offsets := make(map[interface{}]float64)

	return &Threshold{
		Base:    baseSec,
		Offsets: offsets,
	}
}

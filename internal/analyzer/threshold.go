// Package analyzer は，解析機能を提供する
package analyzer

import (
	"sort"

	"github.com/hiragi-gkuth/bitris-analyzer/pkg/authlog"
)

// Detections は，しきい値に関連するデータを格納する構造体
type Detections struct {
	Authtime         float64
	DetectionRate    float64
	MisDetectionRate float64
}

// DetectionsSlice は，Thresholdのスライス
type DetectionsSlice []*Detections

// ThresholdCalculator は，閾値に関する各種機能を提供する
type ThresholdCalculator struct {
	Attacks  authlog.AuthInfoSlice
	Regulars authlog.AuthInfoSlice
	WithRTT  bool
}

// Performance は，性能値を返す
func (d Detections) Performance() float64 {
	return d.DetectionRate - d.MisDetectionRate
}

// NewThresholdCalculator は，しきい値に関する機能を提供するインスタンスを返す
func NewThresholdCalculator(attacks authlog.AuthInfoSlice, regulars authlog.AuthInfoSlice, withRTT bool) ThresholdCalculator {
	return ThresholdCalculator{
		attacks,
		regulars,
		withRTT,
	}
}

// CalcBestThreshold は，設定された攻撃，及び正規アクセスの中で，最も良い性能値を示すしきい値を返す
func (tc ThresholdCalculator) CalcBestThreshold(begin, end, step float64) Detections {
	dss := tc.CalcDetectionRateInRange(begin, end, step)
	sort.Slice(dss, func(i, j int) bool { return dss[i].Performance() > dss[j].Performance() })
	return *dss[0]
}

// CalcDetectionRateInRange は，設定された範囲内のそれぞれの認証時間のときの，Detectionsのスライスを返す
func (tc ThresholdCalculator) CalcDetectionRateInRange(begin, end, step float64) DetectionsSlice {
	detectionsSlice := DetectionsSlice{}
	for authtime := begin; authtime < end; authtime += step {
		detectionsSlice = append(detectionsSlice, tc.CalcDetectionRatesByAuthtime(authtime))
	}
	return detectionsSlice
}

// CalcDetectionRatesByAuthtime は，与えられたauthtimeのときの，検知率，誤検知率を算出して返す
func (tc ThresholdCalculator) CalcDetectionRatesByAuthtime(authtime float64) *Detections {
	underThreForAttack := tc.Attacks.Where(
		func(auth *authlog.AuthInfo) bool { return selectTime(auth, tc.WithRTT) < authtime })
	underThreForRegular := tc.Regulars.Where(
		func(auth *authlog.AuthInfo) bool { return selectTime(auth, tc.WithRTT) < authtime })
	detectionRate := float64(len(underThreForAttack)) / float64(len(tc.Attacks))
	misDetectionRate := float64(len(underThreForRegular)) / float64(len(tc.Regulars))

	return &Detections{
		Authtime:         authtime,
		DetectionRate:    detectionRate,
		MisDetectionRate: misDetectionRate,
	}
}

func selectTime(auth *authlog.AuthInfo, withRTT bool) float64 {
	if withRTT {
		return auth.Authtime
	}
	return auth.ActualAuthtime
}

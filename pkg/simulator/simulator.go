package simulator

import (
	"errors"
	"fmt"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/pkg/db"
)

// DTF is DateTimeFormat
const (
	dateTimeFormat = "2006-01-02 15:04:05"
	dateFormat     = "2006-01-02"
)

// SimulationType は，どのシミュレーションを行うかを定義します
type SimulationType uint8

const (
	// Legacy は，先行研究による手法の検知率を算出する
	Legacy SimulationType = 0b0001
	// IPSummarized は，IPアドレスごとに要約された攻撃ごとのしきい値による検知率を算出
	IPSummarized SimulationType = 0b0010
	// TimeSummarized は，時間帯ごとに要約された攻撃から算出するしきい値による検知率を算出
	TimeSummarized SimulationType = 0b0011
	// IPTimeSummarized は，IP,時間帯ごとの双方をあわせたしきい値の決定による検知率を算出
	IPTimeSummarized SimulationType = 0b0100
	// InterSessionSummarized は，認証セッションごとの何回目であるかを元にしきい値を
	InterSessionSummarized SimulationType = 0b0101
)

// ISimulator は，Simulator が提供すべきメソッドを定義する
type ISimulator interface {
	Test()
}

// Simulator は，Simulator package が提供する機能をまとめる構造体
type Simulator struct {
	AnalyzeBegin time.Time
	AnalyzeEnd   time.Time
	TestBegin    time.Time
	TestEnd      time.Time
	Type         SimulationType
	WithRTT      bool
}

// NewSimulator は，与えられた解析期間，テスト期間で性能のシミュレーションを行う構造体を返す
func NewSimulator(analyzeBegin, analyzeEnd, testBegin, testEnd time.Time, simType SimulationType, withRTT bool) (ISimulator, error) {
	if analyzeEnd.After(testBegin) {
		err := errors.New("analyzeEnd must be before testBegin")
		return nil, err
	}
	if testEnd.After(time.Now()) {
		err := errors.New("testEnd must be before now")
		return nil, err
	}
	return &Simulator{
		AnalyzeBegin: analyzeBegin,
		AnalyzeEnd:   analyzeEnd,
		TestBegin:    testBegin,
		TestEnd:      testEnd,
		Type:         simType,
		WithRTT:      withRTT,
	}, nil
}

// Test は，実際にシミュレーションを実行します
func (s Simulator) Test() {
	bitris := db.NewDB(db.Uehara)
	aAttacks := bitris.FetchBetween(s.AnalyzeBegin, s.AnalyzeEnd)
	tAttacks := bitris.FetchBetween(s.TestBegin, s.TestEnd)
	regulars := bitris.FetchSuccessSamples()

	fmt.Printf("** Bitris System Simulator **\n")
	fmt.Printf("Analyze Duration: %v - %v\n", s.AnalyzeBegin, s.AnalyzeEnd)
	fmt.Printf("Testing Duration: %v - %v\n", s.TestBegin, s.TestEnd)

	if s.Type&Legacy != 0 {
		s.showLegacyMethodPerformance(aAttacks, tAttacks, regulars)
	}
	if s.Type&IPSummarized != 0 {
		s.showIPSummarizedPerformance(aAttacks, tAttacks, regulars)
	}
	if s.Type&IPSummarized != 0 {
		{
		}
	}
	if s.Type&IPSummarized != 0 {
		{
		}
	}
}

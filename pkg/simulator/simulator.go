package simulator

import (
	"fmt"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/pkg/authlog"
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
	Test(func(a *authlog.AuthInfo) bool) SimulationResults
	SetSubnetMask(int)
}

// Simulator は，Simulator package が提供する機能をまとめる構造体
type Simulator struct {
	Begin        time.Time
	End          time.Time
	AnalyzeRatio float64
	Type         SimulationType
	WithRTT      bool
	SubnetMask   int
}

// NewSimulator は，与えられた解析期間，テスト期間で性能のシミュレーションを行う構造体を返す
func NewSimulator(begin, end time.Time, analyzeRatio float64, simType SimulationType, withRTT bool) (ISimulator, error) {
	return &Simulator{
		Begin:        begin,
		End:          end,
		AnalyzeRatio: analyzeRatio,
		Type:         simType,
		WithRTT:      withRTT,
		SubnetMask:   16, // default
	}, nil
}

// SetSubnetMask は，サブネットマスクを設定する
func (s Simulator) SetSubnetMask(subnetMask int) {
	s.SubnetMask = subnetMask
}

// Test は，実際にシミュレーションを実行します
func (s Simulator) Test(attackFilterFunc func(a *authlog.AuthInfo) bool) SimulationResults {
	// fetch data
	bitris := db.NewDB(db.Uehara)
	attacks := bitris.FetchBetween(s.Begin, s.End)
	regulars := bitris.FetchSuccessSamples()

	// devide analyze and test data
	pivot := int(float64((len(attacks))) * s.AnalyzeRatio)
	aAttacks, tAttacks := attacks[:pivot], attacks[pivot:]

	// save original attacks len for calculating filter ratio
	aOriginalLen := len(aAttacks)

	// filtering
	aAttacks, tAttacks = aAttacks.Where(attackFilterFunc), tAttacks.Where(attackFilterFunc)
	filterRatio := 1.0 - float64(len(aAttacks))/float64(aOriginalLen)
	// inform Simulator status
	fmt.Printf("> Bitris System Simulator \n")
	fmt.Printf("  > Simulate on %v to %v\n", s.Begin, s.End)
	fmt.Printf("  > Analyze Ratio %.1f%%\n", s.AnalyzeRatio*100)
	fmt.Printf("  > Filtered %.1f%% of data\n", (1.0-float64(len(aAttacks))/float64(aOriginalLen))*100)
	fmt.Printf("  > AnalyzeDataLen: %d, TestDataLen: %d, RegularDateLen: %d\n", len(aAttacks), len(tAttacks), len(regulars))

	resultMap := make(map[SimulationType]SimulationResult)
	if s.Type&Legacy != 0 {
		fmt.Printf("    > LegacyPerformanceTestBegin\n")
		now := time.Now()
		resultMap[Legacy] = s.calcLegacyMethodPerformance(aAttacks, tAttacks, regulars)
		fmt.Printf("    > done! %v\n", time.Since(now))
	}
	if s.Type&IPSummarized != 0 {
		fmt.Printf("    > LegacyPerformanceTestBegin\n")
		now := time.Now()
		resultMap[IPSummarized] = s.calcIPSummarizedPerformance(aAttacks, tAttacks, regulars)
		fmt.Printf("    > done! %v\n", time.Since(now))
	}

	fmt.Printf("> End all simulations.\n")
	return SimulationResults{
		Begin:         s.Begin,
		End:           s.End,
		FilteredRatio: filterRatio,
		Results:       resultMap,
	}
}

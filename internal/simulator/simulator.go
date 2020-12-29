package simulator

import (
	"log"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/authlog"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/db"
)

// DTF is DateTimeFormat
const (
	dateTimeFormat = "2006-01-02 15:04:05"
	dateFormat     = "2006-01-02"
)

// SimulateType は，どのシミュレーションを行うかを定義します
type SimulateType uint8

const (
	// Legacy は，先行研究による手法の検知率を算出する
	Legacy SimulateType = 0b0001
	// IPSummarized は，IPアドレスごとに要約された攻撃ごとのしきい値による検知率を算出
	IPSummarized SimulateType = 0b0010
	// TimeSummarized は，時間帯ごとに要約された攻撃から算出するしきい値による検知率を算出
	TimeSummarized SimulateType = 0b0011
	// IPTimeSummarized は，IP,時間帯ごとの双方をあわせたしきい値の決定による検知率を算出
	IPTimeSummarized SimulateType = 0b0100
	// InterSessionSummarized は，認証セッションごとの何回目であるかを元にしきい値を
	InterSessionSummarized SimulateType = 0b0101
)

// ISimulator は，Simulator が提供すべきメソッドを定義する
type ISimulator interface {
	Simulate() Results
	SimulateRange(time.Time, time.Time)
	AnalyzeRatio(float64)
	SubnetMask(int)
	SimulateType(SimulateType)
	WithRTT(bool)
	AttacksFilter(func(a *authlog.AuthInfo) bool)
	Prefetch()
}

// Simulator は，Simulator package が提供する機能をまとめる構造体
type Simulator struct {
	server        db.SSHServer
	simulateRange []time.Time
	fetchRange    []time.Time
	regulars      authlog.AuthInfoSlice
	attacks       authlog.AuthInfoSlice
	fetchAttacks  authlog.AuthInfoSlice
	attacksFilter func(a *authlog.AuthInfo) bool
	analyzeRatio  float64
	simulateType  SimulateType
	withRTT       bool
	subnetMask    int
}

// New は，新たなシミュレータ構造体を返す
func New(simulationServer db.SSHServer) ISimulator {
	return &Simulator{
		server: simulationServer,
	}
}

// SimulateRange は，解析期間を設定する
func (s *Simulator) SimulateRange(begin, end time.Time) {
	s.simulateRange = []time.Time{begin, end}
}

// AnalyzeRatio は，解析比率を設定する
func (s *Simulator) AnalyzeRatio(analyzeRatio float64) {
	s.analyzeRatio = analyzeRatio
}

// SubnetMask は，サブネットマスクを設定する
func (s *Simulator) SubnetMask(subnetMask int) {
	s.subnetMask = subnetMask
}

// SimulateType は，シミュレート種別を設定する
func (s *Simulator) SimulateType(simulateType SimulateType) {
	s.simulateType = simulateType
}

// WithRTT は，RTTを含んでシミュレートするかを設定する
func (s *Simulator) WithRTT(withRTT bool) {
	s.withRTT = withRTT
}

// AttacksFilter は，攻撃に対するフィルターを設定する
func (s *Simulator) AttacksFilter(attacksFilter func(a *authlog.AuthInfo) bool) {
	s.attacksFilter = attacksFilter
}

// Prefetch は，シミュレーション開始前にデータを取得しておく
func (s *Simulator) Prefetch() {
	bitris := db.NewDB(s.server)
	// regulars が取得されていない場合のみ取得
	if s.regulars == nil {
		log.Println("Simulator Prefetch Regulars")
		s.regulars = bitris.FetchSuccessSamples()
	}
	// 一度もPrefetchされていないか，Prefetchされた範囲以上がシミュレーション期間に設定されているなら，再取得
	if s.fetchRange == nil || (s.simulateRange[0].Before(s.fetchRange[0]) || s.simulateRange[1].After(s.fetchRange[1])) {
		log.Println("Simulator Prefetch Attacks")
		s.fetchAttacks = bitris.FetchBetween(s.simulateRange[0], s.simulateRange[1])
		s.fetchRange = make([]time.Time, 2)
		copy(s.fetchRange, s.simulateRange)
	}
}

// Simulate は，実際にシミュレーションを実行する
func (s *Simulator) Simulate() Results {
	// Simulation parameter checking...
	if s.analyzeRatio == 0.0 || s.simulateRange == nil || s.simulateType == 0b0000 || s.subnetMask == 0 {
		log.Fatal("parameters is not enough", s)
	}
	// fetching
	s.Prefetch()

	// Prefetchより短い期間なら，切り詰める
	if s.simulateRange[0].After(s.fetchRange[0]) || s.simulateRange[1].Before(s.fetchRange[1]) {
		s.attacks = s.fetchAttacks.Where(func(a *authlog.AuthInfo) bool {
			return a.AuthAt.Equal(s.simulateRange[0]) || a.AuthAt.After(s.simulateRange[0]) && a.AuthAt.Before(s.simulateRange[1])
		})
	}

	// devide analyze and test data
	pivot := int(float64((len(s.attacks))) * s.analyzeRatio)
	analyzeData, testData := s.attacks[:pivot], s.attacks[pivot:]

	// save original attacks len for calculating filter ratio
	aOriginalLen := len(analyzeData)

	// filtering
	if s.attacksFilter != nil {
		analyzeData, testData = analyzeData.Where(s.attacksFilter), testData.Where(s.attacksFilter)
	}
	filterRatio := 1.0 - float64(len(analyzeData))/float64(aOriginalLen)
	// inform Simulator status
	// fmt.Printf("> Bitris System Simulator \n")
	// fmt.Printf("  > Simulate on %v\n", s.simulateRange)
	// fmt.Printf("  > Analyze Ratio %.1f%%\n", s.analyzeRatio*100)
	// fmt.Printf("  > Filtered %.1f%% of data\n", filterRatio*100)
	// fmt.Printf("  > AnalyzeDataLen: %d, TestDataLen: %d, RegularDateLen: %d\n", len(analyzeData), len(testData), len(s.regulars))

	results := make(map[SimulateType]Result)
	if s.simulateType&Legacy != 0 {
		// fmt.Printf("    > LegacyPerformanceTestBegin\n")
		// now := time.Now()
		results[Legacy] = s.calcLegacyMethodPerformance(analyzeData, testData, s.regulars)
		// fmt.Printf("    > done! %v\n", time.Since(now))
	}
	if s.simulateType&IPSummarized != 0 {
		// fmt.Printf("    > IPSummarizedPerformanceTestBegin\n")
		// now := time.Now()
		results[IPSummarized] = s.calcIPSummarizedPerformance(analyzeData, testData, s.regulars)
		// fmt.Printf("    > done! %v\n", time.Since(now))
	}

	// fmt.Printf("> End all simulations.\n")
	return Results{
		Begin:         s.simulateRange[0],
		End:           s.simulateRange[1],
		FilteredRatio: filterRatio,
		Of:            results,
	}
}

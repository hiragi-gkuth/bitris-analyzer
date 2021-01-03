package simulator

import (
	"log"
	"os"
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
	Legacy SimulateType = 0b1
	// IPSummarized は，IPアドレスごとに要約された攻撃ごとのしきい値による検知率を算出
	IPSummarized SimulateType = 0b10
	// TimeSummarized は，時間帯ごとに要約された攻撃から算出するしきい値による検知率を算出
	TimeSummarized SimulateType = 0b100
	// IPTimeSummarized は，IP,時間帯ごとの双方をあわせたしきい値の決定による検知率を算出
	IPTimeSummarized SimulateType = 0b1000
	// InterSessionSummarized は，認証セッションごとの何回目であるかを元にしきい値を
	InterSessionSummarized SimulateType = 0b10000
)

// ISimulator は，Simulator が提供すべきメソッドを定義する
type ISimulator interface {
	Simulate() Results
	Prefetch()

	SetTerm(begin time.Time, analysisPeriod, operationPeriod time.Duration)
	SetSubnetMask(int)
	SetSimulateType(SimulateType)
	SetWithRTT(bool)
	SetAttacksFilter(func(a *authlog.AuthInfo) bool)
	SetVerbose(bool)
}

// Simulator は，Simulator package が提供する機能をまとめる構造体
type Simulator struct {
	serverID       string
	analysisPeriod time.Duration
	oprationPeriod time.Duration
	simulateRange  []time.Time
	fetchRange     []time.Time
	regulars       authlog.AuthInfoSlice
	attacks        authlog.AuthInfoSlice
	fetchAttacks   authlog.AuthInfoSlice
	attacksFilter  func(a *authlog.AuthInfo) bool
	simulateType   SimulateType
	withRTT        bool
	subnetMask     int
	verbose        bool
	logger         *log.Logger
}

// New は，新たなシミュレータ構造体を返す
func New(serverID string) ISimulator {
	return &Simulator{
		serverID: serverID,
	}
}

// SetTerm は，シミュレーション全体の解析機関，運用期間を設定する
func (s *Simulator) SetTerm(begin time.Time, analysisPeriod, operationPeriod time.Duration) {
	s.analysisPeriod = analysisPeriod
	s.oprationPeriod = operationPeriod
	s.simulateRange = []time.Time{begin, begin.Add(analysisPeriod).Add(operationPeriod)}
}

// SetSubnetMask は，サブネットマスクを設定する
func (s *Simulator) SetSubnetMask(subnetMask int) {
	s.subnetMask = subnetMask
}

// SetSimulateType は，シミュレート種別を設定する
func (s *Simulator) SetSimulateType(simulateType SimulateType) {
	s.simulateType = simulateType
}

// SetWithRTT は，RTTを含んでシミュレートするかを設定する
func (s *Simulator) SetWithRTT(withRTT bool) {
	s.withRTT = withRTT
}

// SetAttacksFilter は，攻撃に対するフィルターを設定する
func (s *Simulator) SetAttacksFilter(attacksFilter func(a *authlog.AuthInfo) bool) {
	s.attacksFilter = attacksFilter
}

// SetVerbose は詳細表示を行う
func (s *Simulator) SetVerbose(v bool) {
	s.verbose = v
}

// Prefetch は，シミュレーション開始前にデータを取得しておく
func (s *Simulator) Prefetch() {
	bitris := db.NewDB(s.serverID)
	// regulars が取得されていない場合のみ取得
	if s.regulars == nil {
		log.Println("Simulator Prefetch Regulars")
		s.regulars = bitris.FetchSuccessSamples()
	}
	// 一度もPrefetchされていないか，Prefetchされた範囲以上がシミュレーション期間に設定されているなら，再取得
	if s.fetchRange == nil || (s.simulateRange[0].Before(s.fetchRange[0]) || s.simulateRange[1].After(s.fetchRange[1])) {
		log.Println("Simulator Prefetch Attacks", s.simulateRange)
		s.fetchAttacks = bitris.FetchBetween(s.simulateRange[0], s.simulateRange[1])
		s.fetchRange = make([]time.Time, 2)
		copy(s.fetchRange, s.simulateRange)
	}
}

// Simulate は，実際にシミュレーションを実行する
func (s *Simulator) Simulate() Results {
	// Simulation parameter checking...
	if s.simulateRange == nil || s.simulateType == 0b0000 || s.subnetMask == 0 {
		log.Fatal("parameters is not enough", s)
	}
	// fetching
	s.Prefetch()

	analyzeData := s.fetchAttacks.Where(func(a *authlog.AuthInfo) bool {
		return !a.AuthAt.Before(s.simulateRange[0]) && a.AuthAt.Before(s.simulateRange[0].Add(s.analysisPeriod))
	})

	operationData := s.fetchAttacks.Where(func(a *authlog.AuthInfo) bool {
		return !a.AuthAt.Before(s.simulateRange[0].Add(s.analysisPeriod)) && a.AuthAt.Before(s.simulateRange[1])
	})

	// save original attacks len for calculating filter ratio
	aOriginalLen := len(analyzeData)

	// filtering
	if s.attacksFilter != nil {
		analyzeData, operationData = analyzeData.Where(s.attacksFilter), operationData.Where(s.attacksFilter)
	}
	filterRatio := 1.0 - float64(len(analyzeData))/float64(aOriginalLen)

	if s.verbose {
		s.logger = log.New(os.Stderr, "[simulator]", 0)
		s.logger.Print("Bitris Simulator")
		s.logger.Printf("%v - %v", s.simulateRange[0], s.simulateRange[1])
		s.logger.Printf("analysis: %v, operation: %v", s.analysisPeriod, s.oprationPeriod)
		s.logger.Printf("analysis count: %v, operation count: %v", len(analyzeData), len(operationData))
	}

	results := make(map[SimulateType]Result)
	if s.simulateType&Legacy != 0 {
		results[Legacy] = s.calcLegacyMethodPerformance(analyzeData, operationData, s.regulars)
	}
	if s.simulateType&IPSummarized != 0 {
		results[IPSummarized] = s.calcIPSummarizedPerformance(analyzeData, operationData, s.regulars)
	}
	if s.simulateType&TimeSummarized != 0 {
		results[TimeSummarized] = s.calcTimeSummarizedPerformance(analyzeData, operationData, s.regulars)
	}

	// fmt.Printf("> End all simulations.\n")
	return Results{
		Begin:           s.simulateRange[0],
		End:             s.simulateRange[1],
		AnalysisPeriod:  s.analysisPeriod,
		OperationPeriod: s.oprationPeriod,
		FilteredRatio:   filterRatio,
		Of:              results,
	}
}

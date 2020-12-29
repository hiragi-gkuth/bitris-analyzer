package plotter

import (
	"fmt"
	"math"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/simulator"
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/plotutil"
	"gonum.org/v1/plot/vg"
)

// SimulationResultParams は，シミュレーションを行うときにどのようなパラメタを用いたかを示す
type SimulationResultParams struct {
	Begin            time.Time
	End              time.Time
	Interval         time.Duration
	SimulateDuration time.Duration
	AnalyzeRatio     float64
	SubnetMask       int
	FilterName       string
	WithRTT          bool
}

// SimulationResultsGraph は，シミュレーション結果をグラフに描画します
func SimulationResultsGraph(resultsSlice []simulator.Results, param SimulationResultParams) {
	p, e := plot.New()
	if e != nil {
		panic(e.Error())
	}

	// Title
	p.Title.TextStyle.Font.Size = vg.Points(12.0)
	// タイトルに描画する必要な情報を収集
	var legacyPerformanceSum float64
	var ipSummarizedPerformanceSum float64
	for _, results := range resultsSlice {
		legacyPerformanceSum += results.Of[simulator.Legacy].Performance
		ipSummarizedPerformanceSum += results.Of[simulator.IPSummarized].Performance
	}
	p.Title.Text = fmt.Sprintf("Legacy: %.3f, IPSummarized: %.3f, Improvement: %.3f\nImprove Ratio: %.1f%%",
		legacyPerformanceSum,
		ipSummarizedPerformanceSum,
		ipSummarizedPerformanceSum-legacyPerformanceSum,
		((ipSummarizedPerformanceSum/legacyPerformanceSum)-1.0)*100)

	// X 軸のラベルたちを設定する
	labelX := []string{}
	for date := param.Begin; !date.After(param.End); date = date.Add(param.Interval) {
		format := "01-02 15:04 "
		labelX = append(labelX, date.Format(format))
	}

	// DataPlotting
	detecPointsMap := make(map[simulator.SimulateType]plotter.XYs)
	misDetecPointsMap := make(map[simulator.SimulateType]plotter.XYs)
	perfPointsMap := make(map[simulator.SimulateType]plotter.XYs)
	hitRatePointsMap := make(map[simulator.SimulateType]plotter.XYs)

	for i, results := range resultsSlice {
		for _, simType := range []simulator.SimulateType{
			simulator.IPSummarized,
			simulator.Legacy,
		} {
			simResult, ok := results.Of[simType]
			if !ok {
				continue
			}
			detecPointsMap[simType] = append(detecPointsMap[simType], plotter.XY{
				X: float64(i),
				Y: simResult.DetectionRate})
			misDetecPointsMap[simType] = append(misDetecPointsMap[simType], plotter.XY{
				X: float64(i),
				Y: simResult.MisDetectionRate})
			perfPointsMap[simType] = append(perfPointsMap[simType], plotter.XY{
				X: float64(i),
				Y: simResult.Performance})
			hitRatePointsMap[simType] = append(hitRatePointsMap[simType], plotter.XY{
				X: float64(i),
				Y: simResult.HitRate})
		}
	}
	for simType := range detecPointsMap {
		// dLine, _ := plotter.NewLine(detecPointsMap[simType])
		// mLine, _ := plotter.NewLine(misDetecPointsMap[simType])
		pLine, _ := plotter.NewLine(perfPointsMap[simType])
		// hLine, _ := plotter.NewLine(hitRatePointsMap[simType])
		// dLine.LineStyle.Color = plotutil.DefaultColors[0]
		// mLine.LineStyle.Color = plotutil.DefaultColors[1]
		pLine.LineStyle.Color = plotutil.DefaultColors[simType]
		// hLine.LineStyle.Color = plotutil.DefaultColors[3]
		p.Add(pLine)

		// decide simType name string
		var legendPrefix string
		switch simType {
		case simulator.Legacy:
			legendPrefix = "Legacy "
		case simulator.IPSummarized:
			legendPrefix = "IPSummarized "
		}

		// p.Legend.Add(legendPrefix+"Detection", dLine)
		// p.Legend.Add(legendPrefix+"MisDetection", mLine)
		p.Legend.Add(legendPrefix+"Performance", pLine)
		// p.Legend.Add(legendPrefix+"HitRate", hLine)
	}

	// Label X
	p.NominalX(labelX...)
	p.X.Label.TextStyle.Font.Size = vg.Points(9)
	p.X.Label.Text = "Date"
	p.X.Tick.Label.YAlign = -0.4
	p.X.Tick.Label.XAlign = -1.0
	p.X.Tick.Label.Rotation = math.Pi / 4

	// Label Y
	p.Y.Label.TextStyle.Font.Size = vg.Points(9)
	p.Y.Label.Text = "DetectionRate(%)"
	p.Y.Min = 0.0
	p.Y.Max = 1.0

	// Grid
	p.Add(plotter.NewGrid())

	// Save
	filename := fmt.Sprintf("%s-%s-%s-%d-%d-%v-%s.png",
		param.Begin.Format("0102T15:04"),
		param.End.Format("0102T15:04"),
		param.Interval.String(),
		param.SubnetMask,
		int(param.AnalyzeRatio*100),
		param.WithRTT,
		param.FilterName)

	if e = p.Save(15*vg.Centimeter, 10*vg.Centimeter, filename); e != nil {
		panic(e)
	}
}

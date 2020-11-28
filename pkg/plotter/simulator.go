package plotter

import (
	"math"
	"strconv"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/pkg/simulator"
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
func SimulationResultsGraph(resultsSlice []simulator.SimulationResults, param SimulationResultParams) {
	plot, e := plot.New()
	if e != nil {
		panic(e.Error())
	}

	// Title
	plot.Title.TextStyle.Font.Size = vg.Points(12.0)
	plot.Title.Text = ""

	// X 軸のラベルたちを設定する
	labelX := []string{}
	for date := param.Begin; !date.After(param.End); date = date.Add(param.Interval) {
		// ラベルの文字列は，計測インターバルが一日以下であれば，月と日と時間，それ以上なら月と日のみ
		var format string
		if param.Interval.Hours() < 24 {
			format = "01-02 15:04"
		} else {
			format = "01-02"
		}
		labelX = append(labelX, date.Format(format))
	}

	// DataPlotting
	detecPointsMap := make(map[simulator.SimulationType]plotter.XYs)
	misDetecPointsMap := make(map[simulator.SimulationType]plotter.XYs)
	perfPointsMap := make(map[simulator.SimulationType]plotter.XYs)
	hitRatePointsMap := make(map[simulator.SimulationType]plotter.XYs)

	for i, results := range resultsSlice {
		// label resetting
		labelX[i] += strconv.FormatFloat(results.Results[simulator.Legacy].BaseThreshold, 'f', 2, 64)
		for _, simType := range []simulator.SimulationType{
			simulator.IPSummarized,
			simulator.Legacy,
		} {
			simResult, ok := results.Results[simType]
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
		dLine, _ := plotter.NewLine(detecPointsMap[simType])
		mLine, _ := plotter.NewLine(misDetecPointsMap[simType])
		pLine, _ := plotter.NewLine(perfPointsMap[simType])
		hLine, _ := plotter.NewLine(hitRatePointsMap[simType])
		dLine.LineStyle.Color = plotutil.DefaultColors[0]
		mLine.LineStyle.Color = plotutil.DefaultColors[1]
		pLine.LineStyle.Color = plotutil.DefaultColors[2]
		hLine.LineStyle.Color = plotutil.DefaultColors[3]
		plot.Add(dLine, mLine, pLine, hLine)

		// decide simType name string
		var legendPrefix string
		switch simType {
		case simulator.Legacy:
			legendPrefix = "Legacy "
		case simulator.IPSummarized:
			legendPrefix = "IPSummarized "
		}

		plot.Legend.Add(legendPrefix+"Detection", dLine)
		plot.Legend.Add(legendPrefix+"MisDetection", mLine)
		plot.Legend.Add(legendPrefix+"Performance", pLine)
		plot.Legend.Add(legendPrefix+"HitRate", hLine)
	}

	// Label X
	plot.NominalX(labelX...)

	plot.X.Label.TextStyle.Font.Size = vg.Points(9)
	plot.X.Label.Text = "Date"
	plot.X.Tick.Label.Rotation = math.Pi / 4

	// Label Y
	plot.Y.Label.TextStyle.Font.Size = vg.Points(9)
	plot.Y.Label.Text = "DetectionRate(%)"
	plot.Y.Min = 0.0
	plot.Y.Max = 1.0

	// Save
	filename := param.Begin.Format("2006-01-02T15:04:05") + "to" + param.End.Format("2006-01-02T15:04:05")
	if e = plot.Save(15*vg.Centimeter, 10*vg.Centimeter, filename+".png"); e != nil {
		panic(e)
	}
}

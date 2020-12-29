// Package plotter は，各種ログから可視化する機能を提供する
package plotter

import (
	"github.com/hiragi-gkuth/bitris-analyzer/internal/analyzer"
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/plotutil"
	"gonum.org/v1/plot/vg"
)

// DetectionGraph は，与えられた認証検知率のスライスから，グラフを描画して保存する
func DetectionGraph(detects analyzer.DetectionsSlice, title string) {
	plot, e := plot.New()
	if e != nil {
		panic(e)
	}

	// set styles
	plot.Title.TextStyle.Font.Size = vg.Points(12.0)
	plot.Title.Text = "Detection rate graph for " + title
	plot.X.Label.TextStyle.Font.Size = vg.Points(9)
	plot.X.Label.Text = "Threshold(sec)"
	plot.Y.Label.TextStyle.Font.Size = vg.Points(9)
	plot.Y.Label.Text = "DetectionRate(%)"
	plot.Y.Min = 0.0
	plot.Y.Max = 100.0
	plot.X.Min = 0.0
	plot.X.Max = 1.6

	plotter.DefaultLineStyle.Width = vg.Points(1)
	plotter.DefaultGlyphStyle.Radius = vg.Points(0)

	// plotting
	detectionRatePoints := plotter.XYs{}
	misDetectionRatePoints := plotter.XYs{}
	performancePoints := plotter.XYs{}
	for _, detect := range detects {
		dxy := plotter.XY{
			X: detect.Authtime,
			Y: detect.DetectionRate * 100,
		}
		mdxy := plotter.XY{
			X: detect.Authtime,
			Y: detect.MisDetectionRate * 100,
		}
		pxy := plotter.XY{
			X: detect.Authtime,
			Y: detect.Performance() * 100,
		}
		detectionRatePoints = append(detectionRatePoints, dxy)
		misDetectionRatePoints = append(misDetectionRatePoints, mdxy)
		performancePoints = append(performancePoints, pxy)
	}
	drLine, drScatter, e := plotter.NewLinePoints(detectionRatePoints)
	if e != nil {
		panic(e)
	}
	mdrLine, mdrScatter, e := plotter.NewLinePoints(misDetectionRatePoints)
	if e != nil {
		panic(e)
	}
	perfLine, perfScatter, e := plotter.NewLinePoints(performancePoints)
	if e != nil {
		panic(e)
	}
	// Color
	drLine.Color = plotutil.Color(1)
	mdrLine.Color = plotutil.Color(0)
	perfLine.Color = plotutil.Color(2)

	// Add points to plot
	plot.Add(drLine, drScatter)
	plot.Add(mdrLine, mdrScatter)
	plot.Add(perfLine, perfScatter)

	// Legends
	plot.Legend.Add("DetectionRate", drLine)
	plot.Legend.Add("MisDetectionRate", mdrLine)
	plot.Legend.Add("Performance", perfLine)

	// save
	if e = plot.Save(15*vg.Centimeter, 10*vg.Centimeter, title+".png"); e != nil {
		panic(e)
	}
}

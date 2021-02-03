package main

import (
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/pkg/analyze"
	"github.com/k0kubun/pp"
)

func testAnalyze() {
	analyzer := analyze.New(analyze.Param{
		ServerID:        "uehara",
		LogServerHost:   "10.1.228.32",
		LogServerPort:   3306,
		AnalyzeDuration: 1 * time.Hour,
		SearchBegin:     0.1,
		SearchEnd:       1.5,
		SearchStep:      0.001,
	})
	result := analyzer.Analyze(8, 1*time.Hour, 24)
	pp.Print(result.OnIPTime)
}

package main

import (
	"flag"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/pkg/analyze"
)

func main() {
	serverID := flag.String("id", "bsshd", "解析対象のサーバID")
	dbHost := flag.String("dbhost", "", "DBサーバホスト")
	dbPort := flag.Int("dbport", 3306, "DBサーバポート")

	flag.Parse()

	if *dbHost == "" {
		panic(flag.ErrHelp)
	}

	analyzer := analyze.New(analyze.Param{
		ServerID:        *serverID,
		LogServerHost:   *dbHost,
		LogServerPort:   *dbPort,
		AnalyzeDuration: 24 * time.Hour,
		SearchBegin:     0.01,
		SearchEnd:       1.50,
		SearchStep:      0.001,
	})

	result := analyzer.Analyze(8, 24*time.Hour, 24)

	result.Show()
}

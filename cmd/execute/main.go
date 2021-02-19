package main

import (
	"flag"
	"io/ioutil"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/pkg/analyze"
)

func main() {
	param := parse()

	analyze := analyze.New(param)

	result := analyze.Analyze()
	createTableSQL := result.CreateTableSQL("uehara")
	insertSQL := result.InsertSQL("uehara")

	ioutil.WriteFile("create.sql", []byte(createTableSQL), 0644)
	ioutil.WriteFile("insert.sql", []byte(insertSQL), 0644)
}

func parse() analyze.Param {
	// commandline options
	var (
		serverID        = flag.String("id", "bsshd", "解析対象のサーバIDを指定します")
		logHost         = flag.String("host", "localhost", "DBサーバのアドレスを指定します")
		logPort         = flag.Int("port", 3306, "DBサーバのアドレスを指定します")
		analyzeDuration = flag.Int("duration", 24, "解析期間を指定します（単位：時間）")
		mask            = flag.Int("mask", 16, "ネットワークアドレス分割のサブネットマスクを指定します")
		entirePeriod    = flag.Int("period", 24, "時間帯分割の全体期間を指定します（単位：時間）")
		divisions       = flag.Int("div", 24, "時間帯の分割数を指定します")
	)
	flag.Parse()

	return analyze.Param{
		ServerID:        *serverID,
		LogServerHost:   *logHost,
		LogServerPort:   *logPort,
		AnalyzeDuration: time.Duration(*analyzeDuration) * time.Hour,
		Mask:            *mask,
		EntireDuration:  time.Duration(*entirePeriod) * time.Hour,
		Divisions:       *divisions,
		SearchBegin:     0.001,
		SearchEnd:       2.0,
		SearchStep:      0.001,
	}
}

package main

import (
	"flag"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/db"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/analyze"
	"github.com/hiragi-gkuth/bitris-analyzer/pkg/threshold"
)

const ( // edit here to set Database User, Pass, Name
	dbUser = ""
	dbPass = ""
	dbName = ""
)

func main() {
	param := parse()
	mysqlConfig := mysql.Config{
		Addr:                 param.LogServerHost,
		AllowNativePasswords: true,
		Net:                  "tcp",
		DBName:               dbName,
		User:                 dbUser,
		Passwd:               dbPass,
	}

	dbConfig := db.Config{
		ServerID: param.ServerID,
		Host:     param.LogServerHost,
		User:     dbUser,
		Pass:     dbPass,
	}

	analyze := analyze.New(param, dbConfig)
	idsModel := analyze.Analyze()

	repository := threshold.NewRepository(param.ServerID, mysqlConfig)

	repository.Save(idsModel)
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

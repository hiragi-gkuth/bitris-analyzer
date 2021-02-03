package analyze

import "time"

// Param は，解析するときのパラメータを指定する
type Param struct {
	ServerID        string
	LogServerHost   string
	LogServerPort   int
	AnalyzeDuration time.Duration
	SearchBegin     float64
	SearchEnd       float64
	SearchStep      float64
}

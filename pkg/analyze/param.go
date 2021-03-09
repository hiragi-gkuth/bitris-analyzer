package analyze

import "time"

// Param は，解析するときのパラメータを指定する
type Param struct {
	ServerID        string
	LogServerHost   string
	LogServerPort   int
	User            string
	Pass            string
	AnalyzeDuration time.Duration
	Mask            int
	EntireDuration  time.Duration
	Divisions       int
	SearchBegin     float64
	SearchEnd       float64
	SearchStep      float64
}

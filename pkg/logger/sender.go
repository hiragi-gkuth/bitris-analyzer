package logger

import (
	"fmt"
	"time"

	"github.com/fluent/fluent-logger-golang/fluent"
)

// Logger is fluent logger structure
type Logger struct {
	f *fluent.Fluent
}

// New is constructor
func New() Logger {
	config := fluent.Config{
		FluentPort: 24224,
		FluentHost: "localhost",
	}

	f, err := fluent.New(config)

	if err != nil {
		panic(err.Error())
	}
	return Logger{
		f: f,
	}
}

// Log is logging to fluent
func (l Logger) Log(logObj interface{}) {
	tag := fmt.Sprintf("bitris.%v.analyzer", l.f.FluentHost)

	err := l.f.PostWithTime(tag, time.Now(), logObj)
	if err != nil {
		panic(err.Error())
	}
}

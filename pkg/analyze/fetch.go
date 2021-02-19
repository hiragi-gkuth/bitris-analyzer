package analyze

import (
	"log"
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/authlog"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/db"
)

func (a *Analyze) fetchAuthLogs(duration time.Duration) (authlog.AuthInfoSlice, authlog.AuthInfoSlice) {
	now := time.Now()
	prev := now.Add(-duration)

	log.Printf("Fetch %v -> %v", prev, now)

	p := a.Param

	db := db.NewDB(p.LogServerHost, p.LogServerPort, "hiragi-gkuth", "emyure-ta", p.ServerID)
	defer db.DB.Close()

	authLogs := db.FetchBetween(prev, now)
	regularLogs := db.FetchSuccessSamples()
	return authLogs, regularLogs
}

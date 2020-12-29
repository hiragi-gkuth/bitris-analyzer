package analyze

import (
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/authlog"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/db"
)

func (a *Analyze) fetchAuthLogs(duration time.Duration) (authlog.AuthInfoSlice, authlog.AuthInfoSlice) {
	now := time.Now()
	prev := now.Truncate(duration)

	db := db.NewDB(a.ServerID)
	defer db.DB.Close()

	authLogs := db.FetchBetween(prev, now)
	regularLogs := db.FetchSuccessSamples()
	return authLogs, regularLogs
}

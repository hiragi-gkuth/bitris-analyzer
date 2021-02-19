package main

import (
	"time"

	"github.com/hiragi-gkuth/bitris-analyzer/internal/authlog"
	"github.com/hiragi-gkuth/bitris-analyzer/internal/db"
)

func fetchAllAuths() authlog.AuthInfoSlice {
	db := db.NewDB("10.1.228.33", 3306, "hiragi-gkuth", "emyure-ta", "uehara")
	begin, _ := time.Parse(Format, "2000-01-01 00:00:00")
	end, _ := time.Parse(Format, "2021-02-04 00:00:00")
	auths := db.FetchBetween(begin, end)

	return auths
}

func fetchAnalyzeAuths(ebegin string, d time.Duration) authlog.AuthInfoSlice {
	begin, _ := time.Parse(Format, ebegin)
	end := begin.Add(d)
	db := db.NewDB("10.1.228.33", 3306, "hiragi-gkuth", "emyure-ta", "uehara")
	attacks := db.FetchBetween(begin, end)

	return attacks
}

func fetchOperationAuths(ebegin string, d time.Duration) authlog.AuthInfoSlice {
	begin, _ := time.Parse(Format, ebegin)
	end := begin.Add(d)
	db := db.NewDB("10.1.228.33", 3306, "hiragi-gkuth", "emyure-ta", "cririn")
	attacks := db.FetchBetween(begin, end)

	return attacks
}

func fetchSuccessAuths() authlog.AuthInfoSlice {
	db := db.NewDB("10.1.228.33", 3306, "hiragi-gkuth", "emyure-ta", "cririn")
	regulars := db.FetchSuccessSamples()

	return regulars
}

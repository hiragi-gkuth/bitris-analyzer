package main

import (
	"database/sql"
	"fmt"

	"github.com/hiragi-gkuth/bitris-analyzer/pkg/authinfo"

	"github.com/go-sql-driver/mysql"
)

// GetDbConnection return db connection
func GetDbConnection() *sql.DB {
	config := mysql.NewConfig()

	config.User = "hiragi-gkuth"
	config.Passwd = "emyure-ta"
	config.DBName = "bitris"
	config.Net = "tcp"
	config.Addr = "10.1.228.31"

	db, err := sql.Open("mysql", config.FormatDSN())

	if err != nil {
		panic(err.Error())
	}
	return db
}

// FetchAuthData is fetcher
func FetchAuthData(db *sql.DB, limit int) []authinfo.AuthData {
	query := fmt.Sprintf("SELECT * FROM bitris_uehara ORDER BY id DESC LIMIT %d", limit)

	rows, err := db.Query(query)
	if err != nil {
		panic(err.Error())
	}
	defer rows.Close()

	authDataList := make([]authinfo.AuthData, 0)

	for rows.Next() {
		authDbData := authinfo.NewAuthDbData()
		err := rows.Scan(
			&authDbData.ID,
			&authDbData.Result,
			&authDbData.User,
			&authDbData.IP,
			&authDbData.Authtime,
			&authDbData.Detect,
			&authDbData.RTT,
			&authDbData.Year,
			&authDbData.Month,
			&authDbData.Day,
			&authDbData.Hour,
			&authDbData.Minute,
			&authDbData.Second,
			&authDbData.Usecond,
			&authDbData.Kex,
			&authDbData.NewKey,
		)
		if err != nil {
			panic(err.Error())
		}
		authDataList = append(authDataList, authDbData.ConvertToAuthData())
	}
	return authDataList
}

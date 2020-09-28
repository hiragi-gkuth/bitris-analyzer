package db

import (
	"database/sql"

	"github.com/go-sql-driver/mysql"
)

type bitris struct {
	*sql.DB
}

// GetDbConnection return db connection
func getDbConnection() *bitris {
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
	return &bitris{db}
}

// Package db is ORM for Bitris DataBase
package db

import (
	"database/sql"

	"github.com/go-sql-driver/mysql"
)

// Bitris is DB ORM
type Bitris struct {
	ServerID string
	DB       *sql.DB
}

// NewDB Returns DB ORM instance
func NewDB(config Config) *Bitris {
	db := getDBConnection(config)
	return &Bitris{config.ServerID, db}
}

// getDBConnection return db connection
func getDBConnection(config Config) *sql.DB {
	mysqlConfig := mysql.NewConfig()

	mysqlConfig.Addr = config.Host
	mysqlConfig.User = config.User
	mysqlConfig.Passwd = config.Pass
	mysqlConfig.DBName = config.DBName
	mysqlConfig.Net = "tcp"

	db, e := sql.Open("mysql", mysqlConfig.FormatDSN())
	if e != nil {
		panic(e.Error())
	}
	return db
}

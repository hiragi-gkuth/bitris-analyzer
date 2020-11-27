// Package db is ORM for Bitris DataBase
package db

import (
	"database/sql"

	"github.com/go-sql-driver/mysql"
)

// Bitris is DB ORM
type Bitris struct {
	Server SSHServer
	DB     *sql.DB
}

// NewDB Returns DB ORM instance
func NewDB(server SSHServer) *Bitris {
	db := getDBConnection()
	return &Bitris{server, db}
}

// getDBConnection return db connection
func getDBConnection() *sql.DB {
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

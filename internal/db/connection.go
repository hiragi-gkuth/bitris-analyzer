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
func NewDB(host string, port int, user string, passwd string, serverID string) *Bitris {
	db := getDBConnection(host, port, user, passwd)
	return &Bitris{serverID, db}
}

// getDBConnection return db connection
func getDBConnection(host string, port int, user string, passwd string) *sql.DB {
	config := mysql.NewConfig()

	config.Addr = host
	config.User = user
	config.Passwd = passwd
	config.DBName = "bitris"
	config.Net = "tcp"

	db, e := sql.Open("mysql", config.FormatDSN())
	if e != nil {
		panic(e.Error())
	}
	return db
}

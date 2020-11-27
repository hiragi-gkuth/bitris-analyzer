// Package db is ORM for Bitris DataBase
package db

import (
	"database/sql"
	"os"

	"github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
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
	e := godotenv.Load(".env")
	if e != nil {
		panic(e.Error())
	}
	config.User = os.Getenv("BITRIS_DB_USER")
	config.Passwd = os.Getenv("BITRIS_DB_PASSWD")
	config.DBName = os.Getenv("BITRIS_DB_NAME")
	config.Net = os.Getenv("BITRIS_DB_NET")
	config.Addr = os.Getenv("BITRIS_DB_ADDR")

	db, e := sql.Open("mysql", config.FormatDSN())
	if e != nil {
		panic(e.Error())
	}
	return db
}
